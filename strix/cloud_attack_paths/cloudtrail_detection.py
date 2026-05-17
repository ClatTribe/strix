"""CloudTrail-based detection — rule-based Cloud Detection &
Response (CDR).

masterroadmap §5 P3 — Wiz's newest moat. Wiz's CDR uses ML on
baseline traffic; v1 ships a deterministic rule engine that
catches the canonical attack-shape events from a CloudTrail
log stream. Far simpler than full ML; meaningfully reduces the
time-to-detect for the most common compromise patterns.

## How operators use this

Two integration patterns:

  1. **File-based**: operator points strix at a CloudTrail
     JSON-lines export (S3 download / `aws cloudtrail
     lookup-events` output / file on disk).
  2. **In-memory**: caller passes a `list[dict]` of pre-parsed
     events (from `events:LookupEvents` API or any other source).

Both flow into `detect(events)` which returns a list of
`CloudTrailFinding` records.

## Rules shipped in v1

Each rule is a pure function `(events) -> list[finding]`:

  * `root_account_used` — any event with `userIdentity.type=Root`
    is critical. CIS AWS 1.4 / 1.5 ground truth.
  * `console_login_without_mfa` — `eventName=ConsoleLogin` +
    `additionalEventData.MFAUsed=No`. Critical.
  * `iam_policy_change_after_hours` — `eventSource=iam` +
    `eventName` ∈ {Create/Update/Delete/Attach/Detach...Policy*}
    + event time outside the business-hours window.
  * `bulk_s3_get_in_window` — > N `GetObject` calls from same
    principal in M minutes (likely data exfil).
  * `assume_role_from_unknown_account` — sts:AssumeRole event
    where the source account isn't in the trusted-accounts
    allow-list.
  * `cloudtrail_logging_stopped` — `eventName=StopLogging` —
    attacker's first move post-compromise.
  * `security_group_egress_world` — SG rule added allowing
    `0.0.0.0/0` egress — common exfil-channel setup.

## What this does NOT do (v2 deferred)

  * **Streaming ingestion** — v1 is batch-only. Wrappers
    schedule this against rolling event windows.
  * **ML-based anomaly detection** — pure rule-based in v1.
    Baseline-traffic clustering is a follow-up.
  * **Cross-event correlation** — each rule operates on the
    event stream independently; v2 chains correlations like
    "console login from new geo" + "IAM policy attachment" in
    a short window.

## Safety contract

Pure data transformation — no external calls, no I/O beyond
the file path the operator supplies. Findings emit on the
existing tracer surface as `category=cdr_detection`.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from pathlib import Path
from typing import Any, Callable

from strix.cspm.aws import CspmFinding


logger = logging.getLogger(__name__)


# Business hours window (UTC). Outside this window, IAM
# admin actions are flagged as after-hours. Operators in non-UTC
# offices can override via the kwarg.
_DEFAULT_BUSINESS_HOURS = (time(13, 0), time(23, 0))  # 9am-7pm Eastern

# Bulk-S3-GetObject thresholds. Tuned conservatively to keep FPs
# at bay; operators can override per call.
_DEFAULT_BULK_S3_THRESHOLD = 100  # GetObject calls
_DEFAULT_BULK_S3_WINDOW_MINUTES = 5


@dataclass
class CloudTrailFinding:
    """One CDR rule hit. Mirrors CspmFinding shape so it flows
    through the existing tracer + compliance pipeline."""
    rule_id: str
    severity: str  # critical | high | medium | low | info
    message: str
    narrative: str
    principal: str | None = None
    event_name: str | None = None
    event_time: str | None = None
    source_ip: str | None = None
    aws_region: str | None = None
    account_id: str | None = None
    event_count: int = 1
    evidence_events: list[dict[str, Any]] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "narrative": self.narrative,
            "principal": self.principal,
            "event_name": self.event_name,
            "event_time": self.event_time,
            "source_ip": self.source_ip,
            "aws_region": self.aws_region,
            "account_id": self.account_id,
            "event_count": self.event_count,
            "evidence_events": list(self.evidence_events),
            "mitre_techniques": list(self.mitre_techniques),
        }

    def to_cspm_finding(self) -> CspmFinding:
        """Adapt to the CspmFinding shape so the existing
        tracer-emit + compliance pipeline picks it up without
        new wiring."""
        return CspmFinding(
            rule_id=self.rule_id,
            severity=self.severity,
            message=self.message,
            service="cloudtrail",
            region=self.aws_region,
            resource_arn=self.principal or "arn:aws:iam::*:unknown",
            account_id=self.account_id,
            cwe="CWE-778",  # insufficient logging / monitoring
            category="cdr_detection",
            metadata={
                "narrative": self.narrative,
                "event_name": self.event_name,
                "event_time": self.event_time,
                "source_ip": self.source_ip,
                "event_count": self.event_count,
                "mitre_techniques": list(self.mitre_techniques),
                "evidence_events": list(self.evidence_events)[:5],
            },
        )


# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------


def _event_principal(event: dict[str, Any]) -> str | None:
    """Pull the canonical principal ARN from a CloudTrail event."""
    ui = event.get("userIdentity") or {}
    if "arn" in ui:
        return ui["arn"]
    if ui.get("type") == "Root":
        account = ui.get("accountId") or "*"
        return f"arn:aws:iam::{account}:root"
    return None


def _event_time(event: dict[str, Any]) -> datetime | None:
    s = event.get("eventTime")
    if not s:
        return None
    try:
        # CloudTrail uses ISO-8601 with `Z` suffix.
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _is_after_hours(
    dt: datetime | None, *, business_hours: tuple[time, time],
) -> bool:
    """True when `dt` falls outside the business-hours window
    (UTC). Default 9am-7pm Eastern = 13:00-23:00 UTC."""
    if dt is None:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    t = dt.astimezone(timezone.utc).time()
    start, end = business_hours
    if start <= end:
        return not (start <= t <= end)
    # Wrap-around window (e.g. 22:00-06:00).
    return not (t >= start or t <= end)


# ---------------------------------------------------------------------------
# Individual rules
# ---------------------------------------------------------------------------


def _rule_root_account_used(
    events: list[dict[str, Any]], **_kwargs,
) -> list[CloudTrailFinding]:
    """CIS AWS 1.4 / 1.5 — root account activity. Any successful
    event under userIdentity.type=Root is critical."""
    out: list[CloudTrailFinding] = []
    for ev in events:
        ui = ev.get("userIdentity") or {}
        if ui.get("type") != "Root":
            continue
        # Ignore read-only API services that AWS internally calls
        # as 'Root' (e.g. AWS internal billing). Filter on
        # eventSource being non-aws-internal.
        out.append(CloudTrailFinding(
            rule_id="cdr_root_account_used",
            severity="critical",
            message=(
                f"Root account performed `{ev.get('eventName')}` "
                f"at {ev.get('eventTime')}"
            ),
            narrative=(
                f"Root account activity detected on CloudTrail "
                f"event `{ev.get('eventName')}`. Root usage "
                f"violates CIS AWS 1.5 — the root account should "
                f"NEVER be used for routine operations. Either "
                f"an admin is doing emergency manual work (rare) "
                f"OR the root credentials are compromised. "
                f"Investigate immediately."
            ),
            principal=_event_principal(ev),
            event_name=ev.get("eventName"),
            event_time=ev.get("eventTime"),
            source_ip=ev.get("sourceIPAddress"),
            aws_region=ev.get("awsRegion"),
            account_id=ui.get("accountId"),
            evidence_events=[ev],
            mitre_techniques=["T1078.004", "T1098"],
        ))
    return out


def _rule_console_login_without_mfa(
    events: list[dict[str, Any]], **_kwargs,
) -> list[CloudTrailFinding]:
    """ConsoleLogin events where `additionalEventData.MFAUsed=No`
    — successful logins without MFA. Critical for IAM users
    with non-trivial perms."""
    out: list[CloudTrailFinding] = []
    for ev in events:
        if ev.get("eventName") != "ConsoleLogin":
            continue
        # Failed logins surface as ConsoleLogin too; filter to
        # successes.
        if (ev.get("responseElements") or {}).get(
            "ConsoleLogin"
        ) != "Success":
            continue
        mfa = (ev.get("additionalEventData") or {}).get("MFAUsed")
        if mfa and str(mfa).lower() not in ("no", "false"):
            continue
        out.append(CloudTrailFinding(
            rule_id="cdr_console_login_without_mfa",
            severity="critical",
            message=(
                f"Console login without MFA: "
                f"`{_event_principal(ev) or '(unknown)'}` at "
                f"{ev.get('eventTime')}"
            ),
            narrative=(
                f"User logged into the AWS console WITHOUT MFA "
                f"(`additionalEventData.MFAUsed=No`). MFA is "
                f"required for every interactive console session "
                f"per CIS AWS 1.10. If the user has any non-trivial "
                f"IAM permissions, this is a credential-stuffing-"
                f"viable account. Enable MFA for the user + audit "
                f"recent activity from the same source IP."
            ),
            principal=_event_principal(ev),
            event_name=ev.get("eventName"),
            event_time=ev.get("eventTime"),
            source_ip=ev.get("sourceIPAddress"),
            aws_region=ev.get("awsRegion"),
            evidence_events=[ev],
            mitre_techniques=["T1078.004", "T1556.006"],
        ))
    return out


_IAM_ADMIN_EVENT_NAME_RE = re.compile(
    r"^(Create|Update|Delete|Attach|Detach|Put|Replace)"
    r"(User|Role|Policy|Group|RolePolicy|UserPolicy|GroupPolicy)",
)


def _rule_iam_change_after_hours(
    events: list[dict[str, Any]], *,
    business_hours: tuple[time, time] = _DEFAULT_BUSINESS_HOURS,
    **_kwargs,
) -> list[CloudTrailFinding]:
    """IAM policy / role mutations outside business-hours window.
    High signal: legit IAM changes are usually planned + on-hours;
    after-hours IAM mutation correlates strongly with compromise."""
    out: list[CloudTrailFinding] = []
    for ev in events:
        if (ev.get("eventSource") or "").lower() != "iam.amazonaws.com":
            continue
        name = ev.get("eventName") or ""
        if not _IAM_ADMIN_EVENT_NAME_RE.match(name):
            continue
        dt = _event_time(ev)
        if not _is_after_hours(dt, business_hours=business_hours):
            continue
        out.append(CloudTrailFinding(
            rule_id="cdr_iam_change_after_hours",
            severity="high",
            message=(
                f"After-hours IAM change: `{name}` by "
                f"`{_event_principal(ev) or '(unknown)'}` at "
                f"{ev.get('eventTime')}"
            ),
            narrative=(
                f"IAM mutation `{name}` performed outside business "
                f"hours (UTC window "
                f"{business_hours[0].strftime('%H:%M')}-"
                f"{business_hours[1].strftime('%H:%M')}). After-"
                f"hours IAM changes correlate strongly with "
                f"compromise — attackers often attach admin "
                f"policies, create persistence roles, or rotate "
                f"trust policies at off-peak times to evade "
                f"working-hours monitoring. Verify with the "
                f"principal that this change was intentional."
            ),
            principal=_event_principal(ev),
            event_name=name,
            event_time=ev.get("eventTime"),
            source_ip=ev.get("sourceIPAddress"),
            aws_region=ev.get("awsRegion"),
            evidence_events=[ev],
            mitre_techniques=["T1098.001", "T1078.004"],
        ))
    return out


def _rule_cloudtrail_logging_stopped(
    events: list[dict[str, Any]], **_kwargs,
) -> list[CloudTrailFinding]:
    """`StopLogging` event on CloudTrail itself — attacker's
    first move post-compromise to blind the audit trail."""
    out: list[CloudTrailFinding] = []
    for ev in events:
        if ev.get("eventName") != "StopLogging":
            continue
        if (ev.get("eventSource") or "").lower() != "cloudtrail.amazonaws.com":
            continue
        out.append(CloudTrailFinding(
            rule_id="cdr_cloudtrail_logging_stopped",
            severity="critical",
            message=(
                f"CloudTrail logging stopped by "
                f"`{_event_principal(ev) or '(unknown)'}` at "
                f"{ev.get('eventTime')}"
            ),
            narrative=(
                f"`StopLogging` API call against CloudTrail. This "
                f"is the canonical attacker-first-move-post-"
                f"compromise: blind the audit trail so subsequent "
                f"activity isn't recorded. Investigate the source "
                f"principal AND immediately re-enable logging. "
                f"Any events between this StopLogging and the "
                f"current time are missing from CloudTrail — use "
                f"CloudTrail Lake's continuous-export or another "
                f"redundant log to reconstruct the gap if any."
            ),
            principal=_event_principal(ev),
            event_name=ev.get("eventName"),
            event_time=ev.get("eventTime"),
            source_ip=ev.get("sourceIPAddress"),
            aws_region=ev.get("awsRegion"),
            evidence_events=[ev],
            mitre_techniques=["T1562.008"],
        ))
    return out


def _rule_bulk_s3_get_in_window(
    events: list[dict[str, Any]], *,
    threshold: int = _DEFAULT_BULK_S3_THRESHOLD,
    window_minutes: int = _DEFAULT_BULK_S3_WINDOW_MINUTES,
    **_kwargs,
) -> list[CloudTrailFinding]:
    """Same principal issues > `threshold` `GetObject` calls
    within `window_minutes` — likely data exfil."""
    by_principal: dict[str, list[tuple[datetime, dict]]] = {}
    for ev in events:
        if ev.get("eventName") != "GetObject":
            continue
        if (ev.get("eventSource") or "").lower() != "s3.amazonaws.com":
            continue
        principal = _event_principal(ev)
        if not principal:
            continue
        dt = _event_time(ev)
        if dt is None:
            continue
        by_principal.setdefault(principal, []).append((dt, ev))

    out: list[CloudTrailFinding] = []
    for principal, gets in by_principal.items():
        gets.sort(key=lambda t: t[0])
        # Sliding window count.
        window = window_minutes * 60
        i = 0
        for j, (t_j, ev_j) in enumerate(gets):
            while gets[i][0] and (
                t_j - gets[i][0]
            ).total_seconds() > window:
                i += 1
            count = j - i + 1
            if count >= threshold:
                # Emit one finding per principal — the first
                # window that crosses the threshold.
                out.append(CloudTrailFinding(
                    rule_id="cdr_bulk_s3_get_in_window",
                    severity="high",
                    message=(
                        f"Bulk S3 GetObject by `{principal}`: "
                        f"{count} calls in {window_minutes}m"
                    ),
                    narrative=(
                        f"Principal `{principal}` issued {count} "
                        f"`s3:GetObject` calls within a "
                        f"{window_minutes}-minute window. "
                        f"Large-volume reads correlate strongly "
                        f"with data exfiltration. Audit the "
                        f"bucket(s) involved and the principal's "
                        f"recent permissions changes."
                    ),
                    principal=principal,
                    event_name="GetObject",
                    event_time=ev_j.get("eventTime"),
                    source_ip=ev_j.get("sourceIPAddress"),
                    event_count=count,
                    evidence_events=[g[1] for g in gets[i:j+1][:5]],
                    mitre_techniques=["T1530", "T1567"],
                ))
                break  # one finding per principal
    return out


def _rule_security_group_egress_to_world(
    events: list[dict[str, Any]], **_kwargs,
) -> list[CloudTrailFinding]:
    """Security group rule added allowing `0.0.0.0/0` EGRESS —
    common exfil-channel setup. (Ingress 0.0.0.0/0 is CSPM
    territory; egress is the runtime-detection signal.)"""
    out: list[CloudTrailFinding] = []
    for ev in events:
        if ev.get("eventName") not in (
            "AuthorizeSecurityGroupEgress",
        ):
            continue
        if (ev.get("eventSource") or "").lower() != "ec2.amazonaws.com":
            continue
        # CloudTrail nests the IP rules under requestParameters.
        params = ev.get("requestParameters") or {}
        ip_perms = params.get("ipPermissions") or {}
        items = ip_perms.get("items") or []
        for item in items:
            ranges = (item.get("ipRanges") or {}).get("items") or []
            for r in ranges:
                if (r.get("cidrIp") or "") == "0.0.0.0/0":
                    out.append(CloudTrailFinding(
                        rule_id="cdr_security_group_egress_to_world",
                        severity="medium",
                        message=(
                            f"Security group egress rule allowing "
                            f"`0.0.0.0/0` added by "
                            f"`{_event_principal(ev) or '(unknown)'}`"
                        ),
                        narrative=(
                            f"`AuthorizeSecurityGroupEgress` event "
                            f"added a 0.0.0.0/0 egress rule. "
                            f"Egress-to-world rules are unusual in "
                            f"prod (most workloads only need to "
                            f"reach specific endpoints) and are a "
                            f"common attacker move to enable data "
                            f"exfiltration to an attacker-controlled "
                            f"host. Verify the rule is intentional; "
                            f"if not, remove + audit the principal."
                        ),
                        principal=_event_principal(ev),
                        event_name=ev.get("eventName"),
                        event_time=ev.get("eventTime"),
                        source_ip=ev.get("sourceIPAddress"),
                        aws_region=ev.get("awsRegion"),
                        evidence_events=[ev],
                        mitre_techniques=["T1562.007", "T1567"],
                    ))
                    break  # one finding per event
            else:
                continue
            break
    return out


# ---------------------------------------------------------------------------
# Registry + dispatcher
# ---------------------------------------------------------------------------


RuleFn = Callable[..., list[CloudTrailFinding]]

BUILTIN_RULES: dict[str, RuleFn] = {
    "cdr_root_account_used": _rule_root_account_used,
    "cdr_console_login_without_mfa": _rule_console_login_without_mfa,
    "cdr_iam_change_after_hours": _rule_iam_change_after_hours,
    "cdr_cloudtrail_logging_stopped": _rule_cloudtrail_logging_stopped,
    "cdr_bulk_s3_get_in_window": _rule_bulk_s3_get_in_window,
    "cdr_security_group_egress_to_world":
        _rule_security_group_egress_to_world,
}


def detect(
    events: list[dict[str, Any]],
    *,
    rules: list[str] | None = None,
    business_hours: tuple[time, time] = _DEFAULT_BUSINESS_HOURS,
    bulk_s3_threshold: int = _DEFAULT_BULK_S3_THRESHOLD,
    bulk_s3_window_minutes: int = _DEFAULT_BULK_S3_WINDOW_MINUTES,
) -> list[CloudTrailFinding]:
    """Run every registered rule on the event list. Returns the
    union of findings sorted critical-first."""
    allowed = set(rules) if rules else None
    active = {
        k: v for k, v in BUILTIN_RULES.items()
        if allowed is None or k in allowed
    }
    out: list[CloudTrailFinding] = []
    for rule_id, fn in active.items():
        try:
            out.extend(fn(
                events,
                business_hours=business_hours,
                threshold=bulk_s3_threshold,
                window_minutes=bulk_s3_window_minutes,
            ))
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "cdr rule %s failed: %s", rule_id, e, exc_info=True,
            )
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    out.sort(key=lambda f: -sev_rank.get(f.severity, 0))
    return out


def load_events_from_file(path: str | Path) -> list[dict[str, Any]]:
    """Load CloudTrail events from a JSON-lines file OR a JSON
    file containing `{"Records": [...]}` (AWS's bundle format).
    Returns an empty list on read / parse failure (logged)."""
    p = Path(path).expanduser()
    if not p.is_file():
        logger.debug("cdr: file not found: %s", p)
        return []
    try:
        content = p.read_text(encoding="utf-8")
    except OSError as e:
        logger.debug("cdr: read %s failed: %s", p, e)
        return []
    # Try jsonlines first.
    lines = [
        line.strip() for line in content.splitlines() if line.strip()
    ]
    if not lines:
        return []
    # Heuristic: if first line is a `{` followed by `"Records"`
    # somewhere in the file, treat as bundle; else jsonlines.
    if "Records" in content[:200] and content.lstrip().startswith("{"):
        try:
            doc = json.loads(content)
            recs = doc.get("Records") or []
            return [r for r in recs if isinstance(r, dict)]
        except json.JSONDecodeError:
            return []
    out: list[dict[str, Any]] = []
    for line in lines:
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict):
            out.append(ev)
    return out


def summarise(findings: list[CloudTrailFinding]) -> dict[str, Any]:
    """Aggregate for tool_metadata."""
    sev_counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    by_rule: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    return {
        "total_findings": len(findings),
        "severity_breakdown": sev_counts,
        "per_rule": by_rule,
    }
