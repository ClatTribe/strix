"""iter-25.10 — finding-triggered probe bundles (Gap 1).

When L1 emits a finding, an engineer's reflex is to immediately fire
2-5 focused follow-ups. None of those follow-ups need the LLM — they're
deterministic re-invocations of existing L1 tools with parameters
drawn from the finding itself.

This module ships:

  * `BUNDLE_REGISTRY` — finding-kind → list[ProbeStep] dispatch table.
    Each ProbeStep names a tool + how to derive its arguments from
    the source finding.

  * `plan_probe_bundle(finding)` — returns the planned ProbeSteps for
    a finding (or [] when no bundle applies). Pure function; the
    caller is responsible for actually firing the tools.

  * `record_planned_bundle(finding, steps)` — attaches the bundle
    plan to the finding under ``triggered_probes[]`` so Wave 4's
    amplify orchestrator (or the L2 LLM, via inspection) can fire
    them.

The actual firing is gated by `posture.stealth_required` — if a WAF
was detected, the bundle plan is annotated with `stealth=True` so the
amplify orchestrator switches to stealth payload sets and lowers
concurrency.

This is the "covers ~70 % of cases at zero LLM cost" claim from
docs/L2-optimization.md §4 Gap 1. The remaining 30 % is the
`execute_adaptive_probe` L2 escape hatch (iter-25.10b, below).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin

from strix.l15.posture import stealth_required
from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProbeStep:
    """One planned follow-up probe."""
    tool: str                          # e.g. "scan_sqli_sqlmap"
    rationale: str                     # short human-readable reason
    args: dict[str, Any] = field(default_factory=dict)
    stealth: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "rationale": self.rationale,
            "args": self.args,
            "stealth": self.stealth,
        }


# ---- Bundle planners --------------------------------------------------------

def _bundle_admin_panel(finding: dict[str, Any]) -> list[ProbeStep]:
    """An unauth admin panel was found → fire the admin-burst."""
    url = finding.get("endpoint") or finding.get("url") or ""
    if not url:
        return []
    return [
        ProbeStep(
            tool="scan_auth_flow",
            rationale="try default creds (admin/admin etc) on admin panel",
            args={"target": url, "default_creds_only": True},
        ),
        ProbeStep(
            tool="discover_paths_feroxbuster",
            rationale="enumerate backup paths under /admin",
            args={
                "target_url": url,
                "wordlist": "admin-backups",
                "depth": 1,
            },
        ),
        ProbeStep(
            tool="scan_multi_role_auth",
            rationale="RBAC matrix with two test sessions",
            args={"target": url},
        ),
    ]


def _bundle_sqli_potential(finding: dict[str, Any]) -> list[ProbeStep]:
    """SAST said SQLi sink — confirm with sqlmap."""
    target = finding.get("endpoint") or finding.get("url")
    if not target:
        return []
    return [
        ProbeStep(
            tool="scan_sqli_sqlmap",
            rationale="confirm potential SQLi sink with sqlmap --batch",
            args={
                "target_url": target,
                "level": 3,
                "risk": 2,
            },
        ),
    ]


def _bundle_xss_potential(finding: dict[str, Any]) -> list[ProbeStep]:
    """SAST said XSS sink — confirm with dalfox."""
    target = finding.get("endpoint") or finding.get("url")
    if not target:
        return []
    return [
        ProbeStep(
            tool="scan_xss_dalfox",
            rationale="confirm potential XSS sink with dalfox",
            args={"target_url": target},
        ),
    ]


def _bundle_verified_secret(finding: dict[str, Any]) -> list[ProbeStep]:
    """Gitleaks/trufflehog found a verified secret → S3/EC2-list bursts."""
    steps: list[ProbeStep] = []
    detector = (
        (finding.get("detector") or "").lower()
        + " "
        + (finding.get("title") or "").lower()
    )
    if "aws" in detector:
        steps.append(ProbeStep(
            tool="terminal_execute",
            rationale="aws sts get-caller-identity to scope blast radius",
            args={"cmd": "aws sts get-caller-identity --no-cli-pager"},
        ))
        steps.append(ProbeStep(
            tool="terminal_execute",
            rationale="enumerate S3 buckets under discovered account",
            args={"cmd": "aws s3 ls --no-cli-pager"},
        ))
    if "stripe" in detector:
        steps.append(ProbeStep(
            tool="terminal_execute",
            rationale="curl /v1/balance to verify Stripe key scope",
            args={
                "cmd": (
                    "curl -fsSL -u "
                    "${STRIPE_KEY:?}:" " https://api.stripe.com/v1/balance"
                ),
            },
        ))
    if "github" in detector:
        steps.append(ProbeStep(
            tool="terminal_execute",
            rationale="enumerate org repos with the discovered PAT",
            args={"cmd": "gh repo list --json name,visibility"},
        ))
    return steps


def _bundle_subdomain(finding: dict[str, Any]) -> list[ProbeStep]:
    """A subdomain takeover candidate was found → probe it harder."""
    host = (
        finding.get("subdomain")
        or finding.get("hostname")
        or finding.get("endpoint")
        or ""
    )
    if not host:
        return []
    return [
        ProbeStep(
            tool="probe_hosts_httpx",
            rationale="HTTP-probe the takeover candidate",
            args={"hosts": [host], "detect_tech": True},
        ),
    ]


def _bundle_tech_jenkins(finding: dict[str, Any]) -> list[ProbeStep]:
    """Wappalyzer fingerprinted Jenkins → fire Jenkins-aware probes."""
    target = finding.get("endpoint") or finding.get("url") or ""
    if not target:
        return []
    return [
        ProbeStep(
            tool="scan_nuclei_templates",
            rationale="Jenkins-specific nuclei templates",
            args={"target": target, "tags": "jenkins"},
        ),
        ProbeStep(
            tool="discover_paths_feroxbuster",
            rationale="Jenkins common-paths (/script, /computer/, /jnlpJars)",
            args={"target_url": target, "wordlist": "jenkins-paths"},
        ),
    ]


def _bundle_tech_drupal(finding: dict[str, Any]) -> list[ProbeStep]:
    target = finding.get("endpoint") or finding.get("url") or ""
    if not target:
        return []
    return [
        ProbeStep(
            tool="discover_paths_feroxbuster",
            rationale="Drupal-specific wordlist + .php .module extensions",
            args={
                "target_url": target,
                "wordlist": "drupal.txt",
            },
        ),
        ProbeStep(
            tool="scan_nuclei_templates",
            rationale="Drupal-tagged nuclei templates",
            args={"target": target, "tags": "drupal"},
        ),
    ]


# ---- Dispatch -------------------------------------------------------------

_BUNDLE_PLANNERS: dict[str, Callable[[dict[str, Any]], list[ProbeStep]]] = {
    "unauth_debug_endpoint": _bundle_admin_panel,
    "exposed_admin_panel": _bundle_admin_panel,
    "sqli_potential_sast": _bundle_sqli_potential,
    "xss_potential_sast": _bundle_xss_potential,
    "verified_secret": _bundle_verified_secret,
    "subdomain_takeover_candidate": _bundle_subdomain,
    "tech_jenkins": _bundle_tech_jenkins,
    "tech_drupal": _bundle_tech_drupal,
}


def _classify_finding_kind(finding: dict[str, Any]) -> str | None:
    """Best-effort classification → key into BUNDLE_PLANNERS."""
    title = (finding.get("title") or "").lower()
    category = (finding.get("category") or "").lower()
    cwe = (finding.get("cwe") or "").upper()
    rule_id = (finding.get("rule_id") or "").lower()

    if "admin" in title and "panel" in title:
        return "exposed_admin_panel"
    if "unauthenticated exposed path" in title or "debug_endpoint" in rule_id:
        return "unauth_debug_endpoint"
    if cwe == "CWE-89" and (
        "sql" in rule_id or "sast" in rule_id or "semgrep" in rule_id
    ):
        return "sqli_potential_sast"
    if cwe == "CWE-79" and (
        "xss" in rule_id or "sast" in rule_id or "semgrep" in rule_id
    ):
        return "xss_potential_sast"
    if cwe == "CWE-798" and (
        finding.get("verified") or "verified" in title.lower()
    ):
        return "verified_secret"
    if "subdomain" in title and (
        "takeover" in title or "candidate" in title
    ):
        return "subdomain_takeover_candidate"
    # Tech-based dispatch — Wappalyzer/httpx tech fingerprint
    tech = finding.get("tech")
    if isinstance(tech, list):
        joined = " ".join(str(t).lower() for t in tech)
        if "jenkins" in joined:
            return "tech_jenkins"
        if "drupal" in joined:
            return "tech_drupal"
    return None


def plan_probe_bundle(finding: dict[str, Any]) -> list[ProbeStep]:
    """Return the planned probe-bundle for a finding (or [])."""
    try:
        kind = _classify_finding_kind(finding)
        if not kind:
            return []
        planner = _BUNDLE_PLANNERS.get(kind)
        if planner is None:
            return []
        steps = planner(finding)
        if not steps:
            return steps
        # Apply stealth flag based on posture cache
        target = (
            finding.get("endpoint")
            or finding.get("url")
            or finding.get("target")
            or ""
        )
        is_stealth = stealth_required(target) if target else False
        if is_stealth:
            return [
                ProbeStep(
                    tool=s.tool,
                    rationale=s.rationale,
                    args=s.args,
                    stealth=True,
                )
                for s in steps
            ]
        return steps
    except Exception as e:  # noqa: BLE001
        logger.debug("plan_probe_bundle failed: %s", e)
        return []


def record_planned_bundle(
    finding: dict[str, Any], steps: list[ProbeStep],
) -> None:
    """Attach the bundle plan to the finding under triggered_probes[]."""
    if not steps:
        return
    try:
        existing = list(finding.get("triggered_probes") or [])
        for s in steps:
            existing.append(s.to_dict())
        finding["triggered_probes"] = existing
    except Exception as e:  # noqa: BLE001
        logger.debug("record_planned_bundle failed: %s", e)


# ---- L2 escape hatch ------------------------------------------------------

_adaptive_call_lock = threading.RLock()
_adaptive_call_log: list[dict[str, Any]] = []
_ADAPTIVE_CALL_CAP = 10


@register_tool(sandbox_execution=False, provenance="framework")
def execute_adaptive_probe(
    tool_name: str,
    target: str,
    extra_args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """L2 LLM escape hatch — fire any L1 tool with custom args.

    Use this when the deterministic L1.5 probe-bundle dispatcher
    didn't cover the follow-up you want — the "unforeseen 30%" of
    cases beyond the built-in admin-burst / sqli-burst / tech-burst
    bundles.

    Before calling, check whether the source finding already has a
    `triggered_probes[]` array attached. If yes, those bundles are
    firing automatically via the amplify orchestrator — don't
    duplicate; this tool is for cases the deterministic planner
    didn't anticipate.

    Args:
        tool_name: the L1 tool name to fire (e.g.
            "scan_sqli_sqlmap", "discover_paths_feroxbuster",
            "probe_hosts_httpx").
        target: target URL or host the tool will probe.
        extra_args: optional dict of extra keyword args passed to the
            tool. Whatever the tool's @register_tool signature
            accepts is valid here.

    Returns:
        ``{queued: bool, reason: str, stealth: bool}``. Does NOT
        actually invoke the tool — the amplify orchestrator dequeues
        and fires. This call just records intent + emits the audit
        event so the LLM has a deterministic feedback signal.

    Per-scan call cap of 10; further calls return ``queued=False``
    with reason="adaptive-probe call cap reached". Stealth flag is
    inherited from the cached SecurityPosture for the target — the
    LLM doesn't get to bypass WAF awareness here either.
    """
    with _adaptive_call_lock:
        if len(_adaptive_call_log) >= _ADAPTIVE_CALL_CAP:
            return {
                "queued": False,
                "reason": (
                    f"adaptive-probe call cap reached "
                    f"({_ADAPTIVE_CALL_CAP}/scan)"
                ),
                "stealth": False,
            }
        is_stealth = stealth_required(target)
        record = {
            "tool": tool_name,
            "target": target,
            "extra_args": dict(extra_args or {}),
            "stealth": is_stealth,
        }
        _adaptive_call_log.append(record)
        return {
            "queued": True,
            "reason": "queued for amplify orchestrator",
            "stealth": is_stealth,
        }


def adaptive_call_log() -> list[dict[str, Any]]:
    """Return a snapshot of the per-scan adaptive call log."""
    with _adaptive_call_lock:
        return list(_adaptive_call_log)


def clear_adaptive_log() -> None:
    """Wipe the adaptive call log. Tests use this between cases."""
    with _adaptive_call_lock:
        _adaptive_call_log.clear()
