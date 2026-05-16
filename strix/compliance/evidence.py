"""Build the `compliance_evidence.json` artifact.

Inputs:
  * Normalised finding list (from
    `strix.finding_chains.normalise.normalise_findings` —
    same shape; we reuse it).
  * Optional framework subset (default: all 4).

Outputs:
  * `ComplianceReport` dataclass — one entry per (framework,
    control_id) covered by either rules or findings.
  * Pass/fail rollup per control + per framework.
  * Untested-control list — controls in the framework
    catalog that no rule in our corpus maps to.

Pass / fail per control:
  * `fail`     — at least one finding with severity high or critical
  * `warn`     — at least one finding with severity low or medium
  * `info`     — only info-severity findings hit this control
  * `pass`     — control is covered by a rule but no findings hit it
  * `untested` — control isn't in our corpus's coverage at all
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from strix.compliance.frameworks import (
    ALL_FRAMEWORKS,
    Control,
    all_controls,
)
from strix.compliance.mappings import (
    controls_for,
    corpus_size_for_control,
    covered_controls,
    untested_controls,
)

# Lazy / type-checking-only import. `strix.finding_chains.__init__`
# transitively pulls `strix.tools.__init__` → `strix.compliance.tools`
# → THIS module — a runtime cycle. We only use `Finding`'s shape via
# attribute access at runtime, so a TYPE_CHECKING import is enough
# for the type hints.
if TYPE_CHECKING:
    from strix.finding_chains.chain import Finding


logger = logging.getLogger(__name__)


_SEVERITY_RANK = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


# Per-control verdict rollup.
VERDICT_FAIL = "fail"
VERDICT_WARN = "warn"
VERDICT_INFO = "info"
VERDICT_PASS = "pass"
VERDICT_UNTESTED = "untested"


# Evidence freshness — auditors discount evidence past this TTL. SOC 2
# Type II default audit window is one year, but most auditors expect
# evidence inside the testing period (commonly quarterly).
_DEFAULT_EVIDENCE_TTL_DAYS = 90


# Bumped when the report payload schema changes in a non-additive way.
# Consumers (wrapper compliance dashboards, auditor handoff) gate on
# this to refuse decode of unrecognised versions.
COMPLIANCE_REPORT_SCHEMA_VERSION = 2


def _iso_utc_now() -> str:
    """Stamp wall-clock UTC time in RFC 3339 / ISO 8601 format with
    explicit `Z` zone — what auditors expect on evidence artifacts."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _evidence_ttl_days() -> int:
    """Read evidence TTL from `STRIX_EVIDENCE_TTL_DAYS` env, falling
    back to 90. Invalid / negative values fall back too."""
    raw = os.environ.get("STRIX_EVIDENCE_TTL_DAYS")
    if not raw:
        return _DEFAULT_EVIDENCE_TTL_DAYS
    try:
        v = int(raw)
    except ValueError:
        return _DEFAULT_EVIDENCE_TTL_DAYS
    if v <= 0:
        return _DEFAULT_EVIDENCE_TTL_DAYS
    return v


def _expires_at_from(collected_at_iso: str, ttl_days: int) -> str:
    """Compute the RFC 3339 `expires_at` from a collected-at stamp."""
    try:
        dt = datetime.strptime(collected_at_iso, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        dt = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    expires = dt + timedelta(days=ttl_days)
    return expires.strftime("%Y-%m-%dT%H:%M:%SZ")


# Per-severity remediation deadlines (days). Auditor-aware
# defaults — most attestation frameworks expect critical / high
# fixes within 30 days, medium within 90.
_REMEDIATION_DEADLINE_DEFAULTS: dict[str, int] = {
    "critical": 30,
    "high": 30,
    "medium": 90,
    "low": 180,
    "info": 180,
}


# Framework-specific overrides — PCI-DSS 4.0 Req 6.3.3 specifies
# 30 days for critical / high; HIPAA Security Rule expectation is
# 30 days for critical (per OCR enforcement). When a control's
# framework has stricter expectations, the framework value wins.
# Keys MUST match the framework strings used in
# `strix/compliance/frameworks.py` (lowercase / underscore form).
_REMEDIATION_FRAMEWORK_OVERRIDES: dict[str, dict[str, int]] = {
    "pci_dss": {"critical": 30, "high": 30, "medium": 60},
    "hipaa": {"critical": 30, "high": 30, "medium": 60},
}


def _default_control_owner() -> str:
    """Owner string defaulted from env (`STRIX_COMPLIANCE_DEFAULT_OWNER`)
    or `AppSec` when unset. Wrapper-side per-customer config can
    override per control after the engine emits."""
    return os.environ.get(
        "STRIX_COMPLIANCE_DEFAULT_OWNER", "AppSec",
    ).strip() or "AppSec"


def _remediation_deadline_for(
    *, framework: str, max_severity: str,
) -> int:
    """Pick the remediation-deadline-days for a control based on
    its framework and the max severity of findings that hit it.
    Framework-specific overrides take precedence."""
    sev = (max_severity or "info").lower()
    overrides = _REMEDIATION_FRAMEWORK_OVERRIDES.get(framework, {})
    if sev in overrides:
        return overrides[sev]
    return _REMEDIATION_DEADLINE_DEFAULTS.get(sev, 180)


def _remediation_deadline_at(
    collected_at_iso: str, days: int,
) -> str:
    try:
        dt = datetime.strptime(collected_at_iso, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        dt = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    return (dt + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ControlEvidence:
    """Evidence for one (framework, control_id) tuple.

    Auditor-grade fields:
      * `evidence_collected_at` — RFC 3339 UTC stamp of when this
        scan ran (i.e. when the verdict was last observed).
      * `last_verified_at` — alias for `evidence_collected_at` on a
        single-scan report; the wrapper updates it when a re-scan
        confirms the same verdict without changing the underlying
        finding set.
      * `expires_at` — `evidence_collected_at + STRIX_EVIDENCE_TTL_DAYS`
        (default 90). Past this, auditors should treat the evidence
        as stale and demand a fresh scan.
      * `probe_coverage` — `{rules_in_corpus, rules_fired,
        coverage_pct}`. Tells auditors how aggressively strix
        probed the control (e.g. PCI 6.5.1 has 12 mapped rules in
        the corpus; this scan fired 12 → 100% probe coverage).
      * `evidence_pointers` — per-finding traceability:
        `{finding_id, target, endpoint, category, cve}`. Auditors
        get the exact endpoint/file that triggered each finding
        for this control.
      * `remediation_deadline_days` / `remediation_deadline_at` —
        defaulted by severity + framework (PCI-DSS / HIPAA stricter).
        Wrapper-side workflow uses these to drive issue-tracker
        deadlines + escalation timers.
      * `control_owner` — defaulted via `STRIX_COMPLIANCE_DEFAULT_OWNER`
        env (or "AppSec"). Wrapper overrides per-customer.
    """
    framework: str
    control_id: str
    title: str
    description: str
    verdict: str                    # one of VERDICT_* constants
    finding_ids: list[str] = field(default_factory=list)
    finding_severities: list[str] = field(default_factory=list)
    rationale: str = ""
    evidence_collected_at: str | None = None
    last_verified_at: str | None = None
    expires_at: str | None = None
    # Phase 2 audit-grade enrichments.
    probe_coverage: dict | None = None
    evidence_pointers: list[dict] = field(default_factory=list)
    remediation_deadline_days: int | None = None
    remediation_deadline_at: str | None = None
    control_owner: str | None = None

    @property
    def fqid(self) -> str:
        return f"{self.framework}:{self.control_id}"

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "control_id": self.control_id,
            "fqid": self.fqid,
            "title": self.title,
            "description": self.description,
            "verdict": self.verdict,
            "finding_ids": list(self.finding_ids),
            "finding_severities": list(self.finding_severities),
            "rationale": self.rationale,
            "evidence_collected_at": self.evidence_collected_at,
            "last_verified_at": self.last_verified_at,
            "expires_at": self.expires_at,
            "probe_coverage": (
                dict(self.probe_coverage)
                if self.probe_coverage is not None else None
            ),
            "evidence_pointers": [
                dict(p) for p in self.evidence_pointers
            ],
            "remediation_deadline_days": self.remediation_deadline_days,
            "remediation_deadline_at": self.remediation_deadline_at,
            "control_owner": self.control_owner,
        }


@dataclass
class ComplianceReport:
    """Aggregate evidence across one or more frameworks.

    Phase 2 enrichments include `coverage_attestation` — per-
    framework summary of how much of the catalog strix can probe.
    Auditors use this to judge "what fraction of PCI-DSS is
    automated vs needing manual attestation."
    """
    schema_version: int = COMPLIANCE_REPORT_SCHEMA_VERSION
    frameworks: list[str] = field(default_factory=list)
    controls: list[ControlEvidence] = field(default_factory=list)
    summary: dict[str, dict[str, int]] = field(default_factory=dict)
    coverage_attestation: dict[str, dict] = field(default_factory=dict)
    generated_at: str | None = None
    evidence_ttl_days: int | None = None
    expires_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "frameworks": list(self.frameworks),
            "controls": [c.to_dict() for c in self.controls],
            "summary": dict(self.summary),
            "coverage_attestation": dict(self.coverage_attestation),
            "generated_at": self.generated_at,
            "evidence_ttl_days": self.evidence_ttl_days,
            "expires_at": self.expires_at,
        }

    def by_framework(self, framework: str) -> list[ControlEvidence]:
        return [c for c in self.controls if c.framework == framework]


def _verdict_for_severities(sevs: list[str]) -> str:
    """Compute the per-control verdict from the severities of
    the findings that hit it."""
    if not sevs:
        # Caller decides between "pass" + "untested" — here we
        # only handle the has-findings case.
        return VERDICT_PASS
    ranks = [_SEVERITY_RANK.get(s.lower(), 0) for s in sevs]
    max_rank = max(ranks)
    if max_rank >= _SEVERITY_RANK["high"]:
        return VERDICT_FAIL
    if max_rank >= _SEVERITY_RANK["low"]:
        return VERDICT_WARN
    return VERDICT_INFO


def _rationale_for(
    findings: list[Finding], control: Control,
) -> str:
    """Human-readable rationale for the verdict — used by
    auditors reading the report."""
    if not findings:
        return (
            f"Control `{control.fqid}` is in strix's coverage — "
            f"at least one rule in the corpus maps to it. No "
            f"findings hit this control during the run, so the "
            f"control passes its automated verification."
        )
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = (f.severity or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    sev_summary = ", ".join(
        f"{count} {sev}" for sev, count in sorted(
            sev_counts.items(),
            key=lambda kv: -_SEVERITY_RANK.get(kv[0], 0),
        )
    )
    return (
        f"Control `{control.fqid}` was hit by {len(findings)} "
        f"finding(s): {sev_summary}. Top-finding title: "
        f"`{findings[0].title[:80]}`."
    )


def build_evidence_report(
    findings: Iterable[Finding],
    *,
    frameworks: Iterable[str] | None = None,
    evidence_collected_at: str | None = None,
) -> ComplianceReport:
    """Build a `ComplianceReport` from the normalised findings.

    Args:
        findings: list of `Finding` (use
            `strix.finding_chains.normalise.normalise_findings`
            to convert raw vulnerability dicts).
        frameworks: subset of frameworks to report on (default:
            all 4).
        evidence_collected_at: ISO 8601 UTC stamp to use on every
            `ControlEvidence` + the report (default: now). Pass a
            fixed value for deterministic test snapshots.

    Returns:
        `ComplianceReport`. Per-control entries cover EVERY
        control in the requested frameworks — including
        untested ones (with verdict='untested'). Every entry is
        stamped with `evidence_collected_at` / `last_verified_at`
        / `expires_at` so auditors can judge freshness.
    """
    fws = list(frameworks) if frameworks else list(ALL_FRAMEWORKS)
    findings_list = list(findings)
    by_id: dict[str, Finding] = {f.id: f for f in findings_list}
    collected_at = evidence_collected_at or _iso_utc_now()
    ttl_days = _evidence_ttl_days()
    expires_at = _expires_at_from(collected_at, ttl_days)

    # Bucket findings by (framework, control_id).
    by_control: dict[tuple[str, str], list[Finding]] = {}
    for f in findings_list:
        for fw, cid in controls_for(cwe=f.cwe, category=f.category):
            if fw not in fws:
                continue
            by_control.setdefault((fw, cid), []).append(f)

    # The covered set — controls in our corpus's coverage.
    covered = covered_controls(fws)

    # Track rules-fired-per-control: a `rule key` is either a
    # CWE ID or `category:<name>`. We count distinct keys across
    # the finding set that map to each control.
    rules_fired_by_control: dict[tuple[str, str], set[str]] = {}
    for f in findings_list:
        for fw, cid in controls_for(cwe=f.cwe, category=f.category):
            if fw not in fws:
                continue
            ckey = (fw, cid)
            bucket = rules_fired_by_control.setdefault(ckey, set())
            if f.cwe:
                bucket.add(f.cwe.strip().upper())
            if f.category:
                bucket.add(f"category:{f.category.strip().lower()}")

    default_owner = _default_control_owner()

    controls_evidence: list[ControlEvidence] = []
    for ctrl in all_controls(fws):
        key = (ctrl.framework, ctrl.id)
        hits = by_control.get(key, [])
        in_corpus = key in covered

        if not hits and not in_corpus:
            verdict = VERDICT_UNTESTED
            rationale = (
                f"Control `{ctrl.fqid}` is in the framework "
                f"catalog but no rule in strix's corpus maps to "
                f"it. Coverage gap — wrappers should surface "
                f"this for the customer to address via other "
                f"tooling."
            )
        elif not hits:
            verdict = VERDICT_PASS
            rationale = _rationale_for([], ctrl)
        else:
            # Order findings highest-severity first.
            hits.sort(key=lambda f: -_SEVERITY_RANK.get(
                (f.severity or "info").lower(), 0,
            ))
            verdict = _verdict_for_severities(
                [f.severity for f in hits]
            )
            rationale = _rationale_for(hits, ctrl)

        # ---- Phase 2 enrichments ----
        # Probe coverage: how many distinct rules in the corpus
        # map to this control, and how many fired during this run.
        rules_in_corpus = corpus_size_for_control(
            ctrl.framework, ctrl.id,
        )
        rules_fired = len(
            rules_fired_by_control.get(key, set())
        )
        probe_coverage: dict | None = None
        if rules_in_corpus > 0:
            probe_coverage = {
                "rules_in_corpus": rules_in_corpus,
                "rules_fired": rules_fired,
                "coverage_pct": round(
                    100.0 * rules_fired / rules_in_corpus, 1,
                ),
                "endpoints_tested": len({
                    (f.target or "") + "::" + (f.endpoint or "")
                    for f in hits
                    if (f.target or f.endpoint)
                }),
            }

        # Evidence pointers — per-finding traceability.
        evidence_pointers: list[dict] = []
        # Cap at 50 per control to keep the JSON bounded.
        for f in hits[:50]:
            evidence_pointers.append({
                "finding_id": f.id,
                "title": f.title[:120],
                "severity": (f.severity or "info").lower(),
                "target": f.target,
                "endpoint": f.endpoint,
                "category": f.category,
                "cwe": f.cwe,
                "cve": f.cve,
                "package": f.package,
            })
        truncated_pointers = max(0, len(hits) - 50)

        # Remediation deadline — picked from the max severity
        # observed; framework-specific overrides apply.
        deadline_days: int | None = None
        deadline_at: str | None = None
        if hits:
            max_sev = (
                hits[0].severity if hits else "info"
            ).lower()
            deadline_days = _remediation_deadline_for(
                framework=ctrl.framework, max_severity=max_sev,
            )
            deadline_at = _remediation_deadline_at(
                collected_at, deadline_days,
            )

        # Append truncation marker to rationale when applicable
        # so an auditor reading evidence_pointers knows more exist.
        if truncated_pointers > 0:
            rationale = (
                f"{rationale} (evidence_pointers truncated; "
                f"{truncated_pointers} additional finding(s) "
                f"omitted from per-control list — see the "
                f"top-level findings array)"
            )

        controls_evidence.append(ControlEvidence(
            framework=ctrl.framework,
            control_id=ctrl.id,
            title=ctrl.title,
            description=ctrl.description,
            verdict=verdict,
            finding_ids=[f.id for f in hits],
            finding_severities=[f.severity for f in hits],
            rationale=rationale,
            evidence_collected_at=collected_at,
            last_verified_at=collected_at,
            expires_at=expires_at,
            probe_coverage=probe_coverage,
            evidence_pointers=evidence_pointers,
            remediation_deadline_days=deadline_days,
            remediation_deadline_at=deadline_at,
            control_owner=default_owner,
        ))

    # Per-framework summary.
    summary: dict[str, dict[str, int]] = {}
    for fw in fws:
        per_fw = [c for c in controls_evidence if c.framework == fw]
        summary[fw] = {
            VERDICT_FAIL: sum(1 for c in per_fw if c.verdict == VERDICT_FAIL),
            VERDICT_WARN: sum(1 for c in per_fw if c.verdict == VERDICT_WARN),
            VERDICT_INFO: sum(1 for c in per_fw if c.verdict == VERDICT_INFO),
            VERDICT_PASS: sum(1 for c in per_fw if c.verdict == VERDICT_PASS),
            VERDICT_UNTESTED: sum(
                1 for c in per_fw if c.verdict == VERDICT_UNTESTED
            ),
            "total": len(per_fw),
        }

    # Per-framework coverage attestation — what fraction of the
    # catalog strix can probe at ALL (covered vs untested) +
    # what fraction WAS probed in this run (rules-fired).
    coverage_attestation: dict[str, dict] = {}
    for fw in fws:
        per_fw = [c for c in controls_evidence if c.framework == fw]
        total = len(per_fw)
        covered_count = sum(
            1 for c in per_fw if c.verdict != VERDICT_UNTESTED
        )
        fired_count = sum(
            1 for c in per_fw if c.probe_coverage and
            c.probe_coverage.get("rules_fired", 0) > 0
        )
        coverage_attestation[fw] = {
            "controls_total": total,
            "controls_covered_by_corpus": covered_count,
            "controls_covered_pct": (
                round(100.0 * covered_count / total, 1) if total > 0 else 0.0
            ),
            "controls_exercised_this_scan": fired_count,
            "controls_exercised_pct": (
                round(100.0 * fired_count / total, 1) if total > 0 else 0.0
            ),
            "untested_controls": sorted(
                c.control_id for c in per_fw
                if c.verdict == VERDICT_UNTESTED
            ),
        }

    return ComplianceReport(
        frameworks=fws,
        controls=controls_evidence,
        summary=summary,
        coverage_attestation=coverage_attestation,
        generated_at=collected_at,
        evidence_ttl_days=ttl_days,
        expires_at=expires_at,
    )


def write_compliance_evidence(
    report: ComplianceReport,
    output_path: str | Path,
) -> Path:
    """Serialise + write the report as `compliance_evidence.json`."""
    p = Path(output_path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(report.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )
    return p
