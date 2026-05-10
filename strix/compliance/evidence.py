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
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from strix.compliance.frameworks import (
    ALL_FRAMEWORKS,
    Control,
    all_controls,
    get_control,
)
from strix.compliance.mappings import (
    controls_for,
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


@dataclass
class ControlEvidence:
    """Evidence for one (framework, control_id) tuple."""
    framework: str
    control_id: str
    title: str
    description: str
    verdict: str                    # one of VERDICT_* constants
    finding_ids: list[str] = field(default_factory=list)
    finding_severities: list[str] = field(default_factory=list)
    rationale: str = ""

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
        }


@dataclass
class ComplianceReport:
    """Aggregate evidence across one or more frameworks."""
    schema_version: int = 1
    frameworks: list[str] = field(default_factory=list)
    controls: list[ControlEvidence] = field(default_factory=list)
    summary: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "frameworks": list(self.frameworks),
            "controls": [c.to_dict() for c in self.controls],
            "summary": dict(self.summary),
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
) -> ComplianceReport:
    """Build a `ComplianceReport` from the normalised findings.

    Args:
        findings: list of `Finding` (use
            `strix.finding_chains.normalise.normalise_findings`
            to convert raw vulnerability dicts).
        frameworks: subset of frameworks to report on (default:
            all 4).

    Returns:
        `ComplianceReport`. Per-control entries cover EVERY
        control in the requested frameworks — including
        untested ones (with verdict='untested').
    """
    fws = list(frameworks) if frameworks else list(ALL_FRAMEWORKS)
    findings_list = list(findings)
    by_id: dict[str, Finding] = {f.id: f for f in findings_list}

    # Bucket findings by (framework, control_id).
    by_control: dict[tuple[str, str], list[Finding]] = {}
    for f in findings_list:
        for fw, cid in controls_for(cwe=f.cwe, category=f.category):
            if fw not in fws:
                continue
            by_control.setdefault((fw, cid), []).append(f)

    # The covered set — controls in our corpus's coverage.
    covered = covered_controls(fws)

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

        controls_evidence.append(ControlEvidence(
            framework=ctrl.framework,
            control_id=ctrl.id,
            title=ctrl.title,
            description=ctrl.description,
            verdict=verdict,
            finding_ids=[f.id for f in hits],
            finding_severities=[f.severity for f in hits],
            rationale=rationale,
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

    return ComplianceReport(
        frameworks=fws,
        controls=controls_evidence,
        summary=summary,
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
