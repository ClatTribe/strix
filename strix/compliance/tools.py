"""LLM-facing compliance-evidence specialist (`emit_compliance_evidence`).

Reads emitted findings (from `vulnerabilities.json` or a caller-
supplied list), maps each to compliance controls via CWE +
category, builds the per-control rollup, and writes
`compliance_evidence.json` next to the input.

Like `correlate_findings`, this is a post-scan step. The lead
should invoke it (per the system-prompt addendum) before
calling `finish_scan`.

Pure Python, deterministic, no LLM cost. ~ms on typical
volumes.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from strix.compliance.evidence import (
    build_evidence_report,
    write_compliance_evidence,
)
from strix.compliance.frameworks import ALL_FRAMEWORKS
from strix.finding_chains.normalise import normalise_findings
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


def _default_findings_path() -> Path:
    run_dir = os.environ.get("STRIX_RUN_DIR")
    if run_dir:
        return Path(run_dir) / "vulnerabilities.json"
    return Path.cwd() / "vulnerabilities.json"


def _default_output_path(findings_path: Path) -> Path:
    return findings_path.parent / "compliance_evidence.json"


def _load_findings(findings_path: Path) -> list:
    """Same shape-tolerance as `correlate_findings`'s loader."""
    if not findings_path.exists():
        return []
    try:
        doc = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("compliance: load failed for %s: %s",
                     findings_path, e)
        return []
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        if isinstance(doc.get("findings"), list):
            return doc["findings"]
        if isinstance(doc.get("vulnerabilities"), list):
            return doc["vulnerabilities"]
    return []


@register_specialist_tool(
    category="compliance-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 30},
    sandbox_execution=False,
    provenance="framework",
)
def emit_compliance_evidence(
    *,
    findings_path: str | None = None,
    output_path: str | None = None,
    frameworks: list[str] | None = None,
) -> SpecialistResult:
    """Read emitted findings, map to compliance controls, write
    `compliance_evidence.json` artifact.

    Args:
        findings_path: path to `vulnerabilities.json` or similar.
            Default: `STRIX_RUN_DIR/vulnerabilities.json` (or
            `cwd/vulnerabilities.json`).
        output_path: where to write `compliance_evidence.json`.
            Default: same dir as `findings_path`.
        frameworks: subset to report on. Default: all 4
            (SOC 2, ISO 27001, PCI DSS, OWASP ASVS).

    Per-control verdict logic:
      * `fail`     — at least one finding at high or critical
      * `warn`     — at least one finding at low or medium
      * `info`     — only info-severity findings hit it
      * `pass`     — control is in our corpus's coverage but no
                     findings hit it
      * `untested` — control isn't covered by any rule in our
                     corpus (a coverage gap)

    Returns:
        SpecialistResult. Per-failed-control draft so the lead
        sees them (severity propagated from the verdict). Plus
        `tool_metadata` with the per-framework rollup for the
        wrapper.
    """
    in_path = (
        Path(findings_path).expanduser() if findings_path
        else _default_findings_path()
    )
    out_path = (
        Path(output_path).expanduser() if output_path
        else _default_output_path(in_path)
    )

    fws = frameworks if frameworks else list(ALL_FRAMEWORKS)
    invalid = [f for f in fws if f not in ALL_FRAMEWORKS]
    if invalid:
        return SpecialistResult(
            status="error",
            error=(
                f"unknown framework(s): {invalid}. Available: "
                f"{ALL_FRAMEWORKS}."
            ),
        )

    raw = _load_findings(in_path)
    findings = normalise_findings(raw) if raw else []

    # Build the report. Even with zero findings, we still emit
    # a useful artifact: every control is "pass" (covered) or
    # "untested" (gap). The wrapper renders coverage state.
    report = build_evidence_report(findings, frameworks=fws)

    written_path: str | None = None
    try:
        written_path = str(write_compliance_evidence(report, out_path))
    except OSError as e:
        logger.debug("compliance: write failed: %s", e)

    drafts: list[FindingDraft] = []
    evidence: list[str] = []

    # Surface failed + warned controls as findings so the lead
    # sees them in its result loop. Pass / info / untested
    # controls don't bubble up — they're informational, the
    # wrapper renders them from the artifact directly.
    for c in report.controls:
        if c.verdict not in ("fail", "warn"):
            continue
        sev = "high" if c.verdict == "fail" else "medium"
        drafts.append(FindingDraft(
            title=(
                f"[compliance:{c.framework}:{c.control_id}] "
                f"{c.title} ({c.verdict.upper()})"
            )[:480],
            severity=sev,
            cwe=None,
            endpoint="",
            category="compliance_violation",
            verification_status="verified",
            confidence=0.9,
            description=c.rationale[:480],
        ))
        evidence.append(
            f"control {c.fqid}: {c.verdict.upper()} "
            f"({len(c.finding_ids)} findings)"
        )

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            [
                "review failed controls first (verdict=fail) — "
                "those are SOC 2 / ISO 27001 / PCI / ASVS "
                "controls with at least one high or critical "
                "finding tied to them",
                "for `untested` controls, surface them to the "
                "customer's compliance lead — these are coverage "
                "gaps strix's rule corpus doesn't address; the "
                "customer needs other tooling (cloud-config "
                "scanner, manual review, etc.) to validate them",
                "compliance_evidence.json sits next to "
                "vulnerabilities.json + finding_chains.json — the "
                "wrapper renders all three for the auditor "
                "handoff",
            ]
            if drafts else
            [
                "no failed or warned controls. Either the scan "
                "produced no findings that map to compliance "
                "controls, OR every finding's controls were "
                "info-severity. Check `untested` count — gaps "
                "to flag to the customer.",
            ]
        ),
        tool_metadata={
            "findings_path": str(in_path),
            "findings_loaded": len(raw),
            "findings_normalised": len(findings),
            "frameworks": fws,
            "evidence_path": written_path,
            "summary": report.summary,
            "total_controls": len(report.controls),
        },
    )
