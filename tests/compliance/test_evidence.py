"""Unit tests for `strix.compliance.evidence`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.compliance.evidence import (
    VERDICT_FAIL,
    VERDICT_INFO,
    VERDICT_PASS,
    VERDICT_UNTESTED,
    VERDICT_WARN,
    build_evidence_report,
    write_compliance_evidence,
)
from strix.compliance.frameworks import (
    FRAMEWORK_OWASP_ASVS,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
)
from strix.finding_chains.chain import Finding


def _f(**kwargs) -> Finding:
    return Finding(
        id=kwargs.get("id", "f"),
        title=kwargs.get("title", "X"),
        category=kwargs.get("category", "sqli"),
        severity=kwargs.get("severity", "medium"),
        cwe=kwargs.get("cwe"),
        target=kwargs.get("target", ""),
        endpoint=kwargs.get("endpoint", ""),
        description=kwargs.get("description", ""),
        cve=kwargs.get("cve"),
        package=kwargs.get("package", ""),
        metadata=kwargs.get("metadata", {}),
    )


# ---------------------------------------------------------------------------
# Per-control verdict logic
# ---------------------------------------------------------------------------


def test_critical_finding_marks_control_fail() -> None:
    """A CWE-89 finding at critical severity → SOC 2 CC6.1
    verdict=fail."""
    findings = [_f(cwe="CWE-89", severity="critical")]
    report = build_evidence_report(findings)
    cc61 = next(
        c for c in report.controls
        if c.framework == FRAMEWORK_SOC2 and c.control_id == "CC6.1"
    )
    assert cc61.verdict == VERDICT_FAIL


def test_high_finding_marks_control_fail() -> None:
    findings = [_f(cwe="CWE-89", severity="high")]
    report = build_evidence_report(findings)
    cc61 = next(
        c for c in report.controls
        if c.framework == FRAMEWORK_SOC2 and c.control_id == "CC6.1"
    )
    assert cc61.verdict == VERDICT_FAIL


def test_medium_finding_marks_control_warn() -> None:
    findings = [_f(cwe="CWE-89", severity="medium")]
    report = build_evidence_report(findings)
    cc61 = next(
        c for c in report.controls
        if c.framework == FRAMEWORK_SOC2 and c.control_id == "CC6.1"
    )
    assert cc61.verdict == VERDICT_WARN


def test_low_finding_marks_control_warn() -> None:
    findings = [_f(cwe="CWE-89", severity="low")]
    report = build_evidence_report(findings)
    cc61 = next(
        c for c in report.controls
        if c.framework == FRAMEWORK_SOC2 and c.control_id == "CC6.1"
    )
    assert cc61.verdict == VERDICT_WARN


def test_info_only_finding_marks_control_info() -> None:
    findings = [_f(cwe="CWE-89", severity="info")]
    report = build_evidence_report(findings)
    cc61 = next(
        c for c in report.controls
        if c.framework == FRAMEWORK_SOC2 and c.control_id == "CC6.1"
    )
    assert cc61.verdict == VERDICT_INFO


def test_no_findings_marks_covered_control_pass() -> None:
    """A control covered by our rule corpus but with no
    findings during this run → pass."""
    report = build_evidence_report([])
    # CC6.1 is covered (CWE-79, CWE-89, CWE-94 etc. all map to it).
    cc61 = next(
        c for c in report.controls
        if c.framework == FRAMEWORK_SOC2 and c.control_id == "CC6.1"
    )
    assert cc61.verdict == VERDICT_PASS


def test_uncovered_control_marks_untested() -> None:
    """SOC 2 CC6.3 (access removal) isn't covered by our rule
    corpus — should appear as untested regardless of findings."""
    report = build_evidence_report([])
    cc63 = next(
        c for c in report.controls
        if c.framework == FRAMEWORK_SOC2 and c.control_id == "CC6.3"
    )
    assert cc63.verdict == VERDICT_UNTESTED


def test_max_severity_wins_when_control_hit_by_multiple_findings() -> None:
    """A control hit by both a high-sev finding AND a
    medium-sev finding should verdict=fail (max wins)."""
    findings = [
        _f(id="a", cwe="CWE-89", severity="medium"),
        _f(id="b", cwe="CWE-89", severity="high"),
        _f(id="c", cwe="CWE-89", severity="info"),
    ]
    report = build_evidence_report(findings)
    cc61 = next(
        c for c in report.controls
        if c.framework == FRAMEWORK_SOC2 and c.control_id == "CC6.1"
    )
    assert cc61.verdict == VERDICT_FAIL


# ---------------------------------------------------------------------------
# Cross-framework propagation
# ---------------------------------------------------------------------------


def test_one_finding_hits_all_mapped_frameworks() -> None:
    """A CWE-89 finding maps to SOC 2 CC6.1 + ISO 27001 A.8.26
    + PCI 6.5.1 + ASVS V5.3.4 — all four should record the hit."""
    report = build_evidence_report([_f(cwe="CWE-89", severity="high")])
    failures = {
        (c.framework, c.control_id) for c in report.controls
        if c.verdict == VERDICT_FAIL
    }
    expected = {
        (FRAMEWORK_SOC2, "CC6.1"),
        ("iso27001", "A.8.26"),
        (FRAMEWORK_PCI_DSS, "6.5.1"),
        (FRAMEWORK_OWASP_ASVS, "V5.3.4"),
    }
    assert expected <= failures


def test_summary_per_framework_counts_correctly() -> None:
    findings = [_f(cwe="CWE-89", severity="high")]
    report = build_evidence_report(findings)
    soc2_summary = report.summary[FRAMEWORK_SOC2]
    assert soc2_summary["fail"] >= 1
    assert "total" in soc2_summary


def test_finding_ids_listed_per_control() -> None:
    """The per-control evidence should reference the finding
    IDs that hit it — auditors trace from control → findings."""
    findings = [
        _f(id="finding-1", cwe="CWE-89", severity="high"),
        _f(id="finding-2", cwe="CWE-89", severity="medium"),
    ]
    report = build_evidence_report(findings)
    cc61 = next(
        c for c in report.controls
        if c.framework == FRAMEWORK_SOC2 and c.control_id == "CC6.1"
    )
    assert "finding-1" in cc61.finding_ids
    assert "finding-2" in cc61.finding_ids


def test_findings_ordered_severity_desc_per_control() -> None:
    """A control's findings should list highest-severity first
    so reviewers see the worst case at the top."""
    findings = [
        _f(id="low-1", cwe="CWE-89", severity="low"),
        _f(id="high-1", cwe="CWE-89", severity="high"),
        _f(id="medium-1", cwe="CWE-89", severity="medium"),
    ]
    report = build_evidence_report(findings)
    cc61 = next(
        c for c in report.controls
        if c.framework == FRAMEWORK_SOC2 and c.control_id == "CC6.1"
    )
    # high should come first.
    assert cc61.finding_ids[0] == "high-1"


# ---------------------------------------------------------------------------
# Framework subset
# ---------------------------------------------------------------------------


def test_framework_subset_filter() -> None:
    """`frameworks=['soc2']` should produce only SOC 2 controls."""
    report = build_evidence_report(
        [_f(cwe="CWE-89", severity="high")],
        frameworks=[FRAMEWORK_SOC2],
    )
    assert all(c.framework == FRAMEWORK_SOC2 for c in report.controls)
    assert report.frameworks == [FRAMEWORK_SOC2]


# ---------------------------------------------------------------------------
# Category-based mappings (CWE-less findings)
# ---------------------------------------------------------------------------


def test_vulnerable_dependency_without_cwe_maps_via_category() -> None:
    """SCA findings emit `category=vulnerable_dependency`
    without CWE. Should still map via category."""
    findings = [_f(
        category="vulnerable_dependency", cwe=None,
        severity="critical",
    )]
    report = build_evidence_report(findings)
    failures = {
        (c.framework, c.control_id) for c in report.controls
        if c.verdict == VERDICT_FAIL
    }
    # CC6.8 (malicious software) should fire.
    assert (FRAMEWORK_SOC2, "CC6.8") in failures


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def test_to_dict_round_trip(tmp_path: Path) -> None:
    findings = [_f(cwe="CWE-89", severity="high")]
    report = build_evidence_report(findings)
    d = report.to_dict()
    assert d["schema_version"] == 1
    assert d["frameworks"]
    assert d["controls"]
    assert d["summary"]
    # Round-trip through JSON.
    serialised = json.dumps(d)
    assert isinstance(serialised, str)


def test_write_compliance_evidence_creates_file(tmp_path: Path) -> None:
    findings = [_f(cwe="CWE-89", severity="high")]
    report = build_evidence_report(findings)
    out = tmp_path / "compliance_evidence.json"
    written = write_compliance_evidence(report, out)
    assert out.exists()
    doc = json.loads(out.read_text())
    assert doc["schema_version"] == 1


def test_write_creates_parent_dirs(tmp_path: Path) -> None:
    findings = []
    report = build_evidence_report(findings)
    out = tmp_path / "deep" / "nested" / "compliance.json"
    write_compliance_evidence(report, out)
    assert out.exists()
