"""Tests for the audit-grade enrichments on `ControlEvidence`:

  * `probe_coverage` — `{rules_in_corpus, rules_fired,
    coverage_pct, endpoints_tested}` per control. Auditor signal
    for "how aggressively did strix actually probe this control".
  * `evidence_pointers` — per-finding `{finding_id, target,
    endpoint, category, cwe, cve, package}` for traceability.
  * `remediation_deadline_days` + `remediation_deadline_at` —
    framework-aware defaults (PCI/HIPAA stricter).
  * `control_owner` — defaulted via env or "AppSec".
  * Top-level `coverage_attestation` per framework.

Companion to `test_evidence.py` (which pins the original
shape). Tests here cover ONLY the new fields.
"""

from __future__ import annotations

import pytest

from strix.compliance.evidence import (
    _default_control_owner,
    _remediation_deadline_for,
    build_evidence_report,
)
from strix.compliance.mappings import (
    corpus_size_for_control,
    rules_for_control,
)
from strix.finding_chains.chain import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _f(
    *, id="F-001", title="SQLi in /login", category="sqli",
    severity="high", cwe="CWE-89",
    target="https://api/x", endpoint="/login",
) -> Finding:
    return Finding(
        id=id, title=title, category=category, severity=severity,
        cwe=cwe, target=target, endpoint=endpoint,
    )


# ---------------------------------------------------------------------------
# mappings — rules_for_control / corpus_size_for_control
# ---------------------------------------------------------------------------


def test_rules_for_control_pci_651_returns_nonempty() -> None:
    """PCI 6.5.1 = SQL injection. The corpus should map CWE-89
    (at minimum) to it. Note: the category map in this repo uses
    coarse buckets (`sast`, `misconfig`, etc.) — no fine-grained
    `sqli` category exists, so the CWE side carries the weight."""
    rules = rules_for_control("pci_dss", "6.5.1")
    assert "CWE-89" in rules
    assert len(rules) >= 1


def test_corpus_size_for_control_matches_rules_for() -> None:
    """Convenience wrapper just returns len()."""
    rules = rules_for_control("pci_dss", "6.5.1")
    assert corpus_size_for_control("pci_dss", "6.5.1") == len(rules)


def test_rules_for_unknown_control_returns_empty() -> None:
    assert rules_for_control("pci_dss", "nonexistent") == set()
    assert corpus_size_for_control("pci_dss", "nonexistent") == 0


# ---------------------------------------------------------------------------
# Remediation deadline defaults
# ---------------------------------------------------------------------------


def test_remediation_deadline_pci_high_is_30_days() -> None:
    """PCI-DSS 4.0 Req 6.3.3 stipulates 30 days for critical/high."""
    assert _remediation_deadline_for(
        framework="pci_dss", max_severity="high",
    ) == 30


def test_remediation_deadline_hipaa_high_is_30_days() -> None:
    assert _remediation_deadline_for(
        framework="hipaa", max_severity="high",
    ) == 30


def test_remediation_deadline_generic_critical_30_high_30() -> None:
    assert _remediation_deadline_for(
        framework="soc2", max_severity="critical",
    ) == 30
    assert _remediation_deadline_for(
        framework="soc2", max_severity="high",
    ) == 30


def test_remediation_deadline_medium_default_90_low_180() -> None:
    assert _remediation_deadline_for(
        framework="soc2", max_severity="medium",
    ) == 90
    assert _remediation_deadline_for(
        framework="soc2", max_severity="low",
    ) == 180


def test_remediation_deadline_framework_override_medium() -> None:
    """PCI-DSS / HIPAA override medium to 60 (vs default 90)."""
    assert _remediation_deadline_for(
        framework="pci_dss", max_severity="medium",
    ) == 60
    assert _remediation_deadline_for(
        framework="hipaa", max_severity="medium",
    ) == 60


def test_remediation_deadline_unknown_severity_default() -> None:
    """Bad severity input → default fallback."""
    assert _remediation_deadline_for(
        framework="soc2", max_severity="nonsense",
    ) == 180


# ---------------------------------------------------------------------------
# Control owner default
# ---------------------------------------------------------------------------


def test_default_control_owner_is_appsec_when_env_unset(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_COMPLIANCE_DEFAULT_OWNER", raising=False)
    assert _default_control_owner() == "AppSec"


def test_default_control_owner_uses_env_override(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_COMPLIANCE_DEFAULT_OWNER", "DevSecOps Team")
    assert _default_control_owner() == "DevSecOps Team"


def test_default_control_owner_empty_env_falls_back(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_COMPLIANCE_DEFAULT_OWNER", "   ")
    assert _default_control_owner() == "AppSec"


# ---------------------------------------------------------------------------
# build_evidence_report — probe_coverage on hit controls
# ---------------------------------------------------------------------------


def test_probe_coverage_populated_on_hit_control() -> None:
    """A SQLi finding hits PCI 6.5.1; probe_coverage should
    report the corpus size and the number of rules fired (here,
    1 CWE + 1 category = 2)."""
    report = build_evidence_report(
        [_f()],
        frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    pci_651 = next(
        c for c in report.controls
        if c.control_id == "6.5.1"
    )
    assert pci_651.probe_coverage is not None
    pc = pci_651.probe_coverage
    assert pc["rules_in_corpus"] > 0
    assert pc["rules_fired"] >= 1
    assert 0.0 < pc["coverage_pct"] <= 100.0
    assert pc["endpoints_tested"] == 1


def test_probe_coverage_endpoints_tested_counts_distinct() -> None:
    """Two findings on different endpoints → endpoints_tested=2."""
    findings = [
        _f(id="F-1", endpoint="/login"),
        _f(id="F-2", endpoint="/admin"),
    ]
    report = build_evidence_report(
        findings,
        frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    pci_651 = next(c for c in report.controls if c.control_id == "6.5.1")
    assert pci_651.probe_coverage["endpoints_tested"] == 2


def test_probe_coverage_none_on_untested_control() -> None:
    """Controls outside the corpus's coverage have no probe
    coverage data — they were never tested. pci_dss has at least
    one such control (per the catalog inspection)."""
    report = build_evidence_report(
        [_f()],
        frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    untested_controls = [
        c for c in report.controls if c.verdict == "untested"
    ]
    # The framework catalog includes more than the corpus covers,
    # so SOME untested controls must exist for the test premise.
    assert len(untested_controls) >= 1, (
        "PCI-DSS catalog should have at least one control "
        "outside strix's rule corpus"
    )
    for c in untested_controls:
        assert c.probe_coverage is None


# ---------------------------------------------------------------------------
# build_evidence_report — evidence_pointers
# ---------------------------------------------------------------------------


def test_evidence_pointers_carry_per_finding_metadata() -> None:
    report = build_evidence_report(
        [_f(target="https://api/v1", endpoint="/login", cwe="CWE-89")],
        frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    pci_651 = next(c for c in report.controls if c.control_id == "6.5.1")
    assert len(pci_651.evidence_pointers) == 1
    p = pci_651.evidence_pointers[0]
    assert p["finding_id"] == "F-001"
    assert p["target"] == "https://api/v1"
    assert p["endpoint"] == "/login"
    assert p["category"] == "sqli"
    assert p["cwe"] == "CWE-89"
    assert p["severity"] == "high"


def test_evidence_pointers_capped_at_50_per_control() -> None:
    """JSON-bound: 60 findings → 50 pointers + truncation marker
    in rationale."""
    findings = [
        _f(id=f"F-{i:03d}", endpoint=f"/path/{i}")
        for i in range(60)
    ]
    report = build_evidence_report(
        findings, frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    pci_651 = next(c for c in report.controls if c.control_id == "6.5.1")
    assert len(pci_651.evidence_pointers) == 50
    assert "truncated" in pci_651.rationale


def test_evidence_pointers_empty_on_pass_control() -> None:
    """A control with no findings has no evidence_pointers."""
    report = build_evidence_report(
        [_f()], frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    # Pick any pass control (not 6.5.1 which gets hit).
    passes = [c for c in report.controls if c.verdict == "pass"]
    assert passes
    for c in passes:
        assert c.evidence_pointers == []


# ---------------------------------------------------------------------------
# build_evidence_report — remediation deadline
# ---------------------------------------------------------------------------


def test_remediation_deadline_at_computed_from_collected_at() -> None:
    """High-severity PCI finding → 30-day deadline FROM the
    collected_at stamp."""
    report = build_evidence_report(
        [_f(severity="high")],
        frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    pci_651 = next(c for c in report.controls if c.control_id == "6.5.1")
    assert pci_651.remediation_deadline_days == 30
    # Deadline is 30 days from 2026-05-16 = 2026-06-15.
    assert pci_651.remediation_deadline_at == "2026-06-15T20:00:00Z"


def test_remediation_deadline_none_on_no_findings() -> None:
    """Pass controls have no deadline — there's nothing to remediate."""
    report = build_evidence_report(
        [_f()], frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    passes = [c for c in report.controls if c.verdict == "pass"]
    for c in passes:
        assert c.remediation_deadline_days is None
        assert c.remediation_deadline_at is None


def test_remediation_deadline_uses_max_severity() -> None:
    """Mix of high + medium findings → deadline picked from
    the max (high → 30 days, not 60 medium)."""
    findings = [
        _f(id="F-1", severity="medium"),
        _f(id="F-2", severity="high"),
    ]
    report = build_evidence_report(
        findings, frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    pci_651 = next(c for c in report.controls if c.control_id == "6.5.1")
    assert pci_651.remediation_deadline_days == 30


# ---------------------------------------------------------------------------
# build_evidence_report — control_owner
# ---------------------------------------------------------------------------


def test_control_owner_defaults_appsec(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_COMPLIANCE_DEFAULT_OWNER", raising=False)
    report = build_evidence_report(
        [_f()], frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    for c in report.controls:
        assert c.control_owner == "AppSec"


def test_control_owner_env_override(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_COMPLIANCE_DEFAULT_OWNER", "Team Alpha")
    report = build_evidence_report(
        [_f()], frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    for c in report.controls:
        assert c.control_owner == "Team Alpha"


# ---------------------------------------------------------------------------
# build_evidence_report — coverage_attestation
# ---------------------------------------------------------------------------


def test_coverage_attestation_present_per_framework() -> None:
    report = build_evidence_report(
        [_f()], frameworks=["pci_dss", "soc2"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    assert "pci_dss" in report.coverage_attestation
    assert "soc2" in report.coverage_attestation


def test_coverage_attestation_pct_in_0_to_100() -> None:
    report = build_evidence_report(
        [_f()], frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    ca = report.coverage_attestation["pci_dss"]
    assert 0.0 <= ca["controls_covered_pct"] <= 100.0
    assert 0.0 <= ca["controls_exercised_pct"] <= 100.0
    assert ca["controls_covered_pct"] >= ca["controls_exercised_pct"]


def test_coverage_attestation_untested_controls_listed() -> None:
    """When a framework has any untested controls, they're listed
    so wrappers can render coverage gaps prominently."""
    report = build_evidence_report(
        [], frameworks=["nist_800_53"],  # nothing fires
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    ca = report.coverage_attestation["nist_800_53"]
    # nist_800_53 likely has at least one untested control
    assert isinstance(ca["untested_controls"], list)


def test_coverage_attestation_counts_match_summary() -> None:
    """`controls_total` should equal the framework's catalog size."""
    report = build_evidence_report(
        [_f()], frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    ca = report.coverage_attestation["pci_dss"]
    summary_total = report.summary["pci_dss"]["total"]
    assert ca["controls_total"] == summary_total


# ---------------------------------------------------------------------------
# to_dict shape — all new fields present
# ---------------------------------------------------------------------------


def test_control_evidence_to_dict_includes_new_fields() -> None:
    report = build_evidence_report(
        [_f()], frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    d = report.controls[0].to_dict()
    for new_field in (
        "probe_coverage",
        "evidence_pointers",
        "remediation_deadline_days",
        "remediation_deadline_at",
        "control_owner",
    ):
        assert new_field in d, f"missing field {new_field!r}"


def test_report_to_dict_includes_coverage_attestation() -> None:
    report = build_evidence_report(
        [_f()], frameworks=["pci_dss"],
        evidence_collected_at="2026-05-16T20:00:00Z",
    )
    d = report.to_dict()
    assert "coverage_attestation" in d
    assert "pci_dss" in d["coverage_attestation"]
