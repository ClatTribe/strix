"""Tests for vendor-risk score derivation (roadmap §16 / PR #133)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.telemetry.vendor_risk import compute_vendor_risk_score


# ---------------------------------------------------------------------------
# Pure function: scoring math
# ---------------------------------------------------------------------------


def test_no_findings_max_score() -> None:
    out = compute_vendor_risk_score([])
    assert out["score"] == 100
    assert out["band"] == "low_risk"
    assert out["band_label"].startswith("Low risk")
    assert out["findings_total"] == 0
    assert out["highest_severity_observed"] is None
    assert "onboard" in out["recommendation"].lower()


def test_single_low_finding_minimal_deduction() -> None:
    findings = [{"severity": "low", "category": "info_disclosure"}]
    out = compute_vendor_risk_score(findings)
    # low × 1.0 multiplier = 1 deduction.
    assert out["score"] == 99
    assert out["band"] == "low_risk"


def test_critical_hardcoded_secret_max_deduction() -> None:
    """Critical secret: 18 × 3.0 multiplier = 54 deduction → score 46 → high_risk."""
    findings = [
        {"severity": "critical", "category": "hardcoded_secret"},
    ]
    out = compute_vendor_risk_score(findings)
    assert out["score"] == 46
    assert out["band"] == "high_risk"
    assert "hardcoded_secret" in out["deductions_by_category"]
    assert out["deductions_by_category"]["hardcoded_secret"] == 54.0


def test_score_floors_at_zero() -> None:
    """Pile up enough findings to drive the score below 0 — must
    floor at 0, not go negative."""
    findings = [
        {"severity": "critical", "category": "hardcoded_secret"} for _ in range(10)
    ]
    out = compute_vendor_risk_score(findings)
    assert out["score"] == 0
    assert out["band"] == "high_risk"


def test_info_findings_contribute_zero() -> None:
    findings = [{"severity": "info", "category": "legal_documents"}] * 50
    out = compute_vendor_risk_score(findings)
    assert out["score"] == 100
    # Counts still tracked.
    assert out["counts_by_severity"]["info"] == 50


def test_band_boundaries() -> None:
    """80 = low_risk; 79 = medium_risk; 60 = medium_risk; 59 = high_risk."""
    # Construct findings to land exactly at each boundary.
    # 1 medium + 4 multiplier = 4 deduction → 96 → low
    out_96 = compute_vendor_risk_score([
        {"severity": "medium", "category": "info_disclosure"},
    ])
    assert out_96["band"] == "low_risk"

    # 5 high × 1.5 (mfa multiplier) = 75 deduction → 25 → high_risk
    out_25 = compute_vendor_risk_score([
        {"severity": "high", "category": "mfa_attestation"} for _ in range(5)
    ])
    assert out_25["band"] == "high_risk"

    # 1 medium + 1 high (no multiplier categories) = 4 + 10 = 14 → 86 → low
    out_86 = compute_vendor_risk_score([
        {"severity": "medium", "category": "uncategorised"},
        {"severity": "high", "category": "uncategorised"},
    ])
    assert out_86["band"] == "low_risk"


def test_category_multiplier_amplifies_deduction() -> None:
    """Same severity, different category multipliers → different scores."""
    out_secret = compute_vendor_risk_score([
        {"severity": "high", "category": "hardcoded_secret"},
    ])
    out_other = compute_vendor_risk_score([
        {"severity": "high", "category": "uncategorised"},
    ])
    # Secret: high (10) × 3.0 = 30 deduction → 70.
    # Other: high (10) × 1.0 = 10 deduction → 90.
    assert out_secret["score"] == 70
    assert out_other["score"] == 90


def test_breakdown_by_category_and_severity() -> None:
    findings = [
        {"severity": "high", "category": "hardcoded_secret"},
        {"severity": "medium", "category": "tls_audit"},
        {"severity": "low", "category": "uncategorised"},
    ]
    out = compute_vendor_risk_score(findings)
    assert out["counts_by_category"]["hardcoded_secret"] == 1
    assert out["counts_by_category"]["tls_audit"] == 1
    assert out["counts_by_severity"]["high"] == 1
    assert out["counts_by_severity"]["medium"] == 1
    assert out["counts_by_severity"]["low"] == 1
    # Highest severity tracked.
    assert out["highest_severity_observed"] == "high"


def test_recommendation_calls_out_top_category() -> None:
    findings = [
        {"severity": "critical", "category": "hardcoded_secret"} for _ in range(3)
    ]
    out = compute_vendor_risk_score(findings)
    # 3 critical × 18 × 3.0 = 162 → floored at 0 → high_risk
    assert out["band"] == "high_risk"
    assert "hardcoded_secret" in out["recommendation"]


def test_unknown_severity_ignored() -> None:
    """Garbage severity value is treated as 0 deduction."""
    findings = [{"severity": "extreme", "category": "x"}]
    out = compute_vendor_risk_score(findings)
    assert out["score"] == 100


def test_uncategorised_uses_default_multiplier() -> None:
    findings = [{"severity": "high"}]  # no category
    out = compute_vendor_risk_score(findings)
    # default multiplier 1.0 → 10 deduction.
    assert out["score"] == 90


def test_schema_keys() -> None:
    out = compute_vendor_risk_score([])
    assert set(out.keys()) >= {
        "schema_version", "score", "band", "band_label",
        "total_deduction",
        "deductions_by_category", "deductions_by_severity",
        "counts_by_severity", "counts_by_category",
        "findings_total", "highest_severity_observed",
        "recommendation",
    }


# ---------------------------------------------------------------------------
# Tracer integration: vendor_risk lands in run_meta.json
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


def test_vendor_risk_in_run_meta(monkeypatch, tmp_path) -> None:
    tracer = Tracer("vendor-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["https://example.com"]})

    # Add a couple findings.
    tracer.add_vulnerability_report(
        title="High severity", severity="high", category="hardcoded_secret",
        cwe="CWE-798", endpoint="/x",
    )
    tracer.add_vulnerability_report(
        title="Low", severity="low", category="info_disclosure",
        cwe="CWE-200", endpoint="/y",
    )

    tracer.save_run_data(mark_complete=True)

    meta_file = tmp_path / "strix_runs" / "vendor-test" / "run_meta.json"
    meta = json.loads(meta_file.read_text())
    assert "vendor_risk" in meta
    block = meta["vendor_risk"]
    assert block["schema_version"] == 1
    # high (10) × 3.0 = 30; low (1) × 1.0 = 1; → 31 deducted → 69 → medium_risk
    assert block["score"] == 69
    assert block["band"] == "medium_risk"
    assert block["findings_total"] == 2


def test_vendor_risk_clean_run_emits_max_score(monkeypatch, tmp_path) -> None:
    """No findings → score 100, low_risk."""
    tracer = Tracer("vendor-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["https://example.com"]})
    tracer.save_run_data(mark_complete=True)

    meta_file = tmp_path / "strix_runs" / "vendor-test" / "run_meta.json"
    meta = json.loads(meta_file.read_text())
    assert meta["vendor_risk"]["score"] == 100
    assert meta["vendor_risk"]["band"] == "low_risk"
