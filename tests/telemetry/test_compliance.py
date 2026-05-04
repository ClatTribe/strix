"""Tests for compliance enrichment (roadmap §16).

Covers:
- enrich_finding_with_compliance: per-CWE control mapping
- data_classification inference (credentials / pci / phi / pii / internal / confidential)
- build_compliance_posture: defaults, env overrides, cadence_status
- Tracer integration: compliance fields auto-attached to findings
- run_meta.json contains compliance_posture
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import compliance, tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_AUDIT_LOG_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("STRIX_SCAN_CADENCE_DAYS", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


# ---------------------------------------------------------------------------
# enrich_finding_with_compliance: control mapping
# ---------------------------------------------------------------------------


def test_sqli_maps_to_pci_owasp_iso() -> None:
    out = compliance.enrich_finding_with_compliance({
        "cwe": "CWE-89", "title": "SQLi", "category": "sql_injection",
    })
    controls = out["compliance_controls"]
    assert "6.5.1" in controls["pci_dss"]
    assert "A03:2021" in controls["owasp"]
    assert "A.14.2.5" in controls["iso_27001"]
    assert "CC6.6" in controls["soc2"]


def test_csrf_maps_to_pci_owasp() -> None:
    out = compliance.enrich_finding_with_compliance({
        "cwe": "CWE-352", "category": "csrf",
    })
    controls = out["compliance_controls"]
    assert "6.5.9" in controls["pci_dss"]
    assert "A01:2021" in controls["owasp"]


def test_weak_crypto_maps_to_hipaa_gdpr() -> None:
    out = compliance.enrich_finding_with_compliance({
        "cwe": "CWE-326", "category": "weak_crypto",
    })
    controls = out["compliance_controls"]
    assert "164.312(a)(2)(iv)" in controls["hipaa"]
    assert "Art.32" in controls["gdpr"]


def test_kev_maps_to_si2_pci() -> None:
    out = compliance.enrich_finding_with_compliance({
        "cwe": "CWE-1395", "category": "vulnerable_software",
    })
    controls = out["compliance_controls"]
    assert "SI-2" in controls["nist_800_53"]
    assert "6.2" in controls["pci_dss"]


def test_unknown_cwe_no_controls() -> None:
    out = compliance.enrich_finding_with_compliance({
        "cwe": "CWE-9999", "category": "x",
    })
    assert "compliance_controls" not in out


def test_no_cwe_no_controls() -> None:
    out = compliance.enrich_finding_with_compliance({"category": "x"})
    assert "compliance_controls" not in out


def test_static_map_immutable() -> None:
    """Mutating returned controls must not affect the static map."""
    out1 = compliance.enrich_finding_with_compliance({"cwe": "CWE-89"})
    out1["compliance_controls"]["pci_dss"].append("MUTATED")
    out2 = compliance.enrich_finding_with_compliance({"cwe": "CWE-89"})
    assert "MUTATED" not in out2["compliance_controls"]["pci_dss"]


# ---------------------------------------------------------------------------
# data_classification inference
# ---------------------------------------------------------------------------


def test_credentials_classification_from_category() -> None:
    out = compliance.enrich_finding_with_compliance({
        "category": "exposed_secret", "cwe": "CWE-200",
    })
    assert out["data_classification"] == "credentials"


def test_credentials_from_jwt() -> None:
    out = compliance.enrich_finding_with_compliance({
        "category": "jwt_misconfiguration", "cwe": "CWE-347",
    })
    assert out["data_classification"] == "credentials"


def test_credentials_from_session() -> None:
    out = compliance.enrich_finding_with_compliance({
        "category": "weak_session_id", "cwe": "CWE-330",
    })
    assert out["data_classification"] == "credentials"


def test_pci_classification() -> None:
    out = compliance.enrich_finding_with_compliance({
        "category": "card_data_leak", "cwe": "CWE-200",
    })
    assert out["data_classification"] == "pci"


def test_phi_classification() -> None:
    out = compliance.enrich_finding_with_compliance({
        "title": "HIPAA medical record exposure", "cwe": "CWE-200",
    })
    assert out["data_classification"] == "phi"


def test_pii_classification_email() -> None:
    out = compliance.enrich_finding_with_compliance({
        "title": "Email address disclosure", "cwe": "CWE-200",
    })
    assert out["data_classification"] == "pii"


def test_information_disclosure_internal() -> None:
    out = compliance.enrich_finding_with_compliance({
        "category": "information_disclosure", "cwe": "CWE-200",
    })
    assert out["data_classification"] == "internal"


def test_default_internal_no_match() -> None:
    """A finding without keyword hits AND without a CVE defaults to
    `internal`. CSRF intentionally matches `credentials` because the
    word `token` is in the title (CSRF tokens ARE credentials). To
    test the no-match path we use a finding that doesn't trigger any
    classifier."""
    out = compliance.enrich_finding_with_compliance({
        "category": "race_condition", "cwe": "CWE-362",
        "title": "Race in /api/redeem",
    })
    assert out["data_classification"] == "internal"


def test_cve_finding_default_confidential() -> None:
    """A finding with a CVE but no matching classification rule
    defaults to `confidential`."""
    out = compliance.enrich_finding_with_compliance({
        "category": "vulnerable_dependency", "cwe": "CWE-1395",
        "cve": "CVE-2024-12345",
        "title": "log4shell still installed",
    })
    assert out["data_classification"] == "confidential"


# ---------------------------------------------------------------------------
# build_compliance_posture
# ---------------------------------------------------------------------------


def test_compliance_posture_defaults() -> None:
    posture = compliance.build_compliance_posture()
    assert posture["audit_log_retention_days"] == 90
    assert posture["cadence_required_days"] == 90
    # No days_since_last_scan supplied → cadence_status absent
    assert "cadence_status" not in posture


def test_compliance_posture_env_overrides(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_AUDIT_LOG_RETENTION_DAYS", "365")
    monkeypatch.setenv("STRIX_SCAN_CADENCE_DAYS", "30")
    posture = compliance.build_compliance_posture()
    assert posture["audit_log_retention_days"] == 365
    assert posture["cadence_required_days"] == 30


def test_compliance_posture_in_compliance() -> None:
    posture = compliance.build_compliance_posture(
        cadence_required_days=90, days_since_last_scan=10,
    )
    assert posture["cadence_status"] == "in_compliance"
    assert posture["days_since_last_scan"] == 10


def test_compliance_posture_overdue() -> None:
    posture = compliance.build_compliance_posture(
        cadence_required_days=90, days_since_last_scan=120,
    )
    assert posture["cadence_status"] == "overdue"


def test_compliance_posture_invalid_env(monkeypatch) -> None:
    """Garbage env values fall back to defaults."""
    monkeypatch.setenv("STRIX_AUDIT_LOG_RETENTION_DAYS", "not-a-number")
    posture = compliance.build_compliance_posture()
    assert posture["audit_log_retention_days"] == 90


def test_compliance_posture_negative_clamped() -> None:
    posture = compliance.build_compliance_posture(
        audit_log_retention_days=-5, cadence_required_days=-1,
    )
    assert posture["audit_log_retention_days"] >= 1
    assert posture["cadence_required_days"] >= 1


# ---------------------------------------------------------------------------
# Tracer integration: enrichment lands on findings
# ---------------------------------------------------------------------------


def test_tracer_attaches_compliance_controls() -> None:
    tracer = Tracer("compliance-1")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    tracer.add_vulnerability_report(
        title="SQLi",
        severity="high",
        category="sql_injection",
        cwe="CWE-89",
        endpoint="https://app.example.com/api/users",
        verification_status="verified",
        description_plain="p", recommended_action="a",
    )
    findings = tracer.get_existing_vulnerabilities()
    f = findings[0]
    assert "compliance_controls" in f
    assert "6.5.1" in f["compliance_controls"]["pci_dss"]
    assert "data_classification" in f


def test_tracer_attaches_credentials_classification_for_jwt() -> None:
    tracer = Tracer("compliance-2")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    tracer.add_vulnerability_report(
        title="JWT alg=none accepted",
        severity="critical",
        category="jwt_misconfiguration",
        cwe="CWE-347",
        endpoint="https://api.example.com/v1/profile",
        verification_status="verified",
        description_plain="p", recommended_action="a",
    )
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["data_classification"] == "credentials"


# ---------------------------------------------------------------------------
# run_meta.json contains compliance_posture
# ---------------------------------------------------------------------------


def test_run_meta_includes_compliance_posture(tmp_path) -> None:
    tracer = Tracer("compliance-runmeta")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})
    tracer.final_scan_result = "Done."
    tracer.save_run_data(mark_complete=True)

    meta_path = tracer.get_run_dir() / "run_meta.json"
    assert meta_path.exists()
    data = json.loads(meta_path.read_text())
    posture = data.get("compliance_posture")
    assert posture is not None
    assert posture["audit_log_retention_days"] == 90
    assert posture["cadence_required_days"] == 90


def test_run_meta_compliance_posture_respects_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("STRIX_AUDIT_LOG_RETENTION_DAYS", "180")
    tracer = Tracer("compliance-runmeta-env")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})
    tracer.save_run_data(mark_complete=True)

    meta_path = tracer.get_run_dir() / "run_meta.json"
    data = json.loads(meta_path.read_text())
    assert data["compliance_posture"]["audit_log_retention_days"] == 180


# ---------------------------------------------------------------------------
# list_known_cwes for introspection
# ---------------------------------------------------------------------------


def test_list_known_cwes() -> None:
    cwes = compliance.list_known_cwes()
    assert isinstance(cwes, list)
    assert "CWE-89" in cwes
    assert "CWE-352" in cwes
    assert cwes == sorted(cwes)


# ---------------------------------------------------------------------------
# Coverage breadth — common CWEs from the §10 / §7.2 PRs all map
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cwe", [
    "CWE-89", "CWE-79", "CWE-352", "CWE-942", "CWE-918",
    "CWE-22", "CWE-77", "CWE-200", "CWE-326", "CWE-330",
    "CWE-269", "CWE-285", "CWE-287", "CWE-353", "CWE-444",
    "CWE-525", "CWE-434", "CWE-915", "CWE-345", "CWE-347",
    "CWE-362", "CWE-613", "CWE-1236", "CWE-1395", "CWE-693",
    "CWE-20", "CWE-453", "CWE-209", "CWE-611", "CWE-94",
    "CWE-78", "CWE-918", "CWE-327", "CWE-1104",
])
def test_recent_pr_cwes_all_have_at_least_one_control(cwe) -> None:
    out = compliance.enrich_finding_with_compliance({"cwe": cwe})
    assert "compliance_controls" in out, f"{cwe} not mapped"
    controls = out["compliance_controls"]
    # At least one framework has at least one control.
    assert any(controls.get(fw) for fw in ("soc2", "pci_dss", "iso_27001",
                                            "nist_800_53", "owasp", "hipaa", "gdpr", "cis"))
