"""Tests for GRC-platform export renderers (roadmap §16 / PR #130)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry.grc_export import (
    SUPPORTED_PLATFORMS,
    export_for_platform,
    write_export,
)


def _run_metadata() -> dict[str, Any]:
    return {
        "run_id": "rid-001",
        "run_name": "rid-001",
        "scan_mode": "deep",
        "scope_mode": "full",
        "targets": [{"type": "web_application", "value": "https://example.com"}],
    }


def _findings() -> list[dict[str, Any]]:
    return [
        {
            "id": "v-001",
            "title": "SQL injection",
            "severity": "high",
            "category": "sql_injection",
            "cwe": "CWE-89",
            "cve": None,
            "verification_status": "verified",
            "is_kev": False,
            "target": "https://example.com",
            "endpoint": "/api/users",
            "description": "SQLi in users API.",
            "recommended_action": "Use parameterized queries.",
            "timestamp": "2026-05-04T00:00:00+00:00",
            "data_classification": "pii",
            "compliance_controls": {
                "soc2": ["CC6.1"],
                "pci_dss": ["6.5.1"],
                "iso_27001": ["A.14.2.5"],
            },
        },
        {
            "id": "v-002",
            "title": "XSS",
            "severity": "medium",
            "category": "xss",
            "cwe": "CWE-79",
            "verification_status": "pattern_match",
            "is_kev": True,
            "target": "https://example.com",
            "endpoint": "/search",
            "description": "Reflected XSS.",
            "recommended_action": "Encode output.",
            "timestamp": "2026-05-04T00:01:00+00:00",
            "compliance_controls": {
                "soc2": ["CC6.1"],
            },
        },
    ]


# ---------------------------------------------------------------------------
# Supported platforms
# ---------------------------------------------------------------------------


def test_supported_platforms_advertised() -> None:
    assert "vanta" in SUPPORTED_PLATFORMS
    assert "drata" in SUPPORTED_PLATFORMS
    assert "hyperproof" in SUPPORTED_PLATFORMS
    assert "secureframe" in SUPPORTED_PLATFORMS
    assert "servicenow" in SUPPORTED_PLATFORMS
    assert "generic" in SUPPORTED_PLATFORMS


def test_unknown_platform_rejected() -> None:
    with pytest.raises(ValueError) as exc:
        export_for_platform("magic_grc", findings=[], run_metadata={})
    assert "magic_grc" in str(exc.value)


@pytest.mark.parametrize("platform", SUPPORTED_PLATFORMS)
def test_each_platform_renders_without_error(platform: str) -> None:
    out = export_for_platform(
        platform, findings=_findings(), run_metadata=_run_metadata()
    )
    assert out["format"] == platform
    assert "schema_version" in out
    assert "generated_at" in out


# ---------------------------------------------------------------------------
# Vanta shape
# ---------------------------------------------------------------------------


def test_vanta_shape() -> None:
    out = export_for_platform("vanta", findings=_findings(), run_metadata=_run_metadata())
    assert "vulnerabilities" in out
    assert len(out["vulnerabilities"]) == 2
    v = out["vulnerabilities"][0]
    assert v["external_id"] == "v-001"
    assert v["severity"] == "high"
    assert v["cvss_score"] == 8.5  # high
    assert v["cwe_id"] == "CWE-89"
    assert v["asset_url"] == "https://example.com"


def test_vanta_severity_canonical_lowercase() -> None:
    """Per #106, machine-readable surfaces emit lowercase severity."""
    out = export_for_platform("vanta", findings=_findings(), run_metadata=_run_metadata())
    for v in out["vulnerabilities"]:
        assert v["severity"] == v["severity"].lower()


# ---------------------------------------------------------------------------
# Drata shape
# ---------------------------------------------------------------------------


def test_drata_shape() -> None:
    out = export_for_platform("drata", findings=_findings(), run_metadata=_run_metadata())
    assert "evidence" in out
    assert len(out["evidence"]) == 2
    e = out["evidence"][0]
    assert e["evidence_type"] == "scan_finding"
    assert "CC6.1" in e["control_ids"]
    assert e["metadata"]["data_classification"] == "pii"


def test_drata_pulls_only_soc2_controls() -> None:
    """Drata is SOC 2-first; we attach the SOC 2 controls only."""
    out = export_for_platform("drata", findings=_findings(), run_metadata=_run_metadata())
    e = out["evidence"][0]
    # Should not include PCI / ISO controls in control_ids field.
    for control_id in e["control_ids"]:
        assert control_id.startswith("CC")  # SOC 2 control IDs start with CC


# ---------------------------------------------------------------------------
# Hyperproof shape
# ---------------------------------------------------------------------------


def test_hyperproof_emits_one_record_per_control() -> None:
    """SQL injection (3 frameworks: SOC 2 / PCI / ISO) → 3 records.
    XSS (1 framework: SOC 2) → 1 record. Total: 4 records."""
    out = export_for_platform("hyperproof", findings=_findings(), run_metadata=_run_metadata())
    assert len(out["records"]) == 4
    frameworks = {r["framework"] for r in out["records"]}
    assert "soc2" in frameworks
    assert "pci_dss" in frameworks
    assert "iso_27001" in frameworks


def test_hyperproof_unmapped_finding_gets_unmapped_record() -> None:
    """Finding without compliance_controls → single 'unmapped' record."""
    findings = [{
        "id": "v-x",
        "title": "Some finding",
        "severity": "low",
        "cwe": "CWE-200",
        # no compliance_controls
    }]
    out = export_for_platform("hyperproof", findings=findings, run_metadata=_run_metadata())
    assert len(out["records"]) == 1
    assert out["records"][0]["framework"] == "unmapped"
    assert out["records"][0]["control"] is None


# ---------------------------------------------------------------------------
# Secureframe shape
# ---------------------------------------------------------------------------


def test_secureframe_shape() -> None:
    out = export_for_platform("secureframe", findings=_findings(), run_metadata=_run_metadata())
    assert "findings" in out
    f = out["findings"][0]
    assert f["risk_level"] == "high"
    assert f["cwe_id"] == "CWE-89"
    assert "soc2" in f["compliance_frameworks"]
    assert "pci_dss" in f["compliance_frameworks"]


# ---------------------------------------------------------------------------
# ServiceNow shape
# ---------------------------------------------------------------------------


def test_servicenow_shape_uses_u_prefixed_columns() -> None:
    """ServiceNow custom-table columns conventionally start with 'u_'."""
    out = export_for_platform("servicenow", findings=_findings(), run_metadata=_run_metadata())
    assert "records" in out
    r = out["records"][0]
    assert "u_short_description" in r
    assert "u_severity" in r
    # ServiceNow uses uppercase severity tags.
    assert r["u_severity"] == "HIGH"
    assert r["u_state"] == "open"


def test_servicenow_pattern_match_state() -> None:
    """pattern_match → state="open" (still actionable)."""
    out = export_for_platform("servicenow", findings=_findings(), run_metadata=_run_metadata())
    xss = next(r for r in out["records"] if r["u_external_id"] == "v-002")
    assert xss["u_state"] == "open"


# ---------------------------------------------------------------------------
# Generic shape
# ---------------------------------------------------------------------------


def test_generic_carries_full_findings_list() -> None:
    out = export_for_platform("generic", findings=_findings(), run_metadata=_run_metadata())
    assert out["count"] == 2
    assert len(out["findings"]) == 2
    assert out["run_id"] == "rid-001"


# ---------------------------------------------------------------------------
# write_export
# ---------------------------------------------------------------------------


def test_write_export_writes_file(tmp_path: Path) -> None:
    out_path = tmp_path / "grc_export_vanta.json"
    result = write_export(
        "vanta",
        findings=_findings(),
        run_metadata=_run_metadata(),
        output_path=out_path,
    )

    assert result["platform"] == "vanta"
    assert Path(result["output_path"]).exists()
    assert result["record_count"] == 2

    data = json.loads(out_path.read_text())
    assert data["format"] == "vanta"


def test_write_export_creates_parent_dirs(tmp_path: Path) -> None:
    """Parent directories are auto-created."""
    out_path = tmp_path / "deep" / "nested" / "drata.json"
    write_export(
        "drata",
        findings=_findings(),
        run_metadata=_run_metadata(),
        output_path=out_path,
    )
    assert out_path.exists()


def test_write_export_record_count_per_platform(tmp_path: Path) -> None:
    """record_count is platform-dependent — Hyperproof emits one
    record per (finding, framework) so it has more records."""
    vanta_result = write_export(
        "vanta",
        findings=_findings(),
        run_metadata=_run_metadata(),
        output_path=tmp_path / "vanta.json",
    )
    hyperproof_result = write_export(
        "hyperproof",
        findings=_findings(),
        run_metadata=_run_metadata(),
        output_path=tmp_path / "hyperproof.json",
    )
    assert vanta_result["record_count"] == 2
    assert hyperproof_result["record_count"] == 4  # SQLi×3 + XSS×1
