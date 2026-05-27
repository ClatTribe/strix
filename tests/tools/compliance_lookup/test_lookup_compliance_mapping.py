"""Tests for iter-Q5.8 — `lookup_compliance_mapping`."""

from __future__ import annotations

import json

import pytest

from strix.tools.compliance_lookup.lookup_compliance_mapping import (
    _SUPPORTED_FRAMEWORKS,
    lookup_compliance_mapping,
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_rejects_non_dict_finding_shape() -> None:
    out = lookup_compliance_mapping(
        finding_shape="not a dict",  # type: ignore[arg-type]
        frameworks=["SOC2"],
    )
    assert out["success"] is False
    assert "must be a dict" in out["reason"]


def test_rejects_missing_cwe() -> None:
    out = lookup_compliance_mapping(
        finding_shape={"severity": "high"},  # no cwe
        frameworks=["SOC2"],
    )
    assert out["success"] is False
    assert "finding_shape.cwe is required" in out["reason"]


def test_rejects_empty_frameworks() -> None:
    out = lookup_compliance_mapping(
        finding_shape={"cwe": "CWE-89"},
        frameworks=[],
    )
    assert out["success"] is False
    assert "non-empty list" in out["reason"]


def test_rejects_unknown_framework() -> None:
    out = lookup_compliance_mapping(
        finding_shape={"cwe": "CWE-89"},
        frameworks=["SOC2", "DEFCON"],
    )
    assert out["success"] is False
    assert "DEFCON" in out["reason"]
    assert "SOC2" not in out.get("mappings", {})  # short-circuit


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_known_cwe_returns_controls() -> None:
    out = lookup_compliance_mapping(
        finding_shape={"cwe": "CWE-89", "severity": "critical"},
        frameworks=["SOC2", "PCI-DSS"],
    )
    assert out["success"] is True
    assert out["status"] == "ok"
    assert out["finding_shape"]["cwe"] == "CWE-89"
    soc2 = out["mappings"]["SOC2"]
    pci = out["mappings"]["PCI-DSS"]
    assert len(soc2) > 0
    assert len(pci) > 0
    # Each control should have id + description + revision.
    first = soc2[0]
    assert "control_id" in first
    assert "description" in first
    assert "revision" in first
    assert "2017" in first["revision"] or "2022" in first["revision"]


def test_multiple_frameworks_all_returned() -> None:
    out = lookup_compliance_mapping(
        finding_shape={"cwe": "CWE-287"},
        frameworks=list(_SUPPORTED_FRAMEWORKS),
    )
    assert out["success"] is True
    # Every requested framework appears in mappings (even if empty).
    for fw in _SUPPORTED_FRAMEWORKS:
        assert fw in out["mappings"]


def test_unknown_cwe_returns_empty_with_reason() -> None:
    out = lookup_compliance_mapping(
        finding_shape={"cwe": "CWE-99999"},
        frameworks=["SOC2"],
    )
    assert out["success"] is True
    assert out["mappings"]["SOC2"] == []
    assert "CWE-99999" in out["reason"]
    assert "No mappings found" in out["reason"]


# ---------------------------------------------------------------------------
# Corpus metadata
# ---------------------------------------------------------------------------


def test_returns_corpus_version() -> None:
    out = lookup_compliance_mapping(
        finding_shape={"cwe": "CWE-89"},
        frameworks=["SOC2"],
    )
    assert out["corpus_version"] != "unknown"
    assert "2026.05" in out["corpus_version"]


def test_returns_corpus_age_days() -> None:
    out = lookup_compliance_mapping(
        finding_shape={"cwe": "CWE-89"},
        frameworks=["SOC2"],
    )
    # The corpus was created in this PR — should be 0-1 days old.
    assert out["corpus_age_days"] >= 0
    assert out["corpus_age_days"] < 30  # sanity bound


# ---------------------------------------------------------------------------
# Override corpus dir
# ---------------------------------------------------------------------------


def test_custom_corpus_dir_via_env(monkeypatch, tmp_path) -> None:
    """STRIX_COMPLIANCE_CORPUS_DIR lets ops point at a refreshed
    corpus without rebuilding the package."""
    # Write a minimal custom corpus.
    (tmp_path / "SOC2.json").write_text(
        json.dumps({
            "__revision": "CUSTOM TEST",
            "CWE-1": [
                {"control_id": "TEST.1", "description": "test control"},
            ],
        }),
        encoding="utf-8",
    )
    (tmp_path / "VERSION").write_text("custom-test-corpus", encoding="utf-8")
    monkeypatch.setenv("STRIX_COMPLIANCE_CORPUS_DIR", str(tmp_path))

    out = lookup_compliance_mapping(
        finding_shape={"cwe": "CWE-1"},
        frameworks=["SOC2"],
    )
    assert out["mappings"]["SOC2"][0]["control_id"] == "TEST.1"
    assert out["mappings"]["SOC2"][0]["revision"] == "CUSTOM TEST"
    assert out["corpus_version"] == "custom-test-corpus"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_lookup_compliance_mapping_is_registered() -> None:
    from strix.tools.registry import get_tool_by_name, get_tool_names
    assert "lookup_compliance_mapping" in get_tool_names()
    assert get_tool_by_name("lookup_compliance_mapping") is not None


def test_in_minimal_core() -> None:
    from strix.agents.lead_agent.tool_catalog import _MINIMAL_CORE_TOOLS
    assert "lookup_compliance_mapping" in _MINIMAL_CORE_TOOLS
