"""Tool-surface tests for the §4 verification pipeline tools.

The underlying pipeline is exhaustively tested in
`tests/agents/test_verification_pipeline.py`. This file pins the
tool wrappers: arg parsing, return shape, error handling.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.agents import verification_pipeline as vp
from strix.tools.workflow import verification_tools as vt


@pytest.fixture(autouse=True)
def _reset_pipeline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    vp.reset_for_testing()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_VERIFICATION_DISABLED", raising=False)


def test_register_returns_initial_record() -> None:
    r = vt.register_finding_for_verification(
        finding_id="F-001", severity="high",
    )
    assert r["success"] is True
    assert r["record"]["stage"] == "SCANNED"
    assert r["record"]["severity"] == "high"


def test_record_evidence_happy_path() -> None:
    vt.register_finding_for_verification(finding_id="F-001", severity="medium")
    r = vt.record_verification_evidence(
        finding_id="F-001",
        method="payload_response",
        outcome="PASSED",
        tool="sqlmap",
        detail="union-based, 3 cols",
    )
    assert r["success"] is True
    assert len(r["record"]["evidence"]) == 1


def test_record_evidence_unknown_finding() -> None:
    r = vt.record_verification_evidence(
        finding_id="F-NOPE",
        method="timing",
        outcome="PASSED",
        tool="x",
    )
    assert r["success"] is False
    assert r["error"] == "finding_not_registered"


def test_record_evidence_unknown_method_returns_error() -> None:
    vt.register_finding_for_verification(finding_id="F-001", severity="high")
    r = vt.record_verification_evidence(
        finding_id="F-001",
        method="psychic_reading",
        outcome="PASSED",
        tool="x",
    )
    assert r["success"] is False
    assert "invalid method" in r["error"]


def test_advance_happy_path() -> None:
    vt.register_finding_for_verification(finding_id="F-001", severity="medium")
    r = vt.advance_verification_stage(finding_id="F-001", target_stage="DETECTED")
    assert r["success"] is True
    assert r["record"]["stage"] == "DETECTED"


def test_advance_blocked_by_floor_returns_record() -> None:
    """When advance fails due to the 2-method floor, the agent still
    gets the current record back so it can see what's missing."""
    vt.register_finding_for_verification(finding_id="F-001", severity="high")
    vt.advance_verification_stage(finding_id="F-001", target_stage="DETECTED")
    vt.advance_verification_stage(finding_id="F-001", target_stage="VERIFYING")
    vt.record_verification_evidence(
        finding_id="F-001",
        method="payload_response",
        outcome="PASSED",
        tool="x",
    )
    r = vt.advance_verification_stage(
        finding_id="F-001", target_stage="VERIFIED",
    )
    assert r["success"] is False
    assert "insufficient" in r["reason"]
    assert r["record"] is not None
    assert r["record"]["stage"] == "VERIFYING"


def test_status_returns_single_finding() -> None:
    vt.register_finding_for_verification(finding_id="F-001", severity="medium")
    r = vt.verification_status(finding_id="F-001")
    assert r["success"] is True
    assert r["record"]["finding_id"] == "F-001"


def test_status_unknown_finding() -> None:
    r = vt.verification_status(finding_id="F-NOPE")
    assert r["success"] is False
    assert r["error"] == "not_found"


def test_status_list_no_filters() -> None:
    vt.register_finding_for_verification(finding_id="F-001", severity="high")
    vt.register_finding_for_verification(finding_id="F-002", severity="low")
    r = vt.verification_status()
    assert r["total"] == 2


def test_status_list_filtered_by_severity() -> None:
    vt.register_finding_for_verification(finding_id="F-001", severity="high")
    vt.register_finding_for_verification(finding_id="F-002", severity="low")
    r = vt.verification_status(severity="high")
    assert r["total"] == 1
    assert r["records"][0]["finding_id"] == "F-001"


def test_status_list_filtered_by_stage() -> None:
    vt.register_finding_for_verification(finding_id="F-001", severity="medium")
    vt.advance_verification_stage(finding_id="F-001", target_stage="DETECTED")
    vt.register_finding_for_verification(finding_id="F-002", severity="medium")
    r = vt.verification_status(stage="DETECTED")
    assert r["total"] == 1
    assert r["records"][0]["finding_id"] == "F-001"
