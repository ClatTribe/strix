"""Tests for the §2 objective CRUD tools.

The underlying tracker is exhaustively tested in
`tests/agents/test_objective_tracker.py`. This file pins the
tool-level surface: arg parsing, return shape, error handling.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.agents import objective_tracker as ot
from strix.tools.workflow import objective_tools


@pytest.fixture(autouse=True)
def _reset_tracker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ot.reset_for_testing()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_OBJECTIVES_DISABLED", raising=False)


def test_create_objective_returns_dict() -> None:
    result = objective_tools.create_objective(
        title="Verify SQLi on /login",
        phase="probe",
        category="sqli",
        surface="https://app/login",
    )
    assert result["success"] is True
    assert result["objective"]["id"] == "OBJ-001"
    assert result["objective"]["status"] == "pending"


def test_create_objective_parses_depends_on_csv() -> None:
    objective_tools.create_objective(
        title="a", phase="recon", category="recon",
    )
    objective_tools.create_objective(
        title="b", phase="recon", category="fingerprint",
    )
    result = objective_tools.create_objective(
        title="probe", phase="probe", category="sqli",
        depends_on="OBJ-001, OBJ-002",
    )
    assert result["objective"]["depends_on"] == ["OBJ-001", "OBJ-002"]


def test_list_objectives_returns_total_and_array() -> None:
    objective_tools.create_objective(
        title="a", phase="recon", category="recon",
    )
    objective_tools.create_objective(
        title="b", phase="probe", category="sqli",
    )
    result = objective_tools.list_objectives()
    assert result["total"] == 2
    assert len(result["objectives"]) == 2


def test_list_objectives_filters() -> None:
    objective_tools.create_objective(
        title="a", phase="recon", category="recon",
    )
    objective_tools.create_objective(
        title="b", phase="probe", category="sqli",
    )
    result = objective_tools.list_objectives(phase="probe")
    assert result["total"] == 1
    assert result["objectives"][0]["title"] == "b"


def test_update_objective_status() -> None:
    objective_tools.create_objective(
        title="x", phase="probe", category="sqli",
    )
    result = objective_tools.update_objective(id="OBJ-001", status="in_progress")
    assert result["success"] is True
    assert result["objective"]["status"] == "in_progress"


def test_update_objective_invalid_transition() -> None:
    objective_tools.create_objective(
        title="x", phase="probe", category="sqli",
    )
    objective_tools.update_objective(id="OBJ-001", status="in_progress")
    objective_tools.update_objective(id="OBJ-001", status="completed")
    result = objective_tools.update_objective(id="OBJ-001", status="pending")
    assert result["success"] is False
    assert "transition" in result["error"].lower()


def test_update_objective_unknown_id() -> None:
    result = objective_tools.update_objective(id="OBJ-999", status="completed")
    assert result["success"] is False
    assert result["error"] == "not_found"


def test_get_objective_returns_can_start_flag() -> None:
    objective_tools.create_objective(
        title="dep", phase="recon", category="recon",
    )
    objective_tools.create_objective(
        title="x", phase="probe", category="sqli",
        depends_on="OBJ-001",
    )
    result = objective_tools.get_objective(id="OBJ-002")
    assert result["success"] is True
    # Dep is pending → can't start yet.
    assert result["can_start"] is False


def test_get_objective_unknown_id() -> None:
    result = objective_tools.get_objective(id="OBJ-999")
    assert result["success"] is False


def test_add_child_objective_inherits_phase() -> None:
    parent = objective_tools.create_objective(
        title="parent", phase="probe", category="sqli",
        surface="https://app/login",
    )
    child = objective_tools.add_child_objective(
        parent_id=parent["objective"]["id"],
        title="test JWT none-alg",
    )
    assert child["success"] is True
    assert child["objective"]["phase"] == "probe"
    assert child["objective"]["category"] == "sqli"
    assert child["objective"]["surface"] == "https://app/login"
    assert child["objective"]["parent_id"] == "OBJ-001"


def test_add_child_objective_unknown_parent() -> None:
    result = objective_tools.add_child_objective(
        parent_id="OBJ-999",
        title="x",
    )
    assert result["success"] is False
    assert result["error"] == "parent_not_found"


def test_add_child_objective_can_override_category() -> None:
    parent = objective_tools.create_objective(
        title="parent", phase="probe", category="sqli",
    )
    child = objective_tools.add_child_objective(
        parent_id=parent["objective"]["id"],
        title="orthogonal sub-check",
        category="xss",
    )
    assert child["objective"]["category"] == "xss"
