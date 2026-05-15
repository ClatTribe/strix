"""Tests for the §2 OPPLAN-style objective tracker.

Covers:
  * CRUD invariants (create / get / list / update / decompose)
  * Status transitions: valid + rejected (e.g. completed → pending)
  * Dependency gating (`can_start`)
  * Evidence-count mechanics
  * Persistence to <run_dir>/objectives.jsonl
  * Prompt rendering — table structure, status icons, filters
  * Kill switch (STRIX_OBJECTIVES_DISABLED)
  * Telemetry snapshot
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.agents import objective_tracker as ot


@pytest.fixture(autouse=True)
def _reset_tracker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Fresh tracker + scratch run dir for every test."""
    ot.reset_for_testing()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_OBJECTIVES_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_OBJECTIVES_PERSIST", raising=False)


# ---------------------------------------------------------------------------
# Create / read
# ---------------------------------------------------------------------------


def test_create_assigns_sequential_ids() -> None:
    t = ot.get_tracker()
    o1 = t.create(title="recon", phase="recon", category="recon")
    o2 = t.create(title="probe sqli", phase="probe", category="sqli")
    assert o1.id == "OBJ-001"
    assert o2.id == "OBJ-002"


def test_create_records_all_fields() -> None:
    t = ot.get_tracker()
    o = t.create(
        title="Verify IDOR on /api/users/{id}",
        phase="probe",
        category="idor",
        surface="https://app/api/users",
        depends_on=["OBJ-001"],
        acceptance="Cross-tenant read with role=user creds",
        evidence_required=2,
    )
    assert o.title == "Verify IDOR on /api/users/{id}"
    assert o.phase == "probe"
    assert o.category == "idor"
    assert o.surface == "https://app/api/users"
    assert o.depends_on == ["OBJ-001"]
    assert o.acceptance == "Cross-tenant read with role=user creds"
    assert o.evidence_required == 2
    assert o.status == "pending"
    assert o.evidence_count == 0


def test_evidence_required_floor_at_one() -> None:
    t = ot.get_tracker()
    o = t.create(
        title="x", phase="probe", category="sqli", evidence_required=0,
    )
    assert o.evidence_required == 1


def test_get_returns_none_for_unknown() -> None:
    assert ot.get_tracker().get("OBJ-999") is None


def test_list_sorted_by_id() -> None:
    t = ot.get_tracker()
    t.create(title="a", phase="probe", category="sqli")
    t.create(title="b", phase="probe", category="xss")
    t.create(title="c", phase="recon", category="recon")
    ids = [o.id for o in t.list()]
    assert ids == ["OBJ-001", "OBJ-002", "OBJ-003"]


def test_list_filters() -> None:
    t = ot.get_tracker()
    t.create(title="a", phase="recon", category="recon")
    t.create(title="b", phase="probe", category="sqli")
    t.create(title="c", phase="probe", category="xss")

    assert len(t.list(phase="probe")) == 2
    assert len(t.list(phase="recon")) == 1
    assert len(t.list(category="sqli")) == 1
    assert len(t.list(status="pending")) == 3
    assert len(t.list(status="completed")) == 0


# ---------------------------------------------------------------------------
# Status transitions
# ---------------------------------------------------------------------------


def test_pending_to_in_progress_allowed() -> None:
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli")
    updated = t.update(o.id, status="in_progress")
    assert updated is not None
    assert updated.status == "in_progress"


def test_in_progress_to_completed_allowed() -> None:
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli")
    t.update(o.id, status="in_progress")
    updated = t.update(o.id, status="completed")
    assert updated is not None
    assert updated.status == "completed"


def test_completed_to_pending_rejected() -> None:
    """Reopening a completed objective by going back to pending is
    a fat-finger. Must be explicit (via cancelled first)."""
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli")
    t.update(o.id, status="in_progress")
    t.update(o.id, status="completed")
    with pytest.raises(ValueError) as exc:
        t.update(o.id, status="pending")
    assert "transition" in str(exc.value).lower()


def test_cancelled_is_terminal() -> None:
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli")
    t.update(o.id, status="cancelled")
    with pytest.raises(ValueError):
        t.update(o.id, status="pending")


def test_blocked_to_in_progress_allowed() -> None:
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli")
    t.update(o.id, status="in_progress")
    t.update(o.id, status="blocked")
    updated = t.update(o.id, status="in_progress")
    assert updated is not None
    assert updated.status == "in_progress"


def test_update_unknown_id_returns_none() -> None:
    assert ot.get_tracker().update("OBJ-999", status="completed") is None


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


def test_can_start_no_deps() -> None:
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli")
    assert t.can_start(o.id) is True


def test_can_start_blocked_by_pending_dep() -> None:
    t = ot.get_tracker()
    d = t.create(title="dep", phase="recon", category="recon")
    o = t.create(
        title="probe", phase="probe", category="sqli",
        depends_on=[d.id],
    )
    assert t.can_start(o.id) is False


def test_can_start_unblocked_after_dep_completes() -> None:
    t = ot.get_tracker()
    d = t.create(title="dep", phase="recon", category="recon")
    o = t.create(
        title="probe", phase="probe", category="sqli",
        depends_on=[d.id],
    )
    t.update(d.id, status="in_progress")
    t.update(d.id, status="completed")
    assert t.can_start(o.id) is True


def test_can_start_unknown_dep_blocks() -> None:
    t = ot.get_tracker()
    o = t.create(
        title="x", phase="probe", category="sqli",
        depends_on=["OBJ-DOES-NOT-EXIST"],
    )
    assert t.can_start(o.id) is False


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def test_mark_evidence_increments() -> None:
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli", evidence_required=3)
    t.mark_evidence(o.id)
    t.mark_evidence(o.id, n=2)
    assert t.get(o.id).evidence_count == 3  # type: ignore[union-attr]


def test_update_evidence_count_clamps_to_zero() -> None:
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli")
    t.update(o.id, evidence_count=-5)
    assert t.get(o.id).evidence_count == 0  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_persistence_appends_jsonl(tmp_path: Path) -> None:
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli")
    t.update(o.id, status="in_progress")
    t.update(o.id, status="completed")

    log = tmp_path / "objectives.jsonl"
    assert log.exists()
    records = [json.loads(line) for line in log.read_text().splitlines() if line]
    assert len(records) >= 3
    # Each record has event + ts + objective
    for r in records:
        assert "event" in r
        assert "ts" in r
        assert "objective" in r
        assert r["objective"]["id"] == o.id


def test_persistence_disabled_skips_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("STRIX_OBJECTIVES_PERSIST", "0")
    t = ot.get_tracker()
    t.create(title="x", phase="probe", category="sqli")
    log = tmp_path / "objectives.jsonl"
    assert not log.exists()


def test_persistence_without_run_dir_is_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No run dir → no persistence, but tracker still works."""
    monkeypatch.delenv("STRIX_RUN_DIR", raising=False)
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli")
    assert o.id == "OBJ-001"
    # No exception raised — just silently skips the append.


# ---------------------------------------------------------------------------
# Prompt rendering
# ---------------------------------------------------------------------------


def test_render_empty_returns_empty() -> None:
    """No objectives → empty string (template skips the section)."""
    assert ot.render_progress_table() == ""


def test_render_has_header_and_status_icons() -> None:
    t = ot.get_tracker()
    t.create(title="x", phase="probe", category="sqli")
    t.create(title="y", phase="recon", category="recon")
    out = ot.render_progress_table()
    assert "OBJECTIVES" in out
    assert "OBJ-001" in out
    assert "OBJ-002" in out
    # Default status is pending → uses the · icon
    assert "·" in out


def test_render_shows_completed_icon() -> None:
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli")
    t.update(o.id, status="in_progress")
    t.update(o.id, status="completed")
    out = ot.render_progress_table()
    assert "✓" in out


def test_render_shows_dependency_tags() -> None:
    t = ot.get_tracker()
    d = t.create(title="dep", phase="recon", category="recon")
    t.create(
        title="probe", phase="probe", category="sqli",
        depends_on=[d.id],
    )
    out = ot.render_progress_table()
    assert "deps=OBJ-001" in out


def test_render_shows_evidence_progress() -> None:
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli", evidence_required=3)
    t.mark_evidence(o.id)
    out = ot.render_progress_table()
    assert "evidence=1/3" in out


def test_render_groups_by_phase() -> None:
    t = ot.get_tracker()
    t.create(title="r1", phase="recon", category="recon")
    t.create(title="p1", phase="probe", category="sqli")
    out = ot.render_progress_table()
    # Both phase labels appear.
    assert "  recon:" in out
    assert "  probe:" in out


def test_render_shows_surface() -> None:
    t = ot.get_tracker()
    t.create(
        title="x", phase="probe", category="sqli",
        surface="https://app/api/users",
    )
    out = ot.render_progress_table()
    assert "https://app/api/users" in out


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "True", "yes", "ON"])
def test_kill_switch_disables_render(
    val: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_OBJECTIVES_DISABLED", val)
    t = ot.get_tracker()
    t.create(title="x", phase="probe", category="sqli")
    assert ot.render_progress_table() == ""


def test_kill_switch_unset_is_falsy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_OBJECTIVES_DISABLED", raising=False)
    assert not ot.is_disabled()


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


def test_get_tracker_stats_shape() -> None:
    t = ot.get_tracker()
    o = t.create(title="x", phase="probe", category="sqli")
    t.update(o.id, status="in_progress")
    stats = ot.get_tracker_stats()
    assert stats["enabled"] is True
    assert stats["objectives"] == 1
    assert stats["status_counts"]["in_progress"] == 1


def test_get_tracker_stats_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_OBJECTIVES_DISABLED", "1")
    stats = ot.get_tracker_stats()
    assert stats == {"enabled": False, "objectives": 0}
