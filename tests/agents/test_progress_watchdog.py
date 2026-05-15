"""Tests for the progress watchdog (PR-γ).

The watchdog is the 5th termination criterion — it observes
progress signals across turns (finding.created, endpoint.probed,
hypothesis.resolved, phase.transitioned, auth.captured,
endpoint.discovered) and emits escalating warning messages when
no progress occurs for `STRIX_MAX_STALL_MINUTES` minutes.

These tests pin:
  * Progress recording + idempotence
  * Stall detection with deterministic clock control
  * Warning-ladder escalation (tier 1 → tier 2 → tier 3)
  * Throttling — warnings don't spam every iteration
  * Counter reset on any progress event
  * Kill switch (STRIX_PROGRESS_WATCHDOG_DISABLED=1)
  * Env-var tunables (STRIX_MAX_STALL_MINUTES / STRIX_WATCHDOG_ESCALATE_AFTER)
  * Snapshot shape for telemetry
"""

from __future__ import annotations

import pytest

import strix.agents.progress_watchdog as pw


@pytest.fixture
def fake_clock(monkeypatch):
    """Deterministic monotonic clock — tests advance the clock
    explicitly via `clock['now'] = N`. Time-since-progress checks
    therefore aren't subject to real wall-clock during the test."""
    clock = {"now": 0.0}
    monkeypatch.setattr(pw.time, "monotonic", lambda: clock["now"])
    yield clock


@pytest.fixture(autouse=True)
def _reset(monkeypatch, fake_clock):
    monkeypatch.delenv("STRIX_PROGRESS_WATCHDOG_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_MAX_STALL_MINUTES", raising=False)
    monkeypatch.delenv("STRIX_WATCHDOG_ESCALATE_AFTER", raising=False)
    pw.reset_for_testing()
    yield
    pw.reset_for_testing()


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------


def test_initial_state_is_not_stalled(fake_clock) -> None:
    """Before any progress is recorded, the watchdog is still
    "fresh" — created_at = 0, last_progress_at = 0, so elapsed=0."""
    assert pw.minutes_since_progress() == 0.0
    assert pw.is_stalled() is False


def test_record_progress_increments_counters(fake_clock) -> None:
    pw.record_progress("finding.created", "sqli in login")
    pw.record_progress("endpoint.probed", "/api/users/42")
    snap = pw.snapshot()
    assert snap["total_progress_events"] == 2
    assert snap["events_by_kind"]["finding.created"] == 1
    assert snap["events_by_kind"]["endpoint.probed"] == 1


def test_record_progress_resets_stall_clock(fake_clock) -> None:
    """Recording any progress moves last_progress_at to NOW, so
    minutes_since_progress drops to 0."""
    fake_clock["now"] = 100
    pw.record_progress("finding.created")
    assert pw.minutes_since_progress() == 0.0
    fake_clock["now"] = 100 + 600
    assert pw.minutes_since_progress() == pytest.approx(10.0)


def test_unknown_kinds_still_reset_clock(fake_clock) -> None:
    """An unknown kind isn't counted in `events_by_kind` but
    still resets the stall clock — we'd rather be too generous
    on what counts as progress than under-fire."""
    fake_clock["now"] = 600
    pw.record_progress("custom.bespoke_signal", "x")
    assert pw.minutes_since_progress() == 0.0
    snap = pw.snapshot()
    # Total counted; per-kind not.
    assert snap["total_progress_events"] == 1
    assert snap["events_by_kind"] == {}


def test_record_progress_ignores_empty_kind(fake_clock) -> None:
    pw.record_progress("", "x")
    pw.record_progress(None, "x")  # type: ignore[arg-type]
    snap = pw.snapshot()
    assert snap.get("initialized") is False or snap["total_progress_events"] == 0


# ---------------------------------------------------------------------------
# Stall detection
# ---------------------------------------------------------------------------


def test_is_stalled_false_before_threshold(fake_clock) -> None:
    """Default threshold is 5 min. At 4 min elapsed, not stalled."""
    pw.record_progress("finding.created")
    fake_clock["now"] = 4 * 60
    assert pw.is_stalled() is False


def test_is_stalled_true_at_threshold(fake_clock) -> None:
    pw.record_progress("finding.created")
    fake_clock["now"] = 5 * 60
    assert pw.is_stalled() is True


def test_is_stalled_respects_env_threshold(monkeypatch, fake_clock) -> None:
    monkeypatch.setenv("STRIX_MAX_STALL_MINUTES", "2")
    pw.record_progress("finding.created")
    fake_clock["now"] = 1 * 60
    assert pw.is_stalled() is False
    fake_clock["now"] = 2 * 60
    assert pw.is_stalled() is True


# ---------------------------------------------------------------------------
# Warning ladder
# ---------------------------------------------------------------------------


def test_no_warning_when_not_stalled(fake_clock) -> None:
    pw.record_progress("finding.created")
    fake_clock["now"] = 60   # 1 min in
    assert pw.get_warning_message() is None


def test_tier_1_warning_at_first_stall(fake_clock) -> None:
    """First time the watchdog notices a stall, it emits a
    tier-1 'STALL' message. No 'REPEATED' / 'ESCALATION' prefix."""
    fake_clock["now"] = 6 * 60   # 6 min, past the 5-min threshold
    w = pw.get_warning_message()
    assert w is not None
    assert "PROGRESS_WATCHDOG_STALL" in w
    assert "ESCALATION" not in w
    assert "REPEATED" not in w


def test_tier_2_warning_at_second_stall_window(fake_clock) -> None:
    """The second stall window (after another 5 min without
    progress) emits a louder 'REPEATED_STALL' warning."""
    fake_clock["now"] = 6 * 60   # 6 min — first warning
    pw.get_warning_message()
    fake_clock["now"] = 12 * 60   # another 6 min — second
    w = pw.get_warning_message()
    assert w is not None
    assert "PROGRESS_WATCHDOG_REPEATED_STALL" in w


def test_tier_3_escalation_at_threshold(fake_clock) -> None:
    """At STRIX_WATCHDOG_ESCALATE_AFTER (default 3), the warning
    becomes the ESCALATION tier — agent loop should force-advance
    to report phase + request_stop."""
    # Trigger 3 stall windows
    fake_clock["now"] = 6 * 60
    pw.get_warning_message()
    fake_clock["now"] = 12 * 60
    pw.get_warning_message()
    fake_clock["now"] = 18 * 60
    w = pw.get_warning_message()
    assert w is not None
    assert "PROGRESS_WATCHDOG_ESCALATION" in w
    assert pw.should_escalate() is True


def test_warning_throttled_within_stall_window(fake_clock) -> None:
    """Once a warning is emitted, the watchdog throttles — no
    additional warning until ANOTHER full stall window elapses.
    Without throttling, every agent loop iteration past the
    threshold would emit a fresh warning."""
    fake_clock["now"] = 6 * 60
    assert pw.get_warning_message() is not None
    # 30 seconds later, no new warning.
    fake_clock["now"] = 6 * 60 + 30
    assert pw.get_warning_message() is None
    # 1 more minute, still throttled.
    fake_clock["now"] = 6 * 60 + 90
    assert pw.get_warning_message() is None


def test_progress_resets_warning_ladder(fake_clock) -> None:
    """Recording progress in the middle of a warning ladder
    resets the counter to 0 — productive lead never sees
    escalation."""
    fake_clock["now"] = 6 * 60
    pw.get_warning_message()
    fake_clock["now"] = 12 * 60
    pw.get_warning_message()
    assert pw.snapshot()["warning_count"] == 2

    pw.record_progress("finding.created")
    assert pw.snapshot()["warning_count"] == 0
    assert pw.should_escalate() is False


def test_custom_escalation_threshold(monkeypatch, fake_clock) -> None:
    """STRIX_WATCHDOG_ESCALATE_AFTER tunes the ladder length."""
    monkeypatch.setenv("STRIX_WATCHDOG_ESCALATE_AFTER", "2")
    fake_clock["now"] = 6 * 60
    w1 = pw.get_warning_message()
    fake_clock["now"] = 12 * 60
    w2 = pw.get_warning_message()
    assert "ESCALATION" in w2
    assert pw.should_escalate() is True


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
def test_kill_switch_disables_warnings(monkeypatch, fake_clock, val) -> None:
    """STRIX_PROGRESS_WATCHDOG_DISABLED=1 → record_progress still
    runs (telemetry), but is_stalled / get_warning_message /
    should_escalate are all no-ops."""
    monkeypatch.setenv("STRIX_PROGRESS_WATCHDOG_DISABLED", val)
    pw.record_progress("finding.created")
    fake_clock["now"] = 60 * 60   # 1 hour
    assert pw.is_stalled() is False
    assert pw.get_warning_message() is None
    assert pw.should_escalate() is False


def test_kill_switch_still_records_telemetry(monkeypatch, fake_clock) -> None:
    """Even disabled, the watchdog tracks events so post-run
    telemetry (run_meta.json) reflects what happened."""
    monkeypatch.setenv("STRIX_PROGRESS_WATCHDOG_DISABLED", "1")
    pw.record_progress("finding.created")
    pw.record_progress("endpoint.probed")
    snap = pw.snapshot()
    assert snap["total_progress_events"] == 2
    assert snap["disabled"] is True


# ---------------------------------------------------------------------------
# Snapshot shape
# ---------------------------------------------------------------------------


def test_snapshot_before_initialization(fake_clock) -> None:
    """Calling snapshot before any progress is recorded returns
    a minimal "uninitialized" shape so run_meta.json never
    crashes on a scan that finished without ever recording
    progress."""
    snap = pw.snapshot()
    assert snap["initialized"] is False
    assert "stall_minutes_threshold" in snap
    assert snap["disabled"] is False


def test_snapshot_after_progress_carries_state(fake_clock) -> None:
    pw.record_progress("finding.created", "sqli")
    pw.record_progress("endpoint.probed", "/api/users")
    snap = pw.snapshot()
    assert snap["initialized"] is True
    assert snap["total_progress_events"] == 2
    assert snap["events_by_kind"]["finding.created"] == 1
    assert snap["events_by_kind"]["endpoint.probed"] == 1
    assert snap["last_progress_kind"] == "endpoint.probed"
    assert "minutes_since_progress" in snap


# ---------------------------------------------------------------------------
# Progress signals from existing tools — wired correctly
# ---------------------------------------------------------------------------


def test_workflow_record_endpoint_discovered_emits_signal(fake_clock) -> None:
    """workflow_state's recorders hook into the watchdog. The
    integration ensures recording happens via the existing
    progress points, not new ad-hoc instrumentation."""
    from strix.agents import workflow_state as ws
    ws.reset_for_testing()
    fake_clock["now"] = 60
    ws.record_endpoint_discovered("https://x.com/login")
    snap = pw.snapshot()
    assert snap["events_by_kind"]["endpoint.discovered"] >= 1


def test_workflow_record_endpoint_probed_emits_signal(fake_clock) -> None:
    from strix.agents import workflow_state as ws
    ws.reset_for_testing()
    ws.record_endpoint_probed("https://x.com/api/users/42")
    snap = pw.snapshot()
    assert snap["events_by_kind"]["endpoint.probed"] >= 1


def test_workflow_advance_phase_emits_signal(fake_clock) -> None:
    """Phase transitions count as progress — the workflow moved."""
    from strix.agents import workflow_state as ws
    ws.reset_for_testing()
    ws.record_endpoint_discovered("https://x.com/x")
    ws.advance_phase("probe")
    snap = pw.snapshot()
    assert "phase.transitioned" in snap["events_by_kind"]
