"""Tests for §8.5 Phase 6 — `WatchdogState`.

Pins the stuck-loop detection contract: 5 turns without progress →
`should_force_exit()` returns True. Lead loop polls every turn
after `tick()`.
"""

from __future__ import annotations

import threading

import pytest

from strix.agents.lead_agent.watchdog import WatchdogState


def test_initial_state_does_not_force_exit() -> None:
    w = WatchdogState()
    assert w.should_force_exit() is False
    assert w.turns_since_progress == 0
    assert w.total_turns == 0


def test_tick_increments_idle_counter() -> None:
    w = WatchdogState()
    w.tick()
    w.tick()
    assert w.turns_since_progress == 2
    assert w.total_turns == 2


def test_record_progress_resets_idle_counter() -> None:
    w = WatchdogState()
    w.tick()
    w.tick()
    w.record_progress("finding")
    assert w.turns_since_progress == 0
    assert w.total_turns == 2  # total preserved
    assert w.progress_events == ["finding"]


def test_force_exit_after_max_idle_turns() -> None:
    w = WatchdogState(max_idle_turns=3)
    for _ in range(2):
        w.tick()
    assert w.should_force_exit() is False
    w.tick()  # 3rd idle turn
    assert w.should_force_exit() is True


def test_force_exit_does_not_fire_after_progress() -> None:
    w = WatchdogState(max_idle_turns=3)
    for _ in range(2):
        w.tick()
    w.record_progress("phase")
    w.tick()
    assert w.should_force_exit() is False


@pytest.mark.parametrize(
    "kind",
    ["finding", "endpoint", "phase", "update"],
)
def test_progress_kinds_all_reset_counter(kind: str) -> None:
    w = WatchdogState(max_idle_turns=3)
    for _ in range(3):
        w.tick()
    assert w.should_force_exit() is True
    w.record_progress(kind)
    assert w.should_force_exit() is False


def test_snapshot_returns_full_state() -> None:
    w = WatchdogState(max_idle_turns=5)
    w.tick()
    w.record_progress("finding")
    w.tick()
    snap = w.snapshot()
    assert snap["max_idle_turns"] == 5
    assert snap["turns_since_progress"] == 1
    assert snap["total_turns"] == 2
    assert snap["progress_event_count"] == 1
    assert snap["progress_kinds"] == ["finding"]


def test_reset_clears_counters() -> None:
    w = WatchdogState()
    w.tick()
    w.tick()
    w.record_progress("finding")
    w.reset()
    assert w.turns_since_progress == 0
    assert w.total_turns == 0
    assert w.progress_events == []


def test_thread_safe_under_parallel_dispatch() -> None:
    """Phase 3b parallel-tool-dispatch may call tick() / record_progress()
    from worker threads. Ensure counters stay consistent."""
    w = WatchdogState(max_idle_turns=10_000)

    def hammer():
        for _ in range(100):
            w.tick()
            w.record_progress("finding")

    threads = [threading.Thread(target=hammer) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # 1000 ticks total. Last operation per thread is record_progress
    # which resets to 0; counter could be 0-9 depending on
    # interleaving. total_turns must be exactly 1000.
    assert w.total_turns == 1000
    assert len(w.progress_events) == 1000
