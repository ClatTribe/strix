"""Tests for the OODA-shaped rejection tracker
(strix/agents/rejection_tracker.py).

The tracker closes the cost pathology observed in the Phase 3d
benchmark: 36 consecutive finish_scan retries, ~$0.50 wasted on
rejection loops. Three mechanisms:

  1. Counter per (tool_name) — module-global, thread-safe.
  2. OODA-structured rejection responses — observe / orient /
     decide / act fields the lead's LLM is expected to parse.
  3. Auto-bypass after `AUTO_BYPASS_THRESHOLD` consecutive
     rejections — guard returns None so the gated tool proceeds.

This file tests the tracker primitive itself. Integration with
`finish_scan` and `advance_workflow_phase` is tested in their
respective test files.
"""

from __future__ import annotations

import threading

import pytest

from strix.agents import rejection_tracker as rt


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_REJECTION_TRACKER_DISABLED", raising=False)
    rt.reset_for_testing()
    yield
    rt.reset_for_testing()


# ---------------------------------------------------------------------------
# Counter primitives
# ---------------------------------------------------------------------------


def test_initial_count_is_zero() -> None:
    assert rt.get_rejection_count("finish_scan") == 0


def test_record_rejection_increments() -> None:
    assert rt.record_rejection("finish_scan") == 1
    assert rt.record_rejection("finish_scan") == 2
    assert rt.record_rejection("finish_scan") == 3
    assert rt.get_rejection_count("finish_scan") == 3


def test_record_success_resets_counter() -> None:
    rt.record_rejection("finish_scan")
    rt.record_rejection("finish_scan")
    rt.record_success("finish_scan")
    assert rt.get_rejection_count("finish_scan") == 0


def test_counters_are_per_tool() -> None:
    """Each tool has its own counter — a burst on `finish_scan`
    shouldn't affect `advance_workflow_phase`'s count."""
    rt.record_rejection("finish_scan")
    rt.record_rejection("finish_scan")
    rt.record_rejection("advance_workflow_phase")
    assert rt.get_rejection_count("finish_scan") == 2
    assert rt.get_rejection_count("advance_workflow_phase") == 1


# ---------------------------------------------------------------------------
# Auto-bypass
# ---------------------------------------------------------------------------


def test_auto_bypass_threshold_is_documented() -> None:
    """The threshold is a public constant — tests + benchmark
    tooling reference it directly."""
    assert rt.AUTO_BYPASS_THRESHOLD == 6
    assert rt.STUCK_WARNING_THRESHOLD < rt.AUTO_BYPASS_THRESHOLD


def test_auto_bypass_off_below_threshold() -> None:
    for _ in range(rt.AUTO_BYPASS_THRESHOLD - 1):
        rt.record_rejection("finish_scan")
    assert rt.should_auto_bypass("finish_scan") is False


def test_auto_bypass_on_at_threshold() -> None:
    for _ in range(rt.AUTO_BYPASS_THRESHOLD):
        rt.record_rejection("finish_scan")
    assert rt.should_auto_bypass("finish_scan") is True


def test_auto_bypass_resets_on_success() -> None:
    """After auto-bypass fires + the gated tool's success-handler
    resets the counter, future rejections start from 1 again."""
    for _ in range(rt.AUTO_BYPASS_THRESHOLD):
        rt.record_rejection("finish_scan")
    assert rt.should_auto_bypass("finish_scan") is True
    rt.record_success("finish_scan")
    assert rt.should_auto_bypass("finish_scan") is False
    rt.record_rejection("finish_scan")
    assert rt.get_rejection_count("finish_scan") == 1


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
def test_kill_switch_enabled_values(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_REJECTION_TRACKER_DISABLED", val)
    assert rt.is_disabled() is True
    # Recording is a no-op.
    assert rt.record_rejection("finish_scan") == 0
    assert rt.should_auto_bypass("finish_scan") is False


def test_kill_switch_disabled_default(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_REJECTION_TRACKER_DISABLED", raising=False)
    assert rt.is_disabled() is False


# ---------------------------------------------------------------------------
# OODA response builder
# ---------------------------------------------------------------------------


def test_build_ooda_response_first_rejection_no_warning() -> None:
    """1st rejection: standard OODA shape, no loop_warning, no
    AUTO_BYPASS_IMMINENT prefix in orient."""
    r = rt.build_ooda_response(
        tool_name="finish_scan",
        error="some_error",
        observe="state observed",
        orient="why blocked",
        decide=["step 1"],
        act=[{"tool": "x", "args": {}}],
    )
    assert r["success"] is False
    assert r["error"] == "some_error"
    assert r["rejection_count"] == 1
    assert r["auto_bypass_at"] == rt.AUTO_BYPASS_THRESHOLD
    assert "loop_warning" not in r
    assert "STUCK_LOOP_WARNING" not in r["ooda"]["orient"]
    assert "AUTO_BYPASS_IMMINENT" not in r["ooda"]["orient"]


def test_build_ooda_response_carries_full_ooda_structure() -> None:
    """Every required OODA field is present + correctly populated."""
    r = rt.build_ooda_response(
        tool_name="finish_scan",
        error="x",
        observe="o",
        orient="orient",
        decide=["d1", "d2"],
        act=[
            {"tool": "advance_workflow_phase", "args": {"target": "probe"}},
            {"tool": "finish_scan", "args": {}},
        ],
    )
    o = r["ooda"]
    assert o["observe"] == "o"
    assert "orient" in o["orient"]
    assert o["decide"] == ["d1", "d2"]
    assert len(o["act"]) == 2
    assert o["act"][0]["tool"] == "advance_workflow_phase"


def test_build_ooda_response_stuck_warning_at_threshold() -> None:
    """At STUCK_WARNING_THRESHOLD, the response carries
    `loop_warning` + the orient field gets the warning prefix."""
    for _ in range(rt.STUCK_WARNING_THRESHOLD - 1):
        rt.record_rejection("finish_scan")
    r = rt.build_ooda_response(
        tool_name="finish_scan", error="x", observe="o",
        orient="orient", decide=[], act=[],
    )
    assert r["rejection_count"] == rt.STUCK_WARNING_THRESHOLD
    assert "loop_warning" in r
    assert "STUCK_LOOP_WARNING" in r["ooda"]["orient"]


def test_build_ooda_response_auto_bypass_imminent_message() -> None:
    """At AUTO_BYPASS_THRESHOLD, orient field warns the bypass
    is imminent."""
    for _ in range(rt.AUTO_BYPASS_THRESHOLD - 1):
        rt.record_rejection("finish_scan")
    r = rt.build_ooda_response(
        tool_name="finish_scan", error="x", observe="o",
        orient="orient", decide=[], act=[],
    )
    assert r["rejection_count"] == rt.AUTO_BYPASS_THRESHOLD
    assert "AUTO_BYPASS_IMMINENT" in r["ooda"]["orient"]


def test_build_ooda_response_extra_fields_merge() -> None:
    """The optional `extra_fields` dict is merged into the
    response — used for surfacing workflow state, hypothesis
    lists, etc. alongside the OODA structure."""
    r = rt.build_ooda_response(
        tool_name="finish_scan", error="x", observe="o",
        orient="orient", decide=[], act=[],
        extra_fields={"current_phase": "probe", "custom_field": [1, 2]},
    )
    assert r["current_phase"] == "probe"
    assert r["custom_field"] == [1, 2]


def test_build_auto_bypass_marker_shape() -> None:
    """Auto-bypass marker has the documented shape — wrappers
    use this to flag scans for review."""
    marker = rt.build_auto_bypass_marker("finish_scan")
    assert marker["auto_bypassed"] is True
    assert "finish_scan" in marker["auto_bypass_reason"]
    assert marker["auto_bypass_threshold"] == rt.AUTO_BYPASS_THRESHOLD


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


def test_record_rejection_thread_safe() -> None:
    """The tracker is process-global; concurrent specialist calls
    incrementing it must produce correct totals."""

    def burst() -> None:
        for _ in range(50):
            rt.record_rejection("finish_scan")

    threads = [threading.Thread(target=burst) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert rt.get_rejection_count("finish_scan") == 200
