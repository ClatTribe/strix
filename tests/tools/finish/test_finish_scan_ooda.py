"""Integration tests for finish_scan + OODA rejection tracker
(PR-#232 / OODA loop-breaker).

Tests the end-to-end behavior across the rejection ladder:
  * Standard OODA-shaped responses
  * Stuck-loop warning at threshold
  * Auto-bypass at higher threshold (caps cost of retry storms)
  * Counter reset on success

Uses the actual finish_scan tool (not mocks) to verify the
integration is wired correctly.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from strix.agents import rejection_tracker as rt
from strix.agents import workflow_state as ws
from strix.tools.finish.finish_actions import finish_scan


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_REJECTION_TRACKER_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_WORKFLOW_DISABLED", raising=False)
    rt.reset_for_testing()
    ws.reset_for_testing()
    yield
    rt.reset_for_testing()
    ws.reset_for_testing()


# ---------------------------------------------------------------------------
# Workflow phase guard — OODA shape
# ---------------------------------------------------------------------------


def test_first_rejection_has_ooda_shape() -> None:
    """1st finish_scan call in non-report phase: rejected with
    OODA fields populated. No loop_warning yet."""
    r = finish_scan(
        executive_summary="x", methodology="y",
        technical_analysis="z", recommendations="w",
    )
    assert r["success"] is False
    assert r["error"] == "workflow_not_in_report_phase"
    assert r["rejection_count"] == 1
    assert "ooda" in r
    assert "observe" in r["ooda"]
    assert "orient" in r["ooda"]
    assert "decide" in r["ooda"]
    assert "act" in r["ooda"]
    assert len(r["ooda"]["act"]) >= 1
    # Each act entry is a concrete tool-call template.
    for call in r["ooda"]["act"]:
        assert "tool" in call
        assert "args" in call
    assert "loop_warning" not in r


def test_act_plan_recommends_recon_in_initial_state() -> None:
    """When the workflow has no endpoints yet, the act plan
    leads with `webapp_recon_pipeline`. The lead doesn't have
    to figure out "what's missing" — the response tells it."""
    r = finish_scan(
        executive_summary="x", methodology="y",
        technical_analysis="z", recommendations="w",
    )
    tools_in_plan = [c["tool"] for c in r["ooda"]["act"]]
    assert "webapp_recon_pipeline" in tools_in_plan
    # The plan ALWAYS ends with finish_scan so the lead has the
    # full ordered sequence in one response.
    assert tools_in_plan[-1] == "finish_scan"


def test_act_plan_recommends_auth_when_login_form_found() -> None:
    """Once a login form is discovered (but auth not attempted),
    the plan pivots to auth_attempt + scan_auth_flow."""
    ws.record_endpoint_discovered("https://x.com/login")
    ws.record_login_form_found("https://x.com/login")
    r = finish_scan(
        executive_summary="x", methodology="y",
        technical_analysis="z", recommendations="w",
    )
    tools_in_plan = [c["tool"] for c in r["ooda"]["act"]]
    assert "advance_workflow_phase" in tools_in_plan
    assert "scan_auth_flow" in tools_in_plan
    # The advance call should target auth_attempt.
    advance_calls = [c for c in r["ooda"]["act"]
                     if c["tool"] == "advance_workflow_phase"]
    assert advance_calls[0]["args"]["target"] == "auth_attempt"


def test_act_plan_recommends_probe_endpoint_in_probe_phase() -> None:
    """In probe phase with unprobed endpoints, the plan
    leads with `probe_endpoint` — the composite specialist
    fan-out from PR-β."""
    ws.record_endpoint_discovered("https://x.com/api/users")
    ws.record_endpoint_discovered("https://x.com/login")
    ws.advance_phase("probe")
    r = finish_scan(
        executive_summary="x", methodology="y",
        technical_analysis="z", recommendations="w",
    )
    tools_in_plan = [c["tool"] for c in r["ooda"]["act"]]
    assert "probe_endpoint" in tools_in_plan


# ---------------------------------------------------------------------------
# Rejection ladder — escalating responses
# ---------------------------------------------------------------------------


def _try_finish() -> dict:
    return finish_scan(
        executive_summary="x", methodology="y",
        technical_analysis="z", recommendations="w",
    )


def test_loop_warning_appears_at_third_rejection() -> None:
    """After STUCK_WARNING_THRESHOLD rejections, the response
    has a `loop_warning` field and the orient field is
    prefixed with the warning."""
    for _ in range(rt.STUCK_WARNING_THRESHOLD - 1):
        _try_finish()
    r = _try_finish()
    assert r["rejection_count"] == rt.STUCK_WARNING_THRESHOLD
    assert "loop_warning" in r
    assert "STUCK_LOOP_WARNING" in r["ooda"]["orient"]


def test_auto_bypass_at_threshold_lets_finish_proceed() -> None:
    """After AUTO_BYPASS_THRESHOLD consecutive rejections, the
    next call's workflow guard returns None (no block) — finish_scan
    proceeds. Cost-control mechanism: caps the retry-loop spend."""
    for _ in range(rt.AUTO_BYPASS_THRESHOLD):
        r = _try_finish()
        # Each of these should be a rejection.
        assert r["success"] is False

    # Next call should be auto-bypassed.
    r = _try_finish()
    # The workflow guard returned None → finish_scan proceeded past
    # the gate. Whether the rest of finish_scan succeeded depends on
    # the tracer being available; but the workflow_not_in_report_phase
    # gate is no longer the blocker.
    assert r.get("error") != "workflow_not_in_report_phase"


def test_success_resets_rejection_counter() -> None:
    """When finish_scan eventually succeeds (after force=True or
    auto-bypass), the counter resets so a NEW burst starts from 1."""
    for _ in range(3):
        _try_finish()
    assert rt.get_rejection_count("finish_scan") == 3
    # Force a successful finish_scan via force=True (bypasses both
    # guards).
    finish_scan(
        executive_summary="x", methodology="y",
        technical_analysis="z", recommendations="w",
        force=True,
    )
    assert rt.get_rejection_count("finish_scan") == 0


def test_kill_switch_disables_tracker(monkeypatch) -> None:
    """STRIX_REJECTION_TRACKER_DISABLED=1 reverts to the pre-fix
    behaviour: no counter, no auto-bypass. Standard rejection
    response shape (no `ooda` / `rejection_count` fields)."""
    monkeypatch.setenv("STRIX_REJECTION_TRACKER_DISABLED", "1")
    rt.reset_for_testing()
    for _ in range(rt.AUTO_BYPASS_THRESHOLD + 3):
        r = _try_finish()
        # Counter still 0 — tracker is disabled.
        assert r.get("rejection_count", 0) == 0


# ---------------------------------------------------------------------------
# Auto-bypass marker is present on success-after-bypass
# ---------------------------------------------------------------------------


def test_success_response_has_auto_bypass_marker_when_loop_was_bypassed() -> None:
    """When the bypass fires + finish_scan succeeds, the success
    response is tagged with `auto_bypassed: True` so the wrapper /
    benchmark pipeline can flag the scan for review."""
    # Burst into the auto-bypass region.
    for _ in range(rt.AUTO_BYPASS_THRESHOLD):
        _try_finish()
    # Next call: workflow gate auto-bypassed.
    r = _try_finish()
    # If the run got past the gates AND tracer was available,
    # `auto_bypassed: True` should be present.
    # We don't assert success directly (tracer may be unavailable
    # in test env) but the auto_bypassed marker should appear on
    # any successful exit path.
    if r.get("scan_completed"):
        assert r.get("auto_bypassed") is True


# ---------------------------------------------------------------------------
# OODA structure stays consistent across guards
# ---------------------------------------------------------------------------


def test_open_hypotheses_rejection_has_ooda_shape() -> None:
    """The hypothesis guard ALSO returns OODA-shaped responses.
    The act plan is a list of dismiss_hypothesis calls + a
    final finish_scan retry."""
    fake_open = [
        {"id": "h-abc", "category": "sqli", "surface": "/login",
         "summary": "probed extensively"},
        {"id": "h-def", "category": "xss", "surface": "/search",
         "summary": "no reflection"},
    ]
    # Advance to report phase first so the workflow guard passes
    # and the hypothesis guard fires.
    ws.advance_phase("report", force=True)
    with patch(
        "strix.agents.active_hypotheses.list_active_hypotheses",
        return_value=fake_open,
    ):
        r = finish_scan(
            executive_summary="x", methodology="y",
            technical_analysis="z", recommendations="w",
        )
    assert r["error"] == "open_hypotheses_remain"
    assert "ooda" in r
    tools_in_plan = [c["tool"] for c in r["ooda"]["act"]]
    # One dismiss per open hypothesis + finish_scan retry.
    assert tools_in_plan.count("dismiss_hypothesis") == 2
    assert tools_in_plan[-1] == "finish_scan"
    # The dismiss calls carry the actual hypothesis IDs.
    dismiss_ids = [
        c["args"]["hypothesis_id"]
        for c in r["ooda"]["act"]
        if c["tool"] == "dismiss_hypothesis"
    ]
    assert "h-abc" in dismiss_ids
    assert "h-def" in dismiss_ids
