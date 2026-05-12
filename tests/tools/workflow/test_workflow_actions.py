"""Tests for `workflow_status` + `advance_workflow_phase` agent
tools (Phase 3d / PR-α).

These are the lead's interface to the workflow state machine. The
state machine itself is tested in tests/agents/test_workflow_state.py;
here we pin the tool wrappers' response shape + error handling.
"""

from __future__ import annotations

import pytest

from strix.agents import workflow_state as ws
from strix.tools.workflow.workflow_actions import (
    advance_workflow_phase,
    workflow_status,
)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_WORKFLOW_DISABLED", raising=False)
    ws.reset_for_testing()
    yield
    ws.reset_for_testing()


# ---------------------------------------------------------------------------
# workflow_status
# ---------------------------------------------------------------------------


def test_workflow_status_returns_success_true() -> None:
    """The tool wrapper adds `success: True` to the snapshot."""
    out = workflow_status()
    assert out["success"] is True
    assert out["current_phase"] == "recon"


def test_workflow_status_carries_full_snapshot() -> None:
    """All expected snapshot keys are present in the response.
    Wrappers / dashboards rely on this shape."""
    out = workflow_status()
    expected_keys = {
        "current_phase", "phase_history", "elapsed_s",
        "endpoints_discovered_count", "post_auth_endpoints_discovered_count",
        "endpoints_probed_count", "unprobed_endpoints_sample",
        "login_forms_found", "auth_state_captured",
        "captured_auth_labels",
        "findings_emitted", "chains_emitted",
        "gates", "next_recommended_actions", "workflow_disabled",
    }
    assert expected_keys.issubset(out.keys())


def test_workflow_status_reflects_progress() -> None:
    """Recorders update the snapshot — calling workflow_status()
    after recording progress shows the new state."""
    ws.record_endpoint_discovered("https://x.com/api/users")
    ws.record_login_form_found("https://x.com/login")
    out = workflow_status()
    assert out["endpoints_discovered_count"] == 1
    assert "https://x.com/login" in out["login_forms_found"]


# ---------------------------------------------------------------------------
# advance_workflow_phase
# ---------------------------------------------------------------------------


def test_advance_to_invalid_phase_returns_error() -> None:
    out = advance_workflow_phase("bogus")
    assert out["success"] is False
    assert out["error"] == "invalid_target_phase"
    assert "valid_phases" in out
    assert "recon" in out["valid_phases"]


def test_advance_blocked_by_gate_returns_message() -> None:
    """auth_attempt blocked without login form → response is
    `success: False, transitioned: False` with the gate's reason."""
    out = advance_workflow_phase("auth_attempt")
    assert out["success"] is False
    assert out["transitioned"] is False
    assert "login form" in out["message"].lower()
    # Current phase didn't change.
    assert out["current_phase"] == "recon"


def test_advance_succeeds_after_prerequisites_met() -> None:
    ws.record_endpoint_discovered("https://x.com/a")
    out = advance_workflow_phase("probe", reason="ready to fan out")
    assert out["success"] is True
    assert out["transitioned"] is True
    assert out["current_phase"] == "probe"
    # Surfaces the next actions for this new phase.
    assert out["next_recommended_actions"]


def test_advance_force_bypasses_gate() -> None:
    """force=True skips the gate validation."""
    out = advance_workflow_phase("probe", force=True)
    assert out["success"] is True
    assert out["current_phase"] == "probe"


def test_advance_returns_recommended_actions_for_new_phase() -> None:
    """After a successful transition the tool surfaces the
    recommended actions for the NEW phase — saves the lead a
    separate workflow_status() call."""
    ws.record_endpoint_discovered("https://x.com/api/users")
    out = advance_workflow_phase("probe")
    actions = out["next_recommended_actions"]
    assert actions  # not empty
    # Mentions unprobed endpoints
    assert any("unprobed" in a.lower() or "fan out" in a.lower()
               for a in actions)


def test_advance_normalises_case_and_whitespace() -> None:
    """Target phase is case- + whitespace-tolerant. `'  PROBE  '`
    should resolve to `'probe'`. Defensive — even if the LLM emits
    an unexpected casing, we still hit the right gate."""
    ws.record_endpoint_discovered("https://x.com/a")
    out = advance_workflow_phase("  PROBE  ", reason="caps + spaces")
    assert out["success"] is True
    assert out["current_phase"] == "probe"
