"""Tests for iter-37.10 — finish_scan auto-fires terminal artifacts.

`emit_compliance_evidence` and `generate_remediation_plan` are
terminal-stage consumers of `vulnerabilities.json`. Pre-iter-37.10
they sat in the LLM's catalog as 2 of 13 minimal-core tools, but the
LLM is the wrong actor to drive them — they're guaranteed to be
called at scan-end, and skipping them is never the right call.

So they fire automatically inside `finish_scan`, freeing up two
slots in the core. Opt-out: `STRIX_FINISH_AUTO_ARTIFACTS=0`.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from strix.agents import rejection_tracker as rt
from strix.agents import workflow_state as ws
from strix.tools.finish.finish_actions import (
    _auto_fire_terminal_artifacts,
    finish_scan,
)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_REJECTION_TRACKER_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_WORKFLOW_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_FINISH_AUTO_ARTIFACTS", raising=False)
    rt.reset_for_testing()
    ws.reset_for_testing()
    yield
    rt.reset_for_testing()
    ws.reset_for_testing()


# ---------------------------------------------------------------------------
# The helper itself — direct unit tests (don't need a full scan running)
# ---------------------------------------------------------------------------


def test_auto_fire_helper_populates_artifacts():
    """When both terminal artifacts succeed, the response should
    have an `auto_artifacts` block with both keys."""
    response: dict = {"success": True}
    with patch(
        "strix.compliance.tools.emit_compliance_evidence"
    ) as mock_comp, patch(
        "strix.tools.remediation_plan.generate_remediation_plan."
        "generate_remediation_plan"
    ) as mock_rem:
        mock_comp.return_value = type(
            "R", (), {"ok": True, "tool_metadata": {"framework": "soc2"}}
        )()
        mock_rem.return_value = {
            "success": True, "status": "ok",
            "path": "/tmp/remediation_plan.md",
        }
        _auto_fire_terminal_artifacts(response)
    assert "auto_artifacts" in response
    assert response["auto_artifacts"]["compliance_evidence"]["ok"] is True
    assert response["auto_artifacts"]["remediation_plan"]["ok"] is True
    assert (
        response["auto_artifacts"]["remediation_plan"]["path"]
        == "/tmp/remediation_plan.md"
    )


def test_auto_fire_helper_records_compliance_failure():
    """If emit_compliance_evidence raises, finish_scan should still
    succeed; the failure is recorded under auto_artifacts."""
    response: dict = {"success": True}
    with patch(
        "strix.compliance.tools.emit_compliance_evidence"
    ) as mock_comp, patch(
        "strix.tools.remediation_plan.generate_remediation_plan."
        "generate_remediation_plan"
    ) as mock_rem:
        mock_comp.side_effect = RuntimeError("compliance corpus missing")
        mock_rem.return_value = {"success": True, "status": "ok"}
        _auto_fire_terminal_artifacts(response)
    assert response["auto_artifacts"]["compliance_evidence"]["ok"] is False
    assert "compliance corpus missing" in (
        response["auto_artifacts"]["compliance_evidence"]["error"]
    )
    # Remediation should still have run.
    assert response["auto_artifacts"]["remediation_plan"]["ok"] is True


def test_auto_fire_helper_records_remediation_failure():
    """If generate_remediation_plan returns success=False, that
    propagates to auto_artifacts.remediation_plan.ok."""
    response: dict = {"success": True}
    with patch(
        "strix.compliance.tools.emit_compliance_evidence"
    ) as mock_comp, patch(
        "strix.tools.remediation_plan.generate_remediation_plan."
        "generate_remediation_plan"
    ) as mock_rem:
        mock_comp.return_value = type("R", (), {"ok": True, "tool_metadata": {}})()
        mock_rem.return_value = {
            "success": False, "status": "error",
            "reason": "no findings file",
        }
        _auto_fire_terminal_artifacts(response)
    assert response["auto_artifacts"]["remediation_plan"]["ok"] is False
    assert (
        response["auto_artifacts"]["remediation_plan"]["status"] == "error"
    )


# ---------------------------------------------------------------------------
# Env-flag opt-out
# ---------------------------------------------------------------------------


def test_auto_fire_skipped_when_env_disabled(monkeypatch):
    """STRIX_FINISH_AUTO_ARTIFACTS=0 makes the helper a no-op so
    legacy callers / orchestrator-mode runs can keep driving these
    tools explicitly."""
    monkeypatch.setenv("STRIX_FINISH_AUTO_ARTIFACTS", "0")
    response: dict = {"success": True}
    with patch(
        "strix.compliance.tools.emit_compliance_evidence"
    ) as mock_comp, patch(
        "strix.tools.remediation_plan.generate_remediation_plan."
        "generate_remediation_plan"
    ) as mock_rem:
        _auto_fire_terminal_artifacts(response)
    mock_comp.assert_not_called()
    mock_rem.assert_not_called()
    assert "auto_artifacts" not in response


@pytest.mark.parametrize("val", ["false", "no", "off", "FALSE"])
def test_auto_fire_skipped_for_falsy_values(monkeypatch, val):
    monkeypatch.setenv("STRIX_FINISH_AUTO_ARTIFACTS", val)
    response: dict = {"success": True}
    with patch("strix.compliance.tools.emit_compliance_evidence") as mock_comp:
        _auto_fire_terminal_artifacts(response)
    mock_comp.assert_not_called()


# ---------------------------------------------------------------------------
# Integration: finish_scan triggers auto-fire on success
# ---------------------------------------------------------------------------


def test_finish_scan_success_invokes_auto_artifacts(monkeypatch):
    """When finish_scan reaches the success path (workflow in report
    phase + tracer available), the response includes auto_artifacts."""
    # Set workflow phase to 'report' to bypass the phase guard.
    ws.advance_phase(target="report", reason="test setup", force=True)

    with patch(
        "strix.compliance.tools.emit_compliance_evidence"
    ) as mock_comp, patch(
        "strix.tools.remediation_plan.generate_remediation_plan."
        "generate_remediation_plan"
    ) as mock_rem:
        mock_comp.return_value = type(
            "R", (), {"ok": True, "tool_metadata": {}}
        )()
        mock_rem.return_value = {
            "success": True, "status": "ok",
            "path": "/tmp/remediation_plan.md",
        }
        r = finish_scan(
            executive_summary="auto-artifact-test summary",
            methodology="auto-artifact-test methodology",
            technical_analysis="auto-artifact-test analysis",
            recommendations="auto-artifact-test recs",
        )

    # finish_scan should succeed (tracer may not be present in unit
    # context — accept the "not persisted" warning path too).
    assert r.get("success") is True
    # The auto-fire helper runs on both persistence paths.
    assert "auto_artifacts" in r
    assert r["auto_artifacts"]["compliance_evidence"]["ok"] is True
    assert r["auto_artifacts"]["remediation_plan"]["ok"] is True
    mock_comp.assert_called_once()
    mock_rem.assert_called_once()
