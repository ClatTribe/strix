"""Tests for iter-33.1 — deterministic auth re-attempt against
discovered login forms.

Verifies that `_retry_default_creds_against_login_forms` reads the
workflow_state login form list and fires probe_default_creds against
each URL. This closes the post-auth gap on SPAs / JS-rendered apps
where the phase-1 default-creds anchor (running against root URL)
never lands a session.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch, MagicMock

import pytest

from strix.agents import workflow_state
from strix.agents.lead_agent.anchor_prepass import (
    PrepassSummary,
    _retry_default_creds_against_login_forms,
)


def _run(coro):
    """Local async-test helper — repo doesn't have pytest-asyncio."""
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _reset_workflow():
    workflow_state.reset_for_testing()
    yield
    workflow_state.reset_for_testing()


def _empty_summary() -> PrepassSummary:
    """Minimal PrepassSummary for the helper to mutate."""
    return PrepassSummary(
        target_type="web_application",
        target_value="http://app",
    )


# ---------------------------------------------------------------------------
# No-op cases
# ---------------------------------------------------------------------------

def test_noop_when_no_login_forms_discovered():
    """Empty login_forms_found → helper returns without firing."""
    summary = _empty_summary()
    initial_n = len(summary.tool_results)

    with patch(
        "strix.tools.default_creds_probe.probe_default_creds.probe_default_creds"
    ) as mock_probe:
        _run(_retry_default_creds_against_login_forms(
            summary, target_value="http://app", agent_state=None, timeout_s=10,
        ))

    mock_probe.assert_not_called()
    assert len(summary.tool_results) == initial_n


def test_noop_when_auth_already_captured():
    """When phase-1 already landed a session, don't re-fire."""
    workflow_state.record_login_form_found("http://app/login")
    # Synthesize auth-captured state via the workflow_state public API.
    workflow_state._get_or_create().auth_state_captured = True

    summary = _empty_summary()
    with patch(
        "strix.tools.default_creds_probe.probe_default_creds.probe_default_creds"
    ) as mock_probe:
        _run(_retry_default_creds_against_login_forms(
            summary, target_value="http://app", agent_state=None, timeout_s=10,
        ))

    mock_probe.assert_not_called()


def test_noop_on_workflow_state_module_error(monkeypatch):
    """If workflow_state.snapshot() raises, helper bails cleanly."""
    def _boom():
        raise RuntimeError("synthetic")
    monkeypatch.setattr(workflow_state, "snapshot", _boom, raising=True)

    summary = _empty_summary()
    # Must not raise
    _run(_retry_default_creds_against_login_forms(
        summary, target_value="http://app", agent_state=None, timeout_s=10,
    ))


# ---------------------------------------------------------------------------
# Happy path: forms present, probe fires
# ---------------------------------------------------------------------------

def test_fires_probe_against_each_login_url():
    """Each discovered login URL gets one probe_default_creds call."""
    workflow_state.record_login_form_found("http://app/login")
    workflow_state.record_login_form_found("http://app/api/auth")

    summary = _empty_summary()
    with patch(
        "strix.tools.default_creds_probe.probe_default_creds.probe_default_creds",
        return_value={"default_credential_found": False, "findings": []},
    ) as mock_probe:
        _run(_retry_default_creds_against_login_forms(
            summary, target_value="http://app", agent_state=None, timeout_s=10,
        ))

    # Both URLs got tried (since none succeeded; helper short-circuits on success)
    assert mock_probe.call_count == 2
    # Each call should pass the login_url
    for call in mock_probe.call_args_list:
        assert "login_url" in call.kwargs
        assert call.kwargs["login_url"].startswith("http://app/")
    # ToolResult records were appended
    assert len(summary.tool_results) == 2


def test_short_circuits_on_first_success():
    """First credential success ends the loop (one session is enough)."""
    workflow_state.record_login_form_found("http://app/login")
    workflow_state.record_login_form_found("http://app/api/auth")
    workflow_state.record_login_form_found("http://app/oauth")

    summary = _empty_summary()
    # First call succeeds → others should never be tried
    with patch(
        "strix.tools.default_creds_probe.probe_default_creds.probe_default_creds",
        return_value={"default_credential_found": True, "findings": [{}]},
    ) as mock_probe:
        _run(_retry_default_creds_against_login_forms(
            summary, target_value="http://app", agent_state=None, timeout_s=10,
        ))

    assert mock_probe.call_count == 1


def test_caps_at_5_login_urls():
    """Discovery dumps don't blow the budget — max 5 URLs."""
    for i in range(20):
        workflow_state.record_login_form_found(f"http://app/login-{i}")

    summary = _empty_summary()
    with patch(
        "strix.tools.default_creds_probe.probe_default_creds.probe_default_creds",
        return_value={"default_credential_found": False},
    ) as mock_probe:
        _run(_retry_default_creds_against_login_forms(
            summary, target_value="http://app", agent_state=None, timeout_s=10,
        ))

    assert mock_probe.call_count == 5


def test_dedups_duplicate_login_urls():
    """If recon recorded the same URL twice, probe it once."""
    workflow_state.record_login_form_found("http://app/login")
    workflow_state.record_login_form_found("http://app/login")  # dup
    workflow_state.record_login_form_found("http://app/login")  # dup

    summary = _empty_summary()
    with patch(
        "strix.tools.default_creds_probe.probe_default_creds.probe_default_creds",
        return_value={"default_credential_found": False},
    ) as mock_probe:
        _run(_retry_default_creds_against_login_forms(
            summary, target_value="http://app", agent_state=None, timeout_s=10,
        ))

    # Helper dedups internally so call_count is 1 regardless of how
    # many duplicates were in workflow_state
    assert mock_probe.call_count == 1


def test_records_status_ok_on_credential_success():
    workflow_state.record_login_form_found("http://app/login")

    summary = _empty_summary()
    with patch(
        "strix.tools.default_creds_probe.probe_default_creds.probe_default_creds",
        return_value={
            "default_credential_found": True,
            "findings": [{"category": "weak_auth"}, {"category": "weak_auth"}],
        },
    ):
        _run(_retry_default_creds_against_login_forms(
            summary, target_value="http://app", agent_state=None, timeout_s=10,
        ))

    assert len(summary.tool_results) == 1
    tr = summary.tool_results[0]
    assert tr.status == "ok"
    assert tr.findings_count >= 1


def test_records_status_partial_on_no_default_landed():
    workflow_state.record_login_form_found("http://app/login")

    summary = _empty_summary()
    with patch(
        "strix.tools.default_creds_probe.probe_default_creds.probe_default_creds",
        return_value={"default_credential_found": False},
    ):
        _run(_retry_default_creds_against_login_forms(
            summary, target_value="http://app", agent_state=None, timeout_s=10,
        ))

    assert summary.tool_results[0].status == "partial"


def test_records_status_error_when_probe_raises():
    workflow_state.record_login_form_found("http://app/login")

    summary = _empty_summary()
    with patch(
        "strix.tools.default_creds_probe.probe_default_creds.probe_default_creds",
        side_effect=RuntimeError("synthetic"),
    ):
        _run(_retry_default_creds_against_login_forms(
            summary, target_value="http://app", agent_state=None, timeout_s=10,
        ))

    assert len(summary.tool_results) == 1
    assert summary.tool_results[0].status == "error"
    assert "synthetic" in (summary.tool_results[0].error_reason or "")


def test_filters_non_string_login_urls():
    """Garbage entries in login_forms_found are skipped."""
    workflow_state.record_login_form_found("http://app/login")
    # record_login_form_found may filter non-strings itself, but ensure
    # the helper is also robust
    state = workflow_state._get_or_create()
    state.login_forms_found.append(42)  # type: ignore[arg-type]
    state.login_forms_found.append(None)  # type: ignore[arg-type]
    state.login_forms_found.append("")

    summary = _empty_summary()
    with patch(
        "strix.tools.default_creds_probe.probe_default_creds.probe_default_creds",
        return_value={"default_credential_found": False},
    ) as mock_probe:
        _run(_retry_default_creds_against_login_forms(
            summary, target_value="http://app", agent_state=None, timeout_s=10,
        ))

    # Only the one valid string URL got probed
    assert mock_probe.call_count == 1


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_helper_source_has_no_sut_specific_strings():
    """The helper must not hardcode SUT-specific URLs or credentials."""
    import strix.agents.lead_agent.anchor_prepass as mod
    src = open(mod.__file__).read()
    # Locate the iter-33.1 helper text section
    start = src.find("_retry_default_creds_against_login_forms")
    end = src.find("async def _run_dependent_api_tools")
    helper_src = src[start:end].lower()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "jsmith", "demo1234", "vampi", "erev0s",
        "/users/v1/_debug",
    )
    for tok in forbidden:
        assert tok not in helper_src, (
            f"iter-33.1 helper contains SUT-specific value {tok!r}"
        )
