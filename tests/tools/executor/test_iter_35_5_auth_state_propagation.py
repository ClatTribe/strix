"""Tests for iter-35.5 — sandbox-tool captured auth states reach
host SecurityContext.

scan_auth_flow + scan_idor are now sandbox-routed (the last two
host-side specialist exceptions closed). scan_auth_flow's
``record_auth_state(label, cookies, bearer)`` call writes to the
SANDBOX'S SecurityContext singleton — invisible to the host lead's
per-turn system-prompt renderer.

iter-35.5 adds an executor-side propagation hook that, when a
sandbox tool's result contains
``tool_metadata.auth_states_captured: list[dict]``, replays each
through the host's ``record_auth_state`` so the L2 lead's prompt
picks them up.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from strix.tools.executor import (
    _propagate_auth_states_to_host,
    _propagate_sandbox_findings_to_host,
)


# ---------------------------------------------------------------------------
# Direct unit tests for the auth-state propagation helper
# ---------------------------------------------------------------------------


def test_no_tool_metadata_passes_silently():
    """Most tool results have no tool_metadata — propagation must
    be a no-op."""
    with patch(
        "strix.agents.security_context.record_auth_state",
    ) as mock_record:
        _propagate_auth_states_to_host("scan_test", {"status": "ok"})
    mock_record.assert_not_called()


def test_empty_auth_states_list_passes_silently():
    """``tool_metadata.auth_states_captured: []`` (empty list) is a
    valid no-op shape — don't crash, don't call record_auth_state."""
    with patch(
        "strix.agents.security_context.record_auth_state",
    ) as mock_record:
        _propagate_auth_states_to_host("scan_test", {
            "status": "ok",
            "tool_metadata": {"auth_states_captured": []},
        })
    mock_record.assert_not_called()


def test_single_auth_state_propagated():
    """Headline case: one captured state → one host record_auth_state
    call with the same fields."""
    with patch(
        "strix.agents.security_context.record_auth_state",
    ) as mock_record:
        _propagate_auth_states_to_host("scan_auth_flow", {
            "tool_metadata": {
                "auth_states_captured": [{
                    "label": "user-a",
                    "cookies": {"sid": "abc123"},
                    "bearer": "eyJ...JWT...",
                    "notes": "default creds",
                }],
            },
        })
    assert mock_record.call_count == 1
    call_kwargs = mock_record.call_args.kwargs
    assert call_kwargs["label"] == "user-a"
    assert call_kwargs["cookies"] == {"sid": "abc123"}
    assert call_kwargs["bearer"] == "eyJ...JWT..."
    assert call_kwargs["notes"] == "default creds"


def test_multiple_auth_states_all_propagated():
    """When scan_auth_flow captures both default-creds AND
    register-then-login sessions, both are propagated."""
    with patch(
        "strix.agents.security_context.record_auth_state",
    ) as mock_record:
        _propagate_auth_states_to_host("scan_auth_flow", {
            "tool_metadata": {
                "auth_states_captured": [
                    {
                        "label": "default-creds",
                        "cookies": {"sid": "default-sid"},
                        "bearer": None,
                    },
                    {
                        "label": "registered-user",
                        "cookies": {"sid": "reg-sid"},
                        "bearer": "reg-jwt",
                    },
                ],
            },
        })
    assert mock_record.call_count == 2
    labels = [c.kwargs["label"] for c in mock_record.call_args_list]
    assert labels == ["default-creds", "registered-user"]


def test_top_level_auth_states_also_accepted():
    """Tools that return ``auth_states_captured`` at the TOP LEVEL
    (not nested in tool_metadata) are also handled, for flexibility."""
    with patch(
        "strix.agents.security_context.record_auth_state",
    ) as mock_record:
        _propagate_auth_states_to_host("scan_test", {
            "auth_states_captured": [{
                "label": "top-level-label",
                "bearer": "tk",
            }],
        })
    assert mock_record.call_count == 1
    assert mock_record.call_args.kwargs["label"] == "top-level-label"


def test_missing_label_entry_skipped():
    """An entry without a `label` string is invalid — skip it
    instead of crashing."""
    with patch(
        "strix.agents.security_context.record_auth_state",
    ) as mock_record:
        _propagate_auth_states_to_host("scan_test", {
            "tool_metadata": {
                "auth_states_captured": [
                    {"cookies": {"sid": "x"}},  # missing label
                    {"label": "", "bearer": "tk"},  # empty label
                    {"label": "valid", "bearer": "tk"},
                ],
            },
        })
    # Only the valid entry propagates.
    assert mock_record.call_count == 1
    assert mock_record.call_args.kwargs["label"] == "valid"


def test_record_auth_state_failure_does_not_crash():
    """If record_auth_state raises, the propagation must swallow the
    error and continue with subsequent entries."""
    with patch(
        "strix.agents.security_context.record_auth_state",
    ) as mock_record:
        mock_record.side_effect = [
            RuntimeError("disk write failed"),
            None,
        ]
        _propagate_auth_states_to_host("scan_test", {
            "tool_metadata": {
                "auth_states_captured": [
                    {"label": "first-fails"},
                    {"label": "second-succeeds"},
                ],
            },
        })
    # Both calls attempted; the failure was swallowed.
    assert mock_record.call_count == 2


def test_non_dict_result_passes_silently():
    """Tools that return non-dict results (string, list, etc.) must
    not crash the propagation helper."""
    with patch(
        "strix.agents.security_context.record_auth_state",
    ) as mock_record:
        _propagate_auth_states_to_host("scan_test", "raw string return")
        _propagate_auth_states_to_host("scan_test", None)
        _propagate_auth_states_to_host("scan_test", [1, 2, 3])
    mock_record.assert_not_called()


# ---------------------------------------------------------------------------
# Integration: full _propagate_sandbox_findings_to_host invokes both
# propagation paths
# ---------------------------------------------------------------------------


def test_findings_and_auth_state_both_propagate_from_one_result():
    """When a sandbox tool emits BOTH findings (via the iter-35.4
    sidecar) AND auth states (via tool_metadata, iter-35.5), the
    executor's single propagation entry point must fire both hooks."""
    captured_findings: list[dict[str, Any]] = []

    def fake_tracer_add(  # noqa: PLR0913
        title: str, severity: str,
        endpoint: str | None = None, cwe: str | None = None,
        description: str | None = None, category: str | None = None,
    ) -> str:
        captured_findings.append({
            "title": title, "severity": severity,
            "endpoint": endpoint, "cwe": cwe,
            "description": description, "category": category,
        })
        return "vuln-0001"

    fake_tracer = type("FakeTracer", (), {})()
    fake_tracer.add_vulnerability_report = fake_tracer_add

    result = {
        "status": "ok",
        "_sandbox_emitted_findings": [{
            "title": "Default credentials accepted",
            "severity": "high",
            "cwe": "CWE-521",
            "endpoint": "/rest/user/login",
            "category": "auth",
        }],
        "tool_metadata": {
            "auth_states_captured": [{
                "label": "default-creds",
                "cookies": {"connect.sid": "s%3A..."},
                "bearer": "eyJ.JWT.token",
                "notes": "admin@juice.sh/admin123",
            }],
        },
    }
    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=fake_tracer,
    ), patch(
        "strix.agents.security_context.record_auth_state",
    ) as mock_record:
        out = _propagate_sandbox_findings_to_host("scan_auth_flow", result)

    # Finding propagation fired.
    assert len(captured_findings) == 1
    assert captured_findings[0]["title"] == "Default credentials accepted"
    # Auth-state propagation fired.
    assert mock_record.call_count == 1
    assert mock_record.call_args.kwargs["label"] == "default-creds"
    assert mock_record.call_args.kwargs["bearer"] == "eyJ.JWT.token"
    # Sidecar stripped from returned result.
    assert "_sandbox_emitted_findings" not in out
    # tool_metadata stays (the LLM may want to read it).
    assert "tool_metadata" in out


# ---------------------------------------------------------------------------
# scan_auth_flow + scan_idor are flagged sandbox-routed
# ---------------------------------------------------------------------------


def test_scan_auth_flow_routes_to_sandbox():
    """The headline contract change: scan_auth_flow now runs INSIDE
    the sandbox container, closing the last specialist host-side
    exception documented in CLAUDE.md §3.6."""
    from strix.tools.executor import should_execute_in_sandbox
    assert should_execute_in_sandbox("scan_auth_flow"), (
        "iter-35.5 — scan_auth_flow must be sandbox-routed. If this "
        "fails, the @register_specialist_tool decorator regressed to "
        "sandbox_execution=False, breaking the iter-35 sandbox-only "
        "guarantee."
    )


def test_scan_idor_routes_to_sandbox():
    """Companion to scan_auth_flow — scan_idor needs the auth states
    that live in sandbox SecurityContext, so it must run sandbox-side
    too."""
    from strix.tools.executor import should_execute_in_sandbox
    assert should_execute_in_sandbox("scan_idor"), (
        "iter-35.5 — scan_idor must be sandbox-routed."
    )
