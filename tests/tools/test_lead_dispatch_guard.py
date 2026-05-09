"""Tests for §8.5 — runtime enforcement of the architectural-commitment
that lead agents cannot spawn sub-agents.

The lead's `tool_catalog_allowlist` is informational — it lives in
`system_prompt_context` and would only constrain the model if the
prompt-rendered tool list were filtered. Today `get_tools_prompt()`
renders the full registry, so the model still sees `create_agent`'s
schema and naturally calls it. Without a dispatch-time guard the
single-lead architecture devolves to legacy parent-spawns-N at
runtime.

These tests pin the executor's refusal of blocked tools when the
caller is a lead.

The project has no async test runner installed, so we drive the
async `_execute_single_tool` via `asyncio.run` from sync test
functions.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from strix.tools.executor import _LEAD_BLOCKED_TOOLS, _execute_single_tool


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def lead_state() -> Any:
    """An AgentState-shaped object whose `category == "lead"`."""
    state = MagicMock()
    state.category = "lead"
    state.agent_id = "agent-test-lead"
    return state


@pytest.fixture
def specialist_state() -> Any:
    """An AgentState with a non-lead category — control case."""
    state = MagicMock()
    state.category = "auth-attacker"
    state.agent_id = "agent-test-specialist"
    return state


def test_lead_cannot_call_create_agent(lead_state) -> None:
    """The architectural commitment: lead → no sub-agents → no
    `create_agent`."""
    obs, images, finish = _run(_execute_single_tool(
        tool_inv={"toolName": "create_agent",
                  "args": {"task": "spawn an XSS agent", "name": "x", "skills": "xss"}},
        agent_state=lead_state,
        tracer=None,
        agent_id="agent-test-lead",
    ))
    assert "blocked under the single-lead architecture" in obs
    assert "create_agent" in obs
    # The error message must nudge the lead toward direct probing.
    assert "scan_xss" in obs or "scan_sqli" in obs or "scan_misconfig" in obs
    assert finish is False
    assert images == []


@pytest.mark.parametrize(
    "blocked",
    sorted(_LEAD_BLOCKED_TOOLS),
)
def test_lead_cannot_call_any_blocked_tool(lead_state, blocked: str) -> None:
    """Pin every name in `_LEAD_BLOCKED_TOOLS` — if a future PR adds
    a new spawn helper, this catches it."""
    obs, _, finish = _run(_execute_single_tool(
        tool_inv={"toolName": blocked, "args": {}},
        agent_state=lead_state,
        tracer=None,
        agent_id="lead",
    ))
    assert "blocked" in obs
    assert blocked in obs
    assert finish is False


def test_specialist_can_still_call_create_agent(
    specialist_state, monkeypatch
) -> None:
    """The guard is scoped to category=='lead'. A legacy parent-spawns-N
    parent (`category != 'lead'`) must still be able to spawn — that
    architecture still ships in Phase 8 until the gate flips.

    We mock `execute_tool_invocation` so the test doesn't need a real
    sandbox / real create_agent implementation."""
    fake_execute = AsyncMock(return_value={"agent_id": "child-001"})
    monkeypatch.setattr(
        "strix.tools.executor.execute_tool_invocation", fake_execute
    )
    obs, _, _ = _run(_execute_single_tool(
        tool_inv={"toolName": "create_agent",
                  "args": {"task": "t", "name": "n", "skills": "xss"}},
        agent_state=specialist_state,
        tracer=None,
        agent_id="specialist",
    ))
    fake_execute.assert_awaited_once()
    assert "blocked" not in obs


def test_lead_can_still_call_allowed_tool(lead_state, monkeypatch) -> None:
    """Sanity: the guard only refuses BLOCKED tools, not all tools.
    A normal scan_xss call from a lead must still dispatch."""
    fake_execute = AsyncMock(return_value={"status": "ok", "findings": []})
    monkeypatch.setattr(
        "strix.tools.executor.execute_tool_invocation", fake_execute
    )
    obs, _, _ = _run(_execute_single_tool(
        tool_inv={"toolName": "scan_xss",
                  "args": {"url": "http://example.com/", "params": ["q"]}},
        agent_state=lead_state,
        tracer=None,
        agent_id="lead",
    ))
    fake_execute.assert_awaited_once()
    assert "blocked" not in obs


def test_no_agent_state_does_not_trigger_guard(monkeypatch) -> None:
    """Edge case: when there's no agent state (some test paths) the
    guard must not erroneously block."""
    fake_execute = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(
        "strix.tools.executor.execute_tool_invocation", fake_execute
    )
    obs, _, _ = _run(_execute_single_tool(
        tool_inv={"toolName": "create_agent", "args": {}},
        agent_state=None,
        tracer=None,
        agent_id="unknown",
    ))
    fake_execute.assert_awaited_once()
    assert "blocked" not in obs


def test_blocked_tool_emits_tracer_error(lead_state) -> None:
    """The block must be visible to the wrapper via the tracer event,
    so the caller can see WHY their tool call didn't fire."""
    tracer = MagicMock()
    tracer.log_tool_execution_start.return_value = "exec-1"
    obs, _, _ = _run(_execute_single_tool(
        tool_inv={"toolName": "spawn_webapp_specialist_team", "args": {}},
        agent_state=lead_state,
        tracer=tracer,
        agent_id="lead",
    ))
    tracer.log_tool_execution_start.assert_called_once()
    tracer.update_tool_execution.assert_called_once()
    # Last call args: (execution_id, "error", message)
    call_args = tracer.update_tool_execution.call_args
    assert call_args[0][0] == "exec-1"
    assert call_args[0][1] == "error"
    assert "blocked" in call_args[0][2]


def test_lead_blocked_tools_matches_catalog_blocked_tools() -> None:
    """The executor's `_LEAD_BLOCKED_TOOLS` and the catalog's
    `_BLOCKED_TOOLS` must stay in sync — the catalog is the policy
    source of truth, the executor is the enforcement point. A
    divergence means the prompt's allowlist disagrees with the
    runtime guard, which would be confusing to debug."""
    from strix.agents.lead_agent.tool_catalog import list_blocked_tools

    catalog_blocked = list_blocked_tools()
    assert _LEAD_BLOCKED_TOOLS == frozenset(catalog_blocked), (
        f"executor `_LEAD_BLOCKED_TOOLS` "
        f"({sorted(_LEAD_BLOCKED_TOOLS)}) does not match "
        f"catalog `_BLOCKED_TOOLS` ({sorted(catalog_blocked)}). "
        f"Update both together."
    )
