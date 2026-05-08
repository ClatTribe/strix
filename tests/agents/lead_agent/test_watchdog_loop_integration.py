"""Tests for §8.5 Phase 6 — `LeadAgent._on_iteration_tick`.

Pins the watchdog wiring: tick fires per iteration, progress
signals reset the idle counter, force-exit fires after
max_idle_turns reached, force-exit emits `run.terminated` event
once.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from strix.agents.lead_agent import LeadAgent
from strix.agents.state import AgentState
from strix.llm.config import LLMConfig


@pytest.fixture(autouse=True)
def _llm_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/gpt-4o-mini")
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    yield


def _build_lead() -> LeadAgent:
    state = AgentState(task="t", agent_name="lead", max_iterations=20)
    return LeadAgent({"state": state, "llm_config": LLMConfig()})


# ---------------------------------------------------------------------------
# WatchdogState init
# ---------------------------------------------------------------------------


def test_lead_agent_initialises_watchdog_with_default_max_idle() -> None:
    agent = _build_lead()
    assert agent._watchdog is not None
    assert agent._watchdog.max_idle_turns == 8
    assert agent._watchdog.turns_since_progress == 0


# ---------------------------------------------------------------------------
# _on_iteration_tick — progress detection
# ---------------------------------------------------------------------------


def test_iteration_tick_returns_false_when_under_threshold() -> None:
    agent = _build_lead()
    # First few ticks should never force-exit.
    for _ in range(5):
        assert agent._on_iteration_tick() is False


def test_iteration_tick_resets_on_finding_progress(monkeypatch) -> None:
    agent = _build_lead()

    fake_tracer = MagicMock()
    fake_tracer.vulnerability_reports = []
    fake_tracer.tool_executions = {}

    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: fake_tracer,
    )

    # 3 idle ticks build up.
    for _ in range(3):
        agent._on_iteration_tick()
    assert agent._watchdog.turns_since_progress == 3

    # Now a finding emerges.
    fake_tracer.vulnerability_reports = [{"id": "vuln-001"}]
    agent._on_iteration_tick()
    # Idle counter reset to 0 by record_progress.
    assert agent._watchdog.turns_since_progress == 0
    assert "finding" in agent._watchdog.progress_events


def test_iteration_tick_resets_on_completed_tool_progress(monkeypatch) -> None:
    agent = _build_lead()

    fake_tracer = MagicMock()
    fake_tracer.vulnerability_reports = []
    fake_tracer.tool_executions = {}

    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: fake_tracer,
    )

    for _ in range(3):
        agent._on_iteration_tick()
    assert agent._watchdog.turns_since_progress == 3

    # A tool execution completes.
    fake_tracer.tool_executions = {
        "exec-1": {"status": "completed", "tool_name": "send_request"},
    }
    agent._on_iteration_tick()
    assert agent._watchdog.turns_since_progress == 0
    assert "endpoint" in agent._watchdog.progress_events


# ---------------------------------------------------------------------------
# Force-exit on idle threshold
# ---------------------------------------------------------------------------


def test_iteration_tick_force_exits_at_max_idle(monkeypatch) -> None:
    agent = _build_lead()
    agent._watchdog.max_idle_turns = 3  # tighten for fast test

    fake_tracer = MagicMock()
    fake_tracer.vulnerability_reports = []
    fake_tracer.tool_executions = {}
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: fake_tracer,
    )

    # Tick threshold-1 times — should not force-exit.
    for _ in range(agent._watchdog.max_idle_turns - 1):
        assert agent._on_iteration_tick() is False

    # One more tick crosses the threshold.
    assert agent._on_iteration_tick() is True


def test_force_exit_emits_run_terminated_once(monkeypatch) -> None:
    agent = _build_lead()
    agent._watchdog.max_idle_turns = 2

    fake_tracer = MagicMock()
    fake_tracer.vulnerability_reports = []
    fake_tracer.tool_executions = {}
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: fake_tracer,
    )

    emit_calls: list[str | None] = []

    def fake_emit(reason_detail: str | None = None) -> None:
        emit_calls.append(reason_detail)

    monkeypatch.setattr(
        "strix.agents.lead_agent.watchdog.emit_watchdog_terminated",
        fake_emit,
    )

    # Tick to threshold.
    for _ in range(agent._watchdog.max_idle_turns):
        agent._on_iteration_tick()

    # First force-exit tick → emit fired once.
    agent._on_iteration_tick()  # already over threshold
    # Re-tick — should NOT emit again (latch on).
    agent._on_iteration_tick()

    assert len(emit_calls) == 1
    assert "without progress" in (emit_calls[0] or "")


# ---------------------------------------------------------------------------
# Defensive — no tracer / missing methods
# ---------------------------------------------------------------------------


def test_iteration_tick_handles_missing_tracer(monkeypatch) -> None:
    agent = _build_lead()
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: None,
    )
    # Should not raise; watchdog still ticks.
    assert agent._on_iteration_tick() is False
    assert agent._watchdog.turns_since_progress == 1


def test_iteration_tick_handles_watchdog_unavailable(monkeypatch) -> None:
    agent = _build_lead()
    agent._watchdog = None
    # Without a watchdog the hook is a no-op returning False.
    assert agent._on_iteration_tick() is False


# ---------------------------------------------------------------------------
# Base agent default — _on_iteration_tick is a no-op for non-lead agents
# ---------------------------------------------------------------------------


def test_base_agent_default_iteration_tick_is_noop() -> None:
    """StrixAgent (sub-agent path) inherits BaseAgent's default no-op
    so the watchdog wiring doesn't interfere with legacy parent-
    spawns-N behaviour."""
    from strix.agents.StrixAgent import StrixAgent

    state = AgentState(task="t", agent_name="legacy", max_iterations=10)
    agent = StrixAgent({"state": state, "llm_config": LLMConfig()})
    assert agent._on_iteration_tick() is False
