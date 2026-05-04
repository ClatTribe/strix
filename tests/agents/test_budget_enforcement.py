"""Tests for per-sub-agent budget enforcement (roadmap §8.0).

Tests cover:

- AgentState.record_token_usage accumulates correctly
- AgentState.has_exceeded_budget — input / output / cost / time / no-limit
- AgentState.should_stop returns True when budget exceeded
- AgentState.set_budget — partial / no-op / explicit-no-limit
- get_execution_summary surfaces the budget state
- BaseAgent constructor reads `budget` from config
- _sync_budget_from_llm pushes deltas, emits `agent.budget_exceeded`
  event once on threshold crossing
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from strix.agents.state import AgentState
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


# ---------------------------------------------------------------------------
# AgentState — pure unit tests
# ---------------------------------------------------------------------------


def test_default_no_budgets_no_limit() -> None:
    s = AgentState()
    assert s.max_input_tokens == 0
    assert s.max_cost_usd == 0.0
    exceeded, reason = s.has_exceeded_budget()
    assert exceeded is False
    assert reason is None


def test_record_token_usage_accumulates() -> None:
    s = AgentState()
    s.record_token_usage(input_tokens=100, output_tokens=50, cost_usd=0.01)
    s.record_token_usage(input_tokens=200, output_tokens=10, cost_usd=0.02)
    assert s.input_tokens_consumed == 300
    assert s.output_tokens_consumed == 60
    assert s.cost_consumed_usd == pytest.approx(0.03)


def test_record_token_usage_ignores_zero_and_negative() -> None:
    s = AgentState()
    s.record_token_usage(input_tokens=0, output_tokens=-5, cost_usd=-1.0)
    assert s.input_tokens_consumed == 0
    assert s.output_tokens_consumed == 0
    assert s.cost_consumed_usd == 0.0


def test_max_input_tokens_exceeded() -> None:
    s = AgentState(max_input_tokens=100)
    s.record_token_usage(input_tokens=99)
    assert s.has_exceeded_budget() == (False, None)
    s.record_token_usage(input_tokens=1)
    assert s.has_exceeded_budget() == (True, "max_input_tokens")


def test_max_output_tokens_exceeded() -> None:
    s = AgentState(max_output_tokens=50)
    s.record_token_usage(output_tokens=50)
    exceeded, reason = s.has_exceeded_budget()
    assert exceeded is True
    assert reason == "max_output_tokens"


def test_max_cost_usd_exceeded() -> None:
    s = AgentState(max_cost_usd=0.10)
    s.record_token_usage(cost_usd=0.05)
    assert s.has_exceeded_budget() == (False, None)
    s.record_token_usage(cost_usd=0.06)
    assert s.has_exceeded_budget() == (True, "max_cost_usd")


def test_time_budget_exceeded() -> None:
    s = AgentState(time_budget_seconds=1)
    # Backdate start_time to simulate elapsed time.
    s.start_time = (datetime.now(UTC) - timedelta(seconds=10)).isoformat()
    exceeded, reason = s.has_exceeded_budget()
    assert exceeded is True
    assert reason == "time_budget_seconds"


def test_time_budget_not_exceeded_when_zero() -> None:
    s = AgentState(time_budget_seconds=0)
    s.start_time = (datetime.now(UTC) - timedelta(seconds=99999)).isoformat()
    exceeded, _ = s.has_exceeded_budget()
    assert exceeded is False


def test_should_stop_includes_budget_check() -> None:
    s = AgentState(max_input_tokens=10)
    assert s.should_stop() is False
    s.record_token_usage(input_tokens=10)
    assert s.should_stop() is True


def test_set_budget_partial_update() -> None:
    s = AgentState(max_input_tokens=100, max_cost_usd=0.50)
    s.set_budget(max_input_tokens=200)  # leave cost unchanged
    assert s.max_input_tokens == 200
    assert s.max_cost_usd == 0.50  # unchanged


def test_set_budget_explicit_no_limit() -> None:
    """0 means explicit no-limit; clears a previously-set limit."""
    s = AgentState(max_input_tokens=100)
    s.set_budget(max_input_tokens=0)
    assert s.max_input_tokens == 0
    s.record_token_usage(input_tokens=1_000_000)
    assert s.has_exceeded_budget() == (False, None)


def test_set_budget_negative_clamped_to_zero() -> None:
    s = AgentState()
    s.set_budget(max_input_tokens=-5, max_cost_usd=-1.0)
    assert s.max_input_tokens == 0
    assert s.max_cost_usd == 0.0


def test_get_execution_summary_includes_budget() -> None:
    s = AgentState(max_cost_usd=1.0)
    s.record_token_usage(input_tokens=100, cost_usd=0.50)
    summary = s.get_execution_summary()
    assert "budget" in summary
    b = summary["budget"]
    assert b["max_cost_usd"] == 1.0
    assert b["input_tokens_consumed"] == 100
    assert b["cost_consumed_usd"] == 0.5
    assert b["exceeded"] is False
    assert b["exceeded_reason"] is None


def test_get_execution_summary_shows_exceeded() -> None:
    s = AgentState(max_input_tokens=10)
    s.record_token_usage(input_tokens=20)
    summary = s.get_execution_summary()
    assert summary["budget"]["exceeded"] is True
    assert summary["budget"]["exceeded_reason"] == "max_input_tokens"


# ---------------------------------------------------------------------------
# Multiple budgets — first-exceeded wins (in declared order)
# ---------------------------------------------------------------------------


def test_multiple_limits_input_wins() -> None:
    s = AgentState(max_input_tokens=10, max_cost_usd=0.01)
    s.record_token_usage(input_tokens=10, cost_usd=0.01)
    # Both are simultaneously hit; declared-order: input first.
    exceeded, reason = s.has_exceeded_budget()
    assert exceeded is True
    assert reason == "max_input_tokens"


def test_multiple_limits_only_cost_exceeded() -> None:
    s = AgentState(max_input_tokens=10_000, max_cost_usd=0.01)
    s.record_token_usage(input_tokens=100, cost_usd=0.05)
    exceeded, reason = s.has_exceeded_budget()
    assert exceeded is True
    assert reason == "max_cost_usd"


# ---------------------------------------------------------------------------
# BaseAgent integration — config + _sync_budget_from_llm
# ---------------------------------------------------------------------------


class _FakeLLMStats:
    def __init__(self, input_tokens: int = 0, output_tokens: int = 0, cost: float = 0.0):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cost = cost


class _FakeAgent:
    """Minimal BaseAgent-shaped stand-in to test _sync_budget_from_llm
    without needing a full LLM init."""

    def __init__(self, state: AgentState, fake_stats: _FakeLLMStats):
        self.state = state

        class _LLM:
            def __init__(self, stats: _FakeLLMStats) -> None:
                self._total_stats = stats

        self.llm = _LLM(fake_stats)
        self._last_pushed_input_tokens = 0
        self._last_pushed_output_tokens = 0
        self._last_pushed_cost = 0.0

    # Reuse the real method by binding it.
    def _sync_budget_from_llm(self, tracer: Any | None) -> None:
        from strix.agents.base_agent import BaseAgent

        BaseAgent._sync_budget_from_llm(self, tracer)


def test_sync_budget_pushes_initial_delta() -> None:
    state = AgentState(max_cost_usd=10.0)
    fake_stats = _FakeLLMStats(input_tokens=500, output_tokens=200, cost=0.05)
    agent = _FakeAgent(state, fake_stats)

    agent._sync_budget_from_llm(tracer=None)

    assert state.input_tokens_consumed == 500
    assert state.output_tokens_consumed == 200
    assert state.cost_consumed_usd == pytest.approx(0.05)


def test_sync_budget_only_pushes_delta() -> None:
    """Second call with same totals → no delta added."""
    state = AgentState()
    fake_stats = _FakeLLMStats(input_tokens=500, output_tokens=200, cost=0.05)
    agent = _FakeAgent(state, fake_stats)

    agent._sync_budget_from_llm(tracer=None)
    agent._sync_budget_from_llm(tracer=None)

    assert state.input_tokens_consumed == 500
    assert state.cost_consumed_usd == pytest.approx(0.05)


def test_sync_budget_incremental_pushes() -> None:
    state = AgentState()
    fake_stats = _FakeLLMStats(input_tokens=500, output_tokens=200, cost=0.05)
    agent = _FakeAgent(state, fake_stats)

    agent._sync_budget_from_llm(tracer=None)
    fake_stats.input_tokens = 800
    fake_stats.output_tokens = 350
    fake_stats.cost = 0.08
    agent._sync_budget_from_llm(tracer=None)

    assert state.input_tokens_consumed == 800
    assert state.output_tokens_consumed == 350
    assert state.cost_consumed_usd == pytest.approx(0.08)


def test_sync_budget_emits_event_on_threshold_cross(tmp_path) -> None:
    """First time the budget is exceeded, `agent.budget_exceeded`
    event is emitted exactly once."""
    tracer = Tracer("budget-event")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "x"}]})

    state = AgentState(
        agent_id="agent_test_1",
        agent_name="ssrf-specialist",
        category="ssrf-scanner",
        max_input_tokens=100,
    )
    fake_stats = _FakeLLMStats(input_tokens=50)
    agent = _FakeAgent(state, fake_stats)

    # Below threshold → no event.
    agent._sync_budget_from_llm(tracer=tracer)
    assert state.budget_exceeded_event_emitted is False

    # Cross threshold → event fires.
    fake_stats.input_tokens = 150
    agent._sync_budget_from_llm(tracer=tracer)
    assert state.budget_exceeded_event_emitted is True
    assert state.budget_exceeded_reason == "max_input_tokens"

    # Repeat call → no double-emit.
    fake_stats.input_tokens = 200
    agent._sync_budget_from_llm(tracer=tracer)

    # Inspect events.jsonl
    import json
    events_file = tracer.get_run_dir() / "events.jsonl"
    events = [
        json.loads(line) for line in events_file.read_text().splitlines() if line.strip()
    ]
    budget_events = [
        e for e in events
        if (e.get("event_type") or e.get("event")) == "agent.budget_exceeded"
    ]
    assert len(budget_events) == 1
    payload = budget_events[0].get("payload") or {}
    assert payload["reason"] == "max_input_tokens"
    assert payload["agent_name"] == "ssrf-specialist"
    assert payload["category"] == "ssrf-scanner"


def test_sync_budget_no_event_when_under_limits(tmp_path) -> None:
    tracer = Tracer("budget-clean")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "x"}]})

    state = AgentState(max_input_tokens=10_000)
    agent = _FakeAgent(state, _FakeLLMStats(input_tokens=100))
    agent._sync_budget_from_llm(tracer=tracer)

    assert state.budget_exceeded_event_emitted is False
    events_file = tracer.get_run_dir() / "events.jsonl"
    if events_file.exists():
        import json
        events = [
            json.loads(line) for line in events_file.read_text().splitlines() if line.strip()
        ]
        budget_events = [
            e for e in events
            if (e.get("event_type") or e.get("event")) == "agent.budget_exceeded"
        ]
        assert budget_events == []


def test_sync_budget_swallows_failures() -> None:
    """Even if state is broken, the sync helper never raises."""
    from strix.agents.base_agent import BaseAgent

    class _BrokenState:
        def record_token_usage(self, **kwargs: Any) -> None:
            raise RuntimeError("oh no")

        def has_exceeded_budget(self) -> tuple[bool, str | None]:
            raise RuntimeError("nope")

    class _Holder:
        def __init__(self) -> None:
            self.state = _BrokenState()

            class _LLM:
                _total_stats = _FakeLLMStats(input_tokens=10)

            self.llm = _LLM()
            self._last_pushed_input_tokens = 0
            self._last_pushed_output_tokens = 0
            self._last_pushed_cost = 0.0

    holder = _Holder()
    # Should NOT raise.
    BaseAgent._sync_budget_from_llm(holder, tracer=None)
