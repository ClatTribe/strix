"""Tests for iter-Q5.15 — `think(thought)` persistence.

Pre-Q5.15: `think` was a no-op echo (validated non-empty, returned
char count, persisted nothing). The L2 audience never saw the LLM's
reasoning. Per the L2 tool audit (§1.3) the choice was: drop
entirely or convert to a persisting log. Q5.15 picks persisting.

Per CLAUDE.md §1.5.6, the LLM can think in response text; the
*side-effect* of writing that reasoning to the audit log is the
legitimate tool job — that's what makes `think` survive the
first-principles filter.
"""

from __future__ import annotations

import pytest

from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.thinking.thinking_actions import think


@pytest.fixture
def fake_tracer(monkeypatch):
    """Install a real Tracer instance (the persistence path uses a
    setattr on the singleton, so a MagicMock won't catch it cleanly)."""
    tracer = Tracer(run_name="q5-15-test")
    set_global_tracer(tracer)
    yield tracer
    set_global_tracer(None)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("STRIX_THINK_PERSIST_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["", "   ", "\n\t  "])
def test_rejects_empty_thought(bad):
    out = think(bad)
    assert out["success"] is False
    assert "cannot be empty" in out["message"].lower()


# ---------------------------------------------------------------------------
# Persistence (default behaviour post-Q5.15)
# ---------------------------------------------------------------------------


def test_think_persists_to_tracer(fake_tracer):
    out = think("Why does this endpoint accept admin: True? Investigate.")
    assert out["success"] is True
    assert out["persisted"] is True
    assert out["trace_length"] == 1
    trace = fake_tracer.lead_reasoning_trace
    assert len(trace) == 1
    assert "admin: True" in trace[0]["thought"]
    assert "ts" in trace[0]


def test_think_appends_in_order(fake_tracer):
    think("First reasoning step.")
    think("Second reasoning step.")
    think("Third reasoning step.")
    trace = fake_tracer.lead_reasoning_trace
    assert len(trace) == 3
    assert "First" in trace[0]["thought"]
    assert "Second" in trace[1]["thought"]
    assert "Third" in trace[2]["thought"]


def test_think_strips_whitespace_on_persistence(fake_tracer):
    think("  reasoning with whitespace  \n")
    trace = fake_tracer.lead_reasoning_trace
    assert trace[0]["thought"] == "reasoning with whitespace"


def test_think_returns_growing_trace_length(fake_tracer):
    out1 = think("step 1")
    out2 = think("step 2")
    assert out1["trace_length"] == 1
    assert out2["trace_length"] == 2


# ---------------------------------------------------------------------------
# Opt-out env var
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("v", ["1", "true", "yes", "on", "TRUE"])
def test_persist_disabled_reverts_to_noop(monkeypatch, fake_tracer, v):
    monkeypatch.setenv("STRIX_THINK_PERSIST_DISABLED", v)
    out = think("this should not persist")
    assert out["success"] is True
    assert out["persisted"] is False
    assert out["trace_length"] == 0
    # Tracer not mutated.
    assert getattr(fake_tracer, "lead_reasoning_trace", []) == []


@pytest.mark.parametrize("v", ["0", "false", "", "garbage"])
def test_persist_enabled_by_default(monkeypatch, fake_tracer, v):
    monkeypatch.setenv("STRIX_THINK_PERSIST_DISABLED", v)
    out = think("this should persist")
    assert out["persisted"] is True


# ---------------------------------------------------------------------------
# Defensive paths
# ---------------------------------------------------------------------------


def test_works_without_tracer(monkeypatch):
    """Before scan starts, get_global_tracer() returns None. think()
    must still succeed (returning persisted=False) — never raise."""
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: None,
    )
    out = think("preboot reasoning")
    assert out["success"] is True
    assert out["persisted"] is False
    assert out["trace_length"] == 0


def test_tracer_exception_swallowed(monkeypatch):
    """If the tracer module itself misbehaves, think() must not
    crash the scan — the LLM's chain of thought is best-effort."""
    def _raises():
        raise RuntimeError("tracer broken")
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        _raises,
    )
    out = think("hope this survives")
    assert out["success"] is True
    assert out["persisted"] is False


# ---------------------------------------------------------------------------
# run_summary integration
# ---------------------------------------------------------------------------


def test_run_summary_exposes_lead_reasoning_trace(fake_tracer):
    """iter-Q5.15 wires lead_reasoning_trace into build_run_summary()
    so the L2-audience artifact reads it without a separate API call."""
    think("Found suspicious URL shape — investigating.")
    think("Confirmed: ID enumeration vector via /api/orders/<id>.")
    summary = fake_tracer.build_run_summary()
    assert "lead_reasoning_trace" in summary
    trace = summary["lead_reasoning_trace"]
    assert len(trace) == 2
    assert "ID enumeration" in trace[1]["thought"]


def test_run_summary_empty_trace_when_think_never_called(fake_tracer):
    """No think() calls → empty trace, never missing."""
    summary = fake_tracer.build_run_summary()
    assert summary["lead_reasoning_trace"] == []


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_think_still_registered_post_q5_15():
    """The tool is still registered (not dropped) — just changed
    behaviour from no-op to persisting. The L2 catalog still has
    it in CORE."""
    from strix.tools.registry import get_tool_names
    assert "think" in get_tool_names()


def test_think_still_in_minimal_core():
    from strix.agents.lead_agent.tool_catalog import _MINIMAL_CORE_TOOLS
    assert "think" in _MINIMAL_CORE_TOOLS
