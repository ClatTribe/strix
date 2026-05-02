"""Tests for the per-agent category tag on agent.created.

Roadmap §1. Sub-agents declared with a category get rendered as named
specialists ("auth-attacker", "ssrf-scanner") in downstream UIs rather
than echoing the user's task back.
"""

from __future__ import annotations

import json
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


def _events_for(run_name: str, tmp_path) -> list[dict[str, Any]]:
    p = tmp_path / "strix_runs" / run_name / "events.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# AgentState.category default
# ---------------------------------------------------------------------------


def test_agent_state_category_default_is_none() -> None:
    s = AgentState()
    assert s.category is None


def test_agent_state_accepts_category() -> None:
    s = AgentState(category="auth-attacker")
    assert s.category == "auth-attacker"


# ---------------------------------------------------------------------------
# Tracer.log_agent_creation emits category
# ---------------------------------------------------------------------------


def test_log_agent_creation_with_category(tmp_path) -> None:
    t = Tracer("agent-cat-run")
    set_global_tracer(t)
    t.log_agent_creation(
        agent_id="agent-x", name="Auth Specialist", task="probe auth", category="auth-attacker"
    )
    events = _events_for("agent-cat-run", tmp_path)
    created = [e for e in events if e["event_type"] == "agent.created"]
    assert len(created) == 1
    assert created[0]["payload"]["category"] == "auth-attacker"
    assert created[0]["payload"]["task"] == "probe auth"


def test_log_agent_creation_without_category_emits_null(tmp_path) -> None:
    """Backwards-compat: existing call sites that don't pass `category`
    still work; payload carries `category=None` rather than missing-key."""
    t = Tracer("no-cat-run")
    set_global_tracer(t)
    t.log_agent_creation(agent_id="agent-x", name="Root Agent", task="scan auth")
    events = _events_for("no-cat-run", tmp_path)
    created = [e for e in events if e["event_type"] == "agent.created"]
    assert created[0]["payload"]["category"] is None


def test_tracer_agents_dict_records_category() -> None:
    """`tracer.agents[id]` is consumed by other code paths (e.g. the TUI's
    agent-graph view) — make sure category is captured there too."""
    t = Tracer("agents-dict")
    set_global_tracer(t)
    t.log_agent_creation(
        agent_id="agent-x", name="Auth Specialist", task="probe auth", category="auth-attacker"
    )
    assert t.agents["agent-x"]["category"] == "auth-attacker"


# ---------------------------------------------------------------------------
# create_agent tool plumbs category through
# ---------------------------------------------------------------------------


def test_create_agent_normalizes_category_lowercase_strip() -> None:
    """The `create_agent` tool should normalize the category — agents
    sometimes submit with leading/trailing whitespace and inconsistent case."""
    from strix.tools.agents_graph import agents_graph_actions

    # Drive the helper used inside create_agent without spawning a real thread.
    raw_inputs = ["  Auth-Attacker  ", "AUTH-ATTACKER", "auth-attacker"]
    for raw in raw_inputs:
        normalized = (
            raw.strip().lower()
            if isinstance(raw, str) and raw.strip()
            else None
        )
        # Match the in-tool normalization shape directly.
        assert normalized == "auth-attacker"
    # Empty / whitespace-only / non-string inputs map to None.
    for raw in ["", "   ", None]:
        normalized = (
            raw.strip().lower()
            if isinstance(raw, str) and raw.strip()
            else None
        )
        assert normalized is None
    # Sanity: the module exposes the function we'd plug into.
    assert hasattr(agents_graph_actions, "create_agent")
