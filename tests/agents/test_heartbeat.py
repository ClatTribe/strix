"""Tests for run.heartbeat emission (roadmap §4)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from strix.agents.base_agent import BaseAgent
from strix.agents.state import AgentState
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
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


def _make_holder(state: AgentState):
    """Minimal stand-in for BaseAgent so we can call
    _maybe_emit_heartbeat without a full constructor."""
    class _H:
        pass
    h = _H()
    h.state = state
    return h


def _events(tracer: Tracer) -> list[dict[str, Any]]:
    p = tracer.get_run_dir() / "events.jsonl"
    if not p.exists():
        return []
    return [
        json.loads(line) for line in p.read_text().splitlines() if line.strip()
    ]


# ---------------------------------------------------------------------------
# Heartbeat emission
# ---------------------------------------------------------------------------


def test_first_call_emits_heartbeat() -> None:
    tracer = Tracer("hb-first")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "x", "value": "y"}]})

    state = AgentState(agent_name="ssrf-specialist")
    holder = _make_holder(state)

    BaseAgent._maybe_emit_heartbeat(holder, tracer)

    events = _events(tracer)
    hb = [e for e in events if (e.get("event_type") or e.get("event")) == "run.heartbeat"]
    assert len(hb) == 1
    payload = hb[0].get("payload") or {}
    assert payload["agent_name"] == "ssrf-specialist"
    assert "seconds_idle" in payload


def test_second_call_within_60s_no_emit() -> None:
    tracer = Tracer("hb-throttle")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "x", "value": "y"}]})

    state = AgentState()
    holder = _make_holder(state)

    BaseAgent._maybe_emit_heartbeat(holder, tracer)
    BaseAgent._maybe_emit_heartbeat(holder, tracer)
    BaseAgent._maybe_emit_heartbeat(holder, tracer)

    events = _events(tracer)
    hb = [e for e in events if (e.get("event_type") or e.get("event")) == "run.heartbeat"]
    assert len(hb) == 1


def test_after_60s_emits_again() -> None:
    tracer = Tracer("hb-after")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "x", "value": "y"}]})

    state = AgentState()
    holder = _make_holder(state)

    # First emission.
    BaseAgent._maybe_emit_heartbeat(holder, tracer)
    # Backdate the last_heartbeat to 90 seconds ago.
    state.last_heartbeat_emitted_at = (
        datetime.now(UTC) - timedelta(seconds=90)
    ).isoformat()
    # Should emit again.
    BaseAgent._maybe_emit_heartbeat(holder, tracer)

    events = _events(tracer)
    hb = [e for e in events if (e.get("event_type") or e.get("event")) == "run.heartbeat"]
    assert len(hb) == 2


def test_heartbeat_includes_last_activity() -> None:
    tracer = Tracer("hb-activity")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "x", "value": "y"}]})

    state = AgentState()
    state.last_tool_call_at = (
        datetime.now(UTC) - timedelta(seconds=30)
    ).isoformat()
    state.last_tool_call_name = "csrf_check"
    holder = _make_holder(state)

    BaseAgent._maybe_emit_heartbeat(holder, tracer)

    events = _events(tracer)
    hb = [e for e in events if (e.get("event_type") or e.get("event")) == "run.heartbeat"]
    assert len(hb) == 1
    payload = hb[0].get("payload") or {}
    assert payload["last_tool_call_name"] == "csrf_check"
    assert payload["seconds_idle"] >= 25  # ~30 with timing slack


def test_heartbeat_no_tracer_no_op() -> None:
    state = AgentState()
    holder = _make_holder(state)
    # Doesn't raise.
    BaseAgent._maybe_emit_heartbeat(holder, None)


def test_heartbeat_swallows_exceptions() -> None:
    """If state is corrupted, heartbeat must not break the agent loop."""

    class _BrokenState:
        @property
        def last_heartbeat_emitted_at(self):
            raise RuntimeError("oh no")

    class _H:
        pass
    h = _H()
    h.state = _BrokenState()

    tracer = Tracer("hb-broken")
    set_global_tracer(tracer)
    # Doesn't raise.
    BaseAgent._maybe_emit_heartbeat(h, tracer)


def test_heartbeat_seconds_idle_zero_when_no_activity_yet() -> None:
    tracer = Tracer("hb-no-activity")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "x", "value": "y"}]})

    state = AgentState()
    # Clear all activity timestamps to test the zero-idle path.
    state.last_updated = ""
    state.last_tool_call_at = None
    state.last_llm_request_at = None
    holder = _make_holder(state)

    BaseAgent._maybe_emit_heartbeat(holder, tracer)
    events = _events(tracer)
    hb = [e for e in events if (e.get("event_type") or e.get("event")) == "run.heartbeat"]
    assert hb
    payload = hb[0].get("payload") or {}
    assert payload["seconds_idle"] == 0
