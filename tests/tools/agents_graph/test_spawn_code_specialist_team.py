"""Tests for spawn_code_specialist_team (roadmap §8.1 row 2).

Hermetic — `create_agent` is mocked. We're testing the
orchestration shape, not the underlying agent loop.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

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
    tracer = Tracer("cs-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "repository", "value": "/some/repo"}]}
    )
    yield


def _stub_create_agent(monkeypatch) -> dict[str, list[dict[str, Any]]]:
    captured: dict[str, list[dict[str, Any]]] = {"calls": []}
    counter = {"i": 0}

    def fake_create(**kwargs):
        counter["i"] += 1
        captured["calls"].append(kwargs)
        return {
            "success": True,
            "agent_id": f"agent_{counter['i']:03d}",
            "agent_info": {"category": kwargs.get("category")},
        }

    monkeypatch.setattr(
        sys.modules["strix.tools.agents_graph.agents_graph_actions"],
        "create_agent", fake_create,
    )
    return captured


def _make_agent_state(agent_id: str = "lead_001") -> Any:
    class _S:
        def __init__(self) -> None:
            self.agent_id = agent_id

        def get_conversation_history(self) -> list:
            return []

    return _S()


def _write_canonical_code_map(run_dir, **overrides) -> None:
    base = {
        "schema_version": 1,
        "repo_path": "/some/repo",
        "repo_name": "repo",
        "generated_at": "2026-05-04T12:00:00+00:00",
        "summary": {
            "files_scanned": 100,
            "routes_discovered": 12,
            "models_discovered": 5,
            "db_queries_discovered": 30,
            "external_http_calls_discovered": 8,
            "auth_boundaries_discovered": 3,
        },
    }
    base.update(overrides)
    (run_dir / "code_map.json").write_text(json.dumps(base))


def _spawn():
    from strix.tools.agents_graph.agents_graph_actions import spawn_code_specialist_team
    return spawn_code_specialist_team


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_empty_repo_path_rejected() -> None:
    out = _spawn()(agent_state=_make_agent_state(), repo_path="")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Default specialist set
# ---------------------------------------------------------------------------


def test_default_spawns_three_specialists(monkeypatch) -> None:
    captured = _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(), repo_path="/some/repo",
    )
    assert out["success"] is True
    assert out["total_spawned"] == 3
    categories = [c["category"] for c in captured["calls"]]
    assert "secret-agent" in categories
    assert "dependency-agent" in categories
    assert "sast-agent" in categories


def test_explicit_subset(monkeypatch) -> None:
    captured = _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(), repo_path="/some/repo",
        specialists="secret-agent,dependency-agent",
    )
    assert out["total_spawned"] == 2
    assert {c["category"] for c in captured["calls"]} == {
        "secret-agent", "dependency-agent",
    }


def test_unknown_category_skipped(monkeypatch) -> None:
    _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(), repo_path="/some/repo",
        specialists="secret-agent,nonexistent-specialist",
    )
    assert out["total_spawned"] == 1
    assert any(s["category"] == "nonexistent-specialist" for s in out["skipped"])


def test_dedup(monkeypatch) -> None:
    _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(), repo_path="/some/repo",
        specialists="secret-agent,secret-agent",
    )
    assert out["total_spawned"] == 1
    duplicates = [s for s in out["skipped"] if s["reason"] == "duplicate"]
    assert len(duplicates) == 1


def test_max_specialists_cap(monkeypatch) -> None:
    _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(), repo_path="/some/repo",
        max_specialists=1,
    )
    assert out["total_spawned"] == 1
    capped = [s for s in out["skipped"] if s["reason"] == "max_specialists cap"]
    assert len(capped) >= 1


# ---------------------------------------------------------------------------
# Code-map auto-load
# ---------------------------------------------------------------------------


def test_code_map_auto_loaded(monkeypatch, tmp_path) -> None:
    captured = _stub_create_agent(monkeypatch)
    tracer = tracer_module.get_global_tracer()
    _write_canonical_code_map(tracer.get_run_dir())

    out = _spawn()(
        agent_state=_make_agent_state(),
        repo_path="/some/repo",
        specialists="secret-agent",
    )
    assert out["code_map_path"] is not None
    spawn_task = captured["calls"][0]["task"]
    assert "100" in spawn_task  # files_scanned
    assert "12" in spawn_task   # routes_discovered


def test_no_code_map_still_spawns(monkeypatch) -> None:
    captured = _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(), repo_path="/some/repo",
        specialists="secret-agent",
    )
    assert out["success"] is True
    assert out["code_map_path"] is None
    spawn_task = captured["calls"][0]["task"]
    assert "no code map" in spawn_task.lower() or "build_code_map" in spawn_task


# ---------------------------------------------------------------------------
# Spawn-failure resilience
# ---------------------------------------------------------------------------


def test_spawn_exception_swallowed(monkeypatch) -> None:
    counter = {"i": 0}

    def fake_create(**kwargs):
        counter["i"] += 1
        if kwargs.get("category") == "secret-agent":
            raise RuntimeError("simulated spawn failure")
        return {
            "success": True,
            "agent_id": f"agent_{counter['i']}",
            "agent_info": {"category": kwargs.get("category")},
        }

    monkeypatch.setattr(
        sys.modules["strix.tools.agents_graph.agents_graph_actions"],
        "create_agent", fake_create,
    )

    out = _spawn()(
        agent_state=_make_agent_state(), repo_path="/some/repo",
        specialists="secret-agent,dependency-agent",
    )
    assert out["success"] is True
    assert out["total_spawned"] == 1
    assert any(
        s["category"] == "secret-agent" and "spawn_failed" in s["reason"]
        for s in out["skipped"]
    )


# ---------------------------------------------------------------------------
# inherit_context
# ---------------------------------------------------------------------------


def test_inherit_context_default_false(monkeypatch) -> None:
    captured = _stub_create_agent(monkeypatch)
    _spawn()(
        agent_state=_make_agent_state(), repo_path="/some/repo",
        specialists="secret-agent",
    )
    assert captured["calls"][0]["inherit_context"] is False


def test_inherit_context_override(monkeypatch) -> None:
    captured = _stub_create_agent(monkeypatch)
    _spawn()(
        agent_state=_make_agent_state(), repo_path="/some/repo",
        specialists="secret-agent",
        inherit_context=True,
    )
    assert captured["calls"][0]["inherit_context"] is True


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(), repo_path="/some/repo",
        specialists="secret-agent",
    )
    assert set(out.keys()) >= {
        "success", "repo_path", "repo_name", "code_map_path",
        "spawned", "skipped", "total_spawned", "max_specialists", "message",
    }
