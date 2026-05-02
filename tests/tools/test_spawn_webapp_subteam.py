"""Tests for spawn_webapp_subteam — the cross-team handoff tool.

Roadmap §8.3. Hermetic — `create_agent` is mocked so we don't actually
spawn threads. We're testing the iteration / cap / dedup / propagation
shape, not the agent-spawn machinery (covered elsewhere).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from strix.tools.agents_graph import agents_graph_actions as gga


def _stub_agent_state() -> SimpleNamespace:
    return SimpleNamespace(agent_id="parent-agent", task="orchestrating", non_interactive=True)


def _patch_create_agent(monkeypatch, *, fail_hosts: set[str] | None = None) -> list[dict[str, Any]]:
    """Replace gga.create_agent with a recorder. Returns the call log."""
    fail_hosts = fail_hosts or set()
    calls: list[dict[str, Any]] = []

    def fake_create_agent(*, agent_state, task, name, inherit_context, skills, category):
        calls.append(
            {
                "task": task,
                "name": name,
                "inherit_context": inherit_context,
                "skills": skills,
                "category": category,
            }
        )
        # Crude host extraction from name for the failure-injection path.
        host = name.replace("WebApp: ", "").strip()
        if host in fail_hosts:
            return {"success": False, "error": f"forced failure for {host}"}
        return {
            "success": True,
            "agent_id": f"agent_for_{host}",
            "agent_info": {"id": f"agent_for_{host}", "name": name, "category": category},
        }

    monkeypatch.setattr(gga, "create_agent", fake_create_agent)
    return calls


# ---------------------------------------------------------------------------
# Empty / malformed input
# ---------------------------------------------------------------------------


def test_empty_targets_returns_empty_spawn(monkeypatch) -> None:
    calls = _patch_create_agent(monkeypatch)
    out = gga.spawn_webapp_subteam(_stub_agent_state(), deep_targets="")
    assert out["success"] is True
    assert out["spawned"] == []
    assert out["skipped"] == []
    assert out["total_spawned"] == 0
    assert calls == []


def test_whitespace_only_targets(monkeypatch) -> None:
    calls = _patch_create_agent(monkeypatch)
    gga.spawn_webapp_subteam(_stub_agent_state(), deep_targets="  ,  ,")
    assert calls == []


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_one_subteam_per_host(monkeypatch) -> None:
    calls = _patch_create_agent(monkeypatch)
    out = gga.spawn_webapp_subteam(
        _stub_agent_state(), deep_targets="api.example.com,admin.example.com,app.example.com"
    )
    assert len(calls) == 3
    assert out["total_spawned"] == 3
    hosts = [c["name"].replace("WebApp: ", "") for c in calls]
    assert hosts == ["api.example.com", "admin.example.com", "app.example.com"]
    # Default category stamped on each spawn.
    assert all(c["category"] == "webapp-attacker" for c in calls)
    # Default skills.
    assert all(c["skills"] == "xss,sql_injection,authentication_jwt,ssrf,idor" for c in calls)
    # inherit_context disabled — sub-teams start fresh per host.
    assert all(c["inherit_context"] is False for c in calls)


def test_task_template_includes_host_and_url(monkeypatch) -> None:
    calls = _patch_create_agent(monkeypatch)
    gga.spawn_webapp_subteam(_stub_agent_state(), deep_targets="api.example.com")
    task = calls[0]["task"]
    assert "api.example.com" in task
    assert "https://api.example.com" in task
    # Stay-in-scope reminder.
    assert "Stay strictly within" in task or "Do not pivot" in task


def test_custom_skills_and_category_propagated(monkeypatch) -> None:
    calls = _patch_create_agent(monkeypatch)
    out = gga.spawn_webapp_subteam(
        _stub_agent_state(),
        deep_targets="auth.example.com,sso.example.com",
        skills="authentication_jwt,business_logic,csrf",
        category="auth-attacker",
    )
    assert all(c["category"] == "auth-attacker" for c in calls)
    assert all(c["skills"] == "authentication_jwt,business_logic,csrf" for c in calls)
    assert out["spawned"][0]["category"] == "auth-attacker"


# ---------------------------------------------------------------------------
# Caps + dedup + failure paths
# ---------------------------------------------------------------------------


def test_max_subteams_cap_enforced(monkeypatch) -> None:
    calls = _patch_create_agent(monkeypatch)
    out = gga.spawn_webapp_subteam(
        _stub_agent_state(),
        deep_targets="a.example.com,b.example.com,c.example.com,d.example.com",
        max_subteams=2,
    )
    assert len(calls) == 2
    assert out["total_spawned"] == 2
    skipped_hosts = [s["host"] for s in out["skipped"]]
    assert "c.example.com" in skipped_hosts
    assert "d.example.com" in skipped_hosts
    assert all(s["reason"] == "max_subteams cap" for s in out["skipped"])


def test_duplicates_skipped(monkeypatch) -> None:
    calls = _patch_create_agent(monkeypatch)
    out = gga.spawn_webapp_subteam(
        _stub_agent_state(),
        deep_targets="api.example.com,api.example.com,API.example.com",
    )
    # Three entries but only one unique host (case-insensitive).
    assert len(calls) == 1
    duplicates = [s for s in out["skipped"] if s["reason"] == "duplicate"]
    assert len(duplicates) == 2


def test_create_agent_failure_recorded_in_skipped(monkeypatch) -> None:
    calls = _patch_create_agent(monkeypatch, fail_hosts={"broken.example.com"})
    out = gga.spawn_webapp_subteam(
        _stub_agent_state(),
        deep_targets="ok.example.com,broken.example.com,ok2.example.com",
    )
    assert out["total_spawned"] == 2
    assert len(calls) == 3  # all three were attempted
    skipped_hosts = [s["host"] for s in out["skipped"]]
    assert skipped_hosts == ["broken.example.com"]


def test_create_agent_exception_caught(monkeypatch) -> None:
    """A raised exception in create_agent for one host shouldn't kill the whole batch."""
    def fake_create_agent(**kw):
        if "broken" in kw["name"]:
            raise RuntimeError("simulated thread spawn failure")
        return {
            "success": True,
            "agent_id": "ok-id",
            "agent_info": {"id": "ok-id", "category": kw["category"]},
        }

    monkeypatch.setattr(gga, "create_agent", fake_create_agent)
    out = gga.spawn_webapp_subteam(
        _stub_agent_state(),
        deep_targets="ok.example.com,broken.example.com,another-ok.example.com",
    )
    assert out["total_spawned"] == 2
    skipped_reasons = [s["reason"] for s in out["skipped"]]
    assert any("spawn_failed" in r for r in skipped_reasons)


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------


def test_spawned_entries_have_expected_shape(monkeypatch) -> None:
    _patch_create_agent(monkeypatch)
    out = gga.spawn_webapp_subteam(_stub_agent_state(), deep_targets="x.example.com")
    spawned = out["spawned"][0]
    assert set(spawned.keys()) == {"agent_id", "host", "category", "name"}
    assert spawned["host"] == "x.example.com"
    assert spawned["name"] == "WebApp: x.example.com"
    assert spawned["agent_id"] == "agent_for_x.example.com"


def test_message_summarizes_outcome(monkeypatch) -> None:
    _patch_create_agent(monkeypatch)
    out = gga.spawn_webapp_subteam(
        _stub_agent_state(), deep_targets="a,b,c", max_subteams=2
    )
    assert "Spawned 2" in out["message"]
    assert "of 3 requested" in out["message"]
