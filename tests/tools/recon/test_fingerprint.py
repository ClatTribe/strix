"""Tests for fingerprint_tech_stack.

We mock the HTTP probe so the suite is hermetic. Skill loading is mocked
via a fake agent state — no actual LLM context manipulation.
"""

from __future__ import annotations

import types
from typing import Any

import pytest

from strix.tools.recon import fingerprint


# ---------------------------------------------------------------------------
# Fake agent state for skill-load assertions
# ---------------------------------------------------------------------------


class _FakeLLM:
    def __init__(self) -> None:
        self.added: list[str] = []

    def add_skills(self, names: list[str]) -> list[str]:
        new = [n for n in names if n not in self.added]
        self.added.extend(new)
        return new


class _FakeAgentInstance:
    def __init__(self) -> None:
        self.llm = _FakeLLM()


class _FakeAgentState:
    def __init__(self, agent_id: str = "agent-1") -> None:
        self.agent_id = agent_id
        self.context: dict[str, Any] = {}

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value


@pytest.fixture
def fake_agent_state(monkeypatch) -> _FakeAgentState:
    state = _FakeAgentState("test-agent")
    instance = _FakeAgentInstance()
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions._agent_instances",
        {state.agent_id: instance},
    )
    state._fake_instance = instance  # type: ignore[attr-defined]
    return state


def _patch_probe(monkeypatch, status: int, headers: dict[str, str], body: str) -> None:
    monkeypatch.setattr(
        fingerprint, "_probe_http", lambda url: (status, headers, body)
    )


# ---------------------------------------------------------------------------
# Detection tests — header-based
# ---------------------------------------------------------------------------


def test_invalid_target_rejected(fake_agent_state) -> None:
    out = fingerprint.fingerprint_tech_stack(fake_agent_state, "")
    assert out["success"] is False


def test_unreachable_target_returns_error(monkeypatch, fake_agent_state) -> None:
    _patch_probe(monkeypatch, 0, {}, "")
    out = fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/"
    )
    assert out["success"] is False
    assert "unreachable" in out["error"]


def test_nextjs_via_x_powered_by_high_confidence(monkeypatch, fake_agent_state) -> None:
    _patch_probe(
        monkeypatch,
        200,
        {"x-powered-by": "Next.js", "server": "Vercel"},
        "<html></html>",
    )
    out = fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/"
    )
    techs = {t["technology"] for t in out["technologies"]}
    assert "nextjs" in techs
    nextjs = next(t for t in out["technologies"] if t["technology"] == "nextjs")
    assert nextjs["confidence"] == "high"
    assert "nextjs" in out["skills_loaded"]


def test_express_detected_no_skill_loaded(monkeypatch, fake_agent_state) -> None:
    """Express has no dedicated skill. Detection should occur but skill list
    should be filled from web-vuln defaults instead."""
    _patch_probe(
        monkeypatch,
        200,
        {"x-powered-by": "Express", "server": "nginx/1.18.0"},
        "<html></html>",
    )
    out = fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/"
    )
    techs = {t["technology"] for t in out["technologies"]}
    assert "express" in techs
    assert "webserver_disclosure" in techs
    # Express has no skill mapping → expect web-vuln defaults to fill the cap.
    loaded = out["skills_loaded"]
    assert "sql_injection" in loaded
    assert "xss" in loaded
    # No nextjs etc.
    assert "nextjs" not in loaded


def test_supabase_detected_via_body(monkeypatch, fake_agent_state) -> None:
    body = '<script src="https://abc.supabase.co/auth/v1/..."></script>'
    _patch_probe(monkeypatch, 200, {}, body)
    out = fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/"
    )
    techs = {t["technology"] for t in out["technologies"]}
    assert "supabase" in techs
    assert "supabase" in out["skills_loaded"]


def test_firebase_detected_via_body(monkeypatch, fake_agent_state) -> None:
    body = '<script src="https://www.gstatic.com/firebasejs/9.0.0/firebase-app.js"></script>'
    _patch_probe(monkeypatch, 200, {}, body)
    out = fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/"
    )
    techs = {t["technology"] for t in out["technologies"]}
    assert "firebase" in techs
    assert "firebase_firestore" in out["skills_loaded"]


def test_django_via_csrf_cookie(monkeypatch, fake_agent_state) -> None:
    _patch_probe(
        monkeypatch,
        200,
        {"set-cookie": "csrftoken=abc123; Path=/"},
        "<html></html>",
    )
    out = fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/"
    )
    techs = {t["technology"] for t in out["technologies"]}
    assert "django" in techs
    # Django has no dedicated skill → web-vuln defaults fill in
    assert "sql_injection" in out["skills_loaded"]


def test_cloudflare_disclosure(monkeypatch, fake_agent_state) -> None:
    _patch_probe(
        monkeypatch,
        200,
        {"server": "cloudflare", "cf-ray": "abc-LAX"},
        "<html></html>",
    )
    out = fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/"
    )
    techs = {t["technology"] for t in out["technologies"]}
    assert "cloudflare" in techs
    # Cloudflare alone (no web framework) → no web-vuln defaults loaded
    assert out["skills_loaded"] == []


# ---------------------------------------------------------------------------
# Skill-cap behaviour
# ---------------------------------------------------------------------------


def test_skill_cap_5_respected(monkeypatch, fake_agent_state) -> None:
    """Multiple high-confidence detections + web-vuln defaults shouldn't
    exceed the cap of 5."""
    body = (
        '<script id="__NEXT_DATA__">{}</script>'
        '<script src="https://abc.supabase.co/auth/v1/..."></script>'
        '<form action="/api/graphql"></form>'
    )
    _patch_probe(
        monkeypatch,
        200,
        {"x-powered-by": "Next.js", "set-cookie": "csrftoken=x; PHPSESSID=y"},
        body,
    )
    out = fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/"
    )
    assert len(out["skills_loaded"]) <= 5


def test_skill_load_dedup(monkeypatch, fake_agent_state) -> None:
    """Same skill found via multiple signals shouldn't load twice."""
    _patch_probe(
        monkeypatch,
        200,
        {"x-powered-by": "Next.js"},
        '<script id="__NEXT_DATA__">{}</script>',
    )
    out = fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/"
    )
    # nextjs detected twice (header + body) but loaded once.
    assert out["skills_loaded"].count("nextjs") == 1


# ---------------------------------------------------------------------------
# Skill-load mechanism integration
# ---------------------------------------------------------------------------


def test_load_skill_failure_returns_error_field(monkeypatch) -> None:
    """No agent instance registered → graceful error, not a raise."""
    state = _FakeAgentState("missing-agent")
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions._agent_instances", {}
    )
    _patch_probe(monkeypatch, 200, {"x-powered-by": "Next.js"}, "")
    out = fingerprint.fingerprint_tech_stack(state, "https://example.com/")
    assert out["success"] is True
    assert out["skills_loaded"] == []
    # The internal call returns a populated error string.
    assert out["skill_load_error"]


def test_recommended_skills_match_loaded_when_agent_present(
    monkeypatch, fake_agent_state
) -> None:
    _patch_probe(monkeypatch, 200, {"x-powered-by": "Next.js"}, "")
    out = fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/"
    )
    assert out["recommended_skills"] == out["skills_loaded"]


def test_target_url_normalised_without_scheme(monkeypatch, fake_agent_state) -> None:
    captured: list[str] = []
    monkeypatch.setattr(
        fingerprint,
        "_probe_http",
        lambda url: (captured.append(url) or (200, {}, "")) if True else None,
    )
    fingerprint.fingerprint_tech_stack(fake_agent_state, "example.com")
    assert captured == ["https://example.com/"]


def test_target_url_strips_path(monkeypatch, fake_agent_state) -> None:
    captured: list[str] = []
    monkeypatch.setattr(
        fingerprint,
        "_probe_http",
        lambda url: (captured.append(url) or (200, {}, "")) if True else None,
    )
    fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/api/v1/users"
    )
    # The probe always hits the root URL.
    assert captured == ["https://example.com/"]
