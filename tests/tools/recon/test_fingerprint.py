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


# ---------------------------------------------------------------------------
# OpenAPI / Swagger probe (deep mode)
# ---------------------------------------------------------------------------


def _make_fake_httpx_module(responses):
    """Build a fake httpx module whose Client.get returns based on URL."""
    import types as _types

    class _FakeResponse:
        def __init__(self, status_code, headers=None, text=""):
            self.status_code = status_code
            self.headers = headers or {}
            self.text = text

    class _FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url):
            if url not in responses:
                return _FakeResponse(404)
            return _FakeResponse(*responses[url])

        def post(self, url, **kw):
            return _FakeResponse(404)

    fake_httpx = _types.SimpleNamespace(Client=_FakeClient)
    return fake_httpx


def test_openapi_spec_discovered_emits_finding(monkeypatch, fake_agent_state) -> None:
    """When `/openapi.json` returns a valid 3.x spec, _probe_openapi reports
    it and the tool emits an info-severity finding."""
    import json as _json
    spec_body = _json.dumps({
        "openapi": "3.0.0",
        "paths": {"/users": {"get": {}}, "/users/{id}": {"get": {}, "delete": {}}},
    })
    fake_httpx = _make_fake_httpx_module({
        "https://example.com/openapi.json": (
            200, {"Content-Type": "application/json"}, spec_body,
        ),
    })
    # Patch the import inside _probe_openapi by stubbing the import.
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "httpx", fake_httpx)
    _patch_probe(monkeypatch, 200, {}, "<html></html>")

    # Tracer setup.
    from strix.telemetry import tracer as tracer_module
    from strix.telemetry import utils as telemetry_utils
    from strix.telemetry.tracer import Tracer, set_global_tracer
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    t = Tracer("openapi-test")
    set_global_tracer(t)

    out = fingerprint.fingerprint_tech_stack(fake_agent_state, "https://example.com", deep=True)
    techs = [d["technology"] for d in out["technologies"]]
    assert "openapi" in techs
    openapi_det = next(d for d in out["technologies"] if d["technology"] == "openapi")
    assert "2 paths" in openapi_det["label"]

    reports = t.get_existing_vulnerabilities()
    openapi_findings = [r for r in reports if "OpenAPI" in r.get("title", "") or "Swagger" in r.get("title", "")]
    assert len(openapi_findings) == 1
    assert openapi_findings[0]["severity"] == "info"
    assert openapi_findings[0]["category"] == "info_disclosure"


def test_openapi_swagger_2x_detected(monkeypatch, fake_agent_state) -> None:
    """OpenAPI 2.x (Swagger) uses `swagger: "2.0"` instead of `openapi`."""
    import json as _json
    spec_body = _json.dumps({
        "swagger": "2.0",
        "host": "api.example.com",
        "basePath": "/v1",
        "paths": {"/health": {"get": {}}},
    })
    fake_httpx = _make_fake_httpx_module({
        "https://example.com/swagger.json": (
            200, {"Content-Type": "application/json"}, spec_body,
        ),
    })
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "httpx", fake_httpx)
    _patch_probe(monkeypatch, 200, {}, "<html></html>")

    from strix.telemetry import tracer as tracer_module
    from strix.telemetry import utils as telemetry_utils
    from strix.telemetry.tracer import Tracer, set_global_tracer
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    t = Tracer("swagger2x-test")
    set_global_tracer(t)

    out = fingerprint.fingerprint_tech_stack(fake_agent_state, "https://example.com", deep=True)
    techs = [d["technology"] for d in out["technologies"]]
    assert "openapi" in techs


def test_swagger_ui_html_detected_when_no_json(monkeypatch, fake_agent_state) -> None:
    """If only a Swagger UI HTML page exists (no JSON spec), still detect it
    (medium confidence)."""
    fake_httpx = _make_fake_httpx_module({
        "https://example.com/swagger-ui.html": (
            200, {"Content-Type": "text/html"},
            "<html><body><script src='swagger-ui.bundle.js'></script></body></html>",
        ),
    })
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "httpx", fake_httpx)
    _patch_probe(monkeypatch, 200, {}, "<html></html>")

    from strix.telemetry import tracer as tracer_module
    from strix.telemetry import utils as telemetry_utils
    from strix.telemetry.tracer import Tracer, set_global_tracer
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    t = Tracer("swagger-ui-only")
    set_global_tracer(t)

    out = fingerprint.fingerprint_tech_stack(fake_agent_state, "https://example.com", deep=True)
    techs = [d["technology"] for d in out["technologies"]]
    assert "swagger_ui" in techs
    swagger_ui = next(d for d in out["technologies"] if d["technology"] == "swagger_ui")
    assert swagger_ui["confidence"] == "medium"


def test_no_openapi_no_finding(monkeypatch, fake_agent_state) -> None:
    """Every probe path 404s → no detection, no finding."""
    fake_httpx = _make_fake_httpx_module({})  # all 404
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "httpx", fake_httpx)
    _patch_probe(monkeypatch, 200, {}, "<html></html>")

    from strix.telemetry import tracer as tracer_module
    from strix.telemetry import utils as telemetry_utils
    from strix.telemetry.tracer import Tracer, set_global_tracer
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    t = Tracer("no-openapi")
    set_global_tracer(t)

    out = fingerprint.fingerprint_tech_stack(fake_agent_state, "https://example.com", deep=True)
    techs = [d["technology"] for d in out["technologies"]]
    assert "openapi" not in techs
    assert "swagger_ui" not in techs
    reports = t.get_existing_vulnerabilities()
    assert all("OpenAPI" not in r.get("title", "") and "Swagger" not in r.get("title", "") for r in reports)


def test_openapi_skipped_in_shallow_mode(monkeypatch, fake_agent_state) -> None:
    """deep=False skips the OpenAPI probe (saves ~13 GETs)."""
    captured_urls: list[str] = []

    fake_httpx = _make_fake_httpx_module({
        "https://example.com/openapi.json": (
            200, {"Content-Type": "application/json"},
            '{"openapi":"3.0.0","paths":{"/x":{"get":{}}}}',
        ),
    })

    # Wrap the fake to record any get() call — should be zero in shallow mode.
    original_get = fake_httpx.Client().get

    class _RecordingClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url):
            captured_urls.append(url)
            return original_get(url)

        def post(self, url, **kw):
            captured_urls.append(url)
            return _types_module.SimpleNamespace(status_code=404, headers={}, text="")

    import types as _types_module
    fake_httpx.Client = _RecordingClient
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "httpx", fake_httpx)
    _patch_probe(monkeypatch, 200, {}, "<html></html>")

    fingerprint.fingerprint_tech_stack(fake_agent_state, "https://example.com", deep=False)
    # No OpenAPI / Swagger paths probed in shallow mode.
    assert all("/openapi" not in u and "/swagger" not in u for u in captured_urls)
