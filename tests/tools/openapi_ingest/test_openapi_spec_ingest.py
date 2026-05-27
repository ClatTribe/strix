"""Tests for `openapi_spec_ingest` — the OpenAPI / Swagger spec
ingester that replaces `bfs_crawl` for `api` target types.

Coverage:
  * Discovery: standard publishing paths, explicit spec_url
  * Parser: OpenAPI 3.x, Swagger 2.x, malformed JSON, missing
    `paths`, missing version marker
  * Endpoint extraction: all HTTP methods + auth-required
    detection + path-level vs operation-level parameters
  * base_url resolution: OpenAPI servers[], Swagger host+basePath,
    fallback
  * KG Surface emission: one node per (path, method) tuple,
    `kind=api_endpoint` prop, `spec_url` recorded
  * Failure modes: bad URL, no spec found, kill switch
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.agents import knowledge_graph as kg
from strix.agents.kg_emit import reset_surface_cache_for_testing


@pytest.fixture(autouse=True)
def _isolated_kg(monkeypatch: pytest.MonkeyPatch) -> None:
    kg.reset_for_testing()
    reset_surface_cache_for_testing()
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_OPENAPI_INGEST_DISABLED", raising=False)


def _stub_fetcher_for(spec_url: str, body: str | dict, status: int = 200):
    """Build a stub HTTP fetcher: 200 with `body` on `spec_url`,
    404 elsewhere. `body` can be a string or dict (auto-JSON)."""
    encoded = body if isinstance(body, str) else json.dumps(body)

    def fetcher(url: str, *, timeout: float) -> tuple[int, str]:
        if url == spec_url:
            return status, encoded
        return 404, ""
    return fetcher


# ---------------------------------------------------------------------------
# Sample specs
# ---------------------------------------------------------------------------


_OPENAPI_3_SPEC: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {"title": "Test API", "version": "1.0.0"},
    "servers": [{"url": "https://api.example.com/v1"}],
    "paths": {
        "/users": {
            "get": {
                "operationId": "listUsers",
                "tags": ["users"],
                "summary": "List users",
                "parameters": [
                    {"name": "limit", "in": "query", "required": False},
                ],
                "security": [{"bearerAuth": []}],
            },
            "post": {
                "operationId": "createUser",
                "tags": ["users"],
                "summary": "Create user",
                "security": [{"bearerAuth": []}],
            },
        },
        "/users/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True},
            ],
            "get": {
                "operationId": "getUser",
                "tags": ["users"],
                "security": [{"bearerAuth": []}],
            },
            "delete": {
                "operationId": "deleteUser",
                "tags": ["users"],
                "security": [{"bearerAuth": []}],
            },
        },
        "/health": {
            "get": {
                "operationId": "health",
                "security": [],  # explicit no-auth
            },
        },
    },
    "security": [{"bearerAuth": []}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
        },
    },
}


_SWAGGER_2_SPEC: dict[str, Any] = {
    "swagger": "2.0",
    "host": "api.swagger-example.com",
    "basePath": "/v2",
    "schemes": ["https"],
    "paths": {
        "/pets": {
            "get": {
                "operationId": "listPets",
                "parameters": [],
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Tool import — late-bound so test_isolation env applies
# ---------------------------------------------------------------------------


def _ingest(target: str, **kwargs):
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    return _mod.openapi_spec_ingest(target=target, **kwargs)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discovers_openapi3_via_standard_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = _stub_fetcher_for(
        "https://api.example.com/openapi.json", _OPENAPI_3_SPEC,
    )
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout, fetcher=fetcher: fetcher(url, timeout=timeout),
    )
    result = _ingest("https://api.example.com")
    assert result["success"] is True
    assert result["spec_url"] == "https://api.example.com/openapi.json"
    assert result["spec_version"] == "openapi-3.0.3"


def test_explicit_spec_url_wins_over_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = _stub_fetcher_for(
        "https://api.example.com/custom/path/spec.json", _OPENAPI_3_SPEC,
    )
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout, fetcher=fetcher: fetcher(url, timeout=timeout),
    )
    result = _ingest(
        "https://api.example.com",
        spec_url="https://api.example.com/custom/path/spec.json",
    )
    assert result["success"] is True
    assert result["spec_url"].endswith("/custom/path/spec.json")


def test_no_spec_found_returns_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout: (404, ""),
    )
    result = _ingest("https://api.example.com")
    assert result["success"] is False
    assert "no parseable" in result["error"]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parses_openapi3() -> None:
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    _parse_spec = _mod._parse_spec
    out = _parse_spec(json.dumps(_OPENAPI_3_SPEC))
    assert out is not None
    assert "paths" in out


def test_parses_swagger2() -> None:
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    _parse_spec = _mod._parse_spec
    out = _parse_spec(json.dumps(_SWAGGER_2_SPEC))
    assert out is not None


def test_rejects_malformed_json() -> None:
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    _parse_spec = _mod._parse_spec
    assert _parse_spec("{not json") is None


def test_rejects_dict_without_paths() -> None:
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    _parse_spec = _mod._parse_spec
    assert _parse_spec(json.dumps({"openapi": "3.0", "info": {}})) is None


def test_rejects_dict_without_version_marker() -> None:
    """A dict with `paths` but no `openapi`/`swagger` key isn't
    a spec we understand."""
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    _parse_spec = _mod._parse_spec
    assert _parse_spec(json.dumps({"paths": {}})) is None


# ---------------------------------------------------------------------------
# Endpoint extraction
# ---------------------------------------------------------------------------


def test_extracts_all_documented_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = _stub_fetcher_for(
        "https://api.example.com/openapi.json", _OPENAPI_3_SPEC,
    )
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout, fetcher=fetcher: fetcher(url, timeout=timeout),
    )
    result = _ingest("https://api.example.com")
    methods_paths = {(e["method"], e["path"]) for e in result["endpoints"]}
    assert ("GET", "/users") in methods_paths
    assert ("POST", "/users") in methods_paths
    assert ("GET", "/users/{id}") in methods_paths
    assert ("DELETE", "/users/{id}") in methods_paths
    assert ("GET", "/health") in methods_paths
    assert result["endpoint_count"] == 5


def test_merges_path_level_and_operation_level_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = _stub_fetcher_for(
        "https://api.example.com/openapi.json", _OPENAPI_3_SPEC,
    )
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout, fetcher=fetcher: fetcher(url, timeout=timeout),
    )
    result = _ingest("https://api.example.com")
    get_user = next(
        e for e in result["endpoints"]
        if e["method"] == "GET" and e["path"] == "/users/{id}"
    )
    param_names = {p["name"] for p in get_user["params"]}
    assert "id" in param_names   # path-level param merged


def test_auth_required_inherits_from_global(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OpenAPI 3.x: global `security: [{bearerAuth: []}]` →
    operations inherit unless they explicitly override."""
    fetcher = _stub_fetcher_for(
        "https://api.example.com/openapi.json", _OPENAPI_3_SPEC,
    )
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout, fetcher=fetcher: fetcher(url, timeout=timeout),
    )
    result = _ingest("https://api.example.com")
    by_path = {(e["method"], e["path"]): e for e in result["endpoints"]}
    assert by_path[("GET", "/users")]["auth_required"] is True
    # Explicit `security: []` overrides the global.
    assert by_path[("GET", "/health")]["auth_required"] is False


def test_skips_unrecognised_methods(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    weird_spec = {
        "openapi": "3.0.0",
        "paths": {
            "/foo": {
                "get": {"operationId": "ok"},
                "trace": {"operationId": "skip"},   # not in allow-list
                "connect": {"operationId": "skip"},
            },
        },
    }
    fetcher = _stub_fetcher_for(
        "https://api.example.com/openapi.json", weird_spec,
    )
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout, fetcher=fetcher: fetcher(url, timeout=timeout),
    )
    result = _ingest("https://api.example.com")
    methods = {e["method"] for e in result["endpoints"]}
    assert methods == {"GET"}


# ---------------------------------------------------------------------------
# base_url resolution
# ---------------------------------------------------------------------------


def test_base_url_from_openapi3_servers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = _stub_fetcher_for(
        "https://api.example.com/openapi.json", _OPENAPI_3_SPEC,
    )
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout, fetcher=fetcher: fetcher(url, timeout=timeout),
    )
    result = _ingest("https://api.example.com")
    assert result["base_url"] == "https://api.example.com/v1"


def test_base_url_from_swagger2_host_basepath(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = _stub_fetcher_for(
        "https://api.swagger-example.com/swagger.json",
        _SWAGGER_2_SPEC,
    )
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout, fetcher=fetcher: fetcher(url, timeout=timeout),
    )
    result = _ingest("https://api.swagger-example.com")
    assert result["base_url"] == "https://api.swagger-example.com/v2"


# ---------------------------------------------------------------------------
# KG Surface emission
# ---------------------------------------------------------------------------


def test_emits_one_surface_per_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = _stub_fetcher_for(
        "https://api.example.com/openapi.json", _OPENAPI_3_SPEC,
    )
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout, fetcher=fetcher: fetcher(url, timeout=timeout),
    )
    result = _ingest("https://api.example.com")
    assert result["surfaces_emitted"] == 5
    stats = kg.get_kg().stats()
    assert stats["node_types"].get("Surface", 0) == 5


def test_emitted_surface_carries_api_endpoint_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = _stub_fetcher_for(
        "https://api.example.com/openapi.json", _OPENAPI_3_SPEC,
    )
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout, fetcher=fetcher: fetcher(url, timeout=timeout),
    )
    _ingest("https://api.example.com")
    g = kg.get_kg()
    surfaces = g.query_nodes(type="Surface")
    assert all(s.props.get("kind") == "api_endpoint" for s in surfaces)
    # Every Surface records the spec URL for audit / re-fetch.
    assert all(
        s.props.get("spec_url") == "https://api.example.com/openapi.json"
        for s in surfaces
    )


def test_kg_disabled_skips_surface_emission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_KG_DISABLED", "1")
    fetcher = _stub_fetcher_for(
        "https://api.example.com/openapi.json", _OPENAPI_3_SPEC,
    )
    import importlib
    _mod = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest",
    )
    monkeypatch.setattr(
        _mod, "_http_fetch",
        lambda url, *, timeout, fetcher=fetcher: fetcher(url, timeout=timeout),
    )
    result = _ingest("https://api.example.com")
    # Ingest succeeds; KG just no-ops.
    assert result["success"] is True
    assert result["surfaces_emitted"] == 0


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_invalid_target_url() -> None:
    result = _ingest("not-a-url")
    assert result["success"] is False
    assert "invalid target URL" in result["error"]


def test_invalid_spec_url() -> None:
    result = _ingest(
        "https://api.example.com",
        spec_url="also-not-a-url",
    )
    assert result["success"] is False
    assert "invalid spec_url" in result["error"]


def test_kill_switch_short_circuits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_OPENAPI_INGEST_DISABLED", "1")
    result = _ingest("https://api.example.com")
    assert result["success"] is False
    assert "kill_switch" in result["error"]


# ---------------------------------------------------------------------------
# `api` target type — tool catalog wiring
# ---------------------------------------------------------------------------


def test_api_target_type_registered_in_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import list_target_types
    assert "api" in list_target_types()


def test_api_anchor_prepass_includes_openapi_ingest() -> None:
    """Post iter-37.2: openapi_spec_ingest fires in anchor_prepass for
    api targets, not in the LLM-visible catalog. The ingested endpoint
    inventory feeds downstream specialists (scan_api_bola, scan_idor)
    via SecurityContext, not via the L2 lead's tool choice."""
    from strix.agents.lead_agent.anchor_prepass import (
        _ANCHORS_BY_TARGET_TYPE,
    )
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE["api"]}
    assert "openapi_spec_ingest" in anchors
    tools = get_lead_tool_catalog(target_types=["api"])
    assert "openapi_spec_ingest" not in tools


def test_api_catalog_excludes_browser_dom_tools() -> None:
    """API targets don't render HTML — DOM / browser / source-map
    tools waste budget. They're not in the api catalog.

    iter-Q5.3: dalfox moved from L2 to anchor_prepass per CLAUDE.md
    §1.5 (tools are LLM's hands, not its brain). It still fires
    (web_application only, in prepass) — just not via LLM choice.
    browser_action is excluded from the post-Q5 minimal catalog
    entirely.
    """
    from strix.agents.lead_agent.anchor_prepass import (
        _ANCHORS_BY_TARGET_TYPE,
    )
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    api_tools = get_lead_tool_catalog(target_types=["api"])
    web_tools = get_lead_tool_catalog(target_types=["web_application"])
    api_anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE["api"]}
    web_anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE["web_application"]}

    # dalfox: web-only deep XSS — fires in web prepass, not api prepass,
    # and not in either LLM-visible catalog post-Q5.3.
    assert "scan_xss_dalfox" not in api_tools
    assert "scan_xss_dalfox" not in web_tools
    assert "scan_xss_dalfox" not in api_anchors
    assert "scan_xss_dalfox" in web_anchors
    # browser_action: post-Q5 minimal catalog excludes it everywhere.
    assert "browser_action" not in api_tools
    assert "browser_action" not in web_tools


def test_api_core_dast_specialists_fire_in_prepass() -> None:
    """Post iter-37.x + Q5.3: the OSS-anchored DAST stack (nuclei,
    sqlmap, InQL, tls_audit, openapi_spec_ingest) fires in
    anchor_prepass for api targets. The L2 catalog keeps the
    L2-native specialists (scan_idor, scan_auth_flow) and the
    map_graphql_inql wrapper pending its Q5.5 move to prepass."""
    from strix.agents.lead_agent.anchor_prepass import (
        _ANCHORS_BY_TARGET_TYPE,
    )
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    api_anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE["api"]}
    api_catalog = get_lead_tool_catalog(target_types=["api"])

    # Prepass coverage (the L1-dashboard surface).
    for name in (
        "scan_nuclei_templates",   # OSS generic detection
        "scan_sqli_sqlmap",        # OSS SQLi (iter-Q5.3)
        "openapi_spec_ingest",     # API endpoint inventory
        "tls_audit",               # OSS TLS audit (testssl.sh)
    ):
        assert name in api_anchors, f"{name} missing from api prepass"
    # L2-native specialists stay in catalog (needs LLM state-reasoning,
    # no OSS substitute).
    for name in ("scan_idor", "scan_auth_flow", "map_graphql_inql"):
        assert name in api_catalog, f"{name} missing from api catalog"
