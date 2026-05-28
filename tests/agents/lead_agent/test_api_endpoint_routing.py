"""iter-Q5.40 — tests for API per-endpoint routing.

Hermetic — every helper is pure (path + method parsing). No tool dispatch
in this module; the integration with `_run_dependent_api_tools` is
covered by the broader anchor_prepass tests."""

from __future__ import annotations

import pytest

from strix.agents.lead_agent.anchor_prepass import (
    _api_endpoint_method,
    _api_endpoint_path,
    _api_routing_enabled,
    _endpoints_for_api_tool,
    _filter_api_endpoints,
    _has_api_path_id,
    _is_api_graphql_endpoint,
    _is_api_health_endpoint,
    _is_api_spec_endpoint,
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_API_ENDPOINT_ROUTING", raising=False)


# ---------------------------------------------------------------------------
# Path / method parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ep,expected", [
    ({"url": "https://api.x.com/v1/users"}, "/v1/users"),
    ({"url": "/v1/users"}, "/v1/users"),
    ({"path": "/v1/users"}, "/v1/users"),
    ({}, ""),
    ("not-a-dict", ""),
])
def test_endpoint_path_extraction(ep, expected) -> None:
    assert _api_endpoint_path(ep) == expected


@pytest.mark.parametrize("ep,expected", [
    ({"method": "GET"}, "GET"),
    ({"method": "post"}, "POST"),
    ({"method": "Delete"}, "DELETE"),
    ({}, "GET"),
    ("not-a-dict", "GET"),
])
def test_endpoint_method_extraction(ep, expected) -> None:
    assert _api_endpoint_method(ep) == expected


# ---------------------------------------------------------------------------
# Endpoint classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,is_health", [
    ("/health", True),
    ("/healthz", True),
    ("/healthcheck", True),
    ("/v1/health-check", True),
    ("/metrics", True),
    ("/api/metrics", True),
    ("/ping", True),
    ("/readyz", True),
    ("/livez", True),
    ("/version", True),
    ("/favicon.ico", True),
    ("/robots.txt", True),
    ("/api/users", False),  # not health
    ("/", False),
    ("/api/healthcare/records", False),  # healthcare ≠ healthcheck
])
def test_is_api_health_endpoint(url, is_health) -> None:
    assert _is_api_health_endpoint({"url": url}) is is_health


@pytest.mark.parametrize("url,is_spec", [
    ("/swagger.json", True),
    ("/swagger-ui.html", True),
    ("/v2/api-docs", True),
    ("/v3/api-docs/swagger-config", True),
    ("/openapi.json", True),
    ("/api/redoc", True),
    ("/api/users", False),
    ("/", False),
])
def test_is_api_spec_endpoint(url, is_spec) -> None:
    assert _is_api_spec_endpoint({"url": url}) is is_spec


@pytest.mark.parametrize("url,is_graphql", [
    ("/graphql", True),
    ("/api/graphql", True),
    ("/graphiql", True),
    ("/playground", True),
    ("/api/users", False),
])
def test_is_api_graphql_endpoint(url, is_graphql) -> None:
    assert _is_api_graphql_endpoint({"url": url}) is is_graphql


@pytest.mark.parametrize("url,has_id", [
    # OpenAPI / Express / FastAPI brace style.
    ("/users/{id}", True),
    ("/users/{userId}/posts", True),
    ("/orders/{order_id}/items/{itemId}", True),
    # Rails / Sinatra colon style.
    ("/users/:id", True),
    ("/users/:user_id/posts", True),
    # No path-id.
    ("/users", False),
    ("/health", False),
    ("/api/v1/products", False),
])
def test_has_api_path_id(url, has_id) -> None:
    assert _has_api_path_id({"url": url}) is has_id


# ---------------------------------------------------------------------------
# Pre-filter
# ---------------------------------------------------------------------------


def test_filter_api_endpoints_drops_health_and_spec() -> None:
    eps = [
        {"method": "GET", "url": "/api/users"},
        {"method": "GET", "url": "/health"},
        {"method": "GET", "url": "/metrics"},
        {"method": "GET", "url": "/swagger.json"},
        {"method": "POST", "url": "/api/orders"},
    ]
    out, rej = _filter_api_endpoints(eps)
    assert len(out) == 2
    assert rej == {"health": 2, "spec": 1, "graphql": 0}
    urls = [e["url"] for e in out]
    assert "/api/users" in urls
    assert "/api/orders" in urls


def test_filter_api_endpoints_keeps_graphql_by_default() -> None:
    """GraphQL endpoints are valuable for mass-assignment + BFLA via
    mutations — keep them in the per-tool list. The dedicated inql /
    GraphQL fuzz path handles introspection separately."""
    eps = [
        {"method": "POST", "url": "/graphql"},
        {"method": "GET", "url": "/api/users"},
    ]
    out, rej = _filter_api_endpoints(eps)
    assert len(out) == 2
    assert rej["graphql"] == 0


def test_filter_api_endpoints_drops_graphql_when_requested() -> None:
    eps = [
        {"method": "POST", "url": "/graphql"},
        {"method": "GET", "url": "/api/users"},
    ]
    out, rej = _filter_api_endpoints(eps, drop_graphql=True)
    assert len(out) == 1
    assert rej["graphql"] == 1


# ---------------------------------------------------------------------------
# Per-tool routing
# ---------------------------------------------------------------------------


def test_routing_bola_only_gets_get_with_path_id() -> None:
    eps = [
        {"method": "GET", "url": "/api/users"},                 # list, no :id
        {"method": "GET", "url": "/api/users/{id}"},            # ✓
        {"method": "POST", "url": "/api/users"},                # not GET
        {"method": "GET", "url": "/api/users/{id}/posts"},      # ✓
        {"method": "DELETE", "url": "/api/users/{id}"},         # not GET
    ]
    out = _endpoints_for_api_tool(eps, "scan_api_bola")
    urls = sorted(e["url"] for e in out)
    assert urls == ["/api/users/{id}", "/api/users/{id}/posts"]


def test_routing_idor_only_gets_get_with_path_id() -> None:
    """Same gate as BOLA — IDOR is the cross-session variant of BOLA."""
    eps = [
        {"method": "GET", "url": "/api/users/{id}"},
        {"method": "POST", "url": "/api/users"},
        {"method": "GET", "url": "/api/users"},
    ]
    out = _endpoints_for_api_tool(eps, "scan_idor")
    assert len(out) == 1
    assert out[0]["url"] == "/api/users/{id}"


def test_routing_bfla_takes_all_state_changing_methods() -> None:
    eps = [
        {"method": "GET", "url": "/api/users"},                 # GET excluded
        {"method": "POST", "url": "/api/users"},                # ✓
        {"method": "PUT", "url": "/api/users/{id}"},            # ✓
        {"method": "PATCH", "url": "/api/users/{id}"},          # ✓
        {"method": "DELETE", "url": "/api/users/{id}"},         # ✓ (BFLA includes DELETE)
    ]
    out = _endpoints_for_api_tool(eps, "scan_api_bfla")
    methods = sorted(e["method"] for e in out)
    assert methods == ["DELETE", "PATCH", "POST", "PUT"]


def test_routing_mass_assignment_excludes_delete() -> None:
    """mass_assignment probes a request BODY mutation — DELETE has no body
    to mass-assign, GET likewise. Only POST/PUT/PATCH carry meaningful
    bodies."""
    eps = [
        {"method": "GET", "url": "/api/users/{id}"},
        {"method": "POST", "url": "/api/users"},
        {"method": "PUT", "url": "/api/users/{id}"},
        {"method": "PATCH", "url": "/api/users/{id}"},
        {"method": "DELETE", "url": "/api/users/{id}"},
    ]
    out = _endpoints_for_api_tool(eps, "scan_api_mass_assignment")
    methods = sorted(e["method"] for e in out)
    assert methods == ["PATCH", "POST", "PUT"]


def test_routing_unknown_tool_passes_all_through() -> None:
    """For tools without a Q5.40 routing rule (e.g. broad signature probes
    like sqli, ssrf), every endpoint passes through — they each have their
    own per-endpoint filter elsewhere in the prepass."""
    eps = [
        {"method": "GET", "url": "/api/users"},
        {"method": "POST", "url": "/api/orders"},
    ]
    out = _endpoints_for_api_tool(eps, "scan_sqli")
    assert len(out) == 2


def test_routing_ablation_via_env(monkeypatch) -> None:
    """STRIX_API_ENDPOINT_ROUTING=0 restores the every-tool-gets-everything
    contract. Useful for measuring the routing's effect on a bench run."""
    monkeypatch.setenv("STRIX_API_ENDPOINT_ROUTING", "0")
    assert _api_routing_enabled() is False
    eps = [
        {"method": "GET", "url": "/api/users"},
        {"method": "POST", "url": "/api/users"},
        {"method": "DELETE", "url": "/api/users/{id}"},
    ]
    # With routing off, mass_assignment normally rejects all (GET, DELETE,
    # plus POST without an id) — but here it gets the FULL list.
    out = _endpoints_for_api_tool(eps, "scan_api_mass_assignment")
    assert len(out) == 3


def test_routing_default_enabled(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_API_ENDPOINT_ROUTING", raising=False)
    assert _api_routing_enabled() is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off"])
def test_routing_disabled_via_falsy_env(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_API_ENDPOINT_ROUTING", val)
    assert _api_routing_enabled() is False


# ---------------------------------------------------------------------------
# End-to-end shape: pre-filter + per-tool routing combined
# ---------------------------------------------------------------------------


def test_real_api_spec_shape() -> None:
    """Representative shape of what openapi_spec_ingest returns for a real
    API (vampi/crapi-style) — 10 endpoints, mix of health/spec/data."""
    eps = [
        # Health / spec / probes — should be filtered out.
        {"method": "GET", "url": "/health"},
        {"method": "GET", "url": "/metrics"},
        {"method": "GET", "url": "/v3/api-docs/swagger-config"},
        # User CRUD.
        {"method": "GET", "url": "/users"},                       # list
        {"method": "POST", "url": "/users"},                      # create
        {"method": "GET", "url": "/users/{userId}"},              # read
        {"method": "PUT", "url": "/users/{userId}"},              # update
        {"method": "PATCH", "url": "/users/{userId}/role"},       # role change (BFLA target)
        {"method": "DELETE", "url": "/users/{userId}"},
        # Order resource.
        {"method": "GET", "url": "/orders/{orderId}"},
    ]
    filtered, rej = _filter_api_endpoints(eps)
    assert len(filtered) == 7
    assert rej == {"health": 2, "spec": 1, "graphql": 0}

    bola = _endpoints_for_api_tool(filtered, "scan_api_bola")
    assert sorted(e["url"] for e in bola) == [
        "/orders/{orderId}", "/users/{userId}",
    ]

    bfla = _endpoints_for_api_tool(filtered, "scan_api_bfla")
    assert len(bfla) == 4   # POST, PUT, PATCH, DELETE

    mass = _endpoints_for_api_tool(filtered, "scan_api_mass_assignment")
    assert len(mass) == 3   # POST, PUT, PATCH

    idor = _endpoints_for_api_tool(filtered, "scan_idor")
    assert len(idor) == 2   # same as BOLA


def test_empty_endpoint_list_returns_empty() -> None:
    out, rej = _filter_api_endpoints([])
    assert out == []
    assert rej == {"health": 0, "spec": 0, "graphql": 0}
    assert _endpoints_for_api_tool([], "scan_api_bola") == []
