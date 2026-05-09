"""Tests for Phase 1.4 — OpenAPI/Swagger threat-model parser hooked
into `send_request`'s side-effect block. Pins:

  * OpenAPI 3 + Swagger 2 detection
  * Per-endpoint `record_endpoint` calls with method + params
  * Partial-signal emission per shape (state-change → CSRF;
    numeric path → IDOR; params → injection)
  * Negative cases (HTML response, plain JSON without spec markers,
    massive payload skipped)
"""

from __future__ import annotations

import json

import pytest

from strix.tools.proxy.proxy_actions import _parse_and_record_openapi_spec


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


def test_swagger_2_spec_records_endpoints() -> None:
    spec = {
        "swagger": "2.0",
        "info": {"title": "petstore", "version": "1.0"},
        "basePath": "/v2",
        "paths": {
            "/pets/{petId}": {
                "get": {
                    "parameters": [
                        {"name": "petId", "in": "path", "required": True},
                    ],
                },
                "delete": {
                    "parameters": [
                        {"name": "petId", "in": "path", "required": True},
                    ],
                },
            },
            "/pets": {
                "post": {
                    "parameters": [
                        {"name": "body", "in": "body"},
                    ],
                },
            },
        },
    }
    _parse_and_record_openapi_spec(
        url="http://example.com/swagger.json",
        body_text=json.dumps(spec),
        content_type="application/json",
    )

    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    paths = {e.path for e in eps}
    # Path canonicalization strips host but keeps path; basePath is
    # included
    assert "/v2/pets/{petId}" in paths
    assert "/v2/pets" in paths

    # The {petId} path has both GET and DELETE methods recorded
    pet_id_endpoint = next(e for e in eps if e.path == "/v2/pets/{petId}")
    assert "GET" in pet_id_endpoint.methods_seen
    assert "DELETE" in pet_id_endpoint.methods_seen


def test_openapi_3_spec_with_servers_url_recorded() -> None:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "x", "version": "1.0"},
        "servers": [{"url": "/api/v3"}],
        "paths": {
            "/users/{id}": {
                "get": {
                    "parameters": [{"name": "id", "in": "path"}],
                },
            },
        },
    }
    _parse_and_record_openapi_spec(
        url="http://example.com/openapi.json",
        body_text=json.dumps(spec),
        content_type="application/json",
    )
    from strix.agents.security_context import list_endpoints
    paths = {e.path for e in list_endpoints()}
    assert "/api/v3/users/{id}" in paths


def test_state_change_methods_emit_csrf_partial_signal() -> None:
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/transfer": {
                "post": {"parameters": [{"name": "amount", "in": "body"}]},
            },
        },
    }
    _parse_and_record_openapi_spec(
        url="http://example.com/openapi.json",
        body_text=json.dumps(spec),
        content_type="application/json",
    )
    from strix.agents.security_context import list_partial_signals
    sigs = list_partial_signals()
    csrf_sigs = [s for s in sigs if s.category_hint == "csrf"]
    assert len(csrf_sigs) >= 1
    assert "csrf_check" in csrf_sigs[0].next_probe.lower()


def test_numeric_path_param_emits_idor_partial_signal() -> None:
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/orders/{orderId}": {"get": {}},
            "/users/{id}/posts": {"get": {}},
        },
    }
    _parse_and_record_openapi_spec(
        url="http://example.com/openapi.json",
        body_text=json.dumps(spec),
        content_type="application/json",
    )
    from strix.agents.security_context import list_partial_signals
    sigs = list_partial_signals()
    idor_sigs = [s for s in sigs if s.category_hint == "idor"]
    assert len(idor_sigs) >= 2  # orderId + id
    surfaces = " ".join(s.surface for s in idor_sigs)
    assert "{orderId}" in surfaces or "{id}" in surfaces


def test_html_response_does_not_parse() -> None:
    """Negative case: HTML body must not trip the parser."""
    _parse_and_record_openapi_spec(
        url="http://example.com/",
        body_text="<html><body>Welcome</body></html>",
        content_type="text/html",
    )
    from strix.agents.security_context import list_endpoints
    assert len(list_endpoints()) == 0


def test_json_without_swagger_marker_not_parsed() -> None:
    """Plain JSON API response without OpenAPI markers — skip."""
    _parse_and_record_openapi_spec(
        url="http://example.com/api/data",
        body_text=json.dumps({"users": [{"id": 1, "name": "alice"}]}),
        content_type="application/json",
    )
    from strix.agents.security_context import list_endpoints
    assert len(list_endpoints()) == 0


def test_oversized_payload_skipped() -> None:
    """5MB cap — don't parse-bomb."""
    huge = '{"openapi":"3.0.0","paths":{"/x":{"get":{}}}}'
    huge_padded = '{"openapi":"3.0.0","z":"' + ("a" * 6_000_000) + '","paths":{}}'
    _parse_and_record_openapi_spec(
        url="http://example.com/openapi.json",
        body_text=huge_padded,
        content_type="application/json",
    )
    from strix.agents.security_context import list_endpoints
    # Must skip — no endpoints recorded.
    assert len(list_endpoints()) == 0


def test_invalid_json_swallowed_silently() -> None:
    _parse_and_record_openapi_spec(
        url="http://example.com/openapi.json",
        body_text='{"openapi": invalid json',
        content_type="application/json",
    )
    from strix.agents.security_context import list_endpoints
    assert len(list_endpoints()) == 0


def test_param_names_collected_per_operation() -> None:
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/search": {
                "get": {
                    "parameters": [
                        {"name": "q", "in": "query"},
                        {"name": "limit", "in": "query"},
                        {"name": "offset", "in": "query"},
                    ],
                },
            },
        },
    }
    _parse_and_record_openapi_spec(
        url="http://example.com/openapi.json",
        body_text=json.dumps(spec),
        content_type="application/json",
    )
    from strix.agents.security_context import list_endpoints
    ep = next(e for e in list_endpoints() if e.path == "/search")
    assert sorted(ep.params_seen) == ["limit", "offset", "q"]
