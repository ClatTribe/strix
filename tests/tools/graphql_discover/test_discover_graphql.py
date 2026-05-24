"""Tests for iter-28.5 — GraphQL endpoint discovery."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from strix.tools.graphql_discover.discover_graphql import (
    _GRAPHQL_PATHS,
    _looks_like_graphql_response,
    _summarize_schema,
    discover_graphql_endpoints,
)


# ---------------------------------------------------------------------------
# Path list — anti-overfitting: must contain industry conventions, not SUT-specific
# ---------------------------------------------------------------------------

def test_default_paths_are_industry_conventions():
    """Path list must be from public conventions (Apollo, Hasura,
    Postgraphile, GraphCMS, Shopify). NOT from any specific SUT."""
    p = set(_GRAPHQL_PATHS)
    # Industry conventions must be present
    assert "/graphql" in p
    assert "/api/graphql" in p
    assert "/v1/graphql" in p          # Hasura
    assert "/v1alpha1/graphql" in p    # Hasura alpha
    # NO SUT-specific paths permitted (overfitting smell)
    forbidden = {"/juice-shop", "/api/Challenges", "/jshop/graphql"}
    assert not (p & forbidden)


# ---------------------------------------------------------------------------
# _looks_like_graphql_response — shape detector
# ---------------------------------------------------------------------------

def test_shape_accepts_schema_with_querytype():
    payload = {"data": {"__schema": {"queryType": {"name": "Query"}}}}
    assert _looks_like_graphql_response(payload)


def test_shape_accepts_errors_envelope():
    """A GraphQL server that has introspection disabled still returns
    a GraphQL-shaped error envelope."""
    payload = {"errors": [{"message": "Introspection disabled"}]}
    assert _looks_like_graphql_response(payload)


def test_shape_rejects_plain_json_api():
    """A plain REST API returning JSON must NOT be confused for GraphQL."""
    payload = {"status": "ok", "users": []}
    assert not _looks_like_graphql_response(payload)


def test_shape_rejects_html():
    """Non-JSON / HTML responses should not pass."""
    assert not _looks_like_graphql_response("<html><body>404</body></html>")
    assert not _looks_like_graphql_response(None)
    assert not _looks_like_graphql_response([])


# ---------------------------------------------------------------------------
# _summarize_schema — compact summary extraction
# ---------------------------------------------------------------------------

def test_summarize_captures_query_and_mutation_fields():
    payload = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": None,
                "types": [
                    {"name": "Query", "kind": "OBJECT", "fields": [
                        {"name": "user"}, {"name": "users"}, {"name": "products"},
                    ]},
                    {"name": "Mutation", "kind": "OBJECT", "fields": [
                        {"name": "createUser"}, {"name": "deleteOrder"},
                    ]},
                    {"name": "User", "kind": "OBJECT"},
                    # __ prefixed types should NOT count toward user-defined
                    {"name": "__Schema", "kind": "OBJECT"},
                ],
            },
        },
    }
    summary = _summarize_schema(payload)
    assert summary["query_type"] == "Query"
    assert summary["mutation_type"] == "Mutation"
    assert summary["subscription_type"] is None
    assert summary["query_fields"] == ["user", "users", "products"]
    assert summary["mutation_fields"] == ["createUser", "deleteOrder"]
    assert summary["query_field_count"] == 3
    assert summary["mutation_field_count"] == 2
    # __ types excluded
    assert "__Schema" not in summary["type_names_sample"]


def test_summarize_handles_missing_mutation_type():
    """Read-only GraphQL APIs have no mutationType."""
    payload = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "subscriptionType": None,
                "types": [
                    {"name": "Query", "fields": [{"name": "ping"}]},
                ],
            },
        },
    }
    summary = _summarize_schema(payload)
    assert summary["mutation_type"] is None
    assert summary["mutation_field_count"] == 0


# ---------------------------------------------------------------------------
# discover_graphql_endpoints — end-to-end with mocked HTTP
# ---------------------------------------------------------------------------

def test_rejects_empty_target():
    out = discover_graphql_endpoints(target_url="")
    assert out["success"] is False
    assert "target_url required" in out["reason"]


def test_rejects_target_without_http_scheme():
    out = discover_graphql_endpoints(target_url="app:3000")
    assert out["success"] is False
    assert "full http(s) URL" in out["reason"]

    out2 = discover_graphql_endpoints(target_url="ftp://app")
    assert out2["success"] is False


@patch("strix.tools.graphql_discover.discover_graphql.requests.post")
def test_discovers_endpoint_at_standard_path(mock_post):
    """When the SUT exposes /graphql with introspection, we find it
    and summarize its schema."""
    def _post(url, json=None, headers=None, timeout=None, **kwargs):
        # Match ONLY the bare `/graphql` path (not /api/graphql etc.)
        if url == "http://app:3000/graphql":
            r = MagicMock()
            r.status_code = 200
            r.json = MagicMock(return_value={
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                        "subscriptionType": None,
                        "types": [
                            {"name": "Query", "fields": [{"name": "me"}]},
                            {"name": "Mutation", "fields": [{"name": "login"}]},
                        ],
                    }
                },
            })
            return r
        r = MagicMock()
        r.status_code = 404
        r.json = MagicMock(side_effect=ValueError("not json"))
        return r
    mock_post.side_effect = _post

    out = discover_graphql_endpoints(target_url="http://app:3000")
    assert out["success"] is True
    assert out["endpoints_found"] == 1
    ep = out["endpoints"][0]
    assert ep["url"].endswith("/graphql")
    assert ep["query_type"] == "Query"
    assert "me" in ep["query_fields"]


@patch("strix.tools.graphql_discover.discover_graphql.requests.post")
def test_discovers_no_endpoint_returns_partial(mock_post):
    """A non-GraphQL SUT returns status=partial, not error."""
    r = MagicMock()
    r.status_code = 404
    r.json = MagicMock(side_effect=ValueError("not json"))
    mock_post.return_value = r

    out = discover_graphql_endpoints(target_url="http://app:3000")
    assert out["success"] is True
    assert out["status"] == "partial"
    assert out["endpoints_found"] == 0
    assert "none returned a GraphQL schema" in out["reason"]


@patch("strix.tools.graphql_discover.discover_graphql.requests.post")
def test_extra_paths_extend_probe_list(mock_post):
    r = MagicMock()
    r.status_code = 404
    r.json = MagicMock(side_effect=ValueError)
    mock_post.return_value = r

    out = discover_graphql_endpoints(
        target_url="http://app:3000",
        extra_paths=["/internal/gql", "/secret/api/graphql"],
    )
    # Paths probed = built-in list + 2 extras
    assert out["paths_probed"] == len(_GRAPHQL_PATHS) + 2


@patch("strix.tools.graphql_discover.discover_graphql.requests.post")
def test_request_exceptions_silently_skip(mock_post):
    """Connection refused / timeout on one path doesn't kill the scan."""
    mock_post.side_effect = requests.ConnectionError("refused")
    out = discover_graphql_endpoints(target_url="http://app:3000")
    assert out["success"] is True  # graceful
    assert out["endpoints_found"] == 0


@patch("strix.tools.graphql_discover.discover_graphql.requests.post")
def test_400_with_graphql_errors_is_still_a_hit(mock_post):
    """Hasura, AppSync return 400 to malformed queries but still a
    GraphQL-shaped envelope. That's a discovered endpoint."""
    def _post(url, **kwargs):
        r = MagicMock()
        # Exact-match `/v1/graphql` only (not `/api/v1/graphql`)
        if url == "http://app:3000/v1/graphql":
            r.status_code = 400
            r.json = MagicMock(return_value={"errors": [{"message": "x"}]})
        else:
            r.status_code = 404
            r.json = MagicMock(side_effect=ValueError)
        return r
    mock_post.side_effect = _post

    out = discover_graphql_endpoints(target_url="http://app:3000")
    assert out["endpoints_found"] == 1
    assert out["endpoints"][0]["url"] == "http://app:3000/v1/graphql"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("discover_graphql_endpoints"))
