"""Tests for the GraphQL specialist tool.

Hermetic — `_post_graphql` is mocked at the module namespace. Tests
cover:
- Introspection-enabled detection + schema summary capture
- Introspection disabled (no finding)
- Depth-abuse acceptance / rejection
- Alias-overloading acceptance / rejection
- Batch-query acceptance / rejection
- Cluster-A composition (excluded paths short-circuit)
- Per-test check events
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.graphql import graphql as gql
from strix.tools.proxy import http_safety


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
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("graphql-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://api.example.com/graphql"}]})
    yield


def _patch_post(monkeypatch, responder):
    """Patch _post_graphql with a callable that takes (url, payload, **kw)
    and returns the response dict."""
    monkeypatch.setattr(gql, "_post_graphql", responder)


def _intro_response_body(types_count: int = 5) -> str:
    return json.dumps({
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": None,
                "types": [{"name": f"Type{i}", "kind": "OBJECT"} for i in range(types_count)],
            }
        }
    })


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_empty_target_rejected() -> None:
    out = gql.graphql_specialist_check("")
    assert out["success"] is False


def test_invalid_scheme_rejected() -> None:
    out = gql.graphql_specialist_check("ftp://api/graphql")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------


def test_introspection_enabled_emits_info_finding(monkeypatch) -> None:
    def respond(url, payload, **kw):
        # Batch payload arrives as a list, not a dict — guard.
        if isinstance(payload, list):
            return {"status_code": 400, "headers": {}, "body": ""}
        if "__schema" in payload.get("query", "") and "ofType" not in payload["query"]:
            # The introspection probe (no nested ofType).
            return {"status_code": 200, "headers": {}, "body": _intro_response_body(7)}
        # Other probes get a generic 400 so they don't accidentally trigger.
        return {"status_code": 400, "headers": {}, "body": ""}

    _patch_post(monkeypatch, respond)
    out = gql.graphql_specialist_check("https://api.example.com/graphql")
    assert out["tests"]["introspection"]["enabled"] is True
    assert out["tests"]["introspection"]["schema_summary"]["type_count"] == 7
    assert out["tests"]["introspection"]["schema_summary"]["query_type"] == "Query"

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    intro_findings = [r for r in reports if "introspection" in r.get("title", "").lower()]
    assert len(intro_findings) == 1
    assert intro_findings[0]["severity"] == "info"
    assert intro_findings[0]["category"] == "info_disclosure"


def test_introspection_disabled_no_finding(monkeypatch) -> None:
    def respond(url, payload, **kw):
        if isinstance(payload, list):
            return {"status_code": 400, "headers": {}, "body": ""}
        return {"status_code": 400, "headers": {}, "body": '{"errors":[{"message":"introspection disabled"}]}'}

    _patch_post(monkeypatch, respond)
    out = gql.graphql_specialist_check("https://api.example.com/graphql")
    assert out["tests"]["introspection"]["enabled"] is False
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    intro_findings = [r for r in reports if "introspection" in r.get("title", "").lower()]
    assert intro_findings == []


def test_introspection_403_no_finding(monkeypatch) -> None:
    """A 403 on the introspection query → not enabled."""
    _patch_post(monkeypatch, lambda url, payload, **kw: {"status_code": 403, "headers": {}, "body": "Forbidden"})
    out = gql.graphql_specialist_check("https://api.example.com/graphql")
    assert out["tests"]["introspection"]["enabled"] is False


# ---------------------------------------------------------------------------
# Depth abuse
# ---------------------------------------------------------------------------


def test_depth_abuse_accepted_emits_high_finding(monkeypatch) -> None:
    def respond(url, payload, **kw):
        if isinstance(payload, list):
            return {"status_code": 400, "headers": {}, "body": ""}
        q = payload.get("query", "")
        if "DepthProbe" in q or "ofType" in q:
            # Server accepts arbitrary depth.
            return {
                "status_code": 200, "headers": {},
                "body": json.dumps({"data": {"__schema": {"types": [{"name": "X", "kind": "OBJECT"}]}}}),
                "elapsed_ms": 850,
            }
        # Other probes — trivial response.
        return {"status_code": 400, "headers": {}, "body": ""}

    _patch_post(monkeypatch, respond)
    out = gql.graphql_specialist_check("https://api.example.com/graphql", depth_probe_max=12)
    assert out["tests"]["depth_abuse"]["accepted"] is True
    assert out["tests"]["depth_abuse"]["depth_tested"] == 12

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    depth_findings = [r for r in reports if "depth limit" in r.get("title", "").lower()]
    assert len(depth_findings) == 1
    assert depth_findings[0]["severity"] == "high"
    assert depth_findings[0]["cwe"] == "CWE-770"


def test_depth_abuse_rejected_no_finding(monkeypatch) -> None:
    def respond(url, payload, **kw):
        if isinstance(payload, list):
            return {"status_code": 400, "headers": {}, "body": ""}
        q = payload.get("query", "")
        if "DepthProbe" in q or "ofType" in q:
            return {"status_code": 400, "headers": {}, "body": '{"errors":[{"message":"max depth exceeded"}]}'}
        return {"status_code": 200, "headers": {}, "body": _intro_response_body(0)}

    _patch_post(monkeypatch, respond)
    out = gql.graphql_specialist_check("https://api.example.com/graphql")
    assert out["tests"]["depth_abuse"]["accepted"] is False
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    depth_findings = [r for r in reports if "depth limit" in r.get("title", "").lower()]
    assert depth_findings == []


# ---------------------------------------------------------------------------
# Alias overloading
# ---------------------------------------------------------------------------


def test_alias_overload_accepted_emits_high_finding(monkeypatch) -> None:
    """Server returns N aliased keys → confirmed accepted."""
    def respond(url, payload, **kw):
        if isinstance(payload, list):
            return {"status_code": 400, "headers": {}, "body": ""}
        q = payload.get("query", "")
        if "AliasProbe" in q:
            data = {f"a{i}": {"queryType": {"name": "Query"}} for i in range(100)}
            return {
                "status_code": 200, "headers": {},
                "body": json.dumps({"data": data}),
            }
        return {"status_code": 400, "headers": {}, "body": ""}

    _patch_post(monkeypatch, respond)
    out = gql.graphql_specialist_check("https://api.example.com/graphql", alias_count=100)
    assert out["tests"]["alias_abuse"]["all_accepted"] is True
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    alias_findings = [r for r in reports if "alias" in r.get("title", "").lower()]
    assert len(alias_findings) == 1
    assert alias_findings[0]["severity"] == "high"


def test_alias_overload_partial_response_no_finding(monkeypatch) -> None:
    """Server processed only a fraction of the aliases → not flagged."""
    def respond(url, payload, **kw):
        if isinstance(payload, list):
            return {"status_code": 400, "headers": {}, "body": ""}
        q = payload.get("query", "")
        if "AliasProbe" in q:
            data = {f"a{i}": {"queryType": {"name": "Query"}} for i in range(5)}
            return {
                "status_code": 200, "headers": {},
                "body": json.dumps({"data": data}),
            }
        return {"status_code": 400, "headers": {}, "body": ""}

    _patch_post(monkeypatch, respond)
    out = gql.graphql_specialist_check("https://api.example.com/graphql", alias_count=100)
    assert out["tests"]["alias_abuse"]["all_accepted"] is False


def test_alias_overload_rejected_no_finding(monkeypatch) -> None:
    def respond(url, payload, **kw):
        if isinstance(payload, list):
            return {"status_code": 400, "headers": {}, "body": ""}
        if "AliasProbe" in payload.get("query", ""):
            return {"status_code": 400, "headers": {}, "body": '{"errors":[{"message":"alias limit exceeded"}]}'}
        return {"status_code": 400, "headers": {}, "body": ""}

    _patch_post(monkeypatch, respond)
    out = gql.graphql_specialist_check("https://api.example.com/graphql")
    assert out["tests"]["alias_abuse"]["all_accepted"] is False


# ---------------------------------------------------------------------------
# Batch query
# ---------------------------------------------------------------------------


def test_batch_query_accepted_emits_medium_finding(monkeypatch) -> None:
    def respond(url, payload, **kw):
        if isinstance(payload, list):
            # Batch payload — server processed all.
            arr = [{"data": {"__schema": {"queryType": {"name": "Query"}}}}] * len(payload)
            return {"status_code": 200, "headers": {}, "body": json.dumps(arr)}
        return {"status_code": 400, "headers": {}, "body": ""}

    _patch_post(monkeypatch, respond)
    out = gql.graphql_specialist_check("https://api.example.com/graphql", batch_size=50)
    assert out["tests"]["batch_abuse"]["accepted"] is True
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    batch_findings = [r for r in reports if "batch" in r.get("title", "").lower()]
    assert len(batch_findings) == 1
    assert batch_findings[0]["severity"] == "medium"


def test_batch_query_rejected_no_finding(monkeypatch) -> None:
    def respond(url, payload, **kw):
        if isinstance(payload, list):
            return {"status_code": 400, "headers": {}, "body": '{"error":"batch not supported"}'}
        return {"status_code": 400, "headers": {}, "body": ""}

    _patch_post(monkeypatch, respond)
    out = gql.graphql_specialist_check("https://api.example.com/graphql")
    assert out["tests"]["batch_abuse"]["accepted"] is False


def test_batch_query_partial_processing_no_finding(monkeypatch) -> None:
    """Server returns fewer items than requested → not flagged."""
    def respond(url, payload, **kw):
        if isinstance(payload, list):
            # Only processed first 5.
            arr = [{"data": {"__schema": {"queryType": {"name": "Query"}}}}] * 5
            return {"status_code": 200, "headers": {}, "body": json.dumps(arr)}
        return {"status_code": 400, "headers": {}, "body": ""}

    _patch_post(monkeypatch, respond)
    out = gql.graphql_specialist_check("https://api.example.com/graphql", batch_size=50)
    assert out["tests"]["batch_abuse"]["accepted"] is False


# ---------------------------------------------------------------------------
# Per-test check events
# ---------------------------------------------------------------------------


def test_emits_one_check_per_test(monkeypatch) -> None:
    _patch_post(monkeypatch, lambda url, payload, **kw: {"status_code": 400, "headers": {}, "body": ""})
    gql.graphql_specialist_check("https://api.example.com/graphql")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 4
    by_cat = summary["by_category"]
    assert "graphql_introspection" in by_cat
    assert "graphql_depth_abuse" in by_cat
    assert "graphql_alias_abuse" in by_cat
    assert "graphql_batch_abuse" in by_cat


# ---------------------------------------------------------------------------
# Cluster-A composition
# ---------------------------------------------------------------------------


def test_excluded_path_short_circuits_via_proxy(monkeypatch) -> None:
    """When the GraphQL URL path matches an exclude-path glob, every probe
    returns the structured `skipped` response and no findings emit."""
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", json.dumps(["/graphql"]))

    class FakeManager:
        def send_simple_request(self, method, url, headers=None, body=None, timeout=30):
            from strix.tools.proxy.http_safety import excluded_response, is_path_excluded
            excluded, glob = is_path_excluded(url)
            if excluded:
                return excluded_response(url, glob or "")
            return {"status_code": 200, "headers": {}, "body": _intro_response_body(5)}

    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: FakeManager(),
    )
    out = gql.graphql_specialist_check("https://api.example.com/graphql")
    assert out["tests"]["introspection"]["enabled"] is False
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []
