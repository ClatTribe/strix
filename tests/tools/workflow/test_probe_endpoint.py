"""Tests for `probe_endpoint` composite specialist fan-out
(Phase 3d / PR-β).

The composite reduces the lead's per-turn decision from "pick 4-6
specialists" to "pick the right kind." These tests pin:
  * URL classification (form / api / search / auth / files /
    id_in_path / state_changing)
  * Per-kind dispatch tables
  * scan_idor is gated on auth_captured
  * Aggregation: findings union, evidence prefixed, status promotion
  * Workflow integration: endpoint recorded as probed
  * Failure modes: missing tool, raising tool, all-error
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from strix.agents import workflow_state as ws
from strix.tools.workflow.probe_endpoint import (
    _classify_endpoint,
    _dispatch_for_kind,
    _filter_kwargs_for_tool,
    probe_endpoint,
)


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_WORKFLOW_DISABLED", raising=False)
    ws.reset_for_testing()
    yield
    ws.reset_for_testing()


# ---------------------------------------------------------------------------
# URL classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,expected_kind", [
    # Auth surfaces — login / signin / reset / register
    ("https://x.com/login",                  "auth"),
    ("https://x.com/api/v1/signin",          "auth"),
    ("https://x.com/auth/token",             "auth"),
    ("https://x.com/password-reset",         "auth"),
    ("https://x.com/register",               "auth"),

    # IDs in path (numeric / UUID / long alphanumeric)
    ("https://x.com/api/users/42",           "id_in_path"),
    ("https://x.com/api/users/550e8400-e29b-41d4-a716-446655440000",
     "id_in_path"),
    ("https://x.com/orders/abc123def456ghi789jk",  "id_in_path"),

    # File-shaped endpoints
    ("https://x.com/static/image.png",       "files"),
    ("https://x.com/upload",                 "files"),
    ("https://x.com/download/report.pdf",    "files"),

    # API
    ("https://x.com/api/users",              "api"),
    ("https://x.com/v2/products",            "api"),
    ("https://x.com/graphql",                "api"),

    # Search via query keys
    ("https://x.com/products?q=widget",      "search"),
    ("https://x.com/?search=test&page=2",    "search"),

    # Default fallback
    ("https://x.com/contact",                "form"),
    ("https://x.com/",                       "form"),
])
def test_classify_endpoint(url, expected_kind) -> None:
    assert _classify_endpoint(url) == expected_kind


# ---------------------------------------------------------------------------
# Dispatch tables
# ---------------------------------------------------------------------------


def test_dispatch_form_fans_out_sqli_xss_open_redirect() -> None:
    specs = _dispatch_for_kind("form", auth_captured=False)
    assert specs == ["scan_sqli", "scan_xss", "open_redirect_check"]


def test_dispatch_auth_uses_auth_specialists() -> None:
    specs = _dispatch_for_kind("auth", auth_captured=False)
    assert "scan_auth_flow" in specs
    # scan_sqli shouldn't be in the auth fan-out — auth endpoints
    # take credentials, not SQLi payloads (the dedicated auth tools
    # handle that surface differently).
    assert "scan_sqli" not in specs


def test_dispatch_state_changing_includes_csrf() -> None:
    specs = _dispatch_for_kind("state_changing", auth_captured=False)
    assert "csrf_check" in specs


def test_dispatch_id_in_path_without_auth_excludes_idor() -> None:
    """scan_idor needs a captured auth state to do cross-session
    diff. Without auth, drop it from the fan-out."""
    specs = _dispatch_for_kind("id_in_path", auth_captured=False)
    assert "scan_idor" not in specs
    assert "scan_path_traversal" in specs


def test_dispatch_id_in_path_with_auth_includes_idor() -> None:
    specs = _dispatch_for_kind("id_in_path", auth_captured=True)
    assert "scan_idor" in specs
    assert "scan_path_traversal" in specs


def test_dispatch_unknown_kind_falls_back_to_form() -> None:
    """An unknown kind shouldn't crash — fall back to the most
    general fan-out (`form`)."""
    specs = _dispatch_for_kind("bogus_kind", auth_captured=False)
    assert specs == _dispatch_for_kind("form", auth_captured=False)


# ---------------------------------------------------------------------------
# probe_endpoint end-to-end (mocked specialists)
# ---------------------------------------------------------------------------


def _fake_tool_result(*, findings=None, status="ok", evidence=None):
    """Build a SpecialistResult-shaped dict that the aggregator
    treats as a real tool response."""
    return {
        "schema_version": 1,
        "status": status,
        "findings": findings or [],
        "evidence": evidence or [],
        "tool_metadata": {},
    }


def test_probe_endpoint_returns_error_for_empty_url() -> None:
    result = probe_endpoint(endpoint_url="")
    assert result["status"] == "error"
    assert "url required" in (result.get("error") or "").lower()


def test_probe_endpoint_classifies_url_when_kind_omitted() -> None:
    """When `kind` isn't passed, classification happens from the
    URL. Verify via tool_metadata.kind_source = 'inferred'."""
    with patch(
        "strix.tools.workflow.probe_endpoint._invoke_specialist",
        return_value=_fake_tool_result(),
    ):
        result = probe_endpoint(endpoint_url="https://x.com/login")
    assert result["tool_metadata"]["kind"] == "auth"
    assert result["tool_metadata"]["kind_source"] == "inferred"


def test_probe_endpoint_uses_explicit_kind() -> None:
    """An explicit `kind=` overrides URL classification — preferred
    when the lead knows the endpoint shape better than the heuristic."""
    with patch(
        "strix.tools.workflow.probe_endpoint._invoke_specialist",
        return_value=_fake_tool_result(),
    ):
        # URL looks like API, but lead says it's a search.
        result = probe_endpoint(
            endpoint_url="https://x.com/api/items",
            kind="search",
        )
    assert result["tool_metadata"]["kind"] == "search"
    assert result["tool_metadata"]["kind_source"] == "explicit"


def test_probe_endpoint_aggregates_findings_across_specialists() -> None:
    """Each specialist's findings show up in the aggregate result."""
    def fake_invoke(name, **_kwargs):
        return _fake_tool_result(
            findings=[
                {"title": f"{name} finding",
                 "severity": "high",
                 "category": "sqli" if "sqli" in name else "xss"},
            ],
            evidence=[f"probe via {name}"],
        )

    with patch(
        "strix.tools.workflow.probe_endpoint._invoke_specialist",
        side_effect=fake_invoke,
    ):
        result = probe_endpoint(
            endpoint_url="https://x.com/contact",  # form kind
        )

    assert result["status"] == "ok"
    # Each dispatched specialist contributes one finding.
    assert len(result["findings"]) == 3
    # Evidence carries the originating tool name as a prefix.
    assert any("[scan_sqli]" in e for e in result["evidence"])
    assert any("[scan_xss]" in e for e in result["evidence"])


def test_probe_endpoint_records_endpoint_probed_in_workflow() -> None:
    """After probe_endpoint runs, the URL appears in workflow's
    endpoints_probed set."""
    ws.record_endpoint_discovered("https://x.com/contact")
    ws.advance_phase("probe")
    with patch(
        "strix.tools.workflow.probe_endpoint._invoke_specialist",
        return_value=_fake_tool_result(),
    ):
        probe_endpoint(endpoint_url="https://x.com/contact")

    snap = ws.snapshot()
    assert snap["endpoints_probed_count"] == 1


def test_probe_endpoint_marks_partial_when_some_specialists_error() -> None:
    """If 1 of 3 specialists errors but the others succeed, the
    overall status should be 'partial' (not 'ok', not 'error')."""
    def fake_invoke(name, **_kwargs):
        if name == "open_redirect_check":
            return _fake_tool_result(status="error")
        return _fake_tool_result(status="ok")

    with patch(
        "strix.tools.workflow.probe_endpoint._invoke_specialist",
        side_effect=fake_invoke,
    ):
        result = probe_endpoint(endpoint_url="https://x.com/contact")
    assert result["status"] == "partial"


def test_probe_endpoint_marks_error_when_all_specialists_error() -> None:
    with patch(
        "strix.tools.workflow.probe_endpoint._invoke_specialist",
        return_value=_fake_tool_result(status="error"),
    ):
        result = probe_endpoint(endpoint_url="https://x.com/contact")
    assert result["status"] == "error"


def test_probe_endpoint_handles_missing_tool_gracefully() -> None:
    """If `_invoke_specialist` returns None (tool not in registry),
    the aggregator skips that contributor without crashing."""
    with patch(
        "strix.tools.workflow.probe_endpoint._invoke_specialist",
        return_value=None,
    ):
        result = probe_endpoint(endpoint_url="https://x.com/contact")
    # All None → no successful statuses → overall error.
    assert result["status"] == "error"


def test_probe_endpoint_exposes_specialists_dispatched_list() -> None:
    """tool_metadata.specialists_dispatched lists the names the
    composite called — gives the lead per-tool traceability."""
    with patch(
        "strix.tools.workflow.probe_endpoint._invoke_specialist",
        return_value=_fake_tool_result(),
    ):
        result = probe_endpoint(
            endpoint_url="https://x.com/contact", kind="form",
        )
    dispatched = result["tool_metadata"]["specialists_dispatched"]
    assert set(dispatched) == {"scan_sqli", "scan_xss", "open_redirect_check"}


def test_probe_endpoint_caps_evidence_lines() -> None:
    """When a fan-out produces lots of evidence (each specialist
    × multiple probes), the aggregator caps the response payload
    so it doesn't blow up the lead's context."""
    big_evidence = [f"probe step {i}" for i in range(100)]

    with patch(
        "strix.tools.workflow.probe_endpoint._invoke_specialist",
        return_value=_fake_tool_result(evidence=big_evidence),
    ):
        result = probe_endpoint(endpoint_url="https://x.com/contact")
    # Cap is 30 lines total.
    assert len(result["evidence"]) <= 30


# ---------------------------------------------------------------------------
# Kwargs filter — pass only what each tool's signature accepts
# ---------------------------------------------------------------------------


def test_filter_kwargs_drops_unknown_args() -> None:
    """The shared probe args (url, params, method, body_template,
    extra_headers) get filtered per-tool. A tool that doesn't take
    `body_template` shouldn't crash when probe_endpoint includes
    it in the common kwargs."""
    candidate = {
        "url": "https://x.com/foo",
        "params": ["q"],
        "method": "POST",
        "body_template": {"q": "v"},
        "extra_headers": {"X": "Y"},
    }
    # scan_xss accepts all of these.
    filtered = _filter_kwargs_for_tool("scan_xss", candidate)
    assert "url" in filtered
    # csrf_check (deterministic check, not a specialist) takes a
    # different shape — most of these args should be dropped.
    filtered_csrf = _filter_kwargs_for_tool("csrf_check", candidate)
    assert isinstance(filtered_csrf, dict)


def test_filter_kwargs_for_unknown_tool_returns_empty() -> None:
    assert _filter_kwargs_for_tool("nonexistent_tool", {"x": 1}) == {}
