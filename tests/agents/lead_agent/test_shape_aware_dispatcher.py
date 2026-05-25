"""Tests for iter-30 — shape-aware dispatcher (phase 2.5 of prepass)."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from strix.agents.lead_agent.shape_aware_dispatcher import (
    DispatchFinding,
    DispatchSummary,
    _CLASS_TO_VULN_CLASSES,
    _build_attack_kwargs_for_shape,
    _build_attack_url,
    _pick_variant_payload,
    shape_aware_dispatch,
)
from strix.l15.baseline_diff import DiffSignal


@pytest.fixture(autouse=True)
def _reset_env(monkeypatch):
    """Clean STRIX_AUTH_*/STRIX_DESTRUCTIVE_OK/STRIX_SHAPE_DISPATCHER_DISABLED."""
    for k in (
        "STRIX_AUTH_BEARER", "STRIX_AUTH_COOKIE",
        "STRIX_DESTRUCTIVE_OK", "STRIX_SHAPE_DISPATCHER_DISABLED",
    ):
        monkeypatch.delenv(k, raising=False)
    yield


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_class_to_vuln_classes_no_sut_specific_logic():
    """The class→vuln-class map must reference generic OWASP/REST
    vocabulary only."""
    from pathlib import Path
    src = Path(__file__).resolve().parents[3] / "strix" / "agents" / "lead_agent" / "shape_aware_dispatcher.py"
    text = src.read_text().lower()
    forbidden = ("juice-shop", "juiceshop", "vampi", "crapi", "nodegoat",
                 "webgoat", "vibe-app", "nginx-vuln", "/rest/user/login",
                 "/api/challenges", "bkimminich")
    for f in forbidden:
        assert f not in text


def test_class_to_vuln_classes_covers_common_endpoint_classes():
    must_have = {"search", "upload", "admin", "api-list", "api-detail",
                 "auth-login", "auth-register", "generic"}
    assert must_have.issubset(set(_CLASS_TO_VULN_CLASSES))


def test_destructive_class_has_no_vuln_classes():
    """destructive endpoints must NEVER be probed — empty class list."""
    assert _CLASS_TO_VULN_CLASSES["destructive"] == []


def test_static_class_has_no_vuln_classes():
    assert _CLASS_TO_VULN_CLASSES["static-asset"] == []


# ---------------------------------------------------------------------------
# Attack URL + kwarg construction
# ---------------------------------------------------------------------------

def test_attack_url_get_appends_query_param():
    url = _build_attack_url(
        "http://app/search", shape="url-param", method="GET",
        params=["q"], payload="' OR 1=1",
    )
    assert "q=' OR 1=1" in url


def test_attack_url_get_path_shape_appends_to_path():
    url = _build_attack_url(
        "http://app/files", shape="path", method="GET",
        params=None, payload="../../../etc/passwd",
    )
    assert url.endswith("../../../etc/passwd")


def test_attack_url_post_returns_unchanged():
    """POSTs put payload in body, not URL."""
    url = _build_attack_url(
        "http://app/login", shape="json", method="POST",
        params=["email"], payload="' OR 1=1",
    )
    assert url == "http://app/login"


def test_attack_kwargs_form_post():
    kw = _build_attack_kwargs_for_shape(
        shape="form", method="POST", params=["email", "password"],
        payload="' OR 1=1",
    )
    assert kw["data"] == {"email": "' OR 1=1", "password": "' OR 1=1"}


def test_attack_kwargs_json_post():
    kw = _build_attack_kwargs_for_shape(
        shape="json", method="POST", params=["email"], payload="x",
    )
    assert kw["json"] == {"email": "x"}


def test_attack_kwargs_json_nosql_payload():
    """JSON SQLi bin can carry dict-shaped NoSQL operators."""
    kw = _build_attack_kwargs_for_shape(
        shape="json", method="POST", params=["password"],
        payload={"$ne": None},
    )
    assert kw["json"] == {"password": {"$ne": None}}


def test_attack_kwargs_graphql_wraps_in_variables():
    kw = _build_attack_kwargs_for_shape(
        shape="graphql", method="POST", params=None, payload="' OR 1=1",
    )
    assert "query" in kw["json"]
    assert kw["json"]["variables"] == {"id": "' OR 1=1"}


# ---------------------------------------------------------------------------
# Variant picker
# ---------------------------------------------------------------------------

def test_variant_picker_prefers_same_type():
    payloads = ["a", "b", {"$ne": 1}]
    v = _pick_variant_payload(payloads, "a")
    assert v == "b"  # same type (str)


def test_variant_picker_falls_back_to_any_different():
    payloads = ["a"]
    v = _pick_variant_payload(payloads, "a")
    assert v is None  # only one payload, no variant


# ---------------------------------------------------------------------------
# shape_aware_dispatch — end-to-end (mocked HTTP)
# ---------------------------------------------------------------------------

@patch("strix.agents.lead_agent.shape_aware_dispatcher.fire_and_diff")
@patch("strix.agents.lead_agent.shape_aware_dispatcher.classify_endpoint")
def test_dispatcher_skips_static_assets(mock_classify, mock_fire):
    from strix.l15.endpoint_classifier import EndpointProfile
    mock_classify.return_value = EndpointProfile(
        url="http://app/static/x.js",
        shape="static", endpoint_class="static-asset",
    )
    summary = shape_aware_dispatch(
        "http://app",
        endpoints=[{"url": "http://app/static/x.js", "method": "GET"}],
    )
    assert summary.endpoints_skipped_static == 1
    assert summary.endpoints_probed == 0
    mock_fire.assert_not_called()


@patch("strix.agents.lead_agent.shape_aware_dispatcher.fire_and_diff")
@patch("strix.agents.lead_agent.shape_aware_dispatcher.classify_endpoint")
def test_dispatcher_refuses_destructive_endpoints(mock_classify, mock_fire, monkeypatch):
    from strix.l15.endpoint_classifier import EndpointProfile
    monkeypatch.delenv("STRIX_DESTRUCTIVE_OK", raising=False)
    mock_classify.return_value = EndpointProfile(
        url="http://app/admin/wipe",
        shape="form", endpoint_class="destructive",
    )
    summary = shape_aware_dispatch(
        "http://app",
        endpoints=[{"url": "http://app/admin/wipe", "method": "POST"}],
    )
    assert summary.endpoints_skipped_destructive == 1
    mock_fire.assert_not_called()


@patch("strix.agents.lead_agent.shape_aware_dispatcher._emit_to_tracer")
@patch("strix.agents.lead_agent.shape_aware_dispatcher.fire_and_diff")
@patch("strix.agents.lead_agent.shape_aware_dispatcher.classify_endpoint")
def test_dispatcher_emits_finding_when_signal_verified(
    mock_classify, mock_fire, mock_emit,
):
    """A scored signal + verified PoC → finding emitted."""
    from strix.l15.endpoint_classifier import EndpointProfile
    mock_classify.return_value = EndpointProfile(
        url="http://app/login", shape="form", endpoint_class="auth-login",
        methods=["POST"], idempotent=False,
    )
    # First fire (signal) + rerun + variant all return same sqli signal
    sqli_signal = DiffSignal(
        score=0.7, new_error_classes=["sqli"],
        new_error_tokens=["SQLSTATE"], reasons=["new error sqli"],
    )
    mock_fire.return_value = sqli_signal

    summary = shape_aware_dispatch(
        "http://app",
        forms=[{
            "action": "/login", "method": "POST",
            "inputs": [{"name": "email"}, {"name": "password"}],
        }],
    )
    assert summary.payloads_fired > 0
    assert summary.signals_above_threshold > 0
    assert len(summary.findings) >= 1
    f = summary.findings[0]
    assert f.vuln_class == "sqli"
    assert f.confidence in ("verified", "likely")
    mock_emit.assert_called()


@patch("strix.agents.lead_agent.shape_aware_dispatcher.fire_and_diff")
@patch("strix.agents.lead_agent.shape_aware_dispatcher.classify_endpoint")
def test_dispatcher_no_emission_when_signal_below_threshold(
    mock_classify, mock_fire,
):
    """Score < 0.5 → don't bother PoC-verifying, don't emit."""
    from strix.l15.endpoint_classifier import EndpointProfile
    mock_classify.return_value = EndpointProfile(
        url="http://app/x", shape="form", endpoint_class="search",
    )
    mock_fire.return_value = DiffSignal(score=0.2)  # weak signal
    summary = shape_aware_dispatch(
        "http://app",
        endpoints=[{"url": "http://app/search", "method": "GET",
                    "params": ["q"]}],
    )
    assert summary.signals_above_threshold == 0
    assert summary.findings == []


def test_dispatcher_disabled_via_env(monkeypatch):
    monkeypatch.setenv("STRIX_SHAPE_DISPATCHER_DISABLED", "1")
    summary = shape_aware_dispatch(
        "http://app",
        endpoints=[{"url": "http://app/x", "method": "GET", "params": []}],
    )
    assert summary.endpoints_seen == 0
    assert summary.endpoints_probed == 0


def test_dispatcher_empty_base_url_returns_empty_summary():
    summary = shape_aware_dispatch("", forms=[], endpoints=[])
    assert summary.endpoints_seen == 0


def test_dispatcher_dedups_by_url_method():
    from strix.l15.endpoint_classifier import EndpointProfile
    with patch(
        "strix.agents.lead_agent.shape_aware_dispatcher.classify_endpoint"
    ) as mock_classify, patch(
        "strix.agents.lead_agent.shape_aware_dispatcher.fire_and_diff"
    ):
        mock_classify.return_value = EndpointProfile(
            url="http://app/x", shape="static", endpoint_class="static-asset",
        )
        summary = shape_aware_dispatch(
            "http://app",
            endpoints=[
                {"url": "http://app/x", "method": "GET", "params": []},
                {"url": "http://app/x", "method": "GET", "params": []},
                {"url": "http://app/x", "method": "POST", "params": []},
            ],
        )
        # 3 candidates, 2 unique (url,method)
        assert summary.endpoints_seen == 2


@patch("strix.agents.lead_agent.shape_aware_dispatcher.fire_and_diff")
@patch("strix.agents.lead_agent.shape_aware_dispatcher.classify_endpoint")
def test_dispatcher_normalizes_openapi_param_objects(mock_classify, mock_fire):
    """Regression: openapi_spec_ingest emits params as OpenAPI parameter
    OBJECTS (dicts with 'name', 'in', 'schema'), not name strings.
    The dispatcher must flatten to strings or we get
    `TypeError: cannot use 'dict' as a dict key` when params are
    spread into a JSON body or form-data dict.

    Caught by iter-30's first vampi bench run; this test pins the fix.
    """
    from strix.l15.endpoint_classifier import EndpointProfile
    mock_classify.return_value = EndpointProfile(
        url="http://app/users/{id}",
        shape="json", endpoint_class="api-detail",
    )
    mock_fire.return_value = DiffSignal(score=0.1)  # weak — short-circuit

    # OpenAPI-shaped params (dict-shaped, with name field)
    summary = shape_aware_dispatch(
        "http://app",
        endpoints=[{
            "url": "http://app/users/{id}",
            "method": "GET",
            "params": [
                {"name": "id", "in": "path", "schema": {"type": "string"}},
                {"name": "include", "in": "query", "schema": {"type": "boolean"}},
                # Malformed param entry — must not crash
                {"not_a_name": "x"},
                # Mixed: also accept bare strings (katana-shape)
                "extra_param",
            ],
        }],
    )
    # No crash + dispatcher proceeded
    assert summary.endpoints_seen == 1
    # fire_and_diff actually got called (at least once)
    assert mock_fire.call_count > 0


def test_dispatch_summary_serializes_to_dict():
    import json
    summary = DispatchSummary(
        endpoints_seen=1, endpoints_probed=1,
        findings=[DispatchFinding(
            endpoint="http://app/x", method="GET", vuln_class="sqli",
            payload_excerpt="...", confidence="verified", score=0.9,
        )],
    )
    json.dumps(summary.to_dict())
