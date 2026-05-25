"""Tests for iter-29.1 — endpoint classifier.

Covers:
  * shape detection (form / json / graphql / multipart / xml / static / unknown)
  * endpoint-class detection (search / upload / admin / auth-* / api-* / destructive / static-asset / generic)
  * framework + WAF fingerprinting from documented signatures
  * baseline metrics (status / size / time / headers / error signals)
  * auth-required detection (401/403 vs 200)
  * idempotency derivation from observed methods
  * anti-overfit guards (no SUT-specific paths in source)
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from strix.l15.endpoint_classifier import (
    _CLASS_PATTERNS,
    _FRAMEWORK_FINGERPRINTS,
    _GRAPHQL_HINTS,
    _STATIC_EXTS,
    _WAF_FINGERPRINTS,
    EndpointProfile,
    classify_endpoint,
    classify_endpoints_batch,
)


# ---------------------------------------------------------------------------
# Anti-overfit — the classifier source must NOT mention any fixture name
# ---------------------------------------------------------------------------

def test_source_has_no_fixture_specific_strings():
    """Regression-guard: the classifier source code must not reference
    any specific SUT fixture. Detection should derive from documented
    conventions only."""
    src = Path(__file__).resolve().parents[2] / "strix" / "l15" / "endpoint_classifier.py"
    text = src.read_text().lower()
    forbidden = (
        "juice-shop", "juiceshop", "bkimminich",
        "vampi", "crapi", "nodegoat", "webgoat",
        "vibe-app", "nginx-vuln", "flask-vuln",
        "/rest/user/login",    # juice-shop-specific
        "/api/challenges",     # juice-shop-specific
        "/api/users/v1/",      # vampi-specific
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific token {f!r} in classifier source"


def test_class_patterns_are_conventions_not_paths():
    """Class-pattern substrings should be REST/OWASP-conventional
    keywords (admin, login, register, upload, ...), not SUT-specific
    full paths."""
    for cls, patterns in _CLASS_PATTERNS:
        for p in patterns:
            # Reasonable upper bound — convention substrings are short
            assert len(p) <= 30, f"class={cls} pattern={p!r} suspiciously long (overfit?)"


def test_framework_fingerprints_are_documented():
    """Each framework fingerprint must come from documented
    framework defaults — names should match real frameworks."""
    names = {name for name, *_ in _FRAMEWORK_FINGERPRINTS}
    # Must contain at least the major ones
    must_have = {"express", "django", "rails", "spring", "tomcat", "nginx", "apache"}
    assert must_have.issubset(names), f"missing framework fingerprints: {must_have - names}"


def test_waf_fingerprints_are_industry():
    """WAF fingerprint vendors must be real, publicly-documented WAFs."""
    names = {name for name, *_ in _WAF_FINGERPRINTS}
    must_have = {"cloudflare", "akamai", "aws-waf", "azure-frontdoor", "sucuri"}
    assert must_have.issubset(names), f"missing WAF fingerprints: {must_have - names}"


# ---------------------------------------------------------------------------
# Shape detection
# ---------------------------------------------------------------------------

def _mock_response(
    status_code: int = 200,
    content_type: str = "text/html",
    body: str = "",
    headers: dict[str, str] | None = None,
):
    r = MagicMock(spec=requests.Response)
    r.status_code = status_code
    h = {"Content-Type": content_type}
    if headers:
        h.update(headers)
    r.headers = h
    r.text = body
    r.content = body.encode("utf-8") if body else b""
    return r


def test_shape_json_content_type():
    r = _mock_response(content_type="application/json", body='{"x":1}')
    p = classify_endpoint("http://app/api/x", response=r, probe_if_no_response=False)
    assert p.shape == "json"


def test_shape_graphql_path_convention():
    """Path containing `/graphql` => shape=graphql regardless of response."""
    p = classify_endpoint("http://app/api/graphql", probe_if_no_response=False)
    assert p.shape == "graphql"


def test_shape_graphql_content_type():
    r = _mock_response(content_type="application/graphql", body="{}")
    p = classify_endpoint("http://app/x", response=r, probe_if_no_response=False)
    assert p.shape == "graphql"


def test_shape_form_when_html_has_form():
    r = _mock_response(content_type="text/html", body="<form><input/></form>")
    p = classify_endpoint("http://app/login", response=r, probe_if_no_response=False)
    assert p.shape == "form"


def test_shape_xml_content_type():
    r = _mock_response(content_type="application/xml", body="<x/>")
    p = classify_endpoint("http://app/x", response=r, probe_if_no_response=False)
    assert p.shape == "xml"


def test_shape_multipart_content_type():
    r = _mock_response(content_type="multipart/form-data; boundary=---x", body="")
    p = classify_endpoint("http://app/x", response=r, probe_if_no_response=False)
    assert p.shape == "multipart"


def test_shape_grpc_content_type():
    r = _mock_response(content_type="application/grpc+proto", body="")
    p = classify_endpoint("http://app/grpc.svc/Method", response=r, probe_if_no_response=False)
    assert p.shape == "grpc"


def test_shape_static_by_extension():
    for ext in (".js", ".css", ".png", ".woff2"):
        p = classify_endpoint(f"http://app/static/main{ext}", probe_if_no_response=False)
        assert p.shape == "static", f"failed for ext={ext}"
        assert p.endpoint_class == "static-asset"


def test_shape_api_pattern_when_no_response():
    """`/api/...` URL with no response defaults to JSON shape (low conf)."""
    p = classify_endpoint("http://app/api/v1/users", probe_if_no_response=False)
    assert p.shape == "json"


def test_shape_unknown_when_nothing_detected():
    p = classify_endpoint("http://app/something", probe_if_no_response=False)
    assert p.shape == "unknown"


# ---------------------------------------------------------------------------
# Endpoint-class detection
# ---------------------------------------------------------------------------

def test_class_destructive():
    for path in ("/api/users/delete", "/admin/wipe", "/remove/123", "/purge"):
        p = classify_endpoint(f"http://app{path}", probe_if_no_response=False)
        assert p.endpoint_class == "destructive", f"failed for {path}"


def test_class_admin():
    for path in ("/admin/users", "/manage/dashboard", "/console", "/api/admin/users"):
        p = classify_endpoint(f"http://app{path}", probe_if_no_response=False)
        assert p.endpoint_class == "admin", f"failed for {path}"


def test_class_auth_login_vs_register():
    p_login = classify_endpoint("http://app/login", probe_if_no_response=False)
    assert p_login.endpoint_class == "auth-login"

    p_register = classify_endpoint("http://app/signup", probe_if_no_response=False)
    assert p_register.endpoint_class == "auth-register"

    p_oauth = classify_endpoint("http://app/oauth/token", probe_if_no_response=False)
    assert p_oauth.endpoint_class == "auth-login"


def test_class_upload():
    for path in ("/upload", "/api/files/upload", "/media/avatar", "/import"):
        p = classify_endpoint(f"http://app{path}", probe_if_no_response=False)
        assert p.endpoint_class == "upload", f"failed for {path}"


def test_class_redirect():
    for path in ("/redirect?to=x", "/r/abc123", "/go/somewhere", "/forward"):
        p = classify_endpoint(f"http://app{path}", probe_if_no_response=False)
        assert p.endpoint_class == "redirect", f"failed for {path}"


def test_class_search():
    p = classify_endpoint("http://app/search?q=x", probe_if_no_response=False)
    assert p.endpoint_class == "search"


def test_class_api_detail_with_numeric_id():
    p = classify_endpoint("http://app/api/v1/users/123", probe_if_no_response=False)
    assert p.endpoint_class == "api-detail"


def test_class_api_detail_with_uuid():
    p = classify_endpoint(
        "http://app/api/products/550e8400-e29b-41d4-a716-446655440000",
        probe_if_no_response=False,
    )
    assert p.endpoint_class == "api-detail"


def test_class_api_list():
    """A bare collection endpoint with /api/ prefix is a list."""
    p = classify_endpoint("http://app/api/v1/products", probe_if_no_response=False)
    assert p.endpoint_class == "api-list"


def test_class_generic_fallback():
    p = classify_endpoint("http://app/random-page", probe_if_no_response=False)
    assert p.endpoint_class == "generic"


def test_class_admin_beats_login():
    """When both 'admin' and 'login' are in the path, admin wins
    because that's the more important attack scope."""
    p = classify_endpoint("http://app/admin/login", probe_if_no_response=False)
    assert p.endpoint_class == "admin"


# ---------------------------------------------------------------------------
# Framework + WAF detection
# ---------------------------------------------------------------------------

def test_framework_express_via_x_powered_by():
    r = _mock_response(headers={"X-Powered-By": "Express"}, body="")
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert "express" in p.framework_hints


def test_framework_django_via_body_csrf():
    r = _mock_response(body='<input name="csrfmiddlewaretoken" value="abc">')
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert "django" in p.framework_hints


def test_framework_rails_via_x_runtime():
    r = _mock_response(headers={"X-Runtime": "0.012345"})
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert "rails-alt" in p.framework_hints


def test_framework_react_via_body():
    r = _mock_response(body='<div id="root"></div>')
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert "react" in p.framework_hints


def test_framework_wordpress():
    r = _mock_response(body='<link href="/wp-content/themes/x/style.css">')
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert "wordpress" in p.framework_hints


def test_waf_cloudflare_via_cf_ray():
    r = _mock_response(headers={"CF-RAY": "abc123-IAD"})
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert p.waf_detected == "cloudflare"


def test_waf_akamai_via_header():
    r = _mock_response(headers={"X-Akamai-Transformed": "9"})
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert p.waf_detected == "akamai"


def test_waf_sucuri():
    r = _mock_response(headers={"X-Sucuri-ID": "x"})
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert p.waf_detected == "sucuri"


def test_waf_none_when_no_signature():
    r = _mock_response(body="<html/>")
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert p.waf_detected is None


# ---------------------------------------------------------------------------
# Baseline metrics
# ---------------------------------------------------------------------------

def test_baseline_captures_status_size_shape():
    r = _mock_response(status_code=200, content_type="application/json", body='{"x":1}')
    p = classify_endpoint("http://app/api/x", response=r, probe_if_no_response=False)
    assert p.expected_status == 200
    assert p.response_shape == "json"
    assert p.response_size_baseline == len('{"x":1}')


def test_baseline_response_shape_redirect():
    r = _mock_response(status_code=302, content_type="text/html")
    p = classify_endpoint("http://app/r", response=r, probe_if_no_response=False)
    assert p.response_shape == "redirect"


def test_baseline_error_signals_captured():
    """Error tokens in the baseline body get captured for the diff
    verifier to compare against later payload responses."""
    r = _mock_response(
        body="java.lang.NullPointerException at com.example.Foo",
    )
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert "java.lang." in p.error_signals_baseline


def test_baseline_headers_subset_only():
    """Headers captured must be a small deterministic subset, not the
    full set (which includes timestamps / request-ids)."""
    r = _mock_response(headers={
        "Server": "nginx",
        "X-Request-Id": "abc123",
        "Date": "Sun, 01 Jan 2024 00:00:00 GMT",
        "X-Frame-Options": "DENY",
    })
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert "server" in p.headers_baseline
    assert "x-frame-options" in p.headers_baseline
    # Per-request headers excluded
    assert "x-request-id" not in p.headers_baseline
    assert "date" not in p.headers_baseline


# ---------------------------------------------------------------------------
# Auth-required detection
# ---------------------------------------------------------------------------

def test_auth_required_true_on_401():
    r = _mock_response(status_code=401)
    p = classify_endpoint("http://app/api/users", response=r, probe_if_no_response=False)
    assert p.auth_required is True


def test_auth_required_true_on_403():
    r = _mock_response(status_code=403)
    p = classify_endpoint("http://app/admin", response=r, probe_if_no_response=False)
    assert p.auth_required is True


def test_auth_required_false_on_200():
    r = _mock_response(status_code=200)
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert p.auth_required is False


def test_auth_required_none_on_500():
    """Unclear signal — leave as None rather than guessing."""
    r = _mock_response(status_code=500)
    p = classify_endpoint("http://app/", response=r, probe_if_no_response=False)
    assert p.auth_required is None


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

def test_idempotent_when_only_get_observed():
    p = classify_endpoint(
        "http://app/", methods=["GET"], probe_if_no_response=False,
    )
    assert p.idempotent is True


def test_not_idempotent_when_post_observed():
    p = classify_endpoint(
        "http://app/users", methods=["GET", "POST"], probe_if_no_response=False,
    )
    assert p.idempotent is False


def test_not_idempotent_when_delete_observed():
    p = classify_endpoint(
        "http://app/users/1", methods=["DELETE"], probe_if_no_response=False,
    )
    assert p.idempotent is False


# ---------------------------------------------------------------------------
# Public API / edge cases
# ---------------------------------------------------------------------------

def test_empty_url_returns_zero_confidence_profile():
    p = classify_endpoint("", probe_if_no_response=False)
    assert p.classification_confidence == 0.0
    assert "empty url" in p.notes


def test_batch_preserves_order():
    urls = [
        "http://app/login",
        "http://app/admin",
        "http://app/upload",
    ]
    profiles = classify_endpoints_batch(urls, probe_if_no_response=False)
    assert len(profiles) == 3
    assert profiles[0].endpoint_class == "auth-login"
    assert profiles[1].endpoint_class == "admin"
    assert profiles[2].endpoint_class == "upload"


@patch("strix.l15.endpoint_classifier.requests.get")
def test_probe_failure_handled_gracefully(mock_get):
    """Connection errors don't crash the classifier."""
    mock_get.side_effect = requests.ConnectionError("refused")
    p = classify_endpoint("http://app/", probe_if_no_response=True)
    # Falls back to URL-only classification
    assert p.endpoint_class == "generic"
    assert any("probe failed" in n for n in p.notes)


def test_to_dict_json_serializable():
    """Profile must round-trip through JSON for IPC/storage."""
    import json
    p = classify_endpoint("http://app/admin", probe_if_no_response=False)
    d = p.to_dict()
    # Roundtrip
    json.dumps(d)
    assert d["endpoint_class"] == "admin"
    assert d["url"] == "http://app/admin"


def test_static_extensions_cover_common_assets():
    """Industry-standard static extensions are present."""
    must = {".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2", ".map"}
    assert must.issubset(set(_STATIC_EXTS))


def test_graphql_hints_cover_industry_conventions():
    must = {"/graphql", "/api/graphql", "/v1/graphql"}
    assert must.issubset(set(_GRAPHQL_HINTS))
