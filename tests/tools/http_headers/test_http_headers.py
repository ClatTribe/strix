"""Tests for http_security_headers_audit.

Hermetic — `_http_get` is mocked. Tests cover each per-header check
(present-and-good / missing / weak variants) plus the CORS probe and
the cookie audit.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.http_headers import http_headers as hh
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
    tracer = Tracer("hh-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://app.example.com"}]})
    yield


def _patch_get(monkeypatch, base_response, *, cors_response=None):
    """Patch _http_get to return base_response for the plain GET and
    cors_response for the Origin-included GET."""
    def fake(url, *, extra_headers=None, timeout=12):
        if extra_headers and "Origin" in extra_headers:
            return cors_response if cors_response is not None else base_response
        return base_response

    monkeypatch.setattr(hh, "_http_get", fake)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_empty_target_rejected() -> None:
    out = hh.http_security_headers_audit("")
    assert out["success"] is False


def test_invalid_scheme_rejected() -> None:
    out = hh.http_security_headers_audit("ftp://x.example.com")
    assert out["success"] is False


def test_unreachable_target_inconclusive(monkeypatch) -> None:
    _patch_get(monkeypatch, {"status": 0, "headers": {}, "body": "", "error": "conn refused"})
    out = hh.http_security_headers_audit("https://app.example.com")
    assert out["success"] is False
    assert "unreachable" in out["error_reason"]


def test_excluded_target_inconclusive(monkeypatch) -> None:
    _patch_get(monkeypatch, {"status": 0, "headers": {}, "body": "", "skipped": True})
    out = hh.http_security_headers_audit("https://app.example.com")
    assert out["success"] is False
    assert "exclude-path" in out["error_reason"]


# ---------------------------------------------------------------------------
# HSTS
# ---------------------------------------------------------------------------


def test_hsts_missing_https_low(monkeypatch) -> None:
    _patch_get(monkeypatch, {"status": 200, "headers": {}, "body": ""})
    out = hh.http_security_headers_audit("https://app.example.com")
    hsts = next(r for r in out["results"] if r["header"] == "Strict-Transport-Security")
    assert hsts["severity"] == "low"
    assert hsts["issue"] == "missing"


def test_hsts_missing_http_no_finding(monkeypatch) -> None:
    """HTTP target → HSTS finding suppressed (only meaningful over HTTPS)."""
    _patch_get(monkeypatch, {"status": 200, "headers": {}, "body": ""})
    out = hh.http_security_headers_audit("http://app.example.com")
    hsts = next(r for r in out["results"] if r["header"] == "Strict-Transport-Security")
    assert hsts["severity"] == "info"
    assert hsts["issue"] is None


def test_hsts_weak_max_age_low(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {"Strict-Transport-Security": "max-age=86400"}, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    hsts = next(r for r in out["results"] if r["header"] == "Strict-Transport-Security")
    assert hsts["severity"] == "low"
    assert hsts["issue"] == "weak_max_age"


def test_hsts_no_subdomains_info(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {"Strict-Transport-Security": "max-age=31536000"}, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    hsts = next(r for r in out["results"] if r["header"] == "Strict-Transport-Security")
    assert hsts["severity"] == "info"
    assert hsts["issue"] == "no_subdomain_coverage"


def test_hsts_full_strength_no_finding(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        }, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    hsts = next(r for r in out["results"] if r["header"] == "Strict-Transport-Security")
    assert hsts["issue"] is None


# ---------------------------------------------------------------------------
# CSP
# ---------------------------------------------------------------------------


def test_csp_missing_medium(monkeypatch) -> None:
    _patch_get(monkeypatch, {"status": 200, "headers": {}, "body": ""})
    out = hh.http_security_headers_audit("https://app.example.com")
    csp = next(r for r in out["results"] if r["header"] == "Content-Security-Policy")
    assert csp["severity"] == "medium"
    assert csp["issue"] == "missing"


def test_csp_report_only_only_low(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {
            "Content-Security-Policy-Report-Only": "default-src 'self'",
        }, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    csp = next(r for r in out["results"] if r["header"] == "Content-Security-Policy")
    assert csp["severity"] == "low"
    assert csp["issue"] == "report_only_only"


def test_csp_unsafe_inline_low(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
        }, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    csp = next(r for r in out["results"] if r["header"] == "Content-Security-Policy")
    assert csp["severity"] == "low"
    assert csp["issue"] == "weak_directives"
    assert "unsafe-inline" in csp.get("description", "")


def test_csp_strict_no_finding(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'self'",
        }, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    csp = next(r for r in out["results"] if r["header"] == "Content-Security-Policy")
    assert csp["issue"] is None


# ---------------------------------------------------------------------------
# X-Frame-Options / frame-ancestors
# ---------------------------------------------------------------------------


def test_xfo_missing_low(monkeypatch) -> None:
    _patch_get(monkeypatch, {"status": 200, "headers": {}, "body": ""})
    out = hh.http_security_headers_audit("https://app.example.com")
    xfo = next(r for r in out["results"] if r["header"] == "X-Frame-Options / CSP frame-ancestors")
    assert xfo["severity"] == "low"
    assert xfo["issue"] == "missing"


def test_xfo_explicit_header_satisfies(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {"X-Frame-Options": "SAMEORIGIN"}, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    xfo = next(r for r in out["results"] if r["header"] == "X-Frame-Options / CSP frame-ancestors")
    assert xfo["issue"] is None


def test_xfo_satisfied_by_csp_frame_ancestors(monkeypatch) -> None:
    """frame-ancestors in CSP also satisfies the clickjacking protection
    requirement — no finding even without an X-Frame-Options header."""
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
        }, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    xfo = next(r for r in out["results"] if r["header"] == "X-Frame-Options / CSP frame-ancestors")
    assert xfo["issue"] is None


# ---------------------------------------------------------------------------
# Other simple headers
# ---------------------------------------------------------------------------


def test_xcto_missing_low(monkeypatch) -> None:
    _patch_get(monkeypatch, {"status": 200, "headers": {}, "body": ""})
    out = hh.http_security_headers_audit("https://app.example.com")
    xcto = next(r for r in out["results"] if r["header"] == "X-Content-Type-Options")
    assert xcto["severity"] == "low"
    assert xcto["issue"] == "missing"


def test_xcto_present_no_finding(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {"X-Content-Type-Options": "nosniff"}, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    xcto = next(r for r in out["results"] if r["header"] == "X-Content-Type-Options")
    assert xcto["issue"] is None


def test_referrer_policy_missing_low(monkeypatch) -> None:
    _patch_get(monkeypatch, {"status": 200, "headers": {}, "body": ""})
    out = hh.http_security_headers_audit("https://app.example.com")
    rp = next(r for r in out["results"] if r["header"] == "Referrer-Policy")
    assert rp["severity"] == "low"


def test_permissions_policy_missing_info(monkeypatch) -> None:
    """Permissions-Policy gap is info-severity (defense-in-depth)."""
    _patch_get(monkeypatch, {"status": 200, "headers": {}, "body": ""})
    out = hh.http_security_headers_audit("https://app.example.com")
    pp = next(r for r in out["results"] if r["header"] == "Permissions-Policy")
    assert pp["severity"] == "info"
    assert pp["issue"] == "missing"


# ---------------------------------------------------------------------------
# Version disclosure
# ---------------------------------------------------------------------------


def test_server_with_version_disclosed_info(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {"Server": "nginx/1.18.0"}, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    server_findings = [r for r in out["results"] if r.get("header") == "Server"]
    assert len(server_findings) == 1
    assert server_findings[0]["severity"] == "info"
    assert server_findings[0]["issue"] == "version_disclosure"


def test_server_without_version_no_finding(monkeypatch) -> None:
    """`Server: nginx` (no version) is just tech disclosure — not flagged."""
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {"Server": "nginx"}, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    server_findings = [r for r in out["results"] if r.get("header") == "Server"]
    assert server_findings == []


def test_x_powered_by_with_version_disclosed(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {"X-Powered-By": "PHP/7.4.3"}, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    xpb_findings = [r for r in out["results"] if r.get("header") == "X-Powered-By"]
    assert len(xpb_findings) == 1


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


def test_cors_reflects_origin_with_credentials_high(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {}, "body": ""},
        cors_response={
            "status": 200,
            "headers": {
                "Access-Control-Allow-Origin": "https://attacker.example.com",
                "Access-Control-Allow-Credentials": "true",
            },
            "body": "",
        },
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    cors = next(r for r in out["results"] if r["header"] == "Access-Control-Allow-Origin")
    assert cors["severity"] == "high"
    assert cors["issue"] == "reflects_origin_with_credentials"
    assert cors.get("cwe") == "CWE-942"

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    cors_findings = [r for r in reports if "Access-Control" in r.get("title", "")]
    assert len(cors_findings) == 1
    assert cors_findings[0]["severity"] == "high"


def test_cors_wildcard_with_credentials_medium(monkeypatch) -> None:
    """`*` + Allow-Credentials is rejected by browsers but still a config bug."""
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {}, "body": ""},
        cors_response={
            "status": 200,
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            "body": "",
        },
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    cors = next(r for r in out["results"] if r["header"] == "Access-Control-Allow-Origin")
    assert cors["severity"] == "medium"
    assert cors["issue"] == "wildcard_with_credentials"


def test_cors_no_reflection_no_finding(monkeypatch) -> None:
    """Server returns no ACAO at all → no CORS finding."""
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {}, "body": ""},
        cors_response={"status": 200, "headers": {}, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    cors = next(r for r in out["results"] if r["header"] == "Access-Control-Allow-Origin")
    assert cors["issue"] is None


def test_cors_strict_allowlist_no_finding(monkeypatch) -> None:
    """Server returns ACAO but does NOT reflect attacker → not flagged."""
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {}, "body": ""},
        cors_response={
            "status": 200,
            "headers": {
                "Access-Control-Allow-Origin": "https://allowed-friend.com",
                "Access-Control-Allow-Credentials": "true",
            },
            "body": "",
        },
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    cors = next(r for r in out["results"] if r["header"] == "Access-Control-Allow-Origin")
    assert cors["issue"] is None


# ---------------------------------------------------------------------------
# Cookie flags
# ---------------------------------------------------------------------------


def test_cookie_session_missing_httponly_medium(monkeypatch) -> None:
    """Session-shaped cookie without HttpOnly → medium."""
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {
            "Set-Cookie": "sessionid=abc123; Path=/; Secure; SameSite=Lax",
        }, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    cookie_findings = [r for r in out["results"] if r.get("issue") == "missing_cookie_flags"]
    assert len(cookie_findings) == 1
    assert cookie_findings[0]["severity"] == "medium"
    assert "HttpOnly" in cookie_findings[0]["missing_flags"]


def test_cookie_non_session_missing_flags_low(monkeypatch) -> None:
    """Non-session cookie without flags → low."""
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {
            "Set-Cookie": "preferences=darkmode; Path=/",
        }, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    cookie_findings = [r for r in out["results"] if r.get("issue") == "missing_cookie_flags"]
    assert len(cookie_findings) == 1
    assert cookie_findings[0]["severity"] == "low"


def test_cookie_full_flags_no_finding(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {
            "Set-Cookie": "sessionid=abc; HttpOnly; Secure; SameSite=Strict",
        }, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    cookie_findings = [r for r in out["results"] if r.get("issue") == "missing_cookie_flags"]
    assert cookie_findings == []


def test_cookie_secure_only_required_on_https(monkeypatch) -> None:
    """A cookie missing Secure on HTTP is fine (Secure can't be set on HTTP);
    on HTTPS it's flagged."""
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {
            "Set-Cookie": "preferences=x; Path=/; HttpOnly; SameSite=Lax",
        }, "body": ""},
    )
    out_http = hh.http_security_headers_audit("http://app.example.com")
    http_findings = [r for r in out_http["results"] if r.get("issue") == "missing_cookie_flags"]
    assert http_findings == []  # not flagged on http://
    # Reset tracer for second invocation.
    from strix.telemetry.tracer import Tracer, set_global_tracer
    t = Tracer("hh-test-https")
    set_global_tracer(t)
    out_https = hh.http_security_headers_audit("https://app.example.com")
    https_findings = [r for r in out_https["results"] if r.get("issue") == "missing_cookie_flags"]
    assert len(https_findings) == 1


def test_cookie_value_never_in_finding(monkeypatch) -> None:
    """Per credentials-feedback memory: cookie values must never appear in
    finding output."""
    _patch_get(
        monkeypatch,
        {"status": 200, "headers": {
            "Set-Cookie": "sessionid=VERY_SENSITIVE_COOKIE_VALUE_12345; Path=/",
        }, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    import json
    serialized = json.dumps(out)
    assert "VERY_SENSITIVE_COOKIE_VALUE_12345" not in serialized
    # Reports too.
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert "VERY_SENSITIVE_COOKIE_VALUE_12345" not in json.dumps(reports)


# ---------------------------------------------------------------------------
# End-to-end findings emission
# ---------------------------------------------------------------------------


def test_clean_target_zero_findings(monkeypatch) -> None:
    """A perfectly-configured target → zero findings emitted."""
    _patch_get(
        monkeypatch,
        {
            "status": 200,
            "headers": {
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'self'",
                "X-Frame-Options": "SAMEORIGIN",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=()",
                "Set-Cookie": "sessionid=x; HttpOnly; Secure; SameSite=Strict",
            },
            "body": "",
        },
        cors_response={"status": 200, "headers": {}, "body": ""},
    )
    out = hh.http_security_headers_audit("https://app.example.com")
    assert out["findings_emitted"] == 0
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


def test_findings_carry_plain_fields(monkeypatch) -> None:
    """Every emitted finding should include description_plain + recommended_action
    (the §11 non-tech UX fields)."""
    _patch_get(monkeypatch, {"status": 200, "headers": {}, "body": ""})
    hh.http_security_headers_audit("https://app.example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) > 0
    for r in reports:
        assert "description_plain" in r
        assert "recommended_action" in r
        assert r.get("fix_time_estimate") == "5min"


def test_check_event_emitted(monkeypatch) -> None:
    _patch_get(monkeypatch, {"status": 200, "headers": {}, "body": ""})
    hh.http_security_headers_audit("https://app.example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "http_security_headers" in summary["by_category"]
