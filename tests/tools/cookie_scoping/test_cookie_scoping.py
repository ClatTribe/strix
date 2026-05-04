"""Tests for cookie_jwt_scoping_check (roadmap §7.2).

Hermetic — `_http_request` monkeypatched. Tests cover:

- Cookie parent-domain scoping detection (high for session,
  info for non-session)
- SameSite=None without Secure (medium CWE-614)
- SameSite missing on session cookie (low)
- SameSite-inconsistent cohort (medium)
- JWT cross-acceptance (high CWE-863)
- JWT aud over-broad (low CWE-345)
- Negative cases: host-only cookie, consistent SameSite,
  bound JWT
- ≥2 hosts required
- Result schema + MITRE
"""

from __future__ import annotations

import base64
import json
import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.cookie_scoping.cookie_scoping_check  # noqa: F401

cs_module = sys.modules["strix.tools.cookie_scoping.cookie_scoping_check"]
cookie_jwt_scoping_check = cs_module.cookie_jwt_scoping_check


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
    tracer = Tracer("cookie-scoping-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://app.example.com"}]}
    )
    yield


def _patch_http(monkeypatch, responses_by_url: dict[str, dict[str, Any]]) -> None:
    """`responses_by_url` maps URL → {status, headers?, raw_set_cookies?, body?}."""
    def fake(method, url, *, headers=None, timeout=10.0):
        resp = responses_by_url.get(url)
        if resp is None:
            return {"status": 404, "headers": {}, "raw_set_cookies": [], "body": ""}
        return {
            "status": resp.get("status", 200),
            "headers": resp.get("headers", {}),
            "raw_set_cookies": resp.get("raw_set_cookies", []),
            "body": resp.get("body", ""),
        }
    monkeypatch.setattr(cs_module, "_http_request", fake)


def _findings() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


def _make_jwt(payload: dict[str, Any]) -> str:
    """Build an unsigned JWT for testing — only the payload matters
    since `_decode_jwt_unsafe` doesn't verify the signature."""
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h_b64}.{p_b64}.dummy_sig"


# ---------------------------------------------------------------------------
# Cookie parent-domain scoping
# ---------------------------------------------------------------------------


def test_session_cookie_with_parent_domain_emits_high(monkeypatch) -> None:
    """`Set-Cookie: sessionid=abc; Domain=.example.com` on app.example.com
    leaks to api.example.com (in scope) → high CWE-1275."""
    _patch_http(monkeypatch, {
        "https://app.example.com": {
            "raw_set_cookies": [
                "sessionid=abc; Domain=.example.com; Path=/; HttpOnly; Secure",
            ],
        },
        "https://api.example.com": {"raw_set_cookies": []},
    })

    out = cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
    )

    assert out["success"] is True
    assert out["findings_emitted"] >= 1
    findings = _findings()
    high = [f for f in findings if f["severity"] == "high"]
    assert any("scopes to parent domain" in f["title"] for f in high)
    assert any(f["cwe"] == "CWE-1275" for f in high)


def test_non_session_cookie_with_parent_domain_emits_info(monkeypatch) -> None:
    _patch_http(monkeypatch, {
        "https://app.example.com": {
            "raw_set_cookies": [
                "tracker=xyz; Domain=.example.com; Path=/",
            ],
        },
        "https://api.example.com": {"raw_set_cookies": []},
    })

    cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
    )

    findings = _findings()
    assert any(f["severity"] == "info" and "tracker" in f["title"] for f in findings)


def test_host_only_cookie_no_finding(monkeypatch) -> None:
    """No `Domain=` attribute → host-only scope → not a finding."""
    _patch_http(monkeypatch, {
        "https://app.example.com": {
            "raw_set_cookies": [
                "sessionid=abc; Path=/; HttpOnly; Secure; SameSite=Lax",
            ],
        },
        "https://api.example.com": {
            "raw_set_cookies": [
                "sessionid=def; Path=/; HttpOnly; Secure; SameSite=Lax",
            ],
        },
    })

    out = cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
    )

    assert out["findings_emitted"] == 0
    # Sanity: cookies were actually examined.
    assert out["cookies_examined"] == 2


def test_explicit_host_domain_no_finding(monkeypatch) -> None:
    """`Domain=app.example.com` (literally the host) doesn't leak."""
    _patch_http(monkeypatch, {
        "https://app.example.com": {
            "raw_set_cookies": [
                "sessionid=abc; Domain=app.example.com; HttpOnly; Secure; SameSite=Lax",
            ],
        },
        "https://api.example.com": {"raw_set_cookies": []},
    })

    out = cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
    )

    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# SameSite checks
# ---------------------------------------------------------------------------


def test_samesite_none_without_secure_emits_medium(monkeypatch) -> None:
    _patch_http(monkeypatch, {
        "https://app.example.com": {
            "raw_set_cookies": [
                "tracker=xyz; SameSite=None; Path=/",
            ],
        },
        "https://api.example.com": {"raw_set_cookies": []},
    })

    cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
    )

    findings = _findings()
    assert any(
        f["severity"] == "medium" and "SameSite=None without Secure" in f["title"]
        for f in findings
    )


def test_session_cookie_missing_samesite_emits_low(monkeypatch) -> None:
    _patch_http(monkeypatch, {
        "https://app.example.com": {
            "raw_set_cookies": [
                "sessionid=abc; Path=/; HttpOnly; Secure",  # no SameSite
            ],
        },
        "https://api.example.com": {
            "raw_set_cookies": [
                "sessionid=def; Path=/; HttpOnly; Secure; SameSite=Lax",
            ],
        },
    })

    cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
    )

    findings = _findings()
    assert any(
        f["severity"] == "low" and "missing SameSite" in f["title"] for f in findings
    )


def test_samesite_inconsistent_emits_medium(monkeypatch) -> None:
    """Same cookie name, different SameSite values across cohort → medium."""
    _patch_http(monkeypatch, {
        "https://app.example.com": {
            "raw_set_cookies": [
                "auth_token=abc; Path=/; HttpOnly; Secure; SameSite=Strict",
            ],
        },
        "https://api.example.com": {
            "raw_set_cookies": [
                "auth_token=def; Path=/; HttpOnly; Secure; SameSite=Lax",
            ],
        },
    })

    cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
    )

    findings = _findings()
    assert any(
        f["severity"] == "medium" and "inconsistent SameSite across cohort" in f["title"]
        for f in findings
    )


def test_samesite_consistent_no_finding(monkeypatch) -> None:
    _patch_http(monkeypatch, {
        "https://app.example.com": {
            "raw_set_cookies": [
                "auth_token=abc; Path=/; HttpOnly; Secure; SameSite=Lax",
            ],
        },
        "https://api.example.com": {
            "raw_set_cookies": [
                "auth_token=def; Path=/; HttpOnly; Secure; SameSite=Lax",
            ],
        },
    })

    out = cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
    )

    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# JWT probes
# ---------------------------------------------------------------------------


def test_jwt_cross_acceptance_emits_high(monkeypatch) -> None:
    """JWT from app.example.com accepted at admin.example.com → high CWE-863."""
    token = _make_jwt({"sub": "alice", "aud": "app.example.com"})
    # Baseline (no auth) returns 401; with cross-issued JWT returns 200 + different body.
    call_log = {"baseline": 0, "authed": 0}

    def fake(method, url, *, headers=None, timeout=10.0):
        if url in (
            "https://app.example.com",
            "https://api.example.com",
            "https://admin.example.com",
        ):
            return {"status": 200, "headers": {}, "raw_set_cookies": [], "body": ""}
        if url == "https://admin.example.com/api/me":
            if headers and "authorization" in {k.lower() for k in headers}:
                call_log["authed"] += 1
                return {"status": 200, "headers": {}, "body": '{"user":"alice"}'}
            call_log["baseline"] += 1
            return {"status": 401, "headers": {}, "body": '{"error":"unauthorized"}'}
        return {"status": 404, "headers": {}, "raw_set_cookies": [], "body": ""}

    monkeypatch.setattr(cs_module, "_http_request", fake)

    cookie_jwt_scoping_check(
        cohort_urls=[
            "https://app.example.com",
            "https://api.example.com",
            "https://admin.example.com",
        ],
        jwt_token=token,
        jwt_issuer_url="https://app.example.com",
        jwt_test_endpoints={
            "admin.example.com": "https://admin.example.com/api/me",
        },
    )

    findings = _findings()
    high = [f for f in findings if f["severity"] == "high"]
    assert any("accepted at sister subdomain" in f["title"] for f in high)
    assert any(f["cwe"] == "CWE-863" for f in high)
    # N+1 verification — both baseline + authed were called.
    assert call_log["baseline"] >= 1
    assert call_log["authed"] >= 1


def test_jwt_no_cross_acceptance_when_rejected(monkeypatch) -> None:
    """When the sister host rejects (401) the cross-issued JWT, no finding."""
    token = _make_jwt({"sub": "alice", "aud": "app.example.com"})

    def fake(method, url, *, headers=None, timeout=10.0):
        if url in (
            "https://app.example.com",
            "https://admin.example.com",
        ):
            return {"status": 200, "headers": {}, "raw_set_cookies": [], "body": ""}
        if url == "https://admin.example.com/api/me":
            # Both calls return 401 — properly bound to issuer.
            return {"status": 401, "headers": {}, "body": '{"error":"unauthorized"}'}
        return {"status": 404, "headers": {}, "raw_set_cookies": [], "body": ""}

    monkeypatch.setattr(cs_module, "_http_request", fake)

    cookie_jwt_scoping_check(
        cohort_urls=[
            "https://app.example.com",
            "https://admin.example.com",
        ],
        jwt_token=token,
        jwt_issuer_url="https://app.example.com",
        jwt_test_endpoints={
            "admin.example.com": "https://admin.example.com/api/me",
        },
    )

    findings = _findings()
    assert not any("accepted at sister subdomain" in f["title"] for f in findings)


def test_jwt_aud_over_broad_emits_low(monkeypatch) -> None:
    """JWT aud=example.com covers app + api + admin → low CWE-345."""
    token = _make_jwt({"sub": "alice", "aud": "example.com"})
    _patch_http(monkeypatch, {
        "https://app.example.com": {"raw_set_cookies": []},
        "https://api.example.com": {"raw_set_cookies": []},
    })

    cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
        jwt_token=token,
        jwt_issuer_url="https://app.example.com",
    )

    findings = _findings()
    assert any(
        f["severity"] == "low" and "covers multiple sister" in f["title"] for f in findings
    )


def test_jwt_aud_specific_no_finding(monkeypatch) -> None:
    """JWT aud bound to specific subdomain → no finding."""
    token = _make_jwt({"sub": "alice", "aud": "app.example.com"})
    _patch_http(monkeypatch, {
        "https://app.example.com": {"raw_set_cookies": []},
        "https://api.example.com": {"raw_set_cookies": []},
    })

    out = cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
        jwt_token=token,
        jwt_issuer_url="https://app.example.com",
    )

    assert out["findings_emitted"] == 0


def test_jwt_aud_list_with_one_overbroad_flags(monkeypatch) -> None:
    """aud as a list, one entry over-broad → finding for that entry."""
    token = _make_jwt({
        "sub": "alice",
        "aud": ["app.example.com", "example.com"],
    })
    _patch_http(monkeypatch, {
        "https://app.example.com": {"raw_set_cookies": []},
        "https://api.example.com": {"raw_set_cookies": []},
    })

    cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
        jwt_token=token,
        jwt_issuer_url="https://app.example.com",
    )

    findings = _findings()
    aud_findings = [f for f in findings if "covers multiple sister" in f["title"]]
    assert len(aud_findings) == 1


def test_malformed_jwt_no_audience_finding(monkeypatch) -> None:
    """A non-JWT string in jwt_token shouldn't crash or mis-flag."""
    _patch_http(monkeypatch, {
        "https://app.example.com": {"raw_set_cookies": []},
        "https://api.example.com": {"raw_set_cookies": []},
    })

    out = cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
        jwt_token="not.a.jwt",
        jwt_issuer_url="https://app.example.com",
    )

    assert out["success"] is True
    findings = _findings()
    assert not any("covers multiple sister" in f["title"] for f in findings)


# ---------------------------------------------------------------------------
# Pre-conditions / schema
# ---------------------------------------------------------------------------


def test_single_host_rejected() -> None:
    out = cookie_jwt_scoping_check(cohort_urls=["https://app.example.com"])
    assert out["success"] is False
    assert "≥2" in (out.get("error") or "") or "2 cohort" in (out.get("error") or "")


def test_empty_cohort_rejected() -> None:
    out = cookie_jwt_scoping_check(cohort_urls=[])
    assert out["success"] is False


def test_result_schema(monkeypatch) -> None:
    _patch_http(monkeypatch, {
        "https://app.example.com": {"raw_set_cookies": []},
        "https://api.example.com": {"raw_set_cookies": []},
    })

    out = cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
    )

    assert set(out.keys()) >= {
        "success", "cohort_hosts", "cookies_examined",
        "findings_emitted", "records",
    }


def test_mitre_techniques_registered() -> None:
    from strix.tools.registry import get_tool_mitre_techniques

    techniques = get_tool_mitre_techniques("cookie_jwt_scoping_check")
    assert "T1539" in techniques  # Steal Web Session Cookie
    assert "T1606.001" in techniques  # Forge Web Credentials: Web Cookies


# ---------------------------------------------------------------------------
# Auth-endpoint override
# ---------------------------------------------------------------------------


def test_auth_endpoints_override_used(monkeypatch) -> None:
    """When `auth_endpoints` is supplied, the per-host endpoint is
    GET'd instead of the bare host."""
    seen: list[str] = []

    def fake(method, url, *, headers=None, timeout=10.0):
        seen.append(url)
        return {"status": 200, "headers": {}, "raw_set_cookies": [], "body": ""}

    monkeypatch.setattr(cs_module, "_http_request", fake)

    cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
        auth_endpoints={
            "app.example.com": "https://app.example.com/login",
            "api.example.com": "https://api.example.com/auth/me",
        },
    )

    assert "https://app.example.com/login" in seen
    assert "https://api.example.com/auth/me" in seen


# ---------------------------------------------------------------------------
# Failure resilience
# ---------------------------------------------------------------------------


def test_skipped_response_does_not_crash(monkeypatch) -> None:
    def fake(method, url, *, headers=None, timeout=10.0):
        return {"status": 0, "headers": {}, "body": "", "skipped": True}

    monkeypatch.setattr(cs_module, "_http_request", fake)

    out = cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
    )

    assert out["success"] is True
    assert out["cookies_examined"] == 0


def test_error_response_recorded(monkeypatch) -> None:
    def fake(method, url, *, headers=None, timeout=10.0):
        return {"status": 0, "headers": {}, "body": "", "error": "DNS failure"}

    monkeypatch.setattr(cs_module, "_http_request", fake)

    out = cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://api.example.com"],
    )

    assert out["success"] is True
    assert "errors" in out
    assert any("DNS failure" in e for e in out["errors"])


# ---------------------------------------------------------------------------
# Multi-issue cohort
# ---------------------------------------------------------------------------


def test_full_cohort_multi_issue(monkeypatch) -> None:
    """End-to-end: parent-scoped session cookie + SameSite-inconsistent
    auth cookie + JWT cross-acceptance — all three findings emit, no
    duplicates."""
    token = _make_jwt({"sub": "alice", "aud": "app.example.com"})

    def fake(method, url, *, headers=None, timeout=10.0):
        if url == "https://app.example.com":
            return {
                "status": 200,
                "raw_set_cookies": [
                    "sessionid=abc; Domain=.example.com; HttpOnly; Secure; SameSite=Strict",
                    "auth_token=t1; Path=/; HttpOnly; Secure; SameSite=Strict",
                ],
                "body": "",
            }
        if url == "https://admin.example.com":
            return {
                "status": 200,
                "raw_set_cookies": [
                    "auth_token=t2; Path=/; HttpOnly; Secure; SameSite=Lax",
                ],
                "body": "",
            }
        if url == "https://admin.example.com/api/me":
            if headers and "authorization" in {k.lower() for k in headers}:
                return {"status": 200, "body": '{"user":"alice"}'}
            return {"status": 401, "body": '{"error":"unauthorized"}'}
        return {"status": 200, "raw_set_cookies": [], "body": ""}

    monkeypatch.setattr(cs_module, "_http_request", fake)

    out = cookie_jwt_scoping_check(
        cohort_urls=["https://app.example.com", "https://admin.example.com"],
        jwt_token=token,
        jwt_issuer_url="https://app.example.com",
        jwt_test_endpoints={
            "admin.example.com": "https://admin.example.com/api/me",
        },
    )

    assert out["success"] is True
    assert out["findings_emitted"] >= 3
    findings = _findings()
    titles = " ".join(f["title"] for f in findings)
    assert "scopes to parent domain" in titles
    assert "inconsistent SameSite" in titles
    assert "accepted at sister subdomain" in titles


# ---------------------------------------------------------------------------
# Helper-function sanity tests
# ---------------------------------------------------------------------------


def test_is_session_cookie_heuristic() -> None:
    is_session = cs_module._is_session_cookie
    assert is_session("sessionid")
    assert is_session("PHPSESSID")
    assert is_session("connect.sid")
    assert is_session("auth_token")
    assert is_session("jwt")
    assert not is_session("ga_tracking_id")
    assert not is_session("color_pref")


def test_domain_attr_covers() -> None:
    cov = cs_module._domain_attr_covers
    assert cov(".example.com", "app.example.com") is True
    assert cov("example.com", "app.example.com") is True
    assert cov("example.com", "example.com") is True
    assert cov("foo.example.com", "app.example.com") is False
    assert cov(".example.com", "app.notexample.com") is False
