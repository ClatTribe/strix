"""Tests for §workitem.md Phase 2.11 — `scan_oauth` (OAuth 2.0 / OIDC
misconfiguration).

Pins:
  * Discovery via .well-known/openid-configuration
  * state-not-enforced → high finding (CWE-352)
  * PKCE-not-enforced → high finding (CWE-602)
  * redirect_uri loose-match → high finding (CWE-601)
  * Implicit-flow supported → medium finding (CWE-922)
  * Discovery failure → status=partial
  * Auth auto-injection
  * SecurityContext + decision_log
  * Registry / catalog wiring
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_oauth import scan_oauth


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path) -> None:
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-oauth"))
    yield


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


def _patch_proxy(monkeypatch, response_for_url):
    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=response_for_url)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: fake,
    )
    return fake


def _discovery_doc(
    *,
    response_types: list[str] | None = None,
    auth_endpoint: str = "https://op.example.com/oauth/authorize",
) -> str:
    """Build a minimal but valid OIDC discovery doc."""
    return json.dumps({
        "issuer": "https://op.example.com",
        "authorization_endpoint": auth_endpoint,
        "token_endpoint": "https://op.example.com/oauth/token",
        "response_types_supported": response_types or ["code"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": ["openid", "profile", "email"],
    })


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_oauth(url="")
    assert out["status"] == "error"


def test_invalid_url_returns_error() -> None:
    out = scan_oauth(url="not-a-url")
    assert out["status"] == "error"


def test_discovery_failure_returns_partial(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 404, "body": "not found", "headers": {},
    })
    out = scan_oauth(url="http://op.example.com/")
    assert out["status"] == "partial"


# ---------------------------------------------------------------------------
# state not enforced
# ---------------------------------------------------------------------------


def test_state_not_enforced_emits_high(monkeypatch) -> None:
    """Discovery succeeds; auth endpoint accepts request without state → 200."""
    def fake_resp(method, url, headers, body, timeout):
        if "openid-configuration" in url:
            return {
                "status_code": 200, "body": _discovery_doc(), "headers": {},
            }
        # Auth endpoint always returns 200 (state not enforced).
        # PKCE probe also returns 200 (no enforcement) — the test
        # accepts that the harness will emit two findings.
        return {"status_code": 200, "body": "<login form>", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_oauth(url="http://op.example.com/", client_id="webapp")
    assert out["status"] == "ok"
    titles = [f["title"] for f in out["findings"]]
    assert any("state" in t.lower() for t in titles)


def test_state_enforced_no_finding(monkeypatch) -> None:
    """Server returns 400 'missing state' → state IS enforced (no finding)."""
    def fake_resp(method, url, headers, body, timeout):
        if "openid-configuration" in url:
            return {"status_code": 200, "body": _discovery_doc(), "headers": {}}
        # Probe without state → server rejects.
        if "state=" not in url:
            return {
                "status_code": 400,
                "body": '{"error":"invalid_request","error_description":"Missing state parameter"}',
                "headers": {},
            }
        # Probe with state → server accepts.
        return {"status_code": 200, "body": "<login form>", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_oauth(url="http://op.example.com/", client_id="webapp")
    titles = [f["title"] for f in out["findings"]]
    assert not any("state" in t.lower() and "not enforced" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# PKCE not enforced
# ---------------------------------------------------------------------------


def test_pkce_not_enforced_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "openid-configuration" in url:
            return {"status_code": 200, "body": _discovery_doc(), "headers": {}}
        # Server accepts both probes.
        return {"status_code": 200, "body": "<login form>", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_oauth(url="http://op.example.com/", client_id="webapp")
    titles = [f["title"] for f in out["findings"]]
    assert any("pkce" in t.lower() for t in titles)


def test_pkce_enforced_no_finding(monkeypatch) -> None:
    """Server returns 400 with `code_challenge` mention → PKCE enforced."""
    def fake_resp(method, url, headers, body, timeout):
        if "openid-configuration" in url:
            return {"status_code": 200, "body": _discovery_doc(), "headers": {}}
        if "code_challenge" not in url:
            return {
                "status_code": 400,
                "body": '{"error":"invalid_request","error_description":"code_challenge is required"}',
                "headers": {},
            }
        return {"status_code": 200, "body": "<login>", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_oauth(url="http://op.example.com/", client_id="webapp")
    titles = [f["title"] for f in out["findings"]]
    assert not any("pkce" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# Redirect URI loose match
# ---------------------------------------------------------------------------


def test_redirect_uri_loose_match_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "openid-configuration" in url:
            return {"status_code": 200, "body": _discovery_doc(), "headers": {}}
        # Tampered redirect_uri probe contains "attacker.com" — the
        # server 302s to it (very bad).
        if "attacker.com" in url:
            return {
                "status_code": 302, "body": "",
                "headers": {"Location": "https://op.example.com.attacker.com/cb?code=ABC"},
            }
        return {"status_code": 400, "body": "rejected", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_oauth(
        url="http://op.example.com/",
        client_id="webapp",
        redirect_uri="https://app.example.com/cb",
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("redirect_uri" in t.lower() for t in titles)


def test_redirect_uri_strict_match_no_finding(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "openid-configuration" in url:
            return {"status_code": 200, "body": _discovery_doc(), "headers": {}}
        if "attacker.com" in url:
            return {
                "status_code": 400,
                "body": '{"error":"invalid_request","error_description":"redirect_uri mismatch"}',
                "headers": {},
            }
        return {"status_code": 400, "body": "rejected", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_oauth(
        url="http://op.example.com/",
        client_id="webapp",
        redirect_uri="https://app.example.com/cb",
    )
    titles = [f["title"] for f in out["findings"]]
    assert not any("redirect_uri" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# Implicit flow
# ---------------------------------------------------------------------------


def test_implicit_flow_supported_emits_medium(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "openid-configuration" in url:
            return {
                "status_code": 200,
                "body": _discovery_doc(response_types=["code", "token", "id_token token"]),
                "headers": {},
            }
        return {"status_code": 400, "body": "rejected", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_oauth(url="http://op.example.com/", client_id="webapp")
    titles = [f["title"] for f in out["findings"]]
    assert any("implicit" in t.lower() for t in titles)


def test_code_only_flow_no_implicit_finding(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "openid-configuration" in url:
            return {
                "status_code": 200,
                "body": _discovery_doc(response_types=["code"]),
                "headers": {},
            }
        return {"status_code": 400, "body": "rejected", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_oauth(url="http://op.example.com/", client_id="webapp")
    titles = [f["title"] for f in out["findings"]]
    assert not any("implicit" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# Auth auto-injection
# ---------------------------------------------------------------------------


def test_auth_state_bearer_auto_forwarded(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        if "openid-configuration" in url:
            return {"status_code": 200, "body": _discovery_doc(), "headers": {}}
        return {"status_code": 400, "body": "no", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="otok")

    scan_oauth(url="http://op.example.com/")
    assert any(
        h.get("Authorization") == "Bearer otok"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# Decision log
# ---------------------------------------------------------------------------


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda method, url, headers, body, timeout: (
        {"status_code": 200, "body": _discovery_doc(), "headers": {}}
        if "openid-configuration" in url
        else {"status_code": 400, "body": "rejected", "headers": {}}
    ))
    scan_oauth(url="http://op.example.com/", client_id="webapp")
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_oauth"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_oauth_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_oauth")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "oauth-specialist"


def test_scan_oauth_in_lead_web_application_catalog(monkeypatch) -> None:
    """iter-37.2 — deprecated tool; visible only under STRIX_LEGACY_CATALOG=1."""
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_oauth" in catalog
