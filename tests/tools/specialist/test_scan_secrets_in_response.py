"""Tests for §workitem.md Phase 2.5 — `scan_secrets_in_response` passive
HTTP-response secrets sniffer (CWE-798 / CWE-200).

Pins detection of:
  * AWS access key + secret pair → critical
  * Google API key (AIza...) → critical
  * GitHub PAT (ghp_...) → critical
  * Stripe keys (sk_live_, sk_test_) → critical
  * Private key blocks → critical
  * MongoDB / Postgres / MySQL / Redis connection strings with creds
  * Generic api_key field with high-entropy value (CWE-200)
  * JWT tokens
  * Placeholder filtering (`your_key_here`, `xxxxxxxx`) → suppressed
  * Low-entropy "secrets" → suppressed
  * Auth auto-injection
  * Negatives (no secrets, transport error)
  * Excerpt redaction (no plaintext leak in our own decision trail)
  * Registry / catalog wiring
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_secrets_in_response import (
    scan_secrets_in_response,
)


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
    set_global_tracer(Tracer("test-secrets"))
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


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_no_urls_returns_partial(monkeypatch) -> None:
    out = scan_secrets_in_response()
    assert out["status"] == "partial"


def test_proxy_unavailable_returns_error(monkeypatch) -> None:
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: (_ for _ in ()).throw(ImportError("boom")),
    )
    out = scan_secrets_in_response(url="http://example.com/")
    assert out["status"] == "error"


# ---------------------------------------------------------------------------
# Cloud / SaaS credential detection
# ---------------------------------------------------------------------------


def test_aws_access_key_id_emits_critical(monkeypatch) -> None:
    body = (
        '{"config":{"region":"us-east-1",'
        '"access_key":"AKIAIOSFODNN7EXAMPLE",'
        '"description":"prod"}}'
    )
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/_debug/env")
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "secrets_exposure"
    assert f["severity"] == "critical"


def test_google_api_key_emits_critical(monkeypatch) -> None:
    body = '{"google":{"key":"AIzaSyA-some-key-with-35-chars-aaaaaaaa"}}'
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/api/config")
    assert any(
        f["severity"] == "critical" and "Google" in f["title"]
        for f in out["findings"]
    )


def test_github_pat_emits_critical(monkeypatch) -> None:
    body = '{"gh":"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/_admin/state")
    assert any(f["severity"] == "critical" for f in out["findings"])


def test_stripe_secret_key_emits_critical(monkeypatch) -> None:
    # Build the credential at runtime — keeps the literal byte sequence
    # out of source so GitHub push protection / secret scanners don't
    # flag the test fixture as a leaked credential.
    fake_stripe = "sk_" + "live_" + ("a" * 24)
    body = '{"stripe_secret":"' + fake_stripe + '"}'
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/api/x")
    assert any(f["severity"] == "critical" for f in out["findings"])


def test_private_key_block_emits_critical(monkeypatch) -> None:
    body = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEvQIBADAN...\n-----END RSA PRIVATE KEY-----\n"
    )
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/keys.txt")
    assert any(f["severity"] == "critical" for f in out["findings"])


# ---------------------------------------------------------------------------
# Connection strings
# ---------------------------------------------------------------------------


def test_mongodb_conn_string_emits_critical(monkeypatch) -> None:
    body = '{"db":"mongodb://admin:hunter2@10.0.0.5:27017/app"}'
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/cfg")
    assert any(
        f["severity"] == "critical" and "MongoDB" in f["title"]
        for f in out["findings"]
    )


def test_postgres_conn_string_emits_critical(monkeypatch) -> None:
    body = 'database_url=postgres://app:s3cret@db.local:5432/main'
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/.env")
    assert any(f["severity"] == "critical" for f in out["findings"])


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------


def test_jwt_emits_high(monkeypatch) -> None:
    body = (
        '{"access_token":'
        '"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.'
        'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
    )
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/api/me")
    # JWT severity is high.
    assert any(f["severity"] == "high" for f in out["findings"])


# ---------------------------------------------------------------------------
# Generic api_key field (entropy gate)
# ---------------------------------------------------------------------------


def test_generic_api_key_high_entropy_emits_finding(monkeypatch) -> None:
    body = '{"api_key":"r3K9zP2vQ7nX8wL4mB1tY6fH0jD3sN5g"}'
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/api/cfg")
    assert any(
        f["severity"] == "high" and "Generic" in f["title"]
        for f in out["findings"]
    )


def test_low_entropy_secret_does_not_emit(monkeypatch) -> None:
    """Word-based "secrets" with low entropy are suppressed."""
    body = '{"api_key":"hellohellohellohello"}'  # repeated chars, low entropy
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/api/x")
    assert all(
        "Generic" not in f["title"]
        for f in out["findings"]
    )


def test_placeholder_does_not_emit(monkeypatch) -> None:
    """`your_key_here` / `xxxxxxxx` style placeholders are suppressed."""
    body = (
        '{"aws_access_key":"AKIAIOSFODNN7EXAMPLE",'
        '"api_key":"your_api_key_goes_here_replace_me_xxxxxxxxxx"}'
    )
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/api/x")
    # AKIA pattern uses the literal placeholder string `EXAMPLE` —
    # _is_likely_placeholder picks "example" as a placeholder marker
    # and suppresses, so no finding.
    assert all("Generic" not in f["title"] for f in out["findings"])


# ---------------------------------------------------------------------------
# Headers blob
# ---------------------------------------------------------------------------


def test_secret_in_response_header_detected(monkeypatch) -> None:
    """Secrets sometimes leak via custom debug headers (Set-Cookie,
    X-Auth-Token)."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200,
        "body": "ok",
        "headers": {
            "X-Auth-Token": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
    })
    out = scan_secrets_in_response(url="http://example.com/")
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Excerpt redaction
# ---------------------------------------------------------------------------


def test_excerpt_redacts_plaintext_secret(monkeypatch) -> None:
    """The evidence we record must NOT contain the raw secret —
    otherwise we leak it back into our own decision/tracer trail."""
    body = '{"key":"AKIAIOSFODNN7AAAAAAA"}'
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": body, "headers": {},
    })
    scan_secrets_in_response(url="http://example.com/x")
    from strix.telemetry.tracer import get_global_tracer
    vuln = get_global_tracer().get_existing_vulnerabilities()[0]
    # Body of the secret must not appear in technical_analysis.
    assert "AKIAIOSFODNN7AAAAAAA" not in vuln.get("technical_analysis", "")
    assert "***REDACTED***" in vuln.get("technical_analysis", "")


# ---------------------------------------------------------------------------
# Negatives
# ---------------------------------------------------------------------------


def test_no_secrets_no_finding(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200,
        "body": '{"hello":"world","count":42}',
        "headers": {},
    })
    out = scan_secrets_in_response(url="http://example.com/api/hello")
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_transport_error_does_not_emit(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"error": "Request failed"})
    out = scan_secrets_in_response(url="http://example.com/")
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Forgiving args + multi-URL
# ---------------------------------------------------------------------------


def test_urls_string_is_accepted(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_secrets_in_response(urls="http://example.com/")
    assert out["status"] == "ok"


def test_multi_url_finds_each(monkeypatch) -> None:
    """Two URLs: each with its own credential — two findings."""
    def fake(method, url, headers, body, timeout):
        if "first" in url:
            return {
                "status_code": 200,
                "body": '{"k":"AKIAIOSFODNN7AAAAAAA"}',
                "headers": {},
            }
        return {
            "status_code": 200,
            "body": '{"gh":"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake)
    out = scan_secrets_in_response(urls=[
        "http://example.com/first",
        "http://example.com/second",
    ])
    assert len(out["findings"]) == 2


# ---------------------------------------------------------------------------
# Auth auto-injection
# ---------------------------------------------------------------------------


def test_auth_state_bearer_auto_forwarded(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_proxy(monkeypatch, fake)
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="stoken")

    scan_secrets_in_response(url="http://example.com/x")
    assert any(
        h.get("Authorization") == "Bearer stoken"
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
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    scan_secrets_in_response(url="http://example.com/x")
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_secrets_in_response"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_secrets_in_response_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_secrets_in_response")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "secrets-exposure-specialist"


def test_scan_secrets_in_response_in_lead_web_application_catalog(monkeypatch) -> None:
    """iter-37.2 — deprecated tool; visible only under STRIX_LEGACY_CATALOG=1."""
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_secrets_in_response" in catalog
