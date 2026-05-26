"""Tests for §workitem.md Phase 2.9 — `scan_subdomain_takeover_active`
(CWE-1390).

Pins:
  * AWS S3 NoSuchBucket signature → finding
  * GitHub Pages "no GitHub Pages site here" → finding
  * Heroku "no such app" → finding
  * Vercel DEPLOYMENT_NOT_FOUND → finding
  * Generic 200 OK with no signature → no finding
  * Multiple subdomains: per-URL fan-out
  * Forgiving args (urls=str / url=)
  * Transport error → no finding
  * Custom User-Agent set
  * SecurityContext + decision_log
  * Registry / catalog wiring (domain catalog)
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_subdomain_takeover_active import (
    scan_subdomain_takeover_active,
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
    set_global_tracer(Tracer("test-takeover"))
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


def test_no_urls_returns_partial() -> None:
    out = scan_subdomain_takeover_active()
    assert out["status"] == "partial"


def test_proxy_unavailable_returns_error(monkeypatch) -> None:
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: (_ for _ in ()).throw(ImportError("boom")),
    )
    out = scan_subdomain_takeover_active(url="http://docs.example.com/")
    assert out["status"] == "error"


# ---------------------------------------------------------------------------
# Per-service signatures
# ---------------------------------------------------------------------------


def test_aws_s3_nosuchbucket_emits(monkeypatch) -> None:
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Error>\n'
        '  <Code>NoSuchBucket</Code>\n'
        '  <Message>The specified bucket does not exist</Message>\n'
        '  <BucketName>old-marketing-assets</BucketName>\n'
        '</Error>\n'
    )
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 404, "body": body, "headers": {},
    })
    out = scan_subdomain_takeover_active(url="http://assets.example.com/")
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "subdomain_takeover"
    assert f["cwe"] == "CWE-1390"
    assert f["severity"] == "high"


def test_github_pages_emits(monkeypatch) -> None:
    body = (
        "<html><head><title>Site not found · GitHub Pages</title></head>"
        "<body><h1>404</h1>"
        "<p>There isn't a GitHub Pages site here.</p>"
        "</body></html>"
    )
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 404, "body": body, "headers": {},
    })
    out = scan_subdomain_takeover_active(url="http://docs.example.com/")
    assert len(out["findings"]) == 1
    assert "github_pages" in out["findings"][0]["description"]


def test_heroku_emits(monkeypatch) -> None:
    body = (
        '<html><body><h1>No such app</h1>'
        '<p>There is no app configured at that hostname.</p></body></html>'
    )
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 404, "body": body, "headers": {},
    })
    out = scan_subdomain_takeover_active(url="http://api.example.com/")
    assert len(out["findings"]) == 1


def test_vercel_emits(monkeypatch) -> None:
    body = '{"errorCode":"DEPLOYMENT_NOT_FOUND","message":"The deployment could not be found"}'
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 404, "body": body, "headers": {},
    })
    out = scan_subdomain_takeover_active(url="http://staging.example.com/")
    assert len(out["findings"]) == 1


def test_zendesk_emits(monkeypatch) -> None:
    body = "<html><body>this help center no longer exists.</body></html>"
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 404, "body": body, "headers": {},
    })
    out = scan_subdomain_takeover_active(url="http://support.example.com/")
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Negatives
# ---------------------------------------------------------------------------


def test_healthy_subdomain_no_finding(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200,
        "body": "<html><body><h1>Welcome to Acme Corp</h1></body></html>",
        "headers": {},
    })
    out = scan_subdomain_takeover_active(url="http://www.example.com/")
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_generic_404_no_finding(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 404,
        "body": "<html><body><h1>Not Found</h1></body></html>",
        "headers": {},
    })
    out = scan_subdomain_takeover_active(url="http://example.com/")
    assert len(out["findings"]) == 0


def test_transport_error_does_not_emit(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"error": "DNS resolution failed"})
    out = scan_subdomain_takeover_active(url="http://gone.example.com/")
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Forgiving args + multi-URL fan-out
# ---------------------------------------------------------------------------


def test_urls_string_is_accepted(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_subdomain_takeover_active(urls="http://example.com/")
    assert out["status"] == "ok"


def test_multi_url_finds_each(monkeypatch) -> None:
    """Three subdomains: two with takeover signatures, one healthy."""
    def fake(method, url, headers, body, timeout):
        if "assets" in url:
            return {
                "status_code": 404,
                "body": "<Code>NoSuchBucket</Code>",
                "headers": {},
            }
        if "docs" in url:
            return {
                "status_code": 404,
                "body": "There isn't a GitHub Pages site here.",
                "headers": {},
            }
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_proxy(monkeypatch, fake)
    out = scan_subdomain_takeover_active(urls=[
        "http://assets.example.com/",
        "http://docs.example.com/",
        "http://www.example.com/",
    ])
    assert len(out["findings"]) == 2


def test_dedup_one_finding_per_url(monkeypatch) -> None:
    """Body matches multiple signatures → one finding per URL (first hit wins)."""
    body = (
        "<Code>NoSuchBucket</Code> "
        "There isn't a GitHub Pages site here. "
        "No such app"
    )
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 404, "body": body, "headers": {},
    })
    out = scan_subdomain_takeover_active(url="http://example.com/")
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# User-Agent
# ---------------------------------------------------------------------------


def test_default_user_agent_set(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_proxy(monkeypatch, fake)
    scan_subdomain_takeover_active(url="http://example.com/")
    assert captured_headers[0].get("User-Agent")
    assert "strix" in captured_headers[0]["User-Agent"].lower()


def test_caller_user_agent_preserved(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_proxy(monkeypatch, fake)
    scan_subdomain_takeover_active(
        url="http://example.com/",
        extra_headers={"User-Agent": "custom-scanner/1.0"},
    )
    assert captured_headers[0]["User-Agent"] == "custom-scanner/1.0"


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
    scan_subdomain_takeover_active(url="http://example.com/")
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_subdomain_takeover_active"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_subdomain_takeover_active_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_subdomain_takeover_active")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "subdomain-takeover-specialist"


def test_scan_subdomain_takeover_active_in_lead_domain_catalog(monkeypatch) -> None:
    """iter-37.2 — deprecated tool; visible only under STRIX_LEGACY_CATALOG=1."""
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["domain"])
    assert "scan_subdomain_takeover_active" in catalog
