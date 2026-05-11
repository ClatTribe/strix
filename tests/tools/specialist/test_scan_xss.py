"""Tests for §8.5 Phase 3b — `scan_xss` deterministic specialist.

Pins the reflection-detection logic and the auto-emit-via-tracer
behaviour. HTTP probes are mocked at the proxy_manager layer so
tests are hermetic.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_xss import scan_xss


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path) -> None:
    """Run each test against a fresh in-memory tracer + suppress
    network."""
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-xss"))
    yield


def _patch_proxy(monkeypatch, response_for_url):
    """Patch `get_proxy_manager().send_simple_request` to return a
    canned response based on the (method, url) pair. `response_for_url`
    is a callable `(method, url, headers, body, timeout) -> dict`."""
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


def test_empty_url_returns_error() -> None:
    out = scan_xss(url="", params=["q"])
    assert out["status"] == "error"


def test_no_params_no_query_string_returns_partial() -> None:
    out = scan_xss(url="http://example.com/", params=None)
    assert out["status"] == "partial"


def test_no_params_uses_existing_query_string(monkeypatch) -> None:
    """When params are missing but URL has a query string, those keys
    are probed."""
    captured: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        captured.append(url)
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/search?q=hello&p=world")
    assert out["status"] == "ok"
    # Both q and p should have been probed.
    probed = " ".join(captured)
    assert "q=" in probed
    assert "p=" in probed


# ---------------------------------------------------------------------------
# Reflection detection — positive
# ---------------------------------------------------------------------------


def test_unescaped_reflection_triggers_finding(monkeypatch) -> None:
    """Server reflects payload verbatim → scan_xss emits a finding."""
    def fake_resp(method, url, headers, body, timeout):
        # Echo the raw query value back into the HTML body unescaped.
        # Extract the q parameter value from the URL.
        from urllib.parse import urlparse, parse_qs

        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        return {
            "status_code": 200,
            "body": f"<html><body>You searched for: {q}</body></html>",
            "headers": {"content-type": "text/html"},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/search.aspx", params=["q"])

    assert out["status"] == "ok"
    # At least one finding emitted (canary varies per probe so dedup
    # only keeps one per param).
    assert len(out["findings"]) >= 1
    # Auto-emit happened: tracer has the finding too.
    from strix.telemetry.tracer import get_global_tracer

    tracer_findings = get_global_tracer().get_existing_vulnerabilities()
    assert len(tracer_findings) >= 1
    assert tracer_findings[0]["category"] == "xss"
    assert tracer_findings[0]["cwe"] == "CWE-79"
    assert tracer_findings[0]["severity"] == "medium"


def test_finding_contains_evidence_excerpt(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        from urllib.parse import urlparse, parse_qs

        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        return {
            "status_code": 200,
            "body": f"<html>echo: {q} more text after</html>",
        }

    _patch_proxy(monkeypatch, fake_resp)
    scan_xss(url="http://example.com/search", params=["q"])

    from strix.telemetry.tracer import get_global_tracer

    f = get_global_tracer().get_existing_vulnerabilities()[0]
    # Evidence excerpt should appear in technical_analysis.
    assert "STRIX" in f["technical_analysis"]


def test_finding_includes_poc_curl_command(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        from urllib.parse import urlparse, parse_qs

        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        return {"status_code": 200, "body": f"<div>{q}</div>"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_xss(url="http://example.com/search", params=["q"])

    from strix.telemetry.tracer import get_global_tracer

    f = get_global_tracer().get_existing_vulnerabilities()[0]
    assert "curl" in f["poc_script_code"]


# ---------------------------------------------------------------------------
# Reflection detection — negative
# ---------------------------------------------------------------------------


def test_html_escaped_reflection_does_not_trigger(monkeypatch) -> None:
    """Server HTML-escapes the payload → no finding."""
    def fake_resp(method, url, headers, body, timeout):
        from urllib.parse import urlparse, parse_qs

        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        # Escape <
        escaped = q.replace("<", "&lt;").replace(">", "&gt;")
        return {
            "status_code": 200,
            "body": f"<html>You searched for: {escaped}</html>",
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/search", params=["q"])

    assert out["status"] == "ok"
    assert len(out["findings"]) == 0
    from strix.telemetry.tracer import get_global_tracer

    assert len(get_global_tracer().get_existing_vulnerabilities()) == 0


def test_canary_not_in_response_does_not_trigger(monkeypatch) -> None:
    """Server returns a generic page that doesn't echo the payload
    → no finding (no reflection at all)."""
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 200, "body": "<html>generic page</html>"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/", params=["q"])
    assert len(out["findings"]) == 0


def test_url_encoded_reflection_does_not_trigger(monkeypatch) -> None:
    """Server URL-encodes the payload → no finding."""
    def fake_resp(method, url, headers, body, timeout):
        from urllib.parse import urlparse, parse_qs, quote

        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        return {
            "status_code": 200,
            "body": f"<html>echo: {quote(q)}</html>",
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/search", params=["q"])
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# De-duplication
# ---------------------------------------------------------------------------


def test_only_one_finding_per_endpoint_param(monkeypatch) -> None:
    """Three payloads tried per param; the first to reflect emits.
    Subsequent reflections on the SAME (path, param) are skipped."""
    def fake_resp(method, url, headers, body, timeout):
        from urllib.parse import urlparse, parse_qs

        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        return {"status_code": 200, "body": f"<div>{q}</div>"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/search", params=["q"])
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Transport errors
# ---------------------------------------------------------------------------


def test_transport_error_does_not_emit(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {"error": "Request failed: ConnectionError", "url": url}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(url="http://example.com/search", params=["q"])
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0
    assert any("transport error" in e for e in out["evidence"])


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_xss_registered_in_specialist_registry() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_xss")
    assert desc is not None
    # Phase 3b — scan_xss now routes through the inner-LLM
    # adaptive-retry orchestrator. Kill switch:
    # STRIX_SPECIALIST_INNER_LLM_DISABLED=1.
    assert desc.llm is True
    assert desc.system_prompt_path == "tools/specialist/prompts/xss.md"
    assert desc.category == "xss-specialist"


def test_scan_xss_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_xss" in catalog


# ---------------------------------------------------------------------------
# Phase 3c — protocol-aware probing (POST + JSON body, path params)
# ---------------------------------------------------------------------------


def test_post_json_body_xss_detection(monkeypatch) -> None:
    """Reflected XSS via a JSON-body API that echoes the payload
    back into an HTML response (e.g. an error page that renders the
    input verbatim)."""
    captured: list[dict[str, Any]] = []

    def fake_resp(method, url, headers, body, timeout):
        import json
        captured.append({"method": method, "headers": dict(headers), "body": body})
        try:
            data = json.loads(body)
            q = data.get("query", "")
        except Exception:
            q = ""
        # Server reflects query back into HTML (unsanitized).
        return {
            "status_code": 200,
            "body": f"<html><body>You searched for: {q}</body></html>",
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(
        url="http://example.com/api/search",
        method="POST",
        params=["query"],
        body_template={"query": "test", "limit": 10},
    )

    assert out["status"] == "ok"
    assert len(out["findings"]) >= 1
    # The probe was a POST with JSON content-type.
    assert all(r["method"] == "POST" for r in captured)
    assert all(r["headers"].get("Content-Type") == "application/json"
               for r in captured)


def test_path_param_xss_detection(monkeypatch) -> None:
    """XSS via path parameter — e.g. `/users/{name}` reflecting
    `name` into the response."""
    def fake_resp(method, url, headers, body, timeout):
        # Extract the last path segment as `name`.
        from urllib.parse import urlparse, unquote
        name = unquote(urlparse(url).path.rsplit("/", 1)[-1])
        return {
            "status_code": 200,
            "body": f"<html>Hello, {name}</html>",
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(
        url="http://example.com/users/{name}",
        method="GET",
        params=["name"],
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) >= 1


def test_xss_params_inferred_from_body_template(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xss(
        url="http://example.com/api",
        method="POST",
        body_template={"q": "test", "context": "user"},
    )
    # No findings (server doesn't reflect), but status=ok means
    # both keys were probed without error.
    assert out["status"] == "ok"
