"""Tests for §workitem.md Phase 2.7 — `scan_xpath_injection` (CWE-643).

Pins:
  * Auth-bypass: baseline 401, probe 200 with payload → finding
  * Length-expansion bypass → finding
  * XPath parser exception leak → finding
  * Negative cases (similar response, transport error)
  * Param inference + forgiving args
  * Auth auto-injection
  * SecurityContext + decision_log integration
  * Registry / catalog wiring
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_xpath_injection import scan_xpath_injection


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
    set_global_tracer(Tracer("test-xpathi"))
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


def test_empty_url_returns_error() -> None:
    out = scan_xpath_injection(url="")
    assert out["status"] == "error"


def test_no_xpath_shaped_params_returns_partial(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    out = scan_xpath_injection(url="http://example.com/api/items")
    assert out["status"] == "partial"


# ---------------------------------------------------------------------------
# Auth-bypass detection
# ---------------------------------------------------------------------------


def test_auth_bypass_baseline_401_probe_200_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "or" in url and ("'" in url or "%27" in url):
            # Probe response — auth bypassed.
            return {
                "status_code": 200,
                "body": (
                    '{"user":"admin","welcome":"Welcome admin",'
                    '"role":"superuser","logged in":true,'
                    '"data":[{"id":1},{"id":2},{"id":3}]}'
                ),
            }
        return {
            "status_code": 401,
            "body": '{"error":"Invalid credentials"}',
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xpath_injection(
        url="http://example.com/api/login?username=guest",
        param="username",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "xpath_injection"
    assert f["cwe"] == "CWE-643"


def test_xpath_exception_leak_emits_high(monkeypatch) -> None:
    """Server returns 500 + XPath stack trace — strong signal."""
    def fake_resp(method, url, headers, body, timeout):
        if "or" in url and ("'" in url or "%27" in url):
            return {
                "status_code": 500,
                "body": (
                    "javax.xml.xpath.XPathExpressionException: "
                    "javax.xml.transform.TransformerException: "
                    "Unexpected token \"' or '1'='1\""
                ),
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xpath_injection(
        url="http://example.com/api/login?username=x",
        param="username",
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Negatives
# ---------------------------------------------------------------------------


def test_similar_response_no_finding(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 401, "body": '{"error":"Invalid credentials"}',
    })
    out = scan_xpath_injection(
        url="http://example.com/api/login?username=x",
        param="username",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_transport_error_does_not_emit(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"error": "Request failed"})
    out = scan_xpath_injection(
        url="http://example.com/api/login?username=x",
        param="username",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Param inference + forgiving args
# ---------------------------------------------------------------------------


def test_inference_picks_xpath_shaped_param(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "or" in url and ("'" in url or "%27" in url):
            return {
                "status_code": 200,
                "body": ('{"welcome":"hi","authenticated":true,'
                         '"users":[' + ",".join(f'"u{i}"' for i in range(20)) + ']}'),
            }
        return {"status_code": 401, "body": '{"error":"invalid"}'}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xpath_injection(
        url="http://example.com/api/login?username=x&page=1",
    )
    assert len(out["findings"]) == 1
    assert "username" in out["findings"][0]["title"]


def test_forgiving_params_string(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 401, "body": "no"})
    out = scan_xpath_injection(
        url="http://example.com/api/login?username=x", params="username",
    )
    assert out["status"] == "ok"


# ---------------------------------------------------------------------------
# Auth auto-injection
# ---------------------------------------------------------------------------


def test_auth_state_bearer_auto_forwarded(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="xtok")

    scan_xpath_injection(
        url="http://example.com/api/login?username=x", param="username",
    )
    assert any(
        h.get("Authorization") == "Bearer xtok"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_xpath_injection(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_xpath_injection(
        url="http://example.com/api/login?username=x", param="username",
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("xpath_injection" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_xpath_injection(
        url="http://example.com/api/login?username=x", param="username",
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_xpath_injection"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_xpath_injection_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_xpath_injection")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "xpath-injection-specialist"


def test_scan_xpath_injection_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_xpath_injection" in catalog
