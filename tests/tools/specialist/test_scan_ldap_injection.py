"""Tests for §workitem.md Phase 2.8 — `scan_ldap_injection` (CWE-90).

Pins:
  * Wildcard close — auth bypass → finding
  * LDAPException leak in 5xx → finding
  * `cn=`/`dn=` markers in probe → finding
  * Negative cases (similar response, transport error)
  * Param inference + forgiving args
  * Auth auto-injection
  * SecurityContext + decision_log
  * Registry / catalog wiring
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_ldap_injection import scan_ldap_injection


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
    set_global_tracer(Tracer("test-ldapi"))
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


def test_empty_url_returns_error() -> None:
    out = scan_ldap_injection(url="")
    assert out["status"] == "error"


def test_no_ldap_shaped_params_returns_partial(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    out = scan_ldap_injection(url="http://example.com/api/items")
    assert out["status"] == "partial"


def test_wildcard_close_emits_high(monkeypatch) -> None:
    """Wildcard close payload bypasses auth — baseline 401, probe 200."""
    def fake_resp(method, url, headers, body, timeout):
        if ("*" in url or "%2A" in url.upper()) and ("uid" in url or "objectClass" in url):
            return {
                "status_code": 200,
                "body": (
                    '{"users":[{"cn":"Alice","dn":"cn=alice,ou=people"},'
                    '{"cn":"Bob","dn":"cn=bob,ou=people"},'
                    '{"cn":"admin","dn":"cn=admin,ou=people"}]}'
                ),
            }
        return {"status_code": 401, "body": '{"error":"invalid credentials"}'}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ldap_injection(
        url="http://example.com/api/login?username=guest", param="username",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "ldap_injection"
    assert f["cwe"] == "CWE-90"


def test_ldap_exception_leak_emits(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if ("*" in url or "%2A" in url.upper()) and ("uid" in url or "objectClass" in url):
            return {
                "status_code": 500,
                "body": (
                    "javax.naming.NamingException: "
                    "[LDAP: error code 32 - No Such Object]: "
                    "remaining: '*)(uid=*'"
                ),
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ldap_injection(
        url="http://example.com/api/find?username=x", param="username",
    )
    assert len(out["findings"]) == 1


def test_similar_response_no_finding(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 401, "body": '{"error":"invalid"}',
    })
    out = scan_ldap_injection(
        url="http://example.com/api/login?username=x", param="username",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_transport_error_does_not_emit(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"error": "Request failed"})
    out = scan_ldap_injection(
        url="http://example.com/api/login?username=x", param="username",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_inference_picks_ldap_shaped_param(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "*" in url or "%2A" in url.upper():
            return {
                "status_code": 200,
                "body": '{"results":[' + ",".join(
                    f'{{"cn":"u{i}","dn":"cn=u{i},ou=p"}}' for i in range(20)
                ) + ']}',
            }
        return {"status_code": 401, "body": '{"error":"invalid"}'}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ldap_injection(
        url="http://example.com/api/find?username=x&page=1",
    )
    assert len(out["findings"]) == 1
    assert "username" in out["findings"][0]["title"]


def test_forgiving_params_string(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 401, "body": "no"})
    out = scan_ldap_injection(
        url="http://example.com/api/login?username=x", params="username",
    )
    assert out["status"] == "ok"


def test_auth_state_bearer_auto_forwarded(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="ltok")

    scan_ldap_injection(
        url="http://example.com/api/find?username=x", param="username",
    )
    assert any(
        h.get("Authorization") == "Bearer ltok"
        for h in captured_headers
    )


def test_records_endpoint_probed_for_ldap_injection(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_ldap_injection(
        url="http://example.com/api/find?username=x", param="username",
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("ldap_injection" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_ldap_injection(
        url="http://example.com/api/find?username=x", param="username",
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_ldap_injection"
        for d in decisions
    )


def test_scan_ldap_injection_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_ldap_injection")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "ldap-injection-specialist"


def test_scan_ldap_injection_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_ldap_injection" in catalog
