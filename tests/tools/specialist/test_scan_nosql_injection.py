"""Tests for §workitem.md Phase 2.4 — `scan_nosql_injection` deterministic
NoSQL-injection specialist (CWE-943).

Pins:
  * `$ne` operator → empty baseline → populated probe → finding
  * `$regex` operator → significant length expansion → finding
  * `$in` operator → success markers → finding
  * Param inference (auth/identifier-shaped lexicon)
  * Forgiving args
  * Auth auto-injection
  * Negative cases (similar response, transport error, parse-error response)
  * SecurityContext + decision_log
  * Registry / catalog wiring
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_nosql_injection import scan_nosql_injection


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
    set_global_tracer(Tracer("test-nosqli"))
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
    out = scan_nosql_injection(url="")
    assert out["status"] == "error"


def test_no_nosql_shaped_params_returns_partial(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    out = scan_nosql_injection(url="http://example.com/api/items")
    assert out["status"] == "partial"


# ---------------------------------------------------------------------------
# $ne — baseline empty, probe populated → finding
# ---------------------------------------------------------------------------


def test_ne_operator_emits_high(monkeypatch) -> None:
    """Baseline returns []; probe (with operator) returns populated array."""
    def fake_resp(method, url, headers, body, timeout):
        if "$ne" in url or "%24ne" in url:
            return {
                "status_code": 200,
                "body": (
                    '[{"id":1,"name":"Apple Juice"},'
                    '{"id":2,"name":"Banana Juice"},'
                    '{"id":3,"name":"Orange Juice"}]'
                ),
            }
        # Baseline: nothing matches the placeholder.
        return {"status_code": 200, "body": "[]"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_nosql_injection(
        url="http://example.com/api/products?q=__strix_baseline__",
        param="q",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "nosql_injection"
    assert f["cwe"] == "CWE-943"
    assert f["severity"] == "high"


# ---------------------------------------------------------------------------
# Length expansion (legitimate baseline returned, probe much longer)
# ---------------------------------------------------------------------------


def test_significant_expansion_emits_finding(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "$regex" in url or "%24regex" in url:
            # Big payload — much longer than baseline.
            return {
                "status_code": 200,
                "body": '[' + ','.join(
                    f'{{"id":{i},"name":"Product {i}"}}' for i in range(50)
                ) + ']',
            }
        # Baseline: small, single-result response.
        return {"status_code": 200, "body": '[{"id":42,"name":"x"}]'}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_nosql_injection(
        url="http://example.com/api/products?search=foo",
        param="search",
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Success-marker detection (login-bypass class)
# ---------------------------------------------------------------------------


def test_success_marker_emits_finding(monkeypatch) -> None:
    """Probe response contains JWT/token absent from baseline."""
    def fake_resp(method, url, headers, body, timeout):
        if "$ne" in url or "%24ne" in url:
            return {
                "status_code": 200,
                "body": (
                    '{"token":"eyJ.someheader.signature",'
                    '"user":"admin","authenticated":true}'
                ),
            }
        # Baseline: 401-style empty.
        return {"status_code": 200, "body": '{"error":"not found"}'}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_nosql_injection(
        url="http://example.com/api/login?email=x@y.com",
        param="email",
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


def test_similar_response_no_finding(monkeypatch) -> None:
    """Baseline + probe responses are similar in size — no finding."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200,
        "body": '[{"id":1,"name":"x"}]',
    })
    out = scan_nosql_injection(
        url="http://example.com/api/products?q=foo",
        param="q",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_parse_error_response_no_finding(monkeypatch) -> None:
    """Probe returns an explicit parse error — server rejects operator
    syntax → no finding."""
    def fake_resp(method, url, headers, body, timeout):
        if "$ne" in url or "%24ne" in url:
            return {
                "status_code": 200,
                "body": '{"error":"syntax error in query","code":"E01"}',
            }
        return {"status_code": 200, "body": "[]"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_nosql_injection(
        url="http://example.com/api/products?q=foo", param="q",
    )
    assert len(out["findings"]) == 0


def test_transport_error_does_not_emit(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "error": "Request failed",
    })
    out = scan_nosql_injection(
        url="http://example.com/api/products?q=foo", param="q",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Param inference + forgiving args
# ---------------------------------------------------------------------------


def test_inference_picks_nosql_shaped_param(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "$ne" in url or "%24ne" in url:
            return {
                "status_code": 200,
                "body": '[' + ','.join(
                    f'{{"id":{i},"name":"User {i}"}}' for i in range(20)
                ) + ']',
            }
        return {"status_code": 200, "body": "[]"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_nosql_injection(
        url="http://example.com/api/find?username=alice&page=1",
    )
    assert len(out["findings"]) == 1
    # Should pick `username` (in lexicon), not `page`.
    assert "username" in out["findings"][0]["title"]


def test_forgiving_params_string(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    out = scan_nosql_injection(
        url="http://example.com/api/x?username=foo", params="username",
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
    record_auth_state(label="lead", bearer="ntoken")

    scan_nosql_injection(
        url="http://example.com/api/x?username=foo", param="username",
    )
    assert any(
        h.get("Authorization") == "Bearer ntoken"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_nosql_injection(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_nosql_injection(
        url="http://example.com/api/x?username=foo", param="username",
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("nosql_injection" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions,
        reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_nosql_injection(
        url="http://example.com/api/x?username=foo", param="username",
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_nosql_injection"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_nosql_injection_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_nosql_injection")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "nosql-injection-specialist"


def test_scan_nosql_injection_in_lead_web_application_catalog(monkeypatch) -> None:
    """iter-37.2 — deprecated tool; visible only under STRIX_LEGACY_CATALOG=1."""
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_nosql_injection" in catalog
