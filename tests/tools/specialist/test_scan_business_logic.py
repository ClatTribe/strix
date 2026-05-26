"""Tests for §workitem.md Phase 5.6 — `scan_business_logic` (A04:2021).

Pins:
  * Price-tampering (negative / zero) accepted → critical CWE-840
  * Role-tampering (admin) accepted → critical CWE-269
  * Quantity-tampering (negative) → high CWE-682
  * Workflow-skip on /checkout/complete with empty body → high CWE-841
  * Param-pollution role=user&role=admin admits admin → critical CWE-235
  * No candidate body fields + no finalizer URL → status=partial
  * Defensive: empty url → error
  * Auth auto-injection
  * SecurityContext + decision_log
  * Registry / catalog wiring
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_business_logic import (
    _build_polluted_url,
    _has_success_marker,
    _is_finalization_url,
    scan_business_logic,
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
    set_global_tracer(Tracer("test-bizlogic"))
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
# Helpers
# ---------------------------------------------------------------------------


def test_has_success_marker_positive() -> None:
    assert _has_success_marker(
        '{"order_id":"ORD-123","status":"completed"}'
    )


def test_has_success_marker_negative() -> None:
    assert not _has_success_marker(
        '{"error":"validation failed","code":"E0102"}'
    )


def test_is_finalization_url() -> None:
    assert _is_finalization_url("http://shop.test/checkout/complete")
    assert _is_finalization_url("http://shop.test/payment/confirm")
    assert _is_finalization_url("http://api.test/api/orders/finalize")
    assert not _is_finalization_url("http://shop.test/products")


def test_build_polluted_url() -> None:
    url = _build_polluted_url(
        "http://example.com/api?role=user", "role", ["user", "admin"],
    )
    assert "role=user" in url
    assert "role=admin" in url
    assert url.count("role=") == 2


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_business_logic(url="")
    assert out["status"] == "error"


def test_no_candidate_fields_no_finalizer_returns_partial(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    # Body has no price/quantity/role fields; URL isn't a finalizer
    # and has no role params.
    out = scan_business_logic(
        url="http://example.com/api/items",
        body_template={"name": "widget", "color": "blue"},
    )
    assert out["status"] == "partial"


# ---------------------------------------------------------------------------
# Price tampering
# ---------------------------------------------------------------------------


def test_price_tampering_negative_accepted_emits_critical(monkeypatch) -> None:
    """Server accepts negative-price purchase → critical CWE-840."""
    def fake_resp(method, url, headers, body, timeout):
        # Always returns success-shape — server doesn't validate.
        return {
            "status_code": 200,
            "body": '{"order_id":"ORD-42","status":"completed",'
                    '"total":-10}',
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_business_logic(
        url="http://shop.test/cart/checkout",
        body_template={"product_id": 1, "price": 100, "quantity": 1},
        enabled_families=["price_tampering"],
    )
    assert out["status"] == "ok"
    cats = [f["category"] for f in out["findings"]]
    assert "business_logic" in cats
    sevs = [f["severity"] for f in out["findings"]]
    assert "critical" in sevs


def test_price_validation_enforced_no_finding(monkeypatch) -> None:
    """Server rejects negative price → no finding."""
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 400,
            "body": '{"error":"price must be positive"}',
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_business_logic(
        url="http://shop.test/cart/checkout",
        body_template={"product_id": 1, "price": 100},
        enabled_families=["price_tampering"],
    )
    # No findings — server validates.
    assert all(f["category"] != "business_logic" for f in out["findings"])


# ---------------------------------------------------------------------------
# Role tampering
# ---------------------------------------------------------------------------


def test_role_tampering_admin_accepted_emits_critical(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        # Server echoes back role=admin in success.
        return {
            "status_code": 200,
            "body": '{"order_id":"x","status":"success",'
                    '"role":"admin","is_admin":true}',
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_business_logic(
        url="http://app.test/api/users/create",
        body_template={"email": "u@x.com", "role": "user"},
        enabled_families=["role_tampering"],
    )
    sevs = [f["severity"] for f in out["findings"]]
    assert "critical" in sevs


# ---------------------------------------------------------------------------
# Quantity tampering
# ---------------------------------------------------------------------------


def test_quantity_negative_accepted_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 200,
            "body": '{"order_id":"ORD-99","status":"completed",'
                    '"quantity":-5}',
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_business_logic(
        url="http://shop.test/cart/checkout",
        body_template={"product_id": 1, "quantity": 1},
        enabled_families=["quantity_tampering"],
    )
    assert any(
        f["category"] == "business_logic" and f["severity"] in {"high", "medium"}
        for f in out["findings"]
    )


# ---------------------------------------------------------------------------
# Workflow skip
# ---------------------------------------------------------------------------


def test_workflow_skip_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        # Empty-body POST to /checkout/complete returns success.
        return {
            "status_code": 200,
            "body": '{"order_id":"ORD-77","status":"completed"}',
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_business_logic(
        url="http://shop.test/checkout/complete",
        enabled_families=["workflow_skip"],
    )
    assert any(
        "workflow_skip" in f["title"].lower() or
        "workflow skip" in f["title"].lower()
        for f in out["findings"]
    )
    sevs = [f["severity"] for f in out["findings"]]
    assert "high" in sevs


def test_workflow_skip_rejected_no_finding(monkeypatch) -> None:
    """Server rejects empty-body finalize → no finding."""
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 400,
            "body": '{"error":"cart is empty"}',
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_business_logic(
        url="http://shop.test/checkout/complete",
        enabled_families=["workflow_skip"],
    )
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Param pollution
# ---------------------------------------------------------------------------


def test_param_pollution_admin_emits_critical(monkeypatch) -> None:
    """role=user&role=admin → server returns admin context."""
    def fake_resp(method, url, headers, body, timeout):
        if "role=admin" in url:
            return {
                "status_code": 200,
                "body": '{"role":"admin","permissions":["all"]}',
                "headers": {},
            }
        return {"status_code": 200, "body": '{"role":"user"}', "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_business_logic(
        url="http://app.test/api/profile?role=user",
        enabled_families=["param_pollution"],
    )
    sevs = [f["severity"] for f in out["findings"]]
    assert "critical" in sevs


# ---------------------------------------------------------------------------
# Auth auto-injection
# ---------------------------------------------------------------------------


def test_auth_state_bearer_auto_forwarded(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="bltok")

    scan_business_logic(
        url="http://shop.test/checkout/complete",
        enabled_families=["workflow_skip"],
    )
    assert any(
        h.get("Authorization") == "Bearer bltok"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_business_logic(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": '{"order_id":"x"}', "headers": {},
    })
    scan_business_logic(
        url="http://shop.test/cart/checkout",
        body_template={"price": 10},
        enabled_families=["price_tampering"],
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("business_logic" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": '{"order_id":"x"}', "headers": {},
    })
    scan_business_logic(
        url="http://shop.test/cart/checkout",
        body_template={"price": 10},
        enabled_families=["price_tampering"],
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_business_logic"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_business_logic_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_business_logic")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "business-logic-specialist"


def test_scan_business_logic_in_lead_web_application_catalog(monkeypatch) -> None:
    """iter-37.2 — deprecated tool; visible only under STRIX_LEGACY_CATALOG=1."""
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_business_logic" in catalog
