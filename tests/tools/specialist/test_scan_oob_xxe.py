"""Tests for §workitem.md Phase 4.2 — `scan_oob_xxe` (blind XXE / CWE-611).

Pins:
  * Param-entity payload triggers OOB callback → finding
  * External-DTD payload triggers OOB callback → finding
  * OOB hit from source IP → critical severity
  * OOB unavailable → status=partial with helpful error
  * Defensive: empty url → error
  * Auth auto-injection
  * Content-Type defaults to application/xml; caller can override
  * SecurityContext + decision_log
  * Registry / catalog wiring
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_oob_xxe import (
    _build_external_dtd_payload,
    _build_param_entity_payload,
    scan_oob_xxe,
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
    set_global_tracer(Tracer("test-oob-xxe"))
    yield


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


@pytest.fixture(autouse=True)
def _reset_oob() -> None:
    """Default: OOB enabled (mocked) so tests can exercise the OOB
    path without binding real ports. Each test patches as needed."""
    import os

    from strix.tools.oob.service import reset_oob_service

    reset_oob_service()
    os.environ["STRIX_OOB_BACKEND"] = "disabled"
    yield
    reset_oob_service()
    os.environ.pop("STRIX_OOB_BACKEND", None)


def _patch_proxy(monkeypatch, response_for_url):
    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=response_for_url)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: fake,
    )
    return fake


@dataclass
class _Cb:
    token: str = "strixDEADBEEF"
    callback_url: str = "http://oob.test/strixDEADBEEF"
    expires_at: str = "2099-01-01T00:00:00+00:00"
    backend_name: str = "local"


def _patch_oob(monkeypatch, *, available: bool, hit: bool,
               source_ip: str = "10.0.0.5",
               raw_request: dict | None = None):
    """Patch the OOB module bindings inside scan_oob_xxe."""
    monkeypatch.setattr(
        "strix.tools.specialist.scan_oob_xxe.oob_is_available"
        if False else "strix.tools.oob.is_available",
        lambda: available,
    )

    def _register(*args, **kw):
        if available:
            return _Cb()
        return None

    monkeypatch.setattr(
        "strix.tools.oob.register_callback",
        _register,
    )

    def _poll(token, *, timeout_seconds=10.0):
        if hit:
            return {
                "hit": True,
                "source_ip": source_ip,
                "raw_request": raw_request or {"method": "GET", "path": f"/{token}"},
            }
        return {"hit": False, "source_ip": None, "raw_request": None}

    monkeypatch.setattr(
        "strix.tools.oob.poll_callback",
        _poll,
    )
    monkeypatch.setattr(
        "strix.tools.oob.backend_name",
        lambda: "local" if available else "disabled",
    )


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def test_param_entity_payload_shape() -> None:
    payload = _build_param_entity_payload("http://oob.test/abc")
    assert "<!DOCTYPE" in payload
    assert "<!ENTITY % strix" in payload
    assert "http://oob.test/abc" in payload
    assert "%strix;" in payload


def test_external_dtd_payload_shape() -> None:
    payload = _build_external_dtd_payload("http://oob.test/abc")
    assert "<!DOCTYPE foo SYSTEM" in payload
    assert "http://oob.test/abc.dtd" in payload


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_oob_xxe(url="")
    assert out["status"] == "error"


def test_oob_unavailable_returns_partial(monkeypatch) -> None:
    """OOB backend disabled → partial with helpful error."""
    _patch_oob(monkeypatch, available=False, hit=False)
    out = scan_oob_xxe(url="http://example.com/api/xml")
    assert out["status"] == "partial"
    assert "OOB" in out["error"] or "Phase 1.3" in out["error"]


def test_proxy_unavailable_returns_error(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit=False)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: (_ for _ in ()).throw(ImportError("boom")),
    )
    out = scan_oob_xxe(url="http://example.com/api/xml")
    assert out["status"] == "error"


# ---------------------------------------------------------------------------
# OOB hit path → critical finding
# ---------------------------------------------------------------------------


def test_oob_hit_emits_critical(monkeypatch) -> None:
    """OOB callback hit → critical CWE-611 finding."""
    _patch_oob(monkeypatch, available=True, hit=True)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_oob_xxe(url="http://example.com/api/xml")
    assert out["status"] == "ok"
    assert len(out["findings"]) >= 1
    f = out["findings"][0]
    assert f["category"] == "xxe"
    assert f["cwe"] == "CWE-611"
    assert f["severity"] == "critical"


def test_no_oob_hit_no_finding(monkeypatch) -> None:
    """OOB available but no callback hit → no finding."""
    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_oob_xxe(url="http://example.com/api/xml")
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_payloads_sent_to_target(monkeypatch) -> None:
    """Both probe payloads (param-entity + external-DTD) reach the target."""
    captured_bodies: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_bodies.append(body)
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, fake_resp)
    scan_oob_xxe(url="http://example.com/api/xml")
    # Two probes sent → two captures.
    assert len(captured_bodies) == 2
    # First is param entity.
    assert "<!ENTITY % strix" in captured_bodies[0]
    # Second is external DTD.
    assert "<!DOCTYPE foo SYSTEM" in captured_bodies[1]


# ---------------------------------------------------------------------------
# Content-Type
# ---------------------------------------------------------------------------


def test_content_type_defaults_to_xml(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, fake_resp)
    scan_oob_xxe(url="http://example.com/api/xml")
    assert all(
        h.get("Content-Type") == "application/xml"
        for h in captured_headers
    )


def test_caller_content_type_preserved(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, fake_resp)
    scan_oob_xxe(
        url="http://example.com/api/xml",
        extra_headers={"Content-Type": "text/xml"},
    )
    assert all(
        h.get("Content-Type") == "text/xml"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# Auth auto-injection
# ---------------------------------------------------------------------------


def test_auth_state_bearer_auto_forwarded(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, fake_resp)
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="oxtok")

    scan_oob_xxe(url="http://example.com/api/xml")
    assert any(
        h.get("Authorization") == "Bearer oxtok"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_oob_xxe(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    scan_oob_xxe(url="http://example.com/api/xml")
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("oob_xxe" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    scan_oob_xxe(url="http://example.com/api/xml")
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_oob_xxe"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_oob_xxe_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_oob_xxe")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "xxe-specialist"


def test_scan_oob_xxe_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_oob_xxe" in catalog
