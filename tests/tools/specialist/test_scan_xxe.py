"""Tests for §8.5 Phase 6 — `scan_xxe` deterministic XXE specialist.

Pins detection of:
  * Local-file disclosure (Linux passwd / Windows hosts)
  * Cloud-metadata SSRF (AWS IMDS / GCP)
  * SOAP-envelope wrapping when `soap=True`
  * Negative cases (parser hardened / wrong content-type)
  * Auto-emit via tracer + SecurityContext probed_for=xxe
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_xxe import scan_xxe


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
    set_global_tracer(Tracer("test-xxe"))
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
    out = scan_xxe(url="")
    assert out["status"] == "error"


def test_proxy_manager_unavailable_returns_error(monkeypatch) -> None:
    def boom():
        raise ImportError("simulated missing dep")
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        boom,
    )
    out = scan_xxe(url="http://example.com/api/orders")
    assert out["status"] == "error"
    assert "proxy_manager" in out["error"]


# ---------------------------------------------------------------------------
# Local-file disclosure detection (the headline manifest case)
# ---------------------------------------------------------------------------


def test_xxe_passwd_disclosure_triggers_finding(monkeypatch) -> None:
    """Server resolves the entity → response contains /etc/passwd
    content → XXE finding emitted."""
    captured: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        captured.append(body)
        if "file:///etc/passwd" in body:
            return {
                "status_code": 200,
                "body": (
                    "Order received. Confirmation:\n"
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                ),
            }
        return {"status_code": 200, "body": "Order received."}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xxe(url="http://example.com/b2b/v2/orders")

    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "xxe"
    assert f["cwe"] == "CWE-611"
    assert f["severity"] == "high"
    # Confirm the probe body actually had a DOCTYPE entity reference.
    assert any("DOCTYPE" in b and "ENTITY" in b for b in captured)
    assert any("file:///etc/passwd" in b for b in captured)


def test_xxe_windows_hosts_disclosure_triggers(monkeypatch) -> None:
    """Windows-style file disclosure (hosts file)."""
    def fake_resp(method, url, headers, body, timeout):
        if "C:/Windows" in body or "C%3A%2FWindows" in body:
            return {
                "status_code": 200,
                "body": (
                    "Result: # Copyright (c) 1993-2009 Microsoft Corp.\n"
                    "127.0.0.1       localhost\n"
                ),
            }
        # First payload is Linux passwd — return innocuous; should NOT trigger
        return {"status_code": 200, "body": "ok no entity resolution"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xxe(url="http://example.com/api/xml")
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Cloud-metadata SSRF (escalates severity to critical)
# ---------------------------------------------------------------------------


def test_xxe_aws_metadata_disclosure_critical(monkeypatch) -> None:
    """If the entity targets AWS metadata and the response contains
    metadata fingerprints, severity should be critical."""
    def fake_resp(method, url, headers, body, timeout):
        # Local-file payloads return innocuous responses
        if "file://" in body:
            return {"status_code": 200, "body": "ok"}
        # Metadata payload returns the IMDS index
        if "169.254.169.254" in body:
            return {
                "status_code": 200,
                "body": (
                    "ami-id\n"
                    "ami-launch-index\n"
                    "iam/security-credentials/\n"
                    "instance-id\n"
                ),
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xxe(url="http://example.com/api/orders")
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["severity"] == "critical"

    from strix.telemetry.tracer import get_global_tracer
    tf = get_global_tracer().get_existing_vulnerabilities()[0]
    # Title should call out SSRF / cloud-metadata.
    assert "SSRF" in tf["title"] or "metadata" in tf["title"].lower()


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


def test_hardened_parser_does_not_trigger(monkeypatch) -> None:
    """Server rejects DOCTYPE or doesn't resolve entities → no finding."""
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 400,
            "body": "<error>DOCTYPE declarations are not allowed</error>",
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xxe(url="http://example.com/api/xml")
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_response_with_no_fingerprint_does_not_trigger(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 200, "body": "Generic OK page; no entity content"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xxe(url="http://example.com/api/xml")
    assert len(out["findings"]) == 0


def test_transport_error_does_not_emit(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {"error": "Request failed: ConnectionError", "url": url}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_xxe(url="http://example.com/api/xml")
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0
    assert any("transport error" in e for e in out["evidence"])


# ---------------------------------------------------------------------------
# Probe payload shape
# ---------------------------------------------------------------------------


def test_probe_includes_doctype_and_entity(monkeypatch) -> None:
    captured: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        captured.append(body)
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_xxe(url="http://example.com/api/xml")

    # At least one probe must have a DOCTYPE+ENTITY definition.
    has_xxe = any(
        "<!DOCTYPE" in b and "<!ENTITY xxe" in b
        for b in captured
    )
    assert has_xxe


def test_content_type_is_xml(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers))
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_xxe(url="http://example.com/api/xml")

    assert all(
        h.get("Content-Type") == "application/xml"
        for h in captured_headers
    )


def test_extra_headers_forwarded(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers))
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_xxe(
        url="http://example.com/api/xml",
        extra_headers={"Authorization": "Bearer token123"},
    )
    assert captured_headers[0]["Authorization"] == "Bearer token123"


# ---------------------------------------------------------------------------
# SOAP envelope mode
# ---------------------------------------------------------------------------


def test_soap_mode_wraps_in_envelope(monkeypatch) -> None:
    captured: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        captured.append(body)
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_xxe(url="http://example.com/soap", soap=True)

    body = captured[0]
    assert "soap:Envelope" in body
    assert "soap:Body" in body
    # DOCTYPE must still be at top (parsers process it before envelope).
    assert "<!DOCTYPE" in body


def test_soap_mode_keeps_entity_reference(monkeypatch) -> None:
    captured: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        captured.append(body)
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_xxe(url="http://example.com/soap", soap=True)
    assert "&xxe;" in captured[0]
    assert "<!ENTITY xxe" in captured[0]


# ---------------------------------------------------------------------------
# SecurityContext integration
# ---------------------------------------------------------------------------


def test_records_endpoint_as_probed_for_xxe(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    scan_xxe(url="http://example.com/api/orders")

    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("xxe" in e.probed_for for e in eps)


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_xxe_registered_in_specialist_registry() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_xxe")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "xxe-specialist"


def test_scan_xxe_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_xxe" in catalog
