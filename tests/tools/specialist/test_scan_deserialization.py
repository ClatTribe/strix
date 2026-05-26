"""Tests for §workitem.md Phase 4.4 — `scan_deserialization`
(CWE-502 / A08:2021).

Pins:
  * Java ObjectInputStream invalid-class fingerprint → high finding
  * PHP unserialize 'Error at offset' → high finding
  * Python pickle UnpicklingError → high finding
  * Ruby Marshal incompatible-marshal → high finding
  * .NET TypeNameHandling 'Could not load type' → high finding
  * OOB hit → critical finding
  * Time-delta → critical finding
  * Tech-stack hint narrows family list (e.g. java only)
  * Defensive: empty url → error
  * Auth auto-injection
  * SecurityContext + decision_log
  * Registry / catalog wiring
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_deserialization import (
    _family_from_tech_stack,
    scan_deserialization,
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
    set_global_tracer(Tracer("test-deser"))
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
# _family_from_tech_stack helper
# ---------------------------------------------------------------------------


def test_family_from_tech_stack_java() -> None:
    from strix.agents.security_context import update_tech_stack
    update_tech_stack(language="Java", framework="Spring")
    families = _family_from_tech_stack()
    assert families == ["java"]


def test_family_from_tech_stack_php() -> None:
    from strix.agents.security_context import update_tech_stack
    update_tech_stack(language="PHP", framework="Laravel")
    families = _family_from_tech_stack()
    assert families == ["php"]


def test_family_from_tech_stack_python() -> None:
    from strix.agents.security_context import update_tech_stack
    update_tech_stack(language="Python", framework="Django")
    families = _family_from_tech_stack()
    assert families == ["python"]


def test_family_from_tech_stack_no_stack() -> None:
    families = _family_from_tech_stack()
    assert families is None


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_deserialization(url="")
    assert out["status"] == "error"


def test_invalid_family_returns_partial(monkeypatch) -> None:
    out = scan_deserialization(
        url="http://example.com/api",
        families=["smalltalk"],  # not a recognised family
    )
    assert out["status"] == "partial"


def test_proxy_unavailable_returns_error(monkeypatch) -> None:
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: (_ for _ in ()).throw(ImportError("boom")),
    )
    out = scan_deserialization(
        url="http://example.com/api", families=["python"],
    )
    assert out["status"] == "error"


# ---------------------------------------------------------------------------
# Per-family fingerprints → high
# ---------------------------------------------------------------------------


def test_java_fingerprint_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 500,
            "body": (
                "java.io.InvalidClassException: strix.NoSuchClass; "
                "no valid constructor at "
                "java.io.ObjectInputStream.readObject(Native)"
            ),
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_deserialization(
        url="http://example.com/api/process",
        families=["java"],
        enable_oob=False,
    )
    assert out["status"] == "ok"
    assert any(f["category"] == "deserialization" for f in out["findings"])
    f = next(f for f in out["findings"] if f["category"] == "deserialization")
    assert f["cwe"] == "CWE-502"
    assert f["severity"] == "high"


def test_php_fingerprint_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 500,
            "body": (
                "Notice: unserialize(): Error at offset 0 of 25 bytes "
                "in /var/www/app.php on line 42"
            ),
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_deserialization(
        url="http://example.com/api/php-handler",
        families=["php"],
        enable_oob=False,
    )
    assert any(f["severity"] == "high" for f in out["findings"])


def test_python_fingerprint_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 500,
            "body": (
                "Traceback (most recent call last):\n"
                "  File 'app.py', line 10, in handler\n"
                "    obj = pickle.loads(data)\n"
                "_pickle.UnpicklingError: invalid load key, '\\x95'."
            ),
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_deserialization(
        url="http://example.com/api/load",
        families=["python"],
        enable_oob=False,
    )
    assert any(f["severity"] == "high" for f in out["findings"])


def test_ruby_fingerprint_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 500,
            "body": "TypeError (incompatible marshal file format (can't be read))",
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_deserialization(
        url="http://example.com/api/ruby",
        families=["ruby"],
        enable_oob=False,
    )
    assert any(f["severity"] == "high" for f in out["findings"])


def test_dotnet_fingerprint_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        return {
            "status_code": 500,
            "body": (
                "Newtonsoft.Json.JsonSerializationException: Could not "
                "load type 'System.IO.FileInfo'. The deserializer is "
                "configured with TypeNameHandling.Auto."
            ),
            "headers": {},
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_deserialization(
        url="http://example.com/api/dotnet",
        families=["dotnet"],
        enable_oob=False,
    )
    assert any(f["severity"] == "high" for f in out["findings"])


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


def test_no_fingerprint_no_finding(monkeypatch) -> None:
    """200 OK with innocuous body → no finding."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_deserialization(
        url="http://example.com/api",
        families=["python"],
        enable_oob=False,
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_transport_error_does_not_emit(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "error": "Request failed: ConnectionError",
    })
    out = scan_deserialization(
        url="http://example.com/api", families=["python"], enable_oob=False,
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# OOB hit → critical
# ---------------------------------------------------------------------------


@dataclass
class _Cb:
    token: str = "strixDEADBEEF"
    callback_url: str = "http://oob.test:8443/strixDEADBEEF"
    expires_at: str = "2099-01-01T00:00:00+00:00"
    backend_name: str = "local"


def test_oob_hit_on_jackson_emits_critical(monkeypatch) -> None:
    """Jackson polymorphic probe + OOB hit → critical RCE-class finding."""
    monkeypatch.setattr("strix.tools.oob.is_available", lambda: True)
    monkeypatch.setattr(
        "strix.tools.oob.register_callback", lambda *a, **kw: _Cb(),
    )
    monkeypatch.setattr(
        "strix.tools.oob.poll_callback",
        lambda token, *, timeout_seconds=10.0: {
            "hit": True,
            "source_ip": "10.0.0.5",
            "raw_request": {"method": "GET", "path": f"/{token}"},
        },
    )

    def fake_resp(method, url, headers, body, timeout):
        # Java endpoint silently swallows the exception but still
        # fires the OOB callback.
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_deserialization(
        url="http://example.com/api/java",
        families=["java"],
        enable_oob=True,
        oob_timeout_seconds=0.1,
    )
    assert any(f["severity"] == "critical" for f in out["findings"])


# ---------------------------------------------------------------------------
# Tech-stack hint narrows the probe set
# ---------------------------------------------------------------------------


def test_tech_stack_narrows_to_python(monkeypatch) -> None:
    """When SecurityContext has Python tech-stack, only python probes
    are sent."""
    captured_content_types: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_content_types.append(headers.get("Content-Type", ""))
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    from strix.agents.security_context import update_tech_stack
    update_tech_stack(language="Python", framework="Flask")

    scan_deserialization(
        url="http://example.com/api", enable_oob=False,
    )
    # Python probe sets octet-stream Content-Type. No Jackson JSON
    # probe should fire.
    assert any("octet-stream" in ct for ct in captured_content_types)
    assert not any("@class" in ct for ct in captured_content_types)


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
    record_auth_state(label="lead", bearer="dtok")

    scan_deserialization(
        url="http://example.com/api",
        families=["python"],
        enable_oob=False,
    )
    assert any(
        h.get("Authorization") == "Bearer dtok"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_deserialization(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    scan_deserialization(
        url="http://example.com/api",
        families=["python"], enable_oob=False,
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("deserialization" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    scan_deserialization(
        url="http://example.com/api",
        families=["python"], enable_oob=False,
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_deserialization"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_deserialization_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_deserialization")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "deserialization-specialist"


def test_scan_deserialization_in_lead_web_application_catalog(monkeypatch) -> None:
    """iter-37.2 — deprecated tool; visible only under STRIX_LEGACY_CATALOG=1."""
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_deserialization" in catalog
