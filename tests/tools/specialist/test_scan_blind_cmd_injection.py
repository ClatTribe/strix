"""Tests for §workitem.md Phase 4.3 — `scan_blind_cmd_injection`
(OOB-DNS blind variant, CWE-78).

Pins:
  * OOB hit on first probe → critical CWE-78 finding
  * No OOB hit → no finding
  * OOB unavailable → status=partial
  * Defensive: empty url, no params → partial
  * Param inference + forgiving args
  * Auth auto-injection
  * Per-(endpoint, param) dedup
  * SecurityContext + decision_log
  * Registry / catalog wiring
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_blind_cmd_injection import (
    _build_url_with_param,
    _callback_dns_host,
    scan_blind_cmd_injection,
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
    set_global_tracer(Tracer("test-blind-cmdi"))
    yield


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


@pytest.fixture(autouse=True)
def _reset_oob() -> None:
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
    callback_url: str = "http://oob.test:8443/strixDEADBEEF"
    expires_at: str = "2099-01-01T00:00:00+00:00"
    backend_name: str = "local"


def _patch_oob(
    monkeypatch, *,
    available: bool,
    hit_on_probe: int = 1,  # 1-based: which probe call returns hit
):
    """Patch OOB module so probes can be deterministically tested."""
    call_counter = [0]

    monkeypatch.setattr(
        "strix.tools.oob.is_available",
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
        call_counter[0] += 1
        if hit_on_probe and call_counter[0] == hit_on_probe:
            return {
                "hit": True,
                "source_ip": "10.0.0.5",
                "raw_request": {"method": "GET", "path": f"/{token}"},
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
# Helpers
# ---------------------------------------------------------------------------


def test_callback_dns_host_local_listener_path() -> None:
    """For local-listener URL `http://oob:8443/<token>`, the host
    becomes `<token>.oob:8443`."""
    result = _callback_dns_host("http://oob.test:8443/strixABC", "strixABC")
    assert result == "strixABC.oob.test:8443"


def test_callback_dns_host_already_subdomain() -> None:
    """If token is already in netloc, just return netloc."""
    result = _callback_dns_host("http://strixABC.oob.test/", "strixABC")
    assert "strixABC.oob.test" == result


def test_build_url_with_param_preserves_metacharacters() -> None:
    url = _build_url_with_param(
        "http://example.com/admin?host=foo",
        "host", "test;nslookup x.oob",
    )
    # Shell metacharacters survive (not percent-encoded into oblivion).
    assert "host=" in url
    assert ";" in url or "%3B" in url


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_blind_cmd_injection(url="")
    assert out["status"] == "error"


def test_oob_unavailable_returns_partial(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=False)
    out = scan_blind_cmd_injection(
        url="http://example.com/admin?host=x", param="host",
    )
    assert out["status"] == "partial"
    assert "OOB" in out["error"] or "Phase 1.3" in out["error"]


def test_no_cmd_shaped_params_returns_partial(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit_on_probe=0)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_cmd_injection(url="http://example.com/api/items")
    assert out["status"] == "partial"


# ---------------------------------------------------------------------------
# OOB hit path
# ---------------------------------------------------------------------------


def test_oob_hit_on_first_probe_emits_critical(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit_on_probe=1)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_cmd_injection(
        url="http://example.com/admin?host=8.8.8.8", param="host",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "command_injection"
    assert f["cwe"] == "CWE-78"
    assert f["severity"] == "critical"


def test_oob_hit_on_third_probe_emits(monkeypatch) -> None:
    """Second probe variant succeeds → finding emitted."""
    _patch_oob(monkeypatch, available=True, hit_on_probe=3)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_cmd_injection(
        url="http://example.com/admin?host=x", param="host",
    )
    assert len(out["findings"]) == 1


def test_no_oob_hit_no_finding(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit_on_probe=0)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_cmd_injection(
        url="http://example.com/admin?host=x", param="host",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Dedup + early termination
# ---------------------------------------------------------------------------


def test_dedup_one_finding_per_param(monkeypatch) -> None:
    """Once one probe hits, scanner moves to the next param — one
    finding per (endpoint, param) max."""
    _patch_oob(monkeypatch, available=True, hit_on_probe=1)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_cmd_injection(
        url="http://example.com/admin?host=x", param="host",
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Param inference + forgiving args
# ---------------------------------------------------------------------------


def test_inference_picks_cmd_shaped_param(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit_on_probe=1)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_cmd_injection(
        url="http://example.com/admin?host=x&page=1",
    )
    # `host` is in lexicon; `page` is not.
    assert any("host" in f["title"] for f in out["findings"])


def test_forgiving_params_string(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit_on_probe=0)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_cmd_injection(
        url="http://example.com/admin?host=x", params="host",
    )
    assert out["status"] == "ok"


# ---------------------------------------------------------------------------
# Auth auto-injection
# ---------------------------------------------------------------------------


def test_auth_state_bearer_auto_forwarded(monkeypatch) -> None:
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_oob(monkeypatch, available=True, hit_on_probe=0)
    _patch_proxy(monkeypatch, fake_resp)
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="bctok")

    scan_blind_cmd_injection(
        url="http://example.com/admin?host=x", param="host",
    )
    assert any(
        h.get("Authorization") == "Bearer bctok"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_blind_cmd_injection(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit_on_probe=0)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    scan_blind_cmd_injection(
        url="http://example.com/admin?host=x", param="host",
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("blind_command_injection" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    _patch_oob(monkeypatch, available=True, hit_on_probe=0)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    scan_blind_cmd_injection(
        url="http://example.com/admin?host=x", param="host",
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_blind_cmd_injection"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_blind_cmd_injection_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_blind_cmd_injection")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "cmd-injection-specialist"


def test_scan_blind_cmd_injection_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_blind_cmd_injection" in catalog
