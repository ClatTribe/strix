"""Tests for §workitem.md Phase 4.5 — `scan_blind_ssrf` (CWE-918, OOB).

Pins:
  * Multi-scheme probes (http/https/gopher/dict) sent per param
  * OOB hit → high finding (or critical when source IP is private)
  * No hit → no finding
  * OOB unavailable → status=partial
  * Defensive: empty url, no params → partial
  * Param inference + forgiving args
  * Auth auto-injection
  * STRIX_OOB_REBIND_HOST env adds rebind probe
  * SecurityContext + decision_log
  * Registry / catalog wiring
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_blind_ssrf import (
    _scheme_variants,
    scan_blind_ssrf,
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
    set_global_tracer(Tracer("test-blind-ssrf"))
    yield


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


@pytest.fixture(autouse=True)
def _reset_oob() -> None:
    from strix.tools.oob.service import reset_oob_service
    reset_oob_service()
    os.environ["STRIX_OOB_BACKEND"] = "disabled"
    yield
    reset_oob_service()
    os.environ.pop("STRIX_OOB_BACKEND", None)
    os.environ.pop("STRIX_OOB_REBIND_HOST", None)


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


def _patch_oob(monkeypatch, *, available: bool, hit: bool,
               source_ip: str = "203.0.113.5"):
    monkeypatch.setattr(
        "strix.tools.oob.is_available",
        lambda: available,
    )
    monkeypatch.setattr(
        "strix.tools.oob.register_callback",
        lambda *a, **kw: _Cb() if available else None,
    )

    def _poll(token, *, timeout_seconds=10.0):
        if hit:
            return {
                "hit": True,
                "source_ip": source_ip,
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
# _scheme_variants helper
# ---------------------------------------------------------------------------


def test_scheme_variants_basic() -> None:
    variants = _scheme_variants("http://oob.test:8443/strixABC", "strixABC")
    labels = [v[0] for v in variants]
    assert "http" in labels
    assert "gopher" in labels
    assert "dict" in labels
    assert "https" in labels


def test_scheme_variants_rebind_when_env_set(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OOB_REBIND_HOST", "rebind.attacker.test")
    variants = _scheme_variants("http://oob.test/strixABC", "strixABC")
    labels = [v[0] for v in variants]
    assert "rebind" in labels


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_blind_ssrf(url="")
    assert out["status"] == "error"


def test_oob_unavailable_returns_partial(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=False, hit=False)
    out = scan_blind_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
    )
    assert out["status"] == "partial"
    assert "OOB" in out["error"] or "Phase 1.3" in out["error"]


def test_no_ssrf_shaped_params_returns_partial(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_ssrf(url="http://example.com/api/items")
    assert out["status"] == "partial"


# ---------------------------------------------------------------------------
# OOB hit → finding
# ---------------------------------------------------------------------------


def test_oob_hit_emits_high(monkeypatch) -> None:
    """Public source IP → high severity."""
    _patch_oob(monkeypatch, available=True, hit=True, source_ip="203.0.113.5")
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "ssrf"
    assert f["cwe"] == "CWE-918"
    assert f["severity"] == "high"


def test_oob_hit_from_private_ip_emits_critical(monkeypatch) -> None:
    """Private source IP (10.x.x.x) → critical (parser on internal LAN)."""
    _patch_oob(monkeypatch, available=True, hit=True, source_ip="10.0.0.5")
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
    )
    f = out["findings"][0]
    assert f["severity"] == "critical"


def test_no_oob_hit_no_finding(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Multi-scheme probes
# ---------------------------------------------------------------------------


def test_multiple_scheme_variants_sent(monkeypatch) -> None:
    """Per param, scanner sends http + https + gopher + dict probes."""
    captured_payloads: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        # Extract the param value to verify scheme variation.
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(url).query)
        url_val = qs.get("url", [""])[0]
        captured_payloads.append(url_val)
        return {"status_code": 200, "body": "ok", "headers": {}}

    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, fake_resp)
    scan_blind_ssrf(
        url="http://example.com/proxy?url=foo", param="url",
    )
    schemes = [p.split(":", 1)[0] for p in captured_payloads if ":" in p]
    assert "http" in schemes
    assert "gopher" in schemes
    assert "dict" in schemes


# ---------------------------------------------------------------------------
# Param inference + forgiving args
# ---------------------------------------------------------------------------


def test_inference_picks_ssrf_shaped_param(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit=True)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_ssrf(
        url="http://example.com/avatar?image=foo&user=alice",
    )
    # `image` is in lexicon, `user` is not.
    assert any("image" in f["title"] for f in out["findings"])


def test_forgiving_params_string(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    out = scan_blind_ssrf(
        url="http://example.com/proxy?url=foo", params="url",
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

    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, fake_resp)
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="bstok")

    scan_blind_ssrf(
        url="http://example.com/proxy?url=foo", param="url",
    )
    assert any(
        h.get("Authorization") == "Bearer bstok"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_blind_ssrf(monkeypatch) -> None:
    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    scan_blind_ssrf(
        url="http://example.com/proxy?url=foo", param="url",
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("blind_ssrf" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    _patch_oob(monkeypatch, available=True, hit=False)
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok", "headers": {},
    })
    scan_blind_ssrf(
        url="http://example.com/proxy?url=foo", param="url",
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_blind_ssrf"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_blind_ssrf_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_blind_ssrf")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "ssrf-specialist"


def test_scan_blind_ssrf_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_blind_ssrf" in catalog
