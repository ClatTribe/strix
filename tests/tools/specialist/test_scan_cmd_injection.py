"""Tests for §workitem.md Phase 2.6 — `scan_cmd_injection` deterministic
in-band command-injection specialist (CWE-78).

Pins:
  * Linux `id` output fingerprint via ;, |, &&, ``, $()
  * Linux `uname -a` fingerprint
  * Windows `whoami` fingerprint (NT AUTHORITY, IIS APPPOOL)
  * Windows `dir` fingerprint
  * Param inference from cmd-shaped lexicon
  * Forgiving args
  * Auth auto-injection
  * Negatives (no fingerprint, transport error, hardened input filter)
  * SecurityContext + decision_log integration
  * Registry / catalog wiring
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_cmd_injection import scan_cmd_injection


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
    set_global_tracer(Tracer("test-cmdi"))
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
    out = scan_cmd_injection(url="")
    assert out["status"] == "error"


def test_no_cmd_shaped_params_returns_partial(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    out = scan_cmd_injection(url="http://example.com/api/items")
    assert out["status"] == "partial"


# ---------------------------------------------------------------------------
# Linux `id` output detection
# ---------------------------------------------------------------------------


def test_id_via_semicolon_emits_critical(monkeypatch) -> None:
    """Server runs `ping <host>;id` → response contains id output."""
    def fake_resp(method, url, headers, body, timeout):
        if "id" in url and (";" in url or "%3B" in url):
            return {
                "status_code": 200,
                "body": (
                    "PING test (192.168.1.1): 56 data bytes\n"
                    "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
                ),
            }
        return {"status_code": 200, "body": "PING test"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_cmd_injection(
        url="http://example.com/admin/ping?host=8.8.8.8", param="host",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "command_injection"
    assert f["cwe"] == "CWE-78"
    assert f["severity"] == "critical"


def test_uname_fingerprint_emits(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "uname" in url:
            return {
                "status_code": 200,
                "body": (
                    "ok\nLinux web-prod-01 5.15.0-86-generic "
                    "#96-Ubuntu SMP Wed Sep 20 08:23:49 UTC 2023 "
                    "x86_64 x86_64 x86_64 GNU/Linux\n"
                ),
            }
        return {"status_code": 200, "body": "PING ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_cmd_injection(
        url="http://example.com/admin/ping?host=x", param="host",
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Windows whoami
# ---------------------------------------------------------------------------


def test_whoami_iis_apppool_fingerprint_emits(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "whoami" in url:
            return {
                "status_code": 200,
                "body": "PING ok\nIIS APPPOOL\\DefaultAppPool\n",
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_cmd_injection(
        url="http://example.com/admin/ping?host=x", param="host",
    )
    assert len(out["findings"]) == 1


def test_dir_fingerprint_emits(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "dir" in url:
            return {
                "status_code": 200,
                "body": (
                    "PING ok\n Volume in drive C is Windows\n"
                    " Directory of C:\\inetpub\\wwwroot\n"
                ),
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_cmd_injection(
        url="http://example.com/admin/exec?cmd=date", param="cmd",
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Negatives
# ---------------------------------------------------------------------------


def test_no_fingerprint_no_finding(monkeypatch) -> None:
    """Hardened filter rejects metacharacters → no finding."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 400,
        "body": "<error>Invalid character in input</error>",
    })
    out = scan_cmd_injection(
        url="http://example.com/admin/ping?host=x", param="host",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_innocuous_response_no_finding(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "PING ok",
    })
    out = scan_cmd_injection(
        url="http://example.com/admin/ping?host=x", param="host",
    )
    assert len(out["findings"]) == 0


def test_transport_error_does_not_emit(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "error": "Request failed",
    })
    out = scan_cmd_injection(
        url="http://example.com/admin/ping?host=x", param="host",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Param inference + forgiving args
# ---------------------------------------------------------------------------


def test_inference_picks_cmd_shaped_param(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "id" in url and (";" in url or "%3B" in url):
            return {
                "status_code": 200,
                "body": "uid=0(root) gid=0(root) groups=0(root)",
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    # `host` is in cmd lexicon, `page` is not.
    out = scan_cmd_injection(
        url="http://example.com/admin?host=8.8.8.8&page=1",
    )
    assert len(out["findings"]) == 1
    assert "host" in out["findings"][0]["title"]


def test_forgiving_params_string(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    out = scan_cmd_injection(
        url="http://example.com/admin?host=x", params="host",
    )
    assert out["status"] == "ok"


def test_dedup_one_finding_per_param(monkeypatch) -> None:
    """Multiple probes match → one finding per param (first-match-wins)."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200,
        "body": (
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            "Linux box 5.15 #1 SMP\n"
        ),
    })
    out = scan_cmd_injection(
        url="http://example.com/admin?host=x", param="host",
    )
    assert len(out["findings"]) == 1


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
    record_auth_state(label="lead", bearer="ctoken")

    scan_cmd_injection(
        url="http://example.com/admin?host=x", param="host",
    )
    assert any(
        h.get("Authorization") == "Bearer ctoken"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_command_injection(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_cmd_injection(
        url="http://example.com/admin?host=x", param="host",
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("command_injection" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_cmd_injection(
        url="http://example.com/admin?host=x", param="host",
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_cmd_injection"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_cmd_injection_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_cmd_injection")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "cmd-injection-specialist"


def test_scan_cmd_injection_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_cmd_injection" in catalog
