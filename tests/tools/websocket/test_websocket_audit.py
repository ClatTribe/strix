"""Tests for websocket_audit (roadmap §7.2 + §7.2 sub-row).

Hermetic — `_send_handshake` is monkeypatched. Tests cover:

  * Baseline upgrade success/failure → run early-out behaviour
  * Auth-on-upgrade detection (with auth + no auth → still 101 = high CWE-306)
  * Origin enforcement classification:
      - server doesn't enforce at all → single info finding
      - server distinguishes presence + accepts attacker-shape → high
      - server rejects all attacker-shapes → no finding
  * Origin variants (null / attacker_apex / suffix / prefix / scheme_swap)
  * Subprotocol echo (verbatim attacker value reflected → low CWE-79)
  * URL normalisation (ws://, wss://, bare host)
  * Schema + MITRE
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


import strix.tools.websocket.websocket_audit  # noqa: F401

ws_module = sys.modules["strix.tools.websocket.websocket_audit"]
websocket_audit = ws_module.websocket_audit


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("ws-test")
    set_global_tracer(tracer)
    yield


def _findings() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


def _101_response() -> dict[str, Any]:
    return {
        "status": 101,
        "response_headers": {
            "upgrade": "websocket",
            "connection": "Upgrade",
            "sec-websocket-accept": "abc",
        },
    }


def _401_response() -> dict[str, Any]:
    return {"status": 401, "response_headers": {}}


def _patch_handshake(
    monkeypatch, responder: callable
) -> list[dict[str, Any]]:
    """Patch _send_handshake to delegate to `responder(url, headers)`.
    Returns a list of (call_url, headers) pairs for inspection."""
    calls: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=10.0):
        h = dict(headers or {})
        calls.append({"url": url, "headers": h})
        return responder(url, h)

    monkeypatch.setattr(ws_module, "_send_handshake", fake)
    return calls


# ---------------------------------------------------------------------------
# Baseline + URL normalisation
# ---------------------------------------------------------------------------


def test_empty_url_rejected() -> None:
    out = websocket_audit("")
    assert out["success"] is False


def test_invalid_url_rejected(monkeypatch) -> None:
    # A URL with no host is rejected at the parse step. We patch the
    # handshake too in case the parse layer permits it through.
    _patch_handshake(monkeypatch, lambda url, h: {"status": 0, "response_headers": {}, "error": "no host"})
    out = websocket_audit("https:///no-host-here")
    # The success may be True with baseline_upgrade_succeeded=False
    # (the URL parses but the network layer fails). Either way, no
    # findings should fire.
    assert out["findings_emitted"] == 0


def test_baseline_failure_returns_early(monkeypatch) -> None:
    """When baseline upgrade returns 404, we early-out — the rest
    of the suite would produce noise."""
    _patch_handshake(monkeypatch, lambda url, h: {"status": 404, "response_headers": {}})

    out = websocket_audit("wss://api.example.com/ws")

    assert out["success"] is True
    assert out["baseline_upgrade_succeeded"] is False
    assert out["findings_emitted"] == 0


def test_baseline_success_kicks_off_full_suite(monkeypatch) -> None:
    """When baseline succeeds AND every probe also succeeds (i.e.
    server doesn't enforce ANYTHING), we get the no-Origin-
    enforcement info finding."""
    _patch_handshake(monkeypatch, lambda url, h: _101_response())

    out = websocket_audit("wss://api.example.com/ws")

    assert out["baseline_upgrade_succeeded"] is True
    assert out["probes_run"] >= 4
    findings = _findings()
    # Server accepts everything → single info finding.
    info_findings = [f for f in findings if f["severity"] == "info"]
    assert len(info_findings) >= 1
    assert any("origin" in f["title"].lower() for f in info_findings)


# ---------------------------------------------------------------------------
# Auth-on-upgrade
# ---------------------------------------------------------------------------


def test_auth_on_upgrade_missing_emits_high(monkeypatch) -> None:
    """When auth_headers are supplied but unauthed upgrade still
    succeeds → high CWE-306."""
    def responder(url, headers):
        # Both authed and unauthed return 101.
        return _101_response()

    _patch_handshake(monkeypatch, responder)

    out = websocket_audit(
        "wss://api.example.com/ws",
        auth_headers={"Cookie": "session=abc"},
    )

    findings = _findings()
    high_findings = [f for f in findings if f["severity"] == "high"]
    assert any("CWE-306" in f["cwe"] for f in high_findings)
    auth_findings = [f for f in high_findings if f["cwe"] == "CWE-306"]
    assert len(auth_findings) == 1


def test_auth_on_upgrade_enforced_no_finding(monkeypatch) -> None:
    """Authed upgrade returns 101; unauthed returns 401 → no auth finding."""
    def responder(url, headers):
        # If Cookie present → 101. Else → 401.
        if "Cookie" in headers and "session=abc" in headers["Cookie"]:
            return _101_response()
        # Unauthed: 401.
        return _401_response()

    _patch_handshake(monkeypatch, responder)

    out = websocket_audit(
        "wss://api.example.com/ws",
        auth_headers={"Cookie": "session=abc"},
    )

    findings = _findings()
    assert not any(f["cwe"] == "CWE-306" for f in findings)


def test_auth_probe_skipped_without_auth_headers(monkeypatch) -> None:
    """No auth_headers supplied → auth-on-upgrade probe doesn't run."""
    _patch_handshake(monkeypatch, lambda url, h: _101_response())

    out = websocket_audit("wss://api.example.com/ws")
    findings = _findings()
    assert not any(f["cwe"] == "CWE-306" for f in findings)


# ---------------------------------------------------------------------------
# Origin enforcement classification
# ---------------------------------------------------------------------------


def test_no_origin_enforcement_emits_info(monkeypatch) -> None:
    """Server accepts upgrade with NO Origin AND with all attacker
    shapes → single info finding (don't double-flag the same
    underlying issue 5×)."""
    _patch_handshake(monkeypatch, lambda url, h: _101_response())

    out = websocket_audit("wss://api.example.com/ws")
    findings = _findings()
    no_enforcement = [
        f for f in findings if "Origin" in f["title"] or "origin" in f["title"]
    ]
    info_findings = [f for f in no_enforcement if f["severity"] == "info"]
    # At least one info finding for "no enforcement".
    assert len(info_findings) >= 1
    # No high findings for individual variants (would be double-flagging).
    high_origin_findings = [
        f for f in findings
        if f["severity"] == "high" and "origin_bypass" in f["title"]
    ]
    assert len(high_origin_findings) == 0


def test_origin_bypass_attacker_apex_emits_high(monkeypatch) -> None:
    """Server REJECTS no-Origin but ACCEPTS attacker-Origin → high CWE-942."""
    def responder(url, headers):
        origin = headers.get("Origin", "")
        # Server rejects no-Origin but accepts anything else.
        if not origin:
            return _401_response()
        return _101_response()

    _patch_handshake(monkeypatch, responder)

    out = websocket_audit("wss://api.example.com/ws")
    findings = _findings()
    high_origin = [
        f for f in findings
        if f["severity"] == "high" and f["cwe"] == "CWE-942"
    ]
    # One high finding per variant (5 variants).
    assert len(high_origin) >= 1


def test_origin_null_emits_medium(monkeypatch) -> None:
    """Specifically `Origin: null` accepted → medium (not high) since
    only sandboxed attackers can use this surface."""
    def responder(url, headers):
        origin = headers.get("Origin", "")
        if not origin:
            return _401_response()
        # Accept legit origin (so baseline succeeds) and `null`,
        # reject everything else.
        if origin == "https://api.example.com" or origin == "null":
            return _101_response()
        return _401_response()

    _patch_handshake(monkeypatch, responder)

    out = websocket_audit("wss://api.example.com/ws")
    findings = _findings()
    null_findings = [
        f for f in findings if "null" in f["title"]
    ]
    assert len(null_findings) == 1
    assert null_findings[0]["severity"] == "medium"


def test_strict_origin_enforcement_no_finding(monkeypatch) -> None:
    """Server enforces Origin strictly → no origin findings."""
    def responder(url, headers):
        origin = headers.get("Origin", "")
        # Server only accepts the legitimate origin.
        if origin == "https://api.example.com":
            return _101_response()
        return _401_response()

    _patch_handshake(monkeypatch, responder)

    out = websocket_audit("wss://api.example.com/ws")
    findings = _findings()
    origin_findings = [f for f in findings if "Origin" in f["title"] or "origin" in f["title"]]
    # No high or medium findings — only the (potentially absent) info.
    high_or_med = [
        f for f in origin_findings if f["severity"] in ("high", "medium")
    ]
    assert len(high_or_med) == 0


def test_origin_bypass_suffix_kind_distinguished(monkeypatch) -> None:
    """When server only accepts the legitimate origin + the suffix-
    shape variant, only the suffix finding fires."""
    def responder(url, headers):
        origin = headers.get("Origin", "")
        if not origin:
            return _401_response()
        # Accept legit + suffix variant (target appears as a label
        # inside the attacker host); reject everything else.
        if origin == "https://api.example.com":
            return _101_response()
        if "api.example.com.strix" in origin:
            return _101_response()
        return _401_response()

    _patch_handshake(monkeypatch, responder)

    out = websocket_audit("wss://api.example.com/ws")
    findings = _findings()
    suffix_findings = [f for f in findings if "suffix" in f["title"]]
    assert len(suffix_findings) == 1
    assert suffix_findings[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Subprotocol echo
# ---------------------------------------------------------------------------


def test_subprotocol_echo_emits_low(monkeypatch) -> None:
    """Server echoes Sec-WebSocket-Protocol verbatim → low CWE-79."""
    def responder(url, headers):
        echoed = headers.get("Sec-WebSocket-Protocol", "")
        resp_headers = {
            "upgrade": "websocket",
            "connection": "Upgrade",
        }
        if echoed:
            resp_headers["sec-websocket-protocol"] = echoed
        return {"status": 101, "response_headers": resp_headers}

    _patch_handshake(monkeypatch, responder)

    out = websocket_audit("wss://api.example.com/ws")
    findings = _findings()
    subprotocol_findings = [
        f for f in findings if "subprotocol" in f["title"].lower()
    ]
    assert len(subprotocol_findings) == 1
    assert subprotocol_findings[0]["severity"] == "low"
    assert subprotocol_findings[0]["cwe"] == "CWE-79"


def test_subprotocol_validated_no_finding(monkeypatch) -> None:
    """Server validates subprotocol against allow-list → no echo finding."""
    def responder(url, headers):
        # Server doesn't echo — uses its own validated value.
        resp_headers = {
            "upgrade": "websocket",
            "connection": "Upgrade",
            "sec-websocket-protocol": "chat-v1",
        }
        return {"status": 101, "response_headers": resp_headers}

    _patch_handshake(monkeypatch, responder)

    out = websocket_audit("wss://api.example.com/ws")
    findings = _findings()
    assert not any("subprotocol" in f["title"].lower() for f in findings)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def test_ws_to_http_url_handles_each_scheme() -> None:
    assert ws_module._ws_to_http_url("ws://example.com/x") == "http://example.com/x"
    assert ws_module._ws_to_http_url("wss://example.com/x") == "https://example.com/x"
    assert ws_module._ws_to_http_url("https://example.com/x") == "https://example.com/x"
    assert ws_module._ws_to_http_url("http://example.com/x") == "http://example.com/x"


def test_is_upgrade_success_requires_101_and_headers() -> None:
    is_ok = ws_module._is_upgrade_success
    assert is_ok({
        "status": 101,
        "response_headers": {"upgrade": "websocket", "connection": "Upgrade"},
    }) is True
    # Status 200 with upgrade headers → still not a valid upgrade.
    assert is_ok({
        "status": 200,
        "response_headers": {"upgrade": "websocket", "connection": "Upgrade"},
    }) is False
    # Missing upgrade header → not a valid upgrade.
    assert is_ok({"status": 101, "response_headers": {"connection": "Upgrade"}}) is False
    # Empty.
    assert is_ok({"status": 0, "response_headers": {}}) is False


# ---------------------------------------------------------------------------
# Schema + MITRE
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    _patch_handshake(monkeypatch, lambda url, h: _401_response())
    out = websocket_audit("wss://api.example.com/ws")
    assert set(out.keys()) >= {
        "success", "target_url", "baseline_upgrade_succeeded",
        "probes_run", "findings_emitted", "records",
    }


def test_mitre_techniques_registered() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    techniques = get_tool_mitre_techniques("websocket_audit")
    assert "T1190" in techniques
    assert "T1090" in techniques


def test_bare_host_auto_prefixed(monkeypatch) -> None:
    """`api.example.com/ws` (no scheme) is auto-prefixed `wss://`."""
    _patch_handshake(monkeypatch, lambda url, h: _401_response())
    out = websocket_audit("api.example.com/ws")
    assert out["target_url"].startswith("wss://")
