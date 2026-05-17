"""Tests for `scan_websocket_auth`.

Hermetic — `_send_handshake` is monkeypatched. Tests cover:

  * Each probe (cross-origin / null / subdomain / anonymous /
    subprotocol) positive + negative case.
  * Baseline-handshake gate (non-WebSocket endpoint → partial).
  * `Upgrade: websocket` validation (101 alone isn't enough).
  * URL scheme variants (ws/wss/http/https).
  * Probe allow-list.
  * Tracer round-trip pin.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.specialist.scan_websocket_auth  # noqa: F401

ws_module = sys.modules["strix.tools.specialist.scan_websocket_auth"]
scan_websocket_auth = ws_module.scan_websocket_auth


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
        "STRIX_ATTACKER_DOMAIN",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("ws-test")
    set_global_tracer(tracer)
    yield


def _patch_handshake(monkeypatch, responder):
    """`responder(host, port, use_tls, request_bytes) -> (status,
    headers_dict, error_str_or_none)`."""
    log: list[dict[str, Any]] = []

    def fake(host, port, *, use_tls, raw_request, timeout=8.0):
        entry = {
            "host": host, "port": port,
            "use_tls": use_tls,
            "request": raw_request.decode("iso-8859-1"),
        }
        log.append(entry)
        return responder(host, port, use_tls, raw_request)

    monkeypatch.setattr(ws_module, "_send_handshake", fake)
    return log


# ---------------------------------------------------------------------------
# Responders
# ---------------------------------------------------------------------------


def _request_origin(request_text: str) -> str | None:
    """Pull the `Origin:` header value out of a raw handshake."""
    for line in request_text.split("\r\n"):
        if line.lower().startswith("origin:"):
            return line.split(":", 1)[1].strip()
    return None


def _accept_response() -> tuple[int, dict[str, str], None]:
    return 101, {
        "upgrade": "websocket",
        "connection": "Upgrade",
        "sec-websocket-accept": "fake-accept-value",
    }, None


def _reject_response(status: int = 403) -> tuple[int, dict[str, str], None]:
    return status, {}, None


def _laxx_origin_responder(host, port, use_tls, raw):
    """Accept ANY origin — vulnerable to CSWSH, null-origin,
    subdomain trust, and anonymous-upgrade simultaneously."""
    return _accept_response()


def _strict_responder(host, port, use_tls, raw):
    """Accept ONLY the legitimate same-origin handshake; reject
    anything else."""
    text = raw.decode("iso-8859-1")
    origin = _request_origin(text)
    expected = f"{'https' if use_tls else 'http'}://{host}"
    if (use_tls and port != 443) or (not use_tls and port != 80):
        expected += f":{port}"
    if origin == expected:
        return _accept_response()
    return _reject_response()


def _no_websocket_endpoint(host, port, use_tls, raw):
    """Plain 200 with no Upgrade header — not a WebSocket
    endpoint at all."""
    return 200, {"content-type": "text/html"}, None


# ---------------------------------------------------------------------------
# Baseline gating
# ---------------------------------------------------------------------------


def test_non_websocket_endpoint_returns_partial(monkeypatch) -> None:
    _patch_handshake(monkeypatch, _no_websocket_endpoint)
    out = scan_websocket_auth(url="wss://app.example.com/ws")
    assert out["status"] == "partial"
    assert "did not accept legitimate" in out["error"]
    assert out["findings"] == []


def test_websocket_endpoint_with_strict_origin_emits_nothing(
    monkeypatch,
) -> None:
    """A correctly-configured WebSocket endpoint only accepts the
    legitimate origin; no probe fires."""
    _patch_handshake(monkeypatch, _strict_responder)
    out = scan_websocket_auth(url="wss://app.example.com/ws")
    assert out["status"] == "ok"
    assert out["findings"] == []


# ---------------------------------------------------------------------------
# Per-probe positives
# ---------------------------------------------------------------------------


def test_cross_origin_attacker_detected(monkeypatch) -> None:
    """Lax server accepts ANY origin → critical CSWSH finding."""
    _patch_handshake(monkeypatch, _laxx_origin_responder)
    out = scan_websocket_auth(
        url="wss://app.example.com/ws",
        probes=["cross_origin_attacker"],
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["severity"] == "critical"
    assert f["cwe"] == "CWE-346"
    assert "cross_origin_attacker" in f["title"]


def test_null_origin_detected(monkeypatch) -> None:
    def responder(host, port, use_tls, raw):
        origin = _request_origin(raw.decode("iso-8859-1"))
        if origin == "null":
            return _accept_response()
        # Accept legitimate origin (baseline) too.
        expected = f"{'https' if use_tls else 'http'}://{host}"
        if origin == expected:
            return _accept_response()
        return _reject_response()

    _patch_handshake(monkeypatch, responder)
    out = scan_websocket_auth(
        url="wss://app.example.com/ws",
        probes=["null_origin"],
    )
    assert len(out["findings"]) == 1
    assert out["findings"][0]["cwe"] == "CWE-346"


def test_subdomain_origin_detected(monkeypatch) -> None:
    def responder(host, port, use_tls, raw):
        origin = _request_origin(raw.decode("iso-8859-1"))
        if origin and origin.startswith("https://evil."):
            return _accept_response()
        expected = f"https://{host}"
        if origin == expected:
            return _accept_response()
        return _reject_response()

    _patch_handshake(monkeypatch, responder)
    out = scan_websocket_auth(
        url="wss://app.example.com/ws",
        probes=["subdomain_origin"],
    )
    assert len(out["findings"]) == 1


def test_anonymous_upgrade_detected(monkeypatch) -> None:
    """Probe strips auth headers from the handshake. Server
    accepts → missing-auth finding."""

    def responder(host, port, use_tls, raw):
        text = raw.decode("iso-8859-1")
        if "Cookie:" in text or "Authorization:" in text:
            # Baseline w/ auth: accept.
            return _accept_response()
        # No auth: still accept (vulnerable).
        return _accept_response()

    _patch_handshake(monkeypatch, responder)
    out = scan_websocket_auth(
        url="wss://app.example.com/ws",
        probes=["anonymous_upgrade"],
    )
    assert len(out["findings"]) == 1
    assert out["findings"][0]["cwe"] == "CWE-306"
    assert out["findings"][0]["severity"] == "high"


def test_wildcard_subprotocol_detected(monkeypatch) -> None:
    """Subprotocol echo means no allowlist enforcement."""

    def responder(host, port, use_tls, raw):
        text = raw.decode("iso-8859-1")
        # Find the subprotocol from request.
        proto = None
        for line in text.split("\r\n"):
            if line.lower().startswith("sec-websocket-protocol:"):
                proto = line.split(":", 1)[1].strip()
                break
        headers = {
            "upgrade": "websocket",
            "connection": "Upgrade",
            "sec-websocket-accept": "fake",
        }
        if proto:
            headers["sec-websocket-protocol"] = proto
        return 101, headers, None

    _patch_handshake(monkeypatch, responder)
    out = scan_websocket_auth(
        url="wss://app.example.com/ws",
        probes=["wildcard_subprotocol"],
    )
    assert len(out["findings"]) == 1
    assert out["findings"][0]["cwe"] == "CWE-693"


def test_wildcard_subprotocol_not_echoed_no_finding(monkeypatch) -> None:
    """Server accepts the handshake but does NOT echo the
    subprotocol back → no finding (the server doesn't actually
    enable our fictional protocol)."""

    def responder(host, port, use_tls, raw):
        # Accept without echoing subprotocol.
        return _accept_response()

    _patch_handshake(monkeypatch, responder)
    out = scan_websocket_auth(
        url="wss://app.example.com/ws",
        probes=["wildcard_subprotocol"],
    )
    assert out["findings"] == []


# ---------------------------------------------------------------------------
# URL scheme variants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,expected_tls,expected_port", [
    ("wss://app.example.com/ws", True, 443),
    ("ws://app.example.com/ws", False, 80),
    ("https://app.example.com/ws", True, 443),
    ("http://app.example.com/ws", False, 80),
    ("wss://app.example.com:9443/ws", True, 9443),
    ("ws://app.example.com:8080/ws", False, 8080),
])
def test_url_scheme_parsing(
    monkeypatch, url: str, expected_tls: bool, expected_port: int,
) -> None:
    log = _patch_handshake(monkeypatch, _strict_responder)
    scan_websocket_auth(url=url, probes=["cross_origin_attacker"])
    # First call is the baseline; should target the right
    # (tls, port).
    assert log[0]["use_tls"] is expected_tls
    assert log[0]["port"] == expected_port


def test_invalid_scheme_rejected() -> None:
    out = scan_websocket_auth(url="ftp://app.example.com/ws")
    assert out["status"] == "error"
    assert "unsupported" in out["error"]


def test_empty_url_rejected() -> None:
    out = scan_websocket_auth(url="")
    assert out["status"] == "error"


# ---------------------------------------------------------------------------
# Probe allow-list
# ---------------------------------------------------------------------------


def test_probe_allowlist_narrows_set(monkeypatch) -> None:
    log = _patch_handshake(monkeypatch, _strict_responder)
    out = scan_websocket_auth(
        url="wss://app.example.com/ws",
        probes=["cross_origin_attacker"],
    )
    assert out["tool_metadata"]["probes_run"] == 1
    # 1 baseline + 1 probe = 2 handshakes total.
    assert len(log) == 2


def test_unknown_probe_label_rejected() -> None:
    out = scan_websocket_auth(
        url="wss://app.example.com/ws",
        probes=["nonexistent_probe"],
    )
    assert out["status"] == "error"
    assert "no probes" in out["error"]


# ---------------------------------------------------------------------------
# Custom attacker domain
# ---------------------------------------------------------------------------


def test_custom_attacker_domain_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_ATTACKER_DOMAIN", "https://my-attacker.com")
    log = _patch_handshake(monkeypatch, _strict_responder)
    scan_websocket_auth(
        url="wss://app.example.com/ws",
        probes=["cross_origin_attacker"],
    )
    # Second handshake is the cross-origin probe; should carry
    # the env'd attacker origin.
    probe_request = log[1]["request"]
    assert "Origin: https://my-attacker.com" in probe_request


# ---------------------------------------------------------------------------
# Tracer round-trip
# ---------------------------------------------------------------------------


def test_tracer_emit_carries_websocket_auth_category(monkeypatch) -> None:
    _patch_handshake(monkeypatch, _laxx_origin_responder)
    tracer = tracer_module.get_global_tracer()
    scan_websocket_auth(
        url="wss://app.example.com/ws",
        probes=["cross_origin_attacker"],
    )
    reports = [
        r for r in tracer.vulnerability_reports
        if r.get("category") == "websocket_auth"
    ]
    assert len(reports) >= 1
    r = reports[0]
    assert r.get("severity") == "critical"
    assert r.get("cwe") == "CWE-346"


# ---------------------------------------------------------------------------
# Handshake acceptance semantics
# ---------------------------------------------------------------------------


def test_status_101_without_upgrade_header_not_accepted(monkeypatch) -> None:
    """Server returns 101 but no `Upgrade: websocket` — this is
    malformed and we should NOT treat it as accepted."""

    def responder(host, port, use_tls, raw):
        return 101, {"connection": "Upgrade"}, None  # no Upgrade header

    _patch_handshake(monkeypatch, responder)
    out = scan_websocket_auth(url="wss://app.example.com/ws")
    # Baseline doesn't validate → partial status.
    assert out["status"] == "partial"


def test_status_400_baseline_yields_partial(monkeypatch) -> None:
    """Baseline rejected → can't establish that this IS a
    WebSocket endpoint → partial."""

    def responder(host, port, use_tls, raw):
        return 400, {}, None

    _patch_handshake(monkeypatch, responder)
    out = scan_websocket_auth(url="wss://app.example.com/ws")
    assert out["status"] == "partial"
