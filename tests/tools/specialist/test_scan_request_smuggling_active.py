"""Tests for §workitem.md Phase 2.10 — `scan_request_smuggling_active`
(CWE-444 timing-based smuggle confirmation).

Pins:
  * Hung socket on smuggle probe → finding
  * Elapsed > 3× baseline AND > 4s → finding
  * All probes match baseline → no finding
  * Baseline failure → status=error
  * Default + custom thresholds
  * SecurityContext + decision_log
  * Registry / catalog wiring

The actual raw-socket probe is mocked via monkeypatching
`_send_raw` so the tests don't need a real listener.
"""

from __future__ import annotations

import pytest


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
    set_global_tracer(Tracer("test-smuggle"))
    yield


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


def _patch_send_raw(monkeypatch, side_effect):
    """Replace `_send_raw` with a stand-in that returns one of the
    pre-canned (elapsed, body, err) tuples per call.

    `side_effect` may be:
      - a callable taking (host, port, use_tls, raw_request, timeout)
        and returning (elapsed, body_bytes, err_or_None)
      - a list of such tuples consumed sequentially
    """
    from strix.tools.specialist import scan_request_smuggling_active as mod

    if callable(side_effect):
        monkeypatch.setattr(mod, "_send_raw", side_effect)
        return None
    seq = list(side_effect)

    def _next(*args, **kwargs):
        return seq.pop(0)

    monkeypatch.setattr(mod, "_send_raw", _next)
    return seq


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    from strix.tools.specialist.scan_request_smuggling_active import (
        scan_request_smuggling_active,
    )
    out = scan_request_smuggling_active(url="")
    assert out["status"] == "error"


def test_invalid_url_returns_error() -> None:
    from strix.tools.specialist.scan_request_smuggling_active import (
        scan_request_smuggling_active,
    )
    out = scan_request_smuggling_active(url="not-a-url")
    assert out["status"] == "error"


def test_baseline_failure_returns_error(monkeypatch) -> None:
    """If all 3 baseline samples error → status=error (can't establish baseline)."""
    from strix.tools.specialist.scan_request_smuggling_active import (
        scan_request_smuggling_active,
    )
    _patch_send_raw(monkeypatch, lambda *a, **kw: (0.0, b"", "ConnectionError: refused"))
    out = scan_request_smuggling_active(url="http://target.example.com/")
    assert out["status"] == "error"
    assert "baseline" in out["error"].lower()


# ---------------------------------------------------------------------------
# Hung socket / timing detection
# ---------------------------------------------------------------------------


def test_hung_socket_emits_critical(monkeypatch) -> None:
    """Baseline returns 200 in 0.1s; smuggle probe hangs (timeout)."""
    from strix.tools.specialist.scan_request_smuggling_active import (
        scan_request_smuggling_active,
    )

    call_count = [0]

    def stub(host, port, *, use_tls, raw_request, timeout):
        call_count[0] += 1
        # First three calls = baseline (3 samples).
        if call_count[0] <= 3:
            return (0.1, b"HTTP/1.1 200 OK\r\n\r\nok", None)
        # Subsequent calls = probes; first probe hangs.
        if call_count[0] == 4:
            return (timeout, b"", "timeout")
        return (0.1, b"HTTP/1.1 400\r\n\r\n", None)

    monkeypatch.setattr(
        "strix.tools.specialist.scan_request_smuggling_active._send_raw",
        stub,
    )
    out = scan_request_smuggling_active(
        url="http://target.example.com/",
        timeout_seconds=8.0,
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) >= 1
    f = out["findings"][0]
    assert f["category"] == "http_request_smuggling"
    assert f["cwe"] == "CWE-444"
    assert f["severity"] == "critical"


def test_elapsed_3x_baseline_emits(monkeypatch) -> None:
    """Probe elapsed = 5s, baseline = 0.5s → 10× ratio, > 4s absolute → finding."""
    from strix.tools.specialist.scan_request_smuggling_active import (
        scan_request_smuggling_active,
    )

    call_count = [0]

    def stub(host, port, *, use_tls, raw_request, timeout):
        call_count[0] += 1
        if call_count[0] <= 3:
            return (0.5, b"baseline ok", None)
        # First probe is slow.
        if call_count[0] == 4:
            return (5.0, b"slow response", None)
        return (0.5, b"normal", None)

    monkeypatch.setattr(
        "strix.tools.specialist.scan_request_smuggling_active._send_raw",
        stub,
    )
    out = scan_request_smuggling_active(url="http://target.example.com/")
    assert len(out["findings"]) >= 1


def test_below_threshold_no_finding(monkeypatch) -> None:
    """Probe elapsed = 1.5s, baseline = 1.0s → 1.5× < 3× → no finding."""
    from strix.tools.specialist.scan_request_smuggling_active import (
        scan_request_smuggling_active,
    )

    def stub(host, port, *, use_tls, raw_request, timeout):
        return (1.5, b"ok", None)

    monkeypatch.setattr(
        "strix.tools.specialist.scan_request_smuggling_active._send_raw",
        stub,
    )
    out = scan_request_smuggling_active(url="http://target.example.com/")
    # All elapsed are similar — no smuggle confirmed.
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_high_ratio_but_short_absolute_no_finding(monkeypatch) -> None:
    """Probe = 0.5s, baseline = 0.1s → 5× ratio BUT < 4s absolute → no finding."""
    from strix.tools.specialist.scan_request_smuggling_active import (
        scan_request_smuggling_active,
    )

    call_count = [0]

    def stub(host, port, *, use_tls, raw_request, timeout):
        call_count[0] += 1
        if call_count[0] <= 3:
            return (0.1, b"ok", None)
        return (0.5, b"slightly slower", None)

    monkeypatch.setattr(
        "strix.tools.specialist.scan_request_smuggling_active._send_raw",
        stub,
    )
    out = scan_request_smuggling_active(url="http://target.example.com/")
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Threshold customisation
# ---------------------------------------------------------------------------


def test_lower_threshold_admits_borderline(monkeypatch) -> None:
    """With timing_threshold_seconds=0.3, a 0.5s probe (5× baseline)
    should now count."""
    from strix.tools.specialist.scan_request_smuggling_active import (
        scan_request_smuggling_active,
    )

    call_count = [0]

    def stub(host, port, *, use_tls, raw_request, timeout):
        call_count[0] += 1
        if call_count[0] <= 3:
            return (0.05, b"ok", None)
        return (0.5, b"slow", None)

    monkeypatch.setattr(
        "strix.tools.specialist.scan_request_smuggling_active._send_raw",
        stub,
    )
    out = scan_request_smuggling_active(
        url="http://target.example.com/",
        timing_threshold_seconds=0.3,
        timing_threshold_ratio=3.0,
    )
    assert len(out["findings"]) >= 1


# ---------------------------------------------------------------------------
# HTTPS uses TLS path
# ---------------------------------------------------------------------------


def test_https_url_sets_use_tls(monkeypatch) -> None:
    captured: list[bool] = []

    def stub(host, port, *, use_tls, raw_request, timeout):
        captured.append(use_tls)
        return (0.1, b"ok", None)

    monkeypatch.setattr(
        "strix.tools.specialist.scan_request_smuggling_active._send_raw",
        stub,
    )
    from strix.tools.specialist.scan_request_smuggling_active import (
        scan_request_smuggling_active,
    )
    scan_request_smuggling_active(url="https://target.example.com/")
    assert all(captured)  # every call was use_tls=True


def test_http_url_does_not_use_tls(monkeypatch) -> None:
    captured: list[bool] = []

    def stub(host, port, *, use_tls, raw_request, timeout):
        captured.append(use_tls)
        return (0.1, b"ok", None)

    monkeypatch.setattr(
        "strix.tools.specialist.scan_request_smuggling_active._send_raw",
        stub,
    )
    from strix.tools.specialist.scan_request_smuggling_active import (
        scan_request_smuggling_active,
    )
    scan_request_smuggling_active(url="http://target.example.com/")
    assert not any(captured)  # no calls used TLS


# ---------------------------------------------------------------------------
# Decision log
# ---------------------------------------------------------------------------


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    monkeypatch.setattr(
        "strix.tools.specialist.scan_request_smuggling_active._send_raw",
        lambda *a, **kw: (0.1, b"ok", None),
    )
    from strix.tools.specialist.scan_request_smuggling_active import (
        scan_request_smuggling_active,
    )
    scan_request_smuggling_active(url="http://target.example.com/")
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_request_smuggling_active"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_request_smuggling_active_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_request_smuggling_active")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "request-smuggling-specialist"


def test_scan_request_smuggling_active_in_lead_web_application_catalog(monkeypatch) -> None:
    """iter-37.2 — deprecated tool; visible only under STRIX_LEGACY_CATALOG=1."""
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_request_smuggling_active" in catalog
