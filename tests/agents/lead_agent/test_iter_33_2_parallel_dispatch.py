"""Tests for iter-33.2 — parallel specialist dispatch.

Verifies the iter-33.2 refactor of `shape_aware_dispatch`:
- Per-endpoint body extracted into `_probe_one_endpoint`
- Concurrency controlled by `STRIX_DISPATCH_CONCURRENCY` env var
- `_PerEndpointResult` is thread-safe (no shared mutation)
- Outer loop merges results single-threaded
- Default behavior (concurrency=1) preserves iter-30 serial flow
"""

from __future__ import annotations

import os
import threading
import time
from unittest.mock import patch, MagicMock

import pytest

from strix.agents.lead_agent.shape_aware_dispatcher import (
    DispatchSummary,
    _PerEndpointResult,
    _dispatch_concurrency,
    _probe_one_endpoint,
    shape_aware_dispatch,
)


# ---------------------------------------------------------------------------
# Env-gate for concurrency
# ---------------------------------------------------------------------------

def test_concurrency_default_is_1():
    """No env → serial. Preserves iter-30 behavior."""
    os.environ.pop("STRIX_DISPATCH_CONCURRENCY", None)
    assert _dispatch_concurrency() == 1


def test_concurrency_respects_env_value():
    for val, expected in [("1", 1), ("2", 2), ("8", 8), ("16", 16)]:
        os.environ["STRIX_DISPATCH_CONCURRENCY"] = val
        assert _dispatch_concurrency() == expected, f"failed for {val!r}"
    os.environ.pop("STRIX_DISPATCH_CONCURRENCY", None)


def test_concurrency_clamps_to_safe_range():
    """Out-of-range values get clamped to [1, 16] (no DoS-by-misconfig)."""
    for val, expected in [("0", 1), ("-5", 1), ("100", 16), ("9999", 16)]:
        os.environ["STRIX_DISPATCH_CONCURRENCY"] = val
        assert _dispatch_concurrency() == expected, f"failed for {val!r}"
    os.environ.pop("STRIX_DISPATCH_CONCURRENCY", None)


def test_concurrency_garbage_value_returns_1():
    for val in ("not-a-number", "", "two", "1.5"):
        os.environ["STRIX_DISPATCH_CONCURRENCY"] = val
        assert _dispatch_concurrency() == 1, f"failed for {val!r}"
    os.environ.pop("STRIX_DISPATCH_CONCURRENCY", None)


# ---------------------------------------------------------------------------
# _PerEndpointResult
# ---------------------------------------------------------------------------

def test_per_endpoint_result_default_state():
    r = _PerEndpointResult(endpoint_url="http://app/x")
    assert r.endpoint_url == "http://app/x"
    assert r.classify_failed is False
    assert r.static_skipped is False
    assert r.destructive_skipped is False
    assert r.probed is False
    assert r.payloads_fired == 0
    assert r.signals_above_threshold == 0
    assert r.findings == []


# ---------------------------------------------------------------------------
# _probe_one_endpoint — classification failure path
# ---------------------------------------------------------------------------

def test_probe_one_endpoint_classify_failure_returns_no_probe():
    ep = {"url": "http://app/x", "method": "GET", "params": []}
    with patch(
        "strix.agents.lead_agent.shape_aware_dispatcher.classify_endpoint",
        side_effect=RuntimeError("synthetic"),
    ):
        result = _probe_one_endpoint(ep, timeout=5, governor=MagicMock())
    assert result.classify_failed is True
    assert result.probed is False
    assert result.findings == []


def test_probe_one_endpoint_static_asset_skips():
    """Static-asset endpoints don't get payloaded."""
    ep = {"url": "http://app/logo.png", "method": "GET", "params": []}
    fake_profile = MagicMock()
    fake_profile.endpoint_class = "static-asset"
    fake_profile.shape = "static"
    with patch(
        "strix.agents.lead_agent.shape_aware_dispatcher.classify_endpoint",
        return_value=fake_profile,
    ):
        result = _probe_one_endpoint(ep, timeout=5, governor=MagicMock())
    assert result.static_skipped is True
    assert result.probed is False


def test_probe_one_endpoint_destructive_skips():
    """Destructive endpoints (DELETE on /admin/users/{id}) refused."""
    ep = {"url": "http://app/admin/users/1", "method": "DELETE", "params": []}
    fake_profile = MagicMock()
    fake_profile.endpoint_class = "destructive"
    fake_profile.shape = "rest"
    with patch(
        "strix.agents.lead_agent.shape_aware_dispatcher.classify_endpoint",
        return_value=fake_profile,
    ), patch(
        "strix.agents.lead_agent.shape_aware_dispatcher.check_destructive",
        return_value=(False, "destructive"),
    ):
        result = _probe_one_endpoint(ep, timeout=5, governor=MagicMock())
    assert result.destructive_skipped is True


# ---------------------------------------------------------------------------
# shape_aware_dispatch concurrency wiring
# ---------------------------------------------------------------------------

def test_shape_aware_dispatch_records_concurrency_used():
    """DispatchSummary.concurrency_used reflects the env value at scan
    start."""
    os.environ["STRIX_DISPATCH_CONCURRENCY"] = "4"
    try:
        # Empty endpoints → quick return path
        summary = shape_aware_dispatch(
            "http://app", forms=[], endpoints=[], timeout=1,
        )
        assert summary.concurrency_used == 4
    finally:
        os.environ.pop("STRIX_DISPATCH_CONCURRENCY", None)


def test_shape_aware_dispatch_serial_default():
    """Without env, defaults to concurrency=1 (serial path)."""
    os.environ.pop("STRIX_DISPATCH_CONCURRENCY", None)
    summary = shape_aware_dispatch(
        "http://app", forms=[], endpoints=[], timeout=1,
    )
    assert summary.concurrency_used == 1


def test_shape_aware_dispatch_parallel_runs_endpoints_concurrently(monkeypatch):
    """When concurrency > 1, multiple `_probe_one_endpoint` calls run
    concurrently. We verify by recording the calling thread name on
    each invocation — under parallelism they should not all be 'MainThread'."""
    monkeypatch.setenv("STRIX_DISPATCH_CONCURRENCY", "4")

    invocations: list[tuple[str, str]] = []  # (endpoint_url, thread_name)
    invocation_lock = threading.Lock()

    def _slow_probe(ep, timeout, governor):
        # Record + simulate work so threads actually overlap
        with invocation_lock:
            invocations.append((ep.get("url"), threading.current_thread().name))
        time.sleep(0.05)  # 50ms — enough to ensure overlap
        return _PerEndpointResult(endpoint_url=ep.get("url", ""))

    monkeypatch.setattr(
        "strix.agents.lead_agent.shape_aware_dispatcher._probe_one_endpoint",
        _slow_probe,
    )

    # 8 endpoints, concurrency 4 → at least some should run on non-Main threads
    endpoints = [
        {"url": f"http://app/ep-{i}", "method": "GET", "params": []}
        for i in range(8)
    ]
    summary = shape_aware_dispatch(
        "http://app", forms=[], endpoints=endpoints, timeout=1,
    )
    assert summary.concurrency_used == 4
    assert len(invocations) == 8
    thread_names = {t for (_url, t) in invocations}
    # Parallel run: at least 2 distinct thread names
    assert len(thread_names) >= 2, (
        f"expected multiple threads, got: {thread_names}"
    )


def test_shape_aware_dispatch_parallel_faster_than_serial(monkeypatch):
    """Parallel dispatch should produce wall-time speedup over serial
    on N independent endpoints with simulated latency."""
    invocations: list[float] = []

    def _slow_probe(ep, timeout, governor):
        time.sleep(0.1)  # 100ms per endpoint
        return _PerEndpointResult(endpoint_url=ep.get("url", ""))

    monkeypatch.setattr(
        "strix.agents.lead_agent.shape_aware_dispatcher._probe_one_endpoint",
        _slow_probe,
    )

    endpoints = [
        {"url": f"http://app/ep-{i}", "method": "GET", "params": []}
        for i in range(6)
    ]

    # Serial
    monkeypatch.delenv("STRIX_DISPATCH_CONCURRENCY", raising=False)
    t0 = time.monotonic()
    shape_aware_dispatch("http://app", forms=[], endpoints=endpoints, timeout=1)
    serial_elapsed = time.monotonic() - t0

    # Parallel
    monkeypatch.setenv("STRIX_DISPATCH_CONCURRENCY", "6")
    t0 = time.monotonic()
    shape_aware_dispatch("http://app", forms=[], endpoints=endpoints, timeout=1)
    parallel_elapsed = time.monotonic() - t0

    # Serial = ~600ms (6 × 100ms). Parallel = ~100ms (6 in parallel).
    # Conservative check: parallel should be at least 2x faster.
    assert parallel_elapsed < serial_elapsed * 0.6, (
        f"parallel ({parallel_elapsed:.3f}s) not meaningfully faster than "
        f"serial ({serial_elapsed:.3f}s)"
    )


def test_shape_aware_dispatch_parallel_merges_all_results(monkeypatch):
    """Every endpoint's _PerEndpointResult should be merged into the
    summary regardless of thread completion order."""
    monkeypatch.setenv("STRIX_DISPATCH_CONCURRENCY", "3")

    def _probe_with_findings(ep, timeout, governor):
        from strix.agents.lead_agent.shape_aware_dispatcher import DispatchFinding
        result = _PerEndpointResult(endpoint_url=ep.get("url", ""))
        result.probed = True
        result.payloads_fired = 2
        # Simulate one finding per endpoint
        finding = DispatchFinding(
            endpoint=ep.get("url", ""),
            method="GET",
            vuln_class="sqli",
            payload_excerpt="x",
            confidence="verified",
            score=0.9,
            reasons=["test"],
        )
        result.findings.append(finding)
        result.finding_profiles.append(MagicMock())
        return result

    monkeypatch.setattr(
        "strix.agents.lead_agent.shape_aware_dispatcher._probe_one_endpoint",
        _probe_with_findings,
    )
    # Avoid actually emitting to tracer
    monkeypatch.setattr(
        "strix.agents.lead_agent.shape_aware_dispatcher._emit_to_tracer",
        lambda *a, **k: None,
    )

    endpoints = [
        {"url": f"http://app/ep-{i}", "method": "GET", "params": []}
        for i in range(5)
    ]
    summary = shape_aware_dispatch(
        "http://app", forms=[], endpoints=endpoints, timeout=1,
    )
    assert len(summary.findings) == 5
    assert summary.endpoints_probed == 5
    assert summary.payloads_fired == 10


def test_shape_aware_dispatch_parallel_handles_worker_crash(monkeypatch):
    """A crash in one worker shouldn't kill the rest of the scan."""
    monkeypatch.setenv("STRIX_DISPATCH_CONCURRENCY", "3")

    call_count = {"n": 0}

    def _flaky_probe(ep, timeout, governor):
        call_count["n"] += 1
        if "crash" in ep.get("url", ""):
            raise RuntimeError("synthetic crash")
        return _PerEndpointResult(endpoint_url=ep.get("url", ""), probed=True)

    monkeypatch.setattr(
        "strix.agents.lead_agent.shape_aware_dispatcher._probe_one_endpoint",
        _flaky_probe,
    )

    endpoints = [
        {"url": "http://app/ep-1", "method": "GET", "params": []},
        {"url": "http://app/ep-crash", "method": "GET", "params": []},
        {"url": "http://app/ep-2", "method": "GET", "params": []},
    ]
    # Must not raise
    summary = shape_aware_dispatch(
        "http://app", forms=[], endpoints=endpoints, timeout=1,
    )
    # All 3 attempted; 2 successful, 1 crashed but absorbed
    assert call_count["n"] == 3
    assert summary.endpoints_probed == 2  # crash didn't probe


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_strings():
    """No SUT-specific tokens in the iter-33.2 additions."""
    import strix.agents.lead_agent.shape_aware_dispatcher as mod
    src = open(mod.__file__).read()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "/users/v1/_debug", "vampi", "erev0s",
    )
    for tok in forbidden:
        assert tok not in src.lower(), (
            f"SUT-specific token {tok!r} in dispatcher"
        )
