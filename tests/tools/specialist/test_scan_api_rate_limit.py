"""Tests for `scan_api_rate_limit` — OWASP API4 (Unrestricted
Resource Consumption) probe.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.specialist.scan_api_rate_limit import (
    _has_rate_limit_signal,
    _is_write_method,
    scan_api_rate_limit,
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_RATE_LIMIT_PROBE_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_RATE_LIMIT_PROBE_MAX_BURST", raising=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_has_rate_limit_signal_detects_retry_after() -> None:
    present, seen = _has_rate_limit_signal({"Retry-After": "60"})
    assert present is True
    assert "Retry-After" in seen


def test_has_rate_limit_signal_detects_x_ratelimit_remaining() -> None:
    present, _ = _has_rate_limit_signal({"X-RateLimit-Remaining": "0"})
    assert present is True


def test_has_rate_limit_signal_case_insensitive() -> None:
    present, _ = _has_rate_limit_signal({"retry-after": "30"})
    assert present is True


def test_has_rate_limit_signal_negative_when_no_headers() -> None:
    present, _ = _has_rate_limit_signal({"Content-Type": "application/json"})
    assert present is False


def test_is_write_method() -> None:
    assert _is_write_method("POST") is True
    assert _is_write_method("PUT") is True
    assert _is_write_method("PATCH") is True
    assert _is_write_method("DELETE") is True
    assert _is_write_method("GET") is False
    assert _is_write_method("get") is False


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------


def _fetcher_always_200(*, url, method, headers, timeout):
    """Endpoint always returns 200 with no rate-limit headers —
    no throttle at all."""
    return 200, {"content-type": "application/json"}


def _fetcher_throttling(*, url, method, headers, timeout):
    """Endpoint returns 429 from the first request."""
    return 429, {"Retry-After": "30"}


def _fetcher_with_signal(*, url, method, headers, timeout):
    """Endpoint returns 200 but with X-RateLimit-* headers
    (soft throttle posture)."""
    return 200, {
        "content-type": "application/json",
        "X-RateLimit-Remaining": "100",
        "X-RateLimit-Limit": "500",
    }


def _fetcher_5xx(*, url, method, headers, timeout):
    """Endpoint returns 500 — error path."""
    return 500, {}


def test_no_throttle_get_emits_medium_finding() -> None:
    result = scan_api_rate_limit(
        url="https://api.example.com/users",
        method="GET",
        burst=10,
        interval_seconds=0.0,   # speed up tests
        _fetcher=_fetcher_always_200,
    )
    assert result["status"] == "ok"
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["severity"] == "medium"
    assert f["cwe"] == "CWE-770"


def test_no_throttle_write_method_emits_high_finding() -> None:
    """Write endpoints get higher severity — credential stuffing
    / abuse vector when unthrottled."""
    result = scan_api_rate_limit(
        url="https://api.example.com/users",
        method="POST",
        burst=10,
        interval_seconds=0.0,
        _fetcher=_fetcher_always_200,
    )
    assert result["findings"][0]["severity"] == "high"


def test_no_throttle_auth_walled_get_emits_high() -> None:
    """Auth-walled GET with no rate limit → high severity."""
    result = scan_api_rate_limit(
        url="https://api.example.com/users",
        method="GET", auth_walled=True,
        burst=10, interval_seconds=0.0,
        _fetcher=_fetcher_always_200,
    )
    assert result["findings"][0]["severity"] == "high"


def test_throttle_observed_no_finding() -> None:
    """When the target throttles, no finding fires."""
    result = scan_api_rate_limit(
        url="https://api.example.com/users",
        burst=30, interval_seconds=0.0,
        _fetcher=_fetcher_throttling,
    )
    assert result["findings"] == []
    # Auto-stops on early 429 — fewer than burst observations.
    observations = result["tool_metadata"]["observations"]
    assert len(observations) <= 5


def test_signal_headers_observed_no_finding() -> None:
    """X-RateLimit-* headers count as throttle signal even
    without a 429."""
    result = scan_api_rate_limit(
        url="https://api.example.com/users",
        burst=10, interval_seconds=0.0,
        _fetcher=_fetcher_with_signal,
    )
    assert result["findings"] == []
    assert result["tool_metadata"]["analysis"]["verdict"] == "rate_limited"


def test_5xx_in_burst_auto_stops_no_finding() -> None:
    """When the target 5xxes early, we stop — don't emit a
    finding for what might be intentional load shedding."""
    result = scan_api_rate_limit(
        url="https://api.example.com/users",
        burst=30, interval_seconds=0.0,
        _fetcher=_fetcher_5xx,
    )
    assert result["findings"] == []
    observations = result["tool_metadata"]["observations"]
    assert len(observations) <= 5


# ---------------------------------------------------------------------------
# Safety + failure modes
# ---------------------------------------------------------------------------


def test_kill_switch_returns_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_RATE_LIMIT_PROBE_DISABLED", "1")
    result = scan_api_rate_limit(
        url="https://api.example.com/x", burst=10,
        _fetcher=_fetcher_always_200,
    )
    assert result["status"] == "error"
    assert "kill_switch" in result["error"]


def test_invalid_url_scheme_rejected() -> None:
    result = scan_api_rate_limit(
        url="ftp://example.com", _fetcher=_fetcher_always_200,
    )
    assert result["status"] == "error"


def test_empty_url_rejected() -> None:
    result = scan_api_rate_limit(
        url="", _fetcher=_fetcher_always_200,
    )
    assert result["status"] == "error"


def test_hard_cap_respected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_RATE_LIMIT_PROBE_MAX_BURST", "5")
    result = scan_api_rate_limit(
        url="https://api.example.com/x",
        burst=500,   # tries to exceed cap
        interval_seconds=0.0,
        _fetcher=_fetcher_always_200,
    )
    observations = result["tool_metadata"]["observations"]
    assert len(observations) <= 5
