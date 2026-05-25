"""Tests for iter-29.9 — destructive + rate-limit guards."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from strix.l15.safety_guards import (
    RateLimitGovernor,
    check_destructive,
    destructive_ok,
    get_governor,
    is_destructive_endpoint,
)


# ---------------------------------------------------------------------------
# Destructive guard
# ---------------------------------------------------------------------------

def test_destructive_class_from_profile():
    yes, why = is_destructive_endpoint(
        "http://app/api/users/42", method="GET",
        endpoint_class="destructive",
    )
    assert yes
    assert "endpoint_class=destructive" in why


def test_destructive_method_delete():
    yes, why = is_destructive_endpoint("http://app/api/users/42", method="DELETE")
    assert yes
    assert "DELETE" in why


def test_destructive_method_patch():
    yes, why = is_destructive_endpoint("http://app/api/users/42", method="PATCH")
    assert yes


def test_not_destructive_get_safe_path():
    yes, why = is_destructive_endpoint("http://app/api/users", method="GET")
    assert not yes


def test_destructive_path_token_drop():
    yes, why = is_destructive_endpoint("http://app/admin/drop-database", method="POST")
    assert yes
    assert "drop" in why


def test_destructive_path_token_wipe():
    yes, why = is_destructive_endpoint("http://app/api/wipe", method="GET")
    assert yes


def test_check_destructive_refused_by_default(monkeypatch):
    monkeypatch.delenv("STRIX_DESTRUCTIVE_OK", raising=False)
    ok, reason = check_destructive("http://app/api/u/1", method="DELETE")
    assert not ok
    assert "destructive guard refused" in reason


def test_check_destructive_bypassed_with_env(monkeypatch):
    monkeypatch.setenv("STRIX_DESTRUCTIVE_OK", "1")
    ok, reason = check_destructive("http://app/api/u/1", method="DELETE")
    assert ok
    assert "STRIX_DESTRUCTIVE_OK=1" in reason


def test_check_destructive_safe_endpoint_passes():
    ok, _ = check_destructive("http://app/", method="GET")
    assert ok


def test_destructive_ok_recognizes_truthy_values(monkeypatch):
    for v in ("1", "true", "yes", "TRUE"):
        monkeypatch.setenv("STRIX_DESTRUCTIVE_OK", v)
        assert destructive_ok()
    monkeypatch.setenv("STRIX_DESTRUCTIVE_OK", "0")
    assert not destructive_ok()


# ---------------------------------------------------------------------------
# Rate-limit governor
# ---------------------------------------------------------------------------

@pytest.fixture
def governor():
    g = RateLimitGovernor()
    return g


def test_governor_no_delay_when_no_history(governor):
    assert governor.delay_for("api.example.com") == 0.0


def test_governor_records_429_triggers_cooldown(governor):
    governor.record_response("api.example.com", status=429)
    delay = governor.delay_for("api.example.com")
    assert delay > 0
    # Default cooldown after 429 is 30s
    assert delay >= 1.0


def test_governor_honors_retry_after_header(governor):
    governor.record_response("api.example.com", status=429, retry_after=15)
    delay = governor.delay_for("api.example.com")
    assert delay == 15.0


def test_governor_below_threshold_no_backoff(governor):
    """5 healthy + 0 rate-limited = 0% ratio = no delay."""
    for _ in range(5):
        governor.record_response("h.example.com", status=200)
    assert governor.delay_for("h.example.com") == 0.0


def test_governor_ratio_over_threshold_triggers_backoff(governor):
    """10/30 = 33% rate-limited → high rung of delay ladder."""
    for _ in range(20):
        governor.record_response("h.example.com", status=200)
    for _ in range(10):
        governor.record_response("h.example.com", status=429)
    # Ratio = 10/30 = 33%, should trigger backoff
    delay = governor.delay_for("h.example.com")
    assert delay >= 2.0


def test_governor_recovers_when_ratio_drops(governor):
    """After a burst of 429s, healthy responses should bring delay down."""
    for _ in range(20):
        governor.record_response("h.example.com", status=429)
    high_delay = governor.delay_for("h.example.com")
    assert high_delay >= 5.0
    # Many healthy responses bring ratio below 10%
    for _ in range(200):
        governor.record_response("h.example.com", status=200)
    low_delay = governor.delay_for("h.example.com")
    assert low_delay < high_delay


def test_governor_per_host_isolation(governor):
    """One host hitting 429 doesn't slow another."""
    for _ in range(5):
        governor.record_response("api.a.com", status=429)
    governor.record_response("api.b.com", status=200)
    assert governor.delay_for("api.a.com") > 0
    assert governor.delay_for("api.b.com") == 0.0


def test_governor_stats_for_host(governor):
    governor.record_response("h.example.com", status=200)
    governor.record_response("h.example.com", status=429)
    stats = governor.stats_for("h.example.com")
    assert stats["total"] == 2
    assert stats["rate_limited"] == 1
    assert stats["ratio"] == 0.5
    assert stats["current_delay_s"] > 0


def test_governor_reset_clears_state(governor):
    governor.record_response("h.example.com", status=429)
    governor.reset("h.example.com")
    assert governor.delay_for("h.example.com") == 0.0


def test_governor_reset_all(governor):
    governor.record_response("h1", status=429)
    governor.record_response("h2", status=429)
    governor.reset()
    assert governor.delay_for("h1") == 0.0
    assert governor.delay_for("h2") == 0.0


def test_before_request_blocks_when_delay_active(governor):
    """before_request should sleep for delay_for()."""
    governor.record_response("h.example.com", status=429, retry_after=0.2)
    t0 = time.monotonic()
    governor.before_request("h.example.com")
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.15  # ≥ 0.2s minus tolerance


def test_get_governor_returns_singleton():
    g1 = get_governor()
    g2 = get_governor()
    assert g1 is g2
