"""Tests for HTTP-safety middleware: auth-injection, exclude-path, rate-limit.

Roadmap §2 + §3. Hermetic — no actual network calls. The middleware reads
env vars directly so tests just monkeypatch env.
"""

from __future__ import annotations

import base64
import json
import time

import pytest

from strix.tools.proxy import http_safety


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch) -> None:
    """Strip every STRIX_* env var our middleware reads, then reset rate
    limiter state between tests."""
    for k in (
        "STRIX_AUTH_COOKIE",
        "STRIX_AUTH_BEARER",
        "STRIX_AUTH_BASIC",
        "STRIX_HEADERS",
        "STRIX_EXCLUDE_PATHS",
        "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    yield


# ---------------------------------------------------------------------------
# inject_auth_headers
# ---------------------------------------------------------------------------


def test_no_env_no_injection() -> None:
    assert http_safety.inject_auth_headers({"X-User": "alice"}) == {"X-User": "alice"}


def test_cookie_injected(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_AUTH_COOKIE", "session=abc; auth=xyz")
    out = http_safety.inject_auth_headers({})
    assert out["Cookie"] == "session=abc; auth=xyz"


def test_bearer_injected(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_AUTH_BEARER", "tok-123")
    out = http_safety.inject_auth_headers({})
    assert out["Authorization"] == "Bearer tok-123"


def test_basic_auth_base64_encoded(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_AUTH_BASIC", "alice:s3cret")
    out = http_safety.inject_auth_headers({})
    expected = base64.b64encode(b"alice:s3cret").decode("ascii")
    assert out["Authorization"] == f"Basic {expected}"


def test_basic_auth_malformed_no_injection(monkeypatch) -> None:
    """STRIX_AUTH_BASIC without a colon is malformed — skip silently."""
    monkeypatch.setenv("STRIX_AUTH_BASIC", "no-colon-here")
    out = http_safety.inject_auth_headers({})
    assert "Authorization" not in out


def test_bearer_takes_priority_over_basic(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_AUTH_BEARER", "tok-123")
    monkeypatch.setenv("STRIX_AUTH_BASIC", "alice:s3cret")
    out = http_safety.inject_auth_headers({})
    assert out["Authorization"].startswith("Bearer ")


def test_agent_authorization_wins(monkeypatch) -> None:
    """If the agent already set Authorization, env values must NOT clobber.
    The agent might be testing a specific auth scenario."""
    monkeypatch.setenv("STRIX_AUTH_BEARER", "global-tok")
    out = http_safety.inject_auth_headers({"Authorization": "Bearer agent-tok"})
    assert out["Authorization"] == "Bearer agent-tok"


def test_agent_cookie_wins(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_AUTH_COOKIE", "global=x")
    out = http_safety.inject_auth_headers({"Cookie": "agent=y"})
    assert out["Cookie"] == "agent=y"


def test_custom_headers_from_env(monkeypatch) -> None:
    monkeypatch.setenv(
        "STRIX_HEADERS",
        json.dumps(["X-API-Key:secret-key-abc", "X-Forwarded-For:1.2.3.4"]),
    )
    out = http_safety.inject_auth_headers({})
    assert out["X-API-Key"] == "secret-key-abc"
    assert out["X-Forwarded-For"] == "1.2.3.4"


def test_custom_header_with_colon_in_value(monkeypatch) -> None:
    """Custom header value with a colon should split only on the first colon."""
    monkeypatch.setenv("STRIX_HEADERS", json.dumps(["X-Trace:run:abc:123"]))
    out = http_safety.inject_auth_headers({})
    assert out["X-Trace"] == "run:abc:123"


def test_custom_headers_dont_clobber_agent(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_HEADERS", json.dumps(["X-API-Key:env-key"]))
    out = http_safety.inject_auth_headers({"X-API-Key": "agent-key"})
    assert out["X-API-Key"] == "agent-key"


def test_custom_headers_malformed_skipped(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_HEADERS", json.dumps(["no-colon", "", ":empty-name"]))
    out = http_safety.inject_auth_headers({})
    # Only 'empty-name' would have been added, but it has no name.
    assert out == {}


def test_custom_headers_invalid_json_silently_ignored(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_HEADERS", "not-json")
    out = http_safety.inject_auth_headers({"X-User": "alice"})
    assert out == {"X-User": "alice"}


# ---------------------------------------------------------------------------
# is_path_excluded
# ---------------------------------------------------------------------------


def test_no_excludes_returns_false() -> None:
    excluded, glob = http_safety.is_path_excluded("https://example.com/admin/delete")
    assert excluded is False
    assert glob is None


def test_exact_path_match(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", json.dumps(["/api/billing/charge"]))
    excluded, glob = http_safety.is_path_excluded(
        "https://example.com/api/billing/charge"
    )
    assert excluded is True
    assert glob == "/api/billing/charge"


def test_glob_match(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", json.dumps(["/admin/*"]))
    excluded, _ = http_safety.is_path_excluded("https://example.com/admin/delete-user")
    assert excluded is True


def test_query_string_ignored(monkeypatch) -> None:
    """Query parameters can't be used to dodge an exclude-path glob."""
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", json.dumps(["/admin/*"]))
    excluded, _ = http_safety.is_path_excluded(
        "https://example.com/admin/destroy?confirm=yes"
    )
    assert excluded is True


def test_unrelated_path_not_excluded(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", json.dumps(["/admin/*"]))
    excluded, _ = http_safety.is_path_excluded("https://example.com/api/users")
    assert excluded is False


def test_first_matching_glob_wins(monkeypatch) -> None:
    monkeypatch.setenv(
        "STRIX_EXCLUDE_PATHS",
        json.dumps(["/admin/*", "/admin/delete*"]),
    )
    _, glob = http_safety.is_path_excluded("https://example.com/admin/delete-user")
    assert glob == "/admin/*"  # first one in the list wins


def test_excluded_response_shape() -> None:
    out = http_safety.excluded_response("https://example.com/admin/x", "/admin/*")
    assert out["skipped"] is True
    assert out["reason"] == "excluded"
    assert out["matched_glob"] == "/admin/*"
    assert out["url"] == "https://example.com/admin/x"
    assert "do not retry" in out["message"].lower()


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


def test_no_rate_limit_no_throttle(monkeypatch) -> None:
    """Without STRIX_RATE_LIMIT set, throttle_for_rate_limit is a no-op."""
    start = time.monotonic()
    http_safety.throttle_for_rate_limit()
    http_safety.throttle_for_rate_limit()
    elapsed = time.monotonic() - start
    assert elapsed < 0.05  # essentially zero


def test_rate_limit_throttles_consecutive_calls(monkeypatch) -> None:
    """At 10 qps, two consecutive calls should be ≥ ~0.1s apart."""
    monkeypatch.setenv("STRIX_RATE_LIMIT", "10")
    start = time.monotonic()
    http_safety.throttle_for_rate_limit()
    http_safety.throttle_for_rate_limit()
    elapsed = time.monotonic() - start
    # Allow some scheduler slack but must be at least the min interval.
    assert elapsed >= 0.08  # 0.1s expected, 80ms lower bound for OS jitter


def test_rate_limit_invalid_value_no_throttle(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_RATE_LIMIT", "not-a-number")
    start = time.monotonic()
    for _ in range(3):
        http_safety.throttle_for_rate_limit()
    assert time.monotonic() - start < 0.05


def test_rate_limit_zero_or_negative_no_throttle(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_RATE_LIMIT", "0")
    start = time.monotonic()
    for _ in range(3):
        http_safety.throttle_for_rate_limit()
    assert time.monotonic() - start < 0.05


def test_rate_limiter_resets_for_testing() -> None:
    http_safety._RATE_LIMIT_LAST_REQUEST_TS.append(time.monotonic())
    http_safety.reset_rate_limiter_for_testing()
    assert http_safety._RATE_LIMIT_LAST_REQUEST_TS == []
