"""Tests for HTTP-safety integration into proxy_manager.send_simple_request.

Hermetic — `requests.request` is mocked at the proxy_manager namespace.
We're testing the wiring of http_safety into the request path: that
auth headers get injected, excluded paths are blocked before dispatch,
rate-limit fires before dispatch.
"""

from __future__ import annotations

import json
import time

import pytest

from strix.tools.proxy import http_safety
from strix.tools.proxy.proxy_manager import ProxyManager


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch) -> None:
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


class _FakeResponse:
    def __init__(self, status: int = 200, text: str = "ok", headers: dict | None = None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.url = "https://example.com/"


def _patch_requests(monkeypatch) -> list[dict]:
    """Replace requests.request with a recorder. Returns the call log."""
    calls: list[dict] = []

    def fake(method, url, **kw):
        calls.append({"method": method, "url": url, **kw})
        return _FakeResponse()

    from strix.tools.proxy import proxy_manager as pm

    monkeypatch.setattr(pm.requests, "request", fake)
    return calls


def _new_manager() -> ProxyManager:
    """Build a ProxyManager that doesn't try to talk to a Caido instance."""
    pm = ProxyManager.__new__(ProxyManager)
    pm.proxies = {}
    return pm


# ---------------------------------------------------------------------------
# Auth-header injection
# ---------------------------------------------------------------------------


def test_cookie_injected_into_request(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_AUTH_COOKIE", "session=abc")
    calls = _patch_requests(monkeypatch)
    _new_manager().send_simple_request("GET", "https://example.com/api")
    assert calls[0]["headers"]["Cookie"] == "session=abc"


def test_bearer_injected_into_request(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_AUTH_BEARER", "tok-xyz")
    calls = _patch_requests(monkeypatch)
    _new_manager().send_simple_request("GET", "https://example.com/api")
    assert calls[0]["headers"]["Authorization"] == "Bearer tok-xyz"


def test_custom_header_injected(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_HEADERS", json.dumps(["X-API-Key:abc"]))
    calls = _patch_requests(monkeypatch)
    _new_manager().send_simple_request("GET", "https://example.com/api")
    assert calls[0]["headers"]["X-API-Key"] == "abc"


def test_agent_supplied_auth_not_overwritten(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_AUTH_BEARER", "global-tok")
    calls = _patch_requests(monkeypatch)
    _new_manager().send_simple_request(
        "GET",
        "https://example.com/api",
        headers={"Authorization": "Bearer agent-tok"},
    )
    assert calls[0]["headers"]["Authorization"] == "Bearer agent-tok"


# ---------------------------------------------------------------------------
# Exclude-path enforcement
# ---------------------------------------------------------------------------


def test_excluded_path_short_circuits_before_dispatch(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", json.dumps(["/admin/*"]))
    calls = _patch_requests(monkeypatch)
    out = _new_manager().send_simple_request(
        "POST", "https://example.com/admin/destroy"
    )
    # Dispatch must not happen.
    assert calls == []
    # Structured response.
    assert out["skipped"] is True
    assert out["reason"] == "excluded"
    assert out["matched_glob"] == "/admin/*"


def test_non_excluded_path_dispatches(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", json.dumps(["/admin/*"]))
    calls = _patch_requests(monkeypatch)
    _new_manager().send_simple_request("GET", "https://example.com/api/users")
    assert len(calls) == 1


def test_excluded_path_does_not_consume_rate_limit(monkeypatch) -> None:
    """A blocked request shouldn't burn a rate-limit token — the user
    excluded it intentionally; pacing should not be punished by exclusions."""
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", json.dumps(["/admin/*"]))
    monkeypatch.setenv("STRIX_RATE_LIMIT", "10")
    calls = _patch_requests(monkeypatch)
    mgr = _new_manager()

    start = time.monotonic()
    # Three excluded calls + one allowed.
    mgr.send_simple_request("GET", "https://example.com/admin/x")
    mgr.send_simple_request("GET", "https://example.com/admin/y")
    mgr.send_simple_request("GET", "https://example.com/admin/z")
    mgr.send_simple_request("GET", "https://example.com/api/users")
    elapsed = time.monotonic() - start

    # Only the allowed call dispatched, and it didn't have to wait for
    # three excluded-call intervals to pass.
    assert len(calls) == 1
    assert elapsed < 0.05  # no throttle from the excluded calls


# ---------------------------------------------------------------------------
# Rate-limit applied at request time
# ---------------------------------------------------------------------------


def test_rate_limit_applied_to_consecutive_dispatched_requests(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_RATE_LIMIT", "10")
    _patch_requests(monkeypatch)
    mgr = _new_manager()

    start = time.monotonic()
    mgr.send_simple_request("GET", "https://example.com/a")
    mgr.send_simple_request("GET", "https://example.com/b")
    elapsed = time.monotonic() - start
    # 10 qps = ≥ 0.1s between calls.
    assert elapsed >= 0.08
