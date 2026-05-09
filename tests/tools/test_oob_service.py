"""Tests for Phase 1.3 — OOB-DNS callback service.

Pins:
  * Backend resolution priority (env > local > interactsh > disabled)
  * `register_callback` returns None when disabled
  * Local listener: registers token, listener accepts hit, poll
    returns hit with source_ip
  * Token uniqueness across registrations
  * Disabled backend is silent (specialists no-op gracefully)
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.request

import pytest

from strix.tools.oob.service import (
    backend_name,
    is_available,
    poll_callback,
    register_callback,
    reset_oob_service,
)


def _free_port() -> int:
    """Bind to port 0 to get an OS-assigned free port, then close."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
def _isolate_backend() -> None:
    reset_oob_service()
    yield
    reset_oob_service()


# ---------------------------------------------------------------------------
# Backend resolution
# ---------------------------------------------------------------------------


def test_disabled_when_env_set(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OOB_BACKEND", "disabled")
    monkeypatch.delenv("STRIX_OOB_LOCAL_HOST", raising=False)
    assert not is_available()
    assert backend_name() == "disabled"


def test_register_callback_returns_none_when_disabled(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OOB_BACKEND", "disabled")
    monkeypatch.delenv("STRIX_OOB_LOCAL_HOST", raising=False)
    cb = register_callback()
    assert cb is None


def test_poll_returns_hit_false_when_disabled(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OOB_BACKEND", "disabled")
    result = poll_callback("strix_anything", timeout_seconds=0.1)
    assert result == {"hit": False, "source_ip": None, "raw_request": None}


# ---------------------------------------------------------------------------
# Local listener backend (the one we test end-to-end)
# ---------------------------------------------------------------------------


def test_local_listener_registers_token(monkeypatch) -> None:
    port = _free_port()
    monkeypatch.setenv("STRIX_OOB_BACKEND", "local")
    monkeypatch.setenv("STRIX_OOB_LOCAL_HOST", f"127.0.0.1:{port}")
    monkeypatch.setenv("STRIX_OOB_PUBLIC_HOST", "127.0.0.1")

    cb = register_callback(ttl_seconds=60)
    assert cb is not None
    assert cb.token.startswith("strix")
    assert f"127.0.0.1:{port}" in cb.callback_url
    assert cb.token in cb.callback_url
    assert cb.backend_name == "local"
    assert is_available()


def test_local_listener_records_hit_and_poll_returns(monkeypatch) -> None:
    """End-to-end: register → fire HTTP request to the callback URL
    → poll returns hit=True with source_ip."""
    port = _free_port()
    monkeypatch.setenv("STRIX_OOB_BACKEND", "local")
    monkeypatch.setenv("STRIX_OOB_LOCAL_HOST", f"127.0.0.1:{port}")
    monkeypatch.setenv("STRIX_OOB_PUBLIC_HOST", "127.0.0.1")

    cb = register_callback()
    assert cb is not None

    # Fire an HTTP request from a thread (simulates a server-side
    # XXE / SSRF / RCE callback hitting the OOB infra).
    def _fire() -> None:
        try:
            urllib.request.urlopen(cb.callback_url, timeout=2)
        except Exception:
            pass
    threading.Thread(target=_fire, daemon=True).start()

    result = poll_callback(cb.token, timeout_seconds=3.0)
    assert result["hit"] is True
    assert result["source_ip"] is not None
    assert result["raw_request"]["method"] == "GET"
    assert cb.token in result["raw_request"]["path"]


def test_local_listener_token_uniqueness(monkeypatch) -> None:
    port = _free_port()
    monkeypatch.setenv("STRIX_OOB_BACKEND", "local")
    monkeypatch.setenv("STRIX_OOB_LOCAL_HOST", f"127.0.0.1:{port}")
    monkeypatch.setenv("STRIX_OOB_PUBLIC_HOST", "127.0.0.1")

    tokens = {register_callback().token for _ in range(10)}
    # All 10 should be distinct.
    assert len(tokens) == 10


def test_poll_returns_no_hit_on_unregistered_token(monkeypatch) -> None:
    port = _free_port()
    monkeypatch.setenv("STRIX_OOB_BACKEND", "local")
    monkeypatch.setenv("STRIX_OOB_LOCAL_HOST", f"127.0.0.1:{port}")
    monkeypatch.setenv("STRIX_OOB_PUBLIC_HOST", "127.0.0.1")

    register_callback()
    # Poll a different token — no hit expected.
    result = poll_callback("strix_different_token", timeout_seconds=0.5)
    assert result["hit"] is False


def test_local_listener_handles_post_method(monkeypatch) -> None:
    """Some attack payloads use POST instead of GET (e.g. blind RCE
    via curl POST callback)."""
    port = _free_port()
    monkeypatch.setenv("STRIX_OOB_BACKEND", "local")
    monkeypatch.setenv("STRIX_OOB_LOCAL_HOST", f"127.0.0.1:{port}")
    monkeypatch.setenv("STRIX_OOB_PUBLIC_HOST", "127.0.0.1")

    cb = register_callback()
    assert cb is not None

    def _fire_post() -> None:
        try:
            req = urllib.request.Request(cb.callback_url, data=b"ping")
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass
    threading.Thread(target=_fire_post, daemon=True).start()

    result = poll_callback(cb.token, timeout_seconds=3.0)
    assert result["hit"] is True
    assert result["raw_request"]["method"] == "POST"


def test_poll_timeout_returns_false(monkeypatch) -> None:
    """When no hit lands within timeout, poll returns hit=False."""
    port = _free_port()
    monkeypatch.setenv("STRIX_OOB_BACKEND", "local")
    monkeypatch.setenv("STRIX_OOB_LOCAL_HOST", f"127.0.0.1:{port}")
    monkeypatch.setenv("STRIX_OOB_PUBLIC_HOST", "127.0.0.1")

    cb = register_callback()
    start = time.time()
    result = poll_callback(cb.token, timeout_seconds=0.5)
    elapsed = time.time() - start
    assert result["hit"] is False
    assert 0.4 < elapsed < 1.5  # roughly the timeout


def test_register_returns_handle_with_expires_at(monkeypatch) -> None:
    port = _free_port()
    monkeypatch.setenv("STRIX_OOB_BACKEND", "local")
    monkeypatch.setenv("STRIX_OOB_LOCAL_HOST", f"127.0.0.1:{port}")
    monkeypatch.setenv("STRIX_OOB_PUBLIC_HOST", "127.0.0.1")

    cb = register_callback(ttl_seconds=120)
    # ISO-formatted expires_at; should parse.
    from datetime import datetime
    parsed = datetime.fromisoformat(cb.expires_at)
    assert parsed is not None
