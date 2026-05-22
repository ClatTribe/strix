"""Tests for iter-24.1 shared ETag-cache refresh logic."""

from __future__ import annotations

import io
import os
import urllib.error
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    """Point cache_root() at a tmpdir so tests don't touch ~/.strix."""
    monkeypatch.setenv("STRIX_RULES_CACHE_DIR", str(tmp_path / "rules"))
    yield tmp_path / "rules"


def _import_common():
    # Re-import inside each test so the monkeypatched env var sticks.
    from strix.tools.rule_updates import _common
    import importlib
    importlib.reload(_common)
    return _common


def test_cache_root_creates_dir(_isolated_cache):
    c = _import_common()
    root = c.cache_root()
    assert root.is_dir()


def test_cached_path_returns_under_root():
    c = _import_common()
    p = c.cached_path("foo.toml")
    assert p.name == "foo.toml"
    assert p.parent == c.cache_root()


def _mock_urlopen(body: bytes, etag: str | None = "W/\"abc\"",
                  status: int = 200):
    """Construct a context-manager-style mock for urlopen."""
    resp = MagicMock()
    resp.read.return_value = body
    resp.headers.get = lambda k, default=None: (
        etag if k.lower() == "etag" else default
    )
    resp.status = status
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def test_initial_fetch_writes_body_and_etag(monkeypatch):
    c = _import_common()
    import urllib.request
    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda *a, **k: _mock_urlopen(b"# gitleaks rules here", "etag-v1"),
    )
    out = c.refresh_via_etag("gitleaks.toml", "https://example/g.toml")
    assert out["status"] == "updated"
    assert out["size_bytes"] == len(b"# gitleaks rules here")
    p = c.cached_path("gitleaks.toml")
    assert p.read_bytes() == b"# gitleaks rules here"
    etag_p = p.with_name(p.name + ".etag")
    assert etag_p.read_text() == "etag-v1"


def test_fresh_window_skips_http(monkeypatch):
    c = _import_common()
    # Pre-populate cache
    p = c.cached_path("gitleaks.toml")
    p.write_bytes(b"existing rules")

    called = {"n": 0}

    def _boom(*a, **k):
        called["n"] += 1
        raise AssertionError("HTTP should not be called within fresh window")
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    out = c.refresh_via_etag(
        "gitleaks.toml", "https://example/g.toml", max_age_hours=24.0,
    )
    assert out["status"] == "fresh"
    assert called["n"] == 0
    assert out["age_hours"] < 1.0


def test_force_bypasses_fresh_window(monkeypatch):
    c = _import_common()
    p = c.cached_path("gitleaks.toml")
    p.write_bytes(b"old rules")

    import urllib.request
    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda *a, **k: _mock_urlopen(b"new rules", "etag-v2"),
    )
    out = c.refresh_via_etag(
        "gitleaks.toml", "https://example/g.toml", force=True,
    )
    assert out["status"] == "updated"
    assert p.read_bytes() == b"new rules"


def test_304_not_modified_keeps_existing(monkeypatch, tmp_path):
    c = _import_common()
    p = c.cached_path("gitleaks.toml")
    p.write_bytes(b"cached rules")
    # Pre-set the file mtime to 30h ago so it's outside the fresh window
    import time
    old_ts = time.time() - 30 * 3600
    os.utime(p, (old_ts, old_ts))

    import urllib.request

    def _raise304(*a, **k):
        raise urllib.error.HTTPError(
            url="https://example/g.toml", code=304,
            msg="Not Modified", hdrs=None, fp=io.BytesIO(b""),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise304)
    out = c.refresh_via_etag("gitleaks.toml", "https://example/g.toml")
    assert out["status"] == "unchanged"
    # Content untouched
    assert p.read_bytes() == b"cached rules"


def test_network_error_returns_partial(monkeypatch):
    c = _import_common()
    p = c.cached_path("gitleaks.toml")
    p.write_bytes(b"cached")

    import urllib.request

    def _raise_url_err(*a, **k):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", _raise_url_err)
    out = c.refresh_via_etag(
        "gitleaks.toml", "https://example/g.toml", force=True,
    )
    assert out["status"] == "partial"
    assert "connection refused" in out["reason"]
    # Cached body untouched
    assert p.read_bytes() == b"cached"


def test_http_5xx_returns_partial(monkeypatch):
    c = _import_common()

    import urllib.request

    def _raise500(*a, **k):
        raise urllib.error.HTTPError(
            url="https://example/g.toml", code=500,
            msg="Internal Server Error", hdrs=None, fp=io.BytesIO(b""),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise500)
    out = c.refresh_via_etag(
        "gitleaks.toml", "https://example/g.toml", force=True,
    )
    assert out["status"] == "partial"
    assert "500" in out["reason"]
