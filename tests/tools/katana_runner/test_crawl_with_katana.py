"""Tests for iter-22.1 `crawl_with_katana` wrapper."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.katana_runner.crawl_with_katana  # noqa: F401,E501
cwk_mod = sys.modules["strix.tools.katana_runner.crawl_with_katana"]
crawl_with_katana = cwk_mod.crawl_with_katana


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_KATANA_DISABLED", raising=False)


def test_error_when_empty():
    out = crawl_with_katana("")
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = crawl_with_katana("https://example.com")
    assert out["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_KATANA_DISABLED", "1")
    out = crawl_with_katana("https://example.com")
    assert out["status"] == "partial"


def test_parses_jsonl_endpoints(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/katana" if b == "katana" else None)
    lines = [
        json.dumps({"request": {"endpoint": "https://example.com/api?id=1",
                                 "method": "GET"}}),
        json.dumps({"request": {"endpoint": "https://example.com/login",
                                 "method": "POST"}}),
        # Duplicate — should dedup
        json.dumps({"request": {"endpoint": "https://example.com/api?id=1",
                                 "method": "GET"}}),
        "garbage line",
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "\n".join(lines)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = crawl_with_katana("https://example.com")
    assert out["status"] == "ok"
    assert out["endpoints_discovered"] == 2
    urls = {e["url"] for e in out["endpoints"]}
    assert "https://example.com/api?id=1" in urls
    assert "https://example.com/login" in urls
    # Param extraction
    api = next(e for e in out["endpoints"] if "/api?" in e["url"])
    assert "id" in api["params"]


def test_max_pages_caps(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/katana" if b == "katana" else None)
    lines = [
        json.dumps({"request": {"endpoint": f"https://x.com/p{i}", "method": "GET"}})
        for i in range(50)
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "\n".join(lines)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = crawl_with_katana("https://x.com", max_pages=10)
    assert out["endpoints_discovered"] == 10


def test_timeout_returns_error(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/katana" if b == "katana" else None)
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="katana", timeout=180)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = crawl_with_katana("https://x.com")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("crawl_with_katana"))
