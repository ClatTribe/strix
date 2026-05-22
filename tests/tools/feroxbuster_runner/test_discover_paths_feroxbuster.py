"""Tests for iter-23.3 `discover_paths_feroxbuster` wrapper."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.feroxbuster_runner.discover_paths_feroxbuster  # noqa: F401,E501
dpf_mod = sys.modules[
    "strix.tools.feroxbuster_runner.discover_paths_feroxbuster"
]
discover_paths_feroxbuster = dpf_mod.discover_paths_feroxbuster


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_FEROXBUSTER_DISABLED", raising=False)


def test_error_when_empty():
    out = discover_paths_feroxbuster("")
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = discover_paths_feroxbuster("https://example.com")
    assert out["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_FEROXBUSTER_DISABLED", "1")
    out = discover_paths_feroxbuster("https://example.com")
    assert out["status"] == "partial"


def test_parses_ndjson_paths(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/feroxbuster" if b == "feroxbuster" else None,
    )
    lines = [
        json.dumps({
            "type": "response",
            "url": "https://example.com/admin",
            "status": 200,
            "content_length": 4096,
            "word_count": 200,
        }),
        json.dumps({
            "type": "response",
            "url": "https://example.com/login",
            "status": 200,
            "content_length": 1024,
        }),
        # Duplicate URL
        json.dumps({
            "type": "response",
            "url": "https://example.com/admin",
            "status": 200,
        }),
        # Non-response (banner / stat line)
        json.dumps({"type": "banner", "version": "2.0.0"}),
        "garbage",
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "\n".join(lines)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = discover_paths_feroxbuster("https://example.com")
    assert out["status"] == "ok"
    assert out["total_found"] == 2
    urls = {p["url"] for p in out["paths"]}
    assert "https://example.com/admin" in urls
    assert "https://example.com/login" in urls
    admin = next(p for p in out["paths"] if p["url"].endswith("/admin"))
    assert admin["status_code"] == 200
    assert admin["content_length"] == 4096
    assert admin["word_count"] == 200


def test_max_results_caps(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/feroxbuster" if b == "feroxbuster" else None,
    )
    lines = [
        json.dumps({
            "type": "response", "url": f"https://example.com/p{i}",
            "status": 200, "content_length": 100,
        })
        for i in range(50)
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "\n".join(lines)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = discover_paths_feroxbuster("https://example.com", max_results=10)
    assert out["total_found"] == 10


def test_timeout(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/feroxbuster" if b == "feroxbuster" else None,
    )

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="feroxbuster", timeout=240)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = discover_paths_feroxbuster("https://example.com")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("discover_paths_feroxbuster"))
