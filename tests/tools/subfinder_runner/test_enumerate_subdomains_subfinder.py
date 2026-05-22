"""Tests for iter-23.1 `enumerate_subdomains_subfinder` wrapper."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.subfinder_runner.enumerate_subdomains_subfinder  # noqa: F401,E501
esd_mod = sys.modules[
    "strix.tools.subfinder_runner.enumerate_subdomains_subfinder"
]
enumerate_subdomains_subfinder = esd_mod.enumerate_subdomains_subfinder


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_SUBFINDER_DISABLED", raising=False)


def test_error_when_empty():
    out = enumerate_subdomains_subfinder("")
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = enumerate_subdomains_subfinder("example.com")
    assert out["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_SUBFINDER_DISABLED", "1")
    out = enumerate_subdomains_subfinder("example.com")
    assert out["status"] == "partial"


def test_parses_jsonl_subdomains(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/subfinder" if b == "subfinder" else None,
    )
    lines = [
        json.dumps({"host": "api.example.com"}),
        json.dumps({"host": "www.example.com"}),
        # Duplicate (case differs)
        json.dumps({"host": "API.example.com"}),
        json.dumps({"host": "dev.example.com"}),
        "garbage line",
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "\n".join(lines)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = enumerate_subdomains_subfinder("example.com")
    assert out["status"] == "ok"
    assert out["total_found"] == 3
    assert "api.example.com" in out["subdomains"]
    assert "www.example.com" in out["subdomains"]
    assert "dev.example.com" in out["subdomains"]


def test_max_results_caps(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/subfinder" if b == "subfinder" else None,
    )
    lines = [
        json.dumps({"host": f"sub{i}.example.com"})
        for i in range(50)
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "\n".join(lines)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = enumerate_subdomains_subfinder("example.com", max_results=10)
    assert out["total_found"] == 10


def test_timeout_returns_error(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/subfinder" if b == "subfinder" else None,
    )

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="subfinder", timeout=180)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = enumerate_subdomains_subfinder("example.com")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("enumerate_subdomains_subfinder"))
