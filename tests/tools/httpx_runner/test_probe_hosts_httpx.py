"""Tests for iter-23.1 `probe_hosts_httpx` wrapper."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.httpx_runner.probe_hosts_httpx  # noqa: F401
phh_mod = sys.modules["strix.tools.httpx_runner.probe_hosts_httpx"]
probe_hosts_httpx = phh_mod.probe_hosts_httpx


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_HTTPX_DISABLED", raising=False)


def test_error_when_empty():
    out = probe_hosts_httpx([])
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = probe_hosts_httpx(["example.com"])
    assert out["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_HTTPX_DISABLED", "1")
    out = probe_hosts_httpx(["example.com"])
    assert out["status"] == "partial"


def test_parses_probe_results(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/httpx" if b == "httpx" else None,
    )
    lines = [
        json.dumps({
            "url": "https://example.com",
            "status_code": 200,
            "title": "Example Domain",
            "tech": ["nginx", "Cloudflare"],
            "content_length": 1256,
            "webserver": "nginx",
        }),
        json.dumps({
            "url": "https://api.example.com",
            "status_code": 401,
            "title": "Unauthorized",
            "tech": ["Express"],
            "webserver": "Express",
        }),
        "garbage",
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "\n".join(lines)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = probe_hosts_httpx(["example.com", "api.example.com"])
    assert out["status"] == "ok"
    assert out["total_probed"] == 2
    assert out["live_hosts"] == 2
    urls = {p["url"] for p in out["probes"]}
    assert "https://example.com" in urls
    assert "https://api.example.com" in urls
    web_probe = next(p for p in out["probes"] if p["url"] == "https://example.com")
    assert web_probe["status_code"] == 200
    assert "nginx" in web_probe["tech"]
    assert web_probe["webserver"] == "nginx"


def test_accepts_newline_string_hosts(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/httpx" if b == "httpx" else None,
    )
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = json.dumps({"url": "https://a.com", "status_code": 200})
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = probe_hosts_httpx("a.com\nb.com\n")
    assert out["total_probed"] == 2


def test_max_results_caps(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/httpx" if b == "httpx" else None,
    )
    lines = [
        json.dumps({"url": f"https://h{i}.com", "status_code": 200})
        for i in range(20)
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "\n".join(lines)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = probe_hosts_httpx([f"h{i}.com" for i in range(20)], max_results=5)
    assert out["live_hosts"] == 5


def test_timeout(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/httpx" if b == "httpx" else None,
    )

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="httpx", timeout=180)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = probe_hosts_httpx(["example.com"])
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("probe_hosts_httpx"))
