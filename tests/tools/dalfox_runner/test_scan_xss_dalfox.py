"""Tests for iter-22.8 `scan_xss_dalfox` wrapper."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.dalfox_runner.scan_xss_dalfox  # noqa: F401,E501
sxd_mod = sys.modules["strix.tools.dalfox_runner.scan_xss_dalfox"]
scan_xss_dalfox = sxd_mod.scan_xss_dalfox


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_DALFOX_DISABLED", raising=False)


def test_error_when_empty():
    out = scan_xss_dalfox("")
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = scan_xss_dalfox("https://example.com/?q=test")
    assert out["status"] == "partial"


def test_verified_xss_emits_critical(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/dalfox" if b == "dalfox" else None)
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = json.dumps([
        {"type": "V", "inject_type": "reflected",
         "param": "q", "data": "<script>alert(1)</script>",
         "evidence": "echoed in body"},
        {"type": "R", "param": "search", "data": "<svg/onload=...>",
         "evidence": "reflected unencoded"},
        {"type": "G", "param": "callback", "data": "javascript:...",
         "evidence": "grep match"},
    ])
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = scan_xss_dalfox("https://example.com/?q=test")
    assert out["status"] == "ok"
    assert out["total_findings"] == 3
    severities = sorted(f["severity"] for f in out["findings"])
    assert severities == ["critical", "high", "medium"]


def test_no_findings_returns_zero(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/dalfox" if b == "dalfox" else None)
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "[]"
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = scan_xss_dalfox("https://example.com/?q=test")
    assert out["status"] == "ok"
    assert out["total_findings"] == 0


def test_timeout(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/dalfox" if b == "dalfox" else None)
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="dalfox", timeout=180)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = scan_xss_dalfox("https://example.com/?q=test")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("scan_xss_dalfox"))
