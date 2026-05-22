"""Tests for iter-22.4 `scan_dockerfile_hadolint` wrapper."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.hadolint_runner.scan_dockerfile_hadolint  # noqa: F401,E501
sdh = sys.modules[
    "strix.tools.hadolint_runner.scan_dockerfile_hadolint"
]
scan_dockerfile_hadolint = sdh.scan_dockerfile_hadolint


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_HADOLINT_DISABLED", raising=False)


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = scan_dockerfile_hadolint("/tmp/Dockerfile")
    assert out["status"] == "partial"
    assert "hadolint" in out["reason"]


def test_partial_when_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("STRIX_HADOLINT_DISABLED", "1")
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu")
    out = scan_dockerfile_hadolint(str(df))
    assert out["status"] == "partial"


def test_error_when_dockerfile_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: "/usr/local/bin/hadolint")
    out = scan_dockerfile_hadolint("/nonexistent/Dockerfile")
    assert out["status"] == "error"


def test_emits_finding_per_rule(monkeypatch, tmp_path):
    import shutil
    import subprocess

    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/hadolint" if b == "hadolint" else None)
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu\nUSER root\n")

    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = json.dumps([
        {
            "code": "DL3006", "level": "warning", "line": 1,
            "message": "Always tag the version of an image explicitly",
        },
        {
            "code": "DL3002", "level": "error", "line": 2,
            "message": "Last USER should not be root",
        },
    ])
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))

    out = scan_dockerfile_hadolint(str(df))
    assert out["status"] == "ok"
    assert out["total_findings"] == 2
    rules = [f["rule_id"] for f in out["findings"]]
    assert "DL3006" in rules
    assert "DL3002" in rules
    # DL3002 (USER root) overridden to high
    dl3002 = next(f for f in out["findings"] if f["rule_id"] == "DL3002")
    assert dl3002["severity"] == "high"
    assert dl3002["cwe"] == "CWE-250"


def test_handles_garbage_stdout(monkeypatch, tmp_path):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/hadolint" if b == "hadolint" else None)
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu")
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "not json"
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = scan_dockerfile_hadolint(str(df))
    assert out["status"] == "ok"
    assert out["total_findings"] == 0


def test_subprocess_failure_returns_error(monkeypatch, tmp_path):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/hadolint" if b == "hadolint" else None)
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu")
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="hadolint", timeout=30)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = scan_dockerfile_hadolint(str(df))
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("scan_dockerfile_hadolint"))
