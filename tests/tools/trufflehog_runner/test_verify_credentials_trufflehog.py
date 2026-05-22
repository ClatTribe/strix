"""Tests for iter-23.3 `verify_credentials_trufflehog` wrapper."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.trufflehog_runner.verify_credentials_trufflehog  # noqa: F401,E501
vct_mod = sys.modules[
    "strix.tools.trufflehog_runner.verify_credentials_trufflehog"
]
verify_credentials_trufflehog = vct_mod.verify_credentials_trufflehog


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_TRUFFLEHOG_DISABLED", raising=False)


def test_error_when_empty():
    out = verify_credentials_trufflehog("")
    assert out["status"] == "error"


def test_error_unknown_mode(tmp_path, monkeypatch):
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/trufflehog" if b == "trufflehog" else None,
    )
    out = verify_credentials_trufflehog(str(tmp_path), mode="nonsense")
    assert out["status"] == "error"


def test_error_filesystem_path_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/trufflehog" if b == "trufflehog" else None,
    )
    out = verify_credentials_trufflehog(
        "/nonexistent/path", mode="filesystem",
    )
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch, tmp_path):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = verify_credentials_trufflehog(str(tmp_path), mode="filesystem")
    assert out["status"] == "partial"


def test_partial_when_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("STRIX_TRUFFLEHOG_DISABLED", "1")
    out = verify_credentials_trufflehog(str(tmp_path), mode="filesystem")
    assert out["status"] == "partial"


def test_parses_verified_findings(monkeypatch, tmp_path):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/trufflehog" if b == "trufflehog" else None,
    )
    lines = [
        json.dumps({
            "DetectorName": "AWS",
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {
                "file": "/app/config.py", "line": 42,
            }}},
        }),
        json.dumps({
            "DetectorName": "Stripe",
            "Raw": "sk_live_abcdef1234567890",
            "Verified": False,
            "SourceMetadata": {"Data": {"Filesystem": {
                "file": "/app/legacy.py", "line": 7,
            }}},
        }),
        "not json",
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "\n".join(lines)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = verify_credentials_trufflehog(str(tmp_path), mode="filesystem")
    assert out["status"] == "ok"
    assert out["total_findings"] == 2
    aws = next(f for f in out["findings"] if f["detector"] == "AWS")
    assert aws["verified"] is True
    assert aws["severity"] == "critical"
    assert aws["file"] == "/app/config.py"
    assert aws["line"] == 42
    assert aws["cwe"] == "CWE-798"
    # value masked: keeps 3 prefix + 3 suffix chars
    assert aws["masked"].startswith("AKI")
    assert aws["masked"].endswith("PLE")
    stripe = next(f for f in out["findings"] if f["detector"] == "Stripe")
    assert stripe["verified"] is False
    assert stripe["severity"] == "high"  # unverified → high not critical


def test_git_mode(monkeypatch, tmp_path):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/trufflehog" if b == "trufflehog" else None,
    )
    captured = {}

    def _capture(cmd, **kw):
        captured["cmd"] = cmd
        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        m.stderr = ""
        return m

    monkeypatch.setattr(subprocess, "run", _capture)
    verify_credentials_trufflehog(str(tmp_path), mode="git")
    assert "git" in captured["cmd"]
    # path is prefixed with file:// when not already
    assert any(arg.startswith("file://") for arg in captured["cmd"])


def test_timeout(monkeypatch, tmp_path):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/trufflehog" if b == "trufflehog" else None,
    )

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="trufflehog", timeout=300)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = verify_credentials_trufflehog(str(tmp_path), mode="filesystem")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("verify_credentials_trufflehog"))
