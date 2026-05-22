"""Tests for iter-22.3 `tls_audit_testssl` wrapper."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest


import strix.tools.testssl_runner.tls_audit_testssl  # noqa: F401,E501
tat_mod = sys.modules["strix.tools.testssl_runner.tls_audit_testssl"]
tls_audit_testssl = tat_mod.tls_audit_testssl


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_TESTSSL_DISABLED", raising=False)


def test_error_when_empty():
    out = tls_audit_testssl("")
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = tls_audit_testssl("example.com")
    assert out["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_TESTSSL_DISABLED", "1")
    out = tls_audit_testssl("example.com")
    assert out["status"] == "partial"


def test_parses_jsonfile(monkeypatch, tmp_path):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/testssl.sh" if b == "testssl.sh" else None)

    # Mock subprocess.run to write a JSON file to the path that
    # testssl.sh would have written it.
    captured = {}

    def _fake_run(cmd, **kw):
        # Pull the --jsonfile-pretty path out of argv
        json_idx = cmd.index("--jsonfile-pretty")
        path = Path(cmd[json_idx + 1])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([
            {"id": "BEAST", "severity": "MEDIUM",
             "finding": "BEAST not vulnerable", "cve": ""},
            {"id": "ROBOT", "severity": "HIGH",
             "finding": "Vulnerable to ROBOT attack", "cve": "CVE-2017-13099"},
            {"id": "RC4_CIPHERS", "severity": "CRITICAL",
             "finding": "RC4 ciphers offered", "cve": ""},
            {"id": "HSTS", "severity": "OK", "finding": "HSTS present"},
        ]))
        captured["path"] = path
        out = MagicMock()
        out.returncode = 0
        out.stdout = ""
        out.stderr = ""
        return out

    monkeypatch.setattr(subprocess, "run", _fake_run)
    out = tls_audit_testssl("example.com")
    assert out["status"] == "ok"
    # 3 findings — OK level skipped
    assert out["total_findings"] == 3
    sev = {f["severity"] for f in out["findings"]}
    assert sev == {"critical", "high", "medium"}
    robot = next(f for f in out["findings"] if f["check_id"] == "ROBOT")
    assert robot["cve"] == "CVE-2017-13099"


def test_handles_missing_json_file(monkeypatch):
    """testssl exited but didn't write the JSON file → no findings,
    but no error either."""
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/testssl.sh" if b == "testssl.sh" else None)
    out_mock = MagicMock()
    out_mock.returncode = 0
    out_mock.stdout = ""
    out_mock.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=out_mock))
    out = tls_audit_testssl("example.com")
    assert out["status"] == "ok"
    assert out["total_findings"] == 0


def test_subprocess_timeout(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/testssl.sh" if b == "testssl.sh" else None)
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="testssl.sh", timeout=300)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = tls_audit_testssl("example.com")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("tls_audit_testssl"))
