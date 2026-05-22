"""Tests for iter-23.2 `scan_sqli_sqlmap` wrapper."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.sqlmap_runner.scan_sqli_sqlmap  # noqa: F401
sss_mod = sys.modules["strix.tools.sqlmap_runner.scan_sqli_sqlmap"]
scan_sqli_sqlmap = sss_mod.scan_sqli_sqlmap


_FINDINGS_STDOUT = """
[15:42:01] [INFO] testing connection to the target URL
[15:42:02] [INFO] testing if GET parameter 'id' is dynamic
[15:42:09] [INFO] back-end DBMS appears to be 'MySQL'

sqlmap identified the following injection point(s) with a total of 47 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 6589=6589

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1 AND (SELECT 1234 FROM (SELECT(SLEEP(0)))xyz)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 4242 FROM(SELECT(SLEEP(5)))aaa)

Parameter: user (POST)
    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: user=admin' UNION SELECT NULL,NULL,NULL-- -
---
[15:42:10] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0
"""

_NO_FINDINGS_STDOUT = """
[15:42:01] [INFO] testing connection to the target URL
[15:42:02] [INFO] all tested parameters do not appear to be injectable.
"""


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_SQLMAP_DISABLED", raising=False)


def test_error_when_no_target():
    out = scan_sqli_sqlmap()
    assert out["status"] == "error"


def test_error_when_request_file_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/bin/sqlmap" if b == "sqlmap" else None,
    )
    out = scan_sqli_sqlmap(request_file="/nonexistent/req.txt")
    assert out["status"] == "error"
    assert "not found" in out["reason"]


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = scan_sqli_sqlmap(target_url="https://example.com/?id=1")
    assert out["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_SQLMAP_DISABLED", "1")
    out = scan_sqli_sqlmap(target_url="https://example.com/?id=1")
    assert out["status"] == "partial"


def test_parses_multi_technique_findings(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/bin/sqlmap" if b == "sqlmap" else None,
    )
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = _FINDINGS_STDOUT
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = scan_sqli_sqlmap(target_url="https://example.com/?id=1")
    assert out["status"] == "ok"
    # 3 techniques on `id` + 1 on `user` = 4 findings
    assert out["total_findings"] == 4
    assert out["dbms_detected"] == "MySQL >= 5.0"
    params = {(f["parameter"], f["location"]) for f in out["findings"]}
    assert ("id", "GET") in params
    assert ("user", "POST") in params
    # all CWE-89, all critical
    for f in out["findings"]:
        assert f["cwe"] == "CWE-89"
        assert f["severity"] == "critical"
    techniques = {f["technique"] for f in out["findings"]}
    assert "boolean-based blind" in techniques
    assert "error-based" in techniques
    assert "time-based blind" in techniques
    assert "UNION query" in techniques


def test_no_findings_returns_zero(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/bin/sqlmap" if b == "sqlmap" else None,
    )
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = _NO_FINDINGS_STDOUT
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = scan_sqli_sqlmap(target_url="https://safe.example.com/?id=1")
    assert out["status"] == "ok"
    assert out["total_findings"] == 0


def test_dbms_hint_passed_through(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/bin/sqlmap" if b == "sqlmap" else None,
    )
    captured: dict = {}

    def _capture(cmd, **kw):
        captured["cmd"] = cmd
        m = MagicMock()
        m.returncode = 0
        m.stdout = _NO_FINDINGS_STDOUT
        m.stderr = ""
        return m

    monkeypatch.setattr(subprocess, "run", _capture)
    scan_sqli_sqlmap(
        target_url="https://example.com/?id=1",
        dbms_hint="postgres",
        risk=3, level=5,
    )
    assert "--dbms" in captured["cmd"]
    assert "postgres" in captured["cmd"]
    assert "--risk" in captured["cmd"]
    assert "3" in captured["cmd"]
    assert "--level" in captured["cmd"]
    assert "5" in captured["cmd"]


def test_timeout(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/bin/sqlmap" if b == "sqlmap" else None,
    )

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="sqlmap", timeout=300)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = scan_sqli_sqlmap(target_url="https://example.com/?id=1")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("scan_sqli_sqlmap"))
