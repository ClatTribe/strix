"""Tests for iter-Q5.51 — `grab_banner_zgrab2` wrapper."""

from __future__ import annotations

import importlib
import json
import pytest

sci = importlib.import_module(
    "strix.tools.zgrab_runner.grab_banner_zgrab2",
)
grab = sci.grab_banner_zgrab2


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_ZGRAB_DISABLED", raising=False)


def _mock_zgrab(monkeypatch, stdout, returncode=0):
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/zgrab2" if b == "zgrab2" else None,
    )
    captured: list[list[str]] = []

    class _Proc:
        def __init__(self):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = ""

    def _run(cmd, **_):
        captured.append(list(cmd))
        return _Proc()

    monkeypatch.setattr(sci.subprocess, "run", _run)
    return captured


def test_error_empty():
    assert grab("")["status"] == "error"


def test_error_unknown_module():
    out = grab("1.2.3.4", module="nope")
    assert out["status"] == "error"
    assert "unsupported module" in out["reason"]


def test_partial_when_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    assert grab("1.2.3.4")["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_ZGRAB_DISABLED", "1")
    assert grab("1.2.3.4")["status"] == "partial"


def test_parses_http_banner(monkeypatch):
    banner = {"data": {"http": {"status_code": 200, "server": "nginx/1.25"}}}
    _mock_zgrab(monkeypatch, json.dumps(banner))
    out = grab("1.2.3.4", module="http")
    assert out["status"] == "ok"
    assert out["module"] == "http"
    assert out["banner"]["data"]["http"]["status_code"] == 200


def test_ssh_module_passes_to_argv(monkeypatch):
    captured = _mock_zgrab(monkeypatch, json.dumps({"data": {}}))
    grab("1.2.3.4", module="ssh", port=22)
    cmd = captured[0]
    assert "ssh" in cmd
    assert "--port" in cmd
    assert cmd[cmd.index("--port") + 1] == "22"


def test_default_no_port_flag(monkeypatch):
    captured = _mock_zgrab(monkeypatch, json.dumps({"data": {}}))
    grab("1.2.3.4", module="http")
    cmd = captured[0]
    assert "--port" not in cmd


def test_first_parseable_record_used(monkeypatch):
    body = "garbage\nmore garbage\n" + json.dumps({"banner": "real"})
    _mock_zgrab(monkeypatch, body)
    out = grab("1.2.3.4")
    assert out["banner"] == {"banner": "real"}


def test_no_parseable_record_returns_error(monkeypatch):
    _mock_zgrab(monkeypatch, "garbage\nmore garbage\n")
    out = grab("1.2.3.4")
    assert out["status"] == "error"


def test_empty_stdout_returns_error(monkeypatch):
    _mock_zgrab(monkeypatch, "")
    out = grab("1.2.3.4")
    assert out["status"] == "error"


def test_no_fixture_identifiers():
    import inspect
    src = inspect.getsource(sci).lower()
    for ident in ("juice-shop", "vampi", "crapi", "wavsep"):
        assert ident not in src
