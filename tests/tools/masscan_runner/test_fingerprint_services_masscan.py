"""Tests for iter-Q5.50 — `fingerprint_services_masscan` wrapper."""

from __future__ import annotations

import importlib
import json
import pytest

sci = importlib.import_module(
    "strix.tools.masscan_runner.fingerprint_services_masscan",
)
fingerprint = sci.fingerprint_services_masscan


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    for k in ("STRIX_MASSCAN_DISABLED", "STRIX_MASSCAN_PORTS",
              "STRIX_MASSCAN_RATE"):
        monkeypatch.delenv(k, raising=False)


def _mock_masscan(monkeypatch, stdout):
    import shutil
    monkeypatch.setattr(
        shutil, "which", lambda b: "/usr/local/bin/masscan" if b == "masscan" else None,
    )
    captured: list[list[str]] = []

    class _Proc:
        returncode = 0
        stderr = ""
        def __init__(self, stdout): self.stdout = stdout

    def _run(cmd, **_):
        captured.append(list(cmd))
        return _Proc(stdout)

    monkeypatch.setattr(sci.subprocess, "run", _run)
    return captured


def test_error_empty():
    assert fingerprint("")["status"] == "error"


def test_partial_when_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    assert fingerprint("1.2.3.4")["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_MASSCAN_DISABLED", "1")
    assert fingerprint("1.2.3.4")["status"] == "partial"


def test_parses_json_array(monkeypatch):
    body = json.dumps([
        {"ip": "1.2.3.4", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
        {"ip": "1.2.3.4", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]},
    ])
    _mock_masscan(monkeypatch, body)
    out = fingerprint("1.2.3.4")
    assert out["status"] == "ok"
    assert out["total_found"] == 2
    ports = sorted(p["port"] for p in out["open_ports"])
    assert ports == [80, 443]


def test_parses_line_oriented_json(monkeypatch):
    """masscan -oJ also emits one record per line in some versions."""
    body = "[\n" + ",\n".join([
        json.dumps({"ip": "1.2.3.4", "ports": [{"port": 22, "proto": "tcp"}]}),
        json.dumps({"ip": "1.2.3.4", "ports": [{"port": 8080, "proto": "tcp"}]}),
    ]) + "\n]"
    _mock_masscan(monkeypatch, body)
    out = fingerprint("1.2.3.4")
    assert out["total_found"] == 2


def test_dedupes_port_proto(monkeypatch):
    body = json.dumps([
        {"ip": "1.2.3.4", "ports": [{"port": 80, "proto": "tcp"}]},
        {"ip": "1.2.3.4", "ports": [{"port": 80, "proto": "tcp"}]},
    ])
    _mock_masscan(monkeypatch, body)
    assert fingerprint("1.2.3.4")["total_found"] == 1


def test_ports_kwarg_emits_p_flag(monkeypatch):
    captured = _mock_masscan(monkeypatch, "[]")
    fingerprint("1.2.3.4", ports="22,80,443")
    cmd = captured[0]
    assert "-p" in cmd
    assert cmd[cmd.index("-p") + 1] == "22,80,443"
    assert "--top-ports" not in cmd


def test_top_ports_default(monkeypatch):
    captured = _mock_masscan(monkeypatch, "[]")
    fingerprint("1.2.3.4")
    cmd = captured[0]
    assert "--top-ports" in cmd
    assert cmd[cmd.index("--top-ports") + 1] == "1000"


def test_rate_env_override(monkeypatch):
    monkeypatch.setenv("STRIX_MASSCAN_RATE", "5000")
    captured = _mock_masscan(monkeypatch, "[]")
    fingerprint("1.2.3.4")
    cmd = captured[0]
    idx = cmd.index("--rate")
    assert cmd[idx + 1] == "5000"


def test_default_rate_is_1000(monkeypatch):
    captured = _mock_masscan(monkeypatch, "[]")
    fingerprint("1.2.3.4")
    cmd = captured[0]
    idx = cmd.index("--rate")
    assert cmd[idx + 1] == "1000"


def test_no_fixture_identifiers():
    import inspect
    src = inspect.getsource(sci).lower()
    for ident in ("juice-shop", "vampi", "crapi", "wavsep"):
        assert ident not in src
