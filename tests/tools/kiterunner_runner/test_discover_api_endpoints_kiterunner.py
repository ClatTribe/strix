"""Tests for iter-Q5.49 — `discover_api_endpoints_kiterunner` wrapper."""

from __future__ import annotations

import importlib
import json
import pytest

sci = importlib.import_module(
    "strix.tools.kiterunner_runner.discover_api_endpoints_kiterunner",
)
discover = sci.discover_api_endpoints_kiterunner


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    for k in ("STRIX_KITERUNNER_DISABLED", "STRIX_KITERUNNER_WORDLIST"):
        monkeypatch.delenv(k, raising=False)


def _mock_kr(monkeypatch, stdout, returncode=0):
    import shutil
    monkeypatch.setattr(
        shutil, "which", lambda b: "/usr/local/bin/kr" if b == "kr" else None,
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


def test_error_empty_target():
    assert discover("")["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    assert discover("https://api.example.com")["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_KITERUNNER_DISABLED", "1")
    assert discover("https://api.example.com")["status"] == "partial"


def test_parses_jsonl(monkeypatch):
    _mock_kr(monkeypatch, "\n".join([
        json.dumps({"url": "https://api.example.com/v1/users", "method": "GET",
                    "status_code": 200, "content_length": 1234}),
        json.dumps({"url": "https://api.example.com/v1/admin", "method": "POST",
                    "status_code": 401, "content_length": 50}),
    ]))
    out = discover("https://api.example.com")
    assert out["status"] == "ok"
    assert out["total_found"] == 2
    eps = out["endpoints"]
    assert eps[0]["url"] == "https://api.example.com/v1/users"
    assert eps[0]["method"] == "GET"
    assert eps[1]["method"] == "POST"


def test_dedupes_same_url_method(monkeypatch):
    _mock_kr(monkeypatch, "\n".join([
        json.dumps({"url": "https://api.x.com/a", "method": "GET"}),
        json.dumps({"url": "https://api.x.com/a", "method": "GET"}),
    ]))
    out = discover("https://api.x.com")
    assert out["total_found"] == 1


def test_max_endpoints_cap(monkeypatch):
    _mock_kr(monkeypatch, "\n".join(
        json.dumps({"url": f"https://api.x.com/r{i}", "method": "GET"})
        for i in range(20)
    ))
    out = discover("https://api.x.com", max_endpoints=5)
    assert out["total_found"] == 5


def test_malformed_jsonl_skipped(monkeypatch):
    _mock_kr(monkeypatch, "\n".join([
        "not json",
        json.dumps({}),
        json.dumps({"url": "https://api.x.com/a", "method": "GET"}),
    ]))
    out = discover("https://api.x.com")
    assert out["total_found"] == 1


def test_wordlist_env_override(monkeypatch):
    monkeypatch.setenv("STRIX_KITERUNNER_WORDLIST", "/custom/wl.kite")
    captured = _mock_kr(monkeypatch, "")
    discover("https://api.x.com")
    cmd = captured[0]
    idx = cmd.index("-w")
    assert cmd[idx + 1] == "/custom/wl.kite"


def test_no_fixture_identifiers():
    import inspect
    src = inspect.getsource(sci).lower()
    for ident in ("juice-shop", "vampi", "crapi", "wavsep"):
        assert ident not in src
