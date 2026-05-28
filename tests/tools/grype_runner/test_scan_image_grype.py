"""Tests for iter-Q5.47 — `scan_image_grype` wrapper."""

from __future__ import annotations

import importlib
import json
from unittest.mock import MagicMock

import pytest

sci = importlib.import_module("strix.tools.grype_runner.scan_image_grype")
scan_image_grype = sci.scan_image_grype


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    for k in ("STRIX_GRYPE_DISABLED", "STRIX_GRYPE_ONLY_FIXED"):
        monkeypatch.delenv(k, raising=False)


def _mock_grype(monkeypatch, stdout: str, returncode: int = 0, stderr: str = ""):
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/grype" if b == "grype" else None,
    )
    captured: list[list[str]] = []

    class _Proc:
        def __init__(self):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def _run(cmd, **_):
        captured.append(list(cmd))
        return _Proc()

    monkeypatch.setattr(sci.subprocess, "run", _run)
    return captured


# ---- recall-safe degrades ----

def test_error_when_empty():
    out = scan_image_grype("")
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = scan_image_grype("nginx:1.25")
    assert out["status"] == "partial"
    assert "grype binary" in out["reason"]


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_GRYPE_DISABLED", "1")
    out = scan_image_grype("nginx:1.25")
    assert out["status"] == "partial"


# ---- parsing ----

def test_parses_matches(monkeypatch):
    _mock_grype(monkeypatch, json.dumps({
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-0001",
                    "severity": "High",
                    "fix": {"state": "fixed", "versions": ["1.2.3"]},
                },
                "artifact": {"name": "openssl", "version": "1.0.0"},
            },
        ],
    }))
    out = scan_image_grype("nginx:1.25")
    assert out["status"] == "ok"
    assert out["total_found"] == 1
    v = out["vulnerabilities"][0]
    assert v["id"] == "CVE-2024-0001"
    assert v["severity"] == "High"
    assert v["package"] == "openssl"
    assert v["version"] == "1.0.0"
    assert v["fix_state"] == "fixed"
    assert v["fix_versions"] == ["1.2.3"]


def test_empty_matches_returns_ok(monkeypatch):
    _mock_grype(monkeypatch, json.dumps({"matches": []}))
    out = scan_image_grype("nginx:1.25")
    assert out["status"] == "ok"
    assert out["total_found"] == 0


def test_missing_matches_key_returns_ok_empty(monkeypatch):
    _mock_grype(monkeypatch, json.dumps({"source": {}}))
    out = scan_image_grype("nginx:1.25")
    assert out["status"] == "ok"
    assert out["vulnerabilities"] == []


def test_invalid_json_returns_error(monkeypatch):
    _mock_grype(monkeypatch, "not json")
    out = scan_image_grype("nginx:1.25")
    assert out["status"] == "error"


def test_empty_stdout_returns_error(monkeypatch):
    _mock_grype(monkeypatch, "  ", stderr="db not initialised")
    out = scan_image_grype("nginx:1.25")
    assert out["status"] == "error"
    assert "no output" in out["reason"]


# ---- severity floor ----

def test_severity_floor_drops_lower(monkeypatch):
    _mock_grype(monkeypatch, json.dumps({"matches": [
        {"vulnerability": {"id": "CVE-LOW", "severity": "Low"}, "artifact": {}},
        {"vulnerability": {"id": "CVE-HIGH", "severity": "High"}, "artifact": {}},
        {"vulnerability": {"id": "CVE-CRIT", "severity": "Critical"}, "artifact": {}},
    ]}))
    out = scan_image_grype("nginx:1.25", severity_floor="high")
    ids = [v["id"] for v in out["vulnerabilities"]]
    assert "CVE-LOW" not in ids
    assert "CVE-HIGH" in ids
    assert "CVE-CRIT" in ids


def test_severity_floor_negligible_drops_unknown(monkeypatch):
    """`negligible` and `unknown` map to rank 0 — the floor itself
    is at rank 0 too, so they should pass."""
    _mock_grype(monkeypatch, json.dumps({"matches": [
        {"vulnerability": {"id": "CVE-X", "severity": "Unknown"}, "artifact": {}},
    ]}))
    out = scan_image_grype("nginx:1.25", severity_floor="negligible")
    assert len(out["vulnerabilities"]) == 1


# ---- only_fixed ----

def test_only_fixed_emits_flag(monkeypatch):
    captured = _mock_grype(monkeypatch, "{}")
    scan_image_grype("nginx:1.25", only_fixed=True)
    assert "--only-fixed" in captured[0]


def test_only_fixed_env_consumed(monkeypatch):
    monkeypatch.setenv("STRIX_GRYPE_ONLY_FIXED", "1")
    captured = _mock_grype(monkeypatch, "{}")
    scan_image_grype("nginx:1.25")
    assert "--only-fixed" in captured[0]


def test_only_fixed_default_omits_flag(monkeypatch):
    captured = _mock_grype(monkeypatch, "{}")
    scan_image_grype("nginx:1.25")
    assert "--only-fixed" not in captured[0]


# ---- cmd shape ----

def test_cmd_has_json_output(monkeypatch):
    captured = _mock_grype(monkeypatch, "{}")
    scan_image_grype("nginx:1.25")
    cmd = captured[0]
    assert "-o" in cmd
    assert cmd[cmd.index("-o") + 1] == "json"
    assert cmd[-1] == "nginx:1.25" or "nginx:1.25" in cmd


# ---- subprocess errors ----

def test_timeout_returns_error(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: "/usr/local/bin/grype")

    def _raise(*_a, **_k):
        raise sci.subprocess.TimeoutExpired(cmd="grype", timeout=600)

    monkeypatch.setattr(sci.subprocess, "run", _raise)
    out = scan_image_grype("nginx:1.25")
    assert out["status"] == "error"
    assert "TimeoutExpired" in out["reason"]


def test_no_fixture_identifiers():
    import inspect
    src = inspect.getsource(sci)
    banned = {"juice-shop", "vampi", "crapi", "wavsep", "getedunext"}
    for ident in banned:
        assert ident not in src.lower()
