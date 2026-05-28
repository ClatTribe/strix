"""Tests for iter-Q5.48 — `extract_sbom_syft` wrapper."""

from __future__ import annotations

import importlib
import json
from typing import Any

import pytest

sci = importlib.import_module("strix.tools.syft_runner.extract_sbom_syft")
extract_sbom_syft = sci.extract_sbom_syft


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    for k in ("STRIX_SYFT_DISABLED", "STRIX_SYFT_FORMAT"):
        monkeypatch.delenv(k, raising=False)


def _mock_syft(monkeypatch, stdout: str, returncode: int = 0, stderr: str = ""):
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/syft" if b == "syft" else None,
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


# ---- recall-safe ----

def test_error_when_empty():
    out = extract_sbom_syft("")
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = extract_sbom_syft("nginx:1.25")
    assert out["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_SYFT_DISABLED", "1")
    out = extract_sbom_syft("nginx:1.25")
    assert out["status"] == "partial"


# ---- format validation ----

def test_unknown_format_returns_error(monkeypatch):
    _mock_syft(monkeypatch, "{}")
    out = extract_sbom_syft("nginx:1.25", sbom_format="garbage")
    assert out["status"] == "error"
    assert "unsupported sbom_format" in out["reason"]


def test_format_env_override(monkeypatch):
    monkeypatch.setenv("STRIX_SYFT_FORMAT", "spdx-json")
    captured = _mock_syft(monkeypatch, json.dumps({"packages": []}))
    extract_sbom_syft("nginx:1.25", sbom_format="cyclonedx-json")
    cmd = captured[0]
    idx = cmd.index("-o")
    assert cmd[idx + 1] == "spdx-json"


# ---- JSON parsing ----

def test_cyclonedx_json_parsed(monkeypatch):
    payload: dict[str, Any] = {
        "components": [
            {"name": "openssl", "version": "1.0.0"},
            {"name": "libc", "version": "2.31"},
        ],
    }
    _mock_syft(monkeypatch, json.dumps(payload))
    out = extract_sbom_syft("nginx:1.25", sbom_format="cyclonedx-json")
    assert out["status"] == "ok"
    assert out["format"] == "cyclonedx-json"
    assert out["package_count"] == 2
    assert out["sbom"] == payload


def test_spdx_json_parsed(monkeypatch):
    payload = {"packages": [{"name": "openssl"}, {"name": "libc"}, {"name": "zlib"}]}
    _mock_syft(monkeypatch, json.dumps(payload))
    out = extract_sbom_syft("nginx:1.25", sbom_format="spdx-json")
    assert out["package_count"] == 3


def test_syft_json_parsed(monkeypatch):
    payload = {"artifacts": [{"name": "a"}, {"name": "b"}]}
    _mock_syft(monkeypatch, json.dumps(payload))
    out = extract_sbom_syft("nginx:1.25", sbom_format="syft-json")
    assert out["package_count"] == 2


def test_table_format_passthrough(monkeypatch):
    _mock_syft(monkeypatch, "NAME VERSION\nopenssl 1.0.0\nlibc 2.31\n")
    out = extract_sbom_syft("nginx:1.25", sbom_format="table")
    assert out["status"] == "ok"
    assert isinstance(out["sbom"], str)
    # Best-effort: 3 non-empty lines - 1 header = 2 packages.
    assert out["package_count"] == 2


def test_invalid_json_returns_error(monkeypatch):
    _mock_syft(monkeypatch, "not json", returncode=0)
    out = extract_sbom_syft("nginx:1.25", sbom_format="cyclonedx-json")
    assert out["status"] == "error"
    assert "unparseable" in out["reason"]


# ---- subprocess errors ----

def test_nonzero_returncode_returns_error(monkeypatch):
    _mock_syft(monkeypatch, "", returncode=2, stderr="syft: cannot pull image")
    out = extract_sbom_syft("nginx:1.25")
    assert out["status"] == "error"
    assert "exit 2" in out["reason"]


def test_empty_stdout_returns_error(monkeypatch):
    _mock_syft(monkeypatch, "  ", returncode=0)
    out = extract_sbom_syft("nginx:1.25")
    assert out["status"] == "error"


def test_timeout_returns_error(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: "/usr/local/bin/syft")

    def _raise(*_a, **_k):
        raise sci.subprocess.TimeoutExpired(cmd="syft", timeout=300)

    monkeypatch.setattr(sci.subprocess, "run", _raise)
    out = extract_sbom_syft("nginx:1.25")
    assert out["status"] == "error"


# ---- return shape ----

def test_required_keys(monkeypatch):
    _mock_syft(monkeypatch, json.dumps({"components": []}))
    out = extract_sbom_syft("nginx:1.25")
    for k in ("success", "status", "image_ref", "format", "sbom", "package_count"):
        assert k in out


def test_no_fixture_identifiers():
    import inspect
    src = inspect.getsource(sci)
    banned = {"juice-shop", "vampi", "crapi", "wavsep", "getedunext"}
    for ident in banned:
        assert ident not in src.lower()
