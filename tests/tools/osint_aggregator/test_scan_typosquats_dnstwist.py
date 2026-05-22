"""Tests for iter-22.6 `scan_typosquats_dnstwist` wrapper."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.osint_aggregator.scan_typosquats_dnstwist  # noqa: F401,E501
std = sys.modules[
    "strix.tools.osint_aggregator.scan_typosquats_dnstwist"
]
scan_typosquats_dnstwist = std.scan_typosquats_dnstwist


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_DNSTWIST_DISABLED", raising=False)


def test_error_when_domain_empty():
    out = scan_typosquats_dnstwist("")
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = scan_typosquats_dnstwist("example.com")
    assert out["status"] == "partial"
    assert "dnstwist" in out["reason"]


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_DNSTWIST_DISABLED", "1")
    out = scan_typosquats_dnstwist("example.com")
    assert out["status"] == "partial"


def test_emits_finding_per_registered_squat(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/dnstwist" if b == "dnstwist" else None,
    )
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = json.dumps([
        {
            "domain": "example.com",       # apex itself — should be skipped
            "fuzzer": "original",
            "dns_a": ["1.2.3.4"],
        },
        {
            "domain": "examp1e.com",       # homograph
            "fuzzer": "homoglyph",
            "dns_a": ["5.6.7.8"],
        },
        {
            "domain": "exampleco.com",     # addition
            "fuzzer": "addition",
            "dns_a": ["9.10.11.12"],
        },
    ])
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))

    out = scan_typosquats_dnstwist("example.com")
    assert out["status"] == "ok"
    # 2 findings — apex itself skipped
    assert out["total_findings"] == 2
    squats = {f["squat_domain"] for f in out["findings"]}
    assert "examp1e.com" in squats
    assert "exampleco.com" in squats
    assert "example.com" not in squats


def test_max_variants_caps(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/dnstwist" if b == "dnstwist" else None,
    )
    records = [
        {"domain": f"squat{i}.com", "fuzzer": "addition",
         "dns_a": ["1.2.3.4"]}
        for i in range(50)
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = json.dumps(records)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))

    out = scan_typosquats_dnstwist("example.com", max_variants=10)
    assert out["total_findings"] == 10


def test_handles_garbage_stdout(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/dnstwist" if b == "dnstwist" else None,
    )
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "not json"
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))

    out = scan_typosquats_dnstwist("example.com")
    assert out["status"] == "ok"
    assert out["total_findings"] == 0


def test_subprocess_timeout_returns_error(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/dnstwist" if b == "dnstwist" else None,
    )

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="dnstwist", timeout=120)

    monkeypatch.setattr(subprocess, "run", _boom)
    out = scan_typosquats_dnstwist("example.com")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("scan_typosquats_dnstwist"))
