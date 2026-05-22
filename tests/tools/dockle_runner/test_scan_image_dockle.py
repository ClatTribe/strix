"""Tests for iter-22.4 `scan_image_dockle` wrapper."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.dockle_runner.scan_image_dockle  # noqa: F401,E501
sid = sys.modules[
    "strix.tools.dockle_runner.scan_image_dockle"
]
scan_image_dockle = sid.scan_image_dockle


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_DOCKLE_DISABLED", raising=False)


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = scan_image_dockle("nginx:1.25")
    assert out["status"] == "partial"
    assert "dockle" in out["reason"]


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_DOCKLE_DISABLED", "1")
    out = scan_image_dockle("nginx:1.25")
    assert out["status"] == "partial"


def test_error_when_image_ref_empty():
    out = scan_image_dockle("")
    assert out["status"] == "error"


def test_emits_finding_per_rule(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/dockle" if b == "dockle" else None)
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = json.dumps({
        "image": "nginx:1.25",
        "details": [
            {"code": "CIS-DI-0001", "title": "Create a user for the container",
             "level": "FATAL", "alerts": ["Last user should not be root"]},
            {"code": "CIS-DI-0006", "title": "Add HEALTHCHECK instruction",
             "level": "INFO", "alerts": ["no HEALTHCHECK"]},
        ],
    })
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = scan_image_dockle("nginx:1.25")
    assert out["status"] == "ok"
    assert out["total_findings"] == 2
    rules = [f["rule_id"] for f in out["findings"]]
    assert "CIS-DI-0001" in rules
    cis_root = next(f for f in out["findings"] if f["rule_id"] == "CIS-DI-0001")
    assert cis_root["severity"] == "high"
    assert cis_root["cwe"] == "CWE-250"


def test_skips_pass_level(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/dockle" if b == "dockle" else None)
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = json.dumps({
        "details": [
            {"code": "CIS-DI-0007", "title": "ok", "level": "PASS"},
            {"code": "CIS-DI-0001", "title": "root", "level": "FATAL"},
        ],
    })
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = scan_image_dockle("nginx:1.25")
    # Only the FATAL emits; PASS is skipped
    assert out["total_findings"] == 1


def test_subprocess_failure(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/dockle" if b == "dockle" else None)
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="dockle", timeout=180)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = scan_image_dockle("nginx:1.25")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("scan_image_dockle"))
