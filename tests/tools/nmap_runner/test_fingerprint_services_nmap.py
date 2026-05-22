"""Tests for iter-23.1 `fingerprint_services_nmap` wrapper."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.nmap_runner.fingerprint_services_nmap  # noqa: F401,E501
fsn_mod = sys.modules["strix.tools.nmap_runner.fingerprint_services_nmap"]
fingerprint_services_nmap = fsn_mod.fingerprint_services_nmap


_SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"
                 extrainfo="Ubuntu 4ubuntu0.5"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
        <service name="mysql"/>
      </port>
      <port protocol="tcp" portid="5432">
        <state state="open"/>
        <service name="postgresql" product="PostgreSQL DB" version="13.2"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_NMAP_DISABLED", raising=False)


def test_error_when_empty():
    out = fingerprint_services_nmap("")
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = fingerprint_services_nmap("10.0.0.5")
    assert out["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_NMAP_DISABLED", "1")
    out = fingerprint_services_nmap("10.0.0.5")
    assert out["status"] == "partial"


def test_parses_xml_open_ports_only(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/bin/nmap" if b == "nmap" else None,
    )
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = _SAMPLE_XML
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = fingerprint_services_nmap("10.0.0.5")
    assert out["status"] == "ok"
    # closed port 3306 must be excluded — 3 open
    assert out["total_open_ports"] == 3
    ports = sorted(s["port"] for s in out["services"])
    assert ports == [22, 80, 5432]
    pg = next(s for s in out["services"] if s["port"] == 5432)
    assert pg["product"] == "PostgreSQL DB"
    assert pg["version"] == "13.2"
    ssh = next(s for s in out["services"] if s["port"] == 22)
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "8.2p1"
    assert "Ubuntu" in ssh["extrainfo"]


def test_no_hosts_returns_zero(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/bin/nmap" if b == "nmap" else None,
    )
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = '<?xml version="1.0"?><nmaprun></nmaprun>'
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = fingerprint_services_nmap("10.0.0.5")
    assert out["status"] == "ok"
    assert out["total_open_ports"] == 0


def test_bad_xml_returns_error(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/bin/nmap" if b == "nmap" else None,
    )
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "not xml at all <<<"
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = fingerprint_services_nmap("10.0.0.5")
    assert out["status"] == "error"


def test_timeout(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/bin/nmap" if b == "nmap" else None,
    )

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=300)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = fingerprint_services_nmap("10.0.0.5")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("fingerprint_services_nmap"))
