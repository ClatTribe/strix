"""Tests for iter-22.4 `scan_dns_hygiene_checkdmarc` wrapper."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.checkdmarc_runner.scan_dns_hygiene_checkdmarc  # noqa: F401,E501
sdh = sys.modules[
    "strix.tools.checkdmarc_runner.scan_dns_hygiene_checkdmarc"
]
scan_dns_hygiene_checkdmarc = sdh.scan_dns_hygiene_checkdmarc


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_CHECKDMARC_DISABLED", raising=False)


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_CHECKDMARC_DISABLED", "1")
    out = scan_dns_hygiene_checkdmarc("example.com")
    assert out["status"] == "partial"


def test_error_when_domain_empty():
    out = scan_dns_hygiene_checkdmarc("")
    assert out["status"] == "error"


def test_partial_when_lib_missing(monkeypatch):
    """When checkdmarc lib isn't installed (ImportError), we
    degrade to partial."""
    import builtins
    real_import = builtins.__import__

    def _denied(name, *a, **k):
        if name == "checkdmarc" or name.startswith("checkdmarc."):
            raise ImportError("checkdmarc not installed")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _denied)
    out = scan_dns_hygiene_checkdmarc("example.com")
    assert out["status"] == "partial"
    assert "checkdmarc" in out["reason"]


def test_dmarc_missing_emits_high(monkeypatch):
    """When checkdmarc returns no valid DMARC, we emit a high
    finding."""
    fake_check_domains = MagicMock(return_value=[{
        "domain": "example.com",
        "dmarc": {"valid": False, "error": "no record"},
        "spf": {"valid": True, "record": "v=spf1 -all"},
        "mta_sts": {"valid": True},
    }])

    import builtins
    real_import = builtins.__import__

    def _patch(name, *a, **k):
        mod = real_import(name, *a, **k)
        if name == "checkdmarc":
            mod.check_domains = fake_check_domains
        return mod

    monkeypatch.setattr(builtins, "__import__", _patch)
    # The wrapper does `from checkdmarc import check_domains` —
    # patch sys.modules to ensure it gets the mock.
    fake_mod = MagicMock()
    fake_mod.check_domains = fake_check_domains
    monkeypatch.setitem(sys.modules, "checkdmarc", fake_mod)

    out = scan_dns_hygiene_checkdmarc("example.com")
    assert out["status"] == "ok"
    rules = [f["rule_id"] for f in out["findings"]]
    assert "dmarc-missing" in rules
    dmarc_finding = next(f for f in out["findings"] if f["rule_id"] == "dmarc-missing")
    assert dmarc_finding["severity"] == "high"


def test_dmarc_policy_none_emits_medium(monkeypatch):
    fake_check_domains = MagicMock(return_value=[{
        "domain": "example.com",
        "dmarc": {
            "valid": True,
            "tags": {"p": {"value": "none"}},
        },
        "spf": {"valid": True, "record": "v=spf1 -all"},
        "mta_sts": {"valid": True},
    }])
    fake_mod = MagicMock()
    fake_mod.check_domains = fake_check_domains
    monkeypatch.setitem(sys.modules, "checkdmarc", fake_mod)

    out = scan_dns_hygiene_checkdmarc("example.com")
    assert out["status"] == "ok"
    rules = [f["rule_id"] for f in out["findings"]]
    assert "dmarc-policy-none" in rules


def test_spf_permissive_emits_medium(monkeypatch):
    fake_check_domains = MagicMock(return_value=[{
        "domain": "example.com",
        "dmarc": {"valid": True, "tags": {"p": {"value": "reject"}}},
        "spf": {"valid": True, "record": "v=spf1 +all"},
        "mta_sts": {"valid": True},
    }])
    fake_mod = MagicMock()
    fake_mod.check_domains = fake_check_domains
    monkeypatch.setitem(sys.modules, "checkdmarc", fake_mod)
    out = scan_dns_hygiene_checkdmarc("example.com")
    rules = [f["rule_id"] for f in out["findings"]]
    assert "spf-permissive" in rules


def test_healthy_domain_no_findings(monkeypatch):
    fake_check_domains = MagicMock(return_value=[{
        "domain": "example.com",
        "dmarc": {"valid": True, "tags": {"p": {"value": "reject"}}},
        "spf": {"valid": True, "record": "v=spf1 include:_spf.example.com -all"},
        "mta_sts": {"valid": True},
    }])
    fake_mod = MagicMock()
    fake_mod.check_domains = fake_check_domains
    monkeypatch.setitem(sys.modules, "checkdmarc", fake_mod)
    out = scan_dns_hygiene_checkdmarc("example.com")
    assert out["status"] == "ok"
    assert out["total_findings"] == 0


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("scan_dns_hygiene_checkdmarc"))
