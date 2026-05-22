"""Tests for iter-22.6 `scan_credential_leaks_hibp` wrapper."""

from __future__ import annotations

import sys

import pytest


import strix.tools.hibp_runner.scan_credential_leaks_hibp  # noqa: F401,E501
sclh_mod = sys.modules["strix.tools.hibp_runner.scan_credential_leaks_hibp"]
scan_credential_leaks_hibp = sclh_mod.scan_credential_leaks_hibp


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_HIBP_DISABLED", raising=False)


def test_error_when_empty():
    out = scan_credential_leaks_hibp("")
    assert out["status"] == "error"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_HIBP_DISABLED", "1")
    out = scan_credential_leaks_hibp("example.com")
    assert out["status"] == "partial"


def test_emits_finding_per_verified_breach(monkeypatch):
    monkeypatch.setattr(
        sclh_mod, "_http_get_json",
        lambda url, timeout: ([
            {
                "Name": "BreachA", "Title": "Breach A",
                "BreachDate": "2024-01-01",
                "PwnCount": 1234567,
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": True,
            },
            {
                "Name": "BreachB", "Title": "Breach B",
                "BreachDate": "2023-06-01",
                "PwnCount": 9000,
                "DataClasses": ["Email addresses"],
                "IsVerified": True,
            },
            # Unverified entries skipped
            {
                "Name": "UnverifiedX", "Title": "X",
                "BreachDate": "2025-01-01",
                "PwnCount": 100, "DataClasses": [],
                "IsVerified": False,
            },
        ], None),
    )
    out = scan_credential_leaks_hibp("example.com")
    assert out["status"] == "ok"
    assert out["total_findings"] == 2
    breaches = {f["breach_name"] for f in out["findings"]}
    assert "BreachA" in breaches
    assert "BreachB" in breaches
    assert "UnverifiedX" not in breaches


def test_no_breaches_returns_zero(monkeypatch):
    monkeypatch.setattr(
        sclh_mod, "_http_get_json",
        lambda url, timeout: ([], None),
    )
    out = scan_credential_leaks_hibp("clean.example.com")
    assert out["status"] == "ok"
    assert out["total_findings"] == 0


def test_http_failure_returns_partial(monkeypatch):
    monkeypatch.setattr(
        sclh_mod, "_http_get_json",
        lambda url, timeout: (None, "connection refused"),
    )
    out = scan_credential_leaks_hibp("example.com")
    assert out["status"] == "partial"
    assert "connection refused" in out["reason"]


def test_unexpected_shape_returns_partial(monkeypatch):
    monkeypatch.setattr(
        sclh_mod, "_http_get_json",
        lambda url, timeout: ({"not": "a list"}, None),
    )
    out = scan_credential_leaks_hibp("example.com")
    assert out["status"] == "partial"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("scan_credential_leaks_hibp"))
