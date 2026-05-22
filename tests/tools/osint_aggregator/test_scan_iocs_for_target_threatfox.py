"""Tests for iter-22.6 `scan_iocs_for_target_threatfox` wrapper."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.osint_aggregator.scan_iocs_for_target_threatfox  # noqa: F401,E501
stf = sys.modules[
    "strix.tools.osint_aggregator.scan_iocs_for_target_threatfox"
]
scan_iocs_for_target_threatfox = stf.scan_iocs_for_target_threatfox


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_THREATFOX_DISABLED", raising=False)


def test_error_when_target_empty():
    out = scan_iocs_for_target_threatfox("")
    assert out["status"] == "error"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_THREATFOX_DISABLED", "1")
    out = scan_iocs_for_target_threatfox("example.com")
    assert out["status"] == "partial"


def test_no_result_returns_zero_findings(monkeypatch):
    """ThreatFox returns query_status='no_result' when no IoC
    matches — we surface this as ok with zero findings (not
    error)."""
    monkeypatch.setattr(
        stf, "_post_json",
        lambda url, payload, timeout: (
            {"query_status": "no_result", "data": []}, None,
        ),
    )
    out = scan_iocs_for_target_threatfox("clean.example.com")
    assert out["status"] == "ok"
    assert out["total_findings"] == 0


def test_http_failure_returns_partial(monkeypatch):
    monkeypatch.setattr(
        stf, "_post_json",
        lambda url, payload, timeout: (None, "connection refused"),
    )
    out = scan_iocs_for_target_threatfox("example.com")
    assert out["status"] == "partial"
    assert "connection refused" in out["reason"]


def test_unexpected_shape_returns_partial(monkeypatch):
    monkeypatch.setattr(
        stf, "_post_json",
        lambda url, payload, timeout: ("not a dict", None),
    )
    out = scan_iocs_for_target_threatfox("example.com")
    assert out["status"] == "partial"


def test_domain_match_emits_high(monkeypatch):
    monkeypatch.setattr(
        stf, "_post_json",
        lambda url, payload, timeout: ({
            "query_status": "ok",
            "data": [{
                "ioc": "bad.example.com",
                "ioc_type": "domain",
                "threat_type": "botnet_cc",
                "malware": "Cobalt Strike",
                "confidence_level": 90,
                "first_seen": "2026-05-15",
            }],
        }, None),
    )
    out = scan_iocs_for_target_threatfox("bad.example.com")
    assert out["status"] == "ok"
    assert out["total_findings"] == 1
    f = out["findings"][0]
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-829"
    assert "Cobalt Strike" in f["title"]


def test_hash_match_emits_critical(monkeypatch):
    monkeypatch.setattr(
        stf, "_post_json",
        lambda url, payload, timeout: ({
            "query_status": "ok",
            "data": [{
                "ioc": "a" * 64,
                "ioc_type": "sha256_hash",
                "threat_type": "payload",
                "malware": "RedLine Stealer",
                "confidence_level": 100,
                "first_seen": "2026-05-20",
            }],
        }, None),
    )
    out = scan_iocs_for_target_threatfox("a" * 64)
    assert out["total_findings"] == 1
    assert out["findings"][0]["severity"] == "critical"
    assert out["findings"][0]["cwe"] == "CWE-506"


def test_ip_port_match_emits_medium(monkeypatch):
    monkeypatch.setattr(
        stf, "_post_json",
        lambda url, payload, timeout: ({
            "query_status": "ok",
            "data": [{
                "ioc": "1.2.3.4:443",
                "ioc_type": "ip:port",
                "threat_type": "botnet_cc",
                "malware": "Unknown",
                "confidence_level": 75,
                "first_seen": "2026-05-21",
            }],
        }, None),
    )
    out = scan_iocs_for_target_threatfox("1.2.3.4:443")
    assert out["findings"][0]["severity"] == "medium"


def test_unknown_query_status_returns_partial(monkeypatch):
    monkeypatch.setattr(
        stf, "_post_json",
        lambda url, payload, timeout: (
            {"query_status": "rate_limited", "data": []}, None,
        ),
    )
    out = scan_iocs_for_target_threatfox("example.com")
    assert out["status"] == "partial"
    assert "rate_limited" in out["reason"]


def test_multiple_matches_emit_multiple_findings(monkeypatch):
    monkeypatch.setattr(
        stf, "_post_json",
        lambda url, payload, timeout: ({
            "query_status": "ok",
            "data": [
                {
                    "ioc": "bad.example.com", "ioc_type": "domain",
                    "threat_type": "botnet_cc",
                    "malware": "TrickBot",
                    "confidence_level": 90,
                    "first_seen": "2026-05-15",
                },
                {
                    "ioc": "https://bad.example.com/payload",
                    "ioc_type": "url",
                    "threat_type": "payload_delivery",
                    "malware": "TrickBot",
                    "confidence_level": 95,
                    "first_seen": "2026-05-16",
                },
            ],
        }, None),
    )
    out = scan_iocs_for_target_threatfox("bad.example.com")
    assert out["total_findings"] == 2


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("scan_iocs_for_target_threatfox"))
