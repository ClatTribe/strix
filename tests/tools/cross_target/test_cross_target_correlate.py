"""Tests for cross_target_correlate.

Hermetic — no real cache files / no HTTP. Tests cover:

- Empty inputs → no-op success
- domain_ip_reputation: pairs from surface_map; ≥3 sources flag → high;
  1-2 sources → medium; no flags → no finding
- kev_in_customer_stack: finding with cve+is_kev → bumped severity;
  ransomware flag → critical
- cve_in_threat_feed: finding's CVE in feed → high; not in feed → no finding
- threat_feed_ioc_match: scan IPs/domains in feed → high
- Per-(class, target) dedup — same correlation runs only once
- enable_correlations subset works
- §11 UX baseline
- check.completed event
- MITRE T1592 + T1589 attached
- Schema integrity
- Helper unit tests
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


import strix.tools.cross_target.cross_target_correlate  # noqa: F401

ct_module = sys.modules["strix.tools.cross_target.cross_target_correlate"]
cross_target_correlate = ct_module.cross_target_correlate


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("ct-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "domain", "value": "example.com"}]}
    )
    yield


def _findings_from_tracer() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    if t is None:
        return []
    return list(t.get_existing_vulnerabilities())


def _check_summary() -> dict[str, Any]:
    t = tracer_module.get_global_tracer()
    if t is None:
        return {}
    return t.get_check_summary()


def _no_rep(_ip: str) -> dict[str, Any]:
    return {"flags": [], "sources": [], "max_severity": "none"}


# ---------------------------------------------------------------------------
# Empty / no-op
# ---------------------------------------------------------------------------


def test_no_inputs_no_op() -> None:
    out = cross_target_correlate(
        findings=[], surface_map=None, ip_reputation_lookup=_no_rep,
    )
    assert out["success"] is True
    assert out["findings_emitted"] == 0
    assert out["correlations_evaluated"] == []


def test_empty_surface_map_skips_domain_ip() -> None:
    out = cross_target_correlate(
        findings=[], surface_map={"subdomain_enum": {"subdomains": []}},
        ip_reputation_lookup=_no_rep,
    )
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# domain_ip_reputation
# ---------------------------------------------------------------------------


def test_domain_ip_reputation_three_sources_high() -> None:
    surface_map = {
        "subdomain_triage": [
            {"subdomain": "api.example.com", "ips_resolved": ["198.51.100.10"]},
        ],
    }

    def lookup(ip: str) -> dict[str, Any]:
        if ip == "198.51.100.10":
            return {
                "flags": ["vt_malicious=12", "otx_pulses=4", "urlhaus=phishing"],
                "sources": ["virustotal", "alienvault_otx", "urlhaus"],
                "max_severity": "high",
            }
        return _no_rep(ip)

    out = cross_target_correlate(
        findings=[], surface_map=surface_map,
        ip_reputation_lookup=lookup,
    )
    findings = _findings_from_tracer()
    domain_ip = [f for f in findings if "threat-intel-flagged IP" in f.get("title", "")]
    assert len(domain_ip) == 1
    assert domain_ip[0]["severity"] == "high"
    assert "api.example.com" in domain_ip[0]["title"]
    assert "198.51.100.10" in domain_ip[0]["title"]


def test_domain_ip_reputation_one_source_medium() -> None:
    surface_map = {
        "subdomain_triage": [
            {"subdomain": "api.example.com", "ips_resolved": ["198.51.100.20"]},
        ],
    }

    def lookup(ip: str) -> dict[str, Any]:
        if ip == "198.51.100.20":
            return {
                "flags": ["vt_malicious=2"],
                "sources": ["virustotal"],
                "max_severity": "medium",
            }
        return _no_rep(ip)

    out = cross_target_correlate(
        findings=[], surface_map=surface_map,
        ip_reputation_lookup=lookup,
    )
    findings = _findings_from_tracer()
    domain_ip = [f for f in findings if "threat-intel-flagged IP" in f.get("title", "")]
    assert len(domain_ip) == 1
    assert domain_ip[0]["severity"] == "medium"


def test_domain_ip_reputation_no_flags_no_finding() -> None:
    surface_map = {
        "subdomain_triage": [
            {"subdomain": "api.example.com", "ips_resolved": ["198.51.100.30"]},
        ],
    }
    out = cross_target_correlate(
        findings=[], surface_map=surface_map,
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    assert findings == []


def test_domain_ip_reputation_passive_dns_pairs() -> None:
    """Passive DNS records also contribute (subdomain, IP) pairs."""
    surface_map = {
        "passive_dns": {
            "records": [
                {"name": "old.example.com", "ip": "198.51.100.40"},
            ]
        }
    }

    def lookup(ip: str) -> dict[str, Any]:
        if ip == "198.51.100.40":
            return {
                "flags": ["greynoise_classification=malicious"],
                "sources": ["greynoise"],
                "max_severity": "high",
            }
        return _no_rep(ip)

    cross_target_correlate(
        findings=[], surface_map=surface_map,
        ip_reputation_lookup=lookup,
    )
    findings = _findings_from_tracer()
    assert any("old.example.com" in f.get("title", "") for f in findings)


def test_domain_ip_reputation_dedup_same_pair_once() -> None:
    """Same (sub, IP) pair appearing twice in different sources → emits one finding."""
    surface_map = {
        "subdomain_triage": [
            {"subdomain": "api.example.com", "ips_resolved": ["198.51.100.50"]},
        ],
        "passive_dns": {
            "records": [
                {"name": "api.example.com", "ip": "198.51.100.50"},
            ]
        }
    }

    def lookup(ip: str) -> dict[str, Any]:
        return {
            "flags": ["vt_malicious=5"],
            "sources": ["virustotal"],
            "max_severity": "medium",
        }

    cross_target_correlate(
        findings=[], surface_map=surface_map,
        ip_reputation_lookup=lookup,
    )
    findings = _findings_from_tracer()
    domain_ip = [f for f in findings if "threat-intel-flagged" in f.get("title", "")]
    assert len(domain_ip) == 1


# ---------------------------------------------------------------------------
# kev_in_customer_stack
# ---------------------------------------------------------------------------


def test_kev_in_customer_stack_bumps_severity() -> None:
    findings_input = [
        {
            "title": "Old Apache",
            "severity": "medium",
            "category": "vulnerable_dependency",
            "cve": "CVE-2024-12345",
            "cwe": "CWE-89",
            "target": "https://api.example.com",
            "is_kev": True,
            "kev_ransomware_use": False,
            "fingerprint": "fp-medium-1",
        }
    ]
    out = cross_target_correlate(
        findings=findings_input, surface_map=None,
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    kev = [f for f in findings if "actively exploited" in f.get("title", "").lower()]
    assert len(kev) == 1
    # medium → high (one bump)
    assert kev[0]["severity"] == "high"


def test_kev_in_customer_stack_ransomware_critical() -> None:
    findings_input = [
        {
            "title": "Old PrintNightmare",
            "severity": "low",
            "category": "vulnerable_dependency",
            "cve": "CVE-2021-34527",
            "cwe": "CWE-269",
            "target": "https://app.example.com",
            "is_kev": True,
            "kev_ransomware_use": True,
            "fingerprint": "fp-low-ransom",
        }
    ]
    cross_target_correlate(
        findings=findings_input, surface_map=None,
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    kev = [f for f in findings if "actively exploited" in f.get("title", "").lower()]
    assert len(kev) == 1
    # ransomware flag → critical regardless of original
    assert kev[0]["severity"] == "critical"


def test_kev_no_kev_flag_no_correlation() -> None:
    findings_input = [
        {
            "title": "Old lib",
            "severity": "high",
            "cve": "CVE-2024-99999",
            "is_kev": False,
            "target": "https://x",
            "fingerprint": "fp-x",
        }
    ]
    cross_target_correlate(
        findings=findings_input, surface_map=None,
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    kev = [f for f in findings if "actively exploited" in f.get("title", "").lower()]
    assert kev == []


def test_kev_no_cve_no_correlation() -> None:
    findings_input = [
        {
            "title": "Some posture finding",
            "severity": "medium",
            "is_kev": True,  # nonsensical without CVE; tool ignores
            "target": "https://x",
            "fingerprint": "fp-y",
        }
    ]
    cross_target_correlate(
        findings=findings_input, surface_map=None,
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    kev = [f for f in findings if "actively exploited" in f.get("title", "").lower()]
    assert kev == []


# ---------------------------------------------------------------------------
# cve_in_threat_feed
# ---------------------------------------------------------------------------


def test_cve_in_threat_feed_match_high() -> None:
    findings_input = [
        {
            "title": "OpenSSL CVE-2024-XYZ",
            "severity": "medium",
            "cve": "CVE-2024-12345",
            "target": "https://api.example.com",
            "fingerprint": "fp-cve-1",
        }
    ]
    out = cross_target_correlate(
        findings=findings_input,
        threat_feed_iocs={"cve": ["CVE-2024-12345", "CVE-2023-77777"]},
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    feed_match = [f for f in findings if "tracked by" in f.get("title", "").lower()]
    assert len(feed_match) == 1
    assert feed_match[0]["severity"] == "high"


def test_cve_in_threat_feed_no_match_no_finding() -> None:
    findings_input = [
        {
            "title": "Some CVE",
            "severity": "medium",
            "cve": "CVE-2024-NOT-IN-FEED",
            "target": "https://x",
            "fingerprint": "fp-x",
        }
    ]
    cross_target_correlate(
        findings=findings_input,
        threat_feed_iocs={"cve": ["CVE-2024-OTHER"]},
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    feed_match = [f for f in findings if "tracked by" in f.get("title", "").lower()]
    assert feed_match == []


def test_cve_in_threat_feed_empty_feed_skips() -> None:
    findings_input = [{"cve": "CVE-X", "title": "x", "severity": "low"}]
    cross_target_correlate(
        findings=findings_input,
        threat_feed_iocs={"cve": []},
        ip_reputation_lookup=_no_rep,
    )
    assert _findings_from_tracer() == []


# ---------------------------------------------------------------------------
# threat_feed_ioc_match
# ---------------------------------------------------------------------------


def test_threat_feed_ioc_match_ip() -> None:
    surface_map = {
        "subdomain_triage": [
            {"subdomain": "x.example.com", "ips_resolved": ["198.51.100.66"]},
        ],
    }
    cross_target_correlate(
        findings=[],
        surface_map=surface_map,
        threat_feed_iocs={"ipv4": ["198.51.100.66"]},
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    feed_ioc = [f for f in findings if "matches customer threat-intel" in f.get("title", "")]
    assert len(feed_ioc) == 1
    assert feed_ioc[0]["severity"] == "high"


def test_threat_feed_ioc_match_domain_in_findings() -> None:
    findings_input = [
        {"title": "x", "severity": "low", "target": "evil.example",
         "endpoint": "https://evil.example/login", "fingerprint": "fp"}
    ]
    cross_target_correlate(
        findings=findings_input,
        threat_feed_iocs={"domain": ["evil.example"]},
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    feed_ioc = [f for f in findings if "matches customer threat-intel" in f.get("title", "")]
    assert len(feed_ioc) == 1


def test_threat_feed_no_iocs_no_finding() -> None:
    cross_target_correlate(
        findings=[{"target": "x.com", "title": "t", "severity": "low"}],
        threat_feed_iocs={},
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    feed_ioc = [f for f in findings if "matches customer threat-intel" in f.get("title", "")]
    assert feed_ioc == []


# ---------------------------------------------------------------------------
# enable_correlations subset
# ---------------------------------------------------------------------------


def test_enable_correlations_subset() -> None:
    """Only the requested classes run."""
    findings_input = [
        {
            "title": "kev-finding",
            "severity": "medium",
            "cve": "CVE-2024-A",
            "target": "https://x",
            "is_kev": True,
            "fingerprint": "fp-1",
        }
    ]
    out = cross_target_correlate(
        findings=findings_input,
        threat_feed_iocs={"cve": ["CVE-2024-A"]},
        enable_correlations=["cve_in_threat_feed"],  # not kev
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    # CVE-in-feed should fire; KEV-bump should NOT.
    feed_match = [f for f in findings if "tracked by" in f.get("title", "").lower()]
    kev = [f for f in findings if "actively exploited" in f.get("title", "").lower()]
    assert len(feed_match) == 1
    assert kev == []
    assert "cve_in_threat_feed" in out["enabled_classes"]
    assert "kev_in_customer_stack" not in out["enabled_classes"]


def test_invalid_class_filtered() -> None:
    out = cross_target_correlate(
        findings=[], surface_map=None,
        enable_correlations=["bogus_class", "kev_in_customer_stack"],
        ip_reputation_lookup=_no_rep,
    )
    assert "bogus_class" not in out["enabled_classes"]
    assert "kev_in_customer_stack" in out["enabled_classes"]


# ---------------------------------------------------------------------------
# §11 UX
# ---------------------------------------------------------------------------


def test_findings_carry_ux_fields() -> None:
    cross_target_correlate(
        findings=[
            {
                "title": "x", "severity": "medium", "cve": "CVE-2024-X",
                "target": "x", "is_kev": True, "kev_ransomware_use": True,
                "fingerprint": "fp",
            }
        ],
        surface_map=None,
        ip_reputation_lookup=_no_rep,
    )
    findings = _findings_from_tracer()
    assert findings
    for f in findings:
        assert f.get("description_plain")
        assert f.get("recommended_action")
        assert f.get("verification_status") == "needs_review"
        assert f.get("category") == "cross_target_correlation"


# ---------------------------------------------------------------------------
# Check summary
# ---------------------------------------------------------------------------


def test_check_summary_vulnerable() -> None:
    cross_target_correlate(
        findings=[
            {
                "title": "x", "severity": "medium", "cve": "CVE-2024-X",
                "target": "x", "is_kev": True, "fingerprint": "fp",
            }
        ],
        surface_map=None,
        ip_reputation_lookup=_no_rep,
    )
    summary = _check_summary()
    assert summary["by_category"]["cross_target"]["vulnerable"] >= 1


def test_check_summary_not_vulnerable() -> None:
    cross_target_correlate(
        findings=[], surface_map=None, ip_reputation_lookup=_no_rep,
    )
    summary = _check_summary()
    assert summary["by_category"]["cross_target"]["not_vulnerable"] >= 1


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def test_mitre_techniques_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques

    techniques = get_tool_mitre_techniques("cross_target_correlate")
    assert "T1592" in techniques
    assert "T1589" in techniques


# ---------------------------------------------------------------------------
# Schema integrity
# ---------------------------------------------------------------------------


def test_result_schema() -> None:
    out = cross_target_correlate(
        findings=[], surface_map=None, ip_reputation_lookup=_no_rep,
    )
    assert set(out.keys()) >= {
        "success", "enabled_classes", "correlations_evaluated",
        "findings_emitted",
    }


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


def test_bump_severity_ladder() -> None:
    assert ct_module._bump_severity("low") == "medium"
    assert ct_module._bump_severity("medium") == "high"
    assert ct_module._bump_severity("high") == "critical"
    assert ct_module._bump_severity("critical") == "critical"
    assert ct_module._bump_severity("info") == "low"


def test_bump_severity_unknown() -> None:
    assert ct_module._bump_severity("bogus") == "high"
    assert ct_module._bump_severity("") == "high"


def test_extract_subdomain_ip_pairs_dedup() -> None:
    sm = {
        "subdomain_triage": [
            {"subdomain": "x.com", "ips_resolved": ["1.1.1.1", "1.1.1.1"]},
        ],
        "passive_dns": {"records": [{"name": "x.com", "ip": "1.1.1.1"}]},
    }
    pairs = ct_module._extract_subdomain_ip_pairs(sm)
    assert ("x.com", "1.1.1.1") in pairs
    assert pairs.count(("x.com", "1.1.1.1")) == 1


def test_normalize_iocs_uppercases_cve() -> None:
    out = ct_module._normalize_iocs({"cve": ["cve-2024-1", "CVE-2024-2"]})
    assert "CVE-2024-1" in out["cve"]
    assert "CVE-2024-2" in out["cve"]


def test_normalize_iocs_lowercases_domain() -> None:
    out = ct_module._normalize_iocs({"domain": ["EVIL.example.COM"]})
    assert "evil.example.com" in out["domain"]


def test_normalize_iocs_skip_unknown_buckets() -> None:
    out = ct_module._normalize_iocs({"weird_bucket": ["x"]})
    assert "weird_bucket" not in out


def test_scan_iocs_pulls_cves_from_findings() -> None:
    findings = [{"cve": "cve-2024-x", "target": "1.2.3.4"}]
    out = ct_module._scan_iocs_from_findings_and_surface(findings, None)
    assert "CVE-2024-X" in out["cve"]
    assert "1.2.3.4" in out["ipv4"]


def test_scan_iocs_pulls_subdomains_from_surface() -> None:
    sm = {"subdomain_enum": {"subdomains": ["api.example.com", "old.example.com"]}}
    out = ct_module._scan_iocs_from_findings_and_surface([], sm)
    assert "api.example.com" in out["domain"]
    assert "old.example.com" in out["domain"]


# ---------------------------------------------------------------------------
# Default IP-reputation lookup against fixture cache files
# ---------------------------------------------------------------------------


def test_default_lookup_reads_vt_cache(tmp_path, monkeypatch) -> None:
    """When VT cache contains an entry flagging the IP, default
    lookup picks it up."""
    cache_dir = tmp_path / ".strix" / "vt_cache"
    cache_dir.mkdir(parents=True)
    payload = {
        "value": "203.0.113.99",
        "general": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1}}},
    }
    (cache_dir / "abc123.json").write_text(json.dumps(payload))

    rep = ct_module._default_ip_reputation_lookup("203.0.113.99")
    assert "virustotal" in rep["sources"]
    assert rep["max_severity"] == "high"


def test_default_lookup_reads_otx_cache(tmp_path) -> None:
    cache_dir = tmp_path / ".strix" / "otx_cache"
    cache_dir.mkdir(parents=True)
    payload = {
        "indicator": "203.0.113.50",
        "pulse_info": {"count": 5, "pulses": []},
    }
    (cache_dir / "x.json").write_text(json.dumps(payload))

    rep = ct_module._default_ip_reputation_lookup("203.0.113.50")
    assert "alienvault_otx" in rep["sources"]


def test_default_lookup_no_cache_no_flags(tmp_path) -> None:
    rep = ct_module._default_ip_reputation_lookup("203.0.113.1")
    assert rep["flags"] == []
    assert rep["max_severity"] == "none"


# ---------------------------------------------------------------------------
# End-to-end: surface_map_path auto-load
# ---------------------------------------------------------------------------


def test_auto_load_surface_map_from_path(tmp_path) -> None:
    sm_path = tmp_path / "surface_map.json"
    sm = {
        "subdomain_triage": [
            {"subdomain": "auto.example.com", "ips_resolved": ["198.51.100.77"]},
        ],
    }
    sm_path.write_text(json.dumps(sm))

    def lookup(ip: str) -> dict[str, Any]:
        if ip == "198.51.100.77":
            return {
                "flags": ["vt_malicious=5"],
                "sources": ["virustotal"],
                "max_severity": "medium",
            }
        return {"flags": [], "sources": [], "max_severity": "none"}

    out = cross_target_correlate(
        findings=[],
        surface_map_path=str(sm_path),
        ip_reputation_lookup=lookup,
    )
    findings = _findings_from_tracer()
    assert any("auto.example.com" in f.get("title", "") for f in findings)
