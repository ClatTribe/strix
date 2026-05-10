"""Tests for the LLM-facing threat-intel tools."""

from __future__ import annotations

import pytest

from strix.threat_intel import cache as ti_cache
from strix.threat_intel.tools import (
    list_actively_exploited_cves,
    lookup_cve_by_id,
    lookup_known_cves,
    threat_intel_status,
)


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


def _seed(tmp_cache):
    ti_cache.upsert_cves([
        {
            "cve_id": "CVE-2024-1001", "cvss_score": 9.8,
            "severity": "critical",
            "components": [{
                "vendor": "apache", "product": "http_server",
                "version_pattern": ">=2.4.0,<2.4.55",
            }],
        },
        {
            "cve_id": "CVE-2024-1002", "cvss_score": 5.5,
            "severity": "medium",
            "components": [{
                "vendor": "apache", "product": "http_server",
                "version_pattern": "*",
            }],
        },
    ], source="nvd")
    ti_cache.upsert_kev_entries([
        {"cve_id": "CVE-2024-1001", "vendor": "apache",
         "product": "http_server", "vuln_name": "Apache RCE"},
    ])
    ti_cache.upsert_epss_scores([
        ("CVE-2024-1001", 0.97),
        ("CVE-2024-1002", 0.05),
    ])


# ---------------------------------------------------------------------------
# lookup_known_cves
# ---------------------------------------------------------------------------


def test_lookup_known_cves_basic(tmp_cache) -> None:
    _seed(tmp_cache)
    result = lookup_known_cves(component="http_server")
    assert result["status"] == "ok"
    assert result["match_count"] == 2
    assert result["kev_count"] == 1
    assert result["high_epss_count"] == 1
    assert result["critical_count"] == 1
    assert "actively exploited" in result["next_action_hint"].lower()


def test_lookup_known_cves_with_version(tmp_cache) -> None:
    _seed(tmp_cache)
    result = lookup_known_cves(
        component="http_server", version="2.4.50",
    )
    # 2.4.50 hits both bounded and wildcard.
    cve_ids = {c["cve_id"] for c in result["cves"]}
    assert "CVE-2024-1001" in cve_ids
    assert "CVE-2024-1002" in cve_ids


def test_lookup_known_cves_only_kev(tmp_cache) -> None:
    _seed(tmp_cache)
    result = lookup_known_cves(component="http_server", only_kev=True)
    assert result["match_count"] == 1
    assert result["cves"][0]["cve_id"] == "CVE-2024-1001"


def test_lookup_known_cves_min_epss(tmp_cache) -> None:
    _seed(tmp_cache)
    result = lookup_known_cves(
        component="http_server", min_epss=0.5,
    )
    assert all(c["epss"] is None or c["epss"] >= 0.5 for c in result["cves"])


def test_lookup_known_cves_unknown_component(tmp_cache) -> None:
    _seed(tmp_cache)
    result = lookup_known_cves(component="notarealproduct")
    assert result["status"] == "ok"
    assert result["match_count"] == 0
    assert "no actively-exploited" in result["next_action_hint"].lower()


def test_lookup_known_cves_empty_component_returns_error(tmp_cache) -> None:
    result = lookup_known_cves(component="")
    assert result["status"] == "error"


def test_lookup_known_cves_max_records_caps(tmp_cache) -> None:
    _seed(tmp_cache)
    result = lookup_known_cves(component="http_server", max_records=1)
    assert len(result["cves"]) == 1


# ---------------------------------------------------------------------------
# lookup_cve_by_id
# ---------------------------------------------------------------------------


def test_lookup_cve_by_id_known(tmp_cache) -> None:
    _seed(tmp_cache)
    r = lookup_cve_by_id("CVE-2024-1001")
    assert r["status"] == "ok"
    assert r["cve"]["cve_id"] == "CVE-2024-1001"
    assert r["cve"]["kev"] is True


def test_lookup_cve_by_id_unknown(tmp_cache) -> None:
    r = lookup_cve_by_id("CVE-9999-9999")
    assert r["status"] == "not_found"
    assert "refresh" in (r.get("message") or "").lower()


def test_lookup_cve_by_id_empty_returns_error(tmp_cache) -> None:
    r = lookup_cve_by_id("")
    assert r["status"] == "error"


# ---------------------------------------------------------------------------
# list_actively_exploited_cves
# ---------------------------------------------------------------------------


def test_list_actively_exploited(tmp_cache) -> None:
    _seed(tmp_cache)
    r = list_actively_exploited_cves()
    assert r["status"] == "ok"
    # Both meet (KEV or high EPSS).
    assert r["match_count"] >= 1


def test_list_actively_exploited_threshold(tmp_cache) -> None:
    _seed(tmp_cache)
    # min_epss=0.99 — only CVEs with EPSS>=0.99; we have 0.97 only.
    # KEV-flagged still surfaces independently of EPSS.
    r = list_actively_exploited_cves(min_epss=0.99)
    ids = {c["cve_id"] for c in r["cves"]}
    assert "CVE-2024-1001" in ids  # via KEV


# ---------------------------------------------------------------------------
# threat_intel_status
# ---------------------------------------------------------------------------


def test_threat_intel_status_empty_suggests_refresh(tmp_cache) -> None:
    r = threat_intel_status()
    assert r["status"] == "ok"
    assert "refresh" in r.get("refresh_hint", "").lower()


def test_threat_intel_status_healthy(tmp_cache) -> None:
    _seed(tmp_cache)
    ti_cache.record_feed_status("kev", status="ok", record_count=1)
    ti_cache.record_feed_status("epss", status="ok", record_count=1)
    ti_cache.record_feed_status("nvd", status="ok", record_count=2)
    r = threat_intel_status()
    assert "healthy" in r.get("refresh_hint", "").lower()
    assert r["totals"]["cves"] == 2


def test_threat_intel_status_error_feed_surfaces_in_hint(tmp_cache) -> None:
    ti_cache.record_feed_status("kev", status="error", error="boom")
    r = threat_intel_status()
    assert "kev" in r.get("refresh_hint", "").lower()


# ---------------------------------------------------------------------------
# Registry wiring — these tools should appear in the lead's catalog
# ---------------------------------------------------------------------------


def test_tools_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog
    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "lookup_known_cves" in catalog
    assert "lookup_cve_by_id" in catalog
    assert "list_actively_exploited_cves" in catalog
    assert "threat_intel_status" in catalog


def test_tools_registered_with_framework_provenance() -> None:
    from strix.tools.registry import get_tool_by_name, get_tool_provenance
    for tool_name in (
        "lookup_known_cves", "lookup_cve_by_id",
        "list_actively_exploited_cves", "threat_intel_status",
    ):
        fn = get_tool_by_name(tool_name)
        assert fn is not None, f"{tool_name} not registered"
        assert get_tool_provenance(tool_name) == "framework"
