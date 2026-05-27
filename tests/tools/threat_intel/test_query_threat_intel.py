"""Tests for iter-Q5.7 + Q5.7a — `query_threat_intel`.

Unified threat-intel fetcher per CLAUDE.md §1.5.7 FETCH EXTERNAL
bucket. The test surface is intentionally narrow: this is a thin
router + cache + unification layer over 4 existing wrappers (which
have their own tests). Verify:

  * Validation: exactly-one-of routing keys
  * Each kind dispatches to the right sub-source
  * Unified response shape
  * Cache hit behaviour (24h TTL)
  * Sub-source exception handling (best-effort, never raises)
  * Tool registration + catalog membership
"""

from __future__ import annotations

from unittest import mock

import pytest

from strix.tools.threat_intel.query_threat_intel import query_threat_intel


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """Isolate cache per test via STRIX_RUN_DIR."""
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))


# ---------------------------------------------------------------------------
# Validation — exactly-one-of
# ---------------------------------------------------------------------------


def test_rejects_no_args() -> None:
    out = query_threat_intel()
    assert out["success"] is False
    assert out["status"] == "error"
    assert "exactly one of" in out["reason"]


def test_rejects_two_args() -> None:
    out = query_threat_intel(cve_id="CVE-2021-44228", domain="example.com")
    assert out["success"] is False
    assert "only one query kind" in out["reason"]


def test_rejects_empty_string() -> None:
    out = query_threat_intel(cve_id="")
    assert out["success"] is False
    assert "exactly one of" in out["reason"]


def test_rejects_whitespace_only() -> None:
    out = query_threat_intel(cve_id="   ")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Routing — CVE
# ---------------------------------------------------------------------------


def test_cve_routes_to_cve_intel_and_kev() -> None:
    """cve_id should call both cve_intel_search + kev_diff_check."""
    cve_intel_payload = {
        "cvss": {"score": 10.0, "severity": "critical"},
        "advisories": [{"vendor": "Apache", "url": "https://example/log4j"}],
        "exploit_availability": {"public_poc": True},
    }
    kev_payload = {
        "matches": [
            {
                "dateAdded": "2021-12-10",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
            },
        ],
        "epss": {"score": 0.97, "percentile": 99},
    }
    with mock.patch(
        "strix.tools.cve_intel.cve_intel_search.cve_intel_search",
        return_value=cve_intel_payload,
    ) as mock_intel, mock.patch(
        "strix.tools.kev_diff.kev_diff_check.kev_diff_check",
        return_value=kev_payload,
    ) as mock_kev:
        out = query_threat_intel(cve_id="CVE-2021-44228")

    mock_intel.assert_called_once_with(cve_id="CVE-2021-44228")
    mock_kev.assert_called_once_with(cve_ids=["CVE-2021-44228"])
    assert out["success"] is True
    assert out["status"] == "ok"
    assert out["query"] == {"kind": "cve_id", "value": "CVE-2021-44228"}
    assert out["cvss"]["score"] == 10.0
    assert out["kev"]["is_listed"] is True
    assert out["kev"]["date_added"] == "2021-12-10"
    assert out["epss"]["score"] == 0.97
    assert len(out["advisories"]) == 1
    assert out["exploit_availability"]["public_poc"] is True


def test_cve_kev_not_listed_returns_explicit_false() -> None:
    """When KEV returns no matches, we should still get a structured
    'is_listed: False' rather than a missing key."""
    with mock.patch(
        "strix.tools.cve_intel.cve_intel_search.cve_intel_search",
        return_value={"cvss": {"score": 5.0}},
    ), mock.patch(
        "strix.tools.kev_diff.kev_diff_check.kev_diff_check",
        return_value={"matches": []},
    ):
        out = query_threat_intel(cve_id="CVE-2020-9999")
    assert out["kev"] == {"is_listed": False}


# ---------------------------------------------------------------------------
# Routing — CWE
# ---------------------------------------------------------------------------


def test_cwe_returns_static_placeholder() -> None:
    """CWE queries skip the network — LLM training data covers them."""
    out = query_threat_intel(cwe_id="CWE-89")
    assert out["success"] is True
    assert out["query"] == {"kind": "cwe_id", "value": "CWE-89"}
    assert "CWE-89" in out["reason"]
    assert out["cvss"] is None
    assert out["kev"] is None


# ---------------------------------------------------------------------------
# Routing — product
# ---------------------------------------------------------------------------


def test_product_routes_to_nvd_lookup() -> None:
    nvd_payload = {
        "cves": [
            {"id": "CVE-2024-1", "cvss_score": 9.8},
            {"id": "CVE-2024-2", "cvss_score": 7.5},
        ],
        "advisories": [],
    }
    with mock.patch(
        "strix.tools.nvd_lookup.nvd_lookup.nvd_lookup",
        return_value=nvd_payload,
    ) as mock_nvd:
        out = query_threat_intel(product="apache-tomcat", version="9.0.49")

    mock_nvd.assert_called_once_with(product="apache-tomcat", version="9.0.49")
    # Worst-CVSS surfacing — picks 9.8 over 7.5
    assert out["cvss"]["score"] == 9.8
    assert out["query"]["kind"] == "product"


def test_product_without_version_works() -> None:
    """`version` is optional on product queries."""
    with mock.patch(
        "strix.tools.nvd_lookup.nvd_lookup.nvd_lookup",
        return_value={"cves": []},
    ) as mock_nvd:
        out = query_threat_intel(product="generic-product")
    mock_nvd.assert_called_once_with(product="generic-product")
    assert out["success"] is True


# ---------------------------------------------------------------------------
# Routing — domain (Q5.7a)
# ---------------------------------------------------------------------------


def test_domain_routes_to_dns_hygiene_and_typosquats() -> None:
    """Q5.7a — domain= adds a passive-DNS + reputation channel."""
    dns_payload = {"summary": {"spf": "pass", "dmarc": "p=quarantine"}}
    twist_payload = {"total_findings": 12}
    with mock.patch(
        "strix.tools.checkdmarc_runner.scan_dns_hygiene_checkdmarc."
        "scan_dns_hygiene_checkdmarc",
        return_value=dns_payload,
    ), mock.patch(
        "strix.tools.osint_aggregator.scan_typosquats_dnstwist."
        "scan_typosquats_dnstwist",
        return_value=twist_payload,
    ):
        out = query_threat_intel(domain="example.com")

    assert out["success"] is True
    assert out["query"] == {"kind": "domain", "value": "example.com"}
    assert out["domain_intel"]["passive_dns"]["spf"] == "pass"
    assert out["domain_intel"]["reputation"]["typosquat_count"] == 12


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def test_repeat_call_hits_cache() -> None:
    """Second call with the same query returns cache_hit=True without
    re-firing the sub-source."""
    with mock.patch(
        "strix.tools.cve_intel.cve_intel_search.cve_intel_search",
        return_value={"cvss": {"score": 8.0}},
    ) as mock_intel, mock.patch(
        "strix.tools.kev_diff.kev_diff_check.kev_diff_check",
        return_value={"matches": []},
    ):
        out1 = query_threat_intel(cve_id="CVE-2024-XXXX")
        out2 = query_threat_intel(cve_id="CVE-2024-XXXX")

    assert out1["cache_hit"] is False
    assert out2["cache_hit"] is True
    # Sub-source was hit only once.
    assert mock_intel.call_count == 1
    # Cached payload identical (minus the cache_hit flag).
    assert out2["cvss"] == out1["cvss"]


def test_different_cve_does_not_hit_cache() -> None:
    """Cache key is per query — different CVEs get separate entries."""
    with mock.patch(
        "strix.tools.cve_intel.cve_intel_search.cve_intel_search",
        return_value={"cvss": None},
    ) as mock_intel, mock.patch(
        "strix.tools.kev_diff.kev_diff_check.kev_diff_check",
        return_value={"matches": []},
    ):
        query_threat_intel(cve_id="CVE-2024-AAAA")
        query_threat_intel(cve_id="CVE-2024-BBBB")
    assert mock_intel.call_count == 2


def test_product_version_in_cache_key() -> None:
    """Same product + different version → distinct cache entries."""
    with mock.patch(
        "strix.tools.nvd_lookup.nvd_lookup.nvd_lookup",
        return_value={"cves": []},
    ) as mock_nvd:
        query_threat_intel(product="nginx", version="1.18.0")
        query_threat_intel(product="nginx", version="1.20.0")
    assert mock_nvd.call_count == 2


# ---------------------------------------------------------------------------
# Defensive — sub-source failures
# ---------------------------------------------------------------------------


def test_cve_intel_failure_does_not_crash() -> None:
    """One sub-source raising should NOT crash the whole call."""
    with mock.patch(
        "strix.tools.cve_intel.cve_intel_search.cve_intel_search",
        side_effect=RuntimeError("NVD down"),
    ), mock.patch(
        "strix.tools.kev_diff.kev_diff_check.kev_diff_check",
        return_value={"matches": []},
    ):
        out = query_threat_intel(cve_id="CVE-2024-9999")
    # The umbrella swallows the sub-source exception and returns a
    # success=True dict with whatever it could gather.
    assert out["success"] is True
    assert out["status"] == "ok"
    # KEV still surfaces.
    assert out["kev"] == {"is_listed": False}


def test_both_subsources_fail_still_returns() -> None:
    with mock.patch(
        "strix.tools.cve_intel.cve_intel_search.cve_intel_search",
        side_effect=RuntimeError("down 1"),
    ), mock.patch(
        "strix.tools.kev_diff.kev_diff_check.kev_diff_check",
        side_effect=RuntimeError("down 2"),
    ):
        out = query_threat_intel(cve_id="CVE-2024-XX")
    # No data, but the dict is still well-shaped.
    assert out["success"] is True
    assert out["cvss"] is None
    assert out["kev"] is None


# ---------------------------------------------------------------------------
# Tool registration + catalog membership
# ---------------------------------------------------------------------------


def test_query_threat_intel_is_registered() -> None:
    from strix.tools.registry import get_tool_by_name, get_tool_names
    assert "query_threat_intel" in get_tool_names()
    fn = get_tool_by_name("query_threat_intel")
    assert fn is not None
    assert callable(fn)


def test_query_threat_intel_in_minimal_core() -> None:
    from strix.agents.lead_agent.tool_catalog import _MINIMAL_CORE_TOOLS
    assert "query_threat_intel" in _MINIMAL_CORE_TOOLS


def test_query_threat_intel_in_legacy_core() -> None:
    from strix.agents.lead_agent.tool_catalog import _CORE_TOOLS
    assert "query_threat_intel" in _CORE_TOOLS


# ---------------------------------------------------------------------------
# Closes the L2-audience capability gap
# ---------------------------------------------------------------------------


def test_reaches_lead_for_every_asset_type() -> None:
    """The FETCH EXTERNAL bucket was empty pre-Q5.7. Now every asset
    type's lead can fetch real-time CVE/KEV/EPSS for findings via this
    universal CORE tool. Verify."""
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog
    for asset in (
        "web_application", "api", "repository", "local_code",
        "container_image", "ip_address", "domain",
    ):
        catalog = get_lead_tool_catalog(target_types=[asset])
        assert "query_threat_intel" in catalog, (
            f"query_threat_intel must be visible to {asset} lead — "
            f"closes the FETCH EXTERNAL bucket per CLAUDE.md §1.5.7"
        )
