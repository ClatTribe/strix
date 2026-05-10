"""Tests for the lookup query API."""

from __future__ import annotations

import pytest

from strix.threat_intel import cache as ti_cache
from strix.threat_intel.lookup import (
    _cmp_versions,
    _matches_pattern,
    _parse_version,
    cache_status,
    find_cves_for,
    find_recently_exploited,
    get_cve,
    list_kev,
)


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------


def test_parse_version_basic() -> None:
    assert _parse_version("1.2.3") == (1, 2, 3, "")
    assert _parse_version("2.4.53") == (2, 4, 53, "")
    assert _parse_version("1.0") == (1, 0, 0, "")
    assert _parse_version("3") == (3, 0, 0, "")


def test_parse_version_with_suffix() -> None:
    assert _parse_version("1.2.3-beta")[3] == "beta"
    assert _parse_version("1.2.3.4")[3] == "4"


def test_cmp_versions() -> None:
    assert _cmp_versions("1.2.3", "1.2.3") == 0
    assert _cmp_versions("1.2.3", "1.2.4") == -1
    assert _cmp_versions("2.0.0", "1.99.99") == 1
    assert _cmp_versions("1.2.3", "1.10.0") == -1  # numeric, not lex


def test_matches_pattern_wildcard() -> None:
    assert _matches_pattern("1.2.3", "*")


def test_matches_pattern_exact() -> None:
    assert _matches_pattern("1.2.3", "1.2.3")
    assert not _matches_pattern("1.2.3", "1.2.4")


def test_matches_pattern_range() -> None:
    assert _matches_pattern("1.5.0", ">=1.0,<2.0")
    assert _matches_pattern("1.0.0", ">=1.0,<2.0")
    assert not _matches_pattern("2.0.0", ">=1.0,<2.0")
    assert not _matches_pattern("0.9.9", ">=1.0,<2.0")


def test_matches_pattern_strict_bounds() -> None:
    assert _matches_pattern("1.5.0", ">1.0")
    assert not _matches_pattern("1.0", ">1.0")
    assert _matches_pattern("0.9", "<1.0")
    assert not _matches_pattern("1.0", "<1.0")


# ---------------------------------------------------------------------------
# find_cves_for
# ---------------------------------------------------------------------------


def _seed(tmp_cache):
    """Seed a small fixture: 3 CVEs across 2 products."""
    ti_cache.upsert_cves([
        {
            "cve_id": "CVE-2024-1001",
            "cvss_score": 9.8, "severity": "critical",
            "components": [{
                "vendor": "apache", "product": "http_server",
                "version_pattern": ">=2.4.0,<2.4.55",
            }],
        },
        {
            "cve_id": "CVE-2024-1002",
            "cvss_score": 5.5, "severity": "medium",
            "components": [{
                "vendor": "apache", "product": "http_server",
                "version_pattern": "*",
            }],
        },
        {
            "cve_id": "CVE-2024-2001",
            "cvss_score": 7.5, "severity": "high",
            "components": [{
                "vendor": "nginx", "product": "nginx",
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
        ("CVE-2024-2001", 0.75),
    ])


def test_find_cves_for_product_basic(tmp_cache) -> None:
    _seed(tmp_cache)
    out = find_cves_for("http_server")
    ids = {r.cve_id for r in out}
    assert ids == {"CVE-2024-1001", "CVE-2024-1002"}


def test_find_cves_for_product_with_version(tmp_cache) -> None:
    _seed(tmp_cache)
    # 2.4.53 is in the bounded range of CVE-2024-1001 AND wildcard CVE-2024-1002
    out = find_cves_for("http_server", version="2.4.53")
    ids = {r.cve_id for r in out}
    assert "CVE-2024-1001" in ids
    assert "CVE-2024-1002" in ids
    # 2.5.0 is outside CVE-2024-1001's bound but matches wildcard 1002.
    out = find_cves_for("http_server", version="2.5.0")
    ids = {r.cve_id for r in out}
    assert "CVE-2024-1001" not in ids
    assert "CVE-2024-1002" in ids


def test_find_cves_for_only_kev(tmp_cache) -> None:
    _seed(tmp_cache)
    out = find_cves_for("http_server", only_kev=True)
    ids = {r.cve_id for r in out}
    assert ids == {"CVE-2024-1001"}


def test_find_cves_for_min_epss(tmp_cache) -> None:
    _seed(tmp_cache)
    out = find_cves_for("nginx", min_epss=0.5)
    assert {r.cve_id for r in out} == {"CVE-2024-2001"}
    out = find_cves_for("nginx", min_epss=0.99)
    assert out == []


def test_find_cves_for_unknown_product(tmp_cache) -> None:
    _seed(tmp_cache)
    assert find_cves_for("notarealproduct") == []


def test_find_cves_for_empty_input(tmp_cache) -> None:
    assert find_cves_for("") == []
    assert find_cves_for("   ") == []


def test_find_cves_for_orders_by_kev_then_epss(tmp_cache) -> None:
    _seed(tmp_cache)
    out = find_cves_for("http_server")
    # KEV-flagged first.
    assert out[0].cve_id == "CVE-2024-1001"


# ---------------------------------------------------------------------------
# get_cve / list_kev / find_recently_exploited
# ---------------------------------------------------------------------------


def test_get_cve_known(tmp_cache) -> None:
    _seed(tmp_cache)
    rec = get_cve("CVE-2024-1001")
    assert rec is not None
    assert rec.kev is True
    assert rec.epss == 0.97


def test_get_cve_case_insensitive(tmp_cache) -> None:
    _seed(tmp_cache)
    rec = get_cve("cve-2024-1001")
    assert rec is not None


def test_get_cve_unknown(tmp_cache) -> None:
    assert get_cve("CVE-9999-9999") is None
    assert get_cve("") is None


def test_list_kev(tmp_cache) -> None:
    _seed(tmp_cache)
    kev = list_kev()
    assert len(kev) == 1
    assert kev[0].cve_id == "CVE-2024-1001"


def test_find_recently_exploited(tmp_cache) -> None:
    _seed(tmp_cache)
    out = find_recently_exploited(min_epss=0.5)
    ids = {r.cve_id for r in out}
    # CVE-2024-1001 (KEV) + CVE-2024-2001 (EPSS 0.75) qualify; 1002 doesn't.
    assert ids == {"CVE-2024-1001", "CVE-2024-2001"}


# ---------------------------------------------------------------------------
# cache_status
# ---------------------------------------------------------------------------


def test_cache_status_empty(tmp_cache) -> None:
    s = cache_status()
    assert s["totals"]["cves"] == 0
    assert s["feeds"] == []


def test_cache_status_populated(tmp_cache) -> None:
    _seed(tmp_cache)
    ti_cache.record_feed_status("kev", status="ok", record_count=1)
    s = cache_status()
    assert s["totals"]["cves"] == 3
    assert s["totals"]["kev"] == 1
    assert s["totals"]["with_epss"] == 3
    assert any(f["feed_name"] == "kev" for f in s["feeds"])
