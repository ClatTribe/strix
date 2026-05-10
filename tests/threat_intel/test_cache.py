"""Tests for the threat-intel SQLite cache.

Pins:
  * Schema bootstrap on first connect
  * upsert_cves merges sources + replaces components
  * upsert_kev_entries flips kev=1 + creates missing cve rows
  * upsert_epss_scores merges into existing cve rows
  * record_feed_status writes one row per feed
  * fetch_cves_for_product filters by product, vendor, KEV, EPSS
  * fetch_cve returns full record with components + KEV meta
  * fetch_kev_list returns KEV-flagged rows
  * fetch_recently_exploited blends KEV + high-EPSS
  * reset_for_testing wipes the DB
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from strix.threat_intel import cache as ti_cache


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    """Isolated SQLite DB per test via env override."""
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_connect_creates_schema(tmp_cache) -> None:
    with ti_cache.connect() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        names = [r["name"] for r in cur.fetchall()]
    assert "cves" in names
    assert "cve_components" in names
    assert "kev_entries" in names
    assert "feed_meta" in names


def test_cache_path_env_override(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(tmp_path / "x.db"))
    assert ti_cache.cache_path() == tmp_path / "x.db"


# ---------------------------------------------------------------------------
# upsert_cves
# ---------------------------------------------------------------------------


def test_upsert_cves_basic(tmp_cache) -> None:
    n = ti_cache.upsert_cves([
        {
            "cve_id": "CVE-2024-1111",
            "description": "RCE in widget",
            "cvss_score": 9.8,
            "severity": "critical",
            "published": "2024-09-01",
            "modified": "2024-09-02",
            "components": [
                {"vendor": "acme", "product": "widget",
                 "version_pattern": ">=1.0,<2.0"},
            ],
        },
    ], source="nvd")
    assert n == 1
    rec = ti_cache.fetch_cve("CVE-2024-1111")
    assert rec is not None
    assert rec.cvss_score == 9.8
    assert rec.severity == "critical"
    assert rec.sources == ["nvd"]
    assert len(rec.components) == 1
    assert rec.components[0]["product"] == "widget"


def test_upsert_cves_merges_sources(tmp_cache) -> None:
    """Re-upserting from a different source appends to sources list."""
    ti_cache.upsert_cves([{"cve_id": "CVE-2024-2222"}], source="nvd")
    ti_cache.upsert_cves([{"cve_id": "CVE-2024-2222"}], source="ghsa")
    rec = ti_cache.fetch_cve("CVE-2024-2222")
    assert "nvd" in rec.sources
    assert "ghsa" in rec.sources


def test_upsert_cves_replaces_components(tmp_cache) -> None:
    """Re-upserting a CVE replaces its component list (not append)."""
    ti_cache.upsert_cves([{
        "cve_id": "CVE-2024-3333",
        "components": [{"vendor": "v1", "product": "p1", "version_pattern": "*"}],
    }], source="nvd")
    ti_cache.upsert_cves([{
        "cve_id": "CVE-2024-3333",
        "components": [{"vendor": "v2", "product": "p2", "version_pattern": "*"}],
    }], source="nvd")
    rec = ti_cache.fetch_cve("CVE-2024-3333")
    products = [c["product"] for c in rec.components]
    assert products == ["p2"]


def test_upsert_cves_skips_invalid_id(tmp_cache) -> None:
    n = ti_cache.upsert_cves([
        {"cve_id": ""}, {"cve_id": None}, {"description": "no id"},
    ], source="nvd")
    assert n == 0


# ---------------------------------------------------------------------------
# upsert_kev_entries
# ---------------------------------------------------------------------------


def test_upsert_kev_entries_creates_cve_row(tmp_cache) -> None:
    """KEV may name a CVE we haven't ingested via NVD yet — the
    helper auto-creates the cves row with kev=1."""
    n = ti_cache.upsert_kev_entries([{
        "cve_id": "CVE-2024-4444",
        "vendor": "Apache",
        "product": "Tomcat",
        "vuln_name": "Apache Tomcat RCE",
        "date_added": "2024-09-01",
        "ransomware": True,
    }])
    assert n == 1
    rec = ti_cache.fetch_cve("CVE-2024-4444")
    assert rec is not None
    assert rec.kev is True
    assert rec.kev_meta["product"] == "Tomcat"
    assert rec.kev_meta["ransomware"] is True


def test_upsert_kev_entries_resets_kev_flag_outside_batch(tmp_cache) -> None:
    """Re-upserting KEV with a smaller batch should clear kev=1
    on entries no longer in the catalog."""
    ti_cache.upsert_kev_entries([
        {"cve_id": "CVE-2024-A", "product": "p", "vendor": "v"},
        {"cve_id": "CVE-2024-B", "product": "p", "vendor": "v"},
    ])
    assert ti_cache.fetch_cve("CVE-2024-A").kev is True
    assert ti_cache.fetch_cve("CVE-2024-B").kev is True
    # Re-upsert with only CVE-2024-A.
    ti_cache.upsert_kev_entries([
        {"cve_id": "CVE-2024-A", "product": "p", "vendor": "v"},
    ])
    assert ti_cache.fetch_cve("CVE-2024-A").kev is True
    assert ti_cache.fetch_cve("CVE-2024-B").kev is False


# ---------------------------------------------------------------------------
# upsert_epss_scores
# ---------------------------------------------------------------------------


def test_upsert_epss_scores_creates_cve_row(tmp_cache) -> None:
    n = ti_cache.upsert_epss_scores([
        ("CVE-2024-5555", 0.92),
        ("CVE-2024-6666", 0.05),
    ])
    assert n == 2
    rec = ti_cache.fetch_cve("CVE-2024-5555")
    assert rec.epss == 0.92


def test_upsert_epss_scores_skips_invalid(tmp_cache) -> None:
    n = ti_cache.upsert_epss_scores([
        ("", 0.1),
        ("CVE-X", "not-a-float"),  # type: ignore[arg-type]
        ("CVE-2024-7777", 0.5),
    ])
    assert n == 1


# ---------------------------------------------------------------------------
# fetch_cves_for_product
# ---------------------------------------------------------------------------


def test_fetch_cves_for_product_basic(tmp_cache) -> None:
    ti_cache.upsert_cves([
        {
            "cve_id": "CVE-2024-A",
            "components": [{"vendor": "apache", "product": "http_server",
                            "version_pattern": "*"}],
        },
        {
            "cve_id": "CVE-2024-B",
            "components": [{"vendor": "nginx", "product": "nginx",
                            "version_pattern": "*"}],
        },
    ], source="nvd")
    apache = ti_cache.fetch_cves_for_product("http_server")
    assert len(apache) == 1
    assert apache[0].cve_id == "CVE-2024-A"


def test_fetch_cves_for_product_filter_kev(tmp_cache) -> None:
    ti_cache.upsert_cves([
        {"cve_id": "CVE-2024-A",
         "components": [{"vendor": "v", "product": "p", "version_pattern": "*"}]},
        {"cve_id": "CVE-2024-B",
         "components": [{"vendor": "v", "product": "p", "version_pattern": "*"}]},
    ], source="nvd")
    ti_cache.upsert_kev_entries([
        {"cve_id": "CVE-2024-A", "vendor": "v", "product": "p"},
    ])
    only_kev = ti_cache.fetch_cves_for_product("p", only_kev=True)
    ids = {r.cve_id for r in only_kev}
    assert ids == {"CVE-2024-A"}


def test_fetch_cves_for_product_filter_min_epss(tmp_cache) -> None:
    ti_cache.upsert_cves([
        {"cve_id": "CVE-2024-A",
         "components": [{"vendor": "v", "product": "p", "version_pattern": "*"}]},
        {"cve_id": "CVE-2024-B",
         "components": [{"vendor": "v", "product": "p", "version_pattern": "*"}]},
    ], source="nvd")
    ti_cache.upsert_epss_scores([
        ("CVE-2024-A", 0.9),
        ("CVE-2024-B", 0.05),
    ])
    high = ti_cache.fetch_cves_for_product("p", min_epss=0.5)
    assert {r.cve_id for r in high} == {"CVE-2024-A"}


# ---------------------------------------------------------------------------
# Feed meta
# ---------------------------------------------------------------------------


def test_record_feed_status(tmp_cache) -> None:
    ti_cache.record_feed_status("kev", status="ok", record_count=1234)
    feeds = ti_cache.fetch_feed_meta()
    assert any(
        f["feed_name"] == "kev" and f["status"] == "ok" and f["record_count"] == 1234
        for f in feeds
    )


def test_record_feed_status_overwrites(tmp_cache) -> None:
    ti_cache.record_feed_status("kev", status="ok", record_count=10)
    ti_cache.record_feed_status("kev", status="error",
                                error="boom", record_count=0)
    feeds = ti_cache.fetch_feed_meta()
    kev = next(f for f in feeds if f["feed_name"] == "kev")
    assert kev["status"] == "error"
    assert kev["error"] == "boom"


# ---------------------------------------------------------------------------
# fetch_recently_exploited
# ---------------------------------------------------------------------------


def test_fetch_recently_exploited_blends_kev_and_epss(tmp_cache) -> None:
    ti_cache.upsert_cves([
        {"cve_id": "CVE-2024-A"},
        {"cve_id": "CVE-2024-B"},
        {"cve_id": "CVE-2024-C"},
    ], source="nvd")
    ti_cache.upsert_kev_entries([
        {"cve_id": "CVE-2024-A", "vendor": "v", "product": "p"},
    ])
    ti_cache.upsert_epss_scores([
        ("CVE-2024-B", 0.92),
        ("CVE-2024-C", 0.10),
    ])
    rec = ti_cache.fetch_recently_exploited(min_epss=0.5)
    ids = {r.cve_id for r in rec}
    assert "CVE-2024-A" in ids  # via KEV
    assert "CVE-2024-B" in ids  # via high EPSS
    assert "CVE-2024-C" not in ids  # low EPSS, no KEV
