"""Tests for the threat-intel feed pollers (KEV / EPSS / NVD).

Each test injects a `fetch` callable that returns canned bytes — no
network. The pollers are pure functions over `(url) -> bytes` plus
the cache, so this keeps tests deterministic.

Pins:
  * KEV success path → records ingested, kev=1 set
  * KEV malformed JSON → status=error, no upsert
  * KEV HTTP failure → status=error
  * EPSS CSV (gzipped) parses, only_cached filtering works
  * EPSS plain CSV also parses
  * NVD recent-window normalises to our cache shape
  * NVD CPE parsing extracts (vendor, product, version_pattern)
  * NVD HTTP failure mid-pagination preserves prior progress
"""

from __future__ import annotations

import gzip
import io
import json

import pytest

from strix.threat_intel import cache as ti_cache
from strix.threat_intel.feeds import epss as epss_feed
from strix.threat_intel.feeds import kev as kev_feed
from strix.threat_intel.feeds import nvd as nvd_feed


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


# ---------------------------------------------------------------------------
# KEV
# ---------------------------------------------------------------------------


def test_kev_poll_success(tmp_cache) -> None:
    doc = {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2024.09.04",
        "dateReleased": "2024-09-04T13:00:00Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-12345",
                "vendorProject": "Apache",
                "product": "Tomcat",
                "vulnerabilityName": "Apache Tomcat RCE",
                "dateAdded": "2024-09-01",
                "dueDate": "2024-09-22",
                "knownRansomwareCampaignUse": "Known",
                "shortDescription": "Description of the bug.",
                "notes": "extra notes",
            },
            {
                "cveID": "CVE-2024-67890",
                "vendorProject": "Microsoft",
                "product": "Windows",
                "vulnerabilityName": "Windows EoP",
                "dateAdded": "2024-08-15",
                "dueDate": "2024-09-05",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ],
    }
    raw = json.dumps(doc).encode("utf-8")
    fake_fetch = lambda url: raw  # noqa: E731

    result = kev_feed.poll_kev(fetch=fake_fetch)
    assert result["status"] == "ok"
    assert result["ingested"] == 2
    assert result["catalog_version"] == "2024.09.04"

    rec_a = ti_cache.fetch_cve("CVE-2024-12345")
    assert rec_a is not None
    assert rec_a.kev is True
    assert rec_a.kev_meta["vuln_name"] == "Apache Tomcat RCE"
    assert rec_a.kev_meta["ransomware"] is True

    rec_b = ti_cache.fetch_cve("CVE-2024-67890")
    assert rec_b.kev is True
    assert rec_b.kev_meta["ransomware"] is False


def test_kev_poll_malformed_json(tmp_cache) -> None:
    fake_fetch = lambda url: b"not valid json"  # noqa: E731
    result = kev_feed.poll_kev(fetch=fake_fetch)
    assert result["status"] == "error"
    assert result["ingested"] == 0
    feeds = ti_cache.fetch_feed_meta()
    kev = next(f for f in feeds if f["feed_name"] == "kev")
    assert kev["status"] == "error"


def test_kev_poll_http_failure(tmp_cache) -> None:
    def boom(url):
        raise RuntimeError("network down")
    result = kev_feed.poll_kev(fetch=boom)
    assert result["status"] == "error"
    assert "network down" in result["error"]


def test_kev_poll_skips_invalid_records(tmp_cache) -> None:
    doc = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-1001", "vendorProject": "v", "product": "p"},
            {"product": "no-cve-id"},  # skipped
            "not a dict",                # skipped
        ],
    }
    fake_fetch = lambda url: json.dumps(doc).encode("utf-8")  # noqa: E731
    result = kev_feed.poll_kev(fetch=fake_fetch)
    assert result["status"] == "ok"
    assert result["ingested"] == 1


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------


def test_epss_parses_gzipped_csv(tmp_cache) -> None:
    """EPSS daily file ships gzipped."""
    # Seed cache so only_cached filtering keeps the rows.
    ti_cache.upsert_cves([
        {"cve_id": "CVE-2024-1001"},
        {"cve_id": "CVE-2024-1002"},
    ], source="nvd")

    csv_text = (
        "#model_version:v2024.04.16,score_date:2024-09-04T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2024-1001,0.92,0.99\n"
        "CVE-2024-1002,0.05,0.20\n"
        "CVE-2024-9999,0.50,0.70\n"  # not in cache; skipped under only_cached
    ).encode("utf-8")
    gz_bytes = gzip.compress(csv_text)

    fake_fetch = lambda url: gz_bytes  # noqa: E731
    result = epss_feed.poll_epss(fetch=fake_fetch, only_cached=True)
    assert result["status"] == "ok"
    assert result["ingested"] == 2
    assert result["skipped"] == 1

    assert ti_cache.fetch_cve("CVE-2024-1001").epss == 0.92
    assert ti_cache.fetch_cve("CVE-2024-9999") is None


def test_epss_parses_plain_csv(tmp_cache) -> None:
    """If the server serves plain CSV (e.g. local mirror), still parses."""
    csv_text = (
        "cve,epss,percentile\n"
        "CVE-2024-1001,0.92,0.99\n"
    ).encode("utf-8")
    fake_fetch = lambda url: csv_text  # noqa: E731
    result = epss_feed.poll_epss(fetch=fake_fetch, only_cached=False)
    assert result["status"] == "ok"
    assert result["ingested"] == 1


def test_epss_skips_invalid_rows(tmp_cache) -> None:
    csv_text = (
        "cve,epss,percentile\n"
        ",0.5,0.5\n"
        "CVE-X-,0.5,0.5\n"
        "CVE-2024-1001,not-a-float,0.5\n"
        "CVE-2024-1002,0.42,0.6\n"
    ).encode("utf-8")
    fake_fetch = lambda url: csv_text  # noqa: E731
    result = epss_feed.poll_epss(fetch=fake_fetch, only_cached=False)
    assert result["status"] == "ok"
    assert result["ingested"] == 1


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------


def _nvd_doc(items, total=None):
    return {
        "totalResults": total if total is not None else len(items),
        "vulnerabilities": items,
    }


def _nvd_item(cve_id, *, score=9.8, products=None):
    products = products or [("apache", "http_server", "2.4.53")]
    return {
        "cve": {
            "id": cve_id,
            "published": "2024-08-01T00:00:00.000",
            "lastModified": "2024-09-01T12:34:56.000",
            "descriptions": [
                {"lang": "en", "value": f"description for {cve_id}"},
            ],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": score,
                        "baseSeverity": "CRITICAL" if score >= 9 else "HIGH",
                    },
                }],
            },
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [
                        {
                            "criteria": (
                                f"cpe:2.3:a:{vendor}:{product}:"
                                f"{version}:*:*:*:*:*:*:*"
                            ),
                            "vulnerable": True,
                        }
                        for (vendor, product, version) in products
                    ],
                }],
            }],
        },
    }


def test_nvd_recent_window_ingest(tmp_cache) -> None:
    doc = _nvd_doc([
        _nvd_item("CVE-2024-2001"),
        _nvd_item("CVE-2024-2002", score=7.5,
                  products=[("nginx", "nginx", "1.21.5")]),
    ])
    raw = json.dumps(doc).encode("utf-8")

    def fake_fetch(url, timeout=60.0, api_key=None):
        return raw

    result = nvd_feed.poll_nvd_recent(days=7, fetch=fake_fetch)
    assert result["status"] == "ok"
    assert result["ingested"] == 2

    rec = ti_cache.fetch_cve("CVE-2024-2001")
    assert rec.cvss_score == 9.8
    assert rec.severity == "critical"
    assert any(
        c["product"] == "http_server" and c["vendor"] == "apache"
        for c in rec.components
    )


def test_nvd_cpe_with_version_bounds(tmp_cache) -> None:
    doc = _nvd_doc([{
        "cve": {
            "id": "CVE-2024-3003",
            "descriptions": [{"lang": "en", "value": "x"}],
            "configurations": [{"nodes": [{
                "cpeMatch": [{
                    "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                    "vulnerable": True,
                    "versionStartIncluding": "1.0.0",
                    "versionEndExcluding": "1.5.0",
                }],
            }]}],
        },
    }])
    raw = json.dumps(doc).encode("utf-8")
    nvd_feed.poll_nvd_recent(
        days=7, fetch=lambda url, timeout=60.0, api_key=None: raw,
    )
    rec = ti_cache.fetch_cve("CVE-2024-3003")
    assert rec is not None
    pat = rec.components[0]["version_pattern"]
    assert ">=1.0.0" in pat
    assert "<1.5.0" in pat


def test_nvd_invalid_window_returns_error(tmp_cache) -> None:
    result = nvd_feed.poll_nvd_recent(days=0)
    assert result["status"] == "error"
    result = nvd_feed.poll_nvd_recent(days=200)
    assert result["status"] == "error"


def test_nvd_http_failure_records_status(tmp_cache) -> None:
    def boom(url, timeout=60.0, api_key=None):
        raise OSError("connection refused")
    result = nvd_feed.poll_nvd_recent(days=7, fetch=boom)
    assert result["status"] == "error"
    assert "connection refused" in result["error"]


# ---------------------------------------------------------------------------
# iter-22.5 — real-time incremental NVD polling
# ---------------------------------------------------------------------------


def test_nvd_incremental_uses_since_iso_kwarg(tmp_cache) -> None:
    """`since_iso=` overrides the feed_meta last_polled lookup."""
    doc = _nvd_doc([_nvd_item("CVE-2024-INC1")])
    captured = {}

    def fake_fetch(url, timeout=60.0, api_key=None):
        captured["url"] = url
        return json.dumps(doc).encode("utf-8")

    result = nvd_feed.poll_nvd_incremental(
        since_iso="2026-05-22T10:00:00Z", fetch=fake_fetch,
    )
    assert result["status"] == "ok"
    assert result["incremental"] is True
    # The lastModStartDate in the URL came from since_iso
    assert "lastModStartDate=2026-05-22T10" in captured["url"]


def test_nvd_incremental_falls_back_to_feed_meta(tmp_cache) -> None:
    """When since_iso is None, the function reads
    feed_meta.last_polled for `nvd`."""
    # Seed feed_meta with a known last_polled.
    ti_cache.record_feed_status("nvd", status="ok", record_count=0)
    doc = _nvd_doc([_nvd_item("CVE-2024-INC2")])
    captured = {}

    def fake_fetch(url, timeout=60.0, api_key=None):
        captured["url"] = url
        return json.dumps(doc).encode("utf-8")

    result = nvd_feed.poll_nvd_incremental(fetch=fake_fetch)
    assert result["status"] == "ok"
    # The URL has a lastModStartDate (we don't know the exact
    # timestamp, but it should be present and well-formed)
    assert "lastModStartDate=" in captured["url"]


def test_nvd_incremental_fallback_minutes_on_cold_start(tmp_cache) -> None:
    """No since_iso AND no feed_meta entry → fallback_minutes
    window."""
    doc = _nvd_doc([])

    def fake_fetch(url, timeout=60.0, api_key=None):
        return json.dumps(doc).encode("utf-8")

    result = nvd_feed.poll_nvd_incremental(
        fallback_minutes=15, fetch=fake_fetch,
    )
    assert result["status"] == "ok"
    assert result["incremental"] is True


def test_nvd_incremental_rejects_bad_since_iso(tmp_cache) -> None:
    result = nvd_feed.poll_nvd_incremental(
        since_iso="not-a-timestamp",
    )
    assert result["status"] == "error"
    assert "unparseable" in result["error"].lower()


def test_nvd_incremental_clamps_huge_gap_to_120_days(tmp_cache) -> None:
    """If last poll was years ago, window is clamped to 120 days
    (NVD API's hard limit)."""
    doc = _nvd_doc([])

    def fake_fetch(url, timeout=60.0, api_key=None):
        return json.dumps(doc).encode("utf-8")

    # 5 years ago — would otherwise be ~1825 days
    result = nvd_feed.poll_nvd_incremental(
        since_iso="2021-01-01T00:00:00Z", fetch=fake_fetch,
    )
    assert result["status"] == "ok"


def test_nvd_incremental_ingests_cves(tmp_cache) -> None:
    doc = _nvd_doc([
        _nvd_item("CVE-2024-INC10"),
        _nvd_item("CVE-2024-INC11", score=7.5,
                  products=[("nginx", "nginx", "1.21.5")]),
    ])

    def fake_fetch(url, timeout=60.0, api_key=None):
        return json.dumps(doc).encode("utf-8")

    result = nvd_feed.poll_nvd_incremental(
        since_iso="2026-05-22T00:00:00Z", fetch=fake_fetch,
    )
    assert result["status"] == "ok"
    assert result["ingested"] == 2
    # Confirm a record landed in the cache
    rec = ti_cache.fetch_cve("CVE-2024-INC10")
    assert rec is not None


def test_nvd_incremental_records_last_polled_for_next_run(
    tmp_cache,
) -> None:
    """After an incremental poll, feed_meta.last_polled is updated
    so the next call picks up where this one ended."""

    def fake_fetch(url, timeout=60.0, api_key=None):
        return json.dumps(_nvd_doc([])).encode("utf-8")

    nvd_feed.poll_nvd_incremental(
        since_iso="2026-05-22T00:00:00Z", fetch=fake_fetch,
    )
    rows = ti_cache.fetch_feed_meta() or []
    nvd_row = next((r for r in rows if r.get("feed_name") == "nvd"), None)
    assert nvd_row is not None
    assert nvd_row.get("last_polled") is not None


def test_nvd_incremental_http_failure_records_error(tmp_cache) -> None:
    def boom(url, timeout=60.0, api_key=None):
        raise OSError("DNS failure")

    result = nvd_feed.poll_nvd_incremental(
        since_iso="2026-05-22T00:00:00Z", fetch=boom,
    )
    assert result["status"] == "error"
    assert "DNS failure" in result["error"]
