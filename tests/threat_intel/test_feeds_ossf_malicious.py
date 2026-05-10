"""Unit tests for `strix.threat_intel.feeds.ossf_malicious`.

Pins:
  * `_normalise_osv_record` extracts (ecosystem, name,
    advisory_id, summary, detected_at, severity,
    affected_versions) from a real OSV-shape advisory.
  * `_walk_zip_for_mal_records` filters to MAL-* prefix and
    skips regular CVEs in the same bulk.
  * `poll_ossf_malicious` writes to cache via `upsert_malicious_packages`.
  * Per-ecosystem error isolation (npm 503 + pypi success →
    `partial`, pypi rows still committed).
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from strix.threat_intel import cache as ti_cache
from strix.threat_intel.feeds import ossf_malicious as feed


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


def _osv_record(
    advisory_id: str = "MAL-2024-1",
    ecosystem_label: str = "npm",
    name: str = "evil-pkg",
    summary: str = "rugpull",
    versions: list[str] | None = None,
) -> dict:
    return {
        "id": advisory_id,
        "summary": summary,
        "details": "long form details",
        "modified": "2024-12-01T00:00:00Z",
        "published": "2024-11-30T00:00:00Z",
        "affected": [{
            "package": {
                "name": name,
                "ecosystem": ecosystem_label,
            },
            # `[]` is a meaningful test value (= "all versions
            # affected") so don't fall through to the default
            # via `versions or [...]`.
            "versions": versions if versions is not None else ["1.0.0"],
        }],
    }


def _build_zip(records: dict[str, dict]) -> bytes:
    """Build an in-memory ZIP file mimicking OSV's per-ecosystem
    bulk export. Each record is one JSON file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, data in records.items():
            zf.writestr(filename, json.dumps(data))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Normaliser tests
# ---------------------------------------------------------------------------


def test_normalise_extracts_basic_fields() -> None:
    osv = _osv_record(
        advisory_id="MAL-2024-1",
        ecosystem_label="npm",
        name="evil-pkg",
        summary="known rugpull",
        versions=["1.0.0", "1.0.1"],
    )
    rows = feed._normalise_osv_record(osv, "npm")
    assert len(rows) == 1
    r = rows[0]
    assert r["ecosystem"] == "npm"
    assert r["name"] == "evil-pkg"
    assert r["advisory_id"] == "MAL-2024-1"
    assert r["summary"] == "known rugpull"
    assert r["detected_at"] == "2024-12-01T00:00:00Z"
    # Default severity is critical.
    assert r["severity"] == "critical"
    assert r["affected_versions"] == ["1.0.0", "1.0.1"]


def test_normalise_lowercases_package_name() -> None:
    osv = _osv_record(name="EVIL-Package", ecosystem_label="npm")
    rows = feed._normalise_osv_record(osv, "npm")
    assert rows[0]["name"] == "evil-package"


def test_normalise_skips_records_for_other_ecosystems() -> None:
    """Bulk ZIP for npm contains the package; if `target_ecosystem`
    is `pypi`, no rows should come back."""
    osv = _osv_record(ecosystem_label="npm", name="evil-pkg")
    rows = feed._normalise_osv_record(osv, "pypi")
    assert rows == []


def test_normalise_handles_osv_canonical_label() -> None:
    """OSV uses 'PyPI' canonical label; we should match against
    our lowercase 'pypi'."""
    osv = _osv_record(ecosystem_label="PyPI", name="evil-pypi")
    rows = feed._normalise_osv_record(osv, "pypi")
    assert len(rows) == 1
    assert rows[0]["ecosystem"] == "pypi"


def test_normalise_empty_versions_means_all_affected() -> None:
    """No `versions` array → empty list = "all versions affected"
    (per the cache table schema docstring)."""
    osv = _osv_record(versions=[])
    rows = feed._normalise_osv_record(osv, "npm")
    assert rows[0]["affected_versions"] == []


def test_normalise_skips_advisory_with_no_id() -> None:
    osv = {"id": "", "affected": [
        {"package": {"name": "x", "ecosystem": "npm"}, "versions": []},
    ]}
    assert feed._normalise_osv_record(osv, "npm") == []


def test_normalise_skips_affected_without_name() -> None:
    osv = {
        "id": "MAL-X",
        "affected": [{"package": {"ecosystem": "npm"}, "versions": []}],
    }
    assert feed._normalise_osv_record(osv, "npm") == []


# ---------------------------------------------------------------------------
# ZIP walker
# ---------------------------------------------------------------------------


def test_walker_filters_to_mal_prefix() -> None:
    """The bulk OSV ZIP includes regular CVEs too; we only want
    `MAL-*` advisory IDs (the OSSF malicious-packages namespace)."""
    payload = _build_zip({
        "MAL-2024-1.json": _osv_record("MAL-2024-1"),
        "CVE-2024-9999.json": _osv_record("CVE-2024-9999"),
        "GHSA-aaaa-bbbb-cccc.json": _osv_record("GHSA-aaaa-bbbb-cccc"),
        "MAL-2024-2.json": _osv_record("MAL-2024-2", name="evil-2"),
    })
    rows = feed._walk_zip_for_mal_records(payload, "npm")
    ids = {r["advisory_id"] for r in rows}
    assert ids == {"MAL-2024-1", "MAL-2024-2"}


def test_walker_skips_directories() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("nested/", "")  # directory entry
        zf.writestr("MAL-2024-1.json", json.dumps(_osv_record()))
    rows = feed._walk_zip_for_mal_records(buf.getvalue(), "npm")
    assert len(rows) == 1


def test_walker_skips_invalid_json() -> None:
    """Bad records shouldn't break the whole walk."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("MAL-bad.json", "{not valid json")
        zf.writestr("MAL-good.json", json.dumps(_osv_record()))
    rows = feed._walk_zip_for_mal_records(buf.getvalue(), "npm")
    assert len(rows) == 1
    assert rows[0]["advisory_id"] == "MAL-2024-1"


# ---------------------------------------------------------------------------
# poll_ossf_malicious — happy path + error paths
# ---------------------------------------------------------------------------


def test_poll_writes_records_per_ecosystem(tmp_cache) -> None:
    npm_zip = _build_zip({
        "MAL-2024-N1.json": _osv_record(
            "MAL-2024-N1", ecosystem_label="npm", name="bad-npm",
        ),
    })
    pypi_zip = _build_zip({
        "MAL-2024-P1.json": _osv_record(
            "MAL-2024-P1", ecosystem_label="PyPI", name="bad-pypi",
        ),
    })

    def fake_fetch(url):
        if "/npm/" in url:
            return npm_zip
        if "/PyPI/" in url:
            return pypi_zip
        # rubygems — empty zip.
        return _build_zip({})

    result = feed.poll_ossf_malicious(fetch=fake_fetch)
    assert result["status"] == "ok"
    assert result["ingested"]["npm"] == 1
    assert result["ingested"]["pypi"] == 1

    npm_hits = ti_cache.fetch_malicious_packages("npm", "bad-npm")
    assert len(npm_hits) == 1
    assert npm_hits[0]["advisory_id"] == "MAL-2024-N1"

    pypi_hits = ti_cache.fetch_malicious_packages("pypi", "bad-pypi")
    assert len(pypi_hits) == 1


def test_poll_partial_when_one_ecosystem_fails(tmp_cache) -> None:
    """npm fetch raises but pypi succeeds → partial."""
    pypi_zip = _build_zip({
        "MAL-X.json": _osv_record("MAL-X", ecosystem_label="PyPI", name="evil"),
    })

    def fake_fetch(url):
        if "/npm/" in url:
            raise OSError("network down")
        if "/PyPI/" in url:
            return pypi_zip
        return _build_zip({})

    result = feed.poll_ossf_malicious(fetch=fake_fetch)
    assert result["status"] == "partial"
    assert "npm" in result["errors"]
    assert ti_cache.fetch_malicious_packages("pypi", "evil")


def test_poll_error_when_all_fail(tmp_cache) -> None:
    def fake_fetch(url):
        raise OSError("all down")
    result = feed.poll_ossf_malicious(fetch=fake_fetch)
    assert result["status"] == "error"


def test_poll_records_feed_status(tmp_cache) -> None:
    def fake_fetch(url):
        return _build_zip({})

    feed.poll_ossf_malicious(fetch=fake_fetch, ecosystems=["npm"])
    meta = {f["feed_name"]: f for f in ti_cache.fetch_feed_meta()}
    assert "ossf_malicious" in meta


def test_poll_max_per_ecosystem_caps_ingestion(tmp_cache) -> None:
    """Defensive cap on bulk ingest size."""
    records = {
        f"MAL-2024-{i}.json": _osv_record(
            f"MAL-2024-{i}", ecosystem_label="npm", name=f"bad-{i}",
        )
        for i in range(20)
    }

    def fake_fetch(url):
        if "/npm/" in url:
            return _build_zip(records)
        return _build_zip({})

    result = feed.poll_ossf_malicious(
        fetch=fake_fetch, ecosystems=["npm"], max_per_ecosystem=5,
    )
    assert result["ingested"]["npm"] == 5


# ---------------------------------------------------------------------------
# Cache fetch
# ---------------------------------------------------------------------------


def test_fetch_returns_empty_when_no_match(tmp_cache) -> None:
    assert ti_cache.fetch_malicious_packages("npm", "definitely-clean") == []


def test_fetch_orders_by_detected_at_desc(tmp_cache) -> None:
    ti_cache.upsert_malicious_packages([
        {"ecosystem": "npm", "name": "p1", "advisory_id": "MAL-OLD",
         "detected_at": "2024-01-01T00:00:00Z", "summary": "older"},
        {"ecosystem": "npm", "name": "p1", "advisory_id": "MAL-NEW",
         "detected_at": "2024-12-01T00:00:00Z", "summary": "newer"},
    ])
    rows = ti_cache.fetch_malicious_packages("npm", "p1")
    assert len(rows) == 2
    assert rows[0]["advisory_id"] == "MAL-NEW"
