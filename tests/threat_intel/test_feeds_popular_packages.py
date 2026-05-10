"""Unit tests for `strix.threat_intel.feeds.popular_packages`.

Pins:
  * `_parse_pypi_top` reads hugovk's top-pypi-packages JSON shape.
  * `_parse_npm_top` reads anvaka's npmrank shape (dict + list variants).
  * `poll_popular_packages` writes to cache via `replace_ecosystem`
    so yesterday's top-N is fully replaced (packages dropping off
    the chart don't linger).
  * Per-ecosystem error isolation — npm fail + pypi success →
    `partial` status, pypi rows still committed.
  * `fetch_popular_packages` returns the cached corpus.
"""

from __future__ import annotations

import json

import pytest

from strix.threat_intel import cache as ti_cache
from strix.threat_intel.feeds import popular_packages as feed


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


def _bytes(payload: dict | list) -> bytes:
    return json.dumps(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# Parser shape tests
# ---------------------------------------------------------------------------


def test_parse_pypi_top_extracts_ranked_packages() -> None:
    raw = _bytes({
        "last_update": "2026-05-10",
        "rows": [
            {"project": "boto3", "download_count": 9000000},
            {"project": "REQUESTS", "download_count": 8000000},
            {"project": "urllib3", "download_count": 7000000},
        ],
    })
    out = feed._parse_pypi_top(raw, top_n=10)
    assert len(out) == 3
    assert out[0] == ("pypi", "boto3", 1)
    # Lowercased.
    assert out[1] == ("pypi", "requests", 2)
    assert out[2] == ("pypi", "urllib3", 3)


def test_parse_pypi_top_respects_top_n() -> None:
    rows = [{"project": f"pkg-{i}", "download_count": 100 - i} for i in range(10)]
    raw = _bytes({"rows": rows})
    out = feed._parse_pypi_top(raw, top_n=5)
    assert len(out) == 5


def test_parse_pypi_top_skips_empty_names() -> None:
    """Empty / null names are silently skipped. Rank reflects the
    source row's index (preserves popularity ordering for
    surviving entries)."""
    raw = _bytes({"rows": [
        {"project": "", "download_count": 100},
        {"project": None, "download_count": 50},
        {"project": "real-pkg", "download_count": 10},
    ]})
    out = feed._parse_pypi_top(raw, top_n=10)
    assert len(out) == 1
    assert out[0][0] == "pypi"
    assert out[0][1] == "real-pkg"


def test_parse_npm_top_dict_shape() -> None:
    """anvaka's npmrank.json — dict keyed by package name."""
    raw = _bytes({
        "lodash": {"name": "lodash", "rank": 1, "downloads": 9000000},
        "react": {"name": "react", "rank": 2, "downloads": 8000000},
        "express": {"name": "express", "rank": 3, "downloads": 7000000},
    })
    out = feed._parse_npm_top(raw, top_n=10)
    names = [n for _e, n, _r in out]
    assert "lodash" in names
    assert "react" in names
    assert "express" in names
    # Rank preserved.
    by_name = {n: r for _e, n, r in out}
    assert by_name["lodash"] == 1


def test_parse_npm_top_list_shape() -> None:
    raw = _bytes([
        {"name": "lodash", "rank": 1},
        {"name": "react", "rank": 2},
    ])
    out = feed._parse_npm_top(raw, top_n=10)
    assert ("npm", "lodash", 1) in out
    assert ("npm", "react", 2) in out


def test_parse_npm_top_falls_back_when_rank_missing() -> None:
    raw = _bytes({
        "p1": {"name": "p1", "downloads": 100},
        "p2": {"name": "p2", "downloads": 50},
    })
    out = feed._parse_npm_top(raw, top_n=10)
    # Both should appear with auto-assigned ranks 1, 2.
    ranks = sorted(r for _e, _n, r in out)
    assert ranks == [1, 2]


# ---------------------------------------------------------------------------
# poll_popular_packages — happy path + error isolation
# ---------------------------------------------------------------------------


def test_poll_writes_to_cache(tmp_cache) -> None:
    pypi_payload = _bytes({
        "rows": [{"project": "django"}, {"project": "flask"}],
    })
    npm_payload = _bytes({
        "lodash": {"name": "lodash", "rank": 1},
        "react": {"name": "react", "rank": 2},
    })

    def fake_fetch(url):
        if "hugovk" in url or "pypi" in url.lower():
            return pypi_payload
        return npm_payload

    result = feed.poll_popular_packages(fetch=fake_fetch, top_n=100)
    assert result["status"] == "ok"
    assert result["ingested"]["pypi"] == 2
    assert result["ingested"]["npm"] == 2

    cached_pypi = ti_cache.fetch_popular_packages("pypi")
    assert cached_pypi == {"django", "flask"}
    cached_npm = ti_cache.fetch_popular_packages("npm")
    assert cached_npm == {"lodash", "react"}


def test_poll_replace_ecosystem_clears_old_packages(tmp_cache) -> None:
    """Anti-staleness: yesterday's top-N gets fully replaced.
    Packages that drop off the chart shouldn't persist forever."""
    # Seed yesterday's data.
    ti_cache.upsert_popular_packages(
        [("pypi", "old-pkg-1", 1), ("pypi", "old-pkg-2", 2)],
        replace_ecosystem="pypi",
    )
    assert "old-pkg-1" in ti_cache.fetch_popular_packages("pypi")

    # Today's poll returns different packages.
    pypi_payload = _bytes({"rows": [{"project": "new-pkg"}]})

    def fake_fetch(url):
        if "pypi" in url.lower() or "hugovk" in url:
            return pypi_payload
        # npm side: empty / fail; pypi-only run.
        return _bytes({})

    feed.poll_popular_packages(
        fetch=fake_fetch, top_n=100, ecosystems=["pypi"],
    )
    cached = ti_cache.fetch_popular_packages("pypi")
    assert cached == {"new-pkg"}
    assert "old-pkg-1" not in cached


def test_poll_partial_when_one_ecosystem_fails(tmp_cache) -> None:
    """npm 503 + pypi success → status=partial, pypi rows still
    committed. Critical: don't drop the working ecosystem just
    because the other 503'd."""

    def fake_fetch(url):
        if "anvaka" in url or "npmrank" in url:
            raise OSError("simulated network failure")
        return _bytes({"rows": [{"project": "django"}]})

    result = feed.poll_popular_packages(fetch=fake_fetch)
    assert result["status"] == "partial"
    assert result["ingested"].get("pypi") == 1
    assert "npm" in result["errors"]
    # pypi rows did land.
    assert "django" in ti_cache.fetch_popular_packages("pypi")


def test_poll_error_when_all_fail(tmp_cache) -> None:
    def fake_fetch(url):
        raise OSError("everything is on fire")

    result = feed.poll_popular_packages(fetch=fake_fetch)
    assert result["status"] == "error"


def test_poll_error_when_source_returns_zero_records(tmp_cache) -> None:
    """A source that returns valid JSON but no usable rows is
    a soft failure — count it as an error rather than committing
    an empty set (which would clobber yesterday's good data)."""

    def fake_fetch(url):
        return _bytes({"rows": []})

    result = feed.poll_popular_packages(
        fetch=fake_fetch, ecosystems=["pypi"],
    )
    # All ecosystems failed → error status.
    assert result["status"] == "error"
    assert "zero records" in result["errors"]["pypi"]


def test_poll_records_feed_status(tmp_cache) -> None:
    """`feed_meta` row gets written so `cache_status()` surfaces
    the popular-package feed's freshness."""
    pypi_payload = _bytes({"rows": [{"project": "django"}]})

    def fake_fetch(url):
        return pypi_payload

    feed.poll_popular_packages(
        fetch=fake_fetch, ecosystems=["pypi"], top_n=10,
    )
    feeds = {f["feed_name"]: f for f in ti_cache.fetch_feed_meta()}
    assert "popular_packages" in feeds
    assert feeds["popular_packages"]["status"] == "ok"
