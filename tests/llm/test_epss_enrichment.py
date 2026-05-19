"""Tests for MA-S2 P0-CVS-A — EPSS enrichment on findings.

Recall-safety contract pinned by tests:
  * The `epss` block is ALWAYS present (MA-S2 attestation
    discipline: "we tried" must be explicit).
  * Missing CVE → `reason: "no_cve"`, never raises.
  * Cache unavailable / errors → `reason: "cache_unavailable"`,
    never raises.
  * Stale cache (>7d) → `reason: "cache_stale"` AND `last_updated`
    surfaces the old timestamp.
  * Kill switch (`STRIX_EPSS_ENRICHMENT_DISABLED=1`) returns a
    consistent block with `reason: "enrichment_disabled"`.
  * Resolver never raises — every error path returns a block.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from strix.llm import epss_enrichment as ee


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_EPSS_ENRICHMENT_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# CVE normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("CVE-2024-1234", "CVE-2024-1234"),
    ("cve-2024-1234", "CVE-2024-1234"),
    ("CVE 2024 1234", "CVE-2024-1234"),
    ("see CVE-2024-1234 for details", "CVE-2024-1234"),
    ("CVE-2024-99999", "CVE-2024-99999"),
    ("not a cve", None),
    ("", None),
    (None, None),
])
def test_normalize_cve_id(raw, expected) -> None:
    assert ee._normalize_cve_id(raw) == expected


def test_normalize_cve_rejects_short_year_number() -> None:
    # CVE-2024-1 (single digit) is malformed per the regex (4+ digits)
    assert ee._normalize_cve_id("CVE-2024-1") is None


# ---------------------------------------------------------------------------
# Feed staleness
# ---------------------------------------------------------------------------


def test_feed_is_stale_when_none() -> None:
    """Missing last_polled → considered stale (conservative)."""
    assert ee._feed_is_stale(None, days=7) is True
    assert ee._feed_is_stale("", days=7) is True


def test_feed_is_stale_when_old() -> None:
    old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    assert ee._feed_is_stale(old, days=7) is True


def test_feed_is_fresh_when_recent() -> None:
    recent = (datetime.now(timezone.utc) - timedelta(hours=12)).isoformat()
    assert ee._feed_is_stale(recent, days=7) is False


def test_feed_is_stale_handles_z_suffix() -> None:
    """Common ISO-8601 with Z suffix should parse correctly."""
    recent = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert ee._feed_is_stale(recent, days=7) is False


def test_feed_is_stale_handles_garbage() -> None:
    """Unparseable timestamps → considered stale."""
    assert ee._feed_is_stale("not a timestamp", days=7) is True


# ---------------------------------------------------------------------------
# resolve_epss_block — happy paths
# ---------------------------------------------------------------------------


def test_resolve_with_no_cve_returns_no_cve_reason() -> None:
    block = ee.resolve_epss_block(cve=None)
    assert block["score"] is None
    assert block["percentile"] is None
    assert block["last_updated"] is None
    assert block["reason"] == "no_cve"


def test_resolve_with_unparseable_cve_returns_no_cve_reason() -> None:
    block = ee.resolve_epss_block(cve="not a cve")
    assert block["reason"] == "no_cve"


def test_resolve_when_cache_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When feed_meta lookup fails, surface cache_unavailable."""
    monkeypatch.setattr(ee, "_epss_feed_last_polled", lambda: None)
    block = ee.resolve_epss_block(cve="CVE-2024-1234")
    assert block["score"] is None
    assert block["last_updated"] is None
    assert block["reason"] == "cache_unavailable"


def test_resolve_when_cache_stale_surfaces_score_and_marks_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale-but-extant cache: surface the score AND mark
    stale so the wrapper knows to discount it."""
    old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    monkeypatch.setattr(ee, "_epss_feed_last_polled", lambda: old)
    monkeypatch.setattr(ee, "_lookup_epss_score", lambda c: 0.85)
    block = ee.resolve_epss_block(cve="CVE-2024-1234")
    assert block["score"] == 0.85
    assert block["last_updated"] == old
    assert block["reason"] == "cache_stale"


def test_resolve_fresh_cache_with_score(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ee, "_epss_feed_last_polled", lambda: fresh)
    monkeypatch.setattr(ee, "_lookup_epss_score", lambda c: 0.94)
    block = ee.resolve_epss_block(cve="CVE-2024-1234")
    assert block["score"] == 0.94
    assert block["last_updated"] == fresh
    assert block["reason"] == "ok"


def test_resolve_fresh_cache_without_score(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Feed is fresh but the specific CVE isn't in the cache."""
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ee, "_epss_feed_last_polled", lambda: fresh)
    monkeypatch.setattr(ee, "_lookup_epss_score", lambda c: None)
    block = ee.resolve_epss_block(cve="CVE-2099-9999")
    assert block["score"] is None
    assert block["reason"] == "no_score_for_cve"


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def test_kill_switch_returns_disabled_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_EPSS_ENRICHMENT_DISABLED", "1")
    block = ee.resolve_epss_block(cve="CVE-2024-1234")
    assert block["score"] is None
    assert block["reason"] == "enrichment_disabled"


# ---------------------------------------------------------------------------
# Recall safety — resolver never raises
# ---------------------------------------------------------------------------


def test_resolve_never_raises_on_lookup_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the underlying threat_intel.get_cve raises, the
    resolver returns a clean block rather than propagating."""
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ee, "_epss_feed_last_polled", lambda: fresh)

    def boom(cve_id: str):
        raise RuntimeError("DB locked")

    monkeypatch.setattr(ee, "_lookup_epss_score", boom)
    # The current resolver code calls _lookup_epss_score; if it
    # raises, we expect a clean fall-through. Wrap defensively
    # in the actual call.
    try:
        block = ee.resolve_epss_block(cve="CVE-2024-1234")
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"resolver raised: {e}")
    # Score will be None or whatever, but reason should be set
    assert "reason" in block


def test_resolve_block_always_has_required_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MA-S2 attestation invariant — every block has all four
    canonical keys regardless of path."""
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ee, "_epss_feed_last_polled", lambda: fresh)
    monkeypatch.setattr(ee, "_lookup_epss_score", lambda c: 0.5)
    for cve in [None, "", "not a cve", "CVE-2024-1234"]:
        block = ee.resolve_epss_block(cve=cve)
        assert set(block.keys()) == {"score", "percentile", "last_updated", "reason"}


# ---------------------------------------------------------------------------
# Custom staleness threshold
# ---------------------------------------------------------------------------


def test_custom_staleness_days_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Caller can override the 7-day default (e.g. for tests)."""
    two_days_ago = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    monkeypatch.setattr(ee, "_epss_feed_last_polled", lambda: two_days_ago)
    monkeypatch.setattr(ee, "_lookup_epss_score", lambda c: 0.5)

    # With 7-day staleness, 2 days is fresh
    block = ee.resolve_epss_block(cve="CVE-2024-1234")
    assert block["reason"] == "ok"

    # With 1-day staleness, 2 days is stale
    block = ee.resolve_epss_block(cve="CVE-2024-1234", staleness_days=1)
    assert block["reason"] == "cache_stale"
