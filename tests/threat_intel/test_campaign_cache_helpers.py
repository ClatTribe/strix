"""Tests for iter-21.2 — campaign cache write/read helpers.

Each test runs against an isolated tmp_path SQLite cache (via
`reset_for_testing(path)`) so the on-disk cache isn't polluted.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.threat_intel import cache as tic


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Force the cache module to point at a fresh tmp SQLite file
    for each test, so concurrent test runs don't share state."""
    p = tmp_path / "ti_cache.sqlite"
    monkeypatch.setattr(tic, "cache_path", lambda: p)
    tic.reset_for_testing(p)
    yield


def _record(**ov):
    base = {
        "campaign_id": "otx:abc-123",
        "source": "otx",
        "name": "Test pulse",
        "description": "x",
        "author": "AlienVault",
        "first_seen": "2026-05-01T00:00:00Z",
        "last_seen": "2026-05-19T00:00:00Z",
        "severity": "high",
        "references": ["https://otx/abc"],
        "tags": ["test", "high"],
    }
    base.update(ov)
    return base


def test_upsert_campaign_inserts_record() -> None:
    assert tic.upsert_campaign(_record()) is True


def test_upsert_campaign_rejects_missing_id() -> None:
    assert tic.upsert_campaign(_record(campaign_id="")) is False
    assert tic.upsert_campaign(_record(campaign_id=None)) is False


def test_upsert_campaign_rejects_missing_source() -> None:
    assert tic.upsert_campaign(_record(source="")) is False


def test_upsert_campaign_is_idempotent() -> None:
    """Two upserts with the same id must not error and must keep
    one row in the table."""
    assert tic.upsert_campaign(_record()) is True
    assert tic.upsert_campaign(_record()) is True


def test_link_campaign_to_cves_inserts_pairs() -> None:
    tic.upsert_campaign(_record())
    n = tic.link_campaign_to_cves("otx:abc-123", ["CVE-2024-1", "CVE-2024-2"])
    assert n == 2


def test_link_campaign_to_cves_ignores_dupes() -> None:
    tic.upsert_campaign(_record())
    tic.link_campaign_to_cves("otx:abc-123", ["CVE-2024-1"])
    # Re-inserting the same link is fine (INSERT OR IGNORE).
    tic.link_campaign_to_cves("otx:abc-123", ["CVE-2024-1"])


def test_link_campaign_to_cves_rejects_garbage() -> None:
    assert tic.link_campaign_to_cves("", ["CVE-1"]) == 0
    assert tic.link_campaign_to_cves(None, ["CVE-1"]) == 0  # type: ignore[arg-type]
    # Empty CVE list short-circuits.
    assert tic.link_campaign_to_cves("otx:abc", []) == 0


def test_fetch_campaigns_for_cve_returns_linked() -> None:
    tic.upsert_campaign(_record(campaign_id="otx:1", severity="high"))
    tic.upsert_campaign(_record(campaign_id="otx:2", severity="medium"))
    tic.link_campaign_to_cves("otx:1", ["CVE-2024-X"])
    tic.link_campaign_to_cves("otx:2", ["CVE-2024-X"])

    results = tic.fetch_campaigns_for_cve("CVE-2024-X")
    assert len(results) == 2
    ids = {r["campaign_id"] for r in results}
    assert ids == {"otx:1", "otx:2"}


def test_fetch_campaigns_for_cve_orders_by_last_seen_desc() -> None:
    tic.upsert_campaign(_record(
        campaign_id="otx:old", last_seen="2026-04-01T00:00:00Z",
    ))
    tic.upsert_campaign(_record(
        campaign_id="otx:new", last_seen="2026-05-19T00:00:00Z",
    ))
    tic.link_campaign_to_cves("otx:old", ["CVE-Y"])
    tic.link_campaign_to_cves("otx:new", ["CVE-Y"])

    results = tic.fetch_campaigns_for_cve("CVE-Y")
    assert results[0]["campaign_id"] == "otx:new"
    assert results[1]["campaign_id"] == "otx:old"


def test_fetch_campaigns_for_cve_no_match() -> None:
    assert tic.fetch_campaigns_for_cve("CVE-NEVER-2024-9999") == []


def test_fetch_campaigns_for_cve_handles_empty() -> None:
    assert tic.fetch_campaigns_for_cve("") == []
    assert tic.fetch_campaigns_for_cve(None) == []  # type: ignore[arg-type]


def test_fetch_campaigns_parses_references_and_tags() -> None:
    tic.upsert_campaign(_record(
        campaign_id="otx:parse-1",
        references=["https://a", "https://b"],
        tags=["t1", "t2"],
    ))
    tic.link_campaign_to_cves("otx:parse-1", ["CVE-Z"])
    rec = tic.fetch_campaigns_for_cve("CVE-Z")[0]
    assert rec["references"] == ["https://a", "https://b"]
    assert rec["tags"] == ["t1", "t2"]


def test_fetch_campaigns_for_cve_limit_clamps() -> None:
    """Limit is clamped to [1, 100]; both bounds tested."""
    for i in range(5):
        tic.upsert_campaign(_record(campaign_id=f"otx:limit-{i}"))
        tic.link_campaign_to_cves(f"otx:limit-{i}", ["CVE-LIM"])
    assert len(tic.fetch_campaigns_for_cve("CVE-LIM", limit=2)) == 2
    # Limit=0 silently floors to 1.
    assert len(tic.fetch_campaigns_for_cve("CVE-LIM", limit=0)) == 1
    # Limit=10000 silently caps to 100.
    assert len(tic.fetch_campaigns_for_cve("CVE-LIM", limit=10_000)) == 5
