"""Tests for `strix.threat_intel.feeds.ghsa`.

The poller is a pure function over `(url, body, headers, timeout)
-> bytes` plus the cache. We inject a fake `fetch` returning canned
GraphQL responses to exercise:
  * happy-path single-page ingest
  * pagination (multi-page) with cursor handoff
  * GraphQL `errors` payload → status=error
  * HTTP failure → status=error
  * ecosystem mapping (NPM/PIP/RUST/COMPOSER → cache vendor)
  * vulnerableVersionRange normalisation
  * CVE id preferred over GHSA id when present
"""

from __future__ import annotations

import json

import pytest

from strix.threat_intel import cache as ti_cache
from strix.threat_intel.feeds import ghsa as ghsa_feed


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    ti_cache.reset_for_testing(db)
    yield db


def _ghsa_node(*, ghsa_id: str, cve: str | None = None,
               severity: str = "HIGH",
               cvss: float | None = 7.5,
               vulnerabilities: list[dict] | None = None) -> dict:
    """Build one GHSA GraphQL node."""
    identifiers = [{"type": "GHSA", "value": ghsa_id}]
    if cve:
        identifiers.append({"type": "CVE", "value": cve})
    return {
        "ghsaId": ghsa_id,
        "summary": f"summary for {ghsa_id}",
        "description": f"description for {ghsa_id}",
        "severity": severity,
        "publishedAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-02-01T00:00:00Z",
        "identifiers": identifiers,
        "cvss": {"score": cvss},
        "cwes": {"nodes": [{"cweId": "CWE-79"}]},
        "vulnerabilities": {
            "nodes": vulnerabilities or [],
        },
    }


def _wrap(nodes: list[dict], *, has_next: bool = False,
          end_cursor: str | None = None) -> bytes:
    return json.dumps({
        "data": {
            "securityAdvisories": {
                "pageInfo": {
                    "hasNextPage": has_next,
                    "endCursor": end_cursor,
                },
                "nodes": nodes,
            },
        },
    }).encode("utf-8")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_poll_ghsa_happy_path(tmp_cache) -> None:
    payload = _wrap([
        _ghsa_node(
            ghsa_id="GHSA-aaaa-bbbb-cccc",
            cve="CVE-2024-9999",
            severity="CRITICAL",
            cvss=9.8,
            vulnerabilities=[
                {
                    "package": {"ecosystem": "NPM", "name": "lodash"},
                    "vulnerableVersionRange": "< 4.17.21",
                },
            ],
        ),
    ])

    def fake_fetch(url, *, body, headers, timeout):
        return payload

    result = ghsa_feed.poll_ghsa(fetch=fake_fetch)
    assert result["status"] == "ok"
    assert result["ingested"] == 1
    assert result["pages"] == 1

    rec = ti_cache.fetch_cve("CVE-2024-9999")
    assert rec is not None
    # Severity normalised to lowercase.
    assert rec.severity == "critical"
    assert rec.cvss_score == 9.8
    # Component vendor + version pattern wired correctly.
    comps = rec.components
    assert comps and comps[0]["vendor"] == "npm"
    assert comps[0]["product"] == "lodash"
    # Whitespace inside operator is stripped.
    assert comps[0]["version_pattern"] == "<4.17.21"


def test_poll_ghsa_uses_ghsa_id_when_no_cve(tmp_cache) -> None:
    payload = _wrap([
        _ghsa_node(
            ghsa_id="GHSA-only-id",
            cve=None,
            vulnerabilities=[
                {"package": {"ecosystem": "NPM", "name": "x"},
                 "vulnerableVersionRange": "*"},
            ],
        ),
    ])

    def fake_fetch(url, *, body, headers, timeout):
        return payload

    ghsa_feed.poll_ghsa(fetch=fake_fetch)
    # Cache stores upper-cased id.
    assert ti_cache.fetch_cve("GHSA-ONLY-ID") is not None


def test_poll_ghsa_severity_moderate_normalised(tmp_cache) -> None:
    payload = _wrap([
        _ghsa_node(
            ghsa_id="GHSA-1", cve="CVE-2024-1",
            severity="MODERATE",
            vulnerabilities=[
                {"package": {"ecosystem": "PIP", "name": "django"},
                 "vulnerableVersionRange": ">= 4.0, < 4.2.7"},
            ],
        ),
    ])

    def fake_fetch(url, *, body, headers, timeout):
        return payload

    ghsa_feed.poll_ghsa(fetch=fake_fetch)
    rec = ti_cache.fetch_cve("CVE-2024-1")
    assert rec.severity == "medium"
    # PIP → pypi vendor mapping.
    assert rec.components[0]["vendor"] == "pypi"
    # Comma-separated range, whitespace stripped.
    assert rec.components[0]["version_pattern"] == ">=4.0,<4.2.7"


# ---------------------------------------------------------------------------
# Ecosystem mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ghsa_eco,cache_vendor", [
    ("NPM", "npm"),
    ("PIP", "pypi"),
    ("RUBYGEMS", "rubygems"),
    ("COMPOSER", "composer"),
    ("RUST", "cargo"),
    ("GO", "go"),
    ("MAVEN", "maven"),
])
def test_ecosystem_label_mapping(ghsa_eco, cache_vendor) -> None:
    assert ghsa_feed._ecosystem_label(ghsa_eco) == cache_vendor


# ---------------------------------------------------------------------------
# Range normalisation
# ---------------------------------------------------------------------------


def test_normalize_range_wildcard() -> None:
    assert ghsa_feed._normalize_range("") == "*"
    assert ghsa_feed._normalize_range("*") == "*"


def test_normalize_range_compound() -> None:
    # Whitespace inside operators is stripped.
    assert (
        ghsa_feed._normalize_range(">= 1.0.0, < 2.0.0")
        == ">=1.0.0,<2.0.0"
    )


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def test_poll_ghsa_paginates(tmp_cache) -> None:
    """Two pages, cursor handoff works."""
    page1 = _wrap(
        [
            _ghsa_node(
                ghsa_id="GHSA-1", cve="CVE-2024-A",
                vulnerabilities=[{
                    "package": {"ecosystem": "NPM", "name": "p1"},
                    "vulnerableVersionRange": "*",
                }],
            ),
        ],
        has_next=True, end_cursor="cursor-2",
    )
    page2 = _wrap(
        [
            _ghsa_node(
                ghsa_id="GHSA-2", cve="CVE-2024-B",
                vulnerabilities=[{
                    "package": {"ecosystem": "NPM", "name": "p2"},
                    "vulnerableVersionRange": "*",
                }],
            ),
        ],
        has_next=False,
    )
    pages = [page1, page2]
    seen_cursors: list = []

    def fake_fetch(url, *, body, headers, timeout):
        decoded = json.loads(body)
        seen_cursors.append(decoded["variables"]["cursor"])
        return pages.pop(0)

    result = ghsa_feed.poll_ghsa(fetch=fake_fetch)
    assert result["status"] == "ok"
    assert result["ingested"] == 2
    assert result["pages"] == 2
    # First page sent cursor=None; second sent the prior endCursor.
    assert seen_cursors == [None, "cursor-2"]
    assert ti_cache.fetch_cve("CVE-2024-A") is not None
    assert ti_cache.fetch_cve("CVE-2024-B") is not None


def test_poll_ghsa_max_pages_caps_pagination(tmp_cache) -> None:
    """If hasNextPage stays True forever, the loop terminates at
    max_pages."""

    def fake_fetch(url, *, body, headers, timeout):
        return _wrap(
            [
                _ghsa_node(
                    ghsa_id="GHSA-X", cve="CVE-2024-X",
                    vulnerabilities=[{
                        "package": {"ecosystem": "NPM", "name": "x"},
                        "vulnerableVersionRange": "*",
                    }],
                ),
            ],
            has_next=True, end_cursor="loop",
        )

    result = ghsa_feed.poll_ghsa(fetch=fake_fetch, max_pages=3)
    assert result["status"] == "ok"
    assert result["pages"] == 3


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_poll_ghsa_graphql_errors_payload(tmp_cache) -> None:
    payload = json.dumps({
        "errors": [{"message": "rate limit"}],
    }).encode("utf-8")

    def fake_fetch(url, *, body, headers, timeout):
        return payload

    result = ghsa_feed.poll_ghsa(fetch=fake_fetch)
    assert result["status"] == "error"
    assert "GraphQL errors" in (result["error"] or "")


def test_poll_ghsa_invalid_json(tmp_cache) -> None:
    def fake_fetch(url, *, body, headers, timeout):
        return b"not json"

    result = ghsa_feed.poll_ghsa(fetch=fake_fetch)
    assert result["status"] == "error"


def test_poll_ghsa_fetch_raises(tmp_cache) -> None:
    def fake_fetch(url, *, body, headers, timeout):
        raise RuntimeError("network down")

    result = ghsa_feed.poll_ghsa(fetch=fake_fetch)
    assert result["status"] == "error"
    assert "network down" in (result["error"] or "")
    # Feed status row recorded.
    meta = {m["feed_name"]: m for m in ti_cache.fetch_feed_meta()}
    assert "ghsa" in meta
    assert meta["ghsa"]["status"] == "error"


def test_poll_ghsa_skips_records_with_no_id(tmp_cache) -> None:
    payload = _wrap([
        # No identifiers at all → _normalize_record returns None.
        {
            "ghsaId": "",
            "summary": "x",
            "description": "x",
            "severity": "HIGH",
            "publishedAt": "2024-01-01T00:00:00Z",
            "updatedAt": "2024-02-01T00:00:00Z",
            "identifiers": [],
            "cvss": {"score": None},
            "cwes": {"nodes": []},
            "vulnerabilities": {"nodes": []},
        },
        _ghsa_node(
            ghsa_id="GHSA-real", cve="CVE-REAL",
            vulnerabilities=[{
                "package": {"ecosystem": "NPM", "name": "p"},
                "vulnerableVersionRange": "*",
            }],
        ),
    ])

    def fake_fetch(url, *, body, headers, timeout):
        return payload

    result = ghsa_feed.poll_ghsa(fetch=fake_fetch)
    # Only the valid record makes it in.
    assert result["status"] == "ok"
    assert result["ingested"] == 1
    assert ti_cache.fetch_cve("CVE-REAL") is not None
