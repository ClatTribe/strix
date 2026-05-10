"""Tests for `strix.sca.match.find_vulnerabilities`.

Seeds a small threat-intel cache with deterministic CVEs across two
ecosystems, then verifies that:
  * Package → CVE matching uses (ecosystem, name, version) as the key.
  * Dev-only packages are skipped by default.
  * only_kev / min_epss filters propagate to the cache lookup.
  * PackageMatch.severity_max / has_kev / max_epss aggregate correctly.
"""

from __future__ import annotations

import pytest

from strix.sca.match import PackageMatch, find_vulnerabilities
from strix.sca.parsers.base import Package
from strix.threat_intel import cache as ti_cache


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


def _seed(tmp_cache) -> None:
    ti_cache.upsert_cves([
        {
            "cve_id": "CVE-2024-NPM-1",
            "cvss_score": 9.8,
            "severity": "critical",
            "components": [{
                "vendor": "npm", "product": "lodash",
                "version_pattern": "<4.17.21",
            }],
        },
        {
            "cve_id": "CVE-2024-NPM-2",
            "cvss_score": 5.5,
            "severity": "medium",
            "components": [{
                "vendor": "npm", "product": "lodash",
                "version_pattern": "*",
            }],
        },
        {
            "cve_id": "CVE-2024-PYPI-1",
            "cvss_score": 7.5,
            "severity": "high",
            "components": [{
                "vendor": "pypi", "product": "django",
                "version_pattern": "<4.2.7",
            }],
        },
    ], source="test")
    ti_cache.upsert_kev_entries([
        {"cve_id": "CVE-2024-NPM-1", "vendor": "npm",
         "product": "lodash", "vuln_name": "Lodash proto pollution"},
    ])
    ti_cache.upsert_epss_scores([
        ("CVE-2024-NPM-1", 0.92),
        ("CVE-2024-NPM-2", 0.04),
        ("CVE-2024-PYPI-1", 0.55),
    ])


def _pkg(name: str, version: str, ecosystem: str = "npm",
         dev_only: bool = False) -> Package:
    return Package(
        ecosystem=ecosystem, name=name, version=version,
        dev_only=dev_only, source_path="lockfile",
    )


def test_matches_vulnerable_package(tmp_cache) -> None:
    _seed(tmp_cache)
    matches = find_vulnerabilities([_pkg("lodash", "4.17.20")])
    assert len(matches) == 1
    m = matches[0]
    ids = {c.cve_id for c in m.cves}
    assert {"CVE-2024-NPM-1", "CVE-2024-NPM-2"} <= ids


def test_dev_only_skipped_by_default(tmp_cache) -> None:
    _seed(tmp_cache)
    matches = find_vulnerabilities([_pkg("lodash", "4.17.20", dev_only=True)])
    assert matches[0].cves == []


def test_dev_only_included_when_disabled(tmp_cache) -> None:
    _seed(tmp_cache)
    matches = find_vulnerabilities(
        [_pkg("lodash", "4.17.20", dev_only=True)],
        skip_dev_only=False,
    )
    assert matches[0].cves


def test_only_kev_filter(tmp_cache) -> None:
    _seed(tmp_cache)
    matches = find_vulnerabilities(
        [_pkg("lodash", "4.17.20")], only_kev=True,
    )
    ids = {c.cve_id for c in matches[0].cves}
    assert ids == {"CVE-2024-NPM-1"}


def test_min_epss_filter(tmp_cache) -> None:
    _seed(tmp_cache)
    matches = find_vulnerabilities(
        [_pkg("lodash", "4.17.20")], min_epss=0.5,
    )
    ids = {c.cve_id for c in matches[0].cves}
    assert ids == {"CVE-2024-NPM-1"}  # only NPM-1 (0.92 >= 0.5)


def test_ecosystem_separation(tmp_cache) -> None:
    """A pypi:django package must not match an npm:lodash CVE."""
    _seed(tmp_cache)
    matches = find_vulnerabilities([
        _pkg("django", "4.2.0", ecosystem="pypi"),
        _pkg("lodash", "4.17.20", ecosystem="npm"),
    ])
    by_pkg = {m.package.name: m for m in matches}
    pypi_ids = {c.cve_id for c in by_pkg["django"].cves}
    npm_ids = {c.cve_id for c in by_pkg["lodash"].cves}
    assert pypi_ids == {"CVE-2024-PYPI-1"}
    assert "CVE-2024-PYPI-1" not in npm_ids


def test_severity_max_uses_kev(tmp_cache) -> None:
    _seed(tmp_cache)
    matches = find_vulnerabilities([_pkg("lodash", "4.17.20")])
    m = matches[0]
    assert m.severity_max == "critical"
    assert m.has_kev is True
    assert m.max_epss == pytest.approx(0.92)


def test_no_cves_for_unknown_package(tmp_cache) -> None:
    _seed(tmp_cache)
    matches = find_vulnerabilities([_pkg("unknown-pkg", "1.0.0")])
    assert matches[0].cves == []
    # severity_max defaults to "info" when no CVEs.
    assert matches[0].severity_max == "info"
    assert matches[0].has_kev is False
    assert matches[0].max_epss == 0.0


def test_version_outside_range_doesnt_match(tmp_cache) -> None:
    """lodash@5.0.0 is above CVE-2024-NPM-1's <4.17.21 bound;
    only the wildcard CVE-2024-NPM-2 matches."""
    _seed(tmp_cache)
    matches = find_vulnerabilities([_pkg("lodash", "5.0.0")])
    ids = {c.cve_id for c in matches[0].cves}
    assert "CVE-2024-NPM-1" not in ids
    assert "CVE-2024-NPM-2" in ids
