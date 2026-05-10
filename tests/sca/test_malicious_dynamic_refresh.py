"""Tests for the §6a dynamic-refresh integration in
`strix.sca.malicious`:

  * `_detect_typosquat` reads the popular corpus from the
    threat-intel cache when populated.
  * Falls back to the hardcoded corpus when the cache is empty.
  * `_detect_known_malicious` hits the OSSF malicious cache and
    emits critical findings on match.
  * `analyse_packages` propagates both detectors via tracer-level
    counts (visible in `tool_metadata.malicious.by_indicator`).
"""

from __future__ import annotations

import pytest

from strix.sca.malicious import (
    INDICATOR_KNOWN_MALICIOUS,
    INDICATOR_TYPOSQUAT,
    _detect_known_malicious,
    _detect_typosquat,
    _resolve_corpus,
    analyse_package,
)
from strix.sca.parsers.base import Package
from strix.threat_intel import cache as ti_cache


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


def _pkg(name: str, *, ecosystem: str = "npm", version: str = "1.0.0",
         direct: bool = True, **md) -> Package:
    return Package(
        ecosystem=ecosystem, name=name, version=version, direct=direct,
        source_path="lockfile", metadata=md,
    )


# ---------------------------------------------------------------------------
# Popular corpus — cache-first, hardcoded-fallback
# ---------------------------------------------------------------------------


def test_resolve_corpus_returns_cached_when_populated(tmp_cache) -> None:
    ti_cache.upsert_popular_packages(
        [("npm", "fresh-pkg", 1), ("npm", "another-fresh", 2)],
        replace_ecosystem="npm",
    )
    corpus = _resolve_corpus("npm")
    assert "fresh-pkg" in corpus
    assert "another-fresh" in corpus


def test_resolve_corpus_falls_back_to_hardcoded_when_cache_empty(tmp_cache) -> None:
    """Empty popular_packages table → fallback to baked-in
    `_POPULAR_NPM_PACKAGES` so the typosquat detector never goes
    silent."""
    corpus = _resolve_corpus("npm")
    # The hardcoded set has `lodash` / `express` / etc.
    assert "lodash" in corpus
    assert "express" in corpus


def test_resolve_corpus_unsupported_ecosystem_returns_empty(tmp_cache) -> None:
    """`cargo` etc. aren't covered by the corpus feeds; resolver
    returns empty (not None) so the detector treats it as
    "no signal" rather than crashing."""
    assert _resolve_corpus("cargo") == frozenset()


def test_typosquat_uses_dynamic_corpus(tmp_cache) -> None:
    """The detector should compute distance against the cached
    corpus, not just the hardcoded set."""
    # Cache: only `mycustompkg` is "popular".
    ti_cache.upsert_popular_packages(
        [("npm", "mycustompkg", 1)],
        replace_ecosystem="npm",
    )
    # Distance-1 squat.
    pkg = _pkg("mycustompk")
    ind = _detect_typosquat(pkg)
    assert ind is not None
    assert ind.indicator == INDICATOR_TYPOSQUAT
    assert ind.extra["typosquat_target"] == "mycustompkg"


def test_typosquat_skips_when_name_in_dynamic_corpus(tmp_cache) -> None:
    """The detector must NOT flag a name that IS in the cached
    popular list as a typosquat of itself."""
    ti_cache.upsert_popular_packages(
        [("npm", "popularpkg", 1)],
        replace_ecosystem="npm",
    )
    pkg = _pkg("popularpkg")
    assert _detect_typosquat(pkg) is None


# ---------------------------------------------------------------------------
# known_malicious detector
# ---------------------------------------------------------------------------


def test_known_malicious_emits_critical_when_version_matches(tmp_cache) -> None:
    ti_cache.upsert_malicious_packages([{
        "ecosystem": "npm", "name": "evil-pkg",
        "advisory_id": "MAL-2024-001",
        "summary": "rugpull on 2024-12-01",
        "detected_at": "2024-12-01T00:00:00Z",
        "severity": "critical",
        "affected_versions": ["1.0.0", "1.0.1"],
    }])
    pkg = _pkg("evil-pkg", version="1.0.0")
    ind = _detect_known_malicious(pkg)
    assert ind is not None
    assert ind.indicator == INDICATOR_KNOWN_MALICIOUS
    assert ind.severity == "critical"
    assert "MAL-2024-001" in ind.rationale


def test_known_malicious_demotes_to_high_when_version_not_in_list(tmp_cache) -> None:
    """A package with a different installed version than the
    advisory's affected list → still flagged (the package was
    malicious at SOME version) but high not critical."""
    ti_cache.upsert_malicious_packages([{
        "ecosystem": "npm", "name": "evil-pkg",
        "advisory_id": "MAL-2024-001",
        "affected_versions": ["1.0.0"],
        "severity": "critical",
    }])
    pkg = _pkg("evil-pkg", version="2.0.0")
    ind = _detect_known_malicious(pkg)
    assert ind is not None
    assert ind.severity == "high"
    assert "not in the advisory's affected list" in ind.rationale


def test_known_malicious_flags_all_versions_when_list_empty(tmp_cache) -> None:
    """Empty `affected_versions` = all versions affected (per the
    cache table schema convention)."""
    ti_cache.upsert_malicious_packages([{
        "ecosystem": "npm", "name": "evil-pkg",
        "advisory_id": "MAL-2024-002",
        "affected_versions": [],
    }])
    pkg = _pkg("evil-pkg", version="9.99.99")
    ind = _detect_known_malicious(pkg)
    assert ind is not None
    assert ind.severity == "critical"


def test_known_malicious_no_signal_when_cache_empty(tmp_cache) -> None:
    """Empty cache → no finding. The detector must not crash and
    must not emit false-positives on every package."""
    pkg = _pkg("totally-clean-pkg", version="1.0.0")
    assert _detect_known_malicious(pkg) is None


def test_known_malicious_is_ecosystem_scoped(tmp_cache) -> None:
    """An entry in the cache for npm:evil-pkg should NOT match
    pypi:evil-pkg."""
    ti_cache.upsert_malicious_packages([{
        "ecosystem": "npm", "name": "evil-pkg",
        "advisory_id": "MAL-X",
    }])
    pypi_pkg = _pkg("evil-pkg", ecosystem="pypi")
    assert _detect_known_malicious(pypi_pkg) is None


# ---------------------------------------------------------------------------
# analyse_package — multi-detector integration
# ---------------------------------------------------------------------------


def test_analyse_package_collects_known_malicious_alongside_heuristics(
    tmp_cache,
) -> None:
    """A package can hit known_malicious AND no_license — both
    indicators should fire in a single analysis."""
    ti_cache.upsert_malicious_packages([{
        "ecosystem": "npm", "name": "evil-pkg",
        "advisory_id": "MAL-Y",
        "affected_versions": [],  # all versions
    }])
    pkg = _pkg("evil-pkg", version="1.0.0", license=None)
    report = analyse_package(pkg)
    indicators = {i.indicator for i in report.indicators}
    assert INDICATOR_KNOWN_MALICIOUS in indicators
    # The no_license indicator also fires (license=None).
    assert "no_license" in indicators


def test_analyse_package_severity_max_picks_known_malicious(tmp_cache) -> None:
    """known_malicious=critical outranks the heuristic-level
    indicators in severity_max."""
    ti_cache.upsert_malicious_packages([{
        "ecosystem": "npm", "name": "evil-pkg",
        "advisory_id": "MAL-Z",
        "affected_versions": [],
    }])
    # Add no_license signal too.
    pkg = _pkg("evil-pkg", license=None)
    report = analyse_package(pkg)
    assert report.severity_max == "critical"
