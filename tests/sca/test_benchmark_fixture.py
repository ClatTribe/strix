"""Offline integration test for the SCA benchmark fixture.

This is the "did Phase 6 actually wire up?" smoke test:

  1. Walk the benchmark fixture's `src/` like the real lead would.
  2. Parse every lockfile we find with the registered parsers.
  3. Seed a deterministic threat-intel cache with one CVE per
     fixture package so we can verify the match step (no live
     GHSA / NVD network).
  4. Run `scan_sca_lockfiles` end-to-end.
  5. Assert the must-find packages from `expected.yaml` are all
     present in the emitted findings.

This guards against regressions where the parser or the matcher
silently drop a package — a class of bug that pure unit tests on
each parser miss because they don't exercise the full
walk-parse-match-emit chain.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.sca.parsers.base import find_lockfiles, parse_lockfile
from strix.sca.tools import scan_sca_lockfiles
from strix.threat_intel import cache as ti_cache


FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "benchmarks" / "per_target" / "fixtures" / "code" / "sca-vuln-deps"
)


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


# Per-package "headline CVE" used to seed the cache. The benchmark
# manifest names the real public CVEs; we use synthetic CVE-ids here
# so the test stays deterministic regardless of cache freshness, but
# the (vendor, product, version_pattern) tuple matches what GHSA
# would emit for the real advisory.
_SEED_CVES = [
    # npm
    {"cve_id": "BENCH-NPM-LODASH",
     "components": [{"vendor": "npm", "product": "lodash",
                     "version_pattern": "<4.17.21"}],
     "severity": "high", "cvss_score": 7.4},
    {"cve_id": "BENCH-NPM-MINIMIST",
     "components": [{"vendor": "npm", "product": "minimist",
                     "version_pattern": "<1.2.6"}],
     "severity": "high", "cvss_score": 7.4},
    {"cve_id": "BENCH-NPM-EXPRESS",
     "components": [{"vendor": "npm", "product": "express",
                     "version_pattern": "<4.19.2"}],
     "severity": "medium", "cvss_score": 6.1},
    {"cve_id": "BENCH-NPM-WS",
     "components": [{"vendor": "npm", "product": "ws",
                     "version_pattern": "<5.2.4"}],
     "severity": "high", "cvss_score": 7.5},
    # pypi
    {"cve_id": "BENCH-PYPI-DJANGO",
     "components": [{"vendor": "pypi", "product": "django",
                     "version_pattern": "<2.2.18"}],
     "severity": "critical", "cvss_score": 9.8},
    {"cve_id": "BENCH-PYPI-REQUESTS",
     "components": [{"vendor": "pypi", "product": "requests",
                     "version_pattern": "<2.20.0"}],
     "severity": "medium", "cvss_score": 6.1},
    {"cve_id": "BENCH-PYPI-PYYAML",
     "components": [{"vendor": "pypi", "product": "pyyaml",
                     "version_pattern": "<5.4"}],
     "severity": "critical", "cvss_score": 9.8},
    {"cve_id": "BENCH-PYPI-FLASK",
     "components": [{"vendor": "pypi", "product": "flask",
                     "version_pattern": "<1.0"}],
     "severity": "high", "cvss_score": 7.5},
]


# Packages that the manifest pins as `must_find: true`. If any of
# these go missing from the emitted findings, the SCA pipeline has
# regressed.
_MUST_FIND_PACKAGES = {
    "lodash", "minimist", "ws",
    "django", "pyyaml",
}


def test_fixture_files_exist() -> None:
    """Sanity: the benchmark fixture is checked in and reachable."""
    assert FIXTURE.exists(), FIXTURE
    assert (FIXTURE / "expected.yaml").exists()
    assert (FIXTURE / "src" / "package-lock.json").exists()
    assert (FIXTURE / "src" / "requirements.txt").exists()


def test_find_lockfiles_walks_fixture_src() -> None:
    """The repo-walk must surface both the npm + pypi lockfiles."""
    found = {p.name for p in find_lockfiles(FIXTURE / "src")}
    assert "package-lock.json" in found
    assert "requirements.txt" in found


def test_npm_fixture_parses_all_pinned_packages() -> None:
    pkgs = parse_lockfile(FIXTURE / "src" / "package-lock.json")
    by = {p.name: p for p in pkgs}
    # The 4 vulnerable + 1 dev-only pinned in the fixture.
    for required in ("lodash", "minimist", "express", "ws", "jest"):
        assert required in by, f"missing {required}: {sorted(by)}"
    assert by["lodash"].version == "4.17.20"
    assert by["jest"].dev_only is True
    assert by["express"].dev_only is False


def test_pypi_fixture_parses_all_pinned_packages() -> None:
    pkgs = parse_lockfile(FIXTURE / "src" / "requirements.txt")
    by = {p.name: p for p in pkgs}
    for required in ("django", "requests", "pyyaml", "flask"):
        assert required in by, f"missing {required}: {sorted(by)}"
    assert by["django"].version == "2.2.0"


def test_end_to_end_sca_emits_must_find_packages(tmp_cache) -> None:
    """Full pipeline: walk fixture → parse → match against seeded
    cache → emit findings. Every must-find package from the manifest
    must appear in the emitted findings list."""
    ti_cache.upsert_cves(_SEED_CVES, source="benchmark-test")

    result = scan_sca_lockfiles(repo_path=str(FIXTURE / "src"))
    assert result["status"] == "ok", result.get("error")

    titles = " | ".join(d["title"] for d in result["findings"])
    missing = [pkg for pkg in _MUST_FIND_PACKAGES if pkg not in titles]
    assert not missing, (
        f"must-find packages missing from SCA emit: {missing}\n"
        f"emitted titles: {titles}"
    )


def test_end_to_end_sca_skips_dev_only_jest(tmp_cache) -> None:
    """jest@29.5.0 is dev-only; with skip_dev_only=True (default) the
    pipeline must NOT emit a finding for it even if the cache had a
    matching CVE."""
    ti_cache.upsert_cves(
        [{"cve_id": "BENCH-NPM-JEST",
          "components": [{"vendor": "npm", "product": "jest",
                          "version_pattern": "*"}],
          "severity": "high", "cvss_score": 7.5}],
        source="benchmark-test",
    )
    result = scan_sca_lockfiles(repo_path=str(FIXTURE / "src"))
    titles = " | ".join(d["title"] for d in result["findings"])
    assert "jest" not in titles, (
        "dev-only package leaked into runtime findings"
    )


def test_packages_by_ecosystem_split_pypi_npm(tmp_cache) -> None:
    """The aggregate report must report both ecosystems separately so
    the wrapper can filter by language/runtime."""
    ti_cache.upsert_cves(_SEED_CVES, source="benchmark-test")
    result = scan_sca_lockfiles(repo_path=str(FIXTURE / "src"))
    by_eco = result["tool_metadata"]["packages_by_ecosystem"]
    assert by_eco.get("npm", 0) >= 4   # 4 runtime + 1 dev
    assert by_eco.get("pypi", 0) >= 4
