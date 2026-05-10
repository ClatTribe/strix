"""End-to-end test for the `sca-reachability/` efficiency benchmark.

Mirrors `test_benchmark_fixture.py`'s shape but for Phase 6.4: walks
the fixture, parses, matches against a seeded threat-intel cache,
classifies reachability, asserts the planted ratio
(`direct_import: 3, unused: 3`) is observed and the demotion math
holds (3 unused findings demoted from high → low while 3 reachable
keep their original severity).

This is the *measurement* version of the unit tests: the unit
tests prove the math is right; this test proves the planted
benchmark fixture matches the math.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.sca.tools import scan_sca_lockfiles
from strix.threat_intel import cache as ti_cache


FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "benchmarks" / "per_target" / "fixtures"
    / "code" / "sca-reachability"
)


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


# Per-package severity assignments matched to the planted fixture's
# expected.yaml. Same severity for all 6 simplifies the
# raw-vs-filtered comparison: if reachability didn't fire, every
# finding would be `high`.
_SEED_CVES = [
    {
        "cve_id": "BENCH-LODASH",
        "cvss_score": 7.4, "severity": "high",
        "components": [{
            "vendor": "npm", "product": "lodash",
            "version_pattern": "*",
        }],
    },
    {
        "cve_id": "BENCH-EJS",
        "cvss_score": 9.8, "severity": "critical",
        "components": [{
            "vendor": "npm", "product": "ejs",
            "version_pattern": "*",
        }],
    },
    {
        "cve_id": "BENCH-EXPRESS",
        "cvss_score": 6.1, "severity": "medium",
        "components": [{
            "vendor": "npm", "product": "express",
            "version_pattern": "*",
        }],
    },
    {
        "cve_id": "BENCH-WS",
        "cvss_score": 7.4, "severity": "high",
        "components": [{
            "vendor": "npm", "product": "ws",
            "version_pattern": "*",
        }],
    },
    {
        "cve_id": "BENCH-MINIMIST",
        "cvss_score": 7.4, "severity": "high",
        "components": [{
            "vendor": "npm", "product": "minimist",
            "version_pattern": "*",
        }],
    },
    {
        "cve_id": "BENCH-YARGS",
        "cvss_score": 7.4, "severity": "high",
        "components": [{
            "vendor": "npm", "product": "yargs",
            "version_pattern": "*",
        }],
    },
]


# ---------------------------------------------------------------------------
# Fixture sanity
# ---------------------------------------------------------------------------


def test_fixture_files_exist() -> None:
    assert FIXTURE.exists()
    assert (FIXTURE / "expected.yaml").exists()
    assert (FIXTURE / "src" / "package-lock.json").exists()
    assert (FIXTURE / "src" / "app.js").exists()


def test_fixture_lockfile_pins_planted_versions() -> None:
    """Anti-rot — bumping any version here breaks the benchmark's
    claim that these specific (package, CVE) pairs match."""
    import strix.sca.parsers  # noqa: F401
    from strix.sca.parsers.base import parse_lockfile

    pkgs = parse_lockfile(FIXTURE / "src" / "package-lock.json")
    by = {p.name: p.version for p in pkgs}
    assert by["lodash"] == "4.17.20"
    assert by["ejs"] == "3.1.6"
    assert by["express"] == "4.16.0"
    assert by["ws"] == "5.2.2"
    assert by["minimist"] == "1.2.5"
    assert by["yargs"] == "16.0.0"


# ---------------------------------------------------------------------------
# Reachability classification — the 3/3 planted ratio
# ---------------------------------------------------------------------------


def test_planted_3_direct_3_unused_split(tmp_cache) -> None:
    """The fixture's planted behaviour: 3 packages directly
    imported, 3 packages unused. If this ratio drifts, either the
    fixture or the import detector regressed."""
    ti_cache.upsert_cves(_SEED_CVES, source="bench-test")

    result = scan_sca_lockfiles(
        repo_path=str(FIXTURE / "src"),
        with_reachability=True,
    )
    assert result["status"] == "ok"
    by_status = result["tool_metadata"]["reachability"]["by_status"]
    assert by_status.get("direct_import", 0) == 3, by_status
    assert by_status.get("unused", 0) == 3, by_status
    assert by_status.get("transitive_only", 0) == 0
    assert by_status.get("unknown", 0) == 0


def test_imported_packages_keep_severity(tmp_cache) -> None:
    """lodash / ejs / express are imported via `require()` — their
    severities must NOT be demoted by reachability."""
    ti_cache.upsert_cves(_SEED_CVES, source="bench-test")

    result = scan_sca_lockfiles(
        repo_path=str(FIXTURE / "src"),
        with_reachability=True,
    )
    by_pkg = {
        d["title"].split("`")[1].split("@")[0].split(":")[1]: d
        for d in result["findings"]
    }
    assert by_pkg["lodash"]["severity"] == "high"
    assert by_pkg["ejs"]["severity"] == "critical"
    assert by_pkg["express"]["severity"] == "medium"
    # And no [reachability=...] suffix on these (direct_import is
    # the no-op default and we deliberately don't tag titles for it).
    assert "reachability=" not in by_pkg["lodash"]["title"]
    assert "reachability=" not in by_pkg["ejs"]["title"]
    assert "reachability=" not in by_pkg["express"]["title"]


def test_unused_packages_demoted_two_tiers(tmp_cache) -> None:
    """ws / minimist / yargs are NOT imported by the source — all
    three demoted from high → low. The title carries the
    `[reachability=unused]` suffix so the wrapper can render the
    demotion badge."""
    ti_cache.upsert_cves(_SEED_CVES, source="bench-test")

    result = scan_sca_lockfiles(
        repo_path=str(FIXTURE / "src"),
        with_reachability=True,
    )
    by_pkg = {
        d["title"].split("`")[1].split("@")[0].split(":")[1]: d
        for d in result["findings"]
    }
    for unused_pkg in ("ws", "minimist", "yargs"):
        finding = by_pkg[unused_pkg]
        assert finding["severity"] == "low", (unused_pkg, finding)
        assert "[reachability=unused]" in finding["title"], finding


# ---------------------------------------------------------------------------
# Efficiency claim — the headline number
# ---------------------------------------------------------------------------


def test_high_count_drops_50pct_with_reachability(tmp_cache) -> None:
    """The benchmark's headline efficiency number: with 4 high
    severities raw and 3 of those getting demoted to low, the
    high-tier count drops from 4 → 1 (75% reduction on this
    fixture). The 30–60% on real repos is real-world; here the
    ratio is contrived to be measurable."""
    ti_cache.upsert_cves(_SEED_CVES, source="bench-test")

    raw = scan_sca_lockfiles(
        repo_path=str(FIXTURE / "src"),
        with_reachability=False,
    )
    filtered = scan_sca_lockfiles(
        repo_path=str(FIXTURE / "src"),
        with_reachability=True,
    )

    raw_high = sum(1 for d in raw["findings"] if d["severity"] == "high")
    filtered_high = sum(1 for d in filtered["findings"] if d["severity"] == "high")
    raw_critical = sum(1 for d in raw["findings"] if d["severity"] == "critical")
    filtered_critical = sum(1 for d in filtered["findings"] if d["severity"] == "critical")

    # Raw: 4 high (lodash + ws + minimist + yargs), 1 critical (ejs),
    # 1 medium (express).
    assert raw_high == 4, [d["severity"] for d in raw["findings"]]
    assert raw_critical == 1
    # Filtered: only lodash stays high (3 unused demoted to low);
    # ejs stays critical (reachable).
    assert filtered_high == 1, [
        (d["title"], d["severity"]) for d in filtered["findings"]
    ]
    assert filtered_critical == 1


def test_efficiency_metric_in_tool_metadata(tmp_cache) -> None:
    """The wrapper-facing claim: `tool_metadata.reachability` exposes
    enough data to compute the reduction ratio without re-walking
    the source tree. The claim is "you can render a 'we filtered N
    noise findings' badge from this dict alone"."""
    ti_cache.upsert_cves(_SEED_CVES, source="bench-test")

    result = scan_sca_lockfiles(
        repo_path=str(FIXTURE / "src"),
        with_reachability=True,
    )
    md = result["tool_metadata"]["reachability"]
    assert md["enabled"] is True
    assert "by_status" in md
    assert "suppressed" in md
    # Suppressed=0 by default (only_reachable=False); demoted but emitted.
    assert md["suppressed"] == 0
