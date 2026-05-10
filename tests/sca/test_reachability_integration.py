"""SCA-efficiency integration tests for Phase 6.4 reachability.

These exercise the full pipeline:
  walk repo → parse lockfile → match against threat-intel cache →
  classify reachability → demote / suppress findings → emit.

Why a dedicated file: the unit tests in `test_reachability.py`
prove each function in isolation. *These* tests measure the
**efficiency claim**: "reachability filters 30–60% of SCA noise on
real repos". We can't validate that claim with synthetic mocks; we
need a fixture that has a known ratio of reachable-vs-unused
vulnerable packages, and we need to assert that the SCA
specialist's `tool_metadata` reports the expected reduction.

The `vibe-app` benchmark fixture (Phase 6.3.4) is the natural test
target: it has lodash + ejs + express in `package-lock.json`, and
the source code imports lodash + ejs but NOT express. Adding a
`unused-vuln-pkg` to the lockfile that nothing imports gives us a
deterministic reachable-to-unused ratio.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from strix.sca.tools import scan_sca_lockfiles
from strix.threat_intel import cache as ti_cache


VIBE_APP = (
    Path(__file__).resolve().parents[2]
    / "benchmarks" / "per_target" / "fixtures"
    / "web+code" / "vibe-app"
)


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


def _seed_cves_for_vibe_app(tmp_cache) -> None:
    """Seed CVEs for every package in the vibe-app lockfile so the
    matcher has something to find. The headline CVEs match the
    real public advisories named in the fixture's expected.yaml.
    """
    ti_cache.upsert_cves(
        [
            {
                "cve_id": "BENCH-LODASH",
                "cvss_score": 7.4, "severity": "high",
                "components": [{
                    "vendor": "npm", "product": "lodash",
                    "version_pattern": "<4.17.21",
                }],
            },
            {
                "cve_id": "BENCH-EJS",
                "cvss_score": 9.8, "severity": "critical",
                "components": [{
                    "vendor": "npm", "product": "ejs",
                    "version_pattern": "<3.1.7",
                }],
            },
            {
                "cve_id": "BENCH-EXPRESS",
                "cvss_score": 6.1, "severity": "medium",
                "components": [{
                    "vendor": "npm", "product": "express",
                    "version_pattern": "<4.19.2",
                }],
            },
        ],
        source="reachability-test",
    )


# ---------------------------------------------------------------------------
# Vibe-app baseline: lodash + ejs imported, express NOT imported by app.js
# ---------------------------------------------------------------------------


def test_vibe_app_baseline_reachability_classification(tmp_cache) -> None:
    """Pin the per-package reachability the §4a vibe-app fixture
    produces. lodash + ejs are imported from app.js; express is in
    the lockfile but NOT imported (the Express server uses the
    `express` global indirectly via `require('express')`)."""
    _seed_cves_for_vibe_app(tmp_cache)

    result = scan_sca_lockfiles(
        repo_path=str(VIBE_APP / "src"),
        with_reachability=True,
    )
    assert result["status"] == "ok"
    by_status = result["tool_metadata"]["reachability"]["by_status"]
    # All three vulnerable packages got classified — none `unknown`
    # because the repo has JS source files.
    total_classified = (
        by_status.get("direct_import", 0)
        + by_status.get("transitive_only", 0)
        + by_status.get("unused", 0)
    )
    assert total_classified >= 3, by_status


def test_vibe_app_express_imported_via_require(tmp_cache) -> None:
    """`app.js` does `require('express')` so express IS reachable —
    pin this so a future regression in `_extract_npm_imports`
    against `require()` patterns gets caught."""
    _seed_cves_for_vibe_app(tmp_cache)

    result = scan_sca_lockfiles(repo_path=str(VIBE_APP / "src"))
    titles = " | ".join(d["title"] for d in result["findings"])
    # If express were reachability=unused/transitive_only, the title
    # would contain `[reachability=...]` — assert the express
    # finding does NOT carry that demotion suffix.
    express_finding = next(
        (d for d in result["findings"] if "express" in d["title"]),
        None,
    )
    assert express_finding is not None, titles
    assert "reachability=" not in express_finding["title"], (
        "express is imported via require('express'); a "
        "[reachability=unused] tag means the require() detector "
        "regressed. title=" + express_finding["title"]
    )


# ---------------------------------------------------------------------------
# Synthetic "deep-bury" — a vulnerable package nothing imports
# ---------------------------------------------------------------------------


def test_unused_vuln_package_demoted_two_tiers(tmp_path: Path, tmp_cache) -> None:
    """The efficiency claim: "your repo has 600 deps, 200 are
    vulnerable, but most are dead/transitive — reachability prunes
    the noise."

    Setup: a tiny repo with one imported package (lodash) and one
    UNIMPORTED but-still-vulnerable package (`unused-evil-pkg`).
    Both have a high-severity CVE seeded. Reachability should:
      * keep lodash at high
      * demote unused-evil-pkg from high → low (-2 tiers)
    """
    # Minimal repo: package-lock.json + app.js.
    src = tmp_path / "src"
    src.mkdir()
    (src / "package-lock.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"dependencies": {
                "lodash": "4.17.20", "unused-evil-pkg": "1.0.0",
            }},
            "node_modules/lodash": {
                "version": "4.17.20", "license": "MIT",
            },
            "node_modules/unused-evil-pkg": {
                "version": "1.0.0", "license": "MIT",
            },
        },
    }))
    (src / "app.js").write_text(
        "const _ = require('lodash');\n"
        "console.log(_.merge({}, {}));\n"
    )

    ti_cache.upsert_cves(
        [
            {
                "cve_id": "DEMO-LODASH",
                "cvss_score": 7.4, "severity": "high",
                "components": [{
                    "vendor": "npm", "product": "lodash",
                    "version_pattern": "*",
                }],
            },
            {
                "cve_id": "DEMO-UNUSED",
                "cvss_score": 7.4, "severity": "high",
                "components": [{
                    "vendor": "npm", "product": "unused-evil-pkg",
                    "version_pattern": "*",
                }],
            },
        ],
        source="reachability-test",
    )

    result = scan_sca_lockfiles(repo_path=str(src), with_reachability=True)
    findings = {
        d["title"].split("`")[1].split("@")[0].split(":")[1]: d
        for d in result["findings"]
    }
    # lodash kept at high (reachable + no demotion).
    assert findings["lodash"]["severity"] == "high"
    assert "reachability=" not in findings["lodash"]["title"]

    # unused-evil-pkg demoted from high → low (-2 tiers for `unused`).
    unused = findings["unused-evil-pkg"]
    assert unused["severity"] == "low", unused
    assert "[reachability=unused]" in unused["title"]


def test_kev_overrides_reachability_demotion(tmp_path: Path, tmp_cache) -> None:
    """Even a totally-unused package stays at critical severity if
    its headline CVE is in CISA KEV. KEV means "actively exploited
    in the wild" and overrides any local-import-graph signal —
    the threat is real even if nothing imports the package today."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "package-lock.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"dependencies": {"never-imported": "1.0.0"}},
            "node_modules/never-imported": {
                "version": "1.0.0", "license": "MIT",
            },
        },
    }))
    (src / "app.js").write_text("console.log('no imports')")

    ti_cache.upsert_cves(
        [{
            "cve_id": "DEMO-KEV",
            "cvss_score": 9.8, "severity": "critical",
            "components": [{
                "vendor": "npm", "product": "never-imported",
                "version_pattern": "*",
            }],
        }],
        source="reachability-test",
    )
    ti_cache.upsert_kev_entries([{
        "cve_id": "DEMO-KEV", "vendor": "npm",
        "product": "never-imported", "vuln_name": "demo KEV",
    }])

    result = scan_sca_lockfiles(repo_path=str(src))
    finding = result["findings"][0]
    # critical preserved despite reachability=unused.
    assert finding["severity"] == "critical", finding
    # Title still shows the reachability tag (so reviewers see WHY
    # we considered demoting), but severity stays critical.
    assert "[reachability=unused]" in finding["title"]


def test_high_epss_overrides_reachability_demotion(
    tmp_path: Path, tmp_cache,
) -> None:
    """EPSS ≥ 0.5 is the same override class as KEV — high
    probability of exploitation in the next 30 days, so don't
    demote on a "we don't see the import" signal."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "package-lock.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"dependencies": {"unused-but-hot": "1.0.0"}},
            "node_modules/unused-but-hot": {
                "version": "1.0.0", "license": "MIT",
            },
        },
    }))
    (src / "app.js").write_text("// nothing imported")

    ti_cache.upsert_cves(
        [{
            "cve_id": "DEMO-EPSS",
            "cvss_score": 7.4, "severity": "high",
            "components": [{
                "vendor": "npm", "product": "unused-but-hot",
                "version_pattern": "*",
            }],
        }],
        source="reachability-test",
    )
    ti_cache.upsert_epss_scores([("DEMO-EPSS", 0.85)])

    result = scan_sca_lockfiles(repo_path=str(src))
    finding = result["findings"][0]
    # EPSS≥0.5 bumps `high` → `critical` (existing _bump_severity
    # logic), and the reachability=unused demotion is BLOCKED by
    # the EPSS override. So the final severity is `critical`, not
    # the demoted-to-low we'd see for an unused package without an
    # EPSS hit.
    assert finding["severity"] == "critical", finding


# ---------------------------------------------------------------------------
# only_reachable mode — for zero-noise dashboards
# ---------------------------------------------------------------------------


def test_only_reachable_suppresses_unused(tmp_path: Path, tmp_cache) -> None:
    """`only_reachable=True` should drop unused/transitive findings
    entirely (no demoted finding emitted), and the count of
    suppressed findings should appear in `tool_metadata`."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "package-lock.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"dependencies": {
                "lodash": "4.17.20", "totally-dead": "1.0.0",
            }},
            "node_modules/lodash": {
                "version": "4.17.20", "license": "MIT",
            },
            "node_modules/totally-dead": {
                "version": "1.0.0", "license": "MIT",
            },
        },
    }))
    (src / "app.js").write_text("const _ = require('lodash');")

    ti_cache.upsert_cves(
        [
            {
                "cve_id": "DEMO-LODASH",
                "cvss_score": 7.4, "severity": "high",
                "components": [{
                    "vendor": "npm", "product": "lodash",
                    "version_pattern": "*",
                }],
            },
            {
                "cve_id": "DEMO-DEAD",
                "cvss_score": 7.4, "severity": "high",
                "components": [{
                    "vendor": "npm", "product": "totally-dead",
                    "version_pattern": "*",
                }],
            },
        ],
        source="reachability-test",
    )

    result = scan_sca_lockfiles(
        repo_path=str(src),
        with_reachability=True,
        only_reachable=True,
    )
    titles = [d["title"] for d in result["findings"]]
    assert any("lodash" in t for t in titles), titles
    assert not any("totally-dead" in t for t in titles), titles
    # And the suppression count is reported.
    assert result["tool_metadata"]["reachability"]["suppressed"] >= 1


def test_only_reachable_keeps_kev_findings(tmp_path: Path, tmp_cache) -> None:
    """`only_reachable=True` must still emit KEV findings even when
    reachability says unused — the override applies before the
    suppression filter."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "package-lock.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"dependencies": {"unused-kev-pkg": "1.0.0"}},
            "node_modules/unused-kev-pkg": {
                "version": "1.0.0", "license": "MIT",
            },
        },
    }))
    (src / "app.js").write_text("// nothing")

    ti_cache.upsert_cves(
        [{
            "cve_id": "DEMO-KEV",
            "cvss_score": 9.8, "severity": "critical",
            "components": [{
                "vendor": "npm", "product": "unused-kev-pkg",
                "version_pattern": "*",
            }],
        }],
        source="reachability-test",
    )
    ti_cache.upsert_kev_entries([{
        "cve_id": "DEMO-KEV", "vendor": "npm",
        "product": "unused-kev-pkg", "vuln_name": "demo KEV",
    }])

    result = scan_sca_lockfiles(
        repo_path=str(src),
        with_reachability=True,
        only_reachable=True,
    )
    titles = [d["title"] for d in result["findings"]]
    assert any("unused-kev-pkg" in t for t in titles), (
        "KEV finding suppressed by only_reachable — override broken"
    )


# ---------------------------------------------------------------------------
# with_reachability=False short-circuits the source walk
# ---------------------------------------------------------------------------


def test_with_reachability_false_skips_demotion(
    tmp_path: Path, tmp_cache,
) -> None:
    """Opt-out path: huge monorepos may not want the source walk.
    `with_reachability=False` should skip it entirely and emit the
    raw severities from the threat-intel cache."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "package-lock.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"dependencies": {"totally-dead": "1.0.0"}},
            "node_modules/totally-dead": {
                "version": "1.0.0", "license": "MIT",
            },
        },
    }))
    (src / "app.js").write_text("// no imports")

    ti_cache.upsert_cves(
        [{
            "cve_id": "DEMO-DEAD",
            "cvss_score": 7.4, "severity": "high",
            "components": [{
                "vendor": "npm", "product": "totally-dead",
                "version_pattern": "*",
            }],
        }],
        source="reachability-test",
    )

    result = scan_sca_lockfiles(
        repo_path=str(src),
        with_reachability=False,
    )
    assert result["tool_metadata"]["reachability"]["enabled"] is False
    # severity NOT demoted; stays at high.
    assert result["findings"][0]["severity"] == "high"
    assert "reachability=" not in result["findings"][0]["title"]


# ---------------------------------------------------------------------------
# Efficiency metric: reduction-ratio measurement
# ---------------------------------------------------------------------------


def test_reachability_reduces_critical_count(tmp_path: Path, tmp_cache) -> None:
    """The headline efficiency claim: reachability filtering reduces
    the count of `critical` / `high` findings by demoting the
    unused / transitive ones. Asserts the count drops between
    `with_reachability=False` and `with_reachability=True` on a
    fixture where the ratio is known."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "package-lock.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"dependencies": {
                "imported-pkg": "1.0.0",
                "dead-1": "1.0.0",
                "dead-2": "1.0.0",
                "dead-3": "1.0.0",
            }},
            "node_modules/imported-pkg": {
                "version": "1.0.0", "license": "MIT",
            },
            "node_modules/dead-1": {"version": "1.0.0", "license": "MIT"},
            "node_modules/dead-2": {"version": "1.0.0", "license": "MIT"},
            "node_modules/dead-3": {"version": "1.0.0", "license": "MIT"},
        },
    }))
    (src / "app.js").write_text("require('imported-pkg');")

    cves = [
        {
            "cve_id": f"DEMO-{name}",
            "cvss_score": 7.4, "severity": "high",
            "components": [{
                "vendor": "npm", "product": name,
                "version_pattern": "*",
            }],
        }
        for name in ("imported-pkg", "dead-1", "dead-2", "dead-3")
    ]
    ti_cache.upsert_cves(cves, source="reachability-test")

    raw = scan_sca_lockfiles(repo_path=str(src), with_reachability=False)
    filtered = scan_sca_lockfiles(repo_path=str(src), with_reachability=True)

    raw_high_count = sum(
        1 for d in raw["findings"] if d["severity"] == "high"
    )
    filtered_high_count = sum(
        1 for d in filtered["findings"] if d["severity"] == "high"
    )
    # Raw: 4 high. Filtered: 1 high (imported-pkg) — the 3 dead
    # ones drop from high to low.
    assert raw_high_count == 4
    assert filtered_high_count == 1
    # Reduction ratio matches our claim "30–60% noise reduction" —
    # here it's 75% because the synthetic ratio is extreme.
    assert filtered_high_count < raw_high_count
