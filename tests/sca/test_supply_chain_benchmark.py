"""End-to-end test for the `sca-supply-chain/` benchmark fixture
(Phase 6.6 + 6.7).

Pins the planted ratio for the supply-chain benchmark — the
fixture should produce a known set of malicious + license
findings without requiring any threat-intel feed (heuristics are
local).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.sca.tools import scan_sca_lockfiles
from strix.threat_intel import cache as ti_cache


FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "benchmarks" / "per_target" / "fixtures"
    / "code" / "sca-supply-chain"
)


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    """Empty cache — these heuristics don't depend on threat intel."""
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


def test_fixture_files_exist() -> None:
    assert FIXTURE.exists()
    assert (FIXTURE / "expected.yaml").exists()
    assert (FIXTURE / "src" / "package-lock.json").exists()


def test_planted_typosquat_surfaces(tmp_cache) -> None:
    """`lodahs` (typo of `lodash`, distance 2) → malicious_dependency
    finding tagged with the typosquat indicator."""
    result = scan_sca_lockfiles(repo_path=str(FIXTURE / "src"))
    findings = [d for d in result["findings"]
                if d["category"] == "malicious_dependency"]
    typosquat_titles = [f["title"] for f in findings if "typosquat" in f["title"]]
    assert any("lodahs" in t for t in typosquat_titles), typosquat_titles


def test_planted_install_script_surfaces(tmp_cache) -> None:
    """`sharp@0.32.0` is a direct dep with hasInstallScript=True →
    medium-severity install_script finding."""
    result = scan_sca_lockfiles(repo_path=str(FIXTURE / "src"))
    findings = [
        d for d in result["findings"]
        if d["category"] == "malicious_dependency"
        and "install_script" in d["title"]
    ]
    assert len(findings) >= 1
    sharp_finding = next((f for f in findings if "sharp" in f["title"]), None)
    assert sharp_finding is not None
    assert sharp_finding["severity"] == "medium"  # direct dep


def test_planted_agpl_emits_high_severity(tmp_cache) -> None:
    result = scan_sca_lockfiles(repo_path=str(FIXTURE / "src"))
    findings = [d for d in result["findings"]
                if d["category"] == "license_violation"]
    agpl = next((f for f in findings if "agpl-utility" in f["title"].lower()),
                None)
    assert agpl is not None, [f["title"] for f in findings]
    assert agpl["severity"] == "high"


def test_planted_busl_emits_high_severity(tmp_cache) -> None:
    result = scan_sca_lockfiles(repo_path=str(FIXTURE / "src"))
    findings = [d for d in result["findings"]
                if d["category"] == "license_violation"]
    busl = next((f for f in findings if "busl-cache" in f["title"].lower()),
                None)
    assert busl is not None
    assert busl["severity"] == "high"


def test_planted_no_license_emits_medium(tmp_cache) -> None:
    result = scan_sca_lockfiles(repo_path=str(FIXTURE / "src"))
    findings = [d for d in result["findings"]
                if d["category"] == "license_violation"]
    nolic = next((f for f in findings if "no-license-pkg" in f["title"].lower()),
                 None)
    assert nolic is not None
    assert nolic["severity"] == "medium"


def test_license_inventory_in_metadata(tmp_cache) -> None:
    """All 8 packages in the lockfile must be classified into a
    family, even those that don't violate policy."""
    result = scan_sca_lockfiles(repo_path=str(FIXTURE / "src"))
    by_family = result["tool_metadata"]["licenses"]["by_family"]
    # Permissive: lodash, express, lodahs, reqests, sharp = 5 (sharp=Apache-2.0).
    # Copyleft: agpl-utility = 1.
    # Commercial: busl-cache = 1.
    # Unknown: no-license-pkg = 1.
    assert by_family["permissive"] == 5, by_family
    assert by_family["copyleft"] == 1
    assert by_family["commercial_restricted"] == 1
    assert by_family["unknown"] == 1


def test_malicious_indicator_rollup(tmp_cache) -> None:
    """`tool_metadata.malicious.by_indicator` reports at least 1
    typosquat + 1 install_script + 1 no_license (no-license-pkg
    triggers BOTH license_violation AND no_license malicious
    indicator — they complement each other)."""
    result = scan_sca_lockfiles(repo_path=str(FIXTURE / "src"))
    by_ind = result["tool_metadata"]["malicious"]["by_indicator"]
    assert by_ind["typosquat"] >= 1, by_ind
    assert by_ind["install_script"] >= 1
    # `no-license-pkg` triggers the no_license malicious indicator
    # (low severity) AND the license_violation finding (medium
    # severity, "unknown" family). The duplicate is intentional —
    # different signal classes routed through different categories.
    assert by_ind["no_license"] >= 1
