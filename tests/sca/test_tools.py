"""Tests for the LLM-facing `scan_sca_lockfiles` specialist.

The `@register_specialist_tool` wrapper coerces the return value to
a `SpecialistResult.model_dump()` dict — these tests treat the
result as a plain dict accordingly.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from strix.sca.tools import scan_sca_lockfiles
from strix.threat_intel import cache as ti_cache


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


def _seed_lodash_kev(tmp_cache) -> None:
    ti_cache.upsert_cves([
        {
            "cve_id": "CVE-2024-LODASH",
            "cvss_score": 9.8,
            "severity": "critical",
            "components": [{
                "vendor": "npm", "product": "lodash",
                "version_pattern": "<4.17.21",
            }],
        },
    ], source="test")
    ti_cache.upsert_kev_entries([
        {"cve_id": "CVE-2024-LODASH", "vendor": "npm",
         "product": "lodash", "vuln_name": "Lodash proto pollution"},
    ])
    ti_cache.upsert_epss_scores([("CVE-2024-LODASH", 0.92)])


def _populate_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copy(FIXTURES / "package-lock.json",
                repo / "package-lock.json")
    return repo


def test_returns_error_for_missing_repo_path() -> None:
    result = scan_sca_lockfiles(repo_path="")
    assert result["status"] == "error"
    assert "repo_path" in (result.get("error") or "")


def test_returns_partial_when_no_lockfiles(tmp_cache, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    result = scan_sca_lockfiles(repo_path=str(empty))
    assert result["status"] == "partial"
    assert "no lockfiles found" in (result.get("error") or "")


def test_emits_finding_for_kev_dependency(tmp_cache, tmp_path: Path) -> None:
    _seed_lodash_kev(tmp_cache)
    repo = _populate_repo(tmp_path)
    result = scan_sca_lockfiles(repo_path=str(repo))
    assert result["status"] == "ok"
    titles = [d["title"] for d in result["findings"]]
    assert any("lodash" in t for t in titles)
    sevs = {d["severity"] for d in result["findings"] if "lodash" in d["title"]}
    assert "critical" in sevs


def test_only_kev_filter_narrows_findings(tmp_cache, tmp_path: Path) -> None:
    """A non-KEV CVE for express should not appear when only_kev=True."""
    ti_cache.upsert_cves([
        {
            "cve_id": "CVE-2024-EXPRESS",
            "cvss_score": 5.5,
            "severity": "medium",
            "components": [{
                "vendor": "npm", "product": "express",
                "version_pattern": "*",
            }],
        },
    ], source="test")
    _seed_lodash_kev(tmp_cache)
    repo = _populate_repo(tmp_path)

    full = scan_sca_lockfiles(repo_path=str(repo))
    titles = [d["title"] for d in full["findings"]]
    assert any("lodash" in t for t in titles)
    assert any("express" in t for t in titles)

    kev_only = scan_sca_lockfiles(repo_path=str(repo), only_kev=True)
    titles = [d["title"] for d in kev_only["findings"]]
    assert any("lodash" in t for t in titles)
    assert not any("express" in t for t in titles)


def test_tool_metadata_populated(tmp_cache, tmp_path: Path) -> None:
    _seed_lodash_kev(tmp_cache)
    repo = _populate_repo(tmp_path)
    result = scan_sca_lockfiles(repo_path=str(repo))
    md = result.get("tool_metadata") or {}
    assert md.get("packages_total", 0) > 0
    assert "npm" in md.get("packages_by_ecosystem", {})
    assert md.get("kev_count", 0) >= 1


def test_no_vulnerabilities_returns_ok(tmp_cache, tmp_path: Path) -> None:
    """Empty cache → no findings, but still status ok with a hint
    about cache freshness."""
    repo = _populate_repo(tmp_path)
    result = scan_sca_lockfiles(repo_path=str(repo))
    assert result["status"] == "ok"
    assert result["findings"] == []
    # Suggested next probe should mention cache freshness.
    nps = result.get("next_probes_suggested") or []
    assert any("cache" in s.lower() for s in nps)
