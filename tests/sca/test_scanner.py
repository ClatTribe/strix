"""Tests for `strix.sca.scanner.scan_repo_lockfiles`."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from strix.sca.scanner import ScaReport, scan_repo_lockfiles
from strix.threat_intel import cache as ti_cache


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


def _seed(tmp_cache) -> None:
    """Lodash@4.17.20 → 1 KEV CVE; nothing else matches."""
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
        {
            "cve_id": "CVE-2024-DJANGO",
            "cvss_score": 7.5,
            "severity": "high",
            "components": [{
                "vendor": "pypi", "product": "django",
                "version_pattern": "<4.2.7",
            }],
        },
    ], source="test")
    ti_cache.upsert_kev_entries([
        {"cve_id": "CVE-2024-LODASH", "vendor": "npm",
         "product": "lodash", "vuln_name": "Lodash proto pollution"},
    ])


def _populate_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copy(FIXTURES / "package-lock.json",
                repo / "package-lock.json")
    py = repo / "py"
    py.mkdir()
    shutil.copy(FIXTURES / "Pipfile.lock", py / "Pipfile.lock")
    return repo


def test_scan_repo_returns_report(tmp_cache, tmp_path: Path) -> None:
    _seed(tmp_cache)
    repo = _populate_repo(tmp_path)
    report = scan_repo_lockfiles(repo)
    assert isinstance(report, ScaReport)
    assert report.error is None
    # Two lockfiles found.
    assert len(report.lockfiles_scanned) == 2
    # Mix of npm + pypi packages.
    assert "npm" in report.packages_by_ecosystem
    assert "pypi" in report.packages_by_ecosystem


def test_scan_repo_finds_vulnerable_packages(tmp_cache, tmp_path: Path) -> None:
    _seed(tmp_cache)
    repo = _populate_repo(tmp_path)
    report = scan_repo_lockfiles(repo)
    vuln_names = {m.package.name for m in report.vulnerable_packages}
    assert "lodash" in vuln_names
    assert "django" in vuln_names


def test_scan_repo_kev_count_and_critical(tmp_cache, tmp_path: Path) -> None:
    _seed(tmp_cache)
    repo = _populate_repo(tmp_path)
    report = scan_repo_lockfiles(repo)
    # Lodash KEV → 1 KEV, 1 critical.
    assert report.kev_count >= 1
    assert report.critical_count >= 1


def test_scan_repo_only_kev_narrows_results(tmp_cache, tmp_path: Path) -> None:
    _seed(tmp_cache)
    repo = _populate_repo(tmp_path)
    report = scan_repo_lockfiles(repo, only_kev=True)
    # Only lodash has KEV.
    vuln_names = {m.package.name for m in report.vulnerable_packages}
    assert vuln_names == {"lodash"}


def test_scan_repo_missing_directory(tmp_path: Path) -> None:
    report = scan_repo_lockfiles(tmp_path / "does-not-exist")
    assert report.error is not None
    assert "not a directory" in report.error


def test_scan_repo_empty_directory(tmp_cache, tmp_path: Path) -> None:
    _seed(tmp_cache)
    empty = tmp_path / "empty"
    empty.mkdir()
    report = scan_repo_lockfiles(empty)
    assert report.error is None
    assert report.lockfiles_scanned == []
    assert report.packages_total == 0


def test_scan_report_to_dict_shape(tmp_cache, tmp_path: Path) -> None:
    _seed(tmp_cache)
    repo = _populate_repo(tmp_path)
    report = scan_repo_lockfiles(repo)
    d = report.to_dict()
    assert "lockfiles_scanned" in d
    assert "packages_by_ecosystem" in d
    assert "matches" in d
    # Round-trips through JSON cleanly (output is meant to be serialised).
    json.dumps(d)
