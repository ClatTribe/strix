"""SCA scanner — walk a repo, parse all lockfiles, match against
the threat-intel cache, return aggregate report.

Used by:
  * `scan_sca_lockfiles` LLM specialist (`tools.py`)
  * `webappsec/` wrapper for one-shot scans triggered by GitHub App
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from strix.sca.match import PackageMatch, find_vulnerabilities
from strix.sca.parsers.base import Package, find_lockfiles, parse_lockfile


logger = logging.getLogger(__name__)


@dataclass
class ScaReport:
    """Aggregate SCA scan report."""
    repo_path: str
    lockfiles_scanned: list[str] = field(default_factory=list)
    packages_total: int = 0
    packages_by_ecosystem: dict[str, int] = field(default_factory=dict)
    matches: list[PackageMatch] = field(default_factory=list)
    error: str | None = None

    @property
    def vulnerable_packages(self) -> list[PackageMatch]:
        """Subset of matches with at least one CVE."""
        return [m for m in self.matches if m.cves]

    @property
    def total_cves(self) -> int:
        return sum(len(m.cves) for m in self.matches)

    @property
    def kev_count(self) -> int:
        return sum(
            1 for m in self.matches
            for c in m.cves if c.kev
        )

    @property
    def critical_count(self) -> int:
        return sum(
            1 for m in self.matches
            for c in m.cves
            if (c.severity or "").lower() == "critical"
        )

    def to_dict(self) -> dict:
        return {
            "repo_path": self.repo_path,
            "lockfiles_scanned": list(self.lockfiles_scanned),
            "packages_total": self.packages_total,
            "packages_by_ecosystem": dict(self.packages_by_ecosystem),
            "vulnerable_packages": len(self.vulnerable_packages),
            "total_cves": self.total_cves,
            "kev_count": self.kev_count,
            "critical_count": self.critical_count,
            "matches": [
                {
                    "package": m.package.to_dict(),
                    "cves": [c.to_dict() for c in m.cves],
                    "severity_max": m.severity_max,
                    "has_kev": m.has_kev,
                    "max_epss": m.max_epss,
                }
                for m in self.matches if m.cves  # only output vulnerable matches
            ],
            "error": self.error,
        }


def scan_repo_lockfiles(
    repo_path: str | Path,
    *,
    only_kev: bool = False,
    min_epss: float = 0.0,
    skip_dev_only: bool = True,
    max_lockfiles: int = 50,
) -> ScaReport:
    """Walk `repo_path`, find every lockfile a registered parser
    handles, parse, match against threat-intel cache, return a
    `ScaReport`.

    Args:
        repo_path: directory path to scan.
        only_kev: filter to CISA KEV-listed CVEs.
        min_epss: filter to EPSS probability >= this.
        skip_dev_only: skip dev-only dependencies (default True).
        max_lockfiles: hard cap on lockfile count to bound runtime.

    Returns:
        ScaReport.
    """
    p = Path(repo_path)
    if not p.exists() or not p.is_dir():
        return ScaReport(
            repo_path=str(p),
            error=f"not a directory: {p}",
        )

    try:
        lockfiles = find_lockfiles(p, max_files=max_lockfiles)
    except Exception as e:  # noqa: BLE001
        return ScaReport(repo_path=str(p), error=f"find_lockfiles: {e}")

    all_packages: list[Package] = []
    for lf in lockfiles:
        try:
            pkgs = parse_lockfile(lf)
        except Exception as e:  # noqa: BLE001
            logger.debug("sca: parse failed for %s: %s", lf, e)
            pkgs = []
        all_packages.extend(pkgs)

    by_eco: dict[str, int] = {}
    for pkg in all_packages:
        by_eco[pkg.ecosystem] = by_eco.get(pkg.ecosystem, 0) + 1

    matches = find_vulnerabilities(
        all_packages,
        only_kev=only_kev,
        min_epss=min_epss,
        skip_dev_only=skip_dev_only,
    )

    # Populate the KG `Dependency` node for EVERY parsed package
    # (not just the currently-vulnerable subset). The CVE-relevance
    # evaluator on the feed-trigger queries this — a customer
    # running log4j 2.14.0 today needs to be in the KG even if no
    # CVE exists yet, so a CVE published tomorrow can route to
    # synthesis. Fail-open inside the helper.
    try:
        from strix.agents.kg_emit import record_dependency_in_kg

        # Build a `pkg → matched cves` index so we can attach
        # known-CVE annotations when present.
        cves_by_pkg: dict[tuple[str, str, str], list[str]] = {}
        for m in matches:
            key = (m.package.ecosystem, m.package.name, m.package.version)
            cves_by_pkg.setdefault(key, []).extend(
                c.cve_id for c in m.cves if c.cve_id
            )

        for pkg in all_packages:
            try:
                record_dependency_in_kg(
                    name=pkg.name,
                    version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    source="sca_lockfiles",
                    cve_ids=cves_by_pkg.get(
                        (pkg.ecosystem, pkg.name, pkg.version),
                    ),
                )
            except Exception:  # noqa: BLE001
                logger.debug(
                    "sca: Dependency emit failed for %s", pkg.name,
                    exc_info=True,
                )
    except ImportError:
        pass

    return ScaReport(
        repo_path=str(p),
        lockfiles_scanned=[str(lf) for lf in lockfiles],
        packages_total=len(all_packages),
        packages_by_ecosystem=by_eco,
        matches=matches,
    )
