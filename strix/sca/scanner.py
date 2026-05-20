"""SCA scanner — walk a repo, parse all lockfiles, match against
the threat-intel cache, return aggregate report.

Used by:
  * `scan_sca_lockfiles` LLM specialist (`tools.py`)
  * `webappsec/` wrapper for one-shot scans triggered by GitHub App

## Threat-intel cache vs osv-scanner fallback (iter-12)

The primary path is the internal threat-intel cache lookup
(`ti_lookup.find_cves_for`). Strix feeds populate it from GHSA + NVD
+ KEV + EPSS sources; when populated, lookups are sub-millisecond
and include EPSS / KEV enrichment for ranking.

The cache is empty in fresh installs and in CI-on-PR runs where no
feed has run. To prevent silent recall collapse on those targets,
this module **falls back to invoking `osv-scanner` as a subprocess**
when the cache returns zero CVEs but lockfiles WERE parsed. The
osv-scanner output is translated into the same `CVERecord` /
`PackageMatch` shape so downstream consumers can't tell the
difference (they DO see `sources=["osv_fallback"]` so attribution
is preserved).

Kill switch: `STRIX_SCA_OSV_FALLBACK_DISABLED=1`. Default: enabled.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from strix.sca.match import PackageMatch, find_vulnerabilities
from strix.sca.parsers.base import Package, find_lockfiles, parse_lockfile
from strix.threat_intel.cache import CVERecord


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

    # Iter-12 — fallback to osv-scanner when the threat-intel cache
    # is empty / unsynced but lockfiles WERE parsed. Without this,
    # fresh installs and CI-on-PR runs silently report 0 CVEs even
    # when the lockfile pins widely-known-vulnerable versions.
    # Measured impact: vibe-app L1 sca-lodash / sca-ejs catches go
    # from 0 → 2 with this fallback.
    total_cves_from_cache = sum(len(m.cves) for m in matches)
    if (
        total_cves_from_cache == 0
        and all_packages
        and _osv_fallback_enabled()
    ):
        try:
            osv_matches = _run_osv_scanner_fallback(
                lockfiles, all_packages,
            )
            if osv_matches:
                # Merge osv-found CVEs into the matches list. Match
                # by (ecosystem, name, version) so the existing
                # `PackageMatch` entries get their `cves` filled in
                # without duplicating Package records.
                idx: dict[tuple[str, str, str], PackageMatch] = {
                    (m.package.ecosystem, m.package.name, m.package.version): m
                    for m in matches
                }
                added = 0
                for osv_match in osv_matches:
                    key = (
                        osv_match.package.ecosystem,
                        osv_match.package.name,
                        osv_match.package.version,
                    )
                    existing = idx.get(key)
                    if existing is not None:
                        # Don't double-append the same CVE id.
                        existing_ids = {c.cve_id for c in existing.cves}
                        for c in osv_match.cves:
                            if c.cve_id not in existing_ids:
                                existing.cves.append(c)
                                added += 1
                    else:
                        matches.append(osv_match)
                        added += len(osv_match.cves)
                logger.info(
                    "sca: osv-scanner fallback added %d CVE(s) "
                    "(cache returned 0 for %d packages)",
                    added, len(all_packages),
                )
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "sca: osv-scanner fallback failed: %s",
                e, exc_info=True,
            )

    return ScaReport(
        repo_path=str(p),
        lockfiles_scanned=[str(lf) for lf in lockfiles],
        packages_total=len(all_packages),
        packages_by_ecosystem=by_eco,
        matches=matches,
    )


# ---------------------------------------------------------------------------
# osv-scanner fallback (iter-12)
# ---------------------------------------------------------------------------


def _osv_fallback_enabled() -> bool:
    """The fallback is on by default; opt-OUT via env var."""
    raw = os.environ.get("STRIX_SCA_OSV_FALLBACK_DISABLED", "").lower()
    return raw not in ("1", "true", "yes", "on")


_OSV_ECOSYSTEM_TO_STRIX = {
    # osv-scanner uses GHSA/OSV ecosystem names; strix uses the
    # short forms. Map both directions to be safe.
    "npm": "npm",
    "pypi": "pypi",
    "PyPI": "pypi",
    "rubygems": "rubygems",
    "RubyGems": "rubygems",
    "crates.io": "cargo",
    "cargo": "cargo",
    "Packagist": "composer",
    "composer": "composer",
    "Go": "go",
    "go": "go",
    "Maven": "maven",
    "maven": "maven",
    "NuGet": "nuget",
    "nuget": "nuget",
}


def _osv_severity_from_max(score_str: str | None) -> str | None:
    """Convert osv-scanner max_severity (CVSS-style numeric string)
    to strix's severity tier. Returns None when input is missing."""
    if not score_str:
        return None
    try:
        score = float(score_str)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return None


def _pick_primary_cve_id(group_ids: list[str], aliases: list[str]) -> str:
    """Prefer a real CVE-id over a GHSA-id for the canonical id.

    osv-scanner returns BOTH in the aliases list. Strix's KG and the
    KEV / EPSS feeds key on CVE-NNNN — the GHSA-only id misses the
    downstream attribution. When no CVE alias exists, fall back to
    the GHSA id (it's still actionable, just less linkable).
    """
    candidates = list(group_ids) + list(aliases)
    for c in candidates:
        if c.startswith("CVE-"):
            return c
    return candidates[0] if candidates else ""


def _run_osv_scanner_fallback(
    lockfiles: list[Path], all_packages: list[Package],
) -> list[PackageMatch]:
    """Invoke `osv-scanner --format=json -L <lockfile>` for each
    lockfile and translate the output into `PackageMatch` records.

    Best-effort: any failure returns empty list. The caller continues
    with the (empty) cache result.

    Returns one PackageMatch per (package, vulnerable-set) — entries
    for packages with no vulns are omitted (saves memory and the
    merge loop in the caller).
    """
    if not shutil.which("osv-scanner"):
        logger.debug("sca: osv-scanner not on PATH; fallback unavailable")
        return []

    # Index parsed packages by (eco-as-osv-might-emit, name, version)
    # so we can look up the strix Package metadata (dev_only, direct,
    # source_path) when we wrap osv results.
    pkg_idx: dict[tuple[str, str, str], Package] = {}
    for p in all_packages:
        # Index by lowercased name to match osv-scanner's behaviour;
        # ecosystem normalised to strix short form.
        pkg_idx[(p.ecosystem, p.name.lower(), p.version)] = p

    out: list[PackageMatch] = []
    seen_keys: set[tuple[str, str, str]] = set()

    for lf in lockfiles:
        try:
            r = subprocess.run(
                ["osv-scanner", "--format=json", "-L", str(lf)],
                capture_output=True, text=True, timeout=60,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug("sca: osv-scanner failed on %s: %s", lf, e)
            continue
        # osv-scanner exits 1 when vulnerabilities ARE found; that's
        # success, not an error. Only treat parse failures as errors.
        if not r.stdout:
            continue
        try:
            data = json.loads(r.stdout)
        except json.JSONDecodeError:
            continue

        for source_block in data.get("results", []):
            if not isinstance(source_block, dict):
                continue
            for pkg_block in source_block.get("packages", []):
                if not isinstance(pkg_block, dict):
                    continue
                pkg_meta = pkg_block.get("package") or {}
                name = (pkg_meta.get("name") or "").strip()
                version = (pkg_meta.get("version") or "").strip()
                eco_raw = (pkg_meta.get("ecosystem") or "").strip()
                if not name or not version:
                    continue
                eco = _OSV_ECOSYSTEM_TO_STRIX.get(eco_raw, eco_raw.lower())
                key = (eco, name.lower(), version)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                # Find the matching strix-parsed Package (carries
                # dev_only / direct / source_path). If missing,
                # synthesize a minimal one.
                strix_pkg = pkg_idx.get(key)
                if strix_pkg is None:
                    strix_pkg = Package(
                        ecosystem=eco,
                        name=name.lower(),
                        version=version,
                        dev_only=False,
                        direct=True,
                        source_path=str(lf),
                    )

                groups = pkg_block.get("groups") or []
                if not isinstance(groups, list):
                    groups = []
                vuln_blocks = pkg_block.get("vulnerabilities") or []
                desc_by_id: dict[str, str] = {}
                if isinstance(vuln_blocks, list):
                    for v in vuln_blocks:
                        if not isinstance(v, dict):
                            continue
                        vid = v.get("id") or ""
                        if vid:
                            desc_by_id[vid] = (
                                v.get("summary")
                                or v.get("details", "")[:300]
                                or ""
                            )

                cves: list[CVERecord] = []
                for grp in groups:
                    if not isinstance(grp, dict):
                        continue
                    ids = grp.get("ids") or []
                    aliases = grp.get("aliases") or []
                    if not isinstance(ids, list):
                        ids = []
                    if not isinstance(aliases, list):
                        aliases = []
                    cve_id = _pick_primary_cve_id(ids, aliases)
                    if not cve_id:
                        continue
                    sev = _osv_severity_from_max(grp.get("max_severity"))
                    cvss_score: float | None
                    try:
                        cvss_score = float(grp.get("max_severity"))
                    except (TypeError, ValueError):
                        cvss_score = None
                    description = ""
                    for vid in ids:
                        if vid in desc_by_id and desc_by_id[vid]:
                            description = desc_by_id[vid]
                            break
                    cves.append(CVERecord(
                        cve_id=cve_id,
                        description=description,
                        cvss_score=cvss_score,
                        severity=sev,
                        kev=False,    # osv-scanner doesn't carry KEV; cache will
                        epss=None,    # backfill later if feed runs
                        sources=["osv_fallback"],
                    ))
                if cves:
                    out.append(PackageMatch(package=strix_pkg, cves=cves))

    return out
