"""Vulnerability matching pipeline.

Takes a list of `Package` records and queries the threat-intel
cache (PR #217) for matching CVEs. Returns one entry per package
with the (possibly empty) list of CVEs that affect it.

The threat-intel cache stores `cve_components(vendor, product,
version_pattern)` — for SCA we use:
  vendor   = ecosystem (npm / pypi / cargo / rubygems / composer / go)
  product  = package name (lowercased)
  version_pattern = exact version OR comma-separated range

This matches the GHSA feed's writes (PR-this-PR's `feeds/ghsa.py`)
and the NVD writes' CPE fallback.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable

from strix.sca.parsers.base import Package
from strix.threat_intel import lookup as ti_lookup
from strix.threat_intel.cache import CVERecord


logger = logging.getLogger(__name__)


@dataclass
class PackageMatch:
    """Result of matching one Package against the threat-intel cache."""
    package: Package
    cves: list[CVERecord] = field(default_factory=list)

    @property
    def severity_max(self) -> str:
        """Max severity across the CVE list (info if empty)."""
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sevs = [(c.severity or "").lower() for c in self.cves]
        sevs = [s for s in sevs if s in order]
        if not sevs:
            return "info"
        return max(sevs, key=lambda s: order[s])

    @property
    def has_kev(self) -> bool:
        return any(c.kev for c in self.cves)

    @property
    def max_epss(self) -> float:
        return max((c.epss or 0.0) for c in self.cves) if self.cves else 0.0


def find_vulnerabilities(
    packages: Iterable[Package], *,
    only_kev: bool = False,
    min_epss: float = 0.0,
    skip_dev_only: bool = True,
    max_per_package: int = 50,
) -> list[PackageMatch]:
    """For each package, query the cache for matching CVEs.

    Args:
        packages: list of Package records to check.
        only_kev: filter to actively-exploited (CISA KEV) CVEs.
        min_epss: filter to EPSS probability >= this.
        skip_dev_only: skip dev-only deps. Defaults True since
            production runtime exposure is the main concern.
        max_per_package: cap CVEs per package to bound output size.

    Returns:
        list of `PackageMatch` (one per input Package, including
        packages with no matching CVEs — caller can filter).
    """
    out: list[PackageMatch] = []
    for pkg in packages:
        if skip_dev_only and pkg.dev_only:
            out.append(PackageMatch(package=pkg, cves=[]))
            continue
        try:
            cves = ti_lookup.find_cves_for(
                component=pkg.name,
                version=pkg.version,
                vendor=pkg.ecosystem,
                only_kev=only_kev,
                min_epss=min_epss,
                limit=max_per_package,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "sca match: lookup failed for %s: %s",
                pkg.display_name, e,
            )
            cves = []
        out.append(PackageMatch(package=pkg, cves=cves))
    return out
