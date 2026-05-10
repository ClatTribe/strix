"""Query API on top of the threat-intel SQLite cache.

Used by:
  * `strix.threat_intel.tools.lookup_known_cves` — the LLM-facing
    tool surface
  * Existing specialists that want to enrich findings with known-CVE
    data (e.g. `scan_misconfig` — when it fingerprints a tech stack,
    it can call `find_cves_for("apache", "2.4.53")` and bump severity
    when KEV-listed)

Best-effort throughout — missing cache, malformed input, lookup
errors all degrade to empty results.

Public functions are re-exported from `strix.threat_intel.__init__`.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from strix.threat_intel import cache as ti_cache
from strix.threat_intel.cache import CVERecord


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Version matching helpers
# ---------------------------------------------------------------------------


_VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[.-](.+))?$")


def _parse_version(v: str) -> tuple[int, int, int, str]:
    """Parse a version string into a (major, minor, patch, suffix)
    tuple suitable for comparison. Non-conforming versions sort
    last."""
    m = _VERSION_RE.match((v or "").strip())
    if not m:
        return (-1, -1, -1, v or "")
    major = int(m.group(1) or 0)
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    suffix = (m.group(4) or "")
    return (major, minor, patch, suffix)


def _cmp_versions(a: str, b: str) -> int:
    """Return -1, 0, +1 for tuple-comparison of version strings."""
    pa = _parse_version(a)
    pb = _parse_version(b)
    # Prefer numeric tuple; fall back to lexicographic for suffix.
    if pa[:3] < pb[:3]:
        return -1
    if pa[:3] > pb[:3]:
        return 1
    if pa[3] < pb[3]:
        return -1
    if pa[3] > pb[3]:
        return 1
    return 0


def _matches_pattern(version: str, pattern: str) -> bool:
    """Test whether `version` satisfies the comma-separated bound
    list in `pattern`.

    Pattern grammar:
      "*"                 — match anything
      "1.2.3"             — exact match
      ">=1.0,<2.0"        — bounded range
      ">1.5"              — strict greater than
    """
    if not isinstance(version, str) or not version.strip():
        return False
    if pattern in ("", "*", None):
        return True
    pattern = pattern.strip()
    # Exact-match shortcut.
    if pattern and pattern[0] not in "<>=!~":
        return _cmp_versions(version, pattern) == 0
    bounds = [b.strip() for b in pattern.split(",") if b.strip()]
    for b in bounds:
        if b.startswith(">="):
            if _cmp_versions(version, b[2:].strip()) < 0:
                return False
        elif b.startswith(">"):
            if _cmp_versions(version, b[1:].strip()) <= 0:
                return False
        elif b.startswith("<="):
            if _cmp_versions(version, b[2:].strip()) > 0:
                return False
        elif b.startswith("<"):
            if _cmp_versions(version, b[1:].strip()) >= 0:
                return False
        elif b.startswith("="):
            if _cmp_versions(version, b[1:].strip()) != 0:
                return False
        elif b.startswith("!="):
            if _cmp_versions(version, b[2:].strip()) == 0:
                return False
        else:
            # Unknown bound shape — treat as exact.
            if _cmp_versions(version, b) != 0:
                return False
    return True


# ---------------------------------------------------------------------------
# Public lookup API
# ---------------------------------------------------------------------------


def find_cves_for(
    component: str,
    version: str | None = None,
    *,
    vendor: str | None = None,
    only_kev: bool = False,
    min_epss: float = 0.0,
    limit: int = 50,
) -> list[CVERecord]:
    """Return CVEs whose component matches `(vendor, component)`.

    Args:
        component: product name, e.g. "apache", "nginx", "express",
            "log4j". Case-insensitive.
        version: optional version string. When supplied, results are
            filtered to CVEs whose `version_pattern` matches.
        vendor: optional vendor name (case-insensitive). Pinning
            vendor + product reduces false positives when product
            names collide (e.g. "tomcat" matches Apache and a
            different OSS project).
        only_kev: filter to actively-exploited (CISA KEV).
        min_epss: filter to EPSS probability >= this.
        limit: cap returned records (default 50).

    Returns:
        List of `CVERecord` ordered by KEV status, EPSS score, CVSS
        score (highest first).
    """
    try:
        candidates = ti_cache.fetch_cves_for_product(
            component, vendor=vendor,
            only_kev=only_kev, min_epss=min_epss,
            limit=limit * 4,  # over-fetch to allow version filter
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("find_cves_for query failed: %s", e, exc_info=True)
        return []

    if not version:
        return candidates[:limit]

    out: list[CVERecord] = []
    for c in candidates:
        # A CVE matches if any of its components matches both the
        # product name AND the version pattern.
        for comp in c.components:
            cp = (comp.get("product") or "").lower()
            cv = (comp.get("vendor") or "").lower()
            if cp != component.strip().lower():
                continue
            if vendor and cv and cv != vendor.strip().lower():
                continue
            pattern = comp.get("version_pattern") or "*"
            try:
                if _matches_pattern(version, pattern):
                    out.append(c)
                    break
            except Exception:  # noqa: BLE001
                continue
    return out[:limit]


def get_cve(cve_id: str) -> CVERecord | None:
    """Single-CVE lookup."""
    try:
        return ti_cache.fetch_cve(cve_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("get_cve failed: %s", e, exc_info=True)
        return None


def list_kev(limit: int = 5000) -> list[CVERecord]:
    """All KEV-flagged CVEs ordered by EPSS descending."""
    try:
        return ti_cache.fetch_kev_list(limit=limit)
    except Exception as e:  # noqa: BLE001
        logger.debug("list_kev failed: %s", e, exc_info=True)
        return []


def find_recently_exploited(
    *, min_epss: float = 0.5, limit: int = 100,
) -> list[CVERecord]:
    """High-EPSS or KEV-flagged CVEs."""
    try:
        return ti_cache.fetch_recently_exploited(
            min_epss=min_epss, limit=limit,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("find_recently_exploited failed: %s", e, exc_info=True)
        return []


def cache_status() -> dict[str, Any]:
    """Per-feed status + overall freshness for debugging.

    Returns:
        {
          "cache_path": "...",
          "feeds": [{"feed_name": "kev", "status": "ok",
                     "last_polled": "...", "record_count": ...}],
          "totals": {"cves": N, "kev": N, "with_epss": N}
        }
    """
    try:
        feeds = ti_cache.fetch_feed_meta()
    except Exception:  # noqa: BLE001
        feeds = []
    totals: dict[str, int] = {}
    try:
        with ti_cache.connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) AS n FROM cves")
            totals["cves"] = int(cur.fetchone()["n"])
            cur.execute("SELECT COUNT(*) AS n FROM cves WHERE kev=1")
            totals["kev"] = int(cur.fetchone()["n"])
            cur.execute("SELECT COUNT(*) AS n FROM cves WHERE epss IS NOT NULL")
            totals["with_epss"] = int(cur.fetchone()["n"])
    except Exception:  # noqa: BLE001
        totals = {"cves": 0, "kev": 0, "with_epss": 0}
    return {
        "cache_path": str(ti_cache.cache_path()),
        "feeds": feeds,
        "totals": totals,
    }
