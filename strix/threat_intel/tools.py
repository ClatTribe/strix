"""LLM-facing threat-intel tools (registered via @register_tool).

Two tools surface to the agent:

  * `lookup_known_cves(component, version=None, ...)` — primary
    surface. Returns a structured CVE list with KEV / EPSS metadata
    so the lead can prioritise actively-exploited issues.
  * `threat_intel_status()` — debug helper. Returns cache freshness
    + per-feed status so the lead can decide whether to trust the
    answer (or trigger a refresh).

These are *framework provenance* tools — output is from a public
feed (CISA / NIST / FIRST), not from the target. Outputs feed into
the lead's hypothesis-EV scoring (Phase 5.1) — KEV-listed CVEs that
match a fingerprinted component should jump to the top of the
queue.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.threat_intel.lookup import (
    cache_status,
    find_cves_for,
    find_recently_exploited,
    get_cve,
    list_kev,
)
from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


def _serialise_records(records: list, *, max_records: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in records[:max_records]:
        try:
            out.append(r.to_dict())
        except Exception:  # noqa: BLE001
            continue
    return out


@register_tool(
    sandbox_execution=False,
    mitre_techniques=["T1592.002"],  # Gather Victim Host Information: Software
    provenance="framework",
)
def lookup_known_cves(
    component: str,
    version: str | None = None,
    vendor: str | None = None,
    only_kev: bool = False,
    min_epss: float = 0.0,
    max_records: int = 25,
) -> dict[str, Any]:
    """Look up known CVEs affecting the given component.

    Backed by a local cache of CISA KEV (actively-exploited),
    FIRST.org EPSS (probability of exploitation), and the NVD CVE
    2.0 API (recent window). The lead should call this whenever
    `fingerprint_tech_stack` / `scan_misconfig` identifies a server
    + version pair, an installed library, or a containerized service.

    Args:
        component: package or product name. Case-insensitive.
            Examples: "apache", "nginx", "express", "log4j",
            "django", "wordpress".
        version: optional version string (e.g. "2.4.53"). When
            supplied, results are filtered to CVEs whose CPE
            version-pattern matches.
        vendor: optional vendor name. Pin vendor + product when
            product names collide (e.g. "tomcat" — multiple
            vendors).
        only_kev: filter to actively-exploited CVEs (CISA KEV
            catalog). Default False.
        min_epss: filter to EPSS probability >= this (0.0-1.0).
            Use 0.5 for "likely to be exploited soon", 0.97 for
            "near-certain weaponisation."
        max_records: cap returned records (default 25).

    Returns: structured result with KEV count, high-EPSS count,
    and the matched CVE list. Empty list when nothing matches —
    NOT an error.
    """
    if not isinstance(component, str) or not component.strip():
        return {
            "status": "error",
            "error": "component (string) is required",
            "cves": [],
        }

    try:
        records = find_cves_for(
            component=component,
            version=version,
            vendor=vendor,
            only_kev=only_kev,
            min_epss=min_epss,
            limit=max(max_records, 50),
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("lookup_known_cves failed: %s", e, exc_info=True)
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "cves": [],
        }

    kev_count = sum(1 for r in records if r.kev)
    high_epss_count = sum(1 for r in records if (r.epss or 0) >= 0.5)
    critical_count = sum(
        1 for r in records if (r.severity or "").lower() == "critical"
    )

    return {
        "status": "ok",
        "component": component,
        "version": version,
        "vendor": vendor,
        "match_count": len(records),
        "kev_count": kev_count,
        "high_epss_count": high_epss_count,
        "critical_count": critical_count,
        "cves": _serialise_records(records, max_records=max_records),
        "next_action_hint": (
            "At least one CVE is in CISA KEV (actively exploited). "
            "Open a high-priority hypothesis and run the matching "
            "specialist." if kev_count > 0 else
            "No actively-exploited CVEs match. Treat findings as "
            "informational unless EPSS is high."
        ),
    }


@register_tool(
    sandbox_execution=False,
    mitre_techniques=["T1592"],
    provenance="framework",
)
def lookup_cve_by_id(
    cve_id: str,
) -> dict[str, Any]:
    """Look up a specific CVE by ID.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2024-12345").

    Returns: the CVE record with KEV / EPSS / CVSS / components,
    or `{"status": "not_found"}` when the cache doesn't have it
    (the lead may then call `threat_intel_refresh_hint()` to
    suggest a poll).
    """
    if not isinstance(cve_id, str) or not cve_id.strip():
        return {
            "status": "error",
            "error": "cve_id (string) is required",
        }
    try:
        record = get_cve(cve_id)
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "error": f"{type(e).__name__}: {e}"}
    if record is None:
        return {
            "status": "not_found",
            "cve_id": cve_id.strip().upper(),
            "message": (
                "CVE not in local cache. Run "
                "`python -m strix.threat_intel.refresh` to update, "
                "or extend NVD window with `--nvd-days 60`."
            ),
        }
    return {"status": "ok", "cve": record.to_dict()}


@register_tool(
    sandbox_execution=False,
    mitre_techniques=["T1592"],
    provenance="framework",
)
def list_actively_exploited_cves(
    min_epss: float = 0.5,
    max_records: int = 100,
) -> dict[str, Any]:
    """List CVEs flagged as actively-exploited (CISA KEV) OR with
    high EPSS probability.

    Useful when the lead wants to bias the hypothesis queue toward
    "what attackers are using right now" — pair with `find_cves_for`
    on detected components.

    Args:
        min_epss: minimum EPSS probability (0.0-1.0). Default 0.5.
        max_records: cap (default 100).

    Returns: list of CVE records ordered by KEV-status + EPSS.
    """
    try:
        records = find_recently_exploited(
            min_epss=min_epss, limit=max_records,
        )
    except Exception as e:  # noqa: BLE001
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "cves": [],
        }
    return {
        "status": "ok",
        "min_epss": min_epss,
        "match_count": len(records),
        "cves": _serialise_records(records, max_records=max_records),
    }


@register_tool(
    sandbox_execution=False,
    mitre_techniques=[],
    provenance="framework",
)
def threat_intel_status() -> dict[str, Any]:
    """Cache-freshness diagnostic.

    Returns per-feed status (last_polled, status, record_count) plus
    overall totals. Use this when the lead suspects the cache is
    stale (e.g. zero KEV results for a popular component).

    Returns:
        {
          "cache_path": "...",
          "feeds": [{"feed_name": "kev", "status": "ok", ...}, ...],
          "totals": {"cves": N, "kev": N, "with_epss": N},
          "refresh_hint": "...",
        }
    """
    try:
        s = cache_status()
    except Exception as e:  # noqa: BLE001
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
        }
    # Surface a refresh hint when feeds look stale.
    feeds = s.get("feeds") or []
    feed_names = {f.get("feed_name") for f in feeds}
    missing = [n for n in ("kev", "epss", "nvd") if n not in feed_names]
    error_feeds = [f["feed_name"] for f in feeds if f.get("status") != "ok"]
    if missing or error_feeds:
        s["refresh_hint"] = (
            f"Run `python -m strix.threat_intel.refresh` to refresh. "
            f"Missing: {missing} Errored: {error_feeds}"
        )
    else:
        s["refresh_hint"] = "Cache is healthy."
    s["status"] = "ok"
    return s
