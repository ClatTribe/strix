"""LLM-facing threat-intel tools (registered via @register_tool).

iter-22.9 (catalog bloat consolidation, per
`docs/l2-architecture-evaluation.md §5.1`): the four CVE-lookup
shapes that previously each had their own `@register_tool` schema
(`lookup_known_cves`, `lookup_cve_by_id`,
`list_actively_exploited_cves`, plus older `cve_lookup` /
`nvd_lookup`) are consolidated into a single
`query_threat_intel(...)` tool. Mode is selected by which kwargs
are supplied:

  * `cve_id=` → single-CVE detail lookup
  * `component=` (+ optional `version` / `vendor`) → component
    CVE list
  * `actively_exploited=True` → KEV / high-EPSS list

The old three lookup_* function bodies stay in this module
(internal callers in `strix/tools/verify/verify_findings.py` and
elsewhere still import them) but **lose their `@register_tool`
decorator** so the LLM's tool catalog no longer carries their
~3K of schema-description tokens.

`threat_intel_status()` remains separately registered — it's a
cache-freshness diagnostic distinct from data queries.

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


# iter-22.9: removed `@register_tool` decorator — the LLM-facing
# entry point is `query_threat_intel(...)` below. The function
# body stays as an internal helper used by `verify_findings.py`
# and re-called by the consolidated tool.
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


# iter-22.9: removed `@register_tool` — consolidated into
# `query_threat_intel(cve_id=...)`. Internal helper kept for
# other-module callers.
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


# iter-22.9: removed `@register_tool` — consolidated into
# `query_threat_intel(actively_exploited=True)`. Internal helper.
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
    mitre_techniques=["T1592", "T1592.002"],
    provenance="framework",
)
def query_threat_intel(
    cve_id: str | None = None,
    component: str | None = None,
    version: str | None = None,
    vendor: str | None = None,
    actively_exploited: bool = False,
    only_kev: bool = False,
    min_epss: float = 0.0,
    max_records: int = 25,
) -> dict[str, Any]:
    """Unified threat-intel query — replaces `lookup_known_cves`,
    `lookup_cve_by_id`, and `list_actively_exploited_cves`
    (iter-22.9 catalog consolidation per
    `docs/l2-architecture-evaluation.md §5.1`).

    Mode dispatch (first matching wins):

      1. `cve_id` supplied → single-CVE detail lookup. Returns
         `{status, cve}` or `{status: "not_found", message}` when
         the cache doesn't have the CVE.

      2. `component` supplied → component → CVE list. Backed by
         CISA KEV + FIRST.org EPSS + NVD CPE matching. Returns
         `{status, match_count, kev_count, high_epss_count,
         critical_count, cves, next_action_hint}`.

      3. `actively_exploited=True` (no component, no cve_id) →
         KEV / high-EPSS list. Returns the global recently-exploited
         set ordered by KEV-status + EPSS descending.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2024-12345"). Triggers
            mode 1 single-CVE lookup.
        component: package or product name (case-insensitive,
            e.g. "apache", "nginx", "lodash", "log4j"). Triggers
            mode 2 component lookup.
        version: optional version filter for mode 2 (CPE-aware).
        vendor: optional vendor filter for mode 2 (pin when product
            names collide, e.g. "tomcat" appears under multiple
            vendors).
        actively_exploited: if True and neither cve_id nor
            component supplied, triggers mode 3 (KEV/high-EPSS
            list).
        only_kev: mode 2/3 filter — CISA KEV catalog only.
        min_epss: mode 2/3 filter — EPSS probability >= this
            (0.0-1.0). Use 0.5 for "likely to be exploited soon",
            0.97 for "near-certain weaponisation".
        max_records: cap returned records (default 25).

    Returns: structured dict with `status` and mode-specific keys.
    Errors are returned as `{"status": "error", "error": ...}` —
    the tool never raises.
    """
    # Mode 1: single-CVE
    if cve_id is not None and isinstance(cve_id, str) and cve_id.strip():
        return lookup_cve_by_id(cve_id=cve_id)

    # Mode 2: component lookup
    if component is not None and isinstance(component, str) and component.strip():
        return lookup_known_cves(
            component=component,
            version=version,
            vendor=vendor,
            only_kev=only_kev,
            min_epss=min_epss,
            max_records=max_records,
        )

    # Mode 3: actively-exploited list
    if actively_exploited:
        return list_actively_exploited_cves(
            min_epss=min_epss if min_epss > 0 else 0.5,
            max_records=max_records,
        )

    return {
        "status": "error",
        "error": (
            "query_threat_intel requires one of: `cve_id` (single-"
            "CVE lookup), `component` (component-to-CVE list), or "
            "`actively_exploited=True` (KEV/EPSS list)."
        ),
        "cves": [],
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
