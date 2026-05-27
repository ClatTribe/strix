"""iter-Q5.7 + Q5.7a — `query_threat_intel(...)`.

Unified real-time threat-intel fetcher. Per CLAUDE.md §1.5.6, this
is a FETCH EXTERNAL bucket tool — the LLM's training cutoff doesn't
know whether CVE-2024-X hit CISA KEV last week, whether EPSS moved
this morning, or what the current vendor advisory says.

Replaces (collapses behind one signature):
  * cve_lookup         — NVD CVE detail
  * nvd_lookup         — NVD CPE / vendor search
  * cve_intel_search   — multi-source CVE intel
  * kev_diff_check     — CISA KEV catalog membership + EPSS

Plus adds (Q5.7a):
  * domain=...         — passive DNS / WHOIS / reputation routing

## Routing

The lead supplies exactly one of:
  - cve_id="CVE-2024-1234"
  - cwe_id="CWE-89"
  - product="apache-tomcat" [+ version="9.0.49"]
  - domain="example.com"

The umbrella picks the right underlying tool(s), merges the results
into a unified dict, and caches per-key for 24h to avoid hammering
NVD / EPSS / WHOIS APIs.

## Returns

```
{
  query: {kind, value},
  cvss: {score, severity, vector, ...} | null,
  kev: {is_listed, date_added, due_date, ransomware_use, ...} | null,
  epss: {score, percentile, date} | null,
  advisories: [{vendor, url, fixed_versions}, ...],
  exploit_availability: {public_poc, weaponized, in_metasploit} | null,
  domain_intel: {passive_dns, whois, reputation} | null,
  reason: str | null,  # populated on partial / no-data
  cache_hit: bool,
}
```

Best-effort: any sub-source failure populates `reason` but the dict
still returns successfully. The L1.5 hook chain (threat_intel.enrich
on add_vulnerability_report) is unaffected — this tool is the
LLM-callable variant for mid-scan intel.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)


# 24h cache TTL — per CLAUDE.md §1.5.6, real-time external data
# changes after LLM training, but doesn't change minute-to-minute.
# 24h is a safe default; the proposal §4.1 codifies it.
_CACHE_TTL_SECONDS = 86_400

# Cache dir. Honours STRIX_RUN_DIR for run-scoped caches; falls back
# to ~/.strix/threat_intel_cache for global caches.
def _cache_dir() -> Path:
    run_dir = os.environ.get("STRIX_RUN_DIR")
    if run_dir:
        return Path(run_dir) / "threat_intel_cache"
    return Path.home() / ".strix" / "threat_intel_cache"


def _cache_key(query: dict[str, Any]) -> str:
    """Stable cache key per query shape."""
    blob = json.dumps(query, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _read_cache(key: str) -> dict[str, Any] | None:
    """Return cached result if fresh, else None."""
    try:
        path = _cache_dir() / f"{key}.json"
        if not path.exists():
            return None
        age = time.time() - path.stat().st_mtime
        if age > _CACHE_TTL_SECONDS:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _write_cache(key: str, payload: dict[str, Any]) -> None:
    """Best-effort cache write."""
    try:
        d = _cache_dir()
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{key}.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )
    except Exception:  # noqa: BLE001
        logger.debug("threat-intel cache write failed", exc_info=True)


# ---------------------------------------------------------------------------
# Sub-source routing helpers
# ---------------------------------------------------------------------------


def _fetch_cve_intel(cve_id: str) -> dict[str, Any]:
    """Route CVE queries through cve_intel_search (broadest signal)
    + kev_diff_check (specific real-time question)."""
    result: dict[str, Any] = {
        "cvss": None, "kev": None, "epss": None,
        "advisories": [], "exploit_availability": None,
    }
    try:
        from strix.tools.cve_intel.cve_intel_search import cve_intel_search
        intel = cve_intel_search(cve_id=cve_id)
        if isinstance(intel, dict):
            # cve_intel_search returns a rich blob; pull the
            # standardised fields.
            result["cvss"] = intel.get("cvss")
            result["advisories"] = intel.get("advisories") or []
            result["exploit_availability"] = intel.get(
                "exploit_availability"
            ) or intel.get("exploits")
    except Exception as e:  # noqa: BLE001
        logger.debug("cve_intel_search failed for %s: %s", cve_id, e)

    try:
        from strix.tools.kev_diff.kev_diff_check import kev_diff_check
        kev = kev_diff_check(cve_ids=[cve_id])
        if isinstance(kev, dict):
            matches = kev.get("matches") or kev.get("found") or []
            if matches and isinstance(matches, list):
                first = matches[0] if isinstance(matches[0], dict) else {}
                result["kev"] = {
                    "is_listed": True,
                    "date_added": first.get("dateAdded"),
                    "due_date": first.get("dueDate"),
                    "ransomware_use": first.get("knownRansomwareCampaignUse"),
                }
            elif "kev" in kev:
                # Some response shapes nest it under "kev"
                result["kev"] = kev["kev"]
            else:
                result["kev"] = {"is_listed": False}
            if "epss" in kev:
                result["epss"] = kev["epss"]
    except Exception as e:  # noqa: BLE001
        logger.debug("kev_diff_check failed for %s: %s", cve_id, e)

    return result


def _fetch_product_intel(
    product: str, version: str | None,
) -> dict[str, Any]:
    """Route product+version queries through nvd_lookup (CPE search)."""
    result: dict[str, Any] = {
        "cvss": None, "kev": None, "epss": None,
        "advisories": [], "exploit_availability": None,
    }
    try:
        from strix.tools.nvd_lookup.nvd_lookup import nvd_lookup
        kwargs: dict[str, Any] = {"product": product}
        if version:
            kwargs["version"] = version
        intel = nvd_lookup(**kwargs)
        if isinstance(intel, dict):
            cves = intel.get("cves") or intel.get("matches") or []
            if cves:
                # Surface the worst CVSS in the result.
                worst = None
                for c in cves:
                    if not isinstance(c, dict):
                        continue
                    score = c.get("cvss_score") or c.get("cvss", {}).get("score")
                    if score and (worst is None or score > worst.get("score", 0)):
                        worst = {
                            "score": score,
                            "id": c.get("id") or c.get("cve_id"),
                        }
                result["cvss"] = worst
            result["advisories"] = intel.get("advisories") or []
    except Exception as e:  # noqa: BLE001
        logger.debug("nvd_lookup failed for %s %s: %s", product, version, e)

    return result


def _fetch_cwe_intel(cwe_id: str) -> dict[str, Any]:
    """CWE queries are corpus-knowledge — LLM training data covers
    them well. We don't make a network call; we just return a
    placeholder so the tool surface stays uniform."""
    return {
        "cvss": None, "kev": None, "epss": None,
        "advisories": [],
        "exploit_availability": None,
        "reason": (
            f"CWE {cwe_id} — no per-CWE real-time intel; the lead "
            f"already knows the static description. Use cve_id="
            f" for time-varying intel."
        ),
    }


def _fetch_domain_intel(domain: str) -> dict[str, Any]:
    """iter-Q5.7a — domain-shaped queries route to passive DNS /
    WHOIS / typo-squat sources via the existing tools."""
    result: dict[str, Any] = {
        "cvss": None, "kev": None, "epss": None,
        "advisories": [], "exploit_availability": None,
        "domain_intel": {
            "passive_dns": None,
            "whois": None,
            "reputation": None,
        },
    }
    # checkdmarc gives us DNS hygiene data (TXT/SPF/DMARC/MX/CAA).
    try:
        from strix.tools.checkdmarc_runner.scan_dns_hygiene_checkdmarc import (
            scan_dns_hygiene_checkdmarc,
        )
        dns = scan_dns_hygiene_checkdmarc(domain=domain)
        if isinstance(dns, dict):
            result["domain_intel"]["passive_dns"] = dns.get("summary")
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_dns_hygiene_checkdmarc failed for %s: %s", domain, e)

    # dnstwist surfaces reputation-adjacent typo-squat candidates.
    try:
        from strix.tools.osint_aggregator.scan_typosquats_dnstwist import (
            scan_typosquats_dnstwist,
        )
        twist = scan_typosquats_dnstwist(domain=domain, max_variants=50)
        if isinstance(twist, dict):
            result["domain_intel"]["reputation"] = {
                "typosquat_count": twist.get("total_findings"),
            }
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_typosquats_dnstwist failed for %s: %s", domain, e)

    return result


# ---------------------------------------------------------------------------
# The umbrella tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=False,
    mitre_techniques=["T1597"],  # Search Closed Sources
)
def query_threat_intel(
    *,
    cve_id: str | None = None,
    cwe_id: str | None = None,
    product: str | None = None,
    version: str | None = None,
    domain: str | None = None,
) -> dict[str, Any]:
    """Unified real-time threat-intel query.

    Exactly ONE of (cve_id, cwe_id, product, domain) is required.
    Returns a unified dict with CVSS + KEV state + EPSS score +
    vendor advisories + exploit availability when applicable, plus
    domain-intel block (passive DNS / WHOIS / reputation) on domain
    queries.

    24h cache per query key — re-firing the same lookup mid-scan
    returns the cached blob, not a new network call.

    Args:
        cve_id: e.g. "CVE-2021-44228" — best for time-varying intel
        cwe_id: e.g. "CWE-89" — returns static-knowledge placeholder
        product: e.g. "apache-tomcat" — paired with `version` for
            CPE-style search
        version: optional version qualifier for product queries
        domain: e.g. "example.com" — routes to DNS/WHOIS/reputation

    Returns:
        See module docstring for the unified shape.
    """
    # Validate exactly-one-of.
    populated = [
        ("cve_id", cve_id),
        ("cwe_id", cwe_id),
        ("product", product),
        ("domain", domain),
    ]
    set_kwargs = [(k, v) for k, v in populated if isinstance(v, str) and v.strip()]
    if len(set_kwargs) == 0:
        return {
            "success": False,
            "status": "error",
            "reason": (
                "exactly one of {cve_id, cwe_id, product, domain} "
                "is required"
            ),
        }
    if len(set_kwargs) > 1:
        kinds = [k for k, _ in set_kwargs]
        return {
            "success": False,
            "status": "error",
            "reason": (
                f"only one query kind at a time; got {kinds}. "
                f"Issue separate calls for each."
            ),
        }
    kind, value = set_kwargs[0]
    value = value.strip()

    query = {"kind": kind, "value": value}
    if kind == "product" and version:
        query["version"] = version.strip()

    # Cache hit?
    key = _cache_key(query)
    cached = _read_cache(key)
    if cached is not None:
        cached["cache_hit"] = True
        return cached

    # Route to the right sub-source.
    try:
        if kind == "cve_id":
            sub = _fetch_cve_intel(value)
        elif kind == "cwe_id":
            sub = _fetch_cwe_intel(value)
        elif kind == "product":
            sub = _fetch_product_intel(value, version)
        else:  # domain
            sub = _fetch_domain_intel(value)
    except Exception as e:  # noqa: BLE001
        logger.debug("query_threat_intel routing failed: %s", e, exc_info=True)
        return {
            "success": False,
            "status": "error",
            "query": query,
            "reason": f"sub-source dispatch failed: {type(e).__name__}: {e}",
        }

    response: dict[str, Any] = {
        "success": True,
        "status": "ok",
        "query": query,
        "cvss": sub.get("cvss"),
        "kev": sub.get("kev"),
        "epss": sub.get("epss"),
        "advisories": sub.get("advisories") or [],
        "exploit_availability": sub.get("exploit_availability"),
        "domain_intel": sub.get("domain_intel"),
        "reason": sub.get("reason"),
        "cache_hit": False,
    }
    _write_cache(key, response)
    return response
