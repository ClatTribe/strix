"""CISA Known Exploited Vulnerabilities (KEV) feed.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
JSON feed:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Updated approximately weekly. Each entry says "this CVE is being
exploited in the wild RIGHT NOW" — gold-standard prioritization
signal.

Per-record schema (CISA's published shape):

    {
      "cveID": "CVE-2024-12345",
      "vendorProject": "Microsoft",
      "product": "Windows",
      "vulnerabilityName": "Microsoft Windows Privilege Escalation",
      "dateAdded": "2024-09-04",
      "shortDescription": "...",
      "requiredAction": "Apply...",
      "dueDate": "2024-09-25",
      "knownRansomwareCampaignUse": "Known" | "Unknown",
      "notes": "..."
    }

Best-effort: HTTP failures swallowed; cache stays at last-known-good
state. The poller writes a `feed_meta` row reflecting status.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from strix.threat_intel import cache as ti_cache


logger = logging.getLogger(__name__)


KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def _http_get(url: str, *, timeout: float = 30.0) -> bytes:
    """Plain HTTP GET via stdlib so we don't pull in `requests` for a
    background daemon. Returns the response body bytes."""
    import urllib.request
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "strix-threat-intel/1.0 (+https://github.com/usestrix/strix)",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _normalize_record(r: dict[str, Any]) -> dict[str, Any] | None:
    """Translate a CISA record into our cache shape. Returns None on
    malformed entries so the loader skips them."""
    cve_id = r.get("cveID")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None
    return {
        "cve_id": cve_id.strip().upper(),
        "vendor": r.get("vendorProject") or "",
        "product": r.get("product") or "",
        "vuln_name": r.get("vulnerabilityName") or "",
        "date_added": r.get("dateAdded"),
        "due_date": r.get("dueDate"),
        "ransomware": (
            (r.get("knownRansomwareCampaignUse") or "").lower() == "known"
        ),
        "notes": (
            (r.get("shortDescription") or "")
            + ("\n" + r.get("notes") if r.get("notes") else "")
        )[:2048],
    }


def poll_kev(
    *,
    url: str = KEV_URL,
    fetch: callable | None = None,
) -> dict[str, Any]:
    """Fetch + persist the latest KEV catalog.

    Args:
        url: override the default KEV URL.
        fetch: optional callable `(url) -> bytes` for testing.

    Returns:
        {"status": "ok"|"error", "ingested": N, "error": str|None,
         "catalog_version": ..., "release_date": ...}
    """
    fetch = fetch or _http_get
    try:
        raw = fetch(url)
    except Exception as e:  # noqa: BLE001
        logger.warning("KEV fetch failed: %s", e)
        ti_cache.record_feed_status(
            "kev", status="error", error=f"{type(e).__name__}: {e}",
        )
        return {"status": "error", "ingested": 0,
                "error": f"{type(e).__name__}: {e}"}

    try:
        doc = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        msg = f"KEV JSON parse failed: {e}"
        logger.warning(msg)
        ti_cache.record_feed_status("kev", status="error", error=msg)
        return {"status": "error", "ingested": 0, "error": msg}

    items = doc.get("vulnerabilities") or []
    if not isinstance(items, list):
        msg = "KEV doc missing 'vulnerabilities' list"
        ti_cache.record_feed_status("kev", status="error", error=msg)
        return {"status": "error", "ingested": 0, "error": msg}

    normalized = [_normalize_record(r) for r in items if isinstance(r, dict)]
    normalized = [r for r in normalized if r is not None]

    try:
        n = ti_cache.upsert_kev_entries(normalized)
    except Exception as e:  # noqa: BLE001
        ti_cache.record_feed_status(
            "kev", status="error",
            error=f"upsert failed: {type(e).__name__}: {e}",
        )
        return {"status": "error", "ingested": 0,
                "error": f"upsert failed: {type(e).__name__}: {e}"}

    catalog_version = doc.get("catalogVersion") or doc.get("catalog_version")
    release_date = doc.get("dateReleased") or doc.get("release_date")
    ti_cache.record_feed_status(
        "kev",
        status="ok",
        record_count=n,
        last_updated_at=release_date,
    )
    return {
        "status": "ok",
        "ingested": n,
        "catalog_version": catalog_version,
        "release_date": release_date,
        "error": None,
    }
