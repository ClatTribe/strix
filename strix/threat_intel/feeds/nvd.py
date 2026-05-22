"""NIST NVD CVE 2.0 API ingester (recent window).

Source: https://nvd.nist.gov/developers/vulnerabilities
API:    https://services.nvd.nist.gov/rest/json/cves/2.0

Strategy: pull the recent window (default last 14 days, configurable
up to 120 days per NVD's API rate limits) so we have current CVEs
matched against detected components. Full historical sync is opt-in
via `--full` on the refresh CLI.

Each NVD record has:
  cve.id, descriptions[], metrics.cvssMetricV31[].cvssData,
  configurations[].nodes[].cpeMatch[].criteria,
  published, lastModified

We translate the CPE criteria
`cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*` into our
`(vendor, product, version_pattern)` shape.

NVD throttling: without an API key, public limit is 5 req / 30s.
With a key (free, register at nvd.nist.gov), the limit is 50 / 30s.
Set `NVD_API_KEY=...` env var to use a key; the poller honours it.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from strix.threat_intel import cache as ti_cache


logger = logging.getLogger(__name__)


NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _http_get(url: str, *, timeout: float = 60.0,
              api_key: str | None = None) -> bytes:
    import urllib.request
    headers = {
        "User-Agent": "strix-threat-intel/1.0 (+https://github.com/usestrix/strix)",
        "Accept": "application/json",
    }
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _parse_cpe(cpe_str: str) -> dict[str, str] | None:
    """Parse a CPE 2.3 URI into (vendor, product, version)."""
    # Format: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
    if not isinstance(cpe_str, str) or not cpe_str.startswith("cpe:2.3:"):
        return None
    parts = cpe_str.split(":")
    if len(parts) < 6:
        return None
    return {
        "vendor": parts[3],
        "product": parts[4],
        "version_pattern": parts[5] if parts[5] != "*" else "*",
    }


def _extract_components(node: dict[str, Any]) -> list[dict[str, str]]:
    """Walk an NVD config node tree, returning component dicts."""
    out: list[dict[str, str]] = []
    if not isinstance(node, dict):
        return out
    for cpe in (node.get("cpeMatch") or []):
        if not isinstance(cpe, dict):
            continue
        if cpe.get("vulnerable") is False:
            continue
        criteria = cpe.get("criteria") or ""
        comp = _parse_cpe(criteria)
        if comp is None:
            continue
        # Apply versionStartIncluding/Excluding if present.
        vsi = cpe.get("versionStartIncluding")
        vse = cpe.get("versionStartExcluding")
        vei = cpe.get("versionEndIncluding")
        vee = cpe.get("versionEndExcluding")
        bounds: list[str] = []
        if vsi:
            bounds.append(f">={vsi}")
        if vse:
            bounds.append(f">{vse}")
        if vei:
            bounds.append(f"<={vei}")
        if vee:
            bounds.append(f"<{vee}")
        if bounds:
            comp["version_pattern"] = ",".join(bounds)
        out.append(comp)
    # Recurse into children.
    for child in (node.get("children") or []):
        out.extend(_extract_components(child))
    return out


def _normalize_cve(item: dict[str, Any]) -> dict[str, Any] | None:
    """Translate one NVD vulnerability item into our cache shape."""
    cve = (item or {}).get("cve") or {}
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        return None

    # Description: prefer en, fall back to first available.
    desc_text = ""
    for d in (cve.get("descriptions") or []):
        if not isinstance(d, dict):
            continue
        if d.get("lang") == "en" and d.get("value"):
            desc_text = d["value"]
            break
    if not desc_text:
        for d in (cve.get("descriptions") or []):
            if isinstance(d, dict) and d.get("value"):
                desc_text = d["value"]
                break

    # CVSS (prefer v3.1, then v3.0, then v2).
    cvss_score: float | None = None
    severity: str | None = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        for m in items:
            if not isinstance(m, dict):
                continue
            d = m.get("cvssData") or {}
            try:
                cvss_score = float(d.get("baseScore"))
                severity = (
                    d.get("baseSeverity")
                    or m.get("baseSeverity")
                    or _severity_from_score(cvss_score)
                )
                break
            except (TypeError, ValueError):
                continue
        if cvss_score is not None:
            break

    # Components.
    comps: list[dict[str, str]] = []
    for cfg in (cve.get("configurations") or []):
        if not isinstance(cfg, dict):
            continue
        for node in (cfg.get("nodes") or []):
            comps.extend(_extract_components(node))

    return {
        "cve_id": cve_id,
        "description": desc_text[:8000],
        "cvss_score": cvss_score,
        "severity": (severity or "").lower() or None,
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "components": comps[:200],  # cap absurd CPE lists
        "raw": None,  # don't bloat the cache; raw available via NVD API
    }


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
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


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def poll_nvd_recent(
    *,
    days: int = 14,
    page_size: int = 2000,
    api_key: str | None = None,
    fetch: callable | None = None,
) -> dict[str, Any]:
    """Pull NVD CVEs modified in the last `days` (default 14).

    Args:
        days: window size (max 120 per NVD).
        page_size: NVD `resultsPerPage` (max 2000).
        api_key: NVD API key. Falls back to `NVD_API_KEY` env.
        fetch: optional callable `(url, timeout, api_key) -> bytes`
            for testing.

    Returns:
        {"status": ..., "ingested": N, "pages": N,
         "window_days": N, "error": ...}
    """
    if days <= 0 or days > 120:
        return {"status": "error", "ingested": 0, "pages": 0,
                "error": f"days must be 1..120 (got {days})"}
    fetch = fetch or _http_get
    api_key = api_key or os.environ.get("NVD_API_KEY")

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    base_qs = {
        "lastModStartDate": _iso_utc(start),
        "lastModEndDate": _iso_utc(end),
        "resultsPerPage": str(page_size),
    }

    pages = 0
    total_ingested = 0
    last_modified_seen: str | None = None
    start_index = 0
    sleep_between = 0.5 if api_key else 6.5  # respect rate limit

    while True:
        qs = "&".join(f"{k}={v}" for k, v in {**base_qs, "startIndex": str(start_index)}.items())
        url = f"{NVD_BASE}?{qs}"
        try:
            raw = fetch(url, timeout=60.0, api_key=api_key)
        except Exception as e:  # noqa: BLE001
            msg = f"NVD fetch failed at startIndex={start_index}: {type(e).__name__}: {e}"
            logger.warning(msg)
            ti_cache.record_feed_status(
                "nvd", status="error", error=msg, record_count=total_ingested,
            )
            return {"status": "error", "ingested": total_ingested,
                    "pages": pages, "window_days": days, "error": msg}

        try:
            doc = json.loads(raw)
        except Exception as e:  # noqa: BLE001
            msg = f"NVD JSON parse failed: {type(e).__name__}: {e}"
            ti_cache.record_feed_status("nvd", status="error", error=msg,
                                        record_count=total_ingested)
            return {"status": "error", "ingested": total_ingested,
                    "pages": pages, "window_days": days, "error": msg}

        items = doc.get("vulnerabilities") or []
        if not isinstance(items, list):
            break
        normalized = [_normalize_cve(it) for it in items]
        normalized = [n for n in normalized if n is not None]
        if normalized:
            try:
                n = ti_cache.upsert_cves(normalized, source="nvd")
                total_ingested += n
                # Track latest modified for feed_meta.
                for r in normalized:
                    m = r.get("modified")
                    if m and (last_modified_seen is None or m > last_modified_seen):
                        last_modified_seen = m
            except Exception as e:  # noqa: BLE001
                msg = f"NVD upsert failed: {type(e).__name__}: {e}"
                ti_cache.record_feed_status("nvd", status="error", error=msg,
                                            record_count=total_ingested)
                return {"status": "error", "ingested": total_ingested,
                        "pages": pages, "window_days": days, "error": msg}

        pages += 1
        total_results = int(doc.get("totalResults") or len(items))
        start_index += len(items)
        if start_index >= total_results or len(items) < page_size:
            break
        # Rate-limit pause.
        time.sleep(sleep_between)

    ti_cache.record_feed_status(
        "nvd", status="ok",
        record_count=total_ingested,
        last_updated_at=last_modified_seen,
    )
    return {
        "status": "ok",
        "ingested": total_ingested,
        "pages": pages,
        "window_days": days,
        "error": None,
    }


def poll_nvd_incremental(
    *,
    since_iso: str | None = None,
    fallback_minutes: int = 30,
    page_size: int = 2000,
    api_key: str | None = None,
    fetch: callable | None = None,
) -> dict[str, Any]:
    """iter-22.5 — real-time NVD CVE polling. Cuts the
    `poll_nvd_recent` 14-day batch window down to minutes by
    using NVD API v2's `lastModStartDate=` for true incremental
    updates. Cron-driven daily polls become 5-minute cron jobs;
    CVE arrival latency goes from ~24h to ~5min.

    Args:
        since_iso: ISO-8601 starting timestamp. When None,
            falls back to the cache's `feed_meta.last_polled`
            for the `nvd` feed, OR to `now - fallback_minutes`
            on first run.
        fallback_minutes: window size used when `since_iso` and
            `feed_meta.last_polled` are both unavailable.
            Default 30min — paired with a 5-10min cron, this gives
            sufficient overlap to absorb cron-skew without
            re-ingesting weeks of history.
        page_size: NVD `resultsPerPage` (max 2000).
        api_key: NVD API key. Falls back to `NVD_API_KEY` env.
        fetch: optional test injection point.

    Returns:
        {"status", "ingested", "pages", "since", "until",
         "incremental": True, "error"}

    Compatibility: this is a NEW function added alongside
    `poll_nvd_recent` (which stays for full-window backfills /
    air-gapped first-run loads). The CLI / refresh.py daemon
    will route to `poll_nvd_incremental` by default after the
    initial seed is in place.
    """
    fetch = fetch or _http_get
    api_key = api_key or os.environ.get("NVD_API_KEY")

    end = datetime.now(timezone.utc)

    # Resolve the start timestamp. Priority:
    #   1. Explicit `since_iso` kwarg
    #   2. feed_meta.last_polled for `nvd` feed
    #   3. `end - fallback_minutes`
    start_dt = None
    if since_iso:
        try:
            s = since_iso.rstrip("Z")
            start_dt = datetime.fromisoformat(s)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        except ValueError as e:
            return {
                "status": "error", "ingested": 0, "pages": 0,
                "since": since_iso, "until": _iso_utc(end),
                "incremental": True,
                "error": f"unparseable since_iso: {e}",
            }
    if start_dt is None:
        try:
            rows = ti_cache.fetch_feed_meta() or []
            for row in rows:
                if (row.get("feed_name") or "").lower() == "nvd":
                    lp = row.get("last_polled")
                    if isinstance(lp, str) and lp:
                        try:
                            s = lp.rstrip("Z")
                            start_dt = datetime.fromisoformat(s)
                            if start_dt.tzinfo is None:
                                start_dt = start_dt.replace(tzinfo=timezone.utc)
                            break
                        except ValueError:
                            pass
        except Exception:  # noqa: BLE001
            start_dt = None
    if start_dt is None:
        start_dt = end - timedelta(minutes=fallback_minutes)

    # NVD's lastModStartDate accepts UP TO 120 days — clamp +
    # surface as fallback when the gap is huge (e.g. cold-start).
    window = (end - start_dt).total_seconds() / 86400
    if window > 120:
        start_dt = end - timedelta(days=120)

    base_qs = {
        "lastModStartDate": _iso_utc(start_dt),
        "lastModEndDate": _iso_utc(end),
        "resultsPerPage": str(page_size),
    }

    pages = 0
    total_ingested = 0
    last_modified_seen: str | None = None
    start_index = 0
    sleep_between = 0.5 if api_key else 6.5  # respect rate limit

    while True:
        qs = "&".join(
            f"{k}={v}"
            for k, v in {**base_qs, "startIndex": str(start_index)}.items()
        )
        url = f"{NVD_BASE}?{qs}"
        try:
            raw = fetch(url, timeout=60.0, api_key=api_key)
        except Exception as e:  # noqa: BLE001
            msg = (
                f"NVD incremental fetch failed at "
                f"startIndex={start_index}: {type(e).__name__}: {e}"
            )
            logger.warning(msg)
            ti_cache.record_feed_status(
                "nvd", status="error", error=msg,
                record_count=total_ingested,
            )
            return {
                "status": "error", "ingested": total_ingested,
                "pages": pages, "since": base_qs["lastModStartDate"],
                "until": base_qs["lastModEndDate"],
                "incremental": True, "error": msg,
            }

        try:
            doc = json.loads(raw)
        except Exception as e:  # noqa: BLE001
            msg = f"NVD JSON parse failed: {type(e).__name__}: {e}"
            ti_cache.record_feed_status(
                "nvd", status="error", error=msg,
                record_count=total_ingested,
            )
            return {
                "status": "error", "ingested": total_ingested,
                "pages": pages, "since": base_qs["lastModStartDate"],
                "until": base_qs["lastModEndDate"],
                "incremental": True, "error": msg,
            }

        items = doc.get("vulnerabilities") or []
        if not isinstance(items, list):
            break
        normalized = [_normalize_cve(it) for it in items]
        normalized = [n for n in normalized if n is not None]
        if normalized:
            try:
                n = ti_cache.upsert_cves(normalized, source="nvd")
                total_ingested += n
                for r in normalized:
                    m = r.get("modified")
                    if m and (
                        last_modified_seen is None or m > last_modified_seen
                    ):
                        last_modified_seen = m
            except Exception as e:  # noqa: BLE001
                msg = f"NVD upsert failed: {type(e).__name__}: {e}"
                ti_cache.record_feed_status(
                    "nvd", status="error", error=msg,
                    record_count=total_ingested,
                )
                return {
                    "status": "error", "ingested": total_ingested,
                    "pages": pages,
                    "since": base_qs["lastModStartDate"],
                    "until": base_qs["lastModEndDate"],
                    "incremental": True, "error": msg,
                }

        pages += 1
        total_results = int(doc.get("totalResults") or len(items))
        start_index += len(items)
        if start_index >= total_results or len(items) < page_size:
            break
        time.sleep(sleep_between)

    # Record the poll. `record_feed_status` sets `last_polled` to
    # "now" automatically — that's what subsequent incremental
    # polls read to compute their start window.
    ti_cache.record_feed_status(
        "nvd", status="ok",
        record_count=total_ingested,
        last_updated_at=last_modified_seen,
    )

    return {
        "status": "ok",
        "ingested": total_ingested,
        "pages": pages,
        "since": base_qs["lastModStartDate"],
        "until": base_qs["lastModEndDate"],
        "incremental": True,
        "error": None,
    }
