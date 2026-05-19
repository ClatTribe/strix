"""EPSS enrichment for emitted findings — MA-S2 P0-CVS-A.

## Why this exists

MA-S2 CVS-0.2 names EPSS (Exploit Prediction Scoring System) as
a *disqualifying deficiency*: vendors who classify vulnerabilities
solely on CVSS without EPSS enrichment fail the control. CVS-0.5
further requires that EPSS be folded into prioritization (the
SLA must shorten for KEV-listed or high-EPSS findings).

Strix already polls FIRST.org EPSS daily into the threat-intel
cache (`strix/threat_intel/feeds/epss.py`). This module surfaces
that data on every emitted finding as a structured `epss` block,
so the wrapper + auditor see the same enrichment.

## Block shape on findings

```json
"epss": {
  "score": 0.94,                       // float [0,1] or null
  "percentile": null,                  // float [0,1] or null (not in cache today)
  "last_updated": "2026-05-18T...",   // ISO-8601 of the feed's last poll, or null
  "reason": "ok"                       // ok | no_cve | cache_stale | cache_unavailable | percentile_not_cached
}
```

The block is ALWAYS present on a finding (per MA-S2 attestation
discipline: "we tried" must be explicit). When data is missing,
`reason` carries the explanation:

  * `no_cve` — finding has no CVE id; EPSS is per-CVE so this is
    correctly null.
  * `cache_stale` — feed_meta says EPSS hasn't been polled in
    >7 days. Lookup may still hit but the result is suspect.
  * `cache_unavailable` — threat_intel cache module unimportable
    or DB inaccessible.
  * `percentile_not_cached` — score resolved but percentile is
    not in today's cache schema (follow-up: extend
    `feeds/epss.py` to parse + persist column 3).

## Recall safety

This module never affects what gets emitted. It only adds a
read-only enrichment block to findings already on their way out.
Failures fall through to a `reason: "cache_unavailable"` block;
the finding still lands.

## Kill switch

`STRIX_EPSS_ENRICHMENT_DISABLED=1` short-circuits to a constant
"disabled" block. Useful for air-gapped envs where the feed
isn't reachable and the attestation just records the absence.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any


logger = logging.getLogger(__name__)


# Maximum age of the EPSS feed before we mark lookups as
# `cache_stale`. MA-S2's CVS-0.2 doesn't specify a TTL; 7 days is
# the conservative interval used by FIRST.org's own dashboards.
DEFAULT_STALENESS_DAYS = 7


_CVE_ID_RE = re.compile(r"\bCVE[- ]?(\d{4})[- ]?(\d{4,})\b", re.IGNORECASE)


def is_disabled() -> bool:
    """`STRIX_EPSS_ENRICHMENT_DISABLED=1` short-circuits."""
    return os.environ.get(
        "STRIX_EPSS_ENRICHMENT_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _normalize_cve_id(cve: Any) -> str | None:
    """Pull a canonical `CVE-YYYY-N` from a free-form string.
    Accepts `cve-2024-1234`, `CVE 2024 1234`, `CVE-2024-1234`,
    or strings with embedded CVE references. Returns None when
    no CVE id can be extracted."""
    if cve is None:
        return None
    if not isinstance(cve, str):
        return None
    m = _CVE_ID_RE.search(cve)
    if not m:
        return None
    return f"CVE-{m.group(1)}-{m.group(2)}"


def _epss_feed_last_polled() -> str | None:
    """Return the EPSS feed's `last_polled` ISO-8601 from the
    threat-intel cache's `feed_meta` table. None when the cache
    is unavailable or no EPSS feed record exists."""
    try:
        from strix.threat_intel.cache import fetch_feed_meta
    except Exception:  # noqa: BLE001
        return None
    try:
        rows = fetch_feed_meta() or []
    except Exception as e:  # noqa: BLE001
        logger.debug("epss feed_meta fetch failed: %s", e)
        return None
    for row in rows:
        if not isinstance(row, dict):
            continue
        if (row.get("feed_name") or "").lower() == "epss":
            lp = row.get("last_polled")
            if isinstance(lp, str) and lp:
                return lp
    return None


def _feed_is_stale(last_polled: str | None, *, days: int) -> bool:
    """True when the EPSS feed's last poll was more than `days`
    days ago. None / unparseable last_polled → considered stale
    (conservative).
    """
    if not last_polled:
        return True
    try:
        from datetime import datetime, timezone
        # Accept ISO-8601 with or without trailing Z. SQLite TEXT
        # columns produce a variety of shapes.
        s = last_polled.rstrip("Z")
        # Try fromisoformat first
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            # Try a couple of common shapes
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(s, fmt)
                    break
                except ValueError:
                    continue
            else:
                return True
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - dt
        return age.total_seconds() > days * 86400
    except Exception as e:  # noqa: BLE001
        logger.debug("feed-staleness parse failed: %s", e)
        return True


def _lookup_epss_score(cve_id: str) -> float | None:
    """Resolve EPSS score from the threat-intel cache for a
    canonical CVE id. None when missing / unavailable."""
    try:
        from strix.threat_intel.lookup import get_cve
    except Exception:  # noqa: BLE001
        return None
    try:
        rec = get_cve(cve_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("get_cve(%s) failed: %s", cve_id, e)
        return None
    if rec is None:
        return None
    score = getattr(rec, "epss", None)
    if isinstance(score, (int, float)):
        return float(score)
    return None


def resolve_epss_block(
    *,
    cve: str | None,
    staleness_days: int | None = None,
) -> dict[str, Any]:
    """Build the MA-S2 P0-CVS-A `epss` block for a finding's
    CVE id. Always returns a dict (per the attestation
    discipline — "we tried" must be explicit).

    Args:
      cve: the finding's CVE field (may be free-form text containing
        a CVE id, or None).
      staleness_days: override the feed-staleness threshold
        (default 7 days).

    Returns a dict with keys: `score` (float|null),
    `percentile` (float|null), `last_updated` (ISO-8601|null),
    `reason` (str).
    """
    if is_disabled():
        return {
            "score": None,
            "percentile": None,
            "last_updated": None,
            "reason": "enrichment_disabled",
        }

    days = staleness_days if staleness_days is not None else DEFAULT_STALENESS_DAYS

    norm_cve = _normalize_cve_id(cve)
    if norm_cve is None:
        return {
            "score": None,
            "percentile": None,
            "last_updated": None,
            "reason": "no_cve",
        }

    last_polled = _epss_feed_last_polled()
    if last_polled is None:
        return {
            "score": None,
            "percentile": None,
            "last_updated": None,
            "reason": "cache_unavailable",
        }

    stale = _feed_is_stale(last_polled, days=days)
    # Defence-in-depth — `_lookup_epss_score` already swallows
    # exceptions, but a monkeypatched / mis-stubbed version (or a
    # future refactor) could raise. The resolver MUST NEVER raise:
    # the finding-emit path depends on this returning a block.
    try:
        score = _lookup_epss_score(norm_cve)
    except Exception as e:  # noqa: BLE001
        logger.debug("epss lookup raised: %s", e)
        score = None

    if stale:
        # Surface the score we *did* find but flag the staleness
        # so the wrapper knows to discount it.
        return {
            "score": score,
            "percentile": None,
            "last_updated": last_polled,
            "reason": "cache_stale",
        }

    # Percentile isn't cached today (the EPSS feed parser drops
    # column 3). Surface the score; mark percentile reason so
    # follow-up PRs know what to fix.
    return {
        "score": score,
        "percentile": None,
        "last_updated": last_polled,
        "reason": "ok" if score is not None else "no_score_for_cve",
    }
