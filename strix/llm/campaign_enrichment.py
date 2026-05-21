"""Active-campaign threat-intel enrichment — iter-21.2.

## Why this exists

Wiz Threat Center, Mandiant Attack Surface Management, and
Microsoft Defender External Attack Surface Management all
correlate detected CVEs with currently-active attacker campaigns
("this Spring Boot version is being hit by APT-X this week").
That correlation costs $50k+/yr at enterprise tiers. The data
itself is largely free: AlienVault OTX, MISP community feeds,
and OSS aggregators like CIRCL OSINT publish campaign / pulse
data with CVE references.

This module surfaces that data on every emitted finding as a
structured `campaigns` block, mirroring the KEV/EPSS enrichment
in `kev_enrichment.py` / `epss_enrichment.py`. The block lists
campaigns that reference the finding's CVE; severity is nudged
up one tier when at least one high-severity campaign is matched.

The campaign poller (`strix/threat_intel/feeds/otx.py` et al)
writes into the `campaigns` + `campaign_cve_links` tables. This
module only reads.

## Block shape on findings

```json
"campaigns": {
  "matched_pulse_count": 3,
  "matched_pulses": [
    {
      "campaign_id": "otx:65f6...",
      "source": "otx",
      "name": "APT-X targeting Spring Boot RCE",
      "author": "AlienVault",
      "last_seen": "2026-05-19T14:21:00Z",
      "severity": "high",
      "references": ["https://otx.alienvault.com/pulse/65f6..."]
    },
    ...
  ],
  "highest_campaign_severity": "high",
  "sources_seen": ["otx", "misp"],
  "last_updated": "2026-05-21T...",   // feed last_polled (most recent across sources)
  "reason": "ok"                      // ok | no_cve | not_in_campaigns | cache_stale | cache_unavailable | enrichment_disabled
}
```

The block is ALWAYS present on a finding (mirrors the EPSS/KEV
attestation discipline). `matched_pulse_count` is `0` when the
CVE isn't on any active campaign in cache — distinct from
`cache_unavailable` (cache itself isn't reachable).

## Severity nudge

`maybe_nudge_severity_for_campaign(current, block)` bumps low/info
findings to medium AND medium findings to high when at least one
matched campaign is severity ≥ high. Conservative: doesn't push
findings to critical (the KEV path is reserved for that — KEV is
a stricter signal). Records a one-line reasoning_trace entry
naming the most-active campaign.

## Kill switch

`STRIX_CAMPAIGN_ENRICHMENT_DISABLED=1` short-circuits both the
block resolver AND the severity-nudge path, for air-gapped envs
where no campaign feed is reachable.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any


logger = logging.getLogger(__name__)


# CISA KEV updates weekly; OTX pulses update continuously. Use a
# 14-day window since OTX users may not update their pulse
# subscriptions as aggressively as CISA's catalog. Operators can
# tighten this for their environment.
DEFAULT_STALENESS_DAYS = 14


_CVE_ID_RE = re.compile(r"\bCVE[- ]?(\d{4})[- ]?(\d{4,})\b", re.IGNORECASE)


# Severity ranking matches `kev_enrichment._SEVERITY_RANK`.
_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
    "unknown": 5,
}


def is_disabled() -> bool:
    """`STRIX_CAMPAIGN_ENRICHMENT_DISABLED=1` short-circuits."""
    return os.environ.get(
        "STRIX_CAMPAIGN_ENRICHMENT_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _normalize_cve_id(cve: Any) -> str | None:
    """Pull a canonical `CVE-YYYY-N` from a free-form string.
    Same shape as `kev_enrichment._normalize_cve_id`."""
    if cve is None or not isinstance(cve, str):
        return None
    m = _CVE_ID_RE.search(cve)
    if not m:
        return None
    return f"CVE-{m.group(1)}-{m.group(2)}"


def _campaign_feeds_last_polled() -> str | None:
    """Return the most-recent `last_polled` across all known
    campaign feeds (`otx`, `misp`, `mandiant`, `recorded_future`).
    None when the cache is unavailable or no campaign feed has
    polled. Picking the most-recent matches the user-visible
    statement "the campaign data is as fresh as the freshest
    feed we have."
    """
    try:
        from strix.threat_intel.cache import fetch_feed_meta
    except Exception:  # noqa: BLE001
        return None
    try:
        rows = fetch_feed_meta() or []
    except Exception as e:  # noqa: BLE001
        logger.debug("campaign feed_meta fetch failed: %s", e)
        return None
    candidates: list[str] = []
    known = {"otx", "misp", "mandiant", "recorded_future"}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = (row.get("feed_name") or "").lower()
        if name in known:
            lp = row.get("last_polled")
            if isinstance(lp, str) and lp:
                candidates.append(lp)
    if not candidates:
        return None
    # Strings are ISO-8601 lexically sortable when zone is consistent.
    return max(candidates)


def _feed_is_stale(last_polled: str | None, *, days: int) -> bool:
    """Mirror of `kev_enrichment._feed_is_stale`. Conservative —
    unparseable / None → stale.
    """
    if not last_polled:
        return True
    try:
        from datetime import datetime, timezone
        s = last_polled.rstrip("Z")
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
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
        logger.debug("campaign feed-staleness parse failed: %s", e)
        return True


def _lookup_campaigns(cve_id: str, *, limit: int = 25) -> list[dict[str, Any]]:
    """Resolve campaigns linked to a CVE. Returns [] on any cache
    error — caller distinguishes "no campaigns" from "cache broken"
    via the parallel `_campaign_feeds_last_polled` check.
    """
    try:
        from strix.threat_intel.cache import fetch_campaigns_for_cve
    except Exception:  # noqa: BLE001
        return []
    try:
        return fetch_campaigns_for_cve(cve_id, limit=limit) or []
    except Exception as e:  # noqa: BLE001
        logger.debug("fetch_campaigns_for_cve(%s) failed: %s", cve_id, e)
        return []


def _highest_severity(campaigns: list[dict[str, Any]]) -> str | None:
    """Return the most-severe severity across the given campaigns.
    Unknown / missing severities don't participate (treated as
    weaker-than-low for ranking purposes). Non-dict entries are
    silently skipped — the resolver may receive garbage from a
    misbehaving feed parser; never raise here.
    """
    best: tuple[int, str] | None = None
    for c in campaigns:
        if not isinstance(c, dict):
            continue
        sev = (c.get("severity") or "").lower().strip()
        if sev not in _SEVERITY_RANK:
            continue
        rank = _SEVERITY_RANK[sev]
        if best is None or rank < best[0]:
            best = (rank, sev)
    return best[1] if best else None


def resolve_campaign_block(
    *,
    cve: str | None,
    staleness_days: int | None = None,
) -> dict[str, Any]:
    """Build the `campaigns` block for a finding's CVE id. Always
    returns a dict (same "we tried" attestation discipline as KEV /
    EPSS).

    Args:
      cve: the finding's CVE field (may be free-form, or None).
      staleness_days: override the feed-staleness threshold
        (default 14 days; campaigns age faster than KEV).

    Returns dict with keys: `matched_pulse_count`, `matched_pulses`,
    `highest_campaign_severity`, `sources_seen`, `last_updated`,
    `reason`.
    """
    if is_disabled():
        return {
            "matched_pulse_count": 0,
            "matched_pulses": [],
            "highest_campaign_severity": None,
            "sources_seen": [],
            "last_updated": None,
            "reason": "enrichment_disabled",
        }

    days = staleness_days if staleness_days is not None else DEFAULT_STALENESS_DAYS

    norm_cve = _normalize_cve_id(cve)
    if norm_cve is None:
        return {
            "matched_pulse_count": 0,
            "matched_pulses": [],
            "highest_campaign_severity": None,
            "sources_seen": [],
            "last_updated": None,
            "reason": "no_cve",
        }

    last_polled = _campaign_feeds_last_polled()
    if last_polled is None:
        return {
            "matched_pulse_count": 0,
            "matched_pulses": [],
            "highest_campaign_severity": None,
            "sources_seen": [],
            "last_updated": None,
            "reason": "cache_unavailable",
        }

    stale = _feed_is_stale(last_polled, days=days)
    try:
        campaigns = _lookup_campaigns(norm_cve)
    except Exception as e:  # noqa: BLE001
        logger.debug("campaign lookup raised: %s", e)
        campaigns = []

    # Trim each campaign down to the fields the block exposes —
    # we don't want to bloat the finding with feed-internal noise.
    trimmed: list[dict[str, Any]] = []
    sources_seen: set[str] = set()
    for c in campaigns:
        if not isinstance(c, dict):
            continue
        src = (c.get("source") or "").strip().lower()
        if src:
            sources_seen.add(src)
        trimmed.append({
            "campaign_id": c.get("campaign_id"),
            "source": src or None,
            "name": c.get("name"),
            "author": c.get("author"),
            "last_seen": c.get("last_seen"),
            "first_seen": c.get("first_seen"),
            "severity": c.get("severity"),
            "references": (c.get("references") or [])[:5],
        })

    highest = _highest_severity(campaigns)
    reason = (
        "cache_stale"
        if stale and trimmed
        else ("not_in_campaigns" if not trimmed else "ok")
    )

    return {
        "matched_pulse_count": len(trimmed),
        "matched_pulses": trimmed,
        "highest_campaign_severity": highest,
        "sources_seen": sorted(sources_seen),
        "last_updated": last_polled,
        "reason": reason,
    }


def maybe_nudge_severity_for_campaign(
    *,
    current_severity: str | None,
    campaign_block: dict[str, Any],
) -> tuple[str | None, str | None]:
    """If at least one matched campaign has severity ≥ high AND
    the current finding severity is below high, bump it up one
    tier. Returns `(new_severity, reasoning_line)`.

    Conservative: stops at high (doesn't push to critical — that's
    the KEV path's territory; campaign correlation is a softer
    signal). Skips when listing is missing / stale / disabled.

    Tier nudge:
      info / informational / low  →  medium
      medium                       →  high
      high  / critical             →  (no change)
    """
    if is_disabled():
        return None, None
    if not isinstance(campaign_block, dict):
        return None, None
    if campaign_block.get("reason") not in ("ok",):
        # `cache_stale` could be ok-ish but we want fresh data
        # for severity changes — operator can re-poll.
        return None, None
    highest = (campaign_block.get("highest_campaign_severity") or "").lower()
    if highest not in ("critical", "high"):
        # Only escalate when the matched campaigns themselves are
        # high-severity. Low / medium campaigns just inform the
        # finding via the block — don't bump severity.
        return None, None
    cur = (current_severity or "").lower().strip()
    cur_rank = _SEVERITY_RANK.get(cur, 5)
    # Don't escalate things already at high or critical.
    if cur_rank <= _SEVERITY_RANK["high"]:
        return None, None
    # Pick the new tier — one step up.
    bump = {
        "medium": "high",
        "low": "medium",
        "info": "medium",
        "informational": "medium",
        "unknown": "medium",
    }
    new_sev = bump.get(cur)
    if new_sev is None:
        return None, None

    matched = campaign_block.get("matched_pulses") or []
    primary = matched[0] if matched else {}
    name = primary.get("name") or "an unnamed active campaign"
    src = primary.get("source") or "campaign feed"
    line = (
        f"Severity nudged to `{new_sev}`: matched active campaign "
        f"`{name}` (source: {src}) referencing this CVE — see "
        "`campaigns` block for full pulse list."
    )
    return new_sev, line
