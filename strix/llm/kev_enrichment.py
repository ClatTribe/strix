"""CISA KEV enrichment for emitted findings — iter-21.1.

## Why this exists

CISA's Known Exploited Vulnerabilities catalog [1] is the
single most-actionable signal in vulnerability triage: every CVE
in the catalog has confirmed in-the-wild exploitation, with a
short, hard remediation deadline imposed on US federal civilian
agencies. Modern commercial scanners (Trivy 2023+, Snyk via
Mandiant feed, Wiz, Tenable VPR, Qualys TruRisk) all promote
KEV-matched findings ahead of pure-CVSS ranking.

Strix already polls the KEV catalog daily into the threat-intel
cache (`strix/threat_intel/feeds/kev.py`). SCA + container scans
look it up and tag findings. This module surfaces that data on
EVERY emitted finding as a structured `kev` block, mirroring the
EPSS enrichment in `epss_enrichment.py` — so the auto-emit path
in `tracer.add_vulnerability_report` no longer has to rely on
the calling tool remembering to look up KEV.

## Block shape on findings

```json
"kev": {
  "listed": true,                          // bool or null
  "date_added": "2024-03-15",              // ISO-8601 or null
  "due_date": "2024-04-05",                // ISO-8601 or null
  "known_ransomware_use": "Known",         // "Known" | "Unknown" | null
  "vendor_project": "Apache",              // string or null
  "product": "Tomcat",                     // string or null
  "vulnerability_name": "Apache Tomcat RCE",
  "short_description": "Tomcat allows ...",
  "required_action": "Apply updates per vendor instructions.",
  "last_updated": "2026-05-21T...",        // feed last_polled ISO-8601 or null
  "reason": "ok"                           // ok | no_cve | not_in_kev | cache_stale | cache_unavailable
}
```

The block is ALWAYS present on a finding with the same "we tried"
attestation discipline as `epss`. When KEV is missing for legit
reasons (`no_cve`, `not_in_kev`) the block reports it explicitly;
when the cache is broken (`cache_stale`, `cache_unavailable`) the
agent / auditor sees that explicitly too.

## Severity auto-promotion

In addition to the block, `kev_enrichment.maybe_promote_severity`
is called by the tracer: if `kev.listed=True` and current severity
is below `critical`, the finding is promoted to `critical` and the
reasoning_trace gets a one-line "promoted-by-kev" entry. This
unifies the severity-bump logic that previously had to be
re-implemented in every CVE-emitting tool (sca_lockfiles +
container_image had their own copies; nuclei_runner / sast did
not — that asymmetry is what this module closes).

## Recall safety

This module never affects WHETHER a finding gets emitted. It only
adds a read-only enrichment block + a single severity tier bump.
Failures fall through to a `reason: "cache_unavailable"` block;
the finding still lands at its original severity.

## Kill switch

`STRIX_KEV_ENRICHMENT_DISABLED=1` short-circuits to a constant
"disabled" block AND disables the severity-promotion path. Useful
for air-gapped envs where the KEV feed isn't reachable and the
attestation just records the absence.

[1] https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any


logger = logging.getLogger(__name__)


# Maximum age of the KEV feed before we mark lookups as
# `cache_stale`. CISA updates the catalog ~weekly; 7 days
# matches the EPSS staleness threshold.
DEFAULT_STALENESS_DAYS = 7


_CVE_ID_RE = re.compile(r"\bCVE[- ]?(\d{4})[- ]?(\d{4,})\b", re.IGNORECASE)


def is_disabled() -> bool:
    """`STRIX_KEV_ENRICHMENT_DISABLED=1` short-circuits the enricher."""
    return os.environ.get(
        "STRIX_KEV_ENRICHMENT_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _normalize_cve_id(cve: Any) -> str | None:
    """Pull a canonical `CVE-YYYY-N` from a free-form string.

    Mirrors `epss_enrichment._normalize_cve_id` so both blocks
    see the same canonical form across the same finding.
    """
    if cve is None:
        return None
    if not isinstance(cve, str):
        return None
    m = _CVE_ID_RE.search(cve)
    if not m:
        return None
    return f"CVE-{m.group(1)}-{m.group(2)}"


def _kev_feed_last_polled() -> str | None:
    """Return the KEV feed's `last_polled` ISO-8601 from
    `strix.threat_intel.cache.fetch_feed_meta`, or None when the
    cache is unavailable / has no KEV row.
    """
    try:
        from strix.threat_intel.cache import fetch_feed_meta
    except Exception:  # noqa: BLE001
        return None
    try:
        rows = fetch_feed_meta() or []
    except Exception as e:  # noqa: BLE001
        logger.debug("kev feed_meta fetch failed: %s", e)
        return None
    for row in rows:
        if not isinstance(row, dict):
            continue
        if (row.get("feed_name") or "").lower() == "kev":
            lp = row.get("last_polled")
            if isinstance(lp, str) and lp:
                return lp
    return None


def _feed_is_stale(last_polled: str | None, *, days: int) -> bool:
    """True when the KEV feed hasn't polled in >`days` days. Shares
    parsing with `epss_enrichment._feed_is_stale` — duplicated
    here to avoid coupling the two enrichers.
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
        logger.debug("kev feed-staleness parse failed: %s", e)
        return True


def _lookup_kev_record(cve_id: str) -> tuple[bool, dict[str, Any]]:
    """Resolve KEV listing for a canonical CVE id. Returns a
    `(listed, metadata)` tuple — `listed=False` means the CVE
    exists in the cache but isn't on the KEV catalog. Cache
    miss or lookup failure also returns `(False, {})`; the
    caller distinguishes by checking the cache-availability
    block separately.
    """
    try:
        from strix.threat_intel.lookup import get_cve
    except Exception:  # noqa: BLE001
        return False, {}
    try:
        rec = get_cve(cve_id)
    except Exception as e:  # noqa: BLE001
        logger.debug("get_cve(%s) failed: %s", cve_id, e)
        return False, {}
    if rec is None:
        return False, {}
    listed = bool(getattr(rec, "kev", False))
    if not listed:
        return False, {}
    meta = getattr(rec, "kev_meta", None) or {}
    if not isinstance(meta, dict):
        meta = {}
    return True, meta


def resolve_kev_block(
    *,
    cve: str | None,
    staleness_days: int | None = None,
) -> dict[str, Any]:
    """Build the iter-21.1 `kev` block for a finding's CVE id.
    Always returns a dict (per the same "we tried" attestation
    discipline that `resolve_epss_block` follows).

    Args:
      cve: the finding's CVE field (may be free-form text
        containing a CVE id, or None).
      staleness_days: override the feed-staleness threshold
        (default 7 days, matches the KEV catalog's weekly
        update cadence).

    Returns a dict with keys: `listed` (bool|null),
    `date_added`, `due_date`, `known_ransomware_use`,
    `vendor_project`, `product`, `vulnerability_name`,
    `short_description`, `required_action`, `last_updated`,
    `reason`.
    """
    if is_disabled():
        return {
            "listed": None,
            "date_added": None,
            "due_date": None,
            "known_ransomware_use": None,
            "vendor_project": None,
            "product": None,
            "vulnerability_name": None,
            "short_description": None,
            "required_action": None,
            "last_updated": None,
            "reason": "enrichment_disabled",
        }

    days = staleness_days if staleness_days is not None else DEFAULT_STALENESS_DAYS

    norm_cve = _normalize_cve_id(cve)
    if norm_cve is None:
        return {
            "listed": None,
            "date_added": None,
            "due_date": None,
            "known_ransomware_use": None,
            "vendor_project": None,
            "product": None,
            "vulnerability_name": None,
            "short_description": None,
            "required_action": None,
            "last_updated": None,
            "reason": "no_cve",
        }

    last_polled = _kev_feed_last_polled()
    if last_polled is None:
        return {
            "listed": None,
            "date_added": None,
            "due_date": None,
            "known_ransomware_use": None,
            "vendor_project": None,
            "product": None,
            "vulnerability_name": None,
            "short_description": None,
            "required_action": None,
            "last_updated": None,
            "reason": "cache_unavailable",
        }

    stale = _feed_is_stale(last_polled, days=days)
    try:
        listed, meta = _lookup_kev_record(norm_cve)
    except Exception as e:  # noqa: BLE001
        logger.debug("kev lookup raised: %s", e)
        listed, meta = False, {}

    block: dict[str, Any] = {
        "listed": listed,
        "date_added": meta.get("date_added") or meta.get("dateAdded"),
        "due_date": meta.get("due_date") or meta.get("dueDate"),
        "known_ransomware_use": (
            meta.get("known_ransomware_use")
            or meta.get("knownRansomwareCampaignUse")
        ),
        "vendor_project": meta.get("vendor_project") or meta.get("vendorProject"),
        "product": meta.get("product"),
        "vulnerability_name": (
            meta.get("vulnerability_name") or meta.get("vulnerabilityName")
        ),
        "short_description": (
            meta.get("short_description") or meta.get("shortDescription")
        ),
        "required_action": (
            meta.get("required_action") or meta.get("requiredAction")
        ),
        "last_updated": last_polled,
        "reason": "cache_stale" if stale else ("ok" if listed else "not_in_kev"),
    }
    return block


# Severity ranking used by `maybe_promote_severity`. Lower index =
# more severe so promotion compares with `<`.
_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
    "unknown": 5,
}


def maybe_promote_severity(
    *, current_severity: str | None, kev_block: dict[str, Any],
) -> tuple[str | None, str | None]:
    """If KEV-listed and current severity is below critical, promote
    to critical and return a one-line reasoning-trace entry.

    Returns `(new_severity, reasoning_line)`. Either value is None
    when no promotion happened (caller leaves the finding alone).

    Conservative: only promotes when `kev.listed` is explicitly
    True (not when the lookup is stale / unavailable / no_cve).
    The reasoning line is added to the finding's reasoning_trace
    so auditors can see WHY a finding moved up a tier.
    """
    if is_disabled():
        return None, None
    if not isinstance(kev_block, dict):
        return None, None
    if kev_block.get("listed") is not True:
        return None, None
    cur = (current_severity or "").lower().strip()
    cur_rank = _SEVERITY_RANK.get(cur, 5)
    if cur_rank <= _SEVERITY_RANK["critical"]:
        # Already critical (or higher); nothing to do.
        return None, None
    name = kev_block.get("vulnerability_name") or "this CVE"
    date_added = kev_block.get("date_added")
    ransomware = kev_block.get("known_ransomware_use")
    line = (
        f"Severity promoted to critical: CISA KEV lists `{name}` "
        f"as actively exploited"
        + (f" (added {date_added})" if date_added else "")
        + (
            " — known ransomware campaign use"
            if isinstance(ransomware, str)
            and ransomware.lower() == "known"
            else ""
        )
        + "."
    )
    return "critical", line
