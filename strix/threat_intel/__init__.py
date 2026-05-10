"""Threat-intelligence daemon (post-Phase-5 follow-up).

Local SQLite cache fed by periodic polls of public threat-intel
sources. Specialists + the lead-agent LLM tool query the cache for
"is component X version Y in any known CVE / actively-exploited
list?"

Sources (free, public, no auth):
  * **CISA KEV** — Known Exploited Vulnerabilities catalog. Updated
    weekly; the gold standard for "actively exploited in the wild
    RIGHT NOW."
  * **FIRST.org EPSS** — Exploit Prediction Scoring System;
    probability that each CVE will be exploited in the next 30 days.
  * **NVD CVE 2.0 API** — recent-window only (default: last 14 days);
    full historical fetch is opt-in via `--full`.

Architecture
------------

  cache.py     — SQLite schema + read/write helpers
  feeds/       — per-source pollers (idempotent, resume-from-last)
  lookup.py    — query API: `find_cves_for(component, version)` etc.
  refresh.py   — CLI: `python -m strix.threat_intel.refresh`
  tools.py     — LLM-facing `@register_tool` surface

Cache location: `$STRIX_THREAT_INTEL_CACHE` or `~/.cache/strix/threat_intel.db`.

Best-effort throughout: feed failures degrade gracefully (lookup
returns whatever is cached). Network is only touched in `feeds/*`
and `refresh.py`; everything else is local SQLite reads.

Public API (re-exported here for convenience):

  * `find_cves_for(component, version=None, ecosystem=None)` —
    returns matching CVE records.
  * `get_cve(cve_id)` — single CVE lookup.
  * `list_kev()` — all KEV entries.
  * `find_recently_exploited(days=30, min_epss=0.5)` — high-EPSS or
    KEV-recent entries.
  * `cache_status()` — feed freshness for debugging.
"""

from strix.threat_intel.lookup import (  # noqa: F401
    cache_status,
    find_cves_for,
    find_recently_exploited,
    get_cve,
    list_kev,
)
