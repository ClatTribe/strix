"""iter-Q5.7 + Q5.7a — unified threat-intel query tool.

Per CLAUDE.md §1.5.7 — the FETCH EXTERNAL bucket. Collapses 4 existing
wrappers (cve_lookup + nvd_lookup + cve_intel_search + kev_diff_check)
behind one signature; adds a domain= route for passive DNS / WHOIS /
reputation (Q5.7a — closes Gap 3 from the consolidated proposal).
"""

from strix.tools.threat_intel.query_threat_intel import query_threat_intel

__all__ = ["query_threat_intel"]
