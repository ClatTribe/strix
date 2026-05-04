"""CISA KEV proactive refresh + diff finding.

Roadmap §10 expert-pentester gap audit (🟡 important). Extends #9
(which lazy-loads KEV with a 24h cache) into a daily-scan workflow:
forces a refresh, compares against the prior cached snapshot, and
emits info findings for new KEV entries since the last scan.
"""

from .kev_diff_check import kev_diff_check


__all__ = ["kev_diff_check"]
