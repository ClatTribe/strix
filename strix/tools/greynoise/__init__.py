"""GreyNoise targeted-vs-noise classification.

Roadmap §10 expert-pentester gap audit (🔴 critical). Distinguishes
opportunistic-internet-noise IPs from targeted attackers — `noise:
true` means the IP is mass-scanning the entire internet (Shodan /
Censys / CensysBot / etc.); `noise: false + classification:
malicious` means a targeted scanner. Free API tier (without key);
RIOT API surfaces benign-known IPs (CDN edges, search-engine bots)
to suppress false positives.
"""

from .greynoise_classify import greynoise_classify


__all__ = ["greynoise_classify"]
