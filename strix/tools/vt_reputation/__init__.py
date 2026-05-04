"""VirusTotal IoC reputation lookup.

Roadmap §10 expert-pentester gap audit (🔴 critical). Multi-engine
consensus on hashes / IPs / domains / URLs across 70+ AV/EDR vendors.
Different signal from URLhaus / AbuseIPDB (single-source) — VT's
value is the *consensus* across many vendors. Free API tier
(`STRIX_VT_KEY`).
"""

from .vt_reputation import vt_reputation


__all__ = ["vt_reputation"]
