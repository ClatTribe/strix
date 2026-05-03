"""Fresh CVE intelligence via Perplexity.

Roadmap §10 threat-intelligence enrichment. Augments `cve_lookup`
(#61, OSV-backed) with fresh web-indexed content — vendor advisories
not yet in OSV, in-the-wild exploitation reports, recent PoCs. Uses
the Perplexity Sonar API (the same API key that gates `web_search`).
"""

from .cve_intel_search import cve_intel_search


__all__ = ["cve_intel_search"]
