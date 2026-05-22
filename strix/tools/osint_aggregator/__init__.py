"""iter-22.6 — OSINT aggregator. Wraps community OSS / free-tier
threat-intel feeds to surface commercial-equivalent capabilities
(brand monitoring, IoC correlation, active-exploitation signals)
that Cyble / Recorded Future / Mandiant ASM charge for.

Currently ships:

  * `scan_typosquats_dnstwist` — phishing/brand-impersonation
    domain discovery via dnstwist (CWE-1023).
  * `scan_iocs_for_target_threatfox` — abuse.ch ThreatFox IoC
    lookup (free, zero-auth) — does any IP / domain / hash
    appearing in the target's logs match active-malware
    campaign IoCs?

Deferred follow-ups (per `docs/L1-optimization.md §6 iter-22.6`):
ransomwatch (leak-site victim check), HIBP credential-leak,
GreyNoise community classification, CertStream live shadow-IT.
"""

from __future__ import annotations

from strix.tools.osint_aggregator.scan_iocs_for_target_threatfox import (  # noqa: F401
    scan_iocs_for_target_threatfox,
)
from strix.tools.osint_aggregator.scan_typosquats_dnstwist import (  # noqa: F401
    scan_typosquats_dnstwist,
)


__all__ = [
    "scan_iocs_for_target_threatfox",
    "scan_typosquats_dnstwist",
]
