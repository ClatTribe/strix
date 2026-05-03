"""Domain / IP reputation lookups across free public blocklists.

Roadmap §10 threat-intelligence enrichment. Bundles 5 sources:
URLhaus (no key), Spamhaus DBL (DNS-RBL, no key), Spamhaus ZEN (DNS-RBL
for IPs, no key), Google Safe Browsing (key-gated), AbuseIPDB (IP only,
key-gated). High-signal context: a "clean" target with an IP on URLhaus
is a real finding (someone else compromised the shared host); a flagged
domain you own is an incident-response lead.
"""

from .domain_reputation import domain_reputation


__all__ = ["domain_reputation"]
