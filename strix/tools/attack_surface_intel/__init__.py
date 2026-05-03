"""Shodan + Censys attack-surface intelligence.

Roadmap §10 threat-intelligence enrichment. For a domain or IP target,
queries Shodan + Censys to surface the attacker's-view of the asset's
internet exposure: open ports, service banners, software versions,
historical scan timestamps, and CVE matches. Complements the
deterministic recon tools (`reverse_ip_discovery` #23,
`domain_reputation` #63) with operational intelligence — "this IP has
RDP, MongoDB, and Redis open, plus Shodan has tagged it with
CVE-2024-XXXXX".
"""

from .attack_surface_intel import attack_surface_intel


__all__ = ["attack_surface_intel"]
