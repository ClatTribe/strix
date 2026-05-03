"""Nuclei template auto-update at scan start.

Roadmap §10 threat-intelligence enrichment. Pulls the latest Nuclei
templates from `projectdiscovery/nuclei-templates` upstream so CVE
coverage doesn't degrade between sandbox image rebuilds. Templates
ship daily; image-baked goes stale within weeks.
"""

from .nuclei_template_update import nuclei_template_update


__all__ = ["nuclei_template_update"]
