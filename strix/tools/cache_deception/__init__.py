"""Web cache deception prober.

Roadmap §7.2 web-app expert-pentester gap audit (🔴 critical).
Detects whether a CDN or front-end cache will cache an authenticated
response when the URL is suffixed with a static-asset extension —
the classic Omer Gil 2017 vector for harvesting other users' authed
content via a single attacker-prepared link.
"""

from .cache_deception_check import cache_deception_check


__all__ = ["cache_deception_check"]
