"""`.well-known/` endpoint harvester.

Roadmap §7.3 expert-pentester gap audit. Modern domains have 5–15
well-known endpoints that leak architecture cleanly: security.txt,
openid-configuration, oauth-authorization-server, change-password,
host-meta, asset/app association files, etc. This tool probes the
standard set and emits info-findings on each hit.
"""

from .well_known import well_known_harvest


__all__ = ["well_known_harvest"]
