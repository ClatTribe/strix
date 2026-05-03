"""Have I Been Pwned domain breach lookup.

Roadmap §10 threat-intelligence enrichment. For a domain target,
queries HIBP's free public `breaches?domain=…` endpoint to surface
historical breaches that included email addresses at that domain.
Adds context to authentication findings — "users at this domain
were exposed in breach X 6 months ago" — and pairs naturally with
`org_fingerprint` (#16). No API key required for the public
breach-list endpoint.
"""

from .hibp_breach_check import hibp_breach_check


__all__ = ["hibp_breach_check"]
