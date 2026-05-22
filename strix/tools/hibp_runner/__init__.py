"""iter-22.6 — Have-I-Been-Pwned (HIBP) credential-leak wrapper.

Per `docs/L1-optimization.md §6 iter-22.6` commercial-feed-
equivalent: HIBP is the OSS-side capability for the "org domain
credentials in breach dumps" check Cyble / Constella / DeHashed
charge for.

HIBP's API is RATE-LIMITED and requires a paid API key for
domain-search. We implement a defensive wrapper that gracefully
degrades to `partial` when no API key is configured (operator
opts in via `HIBP_API_KEY` env var) — the wrapper is shipped so
the integration exists; cost-of-credentials is a per-deployment
decision.
"""

from __future__ import annotations

from strix.tools.hibp_runner.scan_credential_leaks_hibp import (  # noqa: F401
    scan_credential_leaks_hibp,
)


__all__ = ["scan_credential_leaks_hibp"]
