"""Finding verification (roadmap §8.2 row 3 — Verifier agent).

The Verifier specialist's tool: re-runs deterministic probes on
existing findings and updates `verification_status` to `verified`
or `could_not_verify` based on whether the original signal still
fires.

This is the deterministic-re-probe subset of the full Validator
agent (§17.1). It can verify finding categories whose probes are
cheap, side-effect-free, and self-contained:

- Information disclosure from `debug_endpoint_check` (#77)
- CORS misconfiguration from `cors_deep_check` (#78)
- Open redirect from `open_redirect_check` (#59)
- HTTP method tampering from `method_tamper_check` (#60)
- Host-header injection from `host_header_check` (#55)

Categories that need PoC re-execution (SQLi, XSS, RCE, complex
authz) are deferred to the future white-box→black-box Validator
described in §17.1.
"""

from .verify_findings import verify_findings


__all__ = ["verify_findings"]
