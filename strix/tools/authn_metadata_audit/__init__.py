"""iter-21.3 — deterministic audit of OIDC / OAuth 2.0 / JWKS
authentication metadata exposed via `.well-known/` endpoints.

Where `well_known_harvest` (strix/tools/well_known/) discovers
the metadata as info-severity disclosures, this module AUDITS
the contents for security issues:

  * `alg: none` accepted in `id_token_signing_alg_values_supported`
  * HMAC keys (`kty=oct`) leaked in a published JWKS
  * Sub-2048-bit RSA keys / weak curves
  * `token_endpoint_auth_methods_supported: ["none"]` without PKCE
  * Deprecated grants (`password`, `implicit`) advertised
  * SHA-1 / MD5 signature algorithms

The audit is L1 deterministic — no LLM, no fuzzing. Pure JSON
field inspection on the metadata documents.
"""

from __future__ import annotations

from strix.tools.authn_metadata_audit.scan_authn_metadata import (  # noqa: F401
    scan_authn_metadata,
)


__all__ = ["scan_authn_metadata"]
