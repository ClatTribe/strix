"""Tests for iter-21.3 `scan_authn_metadata` — deterministic
OIDC / OAuth / JWKS audit rules.

The audit is pure-Python field inspection on metadata JSON; we
exercise the rule functions directly rather than mocking the HTTP
client. The top-level `scan_authn_metadata` HTTP plumbing is
covered separately when network mocks are in place; here we pin
the RULE behaviour.
"""

from __future__ import annotations

import base64

from strix.tools.authn_metadata_audit.scan_authn_metadata import (
    _audit_jwks,
    _audit_oidc_metadata,
    _b64url_decoded_byte_length,
    _normalize_target,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rule_ids(findings: list[dict]) -> list[str]:
    return [f["rule_id"] for f in findings]


def _b64url_encode_bytes(b: bytes) -> str:
    """Encode raw bytes as JWK-style base64url (no padding)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# _normalize_target
# ---------------------------------------------------------------------------


def test_normalize_strips_path_and_lowercases_scheme() -> None:
    assert _normalize_target("https://app.example.com/api/v1") == "https://app.example.com/"


def test_normalize_adds_https_to_bare_host() -> None:
    assert _normalize_target("app.example.com") == "https://app.example.com/"


def test_normalize_preserves_port() -> None:
    assert _normalize_target("http://localhost:8080") == "http://localhost:8080/"


def test_normalize_rejects_bad_scheme() -> None:
    assert _normalize_target("ftp://x.com") is None


def test_normalize_rejects_empty() -> None:
    assert _normalize_target("") is None
    assert _normalize_target("   ") is None


# ---------------------------------------------------------------------------
# _b64url_decoded_byte_length
# ---------------------------------------------------------------------------


def test_b64url_length_2048_bit_rsa_modulus() -> None:
    n_bytes = b"\xff" * 256  # 256 bytes == 2048 bits
    encoded = _b64url_encode_bytes(n_bytes)
    assert _b64url_decoded_byte_length(encoded) == 256


def test_b64url_length_1024_bit_rsa_modulus() -> None:
    n_bytes = b"\xff" * 128
    encoded = _b64url_encode_bytes(n_bytes)
    assert _b64url_decoded_byte_length(encoded) == 128


def test_b64url_length_handles_garbage() -> None:
    assert _b64url_decoded_byte_length("not-base64$$") == 0
    assert _b64url_decoded_byte_length("") == 0


# ---------------------------------------------------------------------------
# OIDC rule: alg: none
# ---------------------------------------------------------------------------


def test_alg_none_supported_emits_critical() -> None:
    meta = {
        "id_token_signing_alg_values_supported": ["RS256", "none", "ES256"],
    }
    findings = _audit_oidc_metadata(meta, source_url="https://x.com/oidc")
    assert "alg-none-supported" in _rule_ids(findings)
    crit = next(f for f in findings if f["rule_id"] == "alg-none-supported")
    assert crit["severity"] == "critical"
    assert crit["cwe"] == "CWE-347"


def test_alg_none_case_insensitive() -> None:
    meta = {"id_token_signing_alg_values_supported": ["NONE"]}
    assert "alg-none-supported" in _rule_ids(
        _audit_oidc_metadata(meta, source_url="x"),
    )


def test_strong_algs_only_no_alg_none_finding() -> None:
    meta = {"id_token_signing_alg_values_supported": ["RS256", "ES256"]}
    assert "alg-none-supported" not in _rule_ids(
        _audit_oidc_metadata(meta, source_url="x"),
    )


# ---------------------------------------------------------------------------
# OIDC rule: PKCE
# ---------------------------------------------------------------------------


def test_pkce_missing_emits_medium() -> None:
    meta: dict = {}
    findings = _audit_oidc_metadata(meta, source_url="x")
    assert "pkce-not-supported" in _rule_ids(findings)
    assert next(
        f for f in findings if f["rule_id"] == "pkce-not-supported"
    )["severity"] == "medium"


def test_pkce_plain_only_emits_low() -> None:
    meta = {"code_challenge_methods_supported": ["plain"]}
    findings = _audit_oidc_metadata(meta, source_url="x")
    assert "pkce-s256-missing" in _rule_ids(findings)
    assert "pkce-not-supported" not in _rule_ids(findings)


def test_pkce_s256_present_no_finding() -> None:
    meta = {"code_challenge_methods_supported": ["S256"]}
    findings = _audit_oidc_metadata(meta, source_url="x")
    assert "pkce-not-supported" not in _rule_ids(findings)
    assert "pkce-s256-missing" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# OIDC rule: deprecated grants
# ---------------------------------------------------------------------------


def test_implicit_grant_advertised_emits_medium() -> None:
    meta = {"grant_types_supported": ["authorization_code", "implicit"]}
    findings = _audit_oidc_metadata(meta, source_url="x")
    assert "implicit-flow-advertised" in _rule_ids(findings)


def test_password_grant_advertised_emits_medium() -> None:
    meta = {"grant_types_supported": ["password"]}
    findings = _audit_oidc_metadata(meta, source_url="x")
    assert "password-grant-advertised" in _rule_ids(findings)


def test_modern_grants_no_finding() -> None:
    meta = {
        "grant_types_supported": ["authorization_code", "refresh_token"],
    }
    rids = _rule_ids(_audit_oidc_metadata(meta, source_url="x"))
    assert "implicit-flow-advertised" not in rids
    assert "password-grant-advertised" not in rids


# ---------------------------------------------------------------------------
# OIDC rule: client auth none
# ---------------------------------------------------------------------------


def test_client_auth_none_emits_low() -> None:
    meta = {"token_endpoint_auth_methods_supported": ["client_secret_basic", "none"]}
    findings = _audit_oidc_metadata(meta, source_url="x")
    assert "client-auth-none" in _rule_ids(findings)


# ---------------------------------------------------------------------------
# OIDC rule: request_uri SSRF
# ---------------------------------------------------------------------------


def test_request_uri_supported_emits_medium() -> None:
    meta = {"request_uri_parameter_supported": True}
    findings = _audit_oidc_metadata(meta, source_url="x")
    assert "request-uri-supported" in _rule_ids(findings)
    assert next(
        f for f in findings if f["rule_id"] == "request-uri-supported"
    )["cwe"] == "CWE-918"


def test_request_uri_false_no_finding() -> None:
    meta = {"request_uri_parameter_supported": False}
    assert "request-uri-supported" not in _rule_ids(
        _audit_oidc_metadata(meta, source_url="x"),
    )


# ---------------------------------------------------------------------------
# JWKS rule: HMAC key leaked
# ---------------------------------------------------------------------------


def test_jwks_hmac_kty_oct_emits_critical() -> None:
    jwks = {
        "keys": [
            {
                "kty": "oct",
                "k": "c2VjcmV0",  # b64url("secret")
                "kid": "hmac-key-1",
                "use": "sig",
                "alg": "HS256",
            },
        ],
    }
    findings = _audit_jwks(jwks, source_url="https://x.com/jwks.json")
    assert "jwks-hmac-key-leaked" in _rule_ids(findings)
    crit = next(f for f in findings if f["rule_id"] == "jwks-hmac-key-leaked")
    assert crit["severity"] == "critical"
    assert crit["cwe"] == "CWE-321"


def test_jwks_hmac_kty_without_k_no_finding() -> None:
    """`kty=oct` without a `k` member is a JWS verification-only
    key reference, not a leaked secret."""
    jwks = {"keys": [{"kty": "oct", "kid": "k1"}]}
    assert "jwks-hmac-key-leaked" not in _rule_ids(
        _audit_jwks(jwks, source_url="x"),
    )


# ---------------------------------------------------------------------------
# JWKS rule: weak RSA
# ---------------------------------------------------------------------------


def test_jwks_rsa_1024_emits_high() -> None:
    n_bytes = b"\xff" * 128  # 1024 bits
    jwks = {
        "keys": [
            {"kty": "RSA", "n": _b64url_encode_bytes(n_bytes), "e": "AQAB", "kid": "k"},
        ],
    }
    findings = _audit_jwks(jwks, source_url="x")
    assert "jwks-weak-rsa-key" in _rule_ids(findings)


def test_jwks_rsa_2048_no_finding() -> None:
    n_bytes = b"\xff" * 256
    jwks = {
        "keys": [
            {"kty": "RSA", "n": _b64url_encode_bytes(n_bytes), "e": "AQAB", "kid": "k"},
        ],
    }
    assert "jwks-weak-rsa-key" not in _rule_ids(
        _audit_jwks(jwks, source_url="x"),
    )


# ---------------------------------------------------------------------------
# JWKS rule: weak curves
# ---------------------------------------------------------------------------


def test_jwks_ec_p192_emits_high() -> None:
    jwks = {"keys": [{"kty": "EC", "crv": "P-192", "kid": "k", "x": "x", "y": "y"}]}
    findings = _audit_jwks(jwks, source_url="x")
    assert "jwks-weak-curve" in _rule_ids(findings)


def test_jwks_ec_p256_no_finding() -> None:
    jwks = {"keys": [{"kty": "EC", "crv": "P-256", "kid": "k", "x": "x", "y": "y"}]}
    assert "jwks-weak-curve" not in _rule_ids(
        _audit_jwks(jwks, source_url="x"),
    )


# ---------------------------------------------------------------------------
# JWKS rule: missing kid
# ---------------------------------------------------------------------------


def test_jwks_no_kid_emits_low() -> None:
    n_bytes = b"\xff" * 256
    jwks = {"keys": [{"kty": "RSA", "n": _b64url_encode_bytes(n_bytes), "e": "AQAB"}]}
    findings = _audit_jwks(jwks, source_url="x")
    assert "jwks-no-kid" in _rule_ids(findings)


# ---------------------------------------------------------------------------
# Edge cases — never raises on malformed input
# ---------------------------------------------------------------------------


def test_audit_handles_empty_metadata() -> None:
    findings = _audit_oidc_metadata({}, source_url="x")
    # Empty metadata → only the `pkce-not-supported` rule fires
    # (PKCE absence is the only "default" finding for empty docs).
    assert _rule_ids(findings) == ["pkce-not-supported"]


def test_audit_handles_garbage_jwks() -> None:
    """Audit must not raise on shape-violating JWKS."""
    assert _audit_jwks({}, source_url="x") == []
    assert _audit_jwks({"keys": "not a list"}, source_url="x") == []
    assert _audit_jwks({"keys": [None, "x", 42]}, source_url="x") == []


def test_audit_handles_garbage_oidc_metadata() -> None:
    """Audit must not raise on shape-violating OIDC metadata."""
    meta = {
        "id_token_signing_alg_values_supported": "not a list",
        "grant_types_supported": None,
        "code_challenge_methods_supported": 42,
    }
    findings = _audit_oidc_metadata(meta, source_url="x")
    # Falls through gracefully; only the PKCE-not-supported rule
    # fires because the field isn't a list.
    assert "pkce-not-supported" in _rule_ids(findings)
