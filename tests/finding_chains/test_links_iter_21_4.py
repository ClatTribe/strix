"""Unit tests for iter-21.4 attack-chain linkers.

Each chain linker encodes a SPECIFIC exploit combination, not just
CWE family co-occurrence. The tests pin both:
  * positive: when the right combination fires, the link emits at
    the correct confidence.
  * negative: each component alone, mismatched targets, or
    unrelated findings do NOT emit a link.
"""

from __future__ import annotations

from strix.finding_chains.chain import Finding
from strix.finding_chains.links import (
    LINK_AUTH_BYPASS_VIA_METHOD_OVERRIDE,
    LINK_CORS_TO_SSRF_CHAIN,
    LINK_JWT_CONFUSION_CHAIN,
    link_auth_bypass_via_method_override,
    link_cors_reflection_to_ssrf_chain,
    link_jwt_confusion_chain,
)


def _f(**kwargs) -> Finding:
    return Finding(
        id=kwargs.get("id", "f"),
        title=kwargs.get("title", "X"),
        category=kwargs.get("category", "sqli"),
        severity=kwargs.get("severity", "high"),
        cwe=kwargs.get("cwe"),
        target=kwargs.get("target", ""),
        endpoint=kwargs.get("endpoint", ""),
        description=kwargs.get("description", ""),
        cve=kwargs.get("cve"),
        package=kwargs.get("package", ""),
        metadata=kwargs.get("metadata", {}),
    )


# ---------------------------------------------------------------------------
# CORS → SSRF chain
# ---------------------------------------------------------------------------


def test_cors_to_ssrf_chain_links_on_same_target() -> None:
    cors = _f(
        id="c-1",
        category="cors",
        title="CORS reflects attacker origin with allow-credentials: true",
        description=(
            "Access-Control-Allow-Origin echoed from `Origin` header"
        ),
        target="https://app.example.com/api",
    )
    ssrf = _f(
        id="s-1",
        category="ssrf",
        cwe="CWE-918",
        title="SSRF via image_url param",
        target="https://app.example.com/api",
    )
    links = link_cors_reflection_to_ssrf_chain([cors, ssrf])
    assert len(links) == 1
    assert links[0].link_type == LINK_CORS_TO_SSRF_CHAIN
    assert links[0].confidence == 0.9
    assert links[0].finding_a == "c-1"
    assert links[0].finding_b == "s-1"


def test_cors_to_ssrf_chain_no_link_when_targets_differ() -> None:
    cors = _f(
        id="c-1",
        category="cors",
        title="CORS reflects attacker origin",
        description="Access-Control-Allow-Origin reflects Origin",
        target="https://app1.example.com",
    )
    ssrf = _f(
        id="s-1",
        category="ssrf",
        cwe="CWE-918",
        target="https://different-app.example.org",
    )
    assert link_cors_reflection_to_ssrf_chain([cors, ssrf]) == []


def test_cors_to_ssrf_no_link_without_reflection_signal() -> None:
    """CORS finding that's NOT about origin reflection (e.g. just
    a static-origin misconfig with no dynamic Origin echo) should
    not chain. Carefully avoid trigger keywords: not "reflect"
    (substring of "reflective"), not "allow-credentials" (needs
    the hyphen), not "wildcard", not "echo"."""
    cors = _f(
        id="c-1",
        category="cors",
        title="CORS configured for static origin example.org",
        description="Hardcoded permitted origin — no dynamic behavior",
        target="https://app.example.com",
    )
    ssrf = _f(
        id="s-1", category="ssrf", cwe="CWE-918",
        target="https://app.example.com",
    )
    # Title/description don't contain the trigger second-set
    # substrings — no link.
    assert link_cors_reflection_to_ssrf_chain([cors, ssrf]) == []


def test_cors_to_ssrf_handles_cwe_345_alt_ssrf_cwe() -> None:
    cors = _f(
        id="c-1",
        category="cors",
        title="CORS reflects Origin",
        description="allow-credentials: true",
        target="https://app.example.com",
    )
    ssrf = _f(
        id="s-1", category="misconfig", cwe="CWE-345",
        target="https://app.example.com",
    )
    links = link_cors_reflection_to_ssrf_chain([cors, ssrf])
    assert len(links) == 1


def test_cors_to_ssrf_skips_unrelated_pairs() -> None:
    """Without an SSRF finding, no CORS chain regardless of how
    many CORS findings exist."""
    cors = _f(
        id="c-1",
        category="cors",
        title="CORS reflects Origin",
        description="reflective",
        target="https://x.com",
    )
    xss = _f(id="x-1", category="xss", cwe="CWE-79", target="https://x.com")
    assert link_cors_reflection_to_ssrf_chain([cors, xss]) == []


# ---------------------------------------------------------------------------
# JWT confusion chain
# ---------------------------------------------------------------------------


def test_jwt_confusion_alg_none_metadata_and_verifier() -> None:
    metadata = _f(
        id="m-1",
        category="authn_metadata",
        title="OIDC metadata advertises alg-none-supported",
        description="id_token_signing_alg_values_supported includes none",
        target="https://idp.example.com",
        cwe="CWE-347",
    )
    verifier = _f(
        id="j-1",
        category="jwt",
        title="JWT verifier accepts alg=none forged tokens",
        target="https://idp.example.com",
        cwe="CWE-347",
    )
    links = link_jwt_confusion_chain([metadata, verifier])
    assert len(links) == 1
    assert links[0].link_type == LINK_JWT_CONFUSION_CHAIN
    assert links[0].confidence == 0.95


def test_jwt_confusion_skips_when_target_differs() -> None:
    metadata = _f(
        id="m-1",
        category="authn_metadata",
        title="alg-none-supported",
        target="https://idp1.example.com",
    )
    verifier = _f(
        id="j-1",
        category="jwt",
        title="alg=none accepted",
        target="https://other.example.org",
    )
    assert link_jwt_confusion_chain([metadata, verifier]) == []


def test_jwt_confusion_hmac_key_leaked_chains_to_jwt_finding() -> None:
    leaked = _f(
        id="m-1",
        category="authn_metadata",
        title="jwks-hmac-key-leaked detected in /jwks.json",
        description="HMAC key with k member exposed",
        target="https://api.example.com",
    )
    jwt_protected = _f(
        id="j-1",
        category="auth",
        title="BOLA in /users/{id}",
        target="https://api.example.com",
    )
    links = link_jwt_confusion_chain([leaked, jwt_protected])
    assert len(links) == 1
    assert links[0].confidence == 0.95


def test_jwt_confusion_no_link_without_metadata_finding() -> None:
    """Verifier-side jwt finding alone doesn't chain — needs the
    metadata-side smoking gun."""
    verifier = _f(
        id="j-1",
        category="jwt",
        title="alg=none accepted",
        target="https://x.com",
    )
    assert link_jwt_confusion_chain([verifier]) == []


def test_jwt_confusion_no_link_when_metadata_has_other_rule() -> None:
    """Metadata finding about PKCE / implicit grant should not
    chain to a JWT finding — only `alg-none-supported` and
    `jwks-hmac-key-leaked` are chain anchors."""
    metadata = _f(
        id="m-1",
        category="authn_metadata",
        title="pkce-not-supported",
        target="https://x.com",
    )
    jwt = _f(
        id="j-1", category="jwt",
        title="JWT weak secret",
        target="https://x.com",
    )
    assert link_jwt_confusion_chain([metadata, jwt]) == []


# ---------------------------------------------------------------------------
# Auth-bypass via method override chain
# ---------------------------------------------------------------------------


def test_auth_bypass_chain_links_when_acl_and_override_present() -> None:
    acl = _f(
        id="a-1",
        category="bfla",
        title="BFLA at POST /admin/users",
        description="Role viewer invoked admin function",
        target="https://app.example.com",
    )
    mo = _f(
        id="m-1",
        category="misconfig",
        title="X-HTTP-Method-Override accepted",
        description="Server honors X-HTTP-Method-Override header",
        target="https://app.example.com",
    )
    links = link_auth_bypass_via_method_override([acl, mo])
    assert len(links) == 1
    assert links[0].link_type == LINK_AUTH_BYPASS_VIA_METHOD_OVERRIDE
    assert links[0].confidence == 0.85


def test_auth_bypass_chain_recognizes_underscore_method_param() -> None:
    acl = _f(
        id="a-1",
        category="bola",
        title="BOLA /admin/orders",
        description="Unauth access to admin order list",
        target="https://app.example.com",
    )
    mo = _f(
        id="m-1",
        category="misconfig",
        title="Framework accepts `_method=PATCH` override",
        description="`?_method=` query parameter rewrites HTTP verb",
        target="https://app.example.com",
    )
    links = link_auth_bypass_via_method_override([acl, mo])
    assert len(links) == 1


def test_auth_bypass_no_link_when_only_acl_finding() -> None:
    """ACL finding without a method-override hint doesn't chain."""
    acl = _f(
        id="a-1", category="bfla",
        title="BFLA at /admin/users",
        target="https://x.com",
    )
    assert link_auth_bypass_via_method_override([acl]) == []


def test_auth_bypass_no_link_when_targets_differ() -> None:
    acl = _f(
        id="a-1", category="bfla",
        title="BFLA /admin",
        target="https://app1.example.com",
    )
    mo = _f(
        id="m-1", category="misconfig",
        title="X-HTTP-Method-Override accepted",
        target="https://other.example.org",
    )
    assert link_auth_bypass_via_method_override([acl, mo]) == []


def test_auth_bypass_acl_finding_detected_by_path_substring() -> None:
    """Even when the finding category isn't bola/bfla/idor, an
    `/admin` path in the title triggers the ACL match."""
    acl = _f(
        id="a-1",
        category="info_disclosure",
        title="Verbose error on /admin/users",
        description="Stack trace leaked admin route",
        target="https://app.example.com",
    )
    mo = _f(
        id="m-1",
        category="misconfig",
        title="HTTP method override accepted",
        target="https://app.example.com",
    )
    links = link_auth_bypass_via_method_override([acl, mo])
    assert len(links) == 1


# ---------------------------------------------------------------------------
# Registry integration
# ---------------------------------------------------------------------------


def test_new_linkers_registered_in_registry() -> None:
    """All three iter-21.4 linkers must appear in LINKER_REGISTRY
    so the correlator runs them automatically."""
    from strix.finding_chains.links import LINKER_REGISTRY
    names = {f.__name__ for f in LINKER_REGISTRY}
    assert "link_cors_reflection_to_ssrf_chain" in names
    assert "link_jwt_confusion_chain" in names
    assert "link_auth_bypass_via_method_override" in names


def test_new_link_constants_distinct() -> None:
    """Link-type identifiers must be unique strings — wrapper UIs
    key off them."""
    assert LINK_CORS_TO_SSRF_CHAIN != LINK_JWT_CONFUSION_CHAIN
    assert LINK_JWT_CONFUSION_CHAIN != LINK_AUTH_BYPASS_VIA_METHOD_OVERRIDE
    assert LINK_AUTH_BYPASS_VIA_METHOD_OVERRIDE != LINK_CORS_TO_SSRF_CHAIN
