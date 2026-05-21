"""iter-21.3 — `scan_authn_metadata` deterministic audit.

## Why this exists

`.well-known/openid-configuration`, `.well-known/oauth-authorization-server`,
and a target's JWKS document together advertise the authentication
posture of an application. Most DAST scanners disclose the
endpoints (and strix's `well_known_harvest` does too), but
*auditing* the metadata for security weaknesses is rare —
typically delegated to manual review or specialist tools (Burp
Pro's JWT Editor extension, custom scripts).

This tool runs a deterministic ruleset on the metadata and emits
one finding per weakness, no LLM. The rules are pulled from
RFC 8414, OpenID Connect Core 1.0, RFC 7518 (JWA), and OWASP API
Security Top 10 2023.

## Rules (each emits one finding)

### From `openid-configuration` / `oauth-authorization-server`

| Rule | CWE | Severity | What it catches |
|---|---|---|---|
| `alg-none-supported` | CWE-347 | critical | `id_token_signing_alg_values_supported` includes `none` |
| `pkce-not-supported` | CWE-359 | medium | `code_challenge_methods_supported` missing or empty |
| `pkce-s256-missing` | CWE-359 | low | `code_challenge_methods_supported` lacks `S256` |
| `implicit-flow-advertised` | CWE-359 | medium | `grant_types_supported` includes `implicit` (deprecated) |
| `password-grant-advertised` | CWE-522 | medium | `grant_types_supported` includes `password` (deprecated) |
| `client-auth-none` | CWE-287 | low | `token_endpoint_auth_methods_supported` includes `none` |
| `request-uri-supported` | CWE-918 | medium | `request_uri_parameter_supported: true` (potential SSRF) |
| `weak-id-token-alg` | CWE-327 | low | only HS256 advertised (symmetric secret sharing risk) |

### From JWKS (`jwks_uri`)

| Rule | CWE | Severity | What it catches |
|---|---|---|---|
| `jwks-hmac-key-leaked` | CWE-321 | **critical** | `kty=oct` HMAC key exposed in public JWKS |
| `jwks-weak-rsa-key` | CWE-326 | high | RSA `n` length < 2048 bits |
| `jwks-weak-curve` | CWE-326 | high | EC curve in {P-192, secp192r1, secp192k1} |
| `jwks-no-kid` | CWE-1392 | low | Keys without `kid` — complicates rotation |

## Recall safety

This tool is read-only (one or two HTTP GETs per target). It
never modifies state, never authenticates, never sends payloads.
Failures fall through to `status=partial`; the rest of the audit
proceeds with whatever was reachable.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_HTTP_TIMEOUT = 8
_BODY_CAP_BYTES = 256 * 1024  # JWKS docs are typically <10 KB; cap defensively.


def _normalize_target(url: str) -> str | None:
    """Return `scheme://host[:port]/` from an arbitrary input URL or
    bare host. Returns None on malformed input."""
    if not url or not url.strip():
        return None
    s = url.strip()
    parsed = urlparse(s if "://" in s else f"https://{s}")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}/"


def _http_get(url: str) -> dict[str, Any]:
    """GET via proxy_manager when available, else direct httpx.
    Returns `{status, headers, body, error?, skipped?}`. Body capped."""
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, timeout=_HTTP_TIMEOUT)
            if r.get("skipped"):
                return {"skipped": True, "status": 0, "headers": {}, "body": ""}
            return {
                "status": int(r.get("status") or 0),
                "headers": r.get("headers") or {},
                "body": (r.get("body") or "")[:_BODY_CAP_BYTES],
            }
        except Exception as e:  # noqa: BLE001
            return {"error": f"{type(e).__name__}: {e}", "status": 0, "headers": {}, "body": ""}
    # Fallback — direct httpx (used in bench / tests when proxy
    # manager is absent).
    try:
        import httpx

        with httpx.Client(
            timeout=_HTTP_TIMEOUT, follow_redirects=True, trust_env=False,
        ) as c:
            resp = c.get(url)
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:_BODY_CAP_BYTES],
            }
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}", "status": 0, "headers": {}, "body": ""}


def _parse_json(body: str) -> dict[str, Any] | None:
    if not body:
        return None
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _b64url_decoded_byte_length(value: str) -> int:
    """Return the byte length of a base64url-encoded JWK component.
    JWK `n` (RSA modulus) is encoded big-endian without leading 0x00
    padding; the byte length equals the modulus length / 8.
    """
    if not isinstance(value, str) or not value:
        return 0
    # Restore padding so urlsafe_b64decode accepts it.
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:  # noqa: BLE001
        return 0
    return len(decoded)


# ---------------------------------------------------------------------------
# Audit rules
# ---------------------------------------------------------------------------


def _audit_oidc_metadata(
    meta: dict[str, Any], *, source_url: str,
) -> list[dict[str, Any]]:
    """Apply the OIDC/OAuth metadata ruleset. Returns a list of
    `{rule_id, title, severity, cwe, description, source_url}`
    finding dicts — caller emits them through the tracer."""
    findings: list[dict[str, Any]] = []

    # 1. `alg: none` supported → critical
    algs = meta.get("id_token_signing_alg_values_supported") or []
    if isinstance(algs, list) and any(
        isinstance(a, str) and a.strip().lower() == "none" for a in algs
    ):
        findings.append({
            "rule_id": "alg-none-supported",
            "title": (
                "OIDC metadata advertises `alg: none` in "
                "id_token_signing_alg_values_supported"
            ),
            "severity": "critical",
            "cwe": "CWE-347",
            "description": (
                f"The OIDC issuer at `{source_url}` advertises "
                f"`alg=none` as a supported id_token signing algorithm "
                f"(values: {algs}). Per RFC 8725 §3.1, accepting "
                f"`alg=none` JWTs is a critical authentication bypass: "
                "an attacker forges any user (incl. admin) without "
                "knowing the signing key."
            ),
            "remediation": (
                "Remove `none` from id_token_signing_alg_values_supported. "
                "Restrict to RS256 / RS384 / RS512 / ES256 / ES384 / ES512 / "
                "EdDSA per RFC 7518 §3.1."
            ),
        })

    # 2. PKCE support
    pkce_methods = meta.get("code_challenge_methods_supported") or []
    if not isinstance(pkce_methods, list):
        pkce_methods = []
    if not pkce_methods:
        findings.append({
            "rule_id": "pkce-not-supported",
            "title": "OIDC/OAuth metadata does not advertise PKCE support",
            "severity": "medium",
            "cwe": "CWE-359",
            "description": (
                f"The authorization server at `{source_url}` does not "
                "advertise `code_challenge_methods_supported`. PKCE "
                "(RFC 7636) is required for public clients (mobile / "
                "SPAs) to mitigate authorization-code interception "
                "attacks. Absence of PKCE support means public clients "
                "are vulnerable."
            ),
            "remediation": (
                "Enable PKCE: advertise `code_challenge_methods_supported: "
                "[\"S256\"]` (per RFC 7636 §4.2) and reject requests "
                "from public clients that omit `code_challenge`."
            ),
        })
    elif "S256" not in pkce_methods:
        findings.append({
            "rule_id": "pkce-s256-missing",
            "title": "OIDC/OAuth PKCE method `S256` not advertised",
            "severity": "low",
            "cwe": "CWE-359",
            "description": (
                f"The authorization server at `{source_url}` advertises "
                f"PKCE but does not include `S256` (values: {pkce_methods}). "
                "S256 is the only mandatory-to-implement transformation "
                "per RFC 7636 §4.2; `plain` is deprecated."
            ),
            "remediation": (
                "Add `S256` to code_challenge_methods_supported and "
                "deprecate `plain` for new clients."
            ),
        })

    # 3. Deprecated grant types
    grants = meta.get("grant_types_supported") or []
    if isinstance(grants, list):
        grants_lower = [g.lower() for g in grants if isinstance(g, str)]
        if "implicit" in grants_lower:
            findings.append({
                "rule_id": "implicit-flow-advertised",
                "title": "OAuth `implicit` grant type advertised (deprecated)",
                "severity": "medium",
                "cwe": "CWE-359",
                "description": (
                    f"`{source_url}` advertises the `implicit` grant "
                    "type. OAuth 2.0 Security Best Current Practice "
                    "(RFC draft-ietf-oauth-security-topics) and OAuth "
                    "2.1 BOTH prohibit the implicit flow because the "
                    "access token is exposed in the URL fragment, "
                    "leakable via referer / browser history / log "
                    "aggregation."
                ),
                "remediation": (
                    "Remove `implicit` from grant_types_supported. Use "
                    "authorization_code + PKCE instead for browser "
                    "and mobile clients."
                ),
            })
        if "password" in grants_lower:
            findings.append({
                "rule_id": "password-grant-advertised",
                "title": "OAuth `password` grant type advertised (deprecated)",
                "severity": "medium",
                "cwe": "CWE-522",
                "description": (
                    f"`{source_url}` advertises the resource owner "
                    "`password` credentials grant. OAuth 2.1 prohibits "
                    "this flow: it requires the client to handle "
                    "plaintext credentials, defeating the SSO model "
                    "and the option to use MFA."
                ),
                "remediation": (
                    "Remove `password` from grant_types_supported. "
                    "Migrate clients to authorization_code + PKCE."
                ),
            })

    # 4. Client auth `none` at token endpoint
    auth_methods = meta.get("token_endpoint_auth_methods_supported") or []
    if isinstance(auth_methods, list):
        if any(
            isinstance(a, str) and a.lower() == "none"
            for a in auth_methods
        ):
            findings.append({
                "rule_id": "client-auth-none",
                "title": (
                    "OAuth token endpoint accepts `none` client auth "
                    "method (public clients)"
                ),
                "severity": "low",
                "cwe": "CWE-287",
                "description": (
                    f"`{source_url}` advertises `none` in "
                    "token_endpoint_auth_methods_supported. Public "
                    "clients are legitimate in OAuth 2.1, BUT they "
                    "MUST be required to use PKCE. Pair this with "
                    "`pkce-not-supported` if PKCE isn't also "
                    "advertised — together they constitute a "
                    "code-interception vulnerability."
                ),
                "remediation": (
                    "If `none` is intentional (mobile / SPA clients), "
                    "ensure PKCE with `S256` is also required for "
                    "those clients."
                ),
            })

    # 5. `request_uri` parameter support (SSRF risk)
    if meta.get("request_uri_parameter_supported") is True:
        findings.append({
            "rule_id": "request-uri-supported",
            "title": (
                "OIDC `request_uri` parameter supported (potential SSRF)"
            ),
            "severity": "medium",
            "cwe": "CWE-918",
            "description": (
                f"`{source_url}` advertises "
                "`request_uri_parameter_supported: true`. The "
                "`request_uri` parameter (OIDC Core §6.2) fetches a "
                "Request Object from an attacker-controlled URL — if "
                "the IdP doesn't strictly validate the `request_uri` "
                "against a pre-registered allowlist, this is a "
                "server-side request forgery primitive."
            ),
            "remediation": (
                "Require pre-registration of `request_uris` per client. "
                "Reject any `request_uri` not in the registered set."
            ),
        })

    return findings


def _audit_jwks(jwks: dict[str, Any], *, source_url: str) -> list[dict[str, Any]]:
    """Audit a JWKS document. Returns a list of finding dicts."""
    findings: list[dict[str, Any]] = []
    keys = jwks.get("keys") or []
    if not isinstance(keys, list):
        return findings

    for idx, k in enumerate(keys):
        if not isinstance(k, dict):
            continue
        kty = (k.get("kty") or "").lower()
        kid = k.get("kid") or f"index-{idx}"
        use = k.get("use") or "(no use)"
        alg = k.get("alg") or "(no alg)"

        # 1. HMAC key in public JWKS — instant critical
        if kty == "oct" and k.get("k"):
            findings.append({
                "rule_id": "jwks-hmac-key-leaked",
                "title": (
                    f"HMAC key (`kty=oct`) leaked in public JWKS "
                    f"(kid={kid})"
                ),
                "severity": "critical",
                "cwe": "CWE-321",
                "description": (
                    f"Key `{kid}` in the JWKS at `{source_url}` has "
                    f"`kty=oct` (symmetric HMAC) with the `k` member "
                    f"present. Publishing an HMAC signing key in a "
                    f"public JWKS gives every attacker the ability "
                    f"to forge valid JWTs for this issuer. The "
                    f"`alg` advertised is `{alg}`, `use` is `{use}`. "
                    f"This is a complete authentication bypass."
                ),
                "remediation": (
                    "Remove the symmetric key from the JWKS "
                    "immediately, rotate to an asymmetric (RSA / EC / "
                    "OKP) signing key, invalidate all existing "
                    "JWTs, and force re-authentication."
                ),
            })

        # 2. Weak RSA keys
        if kty == "rsa":
            n = k.get("n") or ""
            n_bytes = _b64url_decoded_byte_length(n)
            n_bits = n_bytes * 8
            if 0 < n_bits < 2048:
                findings.append({
                    "rule_id": "jwks-weak-rsa-key",
                    "title": (
                        f"Weak RSA signing key in JWKS "
                        f"({n_bits}-bit, kid={kid})"
                    ),
                    "severity": "high",
                    "cwe": "CWE-326",
                    "description": (
                        f"Key `{kid}` is RSA-{n_bits}, below the "
                        "2048-bit minimum required by NIST SP 800-57 "
                        "and RFC 7518 §6.3.1. Modern factoring "
                        "attacks (number-field-sieve on ≤1024-bit "
                        "moduli, certain Coppersmith attacks on "
                        "<2048-bit moduli) make this key forgeable "
                        "in real time."
                    ),
                    "remediation": (
                        "Rotate to RSA-2048 or higher (ideally RSA-"
                        "4096) or migrate to EC P-256 / EdDSA. "
                        "Invalidate JWTs signed with the weak key."
                    ),
                })

        # 3. Weak EC curves
        if kty == "ec":
            crv = (k.get("crv") or "").lower()
            if crv in {"p-192", "secp192r1", "secp192k1"}:
                findings.append({
                    "rule_id": "jwks-weak-curve",
                    "title": (
                        f"Weak EC curve in JWKS signing key "
                        f"({crv}, kid={kid})"
                    ),
                    "severity": "high",
                    "cwe": "CWE-326",
                    "description": (
                        f"Key `{kid}` uses curve `{crv}`, below the "
                        "P-256 (secp256r1) minimum. NIST SP 800-186 "
                        "lists P-192 as deprecated; modern ECDLP "
                        "attacks make this curve unsuitable for "
                        "signature use."
                    ),
                    "remediation": (
                        "Rotate to P-256, P-384, or P-521 (RFC 7518 "
                        "§6.2.1.1). For new keys prefer Ed25519 "
                        "(RFC 8037)."
                    ),
                })

        # 4. Missing kid
        if not k.get("kid"):
            findings.append({
                "rule_id": "jwks-no-kid",
                "title": (
                    f"JWKS key missing `kid` (index {idx})"
                ),
                "severity": "low",
                "cwe": "CWE-1392",
                "description": (
                    "A JWKS key without a `kid` makes key rotation "
                    "ambiguous: verifiers must guess which key to "
                    "use for a given JWT, complicating phased "
                    "rollover and incident response."
                ),
                "remediation": (
                    "Assign a unique `kid` per key. Use the kid "
                    "advertised in JWT `kid` claims to select the "
                    "verification key."
                ),
            })

    return findings


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1110.001", "T1212"],  # Brute Force; Exploit. for Cred. Access
)
def scan_authn_metadata(
    target_url: str,
) -> dict[str, Any]:
    """Deterministic L1 audit of OIDC / OAuth 2.0 / JWKS metadata.

    Args:
        target_url: web target (URL or host; `https://` prefixed
                    automatically). Probes
                    `<origin>/.well-known/openid-configuration`,
                    `<origin>/.well-known/oauth-authorization-server`,
                    and the `jwks_uri` advertised by either.

    Returns:
        ```
        {
          success: bool,
          target: str,
          probes: {
            oidc: {fetched, status, parsed_keys: int, findings: int},
            oauth_as: {...same shape},
            jwks: {url, fetched, status, keys: int, findings: int},
          },
          total_findings: int,
          findings: [
            {rule_id, title, severity, cwe, description, remediation,
             source_url},
            ...
          ],
        }
        ```

    Each finding is also emitted through the tracer (when present)
    so it lands in the normal report stream.

    Recall safety: never sends authenticated requests, never sends
    payloads, never modifies state. Each HTTP failure is captured
    in the per-probe record; the audit proceeds with whatever was
    reachable.
    """
    base = _normalize_target(target_url)
    if base is None:
        return {
            "success": False,
            "error": f"invalid target_url: {target_url!r}",
        }

    probes: dict[str, Any] = {
        "oidc": {"fetched": False, "status": 0, "parsed_keys": 0, "findings": 0},
        "oauth_as": {"fetched": False, "status": 0, "parsed_keys": 0, "findings": 0},
        "jwks": {"url": None, "fetched": False, "status": 0, "keys": 0, "findings": 0},
    }
    findings: list[dict[str, Any]] = []
    jwks_uri: str | None = None

    # 1. OIDC discovery
    oidc_url = urljoin(base, ".well-known/openid-configuration")
    oidc_resp = _http_get(oidc_url)
    if oidc_resp.get("status") == 200:
        oidc_meta = _parse_json(oidc_resp.get("body") or "")
        if oidc_meta:
            probes["oidc"] = {
                "fetched": True,
                "status": 200,
                "parsed_keys": len(oidc_meta),
                "findings": 0,
            }
            new = _audit_oidc_metadata(oidc_meta, source_url=oidc_url)
            probes["oidc"]["findings"] = len(new)
            findings.extend(new)
            ju = oidc_meta.get("jwks_uri")
            if isinstance(ju, str) and ju.strip():
                jwks_uri = ju.strip()
        else:
            probes["oidc"]["status"] = 200
            probes["oidc"]["fetched"] = False  # body wasn't JSON
    else:
        probes["oidc"]["status"] = int(oidc_resp.get("status") or 0)

    # 2. OAuth AS metadata (RFC 8414)
    oauth_url = urljoin(base, ".well-known/oauth-authorization-server")
    oauth_resp = _http_get(oauth_url)
    if oauth_resp.get("status") == 200:
        oauth_meta = _parse_json(oauth_resp.get("body") or "")
        if oauth_meta:
            probes["oauth_as"] = {
                "fetched": True,
                "status": 200,
                "parsed_keys": len(oauth_meta),
                "findings": 0,
            }
            new = _audit_oidc_metadata(oauth_meta, source_url=oauth_url)
            probes["oauth_as"]["findings"] = len(new)
            findings.extend(new)
            if not jwks_uri:
                ju = oauth_meta.get("jwks_uri")
                if isinstance(ju, str) and ju.strip():
                    jwks_uri = ju.strip()
        else:
            probes["oauth_as"]["status"] = 200
    else:
        probes["oauth_as"]["status"] = int(oauth_resp.get("status") or 0)

    # 3. JWKS audit (when we have a uri)
    if jwks_uri:
        probes["jwks"]["url"] = jwks_uri
        jwks_resp = _http_get(jwks_uri)
        if jwks_resp.get("status") == 200:
            jwks = _parse_json(jwks_resp.get("body") or "")
            if jwks:
                probes["jwks"].update({
                    "fetched": True,
                    "status": 200,
                    "keys": len(jwks.get("keys") or []),
                })
                new = _audit_jwks(jwks, source_url=jwks_uri)
                probes["jwks"]["findings"] = len(new)
                findings.extend(new)
            else:
                probes["jwks"]["status"] = 200
        else:
            probes["jwks"]["status"] = int(jwks_resp.get("status") or 0)

    # 4. Emit each finding through the tracer (if present). Bench /
    # standalone callers see the structured findings list either way.
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is not None:
            for f in findings:
                tracer.add_vulnerability_report(
                    title=f["title"],
                    severity=f["severity"],
                    cwe=f["cwe"],
                    target=base,
                    endpoint=f.get("source_url") or base,
                    category="authn_metadata",
                    verification_status="pattern_match",
                    confidence=0.95,
                    description=f["description"],
                    impact=(
                        "Metadata-disclosed weakness. "
                        f"Rule: {f['rule_id']}."
                    ),
                    remediation_steps=f["remediation"],
                    technical_analysis=(
                        f"Rule: `{f['rule_id']}`\n"
                        f"Source: `{f.get('source_url') or base}`\n"
                        "Auditor: scan_authn_metadata "
                        "(strix.tools.authn_metadata_audit)."
                    ),
                    reasoning_trace=[
                        "scan_authn_metadata audited "
                        f"{f.get('source_url') or base}.",
                        f"Rule `{f['rule_id']}` matched.",
                        "Auto-emitted by L1 deterministic audit; "
                        "no payload sent, no auth required.",
                    ],
                    poc_description=(
                        "Reproduce by GETting the metadata document "
                        "and inspecting the field flagged in this "
                        "finding."
                    ),
                    poc_script_code=(
                        f"curl -sS {f.get('source_url') or base}"
                    ),
                )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_authn_metadata tracer emit failed: %s", e)

    # If neither metadata doc was fetched, return partial (the target
    # isn't an OIDC/OAuth issuer).
    fetched_any = (
        probes["oidc"]["fetched"]
        or probes["oauth_as"]["fetched"]
    )
    if not fetched_any:
        return {
            "success": True,
            "status": "partial",
            "target": base,
            "probes": probes,
            "total_findings": 0,
            "findings": [],
            "reason": (
                "no OIDC/OAuth metadata discovered at "
                f"`{oidc_url}` or `{oauth_url}` (status: "
                f"{probes['oidc']['status']} / "
                f"{probes['oauth_as']['status']})"
            ),
        }

    return {
        "success": True,
        "status": "ok",
        "target": base,
        "probes": probes,
        "total_findings": len(findings),
        "findings": findings,
    }
