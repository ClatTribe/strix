"""`scan_auth_flow` — auth-aware specialist (roadmap §8.5 Phase 6).

Closes a class of manifest entries that ALL require authentication
to exercise: missing-auth-admin (admin section reachable post-auth),
idor-basket re-tested with another user's session, weak-jwt-handling
(needs a real JWT to mutate), ssrf-image-upload, etc.

Strategy
--------

Try a small ordered cohort against the login endpoint:

  1. **Default credentials** — well-known username/password pairs
     (`admin/admin`, `admin@juice-sh.op/admin123`, `root/root`,
     `test/test`, `guest/guest`, etc.). 16 pairs cover the
     overwhelming majority of CTF-shaped + neglected-app auth.
  2. **Self-registration** — POST to common signup paths
     (`/register`, `/api/Users`, `/auth/signup`) with a unique
     test-user payload. If signup succeeds, log in with the freshly-
     created creds.
  3. **Capture-on-success** — extract Set-Cookie cookies, JWTs from
     `Authorization` response header / JSON body fields (`token`,
     `accessToken`, `jwt`, `id_token`), and CSRF tokens from
     hidden inputs / response headers.

When auth succeeds:
  * Write the captured session into `SecurityContext.AuthState`
    under the relevant label (`anon`, `default-creds`, `registered-
    user`).
  * If default credentials succeeded, AUTO-EMIT a finding —
    `CWE-521 Weak Password Requirements` / `CWE-798 Hardcoded
    Credentials` (severity high — easiest credential bypass).
  * Surface the JWT (if captured) as a partial signal so the lead
    knows to invoke `jwt_audit` on it.

Limitations
-----------

  * No CAPTCHA / MFA bypass — if the login flow requires either,
    this specialist gracefully reports 'inconclusive' and the lead
    must handle manually.
  * Self-registration only fires if `try_register=True` (default
    True). On targets with strict signup gating (email
    verification, etc.), it's a no-op.
  * Doesn't follow OAuth / SAML redirect flows.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import string
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Default-credential cohort. Ordered by historical hit-rate against
# CTF-shaped / neglected-app login endpoints. Pairs are tried in
# sequence; first success wins.
def _load_user_supplied_credentials(
    extra_creds: list[tuple[str, str]] | list[list[str]] | None,
) -> list[tuple[str, str]]:
    """PR-β — assemble user-supplied credentials from the `extra_creds`
    arg AND the `STRIX_LOGIN_CREDS` env var.

    The env var is populated by `interface/main.py`'s `--login-creds`
    handler and survives the wrapper → sandbox boundary like the
    rest of the STRIX_* env contract. Format: JSON list of either
    `[username, password]` pairs OR `{"username": ..., "password": ...}`
    objects.

    `extra_creds` (the kwarg) takes precedence when both are set —
    a programmatic caller can override the wrapper's tenant config.

    Returns deduplicated `(username, password)` tuples. Invalid /
    malformed entries are silently dropped (logged at debug); we
    never let a parse error block scan_auth_flow from running the
    default corpus.
    """
    import json as _json

    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(u: object, p: object) -> None:
        if not isinstance(u, str) or not isinstance(p, str):
            return
        u_strip, p_strip = u.strip(), p.strip()
        if not u_strip or not p_strip:
            return
        key = (u_strip, p_strip)
        if key in seen:
            return
        seen.add(key)
        pairs.append(key)

    # 1. From the kwarg.
    if extra_creds:
        for entry in extra_creds:
            try:
                if isinstance(entry, dict):
                    _add(entry.get("username"), entry.get("password"))
                elif isinstance(entry, (tuple, list)) and len(entry) >= 2:
                    _add(entry[0], entry[1])
            except Exception:  # noqa: BLE001
                logger.debug("ignored malformed extra_creds entry: %r", entry)

    # 2. From the env var (set by interface/main.py from --login-creds).
    env_raw = (os.environ.get("STRIX_LOGIN_CREDS") or "").strip()
    if env_raw:
        try:
            parsed = _json.loads(env_raw)
            if isinstance(parsed, list):
                for entry in parsed:
                    if isinstance(entry, dict):
                        _add(entry.get("username"), entry.get("password"))
                    elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
                        _add(entry[0], entry[1])
        except (ValueError, TypeError) as e:
            logger.debug(
                "STRIX_LOGIN_CREDS not valid JSON list (%s); ignoring", e,
            )

    return pairs


_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    # Juice Shop in particular bakes admin@juice-sh.op/admin123 in.
    ("admin@juice-sh.op", "admin123"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "12345"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("test", "test123"),
    ("guest", "guest"),
    ("user", "user"),
    ("user", "password"),
    ("demo", "demo"),
    ("admin", "letmein"),
)


# JWT marker — base64url-encoded `{"alg":...}` header begins with `eyJ`.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def _build_login_body(
    *, email_field: str, password_field: str,
    email: str, password: str,
    body_template: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a login-shaped request body. Defaults to `{email, password}`
    but uses the caller's template (fills the right field names)."""
    if body_template:
        body = dict(body_template)
        body[email_field] = email
        body[password_field] = password
        return body
    return {email_field: email, password_field: password}


def _extract_jwt(body_text: str, headers: dict[str, str]) -> str | None:
    """Find a JWT in the response body (JSON field) or
    Authorization header."""
    # Headers first
    for hk, hv in headers.items():
        if not isinstance(hv, str):
            continue
        if hk.lower() in {"authorization", "x-auth-token", "x-access-token"}:
            m = _JWT_RE.search(hv)
            if m:
                return m.group(0)
    # JSON body fields
    if isinstance(body_text, str):
        try:
            data = json.loads(body_text)
        except Exception:  # noqa: BLE001
            data = None
        if isinstance(data, dict):
            # Common token-bearing field names
            for key in ("token", "accessToken", "access_token",
                        "jwt", "id_token", "idToken", "authToken"):
                v = data.get(key)
                if isinstance(v, str):
                    m = _JWT_RE.search(v)
                    if m:
                        return m.group(0)
                # Sometimes nested under "data" or "user"
                if isinstance(v, dict):
                    for inner_v in v.values():
                        if isinstance(inner_v, str):
                            m = _JWT_RE.search(inner_v)
                            if m:
                                return m.group(0)
        # Last resort: any JWT-shaped string in body
        m = _JWT_RE.search(body_text)
        if m:
            return m.group(0)
    return None


def _extract_cookies(headers: dict[str, str]) -> dict[str, str]:
    """Parse Set-Cookie response headers into name→value dict.
    Multiple cookies share name=value; semicolons separate attrs."""
    cookies: dict[str, str] = {}
    for hk, hv in headers.items():
        if hk.lower() != "set-cookie" or not isinstance(hv, str):
            continue
        # Split potential multi-cookie format. The proxy_manager dict
        # collapses repeats but Set-Cookie may still be a single value.
        for part in hv.split(","):
            # Each cookie's first `name=value` is what we want.
            m = re.match(r"\s*([A-Za-z0-9_\-]+)\s*=\s*([^;,\s]+)", part)
            if m:
                cookies[m.group(1)] = m.group(2)
    return cookies


def _is_login_success(status: int | None, body: str) -> bool:
    """Heuristic: a successful login returns 2xx AND the body either
    contains a token shape OR doesn't contain typical 'invalid'
    fragments."""
    if not isinstance(status, int) or not (200 <= status < 300):
        return False
    if not isinstance(body, str):
        return True
    body_lc = body.lower()
    # Strong negatives — even on 2xx, presence means failure
    for neg in ("invalid email", "invalid credential", "invalid login",
                "incorrect password", "wrong password", "authentication failed",
                "login failed", "unauthorized"):
        if neg in body_lc:
            return False
    # Strong positives
    if _JWT_RE.search(body):
        return True
    if any(k in body_lc for k in ('"token"', '"accesstoken"', '"jwt"',
                                   '"sessionid"', '"id_token"', '"success":true')):
        return True
    # Neutral: 2xx without negative markers, accept as success.
    return True


@register_specialist_tool(
    category="auth-flow-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,  # host execution; proxy_manager handles host.docker.internal → 127.0.0.1 fallback
    provenance="framework",
    mitre_techniques=["T1110.001"],  # Brute-Force: Password Guessing
)
def scan_auth_flow(
    *,
    login_url: str,
    method: str = "POST",
    email_field: str = "email",
    password_field: str = "password",
    body_template: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    label: str = "default-creds",
    try_register: bool = False,
    register_url: str | None = None,
    extra_creds: list[tuple[str, str]] | list[list[str]] | None = None,
) -> SpecialistResult:
    """Try a small default-credential cohort against the login URL,
    capture session on success, and write to SecurityContext.AuthState.

    Args:
        login_url: full login endpoint URL (e.g.
            `http://x/rest/user/login`).
        method: HTTP method. Default POST. (GET-via-querystring auth
            flows are rare; supported for Basic-auth-shaped logins.)
        email_field: form/JSON key for the username/email. Many apps
            use "username" or "user" or "login".
        password_field: form/JSON key for the password.
        body_template: optional baseline body. The specialist replaces
            `email_field` / `password_field` values per attempt; other
            fields are passed through.
        extra_headers: forwarded as-is.
        label: name to use when writing the captured session into
            `SecurityContext.AuthState`. Default `"default-creds"`.
        try_register: when True AND the default-creds cohort fails,
            attempt self-registration via `register_url` (or inferred
            common paths) and log in with the freshly-created creds.
        register_url: explicit signup endpoint when known. When None
            and `try_register=True`, the specialist tries a small set
            of common signup paths.
        extra_creds: Phase 3d / PR-β — user-supplied credentials to
            try BEFORE the built-in default corpus. Accepts a list of
            `(username, password)` tuples / 2-element lists. Wrappers
            populate this from a tenant-supplied "known creds for
            this target" UI input via the `STRIX_LOGIN_CREDS` env
            var; the lead can also pass `extra_creds=[...]` directly.
            Priority-1 attempts — if a user-supplied pair succeeds,
            we capture that session and report the success WITHOUT
            emitting a "default credentials accepted" finding (those
            are tenant-supplied creds, not exploitable defaults).

    Returns: SpecialistResult. On default-creds success, auto-emits
    a CWE-521 / CWE-798 finding. Always writes captured session
    (cookies + JWT) to SecurityContext.AuthState[label].
    """
    if not isinstance(login_url, str) or not login_url.strip():
        return SpecialistResult(status="error", error="login_url required")
    login_url = login_url.strip()

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager
        from strix.agents.security_context import (
            record_auth_state,
            record_endpoint,
            record_partial_signal,
        )

        pm = get_proxy_manager()
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"proxy_manager unavailable: {type(e).__name__}: {e}",
        )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    probe_count = 0

    headers = dict(extra_headers or {})
    headers.setdefault("Content-Type", "application/json")

    # PR-β / Phase 3d — assemble the credential cohort. Priority-1
    # is user-supplied creds (from `extra_creds=` arg OR the
    # `STRIX_LOGIN_CREDS` env JSON set by the wrapper / CLI's
    # `--login-creds`). Priority-2 is the built-in default
    # corpus. We track which set each pair came from so we can
    # decide whether to emit a "default credentials accepted"
    # finding (only for default-corpus hits — user-supplied
    # credentials are explicit tenant-provided values, not
    # exploitable defaults).
    user_creds = _load_user_supplied_credentials(extra_creds)
    cohort: list[tuple[str, str, str]] = [   # (email, password, source)
        *((u, p, "user_supplied") for u, p in user_creds),
        *((e, p, "default_corpus") for e, p in _DEFAULT_CREDS),
    ]

    # Phase 1 — credential brute force (user-supplied first).
    for email, password, _source in cohort:
        body_dict = _build_login_body(
            email_field=email_field, password_field=password_field,
            email=email, password=password,
            body_template=body_template,
        )
        body_str = json.dumps(body_dict)
        try:
            resp = pm.send_simple_request(
                method.upper(), login_url,
                headers=headers, body=body_str, timeout=15,
            )
            probe_count += 1
        except Exception as e:  # noqa: BLE001
            evidence.append(f"transport error ({email}): {e}")
            continue

        if "error" in resp and not resp.get("status_code"):
            continue

        status = resp.get("status_code")
        body = resp.get("body") or ""
        resp_headers = resp.get("headers") or {}

        if _is_login_success(status, body):
            jwt = _extract_jwt(body, resp_headers)
            cookies = _extract_cookies(resp_headers)

            # Write captured session to SecurityContext.
            record_auth_state(
                label=label,
                cookies=cookies or None,
                bearer=jwt,
                notes=f"Captured via default-creds: {email}/{password}",
            )

            # Surface JWT as partial signal so lead routes to jwt_audit.
            if jwt:
                record_partial_signal(
                    surface=f"login captured JWT (label={label})",
                    signal=f"JWT token bound to user {email}",
                    next_probe=f"jwt_audit on this token (alg=none / weak HMAC / kid manipulation)",
                    category_hint="jwt",
                )

                # Roadmap §8.5 Phase 7 — auto-invoke jwt_audit on the
                # captured token. Closes the `weak-jwt-handling`
                # manifest gap without depending on the lead's prompt
                # discipline. jwt_audit's static analyses (alg=none
                # detection in header, weak HMAC dictionary attack,
                # claims inspection) require no additional network
                # access, just the token. Active probes (test_
                # endpoint_url) use the same proxy_manager path that
                # scan_auth_flow already verified works, so we can
                # safely chain.
                try:
                    from strix.tools.jwt_audit.jwt_audit import jwt_audit as _jwt_audit_fn

                    _jwt_audit_fn(
                        token=jwt,
                        test_endpoint_url=login_url,
                        placement="auth_bearer",
                        method="GET",
                    )
                    evidence.append(
                        f"auto-invoked jwt_audit on captured JWT — "
                        f"any alg=none / weak-HMAC / kid-traversal "
                        f"findings will appear separately"
                    )
                except Exception as e:  # noqa: BLE001
                    logger.debug("scan_auth_flow: jwt_audit chain failed: %s", e, exc_info=True)

            # Emit a finding for default-creds success — but NOT
            # for user-supplied credentials. User-supplied creds
            # are explicit tenant-provided values; succeeding with
            # them just means we authenticated, not that we
            # exploited weak defaults.
            if _source == "default_corpus":
                try:
                    from strix.telemetry.tracer import get_global_tracer
                    tracer = get_global_tracer()
                except Exception:  # noqa: BLE001
                    tracer = None
            else:
                tracer = None
            try:
                if tracer is not None:
                    rid = tracer.add_vulnerability_report(
                        title=f"Default credentials accepted at {urlparse(login_url).path or login_url}",
                        severity="high",
                        cwe="CWE-521",
                        endpoint=login_url,
                        target=login_url,
                        category="auth",
                        verification_status="verified",
                        confidence=1.0,
                        description=(
                            f"The login endpoint at `{login_url}` accepts the "
                            f"default credential pair `{email}` / `{password}`. "
                            f"Default / well-known credentials are the most-"
                            f"exploited bug class on the internet — anyone "
                            f"with the source code (or a list) can log in as "
                            f"this user without further effort."
                        ),
                        impact=(
                            f"Authentication bypass via default credentials. "
                            f"An attacker logs in as `{email}` and gains "
                            f"whatever privileges that account holds. If "
                            f"this is an admin / root account, the attacker "
                            f"gets full control of the application — "
                            f"including all user data, configuration, and "
                            f"any privileged endpoints."
                        ),
                        technical_analysis=(
                            f"POST {login_url}\n"
                            f"Body: {{ {email_field}: \"{email}\", "
                            f"{password_field}: \"{password}\" }}\n"
                            f"Response: status_code={status}\n"
                            f"Captured session: cookies={list(cookies.keys())} "
                            f"jwt_present={bool(jwt)}"
                        ),
                        poc_description=(
                            f"1. Send POST request to {login_url} with body:\n"
                            f"   {{\"{email_field}\": \"{email}\", "
                            f"\"{password_field}\": \"{password}\"}}\n"
                            f"2. The server returns a session token / cookie.\n"
                            f"3. Use that token to access authenticated "
                            f"endpoints as the user."
                        ),
                        poc_script_code=(
                            f"curl -sS -X POST '{login_url}' \\\n"
                            f"  -H 'Content-Type: application/json' \\\n"
                            f"  --data-raw '{body_str}'"
                        ),
                        remediation_steps=(
                            "1. Remove or rotate all default credentials "
                            "before deployment.\n"
                            "2. Enforce strong password policies on user "
                            "registration (minimum length 12+, character-"
                            "class diversity, deny common-password "
                            "lists like rockyou.txt).\n"
                            "3. Implement account lockout / rate limiting "
                            "on the login endpoint to slow brute-force.\n"
                            "4. Add MFA for privileged accounts.\n"
                            "5. Audit production for any account using "
                            "predictable / leaked credentials and force "
                            "reset."
                        ),
                        cvss_breakdown={
                            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                            "S": "U", "C": "H", "I": "H", "A": "H",
                        },
                        reasoning_trace=[
                            f"Probed {len(_DEFAULT_CREDS)} known-default credential pairs.",
                            f"Pair `{email}` / `{password}` returned 2xx response without 'invalid' markers.",
                            f"Session captured: cookies={list(cookies.keys())} jwt_present={bool(jwt)}.",
                            "Authentication bypass via default credentials confirmed.",
                        ],
                    )
                    if rid:
                        emitted_count += 1
                        try:
                            from strix.agents.kg_emit import record_finding_in_kg
                            record_finding_in_kg(
                                finding_id=rid, url=login_url,
                                param="default_credential",
                                cwe="CWE-521", severity="high",
                                category="auth",
                                method="POST",
                                detection_kind="default_corpus_match",
                                confidence=1.0,
                            )
                        except Exception as e:  # noqa: BLE001
                            logger.debug("scan_auth_flow: kg record failed: %s", e, exc_info=True)
            except Exception as e:  # noqa: BLE001
                logger.debug("scan_auth_flow: emit failed: %s", e, exc_info=True)

            # Same source-aware filter — user-supplied successes
            # don't get a `FindingDraft` either. The session
            # capture (via record_auth_state below) is the value
            # the lead wants from a user-supplied cred attempt.
            if _source == "default_corpus":
                drafts.append(FindingDraft(
                    title=f"Default credentials accepted at {login_url}",
                    severity="high", cwe="CWE-521",
                    endpoint=login_url, category="auth",
                    verification_status="verified", confidence=1.0,
                    description=f"Login successful with `{email}` / `{password}`",
                ))
            evidence.append(
                f"{_source} login success: {email}/<redacted> → "
                f"cookies={list(cookies.keys())} jwt={'yes' if jwt else 'no'}"
            )
            # Record probe coverage.
            try:
                record_endpoint(login_url, method=method, probed_for="auth")
            except Exception:  # noqa: BLE001
                pass

            return SpecialistResult(
                status="ok",
                findings=drafts,
                evidence=evidence[:50],
                next_probes_suggested=[
                    f"Re-invoke scan_xss / scan_sqli / open_redirect_check / scan_xxe "
                    f"with the captured session (extra_headers={{'Authorization': 'Bearer ...'}})",
                    "Probe `/admin*` endpoints with the captured session — "
                    "any 200 response from a non-admin user is a missing-"
                    "auth-check finding (CWE-862).",
                    "If a JWT was captured, run jwt_audit on it.",
                ],
                tool_metadata={
                    "probes_sent": probe_count,
                    "session_label": label,
                    "cookies_captured": list(cookies.keys()),
                    "jwt_captured": bool(jwt),
                    "creds_used": email,
                    "findings_emitted_to_tracer": emitted_count,
                },
            )

    # Phase 2 — self-registration fallback.
    if try_register:
        rand_user = "strix_" + "".join(
            secrets.choice(string.ascii_lowercase) for _ in range(8)
        )
        rand_email = f"{rand_user}@example.test"
        rand_password = "Strix_" + secrets.token_urlsafe(12)

        register_paths = [register_url] if register_url else [
            login_url.replace("/login", "/register"),
            login_url.replace("/login", "/signup"),
            login_url.replace("/rest/user/login", "/api/Users/"),
            login_url.replace("/rest/user/login", "/rest/user/register"),
            login_url.replace("/auth/login", "/auth/register"),
        ]
        register_paths = [p for p in register_paths if p and p != login_url]

        registered = False
        for reg_url in register_paths:
            reg_body = json.dumps({
                email_field: rand_email,
                password_field: rand_password,
                "username": rand_user,
            })
            try:
                resp = pm.send_simple_request(
                    "POST", reg_url, headers=headers, body=reg_body, timeout=15,
                )
                probe_count += 1
            except Exception as e:  # noqa: BLE001
                evidence.append(f"register transport error: {e}")
                continue

            if isinstance(resp.get("status_code"), int) and 200 <= resp["status_code"] < 300:
                registered = True
                evidence.append(f"registered new user via {reg_url}")
                break

        if registered:
            # Now log in with the freshly-created creds.
            login_body = json.dumps({
                email_field: rand_email,
                password_field: rand_password,
            })
            try:
                resp = pm.send_simple_request(
                    method.upper(), login_url,
                    headers=headers, body=login_body, timeout=15,
                )
                probe_count += 1
                if _is_login_success(resp.get("status_code"), resp.get("body","")):
                    jwt = _extract_jwt(resp.get("body",""), resp.get("headers",{}))
                    cookies = _extract_cookies(resp.get("headers",{}))
                    record_auth_state(
                        label="registered-user",
                        cookies=cookies or None,
                        bearer=jwt,
                        notes=f"Self-registered: {rand_email}",
                    )
                    if jwt:
                        record_partial_signal(
                            surface="login captured JWT (label=registered-user)",
                            signal=f"JWT token bound to {rand_email}",
                            next_probe="jwt_audit on this token",
                            category_hint="jwt",
                        )
                    evidence.append(
                        f"login successful as registered-user: "
                        f"cookies={list(cookies.keys())} jwt={'yes' if jwt else 'no'}"
                    )
            except Exception as e:  # noqa: BLE001
                evidence.append(f"register-then-login transport error: {e}")

    # Record probe coverage even if no creds worked.
    try:
        record_endpoint(login_url, method=method, probed_for="auth")
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            ["With the captured session, re-invoke other specialists "
             "(scan_xss / scan_sqli / scan_xxe / open_redirect_check) "
             "with extra_headers including the auth.",
             "Probe /admin* endpoints with the session — 200 responses "
             "from non-admin users are CWE-862 findings."]
            if drafts else
            ["No default credentials worked. Try scan_auth_flow(try_register=True). "
             "If signup is gated (email verification), request the lead to manually "
             "perform the auth flow and capture session via send_request."]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "default_creds_tried": len(_DEFAULT_CREDS),
            "findings_emitted_to_tracer": emitted_count,
        },
    )
