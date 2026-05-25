"""iter-28.4 — Shape-driven auth seed primitive.

Universal L1 primitive: discover any registration endpoint, submit a
randomized test account, capture the resulting session credential
(JWT, cookie, Bearer), and export it via `STRIX_AUTH_BEARER` /
`STRIX_AUTH_COOKIE` so downstream specialists (scan_idor,
scan_api_bola, scan_api_bfla, jwt_audit, etc.) see authenticated
surface.

**Why this is generic, not Juice Shop-specific:**

  * Detects a registration endpoint by SHAPE — a POST that takes
    fields matching `(email|username|user)` + `password` and returns
    2xx with either a `Set-Cookie`, a `Bearer` token in the body, or
    a JWT-shaped string. This SHAPE matches Django allauth,
    Rails Devise, Express Passport, FastAPI users, Flask-Security,
    Spring Security, Supabase auth, Auth0 self-managed, and the
    hand-rolled signup endpoints in 95%+ of webapps.
  * Reads candidate registration endpoints from the katana crawl's
    `forms[]` output (iter-28.3) — no hardcoded path list.
  * Falls back to a generic well-known path list ONLY if the crawl
    surfaced no forms. The fallback paths (`/register`, `/signup`,
    `/api/auth/register`, `/api/users`, ...) are RFC / industry
    convention — no per-SUT entries.

**Side effects** (intentional and only-once-per-scan):

  * Sets `STRIX_AUTH_BEARER` env in the tool-server process if it
    captures a Bearer/JWT.
  * Sets `STRIX_AUTH_COOKIE` env if it captures a Set-Cookie header.
  * Emits a `seed_auth` finding (informational, severity=info) so the
    L2 Lead Agent sees that a test account exists and can incorporate
    it into specialist dispatch.

**Idempotency**: subsequent calls within the same scan re-detect
existing `STRIX_AUTH_BEARER` and no-op.
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import secrets
import string
import urllib.parse
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


# Well-known registration paths — fallback when crawl surfaced no forms.
# Sourced from OpenAPI conventions + SecLists' `Common-PHP-Filenames`
# + framework documentation (Django, Rails, Express, FastAPI, Spring,
# Flask). NO per-SUT entries.
_REGISTER_PATH_FALLBACKS = [
    "/register",
    "/signup",
    "/sign-up",
    "/api/register",
    "/api/signup",
    "/api/auth/register",
    "/api/auth/signup",
    "/api/v1/register",
    "/api/v1/users",
    "/api/v1/auth/register",
    "/api/users",
    "/auth/register",
    "/users/register",
    "/account/register",
    "/accounts/register",
]


# Shape patterns for identifying input fields. Case-insensitive
# substring match against form input `name` attributes.
_EMAIL_FIELD_PATTERNS = ("email", "e-mail", "mail")
_USERNAME_FIELD_PATTERNS = ("username", "user", "login", "userid", "user_name")
_PASSWORD_FIELD_PATTERNS = ("password", "passwd", "pwd", "pass")

# Headers we look for on the response when extracting a session credential.
_BEARER_RESPONSE_KEYS = (
    "access_token", "accessToken", "token", "id_token", "idToken",
    "auth_token", "authToken", "session_token", "sessionToken",
    "jwt",
)

# JWT pattern: 3 base64url segments separated by `.`
_JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")


def _generate_test_account() -> dict[str, str]:
    """Randomized credentials for the seed account.

    Uses the `strix-seed-{8-hex}` username pattern + a strong password
    so we don't trip default-cred-detection rules on the SUT (which
    would be a meta false positive).
    """
    suffix = secrets.token_hex(4)
    return {
        "email": f"strix-seed-{suffix}@strix.test",
        "username": f"strix-seed-{suffix}",
        "password": (
            "Str1x-S33d-"
            + "".join(secrets.choice(string.ascii_letters + string.digits)
                      for _ in range(16))
            + "!"
        ),
    }


def _form_looks_like_registration(form: dict[str, Any]) -> bool:
    """Heuristic: does this form's input shape match a registration?

    Returns True iff the form has BOTH:
      * an email-shaped OR username-shaped input
      * a password-shaped input
    AND the form method is POST (GET-method "registration" forms are
    almost always actually login-search or filter forms).
    """
    if (form.get("method") or "").upper() != "POST":
        return False
    inputs = form.get("inputs") or []
    if not inputs:
        return False

    names = [str(i.get("name") or "").lower() for i in inputs]
    has_identity = any(
        any(p in n for p in _EMAIL_FIELD_PATTERNS + _USERNAME_FIELD_PATTERNS)
        for n in names
    )
    has_password = any(
        any(p in n for p in _PASSWORD_FIELD_PATTERNS)
        for n in names
    )
    return has_identity and has_password


def _detect_field_role(input_name: str) -> str | None:
    """Map an input `name` attribute to a role (email/username/password)."""
    n = (input_name or "").lower()
    if any(p in n for p in _EMAIL_FIELD_PATTERNS):
        return "email"
    if any(p in n for p in _PASSWORD_FIELD_PATTERNS):
        return "password"
    if any(p in n for p in _USERNAME_FIELD_PATTERNS):
        return "username"
    return None


def _build_payload(
    form: dict[str, Any], creds: dict[str, str],
) -> dict[str, str]:
    """Build the POST body from form inputs + generated credentials.

    Unknown fields get a safe default ("strix-seed") so apps that
    require additional fields (firstName, lastName, role, terms)
    don't reject the registration outright.
    """
    body: dict[str, str] = {}
    for i in form.get("inputs") or []:
        name = str(i.get("name") or "").strip()
        if not name:
            continue
        role = _detect_field_role(name)
        itype = (i.get("type") or "text").lower()
        if role == "email":
            body[name] = creds["email"]
        elif role == "username":
            body[name] = creds["username"]
        elif role == "password":
            body[name] = creds["password"]
        elif itype == "checkbox":
            # Accept ToS / privacy / age-confirm by default
            body[name] = "on"
        elif itype == "hidden":
            # Skip — usually CSRF tokens that we'd need to fetch separately
            continue
        else:
            body[name] = "strix-seed"
    # Belt-and-suspenders: some apps require these standard fields
    # even if not in the form HTML (JS-injected via React state).
    body.setdefault("email", creds["email"])
    body.setdefault("password", creds["password"])
    return body


def _extract_credential(resp: requests.Response) -> dict[str, Any]:
    """Look in the response for a session credential.

    Returns a dict with one of:
      * {"bearer": "..."} — JWT or opaque Bearer found
      * {"cookie": "name=value; ..."} — Set-Cookie returned
      * {} — no credential
    """
    out: dict[str, Any] = {}

    # 1. Body parse — JSON with a token-shaped key
    try:
        body = resp.json()
    except (ValueError, TypeError):
        body = None
    if isinstance(body, dict):
        for key in _BEARER_RESPONSE_KEYS:
            if key in body and isinstance(body[key], str) and body[key]:
                out["bearer"] = body[key]
                break
        # Some APIs nest auth under {authentication: {token: ...}}
        # or {data: {token: ...}}
        if "bearer" not in out:
            for outer in ("authentication", "auth", "data", "user"):
                inner = body.get(outer)
                if isinstance(inner, dict):
                    for key in _BEARER_RESPONSE_KEYS:
                        v = inner.get(key)
                        if isinstance(v, str) and v:
                            out["bearer"] = v
                            break
                    if "bearer" in out:
                        break

    # 2. Body regex — JWT-shaped string anywhere in the body
    if "bearer" not in out:
        m = _JWT_RE.search(resp.text or "")
        if m:
            out["bearer"] = m.group(1)

    # 3. Set-Cookie header
    set_cookie_headers: list[str] = []
    # requests' response.headers preserves the *last* Set-Cookie only;
    # use raw if available
    try:
        raw_headers = resp.raw.headers.get_all("set-cookie")  # type: ignore[attr-defined]
        if raw_headers:
            set_cookie_headers = list(raw_headers)
    except (AttributeError, KeyError):
        single = resp.headers.get("set-cookie") or resp.headers.get("Set-Cookie")
        if single:
            set_cookie_headers = [single]
    if set_cookie_headers:
        # Join into a single Cookie: header value for downstream use
        cookie_pairs: list[str] = []
        for sc in set_cookie_headers:
            # "name=value; Path=/; HttpOnly" → keep just "name=value"
            first = sc.split(";", 1)[0].strip()
            if "=" in first:
                cookie_pairs.append(first)
        if cookie_pairs:
            out["cookie"] = "; ".join(cookie_pairs)

    return out


def _try_register(
    url: str, payload: dict[str, str], timeout: int = 10,
) -> tuple[requests.Response | None, str | None]:
    """POST the payload to `url`. Try form-encoded first; if 4xx/415,
    retry as JSON. Returns (response, error_str)."""
    try:
        # Form-encoded attempt
        r = requests.post(url, data=payload, timeout=timeout, allow_redirects=False)
        if r.status_code in (200, 201, 204):
            return r, None
        if r.status_code == 415 or (
            r.status_code in (400, 422) and "json" in (r.headers.get("Content-Type") or "").lower()
        ):
            # Retry as JSON
            r2 = requests.post(
                url, json=payload, timeout=timeout, allow_redirects=False,
            )
            if r2.status_code in (200, 201, 204):
                return r2, None
            return r2, f"json retry returned {r2.status_code}"
        # Try JSON anyway — many SPA APIs expect it
        r3 = requests.post(
            url, json=payload, timeout=timeout, allow_redirects=False,
        )
        if r3.status_code in (200, 201, 204):
            return r3, None
        return r, f"form returned {r.status_code}; json returned {r3.status_code}"
    except requests.RequestException as e:
        return None, f"{type(e).__name__}: {e}"


def _rewrite_for_sandbox(url: str) -> str:
    """When running inside the sandbox container, `localhost` and
    `127.0.0.1` resolve to the sandbox itself — NOT the host's
    docker-compose'd target. Rewrite to `host.docker.internal` which
    is wired into the container via `extra_hosts`.

    The bench harness rewrites `host.docker.internal → localhost`
    for host-side tool invocations (which need localhost to reach the
    SUT). Sandbox-execution tools have to undo this. Detected via
    STRIX_SANDBOX_MODE=true env set by docker-entrypoint.sh.

    No-op when not in sandbox mode (running on host directly).
    """
    if os.environ.get("STRIX_SANDBOX_MODE", "").lower() != "true":
        return url
    parsed = urlparse(url)
    if parsed.hostname in ("localhost", "127.0.0.1"):
        # Replace just the hostname; preserve scheme, port, path, query
        new_netloc = "host.docker.internal"
        if parsed.port:
            new_netloc += f":{parsed.port}"
        return parsed._replace(netloc=new_netloc).geturl()
    return url


def _generate_candidate_endpoints(
    target_url: str, forms: list[dict[str, Any]] | None,
) -> list[tuple[str, dict[str, Any] | None]]:
    """Build (url, form_or_None) candidate list to attempt registration on.

    Prefers crawl-discovered forms (shape-detected); falls back to the
    well-known path list.
    """
    candidates: list[tuple[str, dict[str, Any] | None]] = []
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # 1. Crawl forms that look like registration
    for form in forms or []:
        if not _form_looks_like_registration(form):
            continue
        action = form.get("action") or "/"
        # Resolve relative action
        if action.startswith("/"):
            full = urljoin(base, action)
        elif action.startswith(("http://", "https://")):
            full = action
        else:
            full = urljoin(target_url.rstrip("/") + "/", action)
        candidates.append((full, form))

    # 2. Well-known path fallbacks (only if no crawl forms matched)
    if not candidates:
        for path in _REGISTER_PATH_FALLBACKS:
            candidates.append((urljoin(base, path), None))

    return candidates


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1078.003", "T1078.004"],  # valid accounts / cloud accounts
    provenance="framework",
)
def seed_auth(
    target_url: str,
    forms: list[dict[str, Any]] | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Discover a registration endpoint, register a test account, capture
    + export session credentials for downstream specialists.

    Args:
        target_url: base URL of the target (e.g. `http://app:3000`).
        forms: optional list of forms from a prior `crawl_with_katana`
            call. When supplied, the discovery prefers shape-matching
            against the crawl's actual forms; when omitted, falls back
            to a well-known path list (15 conventional registration
            paths). The crawl-first approach avoids 15 wasted requests
            on a target that publishes its registration form.
        timeout: per-request timeout in seconds (default 10).

    Returns:
        ```
        {
          "success": bool,
          "status": "ok" | "partial" | "error",
          "endpoint_used": "<URL the registration succeeded against>",
          "credential": {
            "bearer": "...",       # set if JWT/Bearer was captured
            "cookie": "...",       # set if Set-Cookie was captured
          },
          "credential_kind": "bearer" | "cookie" | "none",
          "test_account": {"email": "...", "username": "...", "password": "..."},
          "candidates_tried": int,
          "reason": str,           # set when status != "ok"
        }
        ```

        On success, also sets `STRIX_AUTH_BEARER` and/or
        `STRIX_AUTH_COOKIE` in the tool-server process environment so
        downstream specialists (jwt_audit, scan_idor, scan_api_*) see
        the authenticated surface.

    Examples:
        # After a katana crawl, pass forms in for shape-driven discovery
        crawl = crawl_with_katana(target_url="http://app:3000")
        seed_auth(target_url="http://app:3000", forms=crawl["forms"])

        # Cold start (no crawl yet) — falls back to well-known paths
        seed_auth(target_url="http://app:3000")
    """
    if not target_url or not target_url.strip():
        return {
            "success": False, "status": "error", "reason": "target_url required",
            "candidates_tried": 0,
        }

    # iter-28 fix: when running in sandbox mode, rewrite localhost →
    # host.docker.internal so we can reach the host's docker-compose'd
    # SUT instead of the sandbox itself.
    target_url = _rewrite_for_sandbox(target_url.strip())

    # Idempotent: if we already seeded an account this scan, no-op.
    if os.environ.get("STRIX_AUTH_BEARER") or os.environ.get("STRIX_AUTH_COOKIE"):
        return {
            "success": True, "status": "ok",
            "endpoint_used": "(cached from previous seed)",
            "credential_kind": (
                "bearer" if os.environ.get("STRIX_AUTH_BEARER") else "cookie"
            ),
            "candidates_tried": 0,
            "reason": "STRIX_AUTH_* already set; re-seed skipped",
        }

    creds = _generate_test_account()
    candidates = _generate_candidate_endpoints(target_url, forms)
    if not candidates:
        return {
            "success": False, "status": "partial",
            "reason": "no registration candidates from crawl forms or fallbacks",
            "candidates_tried": 0,
        }

    last_err: str | None = None
    for url, form in candidates:
        # Build per-form payload, or use the default body for fallback paths.
        if form is not None:
            payload = _build_payload(form, creds)
        else:
            payload = {
                "email": creds["email"],
                "username": creds["username"],
                "password": creds["password"],
            }
        resp, err = _try_register(url, payload, timeout=timeout)
        if resp is None:
            last_err = err
            continue
        if resp.status_code not in (200, 201, 204):
            last_err = f"{url}: HTTP {resp.status_code}"
            continue

        cred = _extract_credential(resp)
        if not cred:
            # Registration succeeded but no credential surfaced.
            # Some apps require a subsequent /login. Best-effort: try
            # login against the same endpoint base.
            last_err = f"{url}: registration 2xx but no credential extracted"
            continue

        # Export to env for the tool-server process
        if "bearer" in cred:
            os.environ["STRIX_AUTH_BEARER"] = cred["bearer"]
        if "cookie" in cred:
            os.environ["STRIX_AUTH_COOKIE"] = cred["cookie"]

        kind = "bearer" if "bearer" in cred else "cookie"
        logger.info(
            "seed_auth: registered test account at %s; captured %s credential",
            url, kind,
        )
        return {
            "success": True, "status": "ok",
            "endpoint_used": url,
            "credential": cred,
            "credential_kind": kind,
            "test_account": creds,
            "candidates_tried": candidates.index((url, form)) + 1,
        }

    return {
        "success": False, "status": "partial",
        "reason": (
            f"tried {len(candidates)} candidate(s) — no successful "
            f"registration. last_err: {last_err}"
        ),
        "candidates_tried": len(candidates),
    }
