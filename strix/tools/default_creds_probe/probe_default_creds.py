"""iter-28.6 — Default-credentials probe (pure-python, no hydra).

Universal L1 primitive: against any discovered login form, try the
top default credentials. Pure-python implementation — does NOT add
hydra/medusa to the docker image (respects #449's slim-track
direction).

**Why this is generic, not Juice Shop-specific:**

  * Credential list is sourced from public **SecLists**
    (`Passwords/Common-Credentials/default-passwords.csv` and
    `Usernames/top-usernames-shortlist.txt`) — every product ships
    with at least one default, and the universe of common defaults
    is small (~100 pairs cover 90%+ of misconfigured apps).
  * Submission shape is detected via the same form-shape rules as
    `seed_auth` (POST with `email|username` + `password` field).
  * Success detection is response-shape-based: 200/302 with
    Set-Cookie OR a Bearer-shaped body field.

**Anti-overfit guardrails:**

  * NO per-SUT credential entries (no `admin/juiceshop`,
    `bkimminich/letmein`, etc.).
  * NO per-SUT path entries — relies on operator-supplied
    `login_url` (or a fallback path list of `/login`, `/api/login`,
    `/auth/login`, `/api/auth/login`, `/api/v1/auth/login`,
    `/users/login`, `/account/login` — all RFC-conventional).
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


def _rewrite_for_sandbox(url: str) -> str:
    """When running inside the sandbox container, localhost / 127.0.0.1
    refers to the sandbox itself, not the host's docker-compose'd SUT.
    Rewrite to `host.docker.internal`. No-op on host invocation."""
    if os.environ.get("STRIX_SANDBOX_MODE", "").lower() != "true":
        return url
    parsed = urlparse(url)
    if parsed.hostname in ("localhost", "127.0.0.1"):
        new_netloc = "host.docker.internal"
        if parsed.port:
            new_netloc += f":{parsed.port}"
        return parsed._replace(netloc=new_netloc).geturl()
    return url


# Top default credentials — sourced from public SecLists corpus
# (https://github.com/danielmiessler/SecLists, MIT-licensed). This
# is a curated subset that covers the most common defaults across
# product categories (admin tools, CMS, web frameworks, databases,
# devices). Format: (username, password).
#
# To stay anti-overfit: this list is industry-known defaults, not
# any per-SUT credentials we've observed.
_DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    # Admin defaults
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "password123"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "letmein"),
    ("admin", "changeme"),
    ("admin", "default"),
    ("admin", ""),
    ("administrator", "administrator"),
    ("administrator", "password"),
    # Root
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", ""),
    # Test / dev defaults
    ("test", "test"),
    ("test", "test123"),
    ("test", "password"),
    ("demo", "demo"),
    ("demo", "password"),
    ("guest", "guest"),
    ("guest", ""),
    # User / standard
    ("user", "user"),
    ("user", "password"),
    # CMS defaults
    ("wp-admin", "admin"),                 # WordPress
    ("admin", "wordpress"),
    ("manager", "manager"),                # Tomcat-Manager
    ("tomcat", "tomcat"),
    ("tomcat", "s3cret"),
    ("jenkins", "jenkins"),
    # DB / cache defaults — included since web apps often expose
    # admin panels on the same path family
    ("postgres", "postgres"),
    ("mongodb", "mongodb"),
    ("redis", ""),
    # Cloud / SaaS / dev tools
    ("admin", "nimda"),                    # admin reversed
    ("admin", "admin@123"),
    ("admin", "Password1!"),
    ("root", "calvin"),                    # iDRAC
    ("Administrator", "Administrator"),
    # Generic short
    ("a", "a"),
    ("", ""),
    # Email-style usernames (modern apps)
    ("admin@admin.com", "admin"),
    ("admin@example.com", "admin"),
    ("admin@admin.com", "password"),
    ("test@test.com", "test"),
)

# Well-known login paths, used when no `login_url` is supplied.
_LOGIN_PATH_FALLBACKS = (
    "/login",
    "/signin",
    "/sign-in",
    "/api/login",
    "/api/signin",
    "/api/auth/login",
    "/api/auth/signin",
    "/api/v1/auth/login",
    "/api/v1/login",
    "/auth/login",
    "/auth/signin",
    "/users/login",
    "/account/login",
)


def _is_login_success(resp: requests.Response) -> tuple[bool, str | None]:
    """Heuristic: did the login succeed?

    Successful login indicators (any one):
      * 2xx with a `Set-Cookie` containing typical session names
        (session, sid, jwt, token, auth, sess)
      * 2xx with a JSON body containing `token`/`access_token`/...
      * 302 redirect to a path that ISN'T the login page itself
        (suggests post-login redirect)

    Failure indicators (override success):
      * 401, 403, 422
      * 200 with a body containing common failure strings
        ("invalid", "incorrect", "wrong", "denied", "failed")

    Returns (success_bool, evidence_string).
    """
    sc = resp.status_code

    if sc in (401, 403, 422):
        return False, f"HTTP {sc}"

    # Body-based failure detection — applies to any 200 response
    body_text = (resp.text or "")[:4096].lower()
    failure_markers = (
        "invalid credentials", "invalid email", "invalid password",
        "incorrect password", "incorrect username", "wrong password",
        "wrong credentials", "login failed", "authentication failed",
        "access denied", "unauthorized",
    )
    if any(m in body_text for m in failure_markers):
        return False, "body contains failure marker"

    # Cookie-based success
    set_cookie = (
        resp.headers.get("set-cookie") or resp.headers.get("Set-Cookie") or ""
    ).lower()
    if set_cookie:
        session_markers = ("session", "sid", "jwt", "token", "auth", "sess")
        if any(m in set_cookie for m in session_markers):
            return True, f"Set-Cookie: {set_cookie[:80]}"

    # JSON-body-based success
    try:
        body = resp.json()
        if isinstance(body, dict):
            token_keys = (
                "access_token", "accessToken", "token", "id_token", "idToken",
                "jwt", "auth_token", "authToken",
            )
            for k in token_keys:
                if k in body and body[k]:
                    return True, f"JSON has `{k}`"
    except (ValueError, TypeError):
        pass

    # Redirect to non-login page
    if sc in (301, 302, 303, 307, 308):
        location = (resp.headers.get("Location") or "").lower()
        if location and "login" not in location and "signin" not in location:
            return True, f"redirect to {location[:80]}"

    return False, f"HTTP {sc} (no success signal)"


def _try_login(
    url: str, username_field: str, username: str,
    password_field: str, password: str,
    timeout: int = 8,
) -> tuple[bool, str]:
    """POST credentials; return (success, evidence)."""
    payload = {username_field: username, password_field: password}
    # Form-encoded first, then JSON fallback
    try:
        r = requests.post(
            url, data=payload, timeout=timeout, allow_redirects=False,
        )
    except requests.RequestException as e:
        return False, f"form post failed: {type(e).__name__}"
    ok, ev = _is_login_success(r)
    if ok:
        return True, f"form-encoded: {ev}"

    try:
        r2 = requests.post(
            url, json=payload, timeout=timeout, allow_redirects=False,
        )
    except requests.RequestException as e:
        return False, f"json post failed: {type(e).__name__}"
    ok2, ev2 = _is_login_success(r2)
    if ok2:
        return True, f"json: {ev2}"

    return False, f"form: {ev}; json: {ev2}"


def _detect_login_form(forms: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """Pick the login form from a crawl's forms list. Same shape rules
    as seed_auth — POST with `email|username` + `password` — but
    additionally checks that the form is NOT a registration form
    (registration forms have additional fields like firstName, age,
    tos-checkbox)."""
    if not forms:
        return None
    candidates = []
    for f in forms:
        if (f.get("method") or "").upper() != "POST":
            continue
        inputs = f.get("inputs") or []
        names = [str(i.get("name") or "").lower() for i in inputs]
        if not any("password" in n or "pwd" in n or "passwd" in n for n in names):
            continue
        if not any(
            "email" in n or "user" in n or "login" in n for n in names
        ):
            continue
        candidates.append((f, len(inputs)))
    if not candidates:
        return None
    # Prefer SHORTEST input list — login forms have fewer fields than
    # registration forms.
    candidates.sort(key=lambda c: c[1])
    return candidates[0][0]


def _detect_field_names(
    form: dict[str, Any],
) -> tuple[str, str]:
    """Find the username and password field names in a form.
    Falls back to `username` / `password` if no match."""
    inputs = form.get("inputs") or []
    user_field = "username"
    pass_field = "password"
    for i in inputs:
        n = str(i.get("name") or "")
        nl = n.lower()
        if any(p in nl for p in ("email", "username", "user", "login", "userid")):
            user_field = n
        elif any(p in nl for p in ("password", "passwd", "pwd")):
            pass_field = n
    return user_field, pass_field


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1110.001", "T1078.001"],  # password guessing, default accounts
    provenance="target",
)
def probe_default_creds(
    target_url: str,
    login_url: str | None = None,
    username_field: str = "username",
    password_field: str = "password",
    forms: list[dict[str, Any]] | None = None,
    max_attempts: int | None = None,
    timeout: int = 8,
) -> dict[str, Any]:
    """Try top default credentials against a discovered login form.

    Args:
        target_url: base URL of the target.
        login_url: explicit login endpoint. When omitted, the tool
            tries to find one via (a) the supplied `forms` list,
            (b) the well-known path fallback list.
        username_field: form field name for username. Auto-detected
            from `forms` when supplied; otherwise defaults to
            `username`.
        password_field: form field name for password. Auto-detected
            from `forms` when supplied; otherwise defaults to
            `password`.
        forms: optional list of forms from a prior `crawl_with_katana`
            call (iter-28.3). When supplied, the tool selects the
            login-shaped form automatically and derives field names.
        max_attempts: cap on credential pairs to try (default: full
            list). Tighten for noisy targets / rate-limited APIs.
        timeout: per-request timeout in seconds.

    Returns:
        ```
        {
          "success": bool,
          "status": "ok" | "partial" | "error",
          "endpoint_used": "...",
          "credential_found": {"username": "...", "password": "..."} | None,
          "evidence": "...",
          "attempts_made": int,
        }
        ```

        On success, emits an informational finding (default credentials
        are usually a CWE-521 / CWE-1392 surface).

    Examples:
        # With a known login URL
        probe_default_creds(
            target_url="http://app:3000",
            login_url="http://app:3000/api/auth/login",
        )

        # Let the tool find the login form from a prior crawl
        crawl = crawl_with_katana(target_url="http://app:3000")
        probe_default_creds(
            target_url="http://app:3000",
            forms=crawl["forms"],
        )
    """
    if not target_url or not target_url.strip():
        return {
            "success": False, "status": "error",
            "reason": "target_url required",
            "attempts_made": 0, "credential_found": None,
        }

    target_url = _rewrite_for_sandbox(target_url.strip())
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {
            "success": False, "status": "error",
            "reason": (
                f"target_url must be a full http(s) URL with a host"
            ),
            "attempts_made": 0, "credential_found": None,
        }
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Resolve login URL + field names
    candidate_urls: list[str] = []
    detected_user_field = username_field
    detected_pass_field = password_field

    if login_url:
        candidate_urls = [_rewrite_for_sandbox(login_url)]
    elif forms:
        login_form = _detect_login_form(forms)
        if login_form is not None:
            action = login_form.get("action") or "/"
            if action.startswith("/"):
                candidate_urls = [urljoin(base, action)]
            elif action.startswith(("http://", "https://")):
                candidate_urls = [action]
            else:
                candidate_urls = [
                    urljoin(target_url.rstrip("/") + "/", action),
                ]
            detected_user_field, detected_pass_field = _detect_field_names(login_form)

    if not candidate_urls:
        candidate_urls = [urljoin(base, p) for p in _LOGIN_PATH_FALLBACKS]

    creds_to_try = list(_DEFAULT_CREDS)
    if max_attempts is not None and max_attempts > 0:
        creds_to_try = creds_to_try[:max_attempts]

    attempts = 0
    last_error_per_url: dict[str, str] = {}

    for url in candidate_urls:
        for username, password in creds_to_try:
            attempts += 1
            success, evidence = _try_login(
                url=url,
                username_field=detected_user_field, username=username,
                password_field=detected_pass_field, password=password,
                timeout=timeout,
            )
            if success:
                return {
                    "success": True, "status": "ok",
                    "endpoint_used": url,
                    "credential_found": {
                        "username": username, "password": password,
                    },
                    "username_field": detected_user_field,
                    "password_field": detected_pass_field,
                    "evidence": evidence,
                    "attempts_made": attempts,
                }
            last_error_per_url[url] = evidence

    return {
        "success": True, "status": "partial",
        "endpoint_used": None,
        "credential_found": None,
        "evidence": (
            f"tried {attempts} cred pair(s) against {len(candidate_urls)} "
            f"endpoint(s) — no default credential accepted"
        ),
        "attempts_made": attempts,
    }
