"""`scan_multi_role_auth` — multi-role authz orchestrator
(workitem.md Phase 3.1).

Extends `scan_auth_flow` (which captures ONE session at a time) to
**capture sessions for multiple user roles in a single specialist
call**. Each captured session lands in
`SecurityContext.AuthState[label]`. Every downstream specialist
already auto-injects auth from there — so once this runs, IDOR,
authz-matrix, and missing-auth-admin probes have everything they
need.

Roles captured (when reachable)
-------------------------------

  * **anon**            — no credentials (implicit baseline; we
    record an empty AuthState entry so the lead can iterate "every
    captured role" symmetrically).
  * **default-creds**   — first successful default-cred attempt.
  * **admin**           — when the successful default-cred attempt
    used an admin-shaped username (`admin*` / `root*`), the same
    session is ALSO recorded under `admin` so authz-matrix probes
    can refer to it explicitly.
  * **user-a**          — self-registered account (seed A).
  * **user-b**          — self-registered account (seed B). NEW
    relative to scan_auth_flow — this is the IDOR precondition.

Output
------

`SpecialistResult` with a `tool_metadata.captured_roles` list naming
the labels the lead can pass to subsequent specialists' `auth_label`
arg. No vulnerability findings emitted directly (those come from the
specialists that USE the captured sessions). The exception: when
default-creds succeed against an admin-shaped username, that's a
CWE-521 / CWE-798 finding (admin default-creds = critical).

Why a separate specialist (vs. extending scan_auth_flow)
--------------------------------------------------------

  * Single-call orchestration — the lead invokes ONE tool to set up
    the entire multi-role substrate, then runs IDOR / authz / missing-
    auth probes against it.
  * `scan_auth_flow` stays single-purpose (default-creds + one
    registration). This specialist composes it: ~3-4 underlying
    auth flows → one merged result.
  * Phase 4.1 `scan_idor` requires `user-a` AND `user-b` labels — this
    specialist is the cleanest entry point for that precondition.
"""

from __future__ import annotations

import json
import logging
import secrets
import string
from typing import Any

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Default role list — order is also priority for captures (anon
# always succeeds; default-creds is fast; user-a/user-b take longer).
_DEFAULT_ROLES: tuple[str, ...] = (
    "anon", "default-creds", "user-a", "user-b",
)


_ADMIN_USERNAME_PREFIXES: tuple[str, ...] = (
    "admin", "root", "administrator", "superadmin", "superuser", "su",
)


def _is_admin_shaped(username: str) -> bool:
    """True when the username looks like an admin/root account.

    Used to decide whether to ALSO record the captured session under
    the `admin` label (so authz-matrix can refer to it explicitly).
    """
    if not isinstance(username, str):
        return False
    u = username.strip().lower()
    # Strip email domain.
    if "@" in u:
        u = u.split("@", 1)[0]
    return any(u == p or u.startswith(p) for p in _ADMIN_USERNAME_PREFIXES)


def _gen_unique_user(seed_label: str) -> tuple[str, str, str]:
    """Generate (username, email, password) for a self-registered user.

    `seed_label` (e.g. "a", "b") makes the username deterministically
    distinct between calls within a run — easier to reason about
    when reading the decision log.
    """
    rand = "".join(secrets.choice(string.ascii_lowercase) for _ in range(8))
    username = f"strix_{seed_label}_{rand}"
    email = f"{username}@strix-test.local"
    # Strong-shape password (mixed-case + digits + symbol) to satisfy
    # most password policies during self-registration.
    password = (
        "Strix"
        + secrets.choice(string.ascii_uppercase)
        + secrets.token_urlsafe(8)
        + str(secrets.randbelow(10))
        + "!"
    )
    return username, email, password


def _emit_admin_default_creds_finding(
    *,
    login_url: str,
    username: str,
    password: str,
) -> str | None:
    """Emit CWE-798 critical finding for an admin-shaped default-cred
    success. Mirrors scan_auth_flow's emission shape so downstream
    aggregators see consistent data."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        finding_id = tracer.add_vulnerability_report(
            title=f"Default admin credentials accepted at `{login_url}`",
            severity="critical",
            cwe="CWE-798",
            endpoint=login_url,
            target=login_url,
            category="authentication",
            verification_status="verified",
            confidence=0.99,
            description=(
                f"The login endpoint `{login_url}` accepted the "
                f"default credentials `{username}` / `{password}`. "
                f"The username is admin-shaped, so this is full "
                f"administrative compromise via guessable credentials."
            ),
            impact=(
                "Full administrative compromise. Default admin "
                "credentials are publicly indexed by Shodan / Censys; "
                "any opportunistic attacker would discover this in "
                "seconds. Pivot to:\n"
                "  * Application data exfiltration.\n"
                "  * Credential reuse against connected services "
                "    (admin email often reuses passwords).\n"
                "  * Privileged operations (user impersonation, "
                "    config tamper, secrets rotation).\n"
                "  * Backdoor planting for persistent access."
            ),
            technical_analysis=(
                f"Endpoint: {login_url}\n"
                f"Username: {username}\n"
                f"Password: (redacted in logs)\n"
                f"Admin-shape match: yes\n"
                f"Detection: scan_multi_role_auth's default-cred "
                f"cohort succeeded with an admin-shaped username."
            ),
            poc_description=(
                f"1. POST to {login_url} with the admin credentials.\n"
                f"2. Server returns a valid session — the captured "
                f"session is now in SecurityContext.AuthState[admin] "
                f"and is reused by every subsequent specialist."
            ),
            poc_script_code=(
                f"# Default credentials are intentionally not echoed "
                f"in the PoC script; see the lead's decision log + "
                f"Burp HAR for the actual values."
            ),
            remediation_steps=(
                "1. ROTATE the admin password IMMEDIATELY. Default "
                "admin creds on a production system are an "
                "indefensible posture.\n"
                "2. Audit logs for prior unauthorised admin logins.\n"
                "3. Implement a password-strength check at the "
                "registration / password-reset layer.\n"
                "4. Force MFA on admin accounts. Default-cred "
                "compromise is an escalation primitive — MFA blocks "
                "the chain at the next step.\n"
                "5. Add a CI check that rejects deployment configs "
                "containing default-cred values (admin/admin, "
                "root/root, admin/password, ...)."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C", "C": "H", "I": "H", "A": "H",
            },
            reasoning_trace=[
                f"scan_multi_role_auth probed {login_url}",
                f"Default-cred cohort succeeded with `{username}`.",
                f"Username is admin-shaped → critical (CWE-798).",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=login_url, param="admin_default_cred",
                cwe="CWE-798", severity="critical", category="authentication",
                method="POST", detection_kind="default_admin_cred",
                confidence=0.99,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_multi_role_auth: kg record failed: %s", e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_multi_role_auth: emit failed: %s", e, exc_info=True)
        return None


def _try_default_creds(
    *, pm: Any, login_url: str, method: str,
    email_field: str, password_field: str,
    body_template: dict[str, Any] | None,
    headers: dict[str, str],
) -> tuple[str | None, dict[str, str], str | None]:
    """Iterate the default-cred cohort. Returns (username_used,
    cookies, jwt) on success; (None, {}, None) otherwise."""
    from strix.tools.specialist.scan_auth_flow import (
        _DEFAULT_CREDS, _build_login_body,
        _extract_cookies, _extract_jwt, _is_login_success,
    )

    for email, password in _DEFAULT_CREDS:
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
        except Exception:  # noqa: BLE001
            continue
        if "error" in resp and not resp.get("status_code"):
            continue
        if _is_login_success(resp.get("status_code"), resp.get("body") or ""):
            jwt = _extract_jwt(resp.get("body") or "", resp.get("headers") or {})
            cookies = _extract_cookies(resp.get("headers") or {})
            return email, cookies, jwt
    return None, {}, None


def _try_register_then_login(
    *, pm: Any,
    login_url: str, register_url: str | None,
    method: str,
    email_field: str, password_field: str,
    headers: dict[str, str],
    seed_label: str,
) -> tuple[str | None, dict[str, str], str | None]:
    """Self-register a unique user and log in. Returns (email, cookies,
    jwt) on success."""
    from strix.tools.specialist.scan_auth_flow import (
        _extract_cookies, _extract_jwt, _is_login_success,
    )

    username, email, password = _gen_unique_user(seed_label)
    register_paths = [register_url] if register_url else [
        login_url.replace("/login", "/register"),
        login_url.replace("/login", "/signup"),
        login_url.replace("/rest/user/login", "/api/Users/"),
        login_url.replace("/rest/user/login", "/rest/user/register"),
        login_url.replace("/auth/login", "/auth/register"),
    ]
    register_paths = [p for p in register_paths if p and p != login_url]

    registered_at: str | None = None
    for reg_url in register_paths:
        reg_body = json.dumps({
            email_field: email,
            password_field: password,
            "username": username,
        })
        try:
            resp = pm.send_simple_request(
                "POST", reg_url, headers=headers, body=reg_body, timeout=15,
            )
        except Exception:  # noqa: BLE001
            continue
        sc = resp.get("status_code")
        if isinstance(sc, int) and 200 <= sc < 300:
            registered_at = reg_url
            break
    if not registered_at:
        return None, {}, None

    # Now log in.
    login_body = json.dumps({
        email_field: email, password_field: password,
    })
    try:
        resp = pm.send_simple_request(
            method.upper(), login_url,
            headers=headers, body=login_body, timeout=15,
        )
    except Exception:  # noqa: BLE001
        return None, {}, None
    if not _is_login_success(resp.get("status_code"), resp.get("body") or ""):
        return None, {}, None
    jwt = _extract_jwt(resp.get("body") or "", resp.get("headers") or {})
    cookies = _extract_cookies(resp.get("headers") or {})
    return email, cookies, jwt


@register_specialist_tool(
    category="multi-role-auth-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 120},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1110.001", "T1078"],
)
def scan_multi_role_auth(
    *,
    login_url: str,
    register_url: str | None = None,
    method: str = "POST",
    email_field: str = "email",
    password_field: str = "password",
    body_template: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    roles: list[str] | None = None,
) -> SpecialistResult:
    """Capture multiple user-role sessions in one call.

    Args:
        login_url: full login endpoint URL.
        register_url: explicit signup endpoint (when None, the
            specialist tries common signup paths).
        method: HTTP method for the login request.
        email_field / password_field: form/JSON keys for username +
            password. (`email` is the most common; many apps use
            `username` or `user`.)
        body_template: optional baseline request body the
            specialist mutates per attempt.
        extra_headers: forwarded as-is on every request.
        roles: which labels to attempt to capture. Defaults to
            `["anon", "default-creds", "user-a", "user-b"]`. Pass a
            subset to skip slow phases (e.g. just `["default-creds",
            "admin"]` to do credential-only).

    Captured sessions are written to `SecurityContext.AuthState[label]`.
    The lead's downstream specialists auto-inject from there.
    """
    if not isinstance(login_url, str) or not login_url.strip():
        return SpecialistResult(status="error", error="login_url required")
    login_url = login_url.strip()

    requested_roles = list(roles) if roles else list(_DEFAULT_ROLES)

    try:
        from strix.agents.security_context import (
            record_auth_state, record_endpoint, record_partial_signal,
        )
        from strix.tools.proxy.proxy_manager import get_proxy_manager
        pm = get_proxy_manager()
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"proxy_manager unavailable: {type(e).__name__}: {e}",
        )

    headers = dict(extra_headers or {})
    headers.setdefault("Content-Type", "application/json")

    captured_roles: list[str] = []
    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0

    # ----- anon -----
    if "anon" in requested_roles:
        try:
            record_auth_state(
                label="anon",
                cookies=None,
                bearer=None,
                notes="Implicit baseline — no credentials",
            )
            captured_roles.append("anon")
            evidence.append("anon: baseline recorded (no creds)")
        except Exception as e:  # noqa: BLE001
            evidence.append(f"anon: record failed: {e}")

    # ----- default-creds (+ admin alias) -----
    if "default-creds" in requested_roles or "admin" in requested_roles:
        username_used, cookies, jwt = _try_default_creds(
            pm=pm, login_url=login_url, method=method,
            email_field=email_field, password_field=password_field,
            body_template=body_template, headers=headers,
        )
        if username_used:
            try:
                record_auth_state(
                    label="default-creds",
                    cookies=cookies or None,
                    bearer=jwt,
                    notes=f"Default-creds: {username_used}",
                )
                captured_roles.append("default-creds")
            except Exception as e:  # noqa: BLE001
                evidence.append(f"default-creds: record failed: {e}")

            if jwt:
                try:
                    record_partial_signal(
                        surface=f"login captured JWT (label=default-creds)",
                        signal=f"JWT bound to {username_used}",
                        next_probe="jwt_audit on this token",
                        category_hint="jwt",
                    )
                except Exception:  # noqa: BLE001
                    pass

            evidence.append(
                f"default-creds: success as {username_used} "
                f"(jwt={'yes' if jwt else 'no'} cookies={list(cookies.keys())})"
            )

            # Mirror under `admin` label when admin-shaped.
            if _is_admin_shaped(username_used) and "admin" in requested_roles:
                try:
                    record_auth_state(
                        label="admin",
                        cookies=cookies or None,
                        bearer=jwt,
                        notes=f"Admin via default-creds: {username_used}",
                    )
                    captured_roles.append("admin")
                except Exception as e:  # noqa: BLE001
                    evidence.append(f"admin: record failed: {e}")

                rid = _emit_admin_default_creds_finding(
                    login_url=login_url, username=username_used,
                    password="(see lead decision log)",
                )
                if rid:
                    emitted_count += 1
                drafts.append(FindingDraft(
                    title="Default admin credentials accepted",
                    severity="critical", cwe="CWE-798",
                    endpoint=login_url, category="authentication",
                    verification_status="verified", confidence=0.99,
                    description=f"username={username_used} works as default cred",
                ))
                evidence.append(f"admin: captured (admin-shaped username)")
        else:
            evidence.append("default-creds: no cohort entry succeeded")

    # ----- user-a -----
    if "user-a" in requested_roles:
        email_a, cookies_a, jwt_a = _try_register_then_login(
            pm=pm, login_url=login_url, register_url=register_url,
            method=method,
            email_field=email_field, password_field=password_field,
            headers=headers, seed_label="a",
        )
        if email_a:
            try:
                record_auth_state(
                    label="user-a",
                    cookies=cookies_a or None,
                    bearer=jwt_a,
                    notes=f"Self-registered: {email_a}",
                )
                captured_roles.append("user-a")
            except Exception as e:  # noqa: BLE001
                evidence.append(f"user-a: record failed: {e}")
            evidence.append(
                f"user-a: registered + logged in as {email_a} "
                f"(jwt={'yes' if jwt_a else 'no'})"
            )
            if jwt_a:
                try:
                    record_partial_signal(
                        surface="login captured JWT (label=user-a)",
                        signal=f"JWT bound to {email_a}",
                        next_probe="jwt_audit on this token",
                        category_hint="jwt",
                    )
                except Exception:  # noqa: BLE001
                    pass
        else:
            evidence.append("user-a: registration or login failed")

    # ----- user-b — distinct seed -----
    if "user-b" in requested_roles:
        email_b, cookies_b, jwt_b = _try_register_then_login(
            pm=pm, login_url=login_url, register_url=register_url,
            method=method,
            email_field=email_field, password_field=password_field,
            headers=headers, seed_label="b",
        )
        if email_b:
            try:
                record_auth_state(
                    label="user-b",
                    cookies=cookies_b or None,
                    bearer=jwt_b,
                    notes=f"Self-registered: {email_b}",
                )
                captured_roles.append("user-b")
            except Exception as e:  # noqa: BLE001
                evidence.append(f"user-b: record failed: {e}")
            evidence.append(
                f"user-b: registered + logged in as {email_b} "
                f"(jwt={'yes' if jwt_b else 'no'})"
            )
        else:
            evidence.append("user-b: registration or login failed")

    # Record probe coverage.
    try:
        record_endpoint(login_url, method=method, probed_for="multi_role_auth")
    except Exception:  # noqa: BLE001
        pass

    # Phase 1.6 — provenance log
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=login_url,
            actor={"tool_name": "scan_multi_role_auth"},
            input={"requested_roles": requested_roles},
            output={
                "captured_roles": captured_roles,
                "findings_emitted": emitted_count,
            },
        )
    except Exception:  # noqa: BLE001
        pass

    next_probes: list[str] = []
    if "user-a" in captured_roles and "user-b" in captured_roles:
        next_probes.append(
            "Both user-a and user-b captured — run scan_idor (Phase 4.1) "
            "with auth_label=user-a probing user-b's resources and vice versa."
        )
    if "admin" in captured_roles:
        next_probes.append(
            "Admin session captured — probe `/admin*` endpoints with "
            "lower-privileged sessions to confirm CWE-862 missing-auth."
        )
    if not captured_roles or captured_roles == ["anon"]:
        next_probes.append(
            "Only anon captured — fallback to manual session capture via "
            "send_request, OR re-run with explicit register_url= if signup "
            "is gated."
        )

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=next_probes,
        tool_metadata={
            "requested_roles": requested_roles,
            "captured_roles": captured_roles,
            "findings_emitted_to_tracer": emitted_count,
        },
    )
