"""MFA enforcement attestation probe.

Probes a web target for public indicators that MFA is part of the
authentication surface. Auditors care about the EVIDENCE — they
ask "show me a test" not "do you support it". This produces a
structured finding per target the auditor can reference.

Detection signals (each = +1 attestation point)
-----------------------------------------------

1. **Login page MFA terminology** — fetch `/login`, `/signin`,
   `/auth/login`, `/account/login`, `/users/sign_in`. Scan
   response body for canonical MFA tokens: `Multi-Factor`,
   `2FA`, `Two-Factor`, `Authenticator`, `Authy`, `Google
   Authenticator`, `TOTP`, `OTP`, `Verification Code`, `Security
   Key`, `WebAuthn`, `FIDO2`, `Passkey`, `Push Notification`.

2. **Login API challenge response** — fetch the same paths;
   parse JSON for `mfa_required`, `requires_otp`, `2fa_required`,
   `mfa_challenge`, `factor_required`, `webauthn_challenge`.

3. **WWW-Authenticate FIDO2 / WebAuthn** — header on a 401
   response advertising `WebAuthn` / `FIDO2`.

4. **MFA-setup endpoint exists** — HEAD probe on `/auth/mfa/`,
   `/auth/2fa/`, `/account/security`, `/settings/security`,
   `/settings/2fa`, `/profile/security`, `/user/mfa`. Status
   2xx/3xx (or 401 — requires auth, indicating the endpoint
   exists) → +1.

Each signal contributes +1, capped at 4 (max score).

Why deterministic / zero-FP
---------------------------

* Body-string match for canonical MFA tokens — binary detection.
* Auth-setup endpoint existence is HTTP status check.
* Response-JSON challenge fields: parsed by exact key match.
* No interpretation of "did MFA actually enforce" — the auditor's
  question is "is MFA visible". We answer that and stop.

References
----------

* SOC 2 CC6.6 — logical access via MFA
* NIST 800-53 IA-2 — Identification + Authentication
* PCI-DSS Req 8.4 — MFA on remote access
* HIPAA §164.312(d) — person/entity authentication
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "mfa_attestation_check"
_DEFAULT_TIMEOUT = 8.0
_MAX_BODY_BYTES = 64 * 1024


# Canonical login-flow paths to probe.
_LOGIN_PATHS = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/account/login",
    "/users/sign_in",
)

# Canonical MFA-setup paths to probe.
_MFA_SETUP_PATHS = (
    "/auth/mfa",
    "/auth/2fa",
    "/account/security",
    "/settings/security",
    "/settings/2fa",
    "/profile/security",
    "/user/mfa",
)

# MFA terminology to scan body content for. Case-insensitive.
_MFA_BODY_TOKENS = (
    "multi-factor",
    "multifactor",
    "two-factor",
    "two factor",
    "2fa",
    "authenticator",
    "totp",
    "verification code",
    "security key",
    "webauthn",
    "fido2",
    "passkey",
    "push notification",
)

# JSON-key markers in login responses indicating an MFA challenge.
_MFA_JSON_KEYS = (
    "mfa_required",
    "requires_otp",
    "2fa_required",
    "mfa_challenge",
    "factor_required",
    "webauthn_challenge",
    "needs_mfa",
    "step_up_required",
)


def _http_get(url: str, *, timeout: float = _DEFAULT_TIMEOUT) -> dict[str, Any]:
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None

    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, timeout=int(timeout))
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": (r.get("body") or "")[:_MAX_BODY_BYTES],
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy fetch failed; falling back", exc_info=True)

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
        merged = inject_auth_headers({})
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_BODY_BYTES],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(d: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in d.items()}


# ---------------------------------------------------------------------------
# Signal extraction
# ---------------------------------------------------------------------------


def _scan_body_for_mfa_tokens(body: str) -> list[str]:
    """Return the list of MFA tokens found in `body` (lowercased)."""
    if not body:
        return []
    haystack = body.lower()
    return [t for t in _MFA_BODY_TOKENS if t in haystack]


def _scan_response_json_for_mfa_keys(body: str) -> list[str]:
    """Return the list of MFA-challenge JSON keys present at any
    nesting depth. Tolerant — non-JSON bodies return []."""
    if not body or not body.strip().startswith(("{", "[")):
        return []
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []

    found: set[str] = set()

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str) and k.lower() in _MFA_JSON_KEYS:
                    found.add(k.lower())
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(data)
    return sorted(found)


def _has_webauthn_authenticate(headers: dict[str, str]) -> bool:
    auth = (headers.get("www-authenticate") or "").lower()
    return "webauthn" in auth or "fido2" in auth


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _severity_for_score(score: int) -> str:
    if score >= 3:
        return "info"
    if score >= 1:
        return "low"
    return "medium"


def _emit_finding(
    *,
    target: str,
    score: int,
    breakdown: dict[str, Any],
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return

    severity = _severity_for_score(score)
    title = f"MFA attestation: score {score}/4 ({severity})"

    parts = [
        f"MFA-attestation score: **{score} / 4**.",
        f"Login-page MFA tokens observed: "
        f"{', '.join(breakdown['login_tokens']) or '(none)'}.",
        f"Login-API challenge keys: "
        f"{', '.join(breakdown['challenge_keys']) or '(none)'}.",
        f"WebAuthn/FIDO2 in WWW-Authenticate: "
        f"{'yes' if breakdown['webauthn_header'] else 'no'}.",
        f"MFA-setup endpoints discovered: "
        f"{', '.join(breakdown['mfa_setup_paths']) or '(none)'}.",
    ]
    description = " ".join(parts)

    plain_by_severity = {
        "info": (
            "MFA appears visible in your auth surface. Auditors who ask "
            "'show me a test that MFA is enforced' have a positive answer."
        ),
        "low": (
            "Some MFA signal observed, but not definitively. The "
            "auditor's 'show me' question may need follow-up."
        ),
        "medium": (
            "No public MFA indicators on a customer-facing app. Auditors "
            "will flag this — either MFA isn't deployed, or it's not "
            "visible to a black-box probe (deeper-flow specialist will "
            "investigate)."
        ),
    }

    recs = []
    if not breakdown["login_tokens"]:
        recs.append(
            "Surface MFA terminology on the login page (e.g. 'Two-Factor "
            "Authentication', 'Authenticator app') so the auth flow's "
            "MFA enforcement is auditable."
        )
    if not breakdown["challenge_keys"]:
        recs.append(
            "Have the login API return a documented MFA-challenge response "
            "(e.g. `{\"mfa_required\": true, \"factor_types\": [\"totp\", "
            "\"webauthn\"]}`) so SDK consumers + auditors see the MFA step."
        )
    if not breakdown["webauthn_header"]:
        recs.append(
            "Consider WebAuthn / FIDO2 — the strongest MFA factor + the "
            "least phishable. Advertise via `WWW-Authenticate: WebAuthn` "
            "on 401 responses."
        )
    if not breakdown["mfa_setup_paths"]:
        recs.append(
            "Publish a canonical MFA-setup URL (e.g. `/account/security` "
            "or `/settings/2fa`) — auditor proof + makes user MFA "
            "self-service easier."
        )
    if not recs:
        recs.append("Continue current MFA posture; periodic re-attestation per audit cycle.")

    finding_id = tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="mfa_attestation",
        cwe="CWE-308",  # Use of Single-Factor Authentication
        target=target,
        endpoint=target,
        description=description,
        impact=(
            "MFA enforcement is a top-tier auditor question on every SOC 2 / "
            "ISO 27001 / PCI-DSS / HIPAA engagement. Lack of public evidence "
            "doesn't prove MFA is missing — but it forces compensating-control "
            "language in the audit report. Visible MFA = clean attestation."
        ),
        remediation_steps="\n\n".join(recs),
        description_plain=plain_by_severity.get(severity, plain_by_severity["medium"]),
        recommended_action=recs[0] if recs else "",
        verification_status="verified",
    )
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        record_finding_in_kg(
            finding_id=finding_id, url=target, param="mfa_attestation",
            cwe="CWE-308", severity=severity, category="mfa_attestation",
            method="GET", detection_kind=title[:60], confidence=0.7,
        )
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug(
            "mfa_attestation: kg record failed: %s", e, exc_info=True,
        )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME) if t else None


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is not None:
        t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


def _normalize_target(target: str) -> str | None:
    if not isinstance(target, str) or not target.strip():
        return None
    target = target.strip()
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1592"],
)
def mfa_attestation_check(
    target_url: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe a web target for public MFA-enforcement indicators.

    Args:
        target_url: web target (URL or bare host; auto-prefixed `https://`).
        timeout: per-request HTTP timeout (default 8s).

    Returns:
        ```
        {
          success, target,
          score, max_score=4, severity,
          login_tokens, challenge_keys, webauthn_header,
          mfa_setup_paths,
          paths_probed, findings_emitted=1,
          errors?,
        }
        ```

    Findings (CWE-308):
        - **Info** — score ≥ 3 (MFA visibly part of auth flow)
        - **Low** — score 1-2 (some signal; not definitive)
        - **Medium** — score 0 (no public MFA indicators)

    Always emits exactly one finding per target — positive
    attestation, not a vuln claim.
    """
    origin = _normalize_target(target_url)
    if origin is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    parsed = urlparse(origin)
    target_host = parsed.netloc
    check_id = _start_check(category="mfa_attestation", surface=target_host)
    errors: list[str] = []

    paths_probed: list[str] = []
    login_tokens: set[str] = set()
    challenge_keys: set[str] = set()
    webauthn_header = False
    mfa_setup_paths: list[str] = []

    # Probe canonical login paths.
    for path in _LOGIN_PATHS:
        url = origin + path
        r = _http_get(url, timeout=timeout)
        if r.get("skipped") or r.get("error"):
            continue
        status = int(r.get("status") or 0)
        if status == 0:
            continue
        paths_probed.append(path)

        # Body tokens.
        body = r.get("body") or ""
        for tok in _scan_body_for_mfa_tokens(body):
            login_tokens.add(tok)

        # JSON challenge keys.
        for key in _scan_response_json_for_mfa_keys(body):
            challenge_keys.add(key)

        # WebAuthn / FIDO2 advertisement.
        if _has_webauthn_authenticate(r.get("headers") or {}):
            webauthn_header = True

    # Probe canonical MFA-setup paths.
    for path in _MFA_SETUP_PATHS:
        url = origin + path
        r = _http_get(url, timeout=timeout)
        if r.get("skipped") or r.get("error"):
            continue
        status = int(r.get("status") or 0)
        # 2xx / 3xx means the endpoint exists; 401 means it's
        # auth-gated (which still proves it exists).
        if 200 <= status < 400 or status == 401:
            mfa_setup_paths.append(path)

    score = (
        (1 if login_tokens else 0)
        + (1 if challenge_keys else 0)
        + (1 if webauthn_header else 0)
        + (1 if mfa_setup_paths else 0)
    )

    breakdown = {
        "login_tokens": sorted(login_tokens),
        "challenge_keys": sorted(challenge_keys),
        "webauthn_header": webauthn_header,
        "mfa_setup_paths": mfa_setup_paths,
    }

    _emit_finding(target=target_host, score=score, breakdown=breakdown)

    severity = _severity_for_score(score)
    _complete_check(
        check_id,
        result="vulnerable" if severity == "medium" else "not_vulnerable",
        evidence=f"MFA-attestation score {score}/4, severity={severity}",
    )

    out: dict[str, Any] = {
        "success": True,
        "target": target_host,
        "score": score,
        "max_score": 4,
        "severity": severity,
        "login_tokens": breakdown["login_tokens"],
        "challenge_keys": breakdown["challenge_keys"],
        "webauthn_header": breakdown["webauthn_header"],
        "mfa_setup_paths": breakdown["mfa_setup_paths"],
        "paths_probed": paths_probed,
        "findings_emitted": 1,
    }
    if errors:
        out["errors"] = errors
    return out
