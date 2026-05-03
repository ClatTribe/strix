"""HTTP security-header audit.

Per-host checks for the standard security-header set. Each missing or weak
header emits a finding with severity tuned to the real-world impact:

- **High**: CORS misconfiguration that reflects arbitrary Origins with
  credentials (CWE-942 — same-origin policy bypass on a credentialed API).
- **Medium**: missing CSP entirely; cookies without Secure on HTTPS app;
  cookies missing HttpOnly on a session-shaped name.
- **Low**: missing HSTS; missing X-Frame-Options / frame-ancestors; missing
  X-Content-Type-Options; missing Referrer-Policy; cookies missing SameSite.
- **Info**: Server / X-Powered-By version disclosure; missing Permissions-
  Policy / COOP / COEP / CORP (defense-in-depth, not exploitable on its own).

Composes with cluster-A safety (auth-injection / exclude-path / rate-limit)
automatically — every fetch routes through the proxy or the direct
fallback that uses the same env-driven `http_safety` middleware.

Each finding carries `description_plain` and `recommended_action` (the §11
non-tech-output fields shipped in #45) so the wrapper's dashboard renders
specific fix instructions per header rather than CWE numbers.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "http_security_headers_audit"
_HTTP_TIMEOUT = 12

_DEFAULT_PROBE_ORIGIN = "https://attacker.example.com"

# HSTS minimum recommended max-age = 6 months (15768000s). Anything shorter
# is technically present but not effective for CT-style preload.
_HSTS_MIN_MAX_AGE = 15_768_000


# Common session/auth cookie names. When one of these is set without
# HttpOnly we treat it as medium (real session-fixation risk) rather than
# the generic low.
_SESSION_COOKIE_NAMES: tuple[str, ...] = (
    "session", "sessid", "sessionid", "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "express.sid", "_session_id", "auth", "auth_token", "auth_session",
    "token", "access_token", "id_token", "refresh_token",
    "sid", "sessionkey", "authsession", "auth_tkt", "sails.sid",
    "rails_session", "django_session", "_session", "_csrf",
    "laravel_session", "wordpress_logged_in", "wordpress_sec",
)


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_get(
    url: str,
    *,
    extra_headers: dict[str, str] | None = None,
    timeout: int = _HTTP_TIMEOUT,
) -> dict[str, Any]:
    """GET via cluster-A path. Returns {status, headers, body, error?}."""
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request(
                "GET", url, headers=extra_headers, timeout=timeout
            )
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": r.get("headers") or {},
                "body": r.get("body") or "",
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
        merged = inject_auth_headers(extra_headers or {})
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body": r.text[:1024],  # not used, but bounded
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _h(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup. Returns the raw value or None."""
    if not headers:
        return None
    name_lower = name.lower()
    for k, v in headers.items():
        if k.lower() == name_lower:
            return v
    return None


def _all(headers: dict[str, str], name: str) -> list[str]:
    """Case-insensitive lookup that returns a list (Set-Cookie can repeat).

    httpx returns multiple Set-Cookie headers folded into one comma-joined
    string; we split on `, ` followed by an alphabetic character to
    approximate per-cookie boundaries.
    """
    raw = _h(headers, name)
    if not raw:
        return []
    if name.lower() == "set-cookie":
        # RFC-incompatible folding is the norm; this regex splits on
        # boundaries between cookies that look like `, name=...`.
        return re.split(r",\s*(?=[A-Za-z_][A-Za-z0-9_-]*=)", raw)
    return [raw]


# ---------------------------------------------------------------------------
# Per-header checks
# ---------------------------------------------------------------------------


def _check_hsts(headers: dict[str, str], is_https: bool) -> dict[str, Any]:
    """Strict-Transport-Security."""
    raw = _h(headers, "strict-transport-security")
    if not is_https:
        # HSTS only meaningful over HTTPS; don't flag on http://.
        return {
            "header": "Strict-Transport-Security",
            "present": bool(raw),
            "value": raw,
            "severity": "info",
            "issue": None,
        }
    if not raw:
        return {
            "header": "Strict-Transport-Security",
            "present": False,
            "value": None,
            "severity": "low",
            "issue": "missing",
            "description": (
                "HTTPS is offered but no `Strict-Transport-Security` header is "
                "set. Browsers will downgrade to HTTP if the user types the URL "
                "without https:// — first-visit MITM risk on coffee-shop Wi-Fi."
            ),
            "description_plain": (
                "Visitors who type the site address without 'https://' can be "
                "redirected to an unencrypted version on first visit. Add a "
                "header that tells browsers to always use HTTPS."
            ),
            "recommended_action": (
                "Add the response header: "
                "`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`"
            ),
        }
    # Parse max-age + flags.
    max_age_match = re.search(r"max-age\s*=\s*(\d+)", raw, re.IGNORECASE)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    has_subdomains = re.search(r"\bincludeSubDomains\b", raw, re.IGNORECASE) is not None
    if max_age < _HSTS_MIN_MAX_AGE:
        return {
            "header": "Strict-Transport-Security",
            "present": True,
            "value": raw,
            "severity": "low",
            "issue": "weak_max_age",
            "description": (
                f"HSTS is set with `max-age={max_age}` "
                f"({max_age // 86400} day(s)). Recommended minimum is 6 months "
                f"({_HSTS_MIN_MAX_AGE}s) for the policy to survive cache rotation."
            ),
            "description_plain": (
                "The HTTPS-enforcement window is too short. Browsers will "
                "forget the rule and may try HTTP again."
            ),
            "recommended_action": (
                f"Increase to: `Strict-Transport-Security: max-age={_HSTS_MIN_MAX_AGE}; "
                "includeSubDomains; preload`"
            ),
        }
    if not has_subdomains:
        return {
            "header": "Strict-Transport-Security",
            "present": True,
            "value": raw,
            "severity": "info",
            "issue": "no_subdomain_coverage",
            "description": (
                f"HSTS set with `max-age={max_age}` but missing `includeSubDomains`. "
                "Subdomains aren't covered."
            ),
            "description_plain": (
                "The HTTPS-enforcement rule applies only to this exact host. "
                "Subdomains of this site can still be downgraded to HTTP."
            ),
            "recommended_action": (
                "Add `includeSubDomains` to the existing header."
            ),
        }
    return {
        "header": "Strict-Transport-Security",
        "present": True,
        "value": raw,
        "severity": "info",
        "issue": None,
    }


def _check_csp(headers: dict[str, str]) -> dict[str, Any]:
    """Content-Security-Policy."""
    raw = _h(headers, "content-security-policy")
    if not raw:
        # Report-only counts as not enforced.
        ro = _h(headers, "content-security-policy-report-only")
        if ro:
            return {
                "header": "Content-Security-Policy",
                "present": False,
                "value": None,
                "severity": "low",
                "issue": "report_only_only",
                "description": (
                    "Only `Content-Security-Policy-Report-Only` is set. The "
                    "policy collects violation reports but does NOT block "
                    "anything — equivalent to CSP-off for security purposes."
                ),
                "description_plain": (
                    "The Content Security Policy is in 'report only' mode. "
                    "It logs violations but doesn't actually block them."
                ),
                "recommended_action": (
                    "Once you've validated the policy via the report-only mode, "
                    "switch the header name to `Content-Security-Policy` to "
                    "enforce it."
                ),
            }
        return {
            "header": "Content-Security-Policy",
            "present": False,
            "value": None,
            "severity": "medium",
            "issue": "missing",
            "description": (
                "No `Content-Security-Policy` header. Standard XSS / clickjacking / "
                "data-exfiltration mitigations all live here; without CSP the app "
                "has no in-browser defence-in-depth."
            ),
            "description_plain": (
                "There's no Content Security Policy. This is a key browser-side "
                "defence against XSS attacks. It's standard for apps to ship one."
            ),
            "recommended_action": (
                "Start with a strict baseline: "
                "`Content-Security-Policy: default-src 'self'; object-src 'none'; "
                "frame-ancestors 'self'; base-uri 'self'`. Tune as needed."
            ),
        }
    # CSP present — check for common weaknesses.
    weaknesses: list[str] = []
    if "'unsafe-inline'" in raw.lower():
        weaknesses.append("uses 'unsafe-inline' (defeats most XSS protection)")
    if "'unsafe-eval'" in raw.lower():
        weaknesses.append("uses 'unsafe-eval' (allows eval() / Function())")
    # Look for `*` standalone or per-directive wildcards.
    if re.search(r"\bdefault-src\s+\*", raw, re.IGNORECASE) or \
       re.search(r"\bscript-src\s+\*", raw, re.IGNORECASE):
        weaknesses.append("uses wildcard `*` source (any origin allowed)")
    if weaknesses:
        return {
            "header": "Content-Security-Policy",
            "present": True,
            "value": raw,
            "severity": "low",
            "issue": "weak_directives",
            "description": (
                f"CSP is set but contains weakening directives: "
                f"{'; '.join(weaknesses)}."
            ),
            "description_plain": (
                "The Content Security Policy is set but has loopholes that let "
                "many XSS attacks through anyway."
            ),
            "recommended_action": (
                "Remove `'unsafe-inline'` (use nonces or hashes instead) and "
                "`'unsafe-eval'`. Replace any `*` source with explicit allowlists."
            ),
        }
    return {
        "header": "Content-Security-Policy",
        "present": True,
        "value": raw,
        "severity": "info",
        "issue": None,
    }


def _check_xfo_or_frame_ancestors(headers: dict[str, str]) -> dict[str, Any]:
    """X-Frame-Options OR CSP frame-ancestors. Either is acceptable; both
    is fine; neither is the issue (clickjacking risk)."""
    xfo = _h(headers, "x-frame-options")
    csp = _h(headers, "content-security-policy") or ""
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if xfo or has_frame_ancestors:
        return {
            "header": "X-Frame-Options / CSP frame-ancestors",
            "present": True,
            "value": xfo or "(via CSP)",
            "severity": "info",
            "issue": None,
        }
    return {
        "header": "X-Frame-Options / CSP frame-ancestors",
        "present": False,
        "value": None,
        "severity": "low",
        "issue": "missing",
        "description": (
            "Neither `X-Frame-Options` nor CSP `frame-ancestors` is set. The "
            "page can be embedded in an attacker-controlled iframe → "
            "clickjacking exposure."
        ),
        "description_plain": (
            "Other websites can embed this page inside their own pages. An "
            "attacker can use this to trick users into clicking buttons here "
            "while thinking they're somewhere else."
        ),
        "recommended_action": (
            "Add `X-Frame-Options: SAMEORIGIN` (legacy-compatible) or include "
            "`frame-ancestors 'self'` in your CSP."
        ),
    }


def _check_xcto(headers: dict[str, str]) -> dict[str, Any]:
    """X-Content-Type-Options: nosniff."""
    raw = _h(headers, "x-content-type-options")
    if raw and raw.strip().lower() == "nosniff":
        return {
            "header": "X-Content-Type-Options",
            "present": True,
            "value": raw,
            "severity": "info",
            "issue": None,
        }
    return {
        "header": "X-Content-Type-Options",
        "present": False,
        "value": raw,
        "severity": "low",
        "issue": "missing",
        "description": (
            "`X-Content-Type-Options: nosniff` is missing. Browsers may MIME-"
            "sniff responses and execute attacker-controlled content as "
            "JavaScript when it's served with the wrong Content-Type."
        ),
        "description_plain": (
            "Without this header, a browser can guess the file type — and "
            "sometimes guesses 'JavaScript' for files that are actually data, "
            "running attacker code."
        ),
        "recommended_action": "Add `X-Content-Type-Options: nosniff`.",
    }


def _check_referrer_policy(headers: dict[str, str]) -> dict[str, Any]:
    """Referrer-Policy."""
    raw = _h(headers, "referrer-policy")
    if raw:
        return {
            "header": "Referrer-Policy",
            "present": True,
            "value": raw,
            "severity": "info",
            "issue": None,
        }
    return {
        "header": "Referrer-Policy",
        "present": False,
        "value": None,
        "severity": "low",
        "issue": "missing",
        "description": (
            "No `Referrer-Policy` header. Browsers default to "
            "`strict-origin-when-cross-origin` modern, but older browsers / "
            "embedded webviews may leak full URL paths in the Referer header."
        ),
        "description_plain": (
            "Without this header, when users click a link from your site, "
            "the destination can see the full URL they came from — including "
            "any IDs or tokens in the path."
        ),
        "recommended_action": (
            "Add `Referrer-Policy: strict-origin-when-cross-origin` (or "
            "`no-referrer` if you don't want any referrer leaking)."
        ),
    }


def _check_permissions_policy(headers: dict[str, str]) -> dict[str, Any]:
    """Permissions-Policy (formerly Feature-Policy)."""
    raw = _h(headers, "permissions-policy") or _h(headers, "feature-policy")
    if raw:
        return {
            "header": "Permissions-Policy",
            "present": True,
            "value": raw,
            "severity": "info",
            "issue": None,
        }
    return {
        "header": "Permissions-Policy",
        "present": False,
        "value": None,
        "severity": "info",
        "issue": "missing",
        "description": (
            "No `Permissions-Policy` header. Defense-in-depth concern: the "
            "app can't restrict which browser features (camera, microphone, "
            "geolocation, payment) iframes can use."
        ),
        "description_plain": (
            "There's no rule limiting what browser features (camera, mic, "
            "location) embedded content can use. Defence-in-depth concern."
        ),
        "recommended_action": (
            "Add a restrictive default like `Permissions-Policy: camera=(), "
            "microphone=(), geolocation=(), payment=()` and open up only what "
            "your app actually uses."
        ),
    }


def _check_version_disclosure(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Server / X-Powered-By disclosure. Each present → one finding."""
    out: list[dict[str, Any]] = []
    for header_name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        raw = _h(headers, header_name)
        # Bare server names like "nginx" are not version-disclosure (they're
        # technology disclosure, lower-impact). Flag only when a version-
        # number-shaped substring is present.
        if not raw:
            continue
        has_version = bool(re.search(r"\d+\.\d", raw))
        if has_version:
            out.append({
                "header": header_name,
                "present": True,
                "value": raw,
                "severity": "info",
                "issue": "version_disclosure",
                "description": (
                    f"Response includes `{header_name}: {raw}` — version "
                    "string disclosed. Helpful for exploit chaining when a "
                    "CVE applies to that version."
                ),
                "description_plain": (
                    "The server is announcing exactly which software and "
                    "version is running. This makes it easy to look up known "
                    "attacks against that specific version."
                ),
                "recommended_action": (
                    f"Suppress the `{header_name}` header in your reverse "
                    "proxy / framework config."
                ),
            })
    return out


def _check_cors(target_url: str, base_response: dict[str, Any]) -> dict[str, Any]:
    """CORS reflection check.

    Sends a follow-up request with `Origin: <attacker>` and inspects the
    response. The classic critical pattern: server reflects the attacker's
    Origin AND sets `Access-Control-Allow-Credentials: true` — full
    cross-origin credentialed access.
    """
    probe = _http_get(target_url, extra_headers={"Origin": _DEFAULT_PROBE_ORIGIN})
    if probe.get("skipped") or probe.get("error"):
        return {
            "header": "Access-Control-Allow-Origin",
            "present": False,
            "value": None,
            "severity": "info",
            "issue": "probe_unavailable",
        }
    aco = _h(probe.get("headers") or {}, "access-control-allow-origin")
    creds = _h(probe.get("headers") or {}, "access-control-allow-credentials")
    creds_yes = creds and creds.strip().lower() == "true"
    # Critical: reflect attacker origin + credentials.
    if aco == _DEFAULT_PROBE_ORIGIN and creds_yes:
        return {
            "header": "Access-Control-Allow-Origin",
            "present": True,
            "value": f"{aco} + Allow-Credentials: true",
            "severity": "high",
            "issue": "reflects_origin_with_credentials",
            "description": (
                f"The server reflected the attacker-controlled `Origin: "
                f"{_DEFAULT_PROBE_ORIGIN}` in `Access-Control-Allow-Origin` "
                "AND set `Access-Control-Allow-Credentials: true`. This grants "
                "any origin full credentialed access — total bypass of the "
                "browser's same-origin protection. CWE-942."
            ),
            "description_plain": (
                "The server lets ANY website read this site's responses while "
                "logged in. Other websites can read your users' data simply "
                "by having them visit the attacker's site while signed in here."
            ),
            "recommended_action": (
                "Replace dynamic Origin reflection with an explicit allowlist "
                "of trusted origins. If credentials are required, the allowlist "
                "MUST NOT contain `*` — list exact origins only. Reject "
                "unknown Origin values with no `Access-Control-Allow-Origin` "
                "header at all."
            ),
            "cwe": "CWE-942",
        }
    # Wildcard with credentials: technically the browser blocks this combo,
    # but it's still a misconfiguration.
    if aco == "*" and creds_yes:
        return {
            "header": "Access-Control-Allow-Origin",
            "present": True,
            "value": "* + Allow-Credentials: true",
            "severity": "medium",
            "issue": "wildcard_with_credentials",
            "description": (
                "Server returns `Access-Control-Allow-Origin: *` with "
                "`Access-Control-Allow-Credentials: true`. Browsers reject "
                "this combination, so the app is currently broken on the "
                "credentialed-CORS path — but the misconfiguration suggests "
                "the developer intent is to allow any origin, which is "
                "incompatible with credentialed access."
            ),
            "description_plain": (
                "The CORS settings are inconsistent. Browsers reject this "
                "combination; the app's CORS path likely doesn't work as "
                "intended — and the configured intent (allow-any) is unsafe."
            ),
            "recommended_action": (
                "Decide whether you actually want credentialed CORS. If yes, "
                "replace `*` with an explicit origin list. If no, drop "
                "`Access-Control-Allow-Credentials`."
            ),
            "cwe": "CWE-942",
        }
    return {
        "header": "Access-Control-Allow-Origin",
        "present": bool(aco),
        "value": aco,
        "severity": "info",
        "issue": None,
    }


def _check_cookies(headers: dict[str, str], is_https: bool) -> list[dict[str, Any]]:
    """Set-Cookie flag audit. One finding per insecure cookie."""
    out: list[dict[str, Any]] = []
    cookies = _all(headers, "set-cookie")
    for cookie in cookies:
        if "=" not in cookie:
            continue
        name = cookie.split("=", 1)[0].strip()
        if not name:
            continue
        flags_lower = cookie.lower()
        is_session = name.lower() in _SESSION_COOKIE_NAMES
        missing_flags: list[str] = []
        if "httponly" not in flags_lower:
            missing_flags.append("HttpOnly")
        if is_https and "secure" not in flags_lower:
            missing_flags.append("Secure")
        if "samesite=" not in flags_lower:
            missing_flags.append("SameSite")
        if not missing_flags:
            continue
        # Severity escalates for session cookies.
        if is_session and ("HttpOnly" in missing_flags or "Secure" in missing_flags):
            severity = "medium"
        else:
            severity = "low"
        out.append({
            "header": "Set-Cookie",
            "present": True,
            "value": f"{name}=...",  # never echo the cookie value
            "severity": severity,
            "issue": "missing_cookie_flags",
            "cookie_name": name,
            "missing_flags": missing_flags,
            "description": (
                f"Cookie `{name}` set without "
                f"{', '.join('`' + f + '`' for f in missing_flags)}. "
                + (
                    "This cookie name suggests it carries authentication state "
                    "— the missing flags expose it to session-fixation, XSS-"
                    "driven theft, or cross-site abuse."
                    if is_session else
                    "Defense-in-depth concern."
                )
            ),
            "description_plain": (
                f"The cookie '{name}' is missing protection flags "
                f"({', '.join(missing_flags)}). "
                + (
                    "This cookie likely holds a login session, which an "
                    "attacker could steal."
                    if is_session
                    else "It's a defense-in-depth concern."
                )
            ),
            "recommended_action": (
                f"Set the cookie with `{'; '.join(missing_flags)}` flags. "
                "For SameSite, use `Strict` for auth cookies, `Lax` otherwise."
            ),
        })
    return out


# ---------------------------------------------------------------------------
# Finding emission
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    category: str,
    cwe: str,
    target_url: str,
    description: str,
    description_plain: str | None,
    recommended_action: str | None,
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
        category=category,
        cwe=cwe,
        target=target_url,
        endpoint=target_url,
        description=description,
        impact=(
            "Security headers are the browser's standard mitigations against "
            "XSS, clickjacking, MIME-sniff abuse, and cross-origin attacks. "
            "Missing or weak headers don't directly expose data, but they "
            "remove the in-browser layer of defence — every other attack "
            "becomes easier and more impactful."
        ),
        remediation_steps=recommended_action
        or (
            "Configure the missing header in your reverse proxy / framework "
            "config and verify with `curl -I <url>`."
        ),
        description_plain=description_plain,
        recommended_action=recommended_action,
        fix_time_estimate="5min",
        verification_status="verified",
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
    mitre_techniques=["T1595.002"],  # Active Scanning: Vulnerability Scanning
)
def http_security_headers_audit(target_url: str) -> dict[str, Any]:
    """Audit HTTP security headers on a single URL.

    Args:
        target_url: full URL (e.g. `https://app.example.com` or
                    `https://app.example.com/dashboard`).

    Sends two requests to the target:
    1. Plain GET → inspect HSTS / CSP / XFO / XCTO / Referrer-Policy /
       Permissions-Policy / Server / Set-Cookie flags.
    2. GET with `Origin: <attacker-origin>` → CORS reflection probe.

    Emits one finding per missing / weak header. Severity tuned per
    real-world impact:
    - **High**: CORS reflects attacker origin + Allow-Credentials: true
    - **Medium**: missing CSP entirely; insecure session cookies
    - **Low**: missing HSTS / XFO / XCTO / Referrer-Policy / non-session
      cookie flags
    - **Info**: missing Permissions-Policy (defense-in-depth); version
      disclosure (Server / X-Powered-By with version string)

    Each finding includes `description_plain` and `recommended_action` for
    the wrapper's non-tech dashboard.

    Composes with cluster-A safety automatically.

    Returns:
        {success, target_url, is_https, status, header_count, results: [
          {header, present, value, severity, issue, ...}
        ], findings_emitted}
    """
    if not target_url or not target_url.strip():
        return {"success": False, "error": "target_url required"}
    target_url = target_url.strip()
    if "://" not in target_url:
        target_url = f"https://{target_url}"
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {"success": False, "error": f"invalid target URL: {target_url!r}"}

    cev = _start_check("http_security_headers", target_url)

    response = _http_get(target_url)
    if response.get("skipped"):
        _complete_check(cev, "inconclusive", "target excluded by --exclude-path")
        return {
            "success": False,
            "error_reason": "target excluded by --exclude-path",
            "target_url": target_url,
        }
    status = response.get("status") or 0
    if status == 0:
        _complete_check(cev, "inconclusive", f"target unreachable ({response.get('error')})")
        return {
            "success": False,
            "error_reason": f"target unreachable: {response.get('error')}",
            "target_url": target_url,
        }
    headers = response.get("headers") or {}
    is_https = parsed.scheme == "https"

    results: list[dict[str, Any]] = []
    results.append(_check_hsts(headers, is_https))
    results.append(_check_csp(headers))
    results.append(_check_xfo_or_frame_ancestors(headers))
    results.append(_check_xcto(headers))
    results.append(_check_referrer_policy(headers))
    results.append(_check_permissions_policy(headers))
    results.extend(_check_version_disclosure(headers))
    results.append(_check_cors(target_url, response))
    results.extend(_check_cookies(headers, is_https))

    findings_emitted = 0
    for r in results:
        if not r.get("issue"):
            continue
        _emit_finding(
            title=f"{r['header']}: {r['issue'].replace('_', ' ')} on {target_url}",
            severity=r.get("severity", "info"),
            category="security_misconfiguration",
            cwe=r.get("cwe", "CWE-693"),  # CWE-693 Protection Mechanism Failure
            target_url=target_url,
            description=r.get("description") or f"{r['header']}: {r['issue']}",
            description_plain=r.get("description_plain"),
            recommended_action=r.get("recommended_action"),
        )
        findings_emitted += 1

    issues = sum(1 for r in results if r.get("issue"))
    _complete_check(
        cev,
        result="vulnerable" if issues else "not_vulnerable",
        evidence=f"{issues}/{len(results)} security-header issue(s) found",
    )

    return {
        "success": True,
        "target_url": target_url,
        "is_https": is_https,
        "status": status,
        "header_count": len(headers),
        "results": results,
        "findings_emitted": findings_emitted,
    }
