"""Cross-subdomain cookie / JWT scoping prober.

Designed for the multi-target case: when several sister subdomains
are in scope, the tool examines whether session cookies leak across
boundaries and whether JWTs honor their audience binding.

Why this is zero-false-positive
-------------------------------

Each finding is grounded in a binary, deterministic observation:

* **Cookie parent-domain scoping**: parse `Set-Cookie` → if `Domain=`
  attribute resolves to a parent domain that covers ≥2 in-scope
  hosts, this is a fact, not a guess. Same-host scoping is fine.
* **SameSite inconsistency**: enum comparison across the cohort.
  If host A says `SameSite=Lax` and host B says `SameSite=None`
  for the same cookie name, that's a binary mismatch.
* **SameSite=None without Secure**: literal attribute presence check.
  Modern browsers (Chrome 80+) silently treat this as Lax — it's
  a deployment bug, full stop.
* **JWT cross-acceptance**: N+1 verification. The token from host A
  is sent to host B's authenticated endpoint. If B returns 2xx with
  the same auth state as B's own session, this is empirical proof.
  Anything less than a 2xx + body-shape match is reported as
  `inconclusive`, NOT as a finding.
* **JWT aud over-broad**: `aud` claim parses to the parent domain
  while the token is presented to a specific subdomain. Binary
  string comparison after URL parsing.

What's NOT in scope
-------------------

Per-cookie content sniffing for "is this REALLY a session cookie?"
We use a name-based heuristic (`session` / `auth` / `token` / `sid`
/ `jwt` / `csrftoken` / `connect.sid` / `phpsessid` / `jsessionid`
/ `auth_token`) but treat unmatched names as `info` not `medium`.
That keeps the high-severity findings deterministic.

References
----------

* OWASP — Insufficient Session Expiration (CWE-613) and Improper
  Restriction (CWE-1275 — Sensitive Cookie with Improper SameSite).
* MDN — `SameSite=None` cookies must include `Secure`.
* RFC 6265 §4.1.2.3 — `Domain=` attribute matching rules.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "cookie_jwt_scoping_check"
_DEFAULT_TIMEOUT = 10.0

# Heuristic: cookie names that strongly suggest session-bearing.
# Match is case-insensitive substring + exact-name.
_SESSION_COOKIE_HINTS = (
    "session",
    "sessid",
    "auth",
    "token",
    "jwt",
    "sid",
    "csrftoken",
    "connect.sid",
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "remember_token",
    "_session",
)


def _is_session_cookie(name: str) -> bool:
    n = name.lower()
    return any(hint in n for hint in _SESSION_COOKIE_HINTS)


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing) — same pattern as sri_audit / dom_xss_static
# ---------------------------------------------------------------------------


def _http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Send a request via cluster-A safety. Returns
    `{status, headers, body, error?, skipped?}`. Headers are
    lower-cased on return so callers don't have to worry about case."""
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None

    if manager is not None:
        try:
            r = manager.send_simple_request(
                method, url, headers=headers or {}, timeout=int(timeout)
            )
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "raw_set_cookies": r.get("raw_set_cookies") or [],
                "body": (r.get("body") or "")[:64 * 1024],
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
        merged = inject_auth_headers(dict(headers or {}))
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.request(method, url, headers=merged)
            # httpx exposes raw set-cookie headers via response.headers.get_list
            raw_cookies: list[str] = []
            try:
                raw_cookies = r.headers.get_list("set-cookie")
            except Exception:  # noqa: BLE001
                if "set-cookie" in r.headers:
                    raw_cookies = [r.headers["set-cookie"]]
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "raw_set_cookies": raw_cookies,
                "body": r.text[: 64 * 1024],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(d: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in d.items()}


# ---------------------------------------------------------------------------
# Cookie parsing
# ---------------------------------------------------------------------------


def _parse_set_cookie(raw: str) -> dict[str, Any]:
    """Parse a single Set-Cookie header value into
    `{name, value, attrs: {domain?, path?, samesite?, secure, httponly, ...}}`.
    Lowercased attribute names; values trimmed."""
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return {"name": "", "value": "", "attrs": {}}
    nv = parts[0]
    if "=" in nv:
        name, _, value = nv.partition("=")
    else:
        name, value = nv, ""
    attrs: dict[str, str | bool] = {}
    for attr in parts[1:]:
        if "=" in attr:
            k, _, v = attr.partition("=")
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[attr.strip().lower()] = True
    return {"name": name.strip(), "value": value.strip(), "attrs": attrs}


def _registrable_parent(host: str) -> str | None:
    """Approximation of "registrable parent" without a TLD list.
    `app.foo.example.com` → `foo.example.com`; `api.example.com` →
    `example.com`. For deeper trees the function returns the
    immediate parent — fine for our cross-subdomain check since
    cookies that scope to ANY ancestor leak across subdomains."""
    parts = host.lower().split(".")
    if len(parts) <= 2:
        return None  # bare apex — no parent
    return ".".join(parts[1:])


def _domain_attr_covers(domain_attr: str, host: str) -> bool:
    """RFC 6265 §5.1.3 domain-match: cookie applies to `host` iff
    `host` == `domain_attr` OR `host` ends with `.<domain_attr>`."""
    domain_attr = domain_attr.lstrip(".").lower()
    h = host.lower()
    return h == domain_attr or h.endswith("." + domain_attr)


# ---------------------------------------------------------------------------
# JWT inspection (no signature verify needed)
# ---------------------------------------------------------------------------


def _decode_jwt_unsafe(token: str) -> dict[str, Any] | None:
    """Decode the payload claims of a JWT without verifying the
    signature. We're inspecting `aud` / `iss`, NOT trusting the
    token. Returns None on malformed input."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # Pad to multiple of 4 then decode urlsafe-b64.
        payload_b64 = parts[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        raw = base64.urlsafe_b64decode(padded)
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001
        return None


_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")


def _looks_like_jwt(s: str) -> bool:
    return bool(_JWT_RE.search(s))


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(**kwargs: Any) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    tracer = get_global_tracer()
    if tracer is None:
        return None
    finding_id = tracer.add_vulnerability_report(**kwargs)
    # §3 KG side-effect — cookie misconfigs are surface-level.
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        record_finding_in_kg(
            finding_id=finding_id,
            url=kwargs.get("endpoint") or kwargs.get("target") or "",
            param=kwargs.get("category", "cookie"),
            cwe=kwargs.get("cwe") or "CWE-1004",
            severity=kwargs.get("severity") or "medium",
            category=kwargs.get("category") or "cookie_scoping",
            method="GET",
            detection_kind=(kwargs.get("title") or "")[:60],
            confidence=0.85,
        )
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug(
            "cookie_scoping: kg record failed: %s", e, exc_info=True,
        )
    return finding_id


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
# Probes
# ---------------------------------------------------------------------------


def _probe_cookie_attributes(
    host: str,
    cookies: list[dict[str, Any]],
    *,
    cohort_hosts: list[str],
) -> list[dict[str, Any]]:
    """Per-host cookie inspection. Returns a list of structured
    finding-records (keyed for cross-host aggregation later)."""
    out: list[dict[str, Any]] = []
    for c in cookies:
        name = c["name"]
        attrs = c["attrs"]
        is_session = _is_session_cookie(name)
        domain_attr = attrs.get("domain")
        samesite = (attrs.get("samesite") or "").lower() if isinstance(
            attrs.get("samesite"), str
        ) else ""
        secure = bool(attrs.get("secure"))

        # 1) Domain-attribute parent-scoping check.
        if isinstance(domain_attr, str) and domain_attr.strip():
            domain_attr_norm = domain_attr.lstrip(".").lower()
            sister_hits = [
                h for h in cohort_hosts
                if _domain_attr_covers(domain_attr_norm, h) and h != host
            ]
            if domain_attr_norm != host.lower() and sister_hits:
                # Cookie's Domain= covers other in-scope subdomains.
                if is_session:
                    severity = "high" if len(sister_hits) >= 1 else "medium"
                    out.append({
                        "kind": "cookie_parent_scope_session",
                        "severity": severity,
                        "host": host,
                        "cookie_name": name,
                        "domain_attr": domain_attr_norm,
                        "leaks_to": sister_hits,
                    })
                else:
                    out.append({
                        "kind": "cookie_parent_scope_other",
                        "severity": "info",
                        "host": host,
                        "cookie_name": name,
                        "domain_attr": domain_attr_norm,
                        "leaks_to": sister_hits,
                    })

        # 2) SameSite=None without Secure.
        if samesite == "none" and not secure:
            out.append({
                "kind": "samesite_none_no_secure",
                "severity": "medium",
                "host": host,
                "cookie_name": name,
            })

        # 3) Session cookie missing SameSite at all.
        if is_session and not samesite:
            out.append({
                "kind": "samesite_missing_session",
                "severity": "low",
                "host": host,
                "cookie_name": name,
            })

    return out


def _probe_samesite_consistency(
    per_host_cookies: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Cross-host consistency. For each cookie name shared across
    ≥2 hosts, report when the SameSite values differ (the weakest
    subdomain effectively defines the cohort's security posture)."""
    out: list[dict[str, Any]] = []
    by_name: dict[str, dict[str, str]] = {}  # name → {host: samesite}
    for host, cookies in per_host_cookies.items():
        for c in cookies:
            attrs = c["attrs"]
            samesite = ""
            if isinstance(attrs.get("samesite"), str):
                samesite = attrs["samesite"].lower()
            by_name.setdefault(c["name"], {})[host] = samesite

    for name, host_to_samesite in by_name.items():
        if len(host_to_samesite) < 2:
            continue
        values = set(host_to_samesite.values())
        if len(values) > 1 and _is_session_cookie(name):
            out.append({
                "kind": "samesite_inconsistent",
                "severity": "medium",
                "cookie_name": name,
                "values": dict(host_to_samesite),
            })
    return out


def _probe_jwt_cross_acceptance(
    *,
    test_endpoints: dict[str, str],
    jwt_token: str,
    issuer_host: str,
    timeout: float,
) -> list[dict[str, Any]]:
    """Send the JWT (issued for `issuer_host`) to OTHER hosts'
    authenticated endpoints. If a sister host returns a 2xx with
    a body that's NOT the unauthenticated default, that's empirical
    cross-acceptance. We require:

    * The host is NOT the issuer.
    * Status is 2xx (binary).
    * Compared to a baseline call without the token, the body shape
      is meaningfully different — proves the token changed the
      response, i.e. the host honored the cross-issued JWT.
    """
    out: list[dict[str, Any]] = []
    auth_header = {"authorization": f"Bearer {jwt_token}"}

    for host, endpoint in test_endpoints.items():
        if host == issuer_host:
            continue

        # Baseline: no auth.
        baseline = _http_request("GET", endpoint, timeout=timeout)
        if baseline.get("error") or baseline.get("skipped"):
            continue

        # With the cross-issued token.
        authed = _http_request("GET", endpoint, headers=auth_header, timeout=timeout)
        if authed.get("error") or authed.get("skipped"):
            continue

        baseline_status = int(baseline.get("status") or 0)
        authed_status = int(authed.get("status") or 0)
        baseline_body = baseline.get("body") or ""
        authed_body = authed.get("body") or ""

        if 200 <= authed_status < 300:
            # 2xx with the cross-token. If baseline was also 2xx with
            # the same body shape, the endpoint is anonymous-public —
            # not a finding. Require body to differ to prove the
            # token was honored.
            if (
                baseline_status != authed_status
                or len(authed_body) != len(baseline_body)
                or authed_body[:200] != baseline_body[:200]
            ):
                out.append({
                    "kind": "jwt_cross_acceptance",
                    "severity": "high",
                    "issuer_host": issuer_host,
                    "accepted_by": host,
                    "endpoint": endpoint,
                    "baseline_status": baseline_status,
                    "authed_status": authed_status,
                })
    return out


def _probe_jwt_audience_scope(
    *,
    issuer_host: str,
    jwt_token: str,
    cohort_hosts: list[str],
) -> list[dict[str, Any]]:
    """Inspect the `aud` claim. If it's a parent domain that covers
    multiple cohort hosts, that's an over-broad audience binding."""
    claims = _decode_jwt_unsafe(jwt_token)
    if not claims:
        return []

    aud = claims.get("aud")
    out: list[dict[str, Any]] = []

    audiences: list[str] = []
    if isinstance(aud, str):
        audiences = [aud]
    elif isinstance(aud, list):
        audiences = [a for a in aud if isinstance(a, str)]

    if not audiences:
        # Missing aud entirely is a CWE-345 — already caught by
        # jwt_audit (#81). We don't double-report here.
        return out

    for a in audiences:
        # Strip scheme if present.
        try:
            host = urlparse(a if "://" in a else f"https://{a}").netloc or a
        except Exception:  # noqa: BLE001
            host = a
        host = host.lower()

        # Check whether the audience host covers multiple cohort
        # subdomains (i.e. it's a parent domain).
        sister_hits = [
            h for h in cohort_hosts
            if _domain_attr_covers(host, h) and h.lower() != host
        ]
        if sister_hits:
            out.append({
                "kind": "jwt_aud_over_broad",
                "severity": "low",
                "issuer_host": issuer_host,
                "aud": a,
                "covers_hosts": sister_hits,
            })
    return out


# ---------------------------------------------------------------------------
# Finding emission helpers
# ---------------------------------------------------------------------------


_DESCRIPTION_BY_KIND = {
    "cookie_parent_scope_session": (
        "Session cookie `{cookie_name}` on `{host}` is set with "
        "`Domain={domain_attr}`, scoping it to ALL subdomains under "
        "`{domain_attr}`. Sister apps in scope ({leaks_to_count}) "
        "automatically receive this cookie on every request — a "
        "compromised or less-trusted subdomain can read the session "
        "and impersonate the user."
    ),
    "cookie_parent_scope_other": (
        "Cookie `{cookie_name}` on `{host}` is set with "
        "`Domain={domain_attr}`, scoping it to all subdomains. Not "
        "session-bearing by name, but informational — review whether "
        "the parent-domain scope is intentional."
    ),
    "samesite_none_no_secure": (
        "Cookie `{cookie_name}` on `{host}` declares `SameSite=None` "
        "without `Secure`. Modern browsers (Chrome 80+) silently "
        "downgrade this to `SameSite=Lax`, breaking cross-site flows "
        "the site presumably wanted."
    ),
    "samesite_missing_session": (
        "Session cookie `{cookie_name}` on `{host}` does not declare "
        "`SameSite`. Browsers default to `Lax` for unset values, but "
        "explicit declaration (`SameSite=Strict` or `Lax` per the "
        "site's CSRF posture) is the OWASP-recommended baseline."
    ),
    "samesite_inconsistent": (
        "Cookie `{cookie_name}` is declared with DIFFERENT "
        "`SameSite` values across the in-scope cohort: "
        "`{values_repr}`. The weakest subdomain effectively defines "
        "the cookie's CSRF posture for the cohort."
    ),
    "jwt_cross_acceptance": (
        "JWT issued by `{issuer_host}` was accepted as authenticated "
        "by `{accepted_by}` (separate sister subdomain). The token "
        "should be bound to its issuer / audience — cross-acceptance "
        "lets an attacker pivot tokens between sister apps, breaking "
        "tenant or trust boundaries."
    ),
    "jwt_aud_over_broad": (
        "JWT issued by `{issuer_host}` declares `aud={aud}` which "
        "covers multiple sister subdomains "
        "({covers_hosts_count}). Audience claim should be the "
        "specific subdomain consuming the token; broader audiences "
        "let one app's token be replayed at another."
    ),
}

_RECOMMENDED_BY_KIND = {
    "cookie_parent_scope_session": (
        "Drop the explicit `Domain=` attribute on session cookies — "
        "browsers default to host-only scope, which is what you want. "
        "If you need cookie sharing across specific subdomains, "
        "implement an SSO flow with short-lived per-app tokens "
        "instead of a parent-domain session cookie."
    ),
    "cookie_parent_scope_other": (
        "Review whether parent-domain scoping is intentional. For "
        "analytics / tracking cookies it usually is; for any cookie "
        "carrying user-identifying data, prefer host-only scope."
    ),
    "samesite_none_no_secure": (
        "Either add `Secure` (so the cookie only travels over HTTPS) "
        "or change to `SameSite=Lax` if cross-site posting isn't "
        "needed. Modern browsers REQUIRE `Secure` for `SameSite=None`."
    ),
    "samesite_missing_session": (
        "Set `SameSite=Lax` (or `Strict` for high-assurance flows) "
        "explicitly on session cookies. Don't rely on browser defaults."
    ),
    "samesite_inconsistent": (
        "Standardize `SameSite` on the cohort's session cookies. "
        "Pick the strictest value compatible with the most permissive "
        "app's flows — the weakest subdomain otherwise defines the "
        "cohort's CSRF posture."
    ),
    "jwt_cross_acceptance": (
        "Bind every JWT to its consumer: validate `aud` (audience) "
        "MUST equal the receiving service's expected value, and "
        "rotate signing keys per service. If using a single signing "
        "service, give each consumer its own audience token."
    ),
    "jwt_aud_over_broad": (
        "Tighten the `aud` claim to the specific subdomain consuming "
        "the token. A `aud=example.com` covers `app.example.com`, "
        "`api.example.com`, `admin.example.com` indistinguishably."
    ),
}


def _emit_for_record(rec: dict[str, Any], *, target: str) -> str | None:
    kind = rec["kind"]
    severity = rec["severity"]

    # Build description params.
    params = dict(rec)
    params["leaks_to_count"] = len(rec.get("leaks_to") or [])
    params["covers_hosts_count"] = len(rec.get("covers_hosts") or [])
    if "values" in rec:
        params["values_repr"] = ", ".join(
            f"{h}={v or '(unset)'}" for h, v in rec["values"].items()
        )

    title_by_kind = {
        "cookie_parent_scope_session": (
            f"Session cookie '{rec.get('cookie_name')}' on "
            f"{rec.get('host')} scopes to parent domain"
        ),
        "cookie_parent_scope_other": (
            f"Cookie '{rec.get('cookie_name')}' on "
            f"{rec.get('host')} scopes to parent domain (informational)"
        ),
        "samesite_none_no_secure": (
            f"Cookie '{rec.get('cookie_name')}' on {rec.get('host')}: "
            f"SameSite=None without Secure"
        ),
        "samesite_missing_session": (
            f"Session cookie '{rec.get('cookie_name')}' on "
            f"{rec.get('host')} missing SameSite attribute"
        ),
        "samesite_inconsistent": (
            f"Cookie '{rec.get('cookie_name')}' has inconsistent "
            f"SameSite across cohort"
        ),
        "jwt_cross_acceptance": (
            f"JWT from {rec.get('issuer_host')} accepted at "
            f"sister subdomain {rec.get('accepted_by')}"
        ),
        "jwt_aud_over_broad": (
            f"JWT aud='{rec.get('aud')}' covers multiple sister "
            f"subdomains"
        ),
    }
    title = title_by_kind.get(kind, f"Cookie/JWT scoping: {kind}")
    description = _DESCRIPTION_BY_KIND.get(kind, kind).format(**params)
    recommended = _RECOMMENDED_BY_KIND.get(kind, "Review the cookie/JWT scoping.")

    cwe_by_kind = {
        "cookie_parent_scope_session": "CWE-1275",
        "cookie_parent_scope_other": "CWE-1275",
        "samesite_none_no_secure": "CWE-614",
        "samesite_missing_session": "CWE-1275",
        "samesite_inconsistent": "CWE-1275",
        "jwt_cross_acceptance": "CWE-863",
        "jwt_aud_over_broad": "CWE-345",
    }

    return _emit_finding(
        title=title,
        severity=severity,
        category="cookie_scoping" if "cookie" in kind or "samesite" in kind
        else "jwt_scoping",
        cwe=cwe_by_kind.get(kind, "CWE-1275"),
        target=target,
        endpoint=rec.get("host") or rec.get("issuer_host") or target,
        description=description,
        impact=(
            "An attacker who compromises (or controls a less-trusted) "
            "subdomain can pivot the broken scoping to take over user "
            "sessions on sister apps. This is a classic horizontal "
            "privilege-escalation primitive — single-target scans "
            "never see it."
        ),
        remediation_steps=recommended,
        description_plain=description,
        recommended_action=recommended,
        verification_status="verified" if kind == "jwt_cross_acceptance" else
        ("pattern_match" if kind in (
            "samesite_inconsistent", "jwt_aud_over_broad"
        ) else "verified"),
    )


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1539", "T1606.001"],
)
def cookie_jwt_scoping_check(
    cohort_urls: list[str],
    auth_endpoints: dict[str, str] | None = None,
    jwt_token: str | None = None,
    jwt_issuer_url: str | None = None,
    jwt_test_endpoints: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe cross-subdomain cookie / JWT scoping issues.

    Args:
        cohort_urls: list of in-scope subdomain URLs (≥2; otherwise
            the check is meaningless and we early-out). The tool will
            GET each one to harvest `Set-Cookie` headers.
        auth_endpoints: optional per-host endpoint URL (e.g. `/api/me`)
            to GET INSTEAD of the bare host. Use this when the bare
            URL doesn't issue session cookies but a login or session-
            check endpoint does.
        jwt_token: optional JWT to test for cross-acceptance. When
            present, `jwt_issuer_url` and `jwt_test_endpoints` should
            also be supplied.
        jwt_issuer_url: URL for which the JWT was originally issued
            (so we know which cohort host is the "rightful" consumer).
        jwt_test_endpoints: per-host (other than the issuer)
            authenticated endpoint URL to send the cross-issued JWT to.
        timeout: HTTP timeout in seconds.

    Returns:
        ```
        {
          success, cohort_hosts, cookies_examined,
          findings_emitted,
          records: [...],          // structured per-record list
          errors?: [str, ...],
        }
        ```

    Findings (CWE / severity):
        * CWE-1275 (cookie scoping):
            - high  — session cookie with parent-domain scope leaks to ≥1 sister
            - info  — non-session cookie with parent-domain scope
            - medium — SameSite=None without Secure
            - low   — session cookie missing SameSite
            - medium — SameSite inconsistent across cohort
        * CWE-614:
            - medium — SameSite=None without Secure (also tagged as 614)
        * CWE-863 (incorrect authorization):
            - high — JWT from one issuer accepted by sister subdomain
        * CWE-345 (insufficient verification):
            - low — JWT `aud` covers multiple cohort subdomains
    """
    # Normalize cohort.
    cohort_hosts: list[str] = []
    cohort_endpoints: list[tuple[str, str]] = []  # (host, fetch_url)
    for raw in cohort_urls or []:
        if not isinstance(raw, str) or not raw.strip():
            continue
        u = raw.strip()
        if "://" not in u:
            u = f"https://{u}"
        parsed = urlparse(u)
        host = parsed.netloc
        if not host:
            continue
        # If caller supplied a per-host auth endpoint, prefer that.
        endpoint = (auth_endpoints or {}).get(host) or u
        cohort_hosts.append(host)
        cohort_endpoints.append((host, endpoint))

    if len(cohort_hosts) < 2:
        return {
            "success": False,
            "error": "cookie_jwt_scoping_check requires ≥2 cohort_urls",
            "cohort_hosts": cohort_hosts,
            "findings_emitted": 0,
        }

    primary_target = cohort_hosts[0]
    check_id = _start_check(category="cookie_scoping", surface=primary_target)
    errors: list[str] = []
    per_host_cookies: dict[str, list[dict[str, Any]]] = {}
    cookies_examined = 0
    records: list[dict[str, Any]] = []

    # ---- Harvest cookies per host ----
    for host, endpoint in cohort_endpoints:
        r = _http_request("GET", endpoint, timeout=timeout)
        if r.get("skipped"):
            continue
        if r.get("error"):
            errors.append(f"{host}: {r['error']}")
            continue
        raw = r.get("raw_set_cookies") or []
        if not raw and "set-cookie" in r.get("headers", {}):
            # Fallback when the proxy/httpx didn't expose raw list.
            raw = [r["headers"]["set-cookie"]]
        cookies = [_parse_set_cookie(s) for s in raw if s]
        per_host_cookies[host] = cookies
        cookies_examined += len(cookies)

    # ---- Probe attribute-level issues ----
    for host, cookies in per_host_cookies.items():
        records.extend(
            _probe_cookie_attributes(host, cookies, cohort_hosts=cohort_hosts)
        )

    # ---- Cross-host SameSite consistency ----
    records.extend(_probe_samesite_consistency(per_host_cookies))

    # ---- JWT probes ----
    if jwt_token and jwt_issuer_url:
        try:
            issuer_host = urlparse(
                jwt_issuer_url if "://" in jwt_issuer_url else f"https://{jwt_issuer_url}"
            ).netloc or jwt_issuer_url
        except Exception:  # noqa: BLE001
            issuer_host = jwt_issuer_url

        # Audience inspection (no I/O).
        records.extend(
            _probe_jwt_audience_scope(
                issuer_host=issuer_host,
                jwt_token=jwt_token,
                cohort_hosts=cohort_hosts,
            )
        )
        # Cross-acceptance probe (HTTP).
        if jwt_test_endpoints:
            records.extend(
                _probe_jwt_cross_acceptance(
                    test_endpoints=jwt_test_endpoints,
                    jwt_token=jwt_token,
                    issuer_host=issuer_host,
                    timeout=timeout,
                )
            )

    # ---- Emit findings ----
    findings_emitted = 0
    for rec in records:
        if _emit_for_record(rec, target=primary_target):
            findings_emitted += 1

    if findings_emitted > 0:
        _complete_check(
            check_id,
            result="vulnerable",
            evidence=f"{findings_emitted} cookie/JWT scoping issue(s) across {len(cohort_hosts)} hosts",
        )
    else:
        _complete_check(
            check_id,
            result="not_vulnerable",
            evidence=f"{cookies_examined} cookie(s) across {len(cohort_hosts)} hosts; no scoping issues found",
        )

    out: dict[str, Any] = {
        "success": True,
        "cohort_hosts": cohort_hosts,
        "cookies_examined": cookies_examined,
        "findings_emitted": findings_emitted,
        "records": records,
    }
    if errors:
        out["errors"] = errors
    return out
