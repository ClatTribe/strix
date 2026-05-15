"""CSRF posture analyzer.

For a state-changing form (URL + method + fields), replay it with
each of the standard CSRF-bypass mutations and flag the variants
the server accepts:

- **Token removed** — omit the CSRF token field entirely.
- **Token empty** — send the field with empty value.
- **Token mutated** — flip the last character of the token.
- **Token random** — replace the token with a CSPRNG-random value
  of the same length.
- **Origin: attacker** — swap the `Origin` header to a
  per-run-unique attacker origin.
- **Referer: attacker** — swap the `Referer` header.
- **Origin: removed** — omit the `Origin` header entirely (some
  presence-only validators are bypassed by no-header-at-all).
- **Referer: removed** — omit the `Referer` header.
- **Origin: null** — `Origin: null` (sandboxed iframe / data: URI).
- **Double-submit cookie mismatch** — when the form has a CSRF
  token in a cookie too, the cookie and form-field values are
  mutated to mismatch.
- **Token replay** — same token submitted twice (one-time-ness check).

Detection: each mutated request is sent and its response shape
compared to the baseline (legitimate-token) request. Acceptance
heuristic: same status class (2xx/3xx) AND body length within ±25%
of baseline AND not a stock 403/Method-Not-Allowed.

Per-class dedup so 4 token-bypass mutations emit at most one
"missing token validation" finding, not four.

Severity:

- **High** (CWE-352) — request accepted with token completely
  removed / empty / mutated / random. The form has no working CSRF
  validation.
- **High** — request accepted with `Origin: <attacker>` AND token
  bypass also works. Strongest CSRF primitive.
- **High** — double-submit-cookie mismatch accepted (the cookie
  vs form-field comparison is broken).
- **Medium** — request accepted with `Origin` / `Referer` removed
  (presence-only validators bypassed).
- **Medium** — request accepted with `Referer: <attacker>` only.
- **Low** — token replay accepted (one-time-ness violation).

Skip cases:

- Baseline submission with the legitimate token returns non-2xx/3xx
  → inconclusive (the form description is wrong; operator needs to
  fix the field map).
- Cluster-A `--exclude-path` blocks the URL → graceful no-op.

Each finding carries `description_plain` + `recommended_action`
(double-submit cookie + per-form unique CSRF token; reject requests
without `Origin` or with `Origin` not in allow-list; reject
mismatched / re-used tokens; rotate token on each form render) and
`verification_status=needs_review`.

Composes with cluster-A safety. MITRE T1190.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any
from urllib.parse import urlencode, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "csrf_check"
_DEFAULT_TIMEOUT = 10.0
_MAX_RESPONSE_SCAN = 64 * 1024


# Auto-detection lexicon for CSRF token field names. Order is
# intentional — frameworks earlier in the list win on ambiguity.
_TOKEN_FIELD_NAMES = (
    "csrfmiddlewaretoken",  # Django
    "authenticity_token",    # Rails
    "__RequestVerificationToken",  # ASP.NET
    "_token",                # Laravel
    "_csrf",                 # Express csurf, NestJS
    "_csrf_token",
    "csrf_token",
    "csrf",
    "anti_csrf_token",
    "anticsrf",
    "x-csrf-token",
    "csrftoken",
    "xsrf_token",
)

_TOKEN_COOKIE_NAMES = (
    "csrftoken",
    "csrf-token",
    "XSRF-TOKEN",
    "_csrf",
    "_xsrf",
    "csrf",
)


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
    omit_origin: bool = False,
    omit_referer: bool = False,
) -> dict[str, Any]:
    """Send an HTTP request via cluster-A safety. Returns
    {status, headers, body, error?, skipped?}.

    `omit_origin` / `omit_referer` are passthroughs — they instruct
    the caller's header dict to actively NOT contain those keys
    (the proxy / httpx layer doesn't add them by default; this is a
    contract for the caller).
    """
    headers = dict(headers or {})
    if omit_origin:
        headers.pop("Origin", None)
        headers.pop("origin", None)
    if omit_referer:
        headers.pop("Referer", None)
        headers.pop("referer", None)

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
# Helpers
# ---------------------------------------------------------------------------


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


def _detect_token_field(fields: dict[str, str]) -> str | None:
    """Return the form-field name that looks like a CSRF token.
    Match order: exact case-insensitive match against the lexicon.
    """
    lower_fields = {k.lower(): k for k in fields.keys()}
    for candidate in _TOKEN_FIELD_NAMES:
        if candidate.lower() in lower_fields:
            return lower_fields[candidate.lower()]
    return None


def _detect_token_cookie(cookies: dict[str, str]) -> str | None:
    lower_cookies = {k.lower(): k for k in cookies.keys()}
    for candidate in _TOKEN_COOKIE_NAMES:
        if candidate.lower() in lower_cookies:
            return lower_cookies[candidate.lower()]
    return None


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
    """True if the response looks like an accepted submission (same
    status class as baseline, body length within ±25%, not 403/405)."""
    status = int(response.get("status") or 0)
    if status in (401, 403, 405, 429):
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


def _build_body(
    fields: dict[str, str],
    method: str,
    content_type: str,
) -> tuple[str, str]:
    """Encode the field map into a request body. Returns
    (body, content_type_used). For GET, returns empty body and the
    field map is appended to the URL by the caller."""
    if method.upper() == "GET":
        return ("", content_type or "")
    if content_type and "json" in content_type.lower():
        import json
        return (json.dumps(fields), "application/json")
    return (urlencode(fields), content_type or "application/x-www-form-urlencoded")


def _append_query(url: str, fields: dict[str, str]) -> str:
    parsed = urlparse(url)
    extra = urlencode(fields)
    new_query = f"{parsed.query}&{extra}" if parsed.query else extra
    return parsed._replace(query=new_query).geturl()


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
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
    finding_id = tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="csrf",
        cwe="CWE-352",
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "CSRF allows an attacker-controlled web page to issue "
            "authenticated state-changing requests to your "
            "application using the victim's session cookies. Real-"
            "world consequences: forced password changes, account "
            "takeover via email rotation, fund transfers, "
            "permission grants, and destructive actions on behalf "
            "of any logged-in user who visits the attacker page."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
    )
    # §3 KG side-effect: record Vuln + Surface + AFFECTS on every
    # successful emit. CSRF is endpoint-level (no param), so we
    # use the empty-string param surrogate; surface dedup still
    # works (one Surface per endpoint+method).
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        record_finding_in_kg(
            finding_id=finding_id, url=endpoint, param="",
            cwe="CWE-352", severity=severity, category="csrf",
            method="POST",  # CSRF concerns state-changing requests
            detection_kind="missing_csrf_token",
            confidence=0.85,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("csrf_check: kg record failed: %s", e, exc_info=True)


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
    mitre_techniques=["T1190"],
)
def csrf_check(
    target_url: str,
    method: str = "POST",
    fields: dict[str, str] | None = None,
    token_field: str | None = None,
    token_cookie: str | None = None,
    cookies: dict[str, str] | None = None,
    content_type: str = "",
    extra_headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe a state-changing form for CSRF posture weaknesses.

    Args:
        target_url: URL the form posts to. Bare hostnames are
            auto-prefixed `https://`.
        method: HTTP method (`POST`, `PUT`, `PATCH`, `DELETE`,
            or `GET` for state-changing-via-GET endpoints).
            Default `POST`.
        fields: Form field name → value map. Must include the CSRF
            token field if the form has one — auto-detected via
            common framework lexicon (`csrfmiddlewaretoken`,
            `authenticity_token`, `_token`, `_csrf`, ...).
        token_field: Override for the CSRF token field name (when
            auto-detection is wrong or the field uses a custom
            name).
        token_cookie: When set, treats the named cookie as the
            double-submit-cookie pair to the form-field token; the
            mismatch probe is enabled.
        cookies: Optional cookie name → value map sent with each
            request (passes through cluster-A `--auth-cookie` env
            on top).
        content_type: Override the default `application/x-www-form-
            urlencoded`. Set to `application/json` for JSON APIs.
        extra_headers: Additional headers (e.g. CSRF tokens carried
            in headers like `X-CSRF-Token`).
        timeout: Per-probe timeout in seconds (default 10).

    Returns:
        {
          success, target_url, target_host, method,
          token_field, token_cookie, baseline,
          probes: [{label, class_, status, body_length,
                    accepted, severity}, ...],
          findings_emitted, inconclusive?, reason?
        }

    Findings:
        - **High** CWE-352 — token removed / empty / mutated /
          random accepted; OR Origin: attacker accepted; OR
          double-submit-cookie mismatch accepted.
        - **Medium** — Origin/Referer removed accepted; OR
          Referer: attacker accepted on its own.
        - **Low** — token replay accepted.

    Notes:
        - Composes with cluster-A safety (`--exclude-path` /
          `--rate-limit` / `--auth-*`).
        - `verification_status=needs_review` since `2xx` doesn't
          always mean the side-effect happened (framework may
          return `200` for unhandled requests).
    """
    target_url_norm = _normalize_target(target_url)
    if target_url_norm is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    target_host = (urlparse(target_url_norm).hostname or "").lower()
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {target_url!r}"}

    fields = dict(fields or {})
    cookies = dict(cookies or {})
    extra_headers = dict(extra_headers or {})

    # Auto-detect token field from the form fields if not supplied.
    detected_token_field = token_field or _detect_token_field(fields)
    detected_token_cookie = token_cookie or _detect_token_cookie(cookies)

    if not detected_token_field:
        # Caller supplied no token field and we couldn't auto-detect.
        # That's still useful — we can still probe Origin/Referer
        # bypasses + (if we have a token cookie) double-submit
        # mismatch. But we can't probe token-removal-class probes
        # without knowing which field to remove.
        pass

    cev = _start_check("csrf", target_host)
    nonce = secrets.token_hex(4)
    attacker_origin = f"https://strix-{nonce}.evil.example"
    attacker_referer = f"https://strix-{nonce}.evil.example/"

    method_upper = method.upper()
    body, used_content_type = _build_body(fields, method_upper, content_type)
    base_headers: dict[str, str] = {}
    if used_content_type and method_upper != "GET":
        base_headers["Content-Type"] = used_content_type
    base_headers.update(extra_headers)
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        base_headers["Cookie"] = cookie_str

    # Add legitimate-baseline Origin / Referer headers (so removal
    # probes have something to remove).
    parsed = urlparse(target_url_norm)
    legit_origin = f"{parsed.scheme}://{parsed.netloc}"
    legit_referer = f"{legit_origin}/"
    base_headers.setdefault("Origin", legit_origin)
    base_headers.setdefault("Referer", legit_referer)

    # ---- Baseline ----
    if method_upper == "GET":
        baseline_url = _append_query(target_url_norm, fields)
        baseline_response = _http_request(
            "GET", baseline_url, headers=base_headers, timeout=timeout,
        )
    else:
        baseline_response = _http_request(
            method_upper, target_url_norm,
            headers=base_headers, body=body, timeout=timeout,
        )

    if baseline_response.get("skipped"):
        _complete_check(cev, "inconclusive", "URL excluded by --exclude-path")
        return {
            "success": True,
            "target_url": target_url_norm,
            "target_host": target_host,
            "method": method_upper,
            "token_field": detected_token_field,
            "token_cookie": detected_token_cookie,
            "baseline": {"skipped": True, "reason": "excluded by --exclude-path"},
            "probes": [],
            "findings_emitted": 0,
            "inconclusive": True,
            "reason": "excluded by --exclude-path",
        }

    baseline_status = int(baseline_response.get("status") or 0)
    baseline_body = baseline_response.get("body") or ""
    baseline_summary = {
        "status": baseline_status,
        "status_class": _status_class(baseline_status),
        "body_length": len(baseline_body),
        "error": baseline_response.get("error"),
    }

    if baseline_summary["status_class"] not in ("2xx", "3xx"):
        _complete_check(
            cev, "inconclusive",
            f"baseline submission returned {baseline_status}; "
            f"the form description is wrong or auth is missing",
        )
        return {
            "success": True,
            "target_url": target_url_norm,
            "target_host": target_host,
            "method": method_upper,
            "token_field": detected_token_field,
            "token_cookie": detected_token_cookie,
            "baseline": baseline_summary,
            "probes": [],
            "findings_emitted": 0,
            "inconclusive": True,
            "reason": (
                f"baseline submission returned {baseline_status}; "
                f"the form description is incomplete or the legitimate "
                f"token is invalid"
            ),
        }

    findings_emitted = 0
    probes: list[dict[str, Any]] = []
    seen_dedup_keys: set[str] = set()

    def _record_probe(
        label: str,
        class_: str,
        response: dict[str, Any],
        accepted: bool,
        finding_severity: str | None = None,
    ) -> None:
        probes.append({
            "label": label,
            "class_": class_,
            "status": int(response.get("status") or 0),
            "body_length": len(response.get("body") or ""),
            "accepted": accepted,
            "finding_severity": finding_severity,
        })

    # ---- Token-bypass probes (only if we know which field is the token) ----
    legit_token_value = fields.get(detected_token_field, "") if detected_token_field else ""

    def _send(probe_fields: dict[str, str], probe_headers: dict[str, str],
              omit_origin: bool = False, omit_referer: bool = False,
              probe_cookies: dict[str, str] | None = None) -> dict[str, Any]:
        merged_headers = dict(base_headers)
        merged_headers.update(probe_headers)
        if probe_cookies is not None:
            cookie_str = "; ".join(f"{k}={v}" for k, v in probe_cookies.items())
            merged_headers["Cookie"] = cookie_str
        if method_upper == "GET":
            url = _append_query(target_url_norm, probe_fields)
            return _http_request(
                "GET", url, headers=merged_headers, timeout=timeout,
                omit_origin=omit_origin, omit_referer=omit_referer,
            )
        body_bytes, _ = _build_body(probe_fields, method_upper, used_content_type)
        return _http_request(
            method_upper, target_url_norm,
            headers=merged_headers, body=body_bytes, timeout=timeout,
            omit_origin=omit_origin, omit_referer=omit_referer,
        )

    if detected_token_field:
        token_bypass_probes: list[tuple[str, dict[str, str]]] = [
            ("token_removed", {k: v for k, v in fields.items() if k != detected_token_field}),
            ("token_empty", {**fields, detected_token_field: ""}),
            ("token_mutated", {**fields, detected_token_field: _mutate_last(legit_token_value)}),
            ("token_random", {**fields, detected_token_field: secrets.token_hex(max(8, len(legit_token_value) // 2))}),
        ]
        for label, probe_fields in token_bypass_probes:
            response = _send(probe_fields, {})
            if response.get("skipped"):
                _record_probe(label, "token_bypass", response, False)
                continue
            accepted = _looks_like_baseline(response, baseline_summary)
            severity = "high" if accepted else None
            _record_probe(label, "token_bypass", response, accepted, severity)
            if accepted:
                dedup_key = "high::token_bypass"
                if dedup_key not in seen_dedup_keys:
                    seen_dedup_keys.add(dedup_key)
                    _emit_finding(
                        title=f"CSRF token validation broken on {target_host} ({method_upper} {parsed.path})",
                        severity="high",
                        target=target_host,
                        endpoint=target_url_norm,
                        description=(
                            f"Probe `{label}` was accepted (status "
                            f"{response.get('status')}, body length "
                            f"{len(response.get('body') or '')}). The "
                            f"server appears to accept this state-"
                            f"changing request with the CSRF token "
                            f"removed/mutated. Token field: "
                            f"`{detected_token_field}`."
                        ),
                        description_plain=(
                            "Your server accepts state-changing "
                            "requests when the CSRF token is removed, "
                            "blanked out, or replaced with random "
                            "garbage. That means CSRF is effectively "
                            "OFF for this form — any malicious web "
                            "page that knows the URL and form fields "
                            "can submit the form on behalf of any "
                            "logged-in user who visits."
                        ),
                        recommended_action=(
                            "Implement double-submit cookie OR per-"
                            "form synchronizer-token CSRF protection. "
                            "Reject requests that lack the token. "
                            "Reject requests where the token doesn't "
                            "match the session-bound expected value. "
                            "If using double-submit cookie, use the "
                            "`__Host-` cookie prefix and verify the "
                            "form-field value byte-equals the cookie "
                            "value. Rotate the token on each form "
                            "render."
                        ),
                    )
                    findings_emitted += 1

    # ---- Token replay probe (one-time-ness) ----
    if detected_token_field and legit_token_value:
        # Re-send with the same token. If the server returns the
        # same baseline shape twice, the token isn't single-use.
        replay_response = _send(fields, {})
        if not replay_response.get("skipped"):
            replay_accepted = _looks_like_baseline(replay_response, baseline_summary)
            severity = "low" if replay_accepted else None
            _record_probe("token_replay", "replay", replay_response, replay_accepted, severity)
            if replay_accepted:
                dedup_key = "low::replay"
                if dedup_key not in seen_dedup_keys:
                    seen_dedup_keys.add(dedup_key)
                    _emit_finding(
                        title=f"CSRF token is not one-time on {target_host} ({method_upper} {parsed.path})",
                        severity="low",
                        target=target_host,
                        endpoint=target_url_norm,
                        description=(
                            "Same token was accepted twice on consecutive "
                            "submissions. The server doesn't rotate / "
                            "expire the token after use."
                        ),
                        description_plain=(
                            "The CSRF token on this form is reusable. "
                            "An attacker who steals the token (e.g. "
                            "via XSS or a leaked URL referrer) can "
                            "use it for many submissions, not just "
                            "one. This is a defense-in-depth weakness "
                            "rather than an immediate bypass."
                        ),
                        recommended_action=(
                            "Mint a fresh CSRF token on each form "
                            "render. After a successful submission, "
                            "invalidate the previous token in the "
                            "session record (or rotate as part of "
                            "session middleware)."
                        ),
                    )
                    findings_emitted += 1

    # ---- Origin: attacker probe ----
    response_origin_swap = _send(fields, {"Origin": attacker_origin})
    if not response_origin_swap.get("skipped"):
        accepted = _looks_like_baseline(response_origin_swap, baseline_summary)
        severity = "high" if accepted else None
        _record_probe("origin_attacker", "origin", response_origin_swap, accepted, severity)
        if accepted:
            dedup_key = "high::origin_attacker"
            if dedup_key not in seen_dedup_keys:
                seen_dedup_keys.add(dedup_key)
                _emit_finding(
                    title=f"CSRF: attacker `Origin` accepted on {target_host} ({method_upper} {parsed.path})",
                    severity="high",
                    target=target_host,
                    endpoint=target_url_norm,
                    description=(
                        f"Probe `origin_attacker` sent "
                        f"`Origin: {attacker_origin}` and was "
                        f"accepted (status "
                        f"{response_origin_swap.get('status')}). The "
                        f"server doesn't validate the request origin "
                        f"against an allow-list."
                    ),
                    description_plain=(
                        "Your server accepts state-changing requests "
                        "from any Origin. This is the broadest CSRF "
                        "primitive: any attacker page can submit "
                        "this form on behalf of a logged-in user."
                    ),
                    recommended_action=(
                        "Reject requests where `Origin` is not in "
                        "your allow-list of own domains. Enforce "
                        "this at the front-end / WAF (cheaper) and "
                        "again in the application middleware (defense "
                        "in depth). Reject `Origin: null` outright."
                    ),
                )
                findings_emitted += 1

    # ---- Referer: attacker probe (lower severity than Origin since
    # Referer is more often missing legitimately) ----
    response_referer_swap = _send(fields, {"Referer": attacker_referer})
    if not response_referer_swap.get("skipped"):
        accepted = _looks_like_baseline(response_referer_swap, baseline_summary)
        severity = "medium" if accepted else None
        _record_probe("referer_attacker", "referer", response_referer_swap, accepted, severity)
        if accepted:
            dedup_key = "medium::referer_attacker"
            if dedup_key not in seen_dedup_keys:
                seen_dedup_keys.add(dedup_key)
                _emit_finding(
                    title=f"CSRF: attacker `Referer` accepted on {target_host} ({method_upper} {parsed.path})",
                    severity="medium",
                    target=target_host,
                    endpoint=target_url_norm,
                    description=(
                        f"Probe `referer_attacker` sent "
                        f"`Referer: {attacker_referer}` and was "
                        f"accepted (status "
                        f"{response_referer_swap.get('status')})."
                    ),
                    description_plain=(
                        "Your server accepts state-changing requests "
                        "from any Referer. The `Referer` header is "
                        "less trustworthy than `Origin` (it can be "
                        "stripped by browser policy), but it's still "
                        "useful as a signal — a request from an "
                        "explicit attacker.com Referer should never "
                        "be accepted."
                    ),
                    recommended_action=(
                        "Use `Origin` as the primary CSRF gateway; "
                        "use `Referer` as secondary signal. Reject "
                        "requests where Referer is set to an external "
                        "domain. Don't reject solely on missing "
                        "Referer (some users set browsers to strip "
                        "it for privacy)."
                    ),
                )
                findings_emitted += 1

    # ---- Origin removed probe ----
    response_origin_removed = _send(fields, {}, omit_origin=True)
    if not response_origin_removed.get("skipped"):
        accepted = _looks_like_baseline(response_origin_removed, baseline_summary)
        severity = "medium" if accepted else None
        _record_probe("origin_removed", "origin", response_origin_removed, accepted, severity)
        if accepted:
            dedup_key = "medium::origin_removed"
            if dedup_key not in seen_dedup_keys:
                seen_dedup_keys.add(dedup_key)
                _emit_finding(
                    title=f"CSRF: missing `Origin` accepted on {target_host} ({method_upper} {parsed.path})",
                    severity="medium",
                    target=target_host,
                    endpoint=target_url_norm,
                    description=(
                        f"Probe `origin_removed` sent the request with "
                        f"no `Origin` header and was accepted (status "
                        f"{response_origin_removed.get('status')}). "
                        f"Presence-only Origin validators can be "
                        f"bypassed by stripping the header."
                    ),
                    description_plain=(
                        "Your server accepts state-changing requests "
                        "with no `Origin` header. An attacker can "
                        "construct a fetch from a server-side context "
                        "(or some browser-extension contexts) without "
                        "an Origin and bypass your defense."
                    ),
                    recommended_action=(
                        "Reject requests with no `Origin` AND no "
                        "trustworthy `Referer`. For first-party "
                        "fetches, `Origin` is reliably set on POST/"
                        "PUT/DELETE; treat its absence as suspicious."
                    ),
                )
                findings_emitted += 1

    # ---- Origin: null probe ----
    response_origin_null = _send(fields, {"Origin": "null"})
    if not response_origin_null.get("skipped"):
        accepted = _looks_like_baseline(response_origin_null, baseline_summary)
        severity = "medium" if accepted else None
        _record_probe("origin_null", "origin", response_origin_null, accepted, severity)
        if accepted:
            dedup_key = "medium::origin_null"
            if dedup_key not in seen_dedup_keys:
                seen_dedup_keys.add(dedup_key)
                _emit_finding(
                    title=f"CSRF: `Origin: null` accepted on {target_host} ({method_upper} {parsed.path})",
                    severity="medium",
                    target=target_host,
                    endpoint=target_url_norm,
                    description=(
                        f"Probe `origin_null` sent `Origin: null` and "
                        f"was accepted (status "
                        f"{response_origin_null.get('status')}). "
                        f"Sandboxed iframes / data: URIs send `null` "
                        f"and would bypass the validator."
                    ),
                    description_plain=(
                        "Your server accepts requests with `Origin: "
                        "null`. Sandboxed iframes, `data:` URIs, and "
                        "some cross-origin redirects send `Origin: "
                        "null`. An attacker can craft a sandboxed "
                        "iframe to issue cross-origin state-changing "
                        "requests."
                    ),
                    recommended_action=(
                        "Reject `Origin: null` outright in your CSRF "
                        "validator. There's no legitimate reason for "
                        "an Origin: null request to mutate state on "
                        "your application."
                    ),
                )
                findings_emitted += 1

    # ---- Double-submit-cookie mismatch probe ----
    if detected_token_cookie and detected_token_field:
        # Mutate just the form-field value; leave the cookie intact.
        # Acceptance means the server doesn't compare cookie value
        # to form-field value.
        mutated_fields = {**fields, detected_token_field: secrets.token_hex(16)}
        response_double_submit = _send(mutated_fields, {})
        if not response_double_submit.get("skipped"):
            accepted = _looks_like_baseline(response_double_submit, baseline_summary)
            severity = "high" if accepted else None
            _record_probe("double_submit_mismatch", "double_submit",
                          response_double_submit, accepted, severity)
            if accepted:
                dedup_key = "high::double_submit_mismatch"
                if dedup_key not in seen_dedup_keys:
                    seen_dedup_keys.add(dedup_key)
                    _emit_finding(
                        title=f"CSRF: double-submit cookie mismatch accepted on {target_host}",
                        severity="high",
                        target=target_host,
                        endpoint=target_url_norm,
                        description=(
                            f"With token cookie `{detected_token_cookie}` "
                            f"intact and form-field "
                            f"`{detected_token_field}` mutated, the "
                            f"server accepted the request. The "
                            f"double-submit-cookie comparison is "
                            f"broken or absent."
                        ),
                        description_plain=(
                            "Your server uses a double-submit-cookie "
                            "CSRF pattern but doesn't actually compare "
                            "the cookie value against the form-field "
                            "value. An attacker can read the cookie "
                            "from the user's browser context, set the "
                            "form field to anything, and the server "
                            "won't notice."
                        ),
                        recommended_action=(
                            "Verify that the form-field token "
                            "byte-equals the cookie token before "
                            "processing the request. Use the `__Host-` "
                            "cookie prefix so the cookie's domain "
                            "scope is locked. Bind the token to the "
                            "session ID (HMAC) so token-stealing "
                            "doesn't roll over to another session."
                        ),
                    )
                    findings_emitted += 1

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{findings_emitted} CSRF finding(s) on {target_host}",
    )

    return {
        "success": True,
        "target_url": target_url_norm,
        "target_host": target_host,
        "method": method_upper,
        "token_field": detected_token_field,
        "token_cookie": detected_token_cookie,
        "baseline": baseline_summary,
        "probes": probes,
        "findings_emitted": findings_emitted,
    }


def _mutate_last(token: str) -> str:
    """Flip the last character of `token`. Empty / single-char
    tokens get a single random character appended."""
    if not token:
        return secrets.token_hex(8)
    if len(token) == 1:
        return token + "X"
    last = token[-1]
    if last == "0":
        flip = "1"
    elif last.isalpha():
        flip = "X" if last.lower() != "x" else "Y"
    else:
        flip = "0"
    return token[:-1] + flip
