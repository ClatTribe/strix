"""Logging / monitoring posture detection.

Each customer-facing app's monitoring-readiness is a positive
attestation the auditor wants to see. Strix has the surfaces;
this tool turns them into a structured finding.

Three signal classes
--------------------

1. **Identifying-headers redaction** — `Server` / `X-Powered-By`
   / `X-AspNet-Version` / `X-Generator` headers leak the stack
   identity. Production-hardened apps strip these. Counted as
   a positive signal when ABSENT.

2. **Rate-limiting / WAF presence** — burst probe (4 quick
   identical GETs) checks for `X-RateLimit-*` / `Retry-After`
   / 429 responses. Production apps should rate-limit.

3. **Monitoring / reporting headers** — `Report-To`,
   `Reporting-Endpoints`, `Content-Security-Policy-Report-Only`,
   `Content-Security-Policy` with `report-uri`/`report-to`
   directives, `NEL` (Network Error Logging), `Server-Timing`
   (when stripped down for prod). Each present → +1 monitoring
   posture point.

Score → severity ladder
-----------------------

The check emits ONE `monitoring_posture` finding per target with
the score breakdown. Severity reflects compliance gap:

  * **Info** — score ≥ 4 (well-configured)
  * **Low** — score 2-3 (partial; some gaps)
  * **Medium** — score 0-1 (auditor would flag)

We deliberately don't go higher than medium — this isn't a
vulnerability, it's a compliance / posture gap. CWE-778
(Insufficient Logging) is the closest mapping.

Why this is zero-FP
-------------------

Each probe is a binary header-presence check on responses we
already make. No fuzzing, no inference. The score is sum-of-
binary-signals; the finding is a posture attestation, not a
vuln claim.

References
----------

* SOC 2 CC7.2 — security-event detection
* ISO 27001 A.12.4 — logging / monitoring controls
* PCI-DSS 10.6 — log review procedures
* OWASP A09:2021 — Security Logging and Monitoring Failures
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "monitoring_posture_check"
_DEFAULT_TIMEOUT = 8.0
_BURST_REQUESTS = 4

# Identifying headers — strip in prod = +1 redaction point.
_IDENTIFYING_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-rails-version",
    "x-django-version",
)

# Reporting / monitoring headers — present = +1 monitoring point per class.
# We bucket related headers so a CSP with both `report-to` and `report-uri`
# only counts once.
_MONITORING_HEADER_BUCKETS: dict[str, tuple[str, ...]] = {
    "report_endpoints": ("report-to", "reporting-endpoints"),
    "csp_reporting": ("content-security-policy-report-only",),
    "nel": ("nel",),
    "server_timing": ("server-timing",),
}

# Rate-limit signal headers (presence only).
_RATELIMIT_HEADERS = (
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
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
                "body": (r.get("body") or "")[:8 * 1024],
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
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:8 * 1024],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(d: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in d.items()}


# ---------------------------------------------------------------------------
# Signal computation
# ---------------------------------------------------------------------------


def _evaluate_identifying_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Score 1 when ALL identifying headers are absent. Otherwise 0
    + record which leaked."""
    leaked = [h for h in _IDENTIFYING_HEADERS if h in headers]
    return {
        "redacted": not leaked,
        "leaked_headers": leaked,
        "score": 0 if leaked else 1,
    }


def _evaluate_monitoring_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Score = number of distinct monitoring-header buckets present.
    Also checks CSP for `report-uri`/`report-to` directives — those
    qualify even when no other monitoring header is set."""
    buckets_hit: list[str] = []

    for bucket_name, bucket_headers in _MONITORING_HEADER_BUCKETS.items():
        if any(h in headers for h in bucket_headers):
            buckets_hit.append(bucket_name)

    # Special case: regular CSP header with reporting directives.
    csp = headers.get("content-security-policy", "").lower()
    if "report-uri" in csp or "report-to" in csp:
        if "csp_reporting" not in buckets_hit:
            buckets_hit.append("csp_reporting")

    return {
        "monitoring_buckets_present": buckets_hit,
        "score": len(buckets_hit),
    }


def _evaluate_rate_limit(burst_responses: list[dict[str, Any]]) -> dict[str, Any]:
    """Score 1 when ANY of: rate-limit headers seen, 429 status
    seen, or `Retry-After` seen. Score 0 otherwise."""
    rate_headers_seen: list[str] = []
    saw_429 = False
    for r in burst_responses:
        if int(r.get("status") or 0) == 429:
            saw_429 = True
        for h in _RATELIMIT_HEADERS:
            if h in r.get("headers", {}) and h not in rate_headers_seen:
                rate_headers_seen.append(h)

    score = 1 if (rate_headers_seen or saw_429) else 0
    return {
        "rate_limit_headers": rate_headers_seen,
        "saw_429": saw_429,
        "score": score,
    }


def _severity_for_score(score: int) -> str:
    if score >= 4:
        return "info"
    if score >= 2:
        return "low"
    return "medium"


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


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
    # Build a one-line summary of the score breakdown for description.
    redacted = breakdown["identifying_headers"]["redacted"]
    leaked = breakdown["identifying_headers"]["leaked_headers"]
    monitoring_buckets = breakdown["monitoring_headers"]["monitoring_buckets_present"]
    rate_limited = breakdown["rate_limit"]["score"] == 1
    saw_429 = breakdown["rate_limit"]["saw_429"]

    description_parts = [
        f"Monitoring-posture score: **{score} / 6**.",
        f"Identifying headers redacted: {'yes' if redacted else 'no — leaks: ' + ', '.join(leaked)}.",
        f"Monitoring headers: {', '.join(monitoring_buckets) if monitoring_buckets else '(none)'}.",
        f"Rate-limiting: {'observed' if rate_limited else 'not observed'} "
        f"(429-in-burst: {'yes' if saw_429 else 'no'}).",
    ]

    description = " ".join(description_parts)
    plain = (
        f"Your app's monitoring posture: score {score}/6. "
        f"{'Well-configured.' if severity == 'info' else 'Some gaps — see breakdown.' if severity == 'low' else 'Auditors will flag this.'}"
    )

    recommendations = []
    if not redacted:
        recommendations.append(
            "Strip identifying response headers (Server / X-Powered-By / "
            "X-AspNet-Version / etc.) at the reverse-proxy edge."
        )
    if not monitoring_buckets:
        recommendations.append(
            "Add reporting endpoints — set `Report-To` / `Reporting-Endpoints` "
            "headers + a CSP with `report-uri` / `report-to` so client-side "
            "errors and CSP violations surface in your monitoring."
        )
    if not rate_limited:
        recommendations.append(
            "Add rate-limit headers (`X-RateLimit-*`) on every dynamic endpoint. "
            "Without them, abuse detection runs blind."
        )
    if not recommendations:
        recommendations.append(
            "Continue current posture; periodic re-attestation per audit cycle."
        )

    tracer.add_vulnerability_report(
        title=f"Monitoring posture: score {score}/6 ({severity})",
        severity=severity,
        category="monitoring_posture",
        cwe="CWE-778",  # Insufficient Logging
        target=target,
        endpoint=target,
        description=description,
        impact=(
            "Logging / monitoring posture is an auditor's first question on "
            "every SOC 2 / ISO 27001 / PCI-DSS engagement. A clean attestation "
            "answers it directly. Gaps slow audit cycles and may force "
            "compensating-control language in the report."
        ),
        remediation_steps="\n\n".join(recommendations),
        description_plain=plain,
        recommended_action=recommendations[0] if recommendations else "",
        verification_status="verified",
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
    return target


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1592"],
)
def monitoring_posture_check(
    target_url: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe a web target's logging / monitoring posture.

    Args:
        target_url: web target (URL or bare host; auto-prefixed `https://`).
        timeout: per-request HTTP timeout (default 8s).

    Returns:
        ```
        {
          success, target, score, max_score=6, severity,
          identifying_headers: {redacted, leaked_headers, score},
          monitoring_headers: {monitoring_buckets_present, score},
          rate_limit: {rate_limit_headers, saw_429, score},
          findings_emitted: 1,
          errors?: [str, ...],
        }
        ```

    Findings (CWE-778):
        - **Info** — score ≥ 4 (well-configured)
        - **Low** — score 2-3 (partial; some gaps)
        - **Medium** — score 0-1 (auditor will flag)

    Always emits exactly one finding per target — this is a
    positive-attestation tool, the gap is informational.
    """
    target = _normalize_target(target_url)
    if target is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    parsed = urlparse(target)
    target_host = parsed.netloc
    check_id = _start_check(category="monitoring_posture", surface=target_host)
    errors: list[str] = []

    # Single primary fetch for headers analysis.
    primary = _http_get(target, timeout=timeout)
    if primary.get("error"):
        errors.append(primary["error"])
    if primary.get("skipped"):
        _complete_check(check_id, result="skipped", evidence="probe excluded")
        return {
            "success": True,
            "target": target_host,
            "score": 0,
            "max_score": 6,
            "severity": None,
            "skipped": True,
            "errors": errors or None,
        }

    headers = primary.get("headers") or {}

    # Burst probe for rate-limit detection (4 GETs).
    burst_responses = [primary]
    for _ in range(_BURST_REQUESTS - 1):
        r = _http_get(target, timeout=timeout)
        if not r.get("error") and not r.get("skipped"):
            burst_responses.append(r)

    identifying = _evaluate_identifying_headers(headers)
    monitoring = _evaluate_monitoring_headers(headers)
    rate_limit = _evaluate_rate_limit(burst_responses)

    # Total score: 0-6. Identifying-redaction = 0 or 1; monitoring
    # buckets max 4 (report_endpoints / csp_reporting / nel /
    # server_timing); rate-limit = 0 or 1. Total max = 6.
    score = identifying["score"] + monitoring["score"] + rate_limit["score"]

    breakdown = {
        "identifying_headers": identifying,
        "monitoring_headers": monitoring,
        "rate_limit": rate_limit,
    }
    _emit_finding(target=target_host, score=score, breakdown=breakdown)

    severity = _severity_for_score(score)
    _complete_check(
        check_id,
        result="vulnerable" if severity == "medium" else "not_vulnerable",
        evidence=f"posture score {score}/6, severity={severity}",
    )

    out: dict[str, Any] = {
        "success": True,
        "target": target_host,
        "score": score,
        "max_score": 6,
        "severity": severity,
        "identifying_headers": identifying,
        "monitoring_headers": monitoring,
        "rate_limit": rate_limit,
        "findings_emitted": 1,
    }
    if errors:
        out["errors"] = errors
    return out
