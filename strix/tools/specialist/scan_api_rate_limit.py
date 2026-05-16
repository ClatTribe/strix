"""`scan_api_rate_limit` — OWASP API4:2023 (Unrestricted Resource
Consumption) probe.

Bursts an endpoint with N requests and looks for the canonical
rate-limit signals: 429 status codes, `Retry-After`, or any
`X-RateLimit-*` header. The absence of all three from a small,
slow burst is the finding — production APIs MUST throttle.

## Safety posture

Rate-limit probing is the most "is this DoS?" tool in Strix.
Defaults are conservative:

  * **Burst defaults to 30** requests with 100ms intervals
    (≈3 req/sec). Lower than typical production rate limits;
    won't trip an alert unless the target's threshold is
    pathologically low.
  * **Hard cap** of 200 requests via `STRIX_RATE_LIMIT_PROBE_MAX_BURST`.
  * **Kill switch**: `STRIX_RATE_LIMIT_PROBE_DISABLED=1` short-
    circuits the whole specialist.
  * **Auto-stop**: if a 429 fires inside the first 5 requests,
    we stop immediately — the target throttles aggressively;
    no need to keep probing.
  * **Auto-stop on 5xx**: if the target starts 5xx-ing inside
    the first 5 requests, stop — we're causing load, not
    measuring throttling.

## Detection logic

Per-request observations:
  * `status` — HTTP status code.
  * `retry_after` — `Retry-After` header (presence).
  * `ratelimit_headers` — any `X-RateLimit-*` header (presence).
  * `latency_ms` — round-trip time.

After the burst:

  * **PASS (no finding)** — at least one of {429 status,
    `Retry-After`, `X-RateLimit-*` header} observed.
  * **FAIL (medium severity)** — none of the rate-limit signals
    observed across the full burst.
  * **FAIL (high severity)** — same as above AND the endpoint
    looks auth-walled / write-shaped (POST/PUT/PATCH/DELETE).
    Auth-walled write endpoints without rate limits are the
    canonical credential-stuffing / abuse vector.

## What this scanner does NOT do

  * Doesn't try to bypass observed rate-limits (header
    spoofing, IP rotation) — that's a separate research task.
  * Doesn't probe pricing-API surfaces specifically (Stripe-
    style cost-of-call). Those need vendor-specific scanners.
  * Doesn't fuzz request bodies — `scan_api_mass_assignment`
    is the follow-up.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import FindingDraft, SpecialistResult


logger = logging.getLogger(__name__)


_DEFAULT_BURST = 30
_DEFAULT_INTERVAL_SECONDS = 0.1
_DEFAULT_TIMEOUT_SECONDS = 8.0
_HARD_CAP_BURST = 200
_FAST_FAIL_WINDOW = 5    # if rate-limit / 5xx fires in first N, stop


def _kill_switched() -> bool:
    return os.environ.get("STRIX_RATE_LIMIT_PROBE_DISABLED") == "1"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _is_write_method(method: str) -> bool:
    return method.upper() in ("POST", "PUT", "PATCH", "DELETE")


def _has_rate_limit_signal(headers: dict[str, str]) -> tuple[bool, list[str]]:
    """Inspect response headers for any rate-limit-shaped header.
    Returns (is_present, sample_header_names)."""
    if not isinstance(headers, dict):
        return False, []
    seen: list[str] = []
    for name in headers:
        if not isinstance(name, str):
            continue
        low = name.lower()
        if low == "retry-after":
            seen.append(name)
        elif low.startswith("x-ratelimit") or low.startswith("ratelimit"):
            seen.append(name)
        elif low == "x-rate-limit-remaining":
            seen.append(name)
    return bool(seen), seen


def _http_burst(
    *,
    url: str,
    method: str,
    burst: int,
    interval_seconds: float,
    timeout_seconds: float,
    extra_headers: dict[str, str] | None,
    fetcher,
) -> list[dict[str, Any]]:
    """Send `burst` requests sequentially with `interval_seconds`
    pause between each. Returns one observation dict per request.

    Auto-stops on:
      * first 429 / `Retry-After` / `X-RateLimit-*` inside the
        fast-fail window (the target throttles; no value in
        burning more requests).
      * first 5xx inside the fast-fail window (we're causing
        damage; back off).
    """
    observations: list[dict[str, Any]] = []
    for i in range(burst):
        started = time.monotonic()
        try:
            status, headers = fetcher(
                url=url, method=method, headers=extra_headers,
                timeout=timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "rate_limit_probe: fetcher raised on burst[%d]: %s",
                i, exc,
            )
            observations.append({
                "index": i, "error": f"{type(exc).__name__}: {exc}",
            })
            continue
        latency = (time.monotonic() - started) * 1000.0
        present, headers_seen = _has_rate_limit_signal(headers or {})
        obs = {
            "index": i,
            "status": status,
            "latency_ms": round(latency, 2),
            "rate_limit_signal": present,
            "rate_limit_headers": headers_seen,
        }
        observations.append(obs)

        if i < _FAST_FAIL_WINDOW:
            if status == 429 or present:
                # Throttling already observed; the target enforces
                # rate limits. Stop early.
                break
            if isinstance(status, int) and status >= 500:
                # Don't keep hammering when responses are erroring.
                break

        if i < burst - 1:
            time.sleep(interval_seconds)
    return observations


def _analyse_observations(
    observations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Roll up burst observations into a single verdict."""
    saw_429 = any(o.get("status") == 429 for o in observations)
    saw_signal = any(o.get("rate_limit_signal") for o in observations)
    saw_5xx = any(
        isinstance(o.get("status"), int) and o["status"] >= 500
        for o in observations
    )
    statuses = [o.get("status") for o in observations if "status" in o]
    return {
        "saw_429": saw_429,
        "saw_signal": saw_signal,
        "saw_5xx": saw_5xx,
        "total_requests": len(observations),
        "status_counts": {
            code: sum(1 for s in statuses if s == code)
            for code in set(statuses)
        },
        "verdict": (
            "rate_limited" if (saw_429 or saw_signal)
            else "no_throttle_observed"
        ),
    }


def _default_fetcher(
    *, url: str, method: str,
    headers: dict[str, str] | None,
    timeout: float,
) -> tuple[int | None, dict[str, str]]:
    """Production fetcher — httpx-based, falls back to (None, {})
    when httpx isn't available."""
    try:
        import httpx
    except ImportError:
        return None, {}
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as c:
            r = c.request(method, url, headers=headers or None)
            # httpx headers are CaseInsensitiveDict — coerce to dict
            # so downstream `.lower()` membership checks behave.
            hdrs = {k: v for k, v in r.headers.items()}
            return r.status_code, hdrs
    except Exception:  # noqa: BLE001
        return None, {}


@register_specialist_tool(
    category="api-rate-limit-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1499"],   # Endpoint Denial of Service
)
def scan_api_rate_limit(
    *,
    url: str,
    method: str = "GET",
    burst: int = _DEFAULT_BURST,
    interval_seconds: float = _DEFAULT_INTERVAL_SECONDS,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    extra_headers: dict[str, str] | None = None,
    auth_walled: bool = False,
    _fetcher=None,
) -> SpecialistResult:
    """Probe one API endpoint for missing rate-limiting (OWASP
    API4:2023 Unrestricted Resource Consumption / CWE-770).

    Args:
        url: full endpoint URL to probe. For templated paths
            from openapi_spec_ingest, the caller must instantiate
            path parameters first.
        method: HTTP method (default GET). Write methods get a
            higher-severity finding when unthrottled.
        burst: how many requests to send (default 30, hard cap
            via `STRIX_RATE_LIMIT_PROBE_MAX_BURST` env).
        interval_seconds: pause between requests (default 0.1s
            → ~10 req/sec).
        timeout_seconds: per-request HTTP timeout.
        extra_headers: optional auth headers / API key.
        auth_walled: when True, mark the endpoint as auth-walled
            (a missing rate limit on an auth-walled write
            endpoint is the credential-stuffing / abuse pattern;
            severity escalates to high).
        _fetcher: injection point for tests.

    Kill switch: `STRIX_RATE_LIMIT_PROBE_DISABLED=1`.
    """
    if _kill_switched():
        return SpecialistResult(
            status="error",
            error="kill_switch (STRIX_RATE_LIMIT_PROBE_DISABLED)",
        )

    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return SpecialistResult(
            status="error", error=f"invalid url scheme: {url!r}",
        )

    hard_cap = _env_int("STRIX_RATE_LIMIT_PROBE_MAX_BURST", _HARD_CAP_BURST)
    burst_capped = max(1, min(burst, hard_cap))

    fetcher = _fetcher or _default_fetcher
    observations = _http_burst(
        url=url, method=method.upper(),
        burst=burst_capped, interval_seconds=interval_seconds,
        timeout_seconds=timeout_seconds,
        extra_headers=extra_headers, fetcher=fetcher,
    )
    analysis = _analyse_observations(observations)

    # Avoid divide-by-zero on rate-rate strings (test-mode
    # interval_seconds=0 is valid; just report it as "burst").
    rate_label = (
        f"{1.0/interval_seconds:.1f} req/sec"
        if interval_seconds > 0
        else "burst (no interval)"
    )
    findings: list[FindingDraft] = []
    evidence: list[str] = [
        f"burst={burst_capped}, interval={interval_seconds}s, "
        f"method={method.upper()}",
        f"verdict={analysis['verdict']}",
        f"status_counts={analysis['status_counts']}",
    ]
    next_probes: list[str] = []

    # Order matters: a 5xx-on-burst doesn't mean "no throttle" —
    # the target may be degrading under load rather than emitting
    # 429s. Don't emit a finding; surface evidence for review.
    if analysis["saw_5xx"]:
        evidence.append("auto-stopped on 5xx within fast-fail window")
        next_probes.append(
            "Endpoint returned 5xx during burst — investigate whether "
            "throttling is implemented via response degradation rather "
            "than 429. Manual review recommended."
        )
    elif analysis["verdict"] == "no_throttle_observed":
        # No rate-limit signal across the full burst → missing
        # throttling. Severity depends on the endpoint shape.
        is_write = _is_write_method(method)
        if is_write or auth_walled:
            severity = "high"
            sev_reason = (
                "auth-walled / write endpoint without rate-limit — "
                "credential stuffing / abuse vector"
            )
        else:
            severity = "medium"
            sev_reason = (
                "read endpoint without rate-limit — DoS / scraping "
                "vector"
            )

        findings.append(FindingDraft(
            title=(
                f"Missing rate limit on {method.upper()} {url} "
                f"({analysis['total_requests']} requests, no 429 / "
                f"Retry-After / X-RateLimit-* observed)"
            ),
            severity=severity,
            cwe="CWE-770",
            endpoint=url,
            description=(
                f"Sent {analysis['total_requests']} requests to "
                f"{method.upper()} {url} at "
                f"{rate_label}. None of the "
                f"canonical rate-limit signals fired: no 429, no "
                f"`Retry-After`, no `X-RateLimit-*` headers.\n\n"
                f"Severity rationale: {sev_reason}.\n\n"
                f"Status-code histogram: {analysis['status_counts']}"
            ),
            verification_status="verified",
            confidence=0.85,
            category="api_rate_limit",
            reasoning_trace=[
                f"Bursted {burst_capped} requests at {rate_label}.",
                "No 429 across the burst → no throttle.",
                "No Retry-After header observed.",
                "No X-RateLimit-* header observed.",
                f"Method={method.upper()} is_write={is_write}; "
                f"auth_walled={auth_walled}.",
                f"Severity: {severity} ({sev_reason}).",
            ],
        ))
        next_probes.append(
            f"Re-test {method.upper()} {url} with a longer burst "
            f"(N=100) to confirm — the short default may have "
            f"missed a delayed-rollover rate limit."
        )
        if is_write:
            next_probes.append(
                "Probe credential-stuffing if this endpoint accepts "
                "username/password — `scan_auth_flow` with credential-"
                "list mode."
            )

    return SpecialistResult(
        status="ok",
        findings=findings,
        evidence=evidence,
        next_probes_suggested=next_probes,
        tool_metadata={
            "analysis": analysis,
            "observations": observations,
        },
    )
