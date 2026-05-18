"""`scan_race_condition` — TOCTOU / time-of-check-time-of-use detector
via parallel-fire probes against state-changing endpoints.

masterroadmap §1 P2 — business-logic attack class that hardly any
competitor covers. The vulnerability shape:

  * **Coupon / promo redemption** — single-use coupon applied N
    times in parallel; server re-reads + re-writes coupon state
    without locking → all N succeed.
  * **Wallet / balance transfer** — withdraw $100 fired N times
    while balance is $100 — multiple succeed, balance goes
    negative.
  * **Invite / referral redemption** — referral bonus pays out
    N times.
  * **Rate-limited action** — N parallel requests slip through
    the rate-limit window check before any has been recorded.
  * **Account / object creation with unique constraint** — N
    parallel POSTs to `/signup` with the same email all succeed
    (uniqueness check beats the insert).

## Detection model

Two-phase: baseline + parallel-fire.

  1. **Baseline** — issue ONE request to the target endpoint with
     the operator-supplied body. Record:
        * status code
        * response body (truncated)
        * a numeric-ish field if one was given (`success_field`)
          — extract its baseline value for comparison.

  2. **Parallel-fire** — issue N concurrent requests using
     `concurrent.futures.ThreadPoolExecutor`. Capture each
     response. Default `concurrency=20` — empirically enough to
     hit the typical race window without DoS'ing the target.

  3. **Classification** — count successful responses:
        * Same status as baseline OR explicit
          `success_status_codes` allow-list.
     If `>1` successful response when the operator says
     `expected_max_successes=1` (default), emit a race-condition
     finding.

## Safety contract

Read-aware mutation: this tool calls state-changing endpoints.
The operator is responsible for the engagement-scope authorisation;
strix only fires what the operator explicitly invokes.

  * Concurrency capped at 50 to prevent accidental DoS.
  * Per-request timeout default 10s.
  * Stops at first detection unless `keep_firing=True`.
  * `cooldown_seconds=1.0` between baseline + parallel fire so
    the server has time to settle (otherwise baseline ≠ steady-
    state).

## Why this is the differentiator

Burp Suite Pro has "Turbo Intruder" which is the gold-standard
race tester but it's a manual + heavyweight setup. Engine-side
auto-emission with reasonable defaults closes the gap for the
80% of cases that are "POST this endpoint N times in parallel,
look for >1 success."
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Per-request timeout cap. The race-window is short; long timeouts
# only mask flapping servers.
_DEFAULT_TIMEOUT = 10.0

# Max concurrency cap — prevent accidental DoS on the operator's
# target. The race-window is typically <100ms; 20 parallel is
# enough to hit it.
_MAX_CONCURRENCY = 50
_DEFAULT_CONCURRENCY = 20

# Cooldown between baseline + parallel fire so the server has
# time to settle.
_DEFAULT_COOLDOWN_SECONDS = 1.0


@dataclass
class _Response:
    """Captured response from a single probe."""

    status: int | None
    body: str
    elapsed: float
    error: str | None = None


def _is_success(
    response: _Response,
    *,
    success_status_codes: tuple[int, ...] | None,
    baseline_status: int | None,
) -> bool:
    """Classify a response as a 'successful' state-changing
    operation. When `success_status_codes` is explicit, use it;
    otherwise fall back to "same status code as baseline AND not
    4xx/5xx"."""
    if response.error is not None or response.status is None:
        return False
    if success_status_codes:
        return response.status in success_status_codes
    if baseline_status is None:
        # No baseline → conservative; treat 2xx as success.
        return 200 <= response.status < 300
    return (
        response.status == baseline_status
        and 200 <= response.status < 400
    )


def _extract_field(body: str, field: str) -> Any:
    """Best-effort: parse the response as JSON and walk dotted-
    path keys (`balance` / `data.balance`)."""
    if not body or not field:
        return None
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    cursor: Any = doc
    for part in field.split("."):
        if isinstance(cursor, dict) and part in cursor:
            cursor = cursor[part]
        else:
            return None
    return cursor


def _emit_finding(
    *,
    url: str,
    successes: int,
    expected_max: int,
    sample_responses: list[_Response],
    baseline: _Response,
    success_field: str | None,
    field_values: list[Any],
) -> str | None:
    """Build + emit a race-condition finding via the tracer."""
    try:
        from strix.telemetry.tracer import get_global_tracer  # noqa: PLC0415

        tracer = get_global_tracer()
    except Exception:  # noqa: BLE001
        tracer = None

    severity = "high" if successes >= expected_max * 5 else "medium"
    title = (
        f"Race condition (TOCTOU): {successes} parallel requests "
        f"succeeded against {url}"
    )
    description = (
        f"Fired {successes + (1 if baseline.error is None else 0)} "
        f"parallel requests against `{url}`; "
        f"{successes} succeeded (expected ≤ {expected_max}). The "
        "endpoint lacks atomic state checks — its check-then-write "
        "logic exposes a race window in which multiple requests "
        "observe stale state and all win."
    )
    if success_field and field_values:
        description += (
            f"\n\nObserved values for `{success_field}` across "
            f"responses: {field_values[:10]}"
        )
    impact = (
        "Bypasses single-use / quota / uniqueness invariants. "
        "Typical exploits: coupon double-redemption, wallet "
        "double-spend, referral / invite multi-claim, unique-"
        "constraint bypass."
    )
    remediation = (
        "Replace check-then-write with an atomic operation: "
        "database-level unique constraint + INSERT…ON CONFLICT, "
        "row-level SELECT…FOR UPDATE inside a transaction, or "
        "a distributed lock (Redis SETNX + TTL) keyed by the "
        "invariant identifier (coupon ID, account ID, email). "
        "Avoid app-level `if exists: error` flows."
    )

    if tracer is None:
        return None

    try:
        return tracer.add_vulnerability_report(
            title=title[:480],
            severity=severity,
            target=url,
            description=description[:2000],
            impact=impact,
            remediation_steps=remediation,
            category="race_condition",
            cwe="CWE-362",
            verification_status="verified",
            poc_description=(
                f"Issue {expected_max + 1} parallel POST requests "
                f"to {url} with identical body; observe "
                f"{successes} successful responses (>{expected_max})."
            ),
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_race_condition: emit failed: %s", e)
        return None


def _default_http(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None,
    body: str | bytes | None,
    timeout: float,
) -> _Response:
    """Default HTTP runner — urllib only so this works in the
    container sandbox without external deps."""
    import urllib.error  # noqa: PLC0415
    import urllib.request  # noqa: PLC0415

    data: bytes | None
    if isinstance(body, str):
        data = body.encode("utf-8", errors="replace")
    else:
        data = body

    req = urllib.request.Request(
        url=url,
        method=method.upper(),
        headers=headers or {},
        data=data,
    )
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read(64 * 1024).decode("utf-8", errors="replace")
            return _Response(
                status=resp.status,
                body=text,
                elapsed=time.monotonic() - start,
            )
    except urllib.error.HTTPError as e:
        # HTTP 4xx/5xx still produces a meaningful classification —
        # capture the status.
        try:
            text = e.read(64 * 1024).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            text = ""
        return _Response(
            status=e.code,
            body=text,
            elapsed=time.monotonic() - start,
        )
    except urllib.error.URLError as e:
        return _Response(
            status=None,
            body="",
            elapsed=time.monotonic() - start,
            error=str(e.reason),
        )
    except Exception as e:  # noqa: BLE001
        return _Response(
            status=None,
            body="",
            elapsed=time.monotonic() - start,
            error=f"{type(e).__name__}: {e}",
        )


@register_specialist_tool(
    category="race-condition-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190"],
)
def scan_race_condition(
    *,
    url: str,
    method: str = "POST",
    body: str | None = None,
    headers: dict[str, str] | None = None,
    concurrency: int = _DEFAULT_CONCURRENCY,
    expected_max_successes: int = 1,
    success_status_codes: list[int] | None = None,
    success_field: str | None = None,
    timeout_seconds: float = _DEFAULT_TIMEOUT,
    cooldown_seconds: float = _DEFAULT_COOLDOWN_SECONDS,
    _http: Callable[..., _Response] | None = None,
) -> SpecialistResult:
    """Fire N parallel requests against a state-changing endpoint;
    flag when more than `expected_max_successes` succeed.

    Args:
        url: target endpoint (the state-changing one — checkout,
            redeem-coupon, transfer, signup, etc.).
        method: HTTP method (default POST).
        body: request body (string; raw — no auto-JSON-encoding).
        headers: request headers including auth.
        concurrency: parallel request count. Capped at 50.
        expected_max_successes: how many successes constitute a
            "race condition triggered" (default 1 — single-use
            invariant).
        success_status_codes: explicit allow-list of status codes
            that count as success. When None, falls back to
            "matches baseline status AND 2xx/3xx".
        success_field: optional dotted-path JSON field whose
            value gets extracted from each response for the
            finding (e.g. `balance` — see if value diverges).
        timeout_seconds: per-request timeout.
        cooldown_seconds: pause between baseline + parallel fire.
        _http: DI hook for tests.

    Auto-emits a finding when race condition triggers.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    parsed = urlparse(url.strip())
    if not parsed.hostname:
        return SpecialistResult(status="error", error="invalid url")
    if method.upper() not in (
        "GET", "POST", "PUT", "PATCH", "DELETE",
    ):
        return SpecialistResult(
            status="error",
            error=f"unsupported method: {method!r}",
        )

    concurrency = max(2, min(int(concurrency), _MAX_CONCURRENCY))
    expected_max_successes = max(1, int(expected_max_successes))
    timeout_seconds = max(1.0, min(float(timeout_seconds), 60.0))
    cooldown_seconds = max(0.0, min(float(cooldown_seconds), 10.0))

    http = _http if _http is not None else _default_http
    success_codes = (
        tuple(int(c) for c in success_status_codes)
        if success_status_codes else None
    )

    # Phase 1: baseline. One request observed under steady-state
    # to anchor the success-classification.
    baseline = http(
        method, url,
        headers=headers, body=body, timeout=timeout_seconds,
    )
    if baseline.error is not None:
        return SpecialistResult(
            status="error",
            error=f"baseline request failed: {baseline.error}",
        )

    baseline_field = (
        _extract_field(baseline.body, success_field)
        if success_field else None
    )

    # Cooldown — let the server settle before the burst.
    if cooldown_seconds > 0:
        time.sleep(cooldown_seconds)

    # Phase 2: parallel fire. ThreadPoolExecutor with the operator's
    # concurrency setting; capture every response.
    responses: list[_Response] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(
                http, method, url,
                headers=headers, body=body, timeout=timeout_seconds,
            )
            for _ in range(concurrency)
        ]
        for f in as_completed(futures):
            try:
                responses.append(f.result())
            except Exception as e:  # noqa: BLE001
                responses.append(_Response(
                    status=None, body="", elapsed=0.0,
                    error=f"{type(e).__name__}: {e}",
                ))

    # Phase 3: classification.
    successful = [
        r for r in responses
        if _is_success(
            r,
            success_status_codes=success_codes,
            baseline_status=baseline.status,
        )
    ]
    field_values: list[Any] = []
    if success_field:
        for r in successful:
            v = _extract_field(r.body, success_field)
            if v is not None:
                field_values.append(v)

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted = 0
    if len(successful) > expected_max_successes:
        rid = _emit_finding(
            url=url,
            successes=len(successful),
            expected_max=expected_max_successes,
            sample_responses=successful[:5],
            baseline=baseline,
            success_field=success_field,
            field_values=field_values,
        )
        if rid:
            emitted += 1
            drafts.append(FindingDraft(
                title=(
                    f"[race] {len(successful)} parallel successes "
                    f"on {url}"
                )[:480],
                severity=(
                    "high" if len(successful) >= expected_max_successes * 5
                    else "medium"
                ),
                cwe="CWE-362",
                endpoint=url,
                category="race_condition",
                verification_status="verified",
                confidence=0.9,
                description=(
                    f"Race window: {len(successful)} of "
                    f"{concurrency} parallel requests succeeded; "
                    f"expected ≤ {expected_max_successes}."
                )[:480],
            ))
            evidence.append(
                f"race: {len(successful)}/{concurrency} succeeded; "
                f"expected_max={expected_max_successes}; "
                f"baseline_status={baseline.status}"
            )

    tool_metadata: dict[str, Any] = {
        "engine": "race-condition-v1",
        "url": url,
        "method": method.upper(),
        "concurrency": concurrency,
        "expected_max_successes": expected_max_successes,
        "baseline_status": baseline.status,
        "baseline_field_value": baseline_field,
        "total_successes": len(successful),
        "total_responses": len(responses),
        "findings_emitted": emitted,
    }
    if success_field:
        tool_metadata["success_field"] = success_field
        tool_metadata["field_values_sample"] = field_values[:10]

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=[
            "jwt_audit — if the endpoint reads a JWT for identity",
            "scan_business_logic — if the race exploits a state machine",
        ] if emitted else [],
        tool_metadata=tool_metadata,
    )
