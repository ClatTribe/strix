"""Race-condition prober.

For state-changing endpoints (purchase, redeem, transfer,
change-password, vote, claim-coupon), sends N concurrent requests
within milliseconds and counts how many succeeded. When more than
the expected `tolerated_success_count` (default 1) succeed, that's
a TOCTOU primitive: the server didn't acquire a lock fast enough,
so multiple concurrent requests all passed the "is this allowed"
check before any of them had committed the side-effect.

Zero-false-positive design (N+1 verification):

1. Establish baseline: hit the endpoint once, observe success/fail
   shape (status class + body length).
2. Race round 1: dispatch N concurrent requests via `asyncio` /
   `httpx.AsyncClient`. Count successes.
3. If round 1 success-count > tolerated → race round 2 (same
   payload, fresh batch).
4. Round 2 success-count > tolerated → emit finding.

A flaky serial-but-fast endpoint has variable behaviour
(sometimes 1, sometimes 2 successes); a real race condition is
deterministic at the millisecond level. Two consecutive rounds
both showing race-shaped behaviour is the zero-FP signal.

`success-count` definition: status class same as baseline (typically
2xx/3xx) AND body length within ±25% of baseline. Stock 4xx/5xx
responses don't count.

Skip / soft-fail:

- Baseline non-2xx/3xx → inconclusive (caller's payload doesn't
  succeed once; can't measure race).
- Round 1 succeeds exactly `tolerated_success_count` times → no
  finding (the endpoint correctly serialises).
- Round 1 race detected, Round 2 doesn't reproduce → no finding
  (flaky behaviour, not a race).
- Cluster-A `--exclude-path` blocks the URL → graceful no-op.

Caveat: this tool DISPATCHES the state-changing request multiple
times per round. Don't run against production — use staging or
dedicated test account. The agent should manually clean up race-
artefacts after the run when applicable.

Severity:

- **High** CWE-362 (Concurrent Execution Using Shared Resource
  with Improper Synchronisation) — both rounds show race-shaped
  outcome (>tolerated successes).

Each finding carries `description_plain` + `recommended_action`
(use database row-level locks, optimistic-concurrency `WHERE
version=...`, or distributed locks like Redis SETNX with TTL;
move the check + state mutation into a single atomic transaction;
add idempotency keys to state-changing endpoints) and
`verification_status=verified` since N+1 verification is
deterministic.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "race_condition_check"
_DEFAULT_TIMEOUT = 10.0
_DEFAULT_CONCURRENCY = 30


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing for the baseline)
# ---------------------------------------------------------------------------


def _http_request_sync(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    headers = dict(headers or {})

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
                "body": (r.get("body") or "")[:65536],
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
                "body": r.text[:65536],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Async race round
# ---------------------------------------------------------------------------


async def _async_race_round(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    body: bytes | None,
    n: int,
    timeout: float,
) -> list[dict[str, Any]]:
    """Fire N concurrent requests; collect (status, body_length, error)."""
    import httpx

    async def _one(client: "httpx.AsyncClient") -> dict[str, Any]:
        try:
            r = await client.request(method, url, headers=headers, content=body)
            return {"status": r.status_code, "body_length": len(r.text), "error": None}
        except Exception as e:  # noqa: BLE001
            return {"status": 0, "body_length": 0, "error": str(e)}

    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, verify=False,
    ) as client:
        tasks = [_one(client) for _ in range(n)]
        return await asyncio.gather(*tasks)


def _run_race_round(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    body: bytes | None,
    n: int,
    timeout: float,
) -> list[dict[str, Any]]:
    """Sync wrapper that runs the async race round."""
    try:
        return asyncio.run(
            _async_race_round(
                method, url, headers=headers, body=body, n=n, timeout=timeout,
            )
        )
    except RuntimeError:
        # Already inside an event loop — fall back to running on
        # the existing loop via a thread.
        import concurrent.futures

        def _runner() -> list[dict[str, Any]]:
            new_loop = asyncio.new_event_loop()
            try:
                return new_loop.run_until_complete(
                    _async_race_round(
                        method, url, headers=headers, body=body, n=n,
                        timeout=timeout,
                    )
                )
            finally:
                new_loop.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(_runner).result(timeout=timeout * 4)


def _count_successes(
    results: list[dict[str, Any]], baseline: dict[str, Any],
) -> int:
    """Count how many results match the baseline shape (success-class)."""
    base_class = baseline.get("status_class")
    base_len = int(baseline.get("body_length") or 0)
    count = 0
    for r in results:
        status = int(r.get("status") or 0)
        body_len = int(r.get("body_length") or 0)
        if 200 <= status < 300 and base_class == "2xx":
            if base_len > 0:
                ratio = body_len / base_len
                if 0.75 <= ratio <= 1.25:
                    count += 1
            else:
                count += 1
        elif 300 <= status < 400 and base_class == "3xx":
            count += 1
    return count


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
        category="race_condition",
        cwe="CWE-362",  # Concurrent Execution Using Shared Resource
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "Race conditions on state-changing endpoints let an "
            "attacker bypass per-user limits and uniqueness "
            "constraints. Real exploits: redeeming the same "
            "single-use coupon N times, transferring more money than "
            "the account balance allows, voting more than once, "
            "claiming a giveaway item N times. Severity scales with "
            "what the endpoint does — financial / loyalty / voting "
            "endpoints are typically high-impact."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="verified",
    )
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        record_finding_in_kg(
            finding_id=finding_id, url=endpoint, param="concurrent_request",
            cwe="CWE-362", severity=severity, category="race_condition",
            method="POST", detection_kind=title[:60], confidence=0.9,
        )
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug(
            "race_check: kg record failed: %s", e, exc_info=True,
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


def _normalize_target(target: str) -> str | None:
    if not isinstance(target, str):
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


def _build_body(
    fields: dict[str, str], content_type: str,
) -> tuple[bytes | None, str]:
    if not fields:
        return (None, content_type or "")
    if content_type and "json" in content_type.lower():
        import json
        return (json.dumps(fields).encode(), "application/json")
    return (urlencode(fields).encode(), content_type or "application/x-www-form-urlencoded")


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1190"],
)
def race_condition_check(  # noqa: PLR0913
    target_url: str,
    method: str = "POST",
    fields: dict[str, str] | None = None,
    content_type: str = "application/x-www-form-urlencoded",
    cookies: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
    concurrency: int = _DEFAULT_CONCURRENCY,
    tolerated_success_count: int = 1,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe an endpoint for race-condition (TOCTOU) vulnerabilities.

    Workflow:
        1. Baseline: send 1 request, observe success-class.
        2. Race round 1: send `concurrency` concurrent requests.
        3. If success-count > `tolerated_success_count`, race round
           2 with the same payload.
        4. Both rounds confirm → emit finding.

    Args:
        target_url: state-changing endpoint to probe.
        method: HTTP method (default POST).
        fields: form / JSON fields. Default empty.
        content_type: `application/x-www-form-urlencoded` (default)
            or `application/json`.
        cookies / extra_headers: passed through.
        concurrency: number of concurrent requests per round
            (default 30).
        tolerated_success_count: how many concurrent successes are
            ACCEPTABLE. Default 1 (typical: each request should
            succeed exactly once and subsequent requests should
            fail). Bump this for endpoints that legitimately allow
            multiple successes (e.g. add-comment).
        timeout: per-request timeout (default 10s).

    Returns:
        {
          success, target_url, target_host, method,
          baseline: {status, status_class, body_length, error?, skipped?},
          rounds: [{success_count, results: [...]}],
          tolerated_success_count, race_confirmed, findings_emitted,
          inconclusive?, reason?
        }

    Findings:
        - **High** CWE-362 — both race rounds show success-count
          > tolerated.

    Notes:
        - DISPATCHES state-changing requests. Use staging only.
        - N+1 verification (round 1 + round 2) is the zero-FP signal.
        - `verification_status=verified` because two-rounds-confirm
          is deterministic.
        - Composes with cluster-A safety; `--exclude-path` skips.
    """
    target_norm = _normalize_target(target_url)
    if target_norm is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    target_host = (urlparse(target_norm).hostname or "").lower()
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {target_url!r}"}

    fields = dict(fields or {})
    cookies = dict(cookies or {})
    extra_headers = dict(extra_headers or {})

    cev = _start_check("race_condition", target_host)
    method_upper = method.upper()
    body_bytes, used_ct = _build_body(fields, content_type)

    base_headers: dict[str, str] = dict(extra_headers)
    if used_ct and method_upper not in ("GET", "HEAD"):
        base_headers["Content-Type"] = used_ct
    if cookies:
        base_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    # Add a strix nonce so probe artefacts are auditable in target logs.
    nonce = secrets.token_hex(4)
    base_headers["X-Strix-Race-Nonce"] = nonce

    # ---- Baseline ----
    baseline_response = _http_request_sync(
        method_upper, target_norm,
        headers=base_headers,
        body=body_bytes.decode() if body_bytes else "",
        timeout=timeout,
    )
    if baseline_response.get("skipped"):
        _complete_check(cev, "inconclusive", "URL excluded by --exclude-path")
        return {
            "success": True,
            "target_url": target_norm, "target_host": target_host,
            "method": method_upper,
            "baseline": {"skipped": True, "reason": "excluded by --exclude-path"},
            "rounds": [],
            "tolerated_success_count": tolerated_success_count,
            "race_confirmed": False,
            "findings_emitted": 0,
            "inconclusive": True, "reason": "excluded by --exclude-path",
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
            f"baseline returned {baseline_status}; can't measure race",
        )
        return {
            "success": True,
            "target_url": target_norm, "target_host": target_host,
            "method": method_upper,
            "baseline": baseline_summary,
            "rounds": [],
            "tolerated_success_count": tolerated_success_count,
            "race_confirmed": False,
            "findings_emitted": 0,
            "inconclusive": True,
            "reason": (
                f"baseline returned {baseline_status}; race "
                f"measurement requires a successful baseline"
            ),
        }

    # ---- Race round 1 ----
    n = max(2, int(concurrency))
    results_r1 = _run_race_round(
        method_upper, target_norm,
        headers=base_headers, body=body_bytes,
        n=n, timeout=timeout,
    )
    success_r1 = _count_successes(results_r1, baseline_summary)
    rounds: list[dict[str, Any]] = [
        {"round": 1, "success_count": success_r1, "results": results_r1},
    ]

    if success_r1 <= tolerated_success_count:
        # Endpoint correctly serialised; no race.
        _complete_check(
            cev, "not_vulnerable",
            f"round 1: {success_r1}/{n} succeeded (≤ tolerated {tolerated_success_count})",
        )
        return {
            "success": True,
            "target_url": target_norm, "target_host": target_host,
            "method": method_upper,
            "baseline": baseline_summary,
            "rounds": rounds,
            "tolerated_success_count": tolerated_success_count,
            "race_confirmed": False,
            "findings_emitted": 0,
        }

    # ---- Race round 2 (N+1 verification) ----
    # Brief pause to let any backend cleanup settle.
    time.sleep(0.5)

    results_r2 = _run_race_round(
        method_upper, target_norm,
        headers=base_headers, body=body_bytes,
        n=n, timeout=timeout,
    )
    success_r2 = _count_successes(results_r2, baseline_summary)
    rounds.append(
        {"round": 2, "success_count": success_r2, "results": results_r2},
    )

    race_confirmed = (
        success_r1 > tolerated_success_count
        and success_r2 > tolerated_success_count
    )

    findings_emitted = 0
    if race_confirmed:
        description_plain = (
            f"Your endpoint accepts more concurrent successes than "
            f"intended. Across two consecutive race rounds of "
            f"{n} concurrent requests, "
            f"{success_r1} and {success_r2} succeeded — when only "
            f"{tolerated_success_count} should have. An attacker can "
            f"redeem single-use coupons N times, transfer more than "
            f"the balance allows, vote N times, etc. The two-round "
            f"reproduction confirms this is a deterministic race "
            f"condition, not a flaky-but-serial endpoint."
        )
        recommended_action = (
            "Acquire a database row-level lock (e.g. PostgreSQL "
            "`SELECT ... FOR UPDATE`) on the resource being mutated "
            "BEFORE the check-and-update. Or use optimistic "
            "concurrency: add a `version` column, "
            "`UPDATE ... WHERE id=? AND version=?` returning rows-"
            "affected, retry on 0. For distributed systems, use "
            "Redis SETNX with a TTL as a critical-section lock. "
            "For idempotent state changes (purchase, transfer), "
            "require an `Idempotency-Key` header so duplicate "
            "concurrent requests collapse to one logical operation."
        )
        _emit_finding(
            title=f"Race condition on {target_host} ({method_upper} {urlparse(target_norm).path})",
            severity="high",
            target=target_host, endpoint=target_norm,
            description=(
                f"Race-condition probe. Round 1: {success_r1}/{n} "
                f"concurrent requests succeeded (tolerated: "
                f"{tolerated_success_count}). Round 2: {success_r2}"
                f"/{n} succeeded. Both rounds exceed the tolerance "
                f"→ deterministic race. Probe nonce: `strix-{nonce}`."
            ),
            description_plain=description_plain,
            recommended_action=recommended_action,
        )
        findings_emitted = 1

    _complete_check(
        cev,
        result="vulnerable" if race_confirmed else "not_vulnerable",
        evidence=(
            f"round 1: {success_r1}/{n}; round 2: {success_r2}/{n}; "
            f"tolerated: {tolerated_success_count}; "
            f"confirmed: {race_confirmed}"
        ),
    )

    return {
        "success": True,
        "target_url": target_norm, "target_host": target_host,
        "method": method_upper,
        "baseline": baseline_summary,
        "rounds": rounds,
        "tolerated_success_count": tolerated_success_count,
        "race_confirmed": race_confirmed,
        "findings_emitted": findings_emitted,
    }
