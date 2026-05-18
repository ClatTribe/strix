"""Pre-dispatch deterministic gate — step 6 of the v2 cost-
optimization plan (docs/proposals/2026-05-19-scan-mode-cost-
optimization.md, workflow phase 4).

## Why this exists

Before spending the 25K-token system prompt + N inner-LLM
iterations of a fresh-context dispatch, run the deterministic
specialist tool directly against the target. If it finds the
bug, emit the finding and skip the LLM dispatch entirely.

This is strictly additive cost reduction: we never skip a
dispatch we would otherwise have done. The gate short-circuits
only when the deterministic prober *positively confirmed* a
finding. Anything else — no signal, uncertain output, prober
error — falls through to the existing dispatch path.

## Recall-safety contract

  * **The gate can ONLY short-circuit by emitting a confirmed
    finding.** No "skip dispatch because scan_sqli returned
    nothing" — that's exactly the case where the LLM
    specialist still matters (it can try POSTs, different
    content-types, WAF bypasses, etc.).
  * **Probers that error or raise → fall through to dispatch.**
    A buggy prober never blocks dispatch.
  * **Probers that don't exist for a category → fall through.**
    Categories without a registered prober pass through unchanged
    (zero behavior change for `idor`, `xss`, etc. until their
    probers ship).
  * **Kill switch: `STRIX_PREDISPATCH_GATE_DISABLED=1`** bypasses
    the gate entirely.
  * **The gate runs BEFORE the scan-mode cap** so a successful
    pre-probe doesn't consume the per-run dispatch budget. That
    leaves the budget for the harder cases.

## Registry interface

Per-category probers register via `@register_prober("sqli")`.
Each prober receives the target URL and returns a `ProbeResult`
with verdict in {FOUND, UNCERTAIN, NOT_APPLICABLE}. The category
name is normalized to lowercase.

To add a prober for a new category, follow the pattern in
`_sqli_prober` below: call the deterministic specialist tool,
detect "did this just emit a finding?" via tracer-delta, return
FOUND when it did and UNCERTAIN otherwise.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable


logger = logging.getLogger(__name__)


@dataclass
class ProbeResult:
    """The verdict from a deterministic pre-dispatch probe.

    verdicts:
      * FOUND — the prober confirmed a vulnerability and emitted
        a finding (via the global tracer). The orchestrator
        skips the LLM dispatch entirely. `summary` should be a
        one-line description for the dispatch result.
      * UNCERTAIN — the prober ran but didn't confirm anything.
        Falls through to LLM dispatch. `reason` carries any
        useful context (e.g. "scan_sqli probed 4 params, all
        baselined clean").
      * NOT_APPLICABLE — no prober is registered for this
        category, or the gate is disabled, or the prober
        explicitly declined. Falls through to LLM dispatch.
    """
    verdict: str
    findings_count: int = 0
    summary: str = ""
    reason: str = ""


# Prober signature: (target: str, objective: str) -> ProbeResult
ProberFn = Callable[[str, str], ProbeResult]


_PROBERS: dict[str, ProberFn] = {}


def register_prober(category: str) -> Callable[[ProberFn], ProberFn]:
    """Decorator to register a deterministic prober for a
    category. Re-registering the same category overwrites (last
    wins) — useful for tests that want to stub a prober."""
    def decorator(fn: ProberFn) -> ProberFn:
        _PROBERS[category.strip().lower()] = fn
        return fn
    return decorator


def unregister_prober(category: str) -> None:
    """Remove a registered prober. Primarily for tests."""
    _PROBERS.pop(category.strip().lower(), None)


def list_registered_categories() -> list[str]:
    """Return the categories with a registered prober (for
    telemetry + tests)."""
    return sorted(_PROBERS.keys())


def is_disabled() -> bool:
    """Returns True when `STRIX_PREDISPATCH_GATE_DISABLED` is
    truthy. Default is enabled."""
    return os.environ.get(
        "STRIX_PREDISPATCH_GATE_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def try_short_circuit(
    *, category: str, target: str | None, objective: str,
) -> ProbeResult:
    """Run the registered prober for this category, if any.

    Args:
      category: the specialist category being dispatched.
      target: the target URL / endpoint. None → NOT_APPLICABLE.
      objective: the dispatch objective string. Passed through
        to the prober for context.

    Returns:
      ProbeResult. The orchestrator skips the LLM dispatch only
      when verdict == FOUND.
    """
    if is_disabled():
        return ProbeResult(verdict="NOT_APPLICABLE", reason="gate disabled")
    if not target or not isinstance(target, str) or not target.strip():
        return ProbeResult(verdict="NOT_APPLICABLE", reason="no target URL")
    norm_category = (category or "").strip().lower()
    prober = _PROBERS.get(norm_category)
    if prober is None:
        return ProbeResult(
            verdict="NOT_APPLICABLE",
            reason=f"no prober registered for category={norm_category!r}",
        )
    try:
        result = prober(target, objective)
    except Exception as e:  # noqa: BLE001
        # A buggy prober NEVER blocks dispatch — the recall-safety
        # contract says any error falls through to LLM.
        logger.warning(
            "predispatch_gate prober for %s raised: %s",
            norm_category, e,
        )
        return ProbeResult(
            verdict="UNCERTAIN",
            reason=f"prober raised {type(e).__name__}: {e}",
        )
    if not isinstance(result, ProbeResult):
        logger.warning(
            "predispatch_gate prober for %s returned non-ProbeResult: %r",
            norm_category, result,
        )
        return ProbeResult(
            verdict="UNCERTAIN",
            reason="prober returned wrong type",
        )
    return result


# ---------------------------------------------------------------------------
# Helpers — tracer-delta detection
# ---------------------------------------------------------------------------


def _findings_count() -> int:
    """Snapshot the global tracer's vulnerability-report count.
    Returns 0 when the tracer isn't available."""
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return 0
        return len(tracer.vulnerability_reports or [])
    except Exception:  # noqa: BLE001
        return 0


def run_with_finding_delta(
    fn: Callable[[], Any],
    *,
    success_summary: str,
    uncertain_reason: str,
) -> ProbeResult:
    """Run `fn` and detect whether it emitted any new findings to
    the global tracer. Returns FOUND when it did, UNCERTAIN
    otherwise.

    Common helper for probers that wrap an existing deterministic
    specialist tool. The wrapped tool is expected to auto-emit
    findings via `create_vulnerability_report`; this helper just
    detects "did any land while fn ran?"
    """
    before = _findings_count()
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        logger.debug("predispatch helper fn raised: %s", e)
        return ProbeResult(
            verdict="UNCERTAIN",
            reason=f"prober raised {type(e).__name__}: {e}",
        )
    after = _findings_count()
    delta = max(0, after - before)
    if delta > 0:
        return ProbeResult(
            verdict="FOUND",
            findings_count=delta,
            summary=success_summary,
        )
    return ProbeResult(verdict="UNCERTAIN", reason=uncertain_reason)


# ---------------------------------------------------------------------------
# Built-in probers
# ---------------------------------------------------------------------------


@register_prober("sqli")
def _sqli_prober(target: str, objective: str) -> ProbeResult:
    """Pre-dispatch prober for the SQLi category.

    Runs `scan_sqli` directly against the target URL. The
    deterministic scanner auto-discovers query-string params when
    none are passed. If it confirms an injection, the finding is
    emitted by `scan_sqli` itself via the tracer; we detect that
    via finding-count delta and return FOUND. Anything else
    (no params discovered, all baselined clean, tool error) →
    UNCERTAIN, dispatch proceeds.

    Conservative: we don't try POST bodies, alternate content
    types, or auth flows here — those are the LLM specialist's
    job. The gate exists to catch the easy cases at
    deterministic cost.
    """
    try:
        from strix.tools.specialist.scan_sqli import scan_sqli  # noqa: PLC0415
    except Exception as e:  # noqa: BLE001
        return ProbeResult(
            verdict="UNCERTAIN",
            reason=f"scan_sqli unavailable: {e}",
        )

    return run_with_finding_delta(
        lambda: scan_sqli(url=target),
        success_summary=(
            f"predispatch sqli prober confirmed SQLi on {target}"
        ),
        uncertain_reason=(
            "scan_sqli completed without confirming SQLi — "
            "dispatch LLM specialist for deeper probing "
            "(POST/JSON/auth-required surfaces)"
        ),
    )
