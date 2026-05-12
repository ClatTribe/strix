"""Run-level cost / token budget self-exit (roadmap §4 / PR #113).

When `--max-cost <usd>` or `--max-input-tokens <n>` is set on the
CLI, this module accumulates LLM token usage across every agent
in the run and signals the agent loop to terminate cleanly when
either limit is breached. Strix exits with the documented
`EXIT_BUDGET_EXCEEDED` (3) and emits a `run.terminated` event.

Distinction from per-sub-agent budgets (§8.0 / #88):

* Per-sub-agent budget (`AgentState.max_cost_usd`) caps a single
  specialist so one runaway agent doesn't starve the cohort.
* Run-level budget (this module) caps the WHOLE scan. A lead
  agent that spawns ten specialists each within their own
  individual budget can still collectively blow past the run cap;
  this module is the belt-and-braces against that.

The two compose: a specialist that hits its individual cap stops
itself; the run-level cap stops the scan when the cumulative
crosses the threshold.

Environment-variable contract (so the flag plumbs through Docker
sandbox boundaries the same way other CLI args do):

    STRIX_MAX_COST_USD         — float, USD. 0 / unset = unlimited.
    STRIX_MAX_INPUT_TOKENS_RUN — int. 0 / unset = unlimited.
    STRIX_MAX_DURATION_S       — int, seconds. 0 / unset = unlimited.

Why a module-level singleton: every `LLM` instance is per-agent;
the run-level accumulator must outlive any single agent. A
process-wide module attribute is the cheapest correct location
without introducing a new dependency-injection layer.

The duration cap exits with EXIT_DURATION_EXCEEDED (4) rather
than the cost-cap's EXIT_BUDGET_EXCEEDED (3) so wrappers can
distinguish "ran out of money" from "ran out of time" — they
warrant different follow-ups (budget bump vs. break the target
into smaller scopes).
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any


logger = logging.getLogger(__name__)


_STATE_LOCK = threading.Lock()
_RUN_TOTALS: dict[str, float] = {
    "input_tokens": 0,
    "output_tokens": 0,
    "cached_tokens": 0,
    "cost_usd": 0.0,
    "requests": 0,
}
# Monotonic timestamp of when the scan first kicked off — set
# once by `mark_run_started()` (called from interface/main.py
# at scan entry). All duration checks read against this.
_RUN_STARTED_AT: dict[str, float | None] = {"at": None}
# Latch — flipped True on first breach so we emit `run.terminated`
# exactly once and the agent loop can poll `is_run_budget_exceeded`
# every iteration without spamming events.
_BUDGET_LATCH: dict[str, Any] = {"exceeded": False, "reason": None, "event_emitted": False}


def _read_env_int(name: str) -> int:
    """Read an int env var. Empty / unset / non-numeric → 0 (unlimited)."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return 0
    try:
        return max(0, int(float(raw)))
    except (ValueError, TypeError):
        return 0


def _read_env_float(name: str) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return 0.0
    try:
        return max(0.0, float(raw))
    except (ValueError, TypeError):
        return 0.0


def get_run_caps() -> dict[str, float]:
    """Return current run-level caps as read from the env. Each
    cap of 0 means "unlimited". Read on every call so a wrapper
    that mutates env mid-flight gets immediate effect."""
    return {
        "max_cost_usd": _read_env_float("STRIX_MAX_COST_USD"),
        "max_input_tokens": float(_read_env_int("STRIX_MAX_INPUT_TOKENS_RUN")),
        "max_duration_s": float(_read_env_int("STRIX_MAX_DURATION_S")),
    }


def mark_run_started() -> None:
    """Pin the run's start time for wall-clock duration enforcement.
    Idempotent — repeated calls leave the original timestamp
    untouched. Called from interface/main.py at scan entry, before
    any agent loop starts.

    Why monotonic: system time can drift / be set; monotonic is
    immune to that. We only care about elapsed seconds, not
    wall-clock alignment."""
    with _STATE_LOCK:
        if _RUN_STARTED_AT["at"] is None:
            _RUN_STARTED_AT["at"] = time.monotonic()


def get_run_elapsed_s() -> float:
    """Return seconds since `mark_run_started()` was called. 0.0
    when `mark_run_started()` hasn't fired yet (e.g. during unit
    tests that don't go through the CLI entrypoint)."""
    with _STATE_LOCK:
        started = _RUN_STARTED_AT["at"]
    if started is None:
        return 0.0
    return max(0.0, time.monotonic() - started)


def reset_for_testing() -> None:
    """Clear all in-memory state. Tests call this in fixtures."""
    with _STATE_LOCK:
        _RUN_TOTALS.update({
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_tokens": 0,
            "cost_usd": 0.0,
            "requests": 0,
        })
        _RUN_STARTED_AT["at"] = None
        _BUDGET_LATCH.update({"exceeded": False, "reason": None, "event_emitted": False})


def record_run_usage(
    *,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cached_tokens: int = 0,
    cost_usd: float = 0.0,
) -> None:
    """Accumulate one round-trip's usage onto the run-level
    counters. Thread-safe so concurrent agents don't race."""
    with _STATE_LOCK:
        if input_tokens > 0:
            _RUN_TOTALS["input_tokens"] += int(input_tokens)
        if output_tokens > 0:
            _RUN_TOTALS["output_tokens"] += int(output_tokens)
        if cached_tokens > 0:
            _RUN_TOTALS["cached_tokens"] += int(cached_tokens)
        if cost_usd > 0:
            _RUN_TOTALS["cost_usd"] += float(cost_usd)
        _RUN_TOTALS["requests"] += 1


def get_run_total() -> dict[str, float]:
    """Snapshot of current run-level totals. Returned dict is a
    copy so callers can mutate freely."""
    with _STATE_LOCK:
        return dict(_RUN_TOTALS)


def is_run_budget_exceeded() -> tuple[bool, str | None]:
    """Return `(exceeded, reason)` against the env-var caps.
    `reason` is one of `"max_cost_usd"` / `"max_input_tokens"` /
    `"max_duration_s"` / `None`. Reads `_BUDGET_LATCH` first so
    once-tripped state sticks even if env vars change after the
    breach."""
    with _STATE_LOCK:
        if _BUDGET_LATCH["exceeded"]:
            return True, _BUDGET_LATCH["reason"]

    caps = get_run_caps()
    totals = get_run_total()

    if caps["max_cost_usd"] > 0 and totals["cost_usd"] >= caps["max_cost_usd"]:
        with _STATE_LOCK:
            _BUDGET_LATCH["exceeded"] = True
            _BUDGET_LATCH["reason"] = "max_cost_usd"
        return True, "max_cost_usd"

    if (
        caps["max_input_tokens"] > 0
        and totals["input_tokens"] >= caps["max_input_tokens"]
    ):
        with _STATE_LOCK:
            _BUDGET_LATCH["exceeded"] = True
            _BUDGET_LATCH["reason"] = "max_input_tokens"
        return True, "max_input_tokens"

    if (
        caps["max_duration_s"] > 0
        and get_run_elapsed_s() >= caps["max_duration_s"]
    ):
        with _STATE_LOCK:
            _BUDGET_LATCH["exceeded"] = True
            _BUDGET_LATCH["reason"] = "max_duration_s"
        return True, "max_duration_s"

    return False, None


def emit_run_terminated_event_once() -> None:
    """Emit `run.terminated` exactly once on the first budget
    breach. The latch ensures repeated callers from the agent
    loop don't generate duplicate events."""
    with _STATE_LOCK:
        if _BUDGET_LATCH["event_emitted"]:
            return
        if not _BUDGET_LATCH["exceeded"]:
            return
        reason = _BUDGET_LATCH["reason"]
        _BUDGET_LATCH["event_emitted"] = True

    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return

    caps = get_run_caps()
    totals = get_run_total()
    # Distinguish the cap type so wrappers can ladder up the right
    # follow-up ("bump budget" vs "narrow target / split scan").
    top_reason = "duration_exceeded" if reason == "max_duration_s" else "budget_exceeded"
    try:
        tracer._emit_event(  # noqa: SLF001
            "run.terminated",
            payload={
                "reason": top_reason,
                "budget_dimension": reason,
                "limits": {
                    "max_cost_usd": caps["max_cost_usd"],
                    "max_input_tokens": int(caps["max_input_tokens"]),
                    "max_duration_s": int(caps["max_duration_s"]),
                },
                "consumed": {
                    "input_tokens": int(totals["input_tokens"]),
                    "output_tokens": int(totals["output_tokens"]),
                    "cached_tokens": int(totals["cached_tokens"]),
                    "cost_usd": round(float(totals["cost_usd"]), 6),
                    "requests": int(totals["requests"]),
                    "elapsed_s": round(get_run_elapsed_s(), 2),
                },
            },
            status="terminated",
            source="strix.run",
        )
    except Exception:  # noqa: BLE001
        # Bookkeeping should never break the shutdown path.
        logger.debug("run.terminated emission failed", exc_info=True)
