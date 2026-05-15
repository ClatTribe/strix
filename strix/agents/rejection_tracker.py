"""OODA-shaped rejection tracker + auto-bypass for tool-call loops.

Closes a real cost pathology observed in the Phase 3d benchmark
(46f12873 / PR #229 + #230): the lead called `finish_scan` **36
consecutive times**, each rejected by the workflow + hypothesis
guards. ~half the run cost ($0.50 of $1.02) was spent on
rejections that produced no findings.

## Root cause (per the user's OODA framing)

Tool-call rejections today are *explanatory* — they tell the
lead WHAT failed and WHY — but they aren't *actionable*. The lead:

  1. **Observes** the rejection ("workflow not in report phase").
  2. ...has no clear **Orient** signal in the response shape.
  3. ...skips **Decide** (which alternative tool to call).
  4. **Acts** by retrying the same `finish_scan` call.

A senior security engineer would do the full OODA cycle —
recognize "guard rejected, so the guard's prerequisite isn't
met, so the next action is the prerequisite, then retry." The
lead doesn't make that jump consistently, especially under
Flash, because the rejection response doesn't FORCE the
reorientation.

## The fix — OODA-shaped responses + escalation + auto-bypass

1. **Structured OODA fields in every rejection.** Each guard
   returns a response with:
     * `ooda.observe` — what state was detected
     * `ooda.orient` — what that state means (why blocked)
     * `ooda.decide` — the ordered list of decisions to make
     * `ooda.act` — concrete tool calls to make next, with
       FULLY-SPECIFIED args (tool name + arg dict, parseable by
       the LLM as an exact template)

2. **Rejection counting per `(tool_name, agent_id)`.** The
   tracker is process-global with an in-memory counter. Reset
   on:
     * Success of the gated tool
     * Explicit `reset_for_testing()` call

3. **Escalating responses by count:**
     * 1-2 rejections: standard OODA response
     * 3-5 rejections: response prepends "**STUCK_LOOP_WARNING**"
       to the orient field + suggests `force=True` explicitly
     * 6+ rejections: **auto-bypass** — guard returns None
       (allowing the gated tool to proceed), and the response
       tags the run with `auto_bypassed=True` so the wrapper /
       artifact pipeline knows to flag the scan for review.

The auto-bypass at N=6 caps the rejection-loop cost at
~$0.10-$0.15 vs the unbounded ~$0.50 observed today. The
gated tool still succeeds; the wrapper-visible signal is the
`auto_bypassed` flag.

## Kill switch

`STRIX_REJECTION_TRACKER_DISABLED=1` reverts to pre-fix
behavior (no counter, no auto-bypass). Use for A/B benchmarking.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any


logger = logging.getLogger(__name__)


# (tool_name → consecutive rejection count). Module-global,
# thread-safe via _LOCK.
_LOCK = threading.Lock()
_REJECTION_COUNTS: dict[str, int] = {}


# Tunable — when consecutive rejections hit this count, the guard
# auto-bypasses. Cost-controlled: each rejection round is ~$0.01-
# $0.02, so 6 = ~$0.10 ceiling on the loop.
AUTO_BYPASS_THRESHOLD: int = 6
# Below this, responses are standard OODA. At or above, the
# response carries a louder STUCK_LOOP_WARNING + explicit
# force=True suggestion.
STUCK_WARNING_THRESHOLD: int = 3


def is_disabled() -> bool:
    """Kill switch — when set, the tracker is a no-op (always
    returns count=0, never auto-bypasses)."""
    return os.environ.get(
        "STRIX_REJECTION_TRACKER_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def record_rejection(tool_name: str) -> int:
    """Called by a tool's guard when it refuses to proceed.
    Returns the post-increment count."""
    if is_disabled():
        return 0
    with _LOCK:
        n = _REJECTION_COUNTS.get(tool_name, 0) + 1
        _REJECTION_COUNTS[tool_name] = n
        return n


def record_success(tool_name: str) -> None:
    """Called when the tool successfully proceeds. Resets the
    counter for this tool so a future rejection burst starts
    counting from 1 again."""
    with _LOCK:
        _REJECTION_COUNTS.pop(tool_name, None)


def get_rejection_count(tool_name: str) -> int:
    with _LOCK:
        return _REJECTION_COUNTS.get(tool_name, 0)


def should_auto_bypass(tool_name: str) -> bool:
    """Returns True when consecutive rejections have hit the
    auto-bypass threshold. The guard SHOULD honour this — let
    the gated tool proceed even though prerequisites aren't met.
    Cost-control mechanism for the rejection loop."""
    if is_disabled():
        return False
    return get_rejection_count(tool_name) >= AUTO_BYPASS_THRESHOLD


def reset_for_testing() -> None:
    """Clear all counters. Tests call this in fixtures."""
    with _LOCK:
        _REJECTION_COUNTS.clear()


# ---------------------------------------------------------------------------
# OODA response builders
# ---------------------------------------------------------------------------


def build_ooda_response(
    *,
    tool_name: str,
    error: str,
    observe: str,
    orient: str,
    decide: list[str],
    act: list[dict[str, Any]],
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a guard-rejection response with structured OODA
    fields. The lead's LLM is expected to parse `ooda.act` as the
    authoritative next-step list — read the first entry, execute
    it, observe, repeat.

    Args:
      tool_name: the tool whose guard fired (for rejection
        counting).
      error: short error tag (machine-readable, e.g.
        `workflow_not_in_report_phase`).
      observe: 1-sentence "what state was detected."
      orient: 1-sentence "what that state means / why blocking."
        Augmented with STUCK_LOOP_WARNING when the rejection
        count crosses the threshold.
      decide: ordered list of reasoning steps the lead should
        follow ("dismiss hypothesis X", "advance phase to report",
        etc.).
      act: ordered list of concrete tool-call templates. Each
        entry is a dict with `tool` (name) and `args` (dict of
        args to pass). The lead executes these in order.
      extra_fields: optional dict of additional fields merged
        into the response (e.g. workflow snapshot, hypothesis
        list). Useful for the lead to introspect deeper state
        without a separate tool call.

    Returns:
      The rejection response dict. Always includes:
        `success`, `error`, `ooda`, `rejection_count`,
        `auto_bypass_at`.
    """
    count = record_rejection(tool_name)
    response: dict[str, Any] = {
        "success": False,
        "error": error,
        "ooda": {
            "observe": observe,
            "orient": _augment_orient_with_warnings(orient, count),
            "decide": list(decide),
            "act": list(act),
        },
        "rejection_count": count,
        "auto_bypass_at": AUTO_BYPASS_THRESHOLD,
    }
    if count >= STUCK_WARNING_THRESHOLD:
        response["loop_warning"] = (
            f"You've been rejected {count} time(s) on `{tool_name}`. "
            f"Either follow the `ooda.act` plan exactly, OR pass "
            f"`force=True` to bypass the guard deliberately. "
            f"After {AUTO_BYPASS_THRESHOLD} consecutive rejections "
            f"the guard auto-bypasses to prevent runaway cost — "
            f"don't rely on that; ACT on the plan."
        )
    if extra_fields:
        response.update(extra_fields)
    return response


def _augment_orient_with_warnings(orient: str, count: int) -> str:
    """When the rejection count crosses the stuck-warning
    threshold, prepend a louder signal to the orient field."""
    if count >= AUTO_BYPASS_THRESHOLD:
        return (
            f"AUTO_BYPASS_IMMINENT (rejection #{count}, threshold "
            f"{AUTO_BYPASS_THRESHOLD}). The guard is about to "
            f"allow this call through. {orient}"
        )
    if count >= STUCK_WARNING_THRESHOLD:
        return (
            f"STUCK_LOOP_WARNING (rejection #{count}). Your last "
            f"{count} attempts on this tool have been rejected with "
            f"the same blocker — STOP retrying the same call and "
            f"follow `ooda.act` exactly. {orient}"
        )
    return orient


def build_auto_bypass_marker(tool_name: str) -> dict[str, Any]:
    """When a guard chooses to auto-bypass (rejection count >=
    threshold), the gated tool's response should be tagged so the
    wrapper / artifact pipeline can flag the scan for review."""
    return {
        "auto_bypassed": True,
        "auto_bypass_reason": (
            f"rejection_loop_detected after "
            f"{AUTO_BYPASS_THRESHOLD} consecutive {tool_name} "
            f"rejections"
        ),
        "auto_bypass_threshold": AUTO_BYPASS_THRESHOLD,
    }
