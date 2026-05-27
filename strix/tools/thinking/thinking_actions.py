"""iter-Q5.15 — `think(thought)` now persists.

Per the L2 audit (`docs/proposals/2026-05-27-l2-tool-audit.md` §1.3):
pre-Q5.15 `think` was a no-op echo — validated non-empty, returned
char count, persisted nothing. The L2 audience (devs + PMs) never
saw the LLM's reasoning.

Per CLAUDE.md §1.5.6 — tools are LLM's hands, not its brain.
Reasoning lives in the LLM's response text; *persistent* reasoning
(audit trail for the L2 audience) is a system-of-record side-effect,
which IS a legitimate tool job. So `think` stays, but it actually
writes now.

## What this commits to

  - Each call appends `{thought, ts}` to
    `tracer.lead_reasoning_trace[]`. Survives compaction.
  - The trace surfaces in `run_summary.lead_reasoning_trace[]` per
    the iter-Q5.15 spec.
  - The L2-audience artifact (developer action list) can render
    the trace as "why the AI security engineer thought this was
    the highest-priority finding."

## Opt-out

  `STRIX_THINK_PERSIST_DISABLED=1` reverts to pre-Q5.15 no-op
  behavior (useful when bench timing matters; trace size adds up
  on long scans).
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)


def _is_persist_disabled() -> bool:
    return os.environ.get(
        "STRIX_THINK_PERSIST_DISABLED", "",
    ).strip().lower() in ("1", "true", "yes", "on")


@register_tool(sandbox_execution=False)
def think(thought: str) -> dict[str, Any]:
    """Record a reasoning step into the scan's audit trail.

    Per CLAUDE.md §1.5.6 — the LLM can think in its response text;
    this tool exists for the *side-effect* of persisting that
    reasoning into `run_summary.lead_reasoning_trace[]` so the L2
    audience can audit the AI security engineer's chain of thought
    after the scan ends.

    Args:
        thought: free-form reasoning. Empty / whitespace-only
            rejected. No length cap (trace size bounded by token
            budget upstream).

    Returns:
        ```
        {success: bool, message: str, persisted: bool, trace_length: int}
        ```

    Opt-out:
        `STRIX_THINK_PERSIST_DISABLED=1` → reverts to pre-Q5.15 no-op
        behaviour for bench timing or low-budget runs.
    """
    if not thought or not thought.strip():
        return {"success": False, "message": "Thought cannot be empty"}

    body = thought.strip()

    if _is_persist_disabled():
        return {
            "success": True,
            "message": f"Thought recorded ({len(body)} chars) — persistence DISABLED",
            "persisted": False,
            "trace_length": 0,
        }

    # Best-effort persistence to the tracer. Any failure falls back
    # to the legacy no-op shape — never blocks the scan.
    persisted = False
    trace_length = 0
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is not None:
            # Lazily create the list attribute so we don't need to
            # modify Tracer.__init__ in this iter.
            trace: list[dict[str, Any]] = getattr(
                tracer, "lead_reasoning_trace", None,
            ) or []
            trace.append({
                "thought": body,
                "ts": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            })
            tracer.lead_reasoning_trace = trace  # type: ignore[attr-defined]
            persisted = True
            trace_length = len(trace)
    except Exception as e:  # noqa: BLE001
        logger.debug("think persistence failed: %s", e)

    return {
        "success": True,
        "message": (
            f"Thought recorded ({len(body)} chars), "
            f"persisted={persisted}, trace_length={trace_length}"
        ),
        "persisted": persisted,
        "trace_length": trace_length,
    }
