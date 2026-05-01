"""Phase-boundary tool — agent declares which scan phase it's in.

Phase events (recon → exploit → validate → report) give consumers a
meaningful progress indicator and let downstream coverage matrices
validate that each required phase was actually entered. The tool is
deliberately lightweight: each call emits one event and updates the
tracer's open-phase tracking.

Symmetrical: the agent calls `record_phase("recon")` to enter, and
`record_phase("recon", action="complete")` (passing the phase_id from
the original call) to exit. Most agents will fire-and-forget on
"complete" since strix's run-completion path closes any still-open
phases automatically.

Roadmap §1.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_VALID_PHASES = {"recon", "exploit", "validate", "report"}


@register_tool(sandbox_execution=False)
def record_phase(
    phase: str,
    action: str = "enter",
    phase_id: str | None = None,
    focus: str | None = None,
) -> dict[str, Any]:
    """Mark a scan phase boundary.

    Args:
        phase: one of `recon`, `exploit`, `validate`, `report`. Custom names
               accepted but tagged as such in the event payload.
        action: `enter` (default) or `complete`.
        phase_id: required when action='complete' — the id returned by the
                  earlier `enter` call. If omitted, the call is a no-op.
        focus: optional string narrowing the phase — e.g.
               focus='dns_security' for a DNS-only recon block.

    Returns a dict with the phase_id (so the agent can close it later) and
    the resolved phase name.
    """
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return {"success": False, "error": "tracer unavailable"}

    tracer = get_global_tracer()
    if tracer is None:
        return {"success": False, "error": "no global tracer"}

    normalised = phase.strip().lower()
    if normalised not in _VALID_PHASES and action == "enter":
        # Don't reject — agents may legitimately introduce custom phases for
        # multi-target scans. We just flag it in the event payload.
        logger.info("custom phase name: %s", phase)

    action_norm = action.strip().lower()
    if action_norm == "enter":
        new_phase_id = tracer.enter_phase(normalised, focus=focus)
        return {
            "success": True,
            "action": "enter",
            "phase": normalised,
            "phase_id": new_phase_id,
        }
    if action_norm == "complete":
        if not phase_id:
            return {
                "success": False,
                "error": "action='complete' requires phase_id from the earlier enter call",
            }
        tracer.complete_phase(phase_id)
        return {
            "success": True,
            "action": "complete",
            "phase": normalised,
            "phase_id": phase_id,
        }
    return {
        "success": False,
        "error": f"invalid action: {action!r} (use 'enter' or 'complete')",
    }
