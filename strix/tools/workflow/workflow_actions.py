"""`workflow_status` + `advance_workflow_phase` — the agent-facing
surface of the Phase 3d workflow state machine.

These two tools are the **primary mechanism** by which the lead
keeps track of where it is in a pentesting run. Without them, the
lead has to infer phase from conversation history (which Flash
loses by turn 20) or from the system-prompt directives (which
Flash empirically doesn't follow consistently).

With them, every turn:
  1. Lead calls `workflow_status()` → gets structured snapshot.
  2. Lead reads `next_recommended_actions` → picks one.
  3. Lead executes the recommended tool.
  4. The tool records progress into the workflow state.
  5. Repeat.

Phase boundaries are enforced by `tool_catalog.py`'s phase-filter
on top of this state machine — so calling a probe tool while
still in `recon` phase isn't even an option presented to the LLM.
"""

from __future__ import annotations

from typing import Any

from strix.tools.registry import register_tool


# NOTE: `strix.agents.workflow_state` is imported lazily inside
# each tool body. `strix.agents.__init__` pulls in `BaseAgent`,
# which transitively imports `strix.llm`; at the time
# `strix.tools.__init__` is resolving this module (because
# `strix.tools/__init__.py` does `from .workflow import *`), the
# `strix.llm` module is still mid-init. A module-level import
# here triggers the cycle. The hypothesis tools at
# `strix/tools/active_hypotheses/active_hypotheses_tools.py:15`
# use the same lazy-import pattern for the same reason.
def _ws():
    import strix.agents.workflow_state as m  # noqa: PLC0415
    return m


@register_tool(sandbox_execution=False, mitre_techniques=[])
def workflow_status() -> dict[str, Any]:
    """Read the current pentesting-workflow state.

    Returns a structured snapshot of:

      * `current_phase` — one of `recon` / `auth_attempt` /
        `post_auth_recon` / `probe` / `chain_correlation` /
        `report`.
      * `phase_history` — full audit trail of phase entries +
        durations.
      * `endpoints_discovered_count`, `endpoints_probed_count`,
        `unprobed_endpoints_sample` — recon + probe progress.
      * `login_forms_found`, `auth_state_captured` — auth gates.
      * `findings_emitted`, `chains_emitted` — output progress.
      * `gates` — explicit pass/fail on each phase prerequisite,
        so you can SEE which condition is blocking a transition.
      * `next_recommended_actions` — 1-3 concrete next steps,
        computed from the current phase + gate state. **Follow
        these unless you have a specific reason not to.**

    Call this at the START of every turn until the workflow is
    in `report` phase. Treat the result as authoritative — your
    own memory of "have I tried auth?" is probably wrong.
    """
    return {"success": True, **_ws().snapshot()}


@register_tool(sandbox_execution=False, mitre_techniques=[])
def advance_workflow_phase(
    target: str,
    reason: str = "",
    force: bool = False,
) -> dict[str, Any]:
    """Transition the workflow to a new phase.

    Args:
      target: one of `recon` / `auth_attempt` / `post_auth_recon` /
        `probe` / `chain_correlation` / `report`.
      reason: short string for the audit log explaining why you
        moved (e.g. "recon found 12 endpoints, ready to probe").
      force: bypass the phase-gate validation. Use only when the
        normal gate refuses but you've made an explicit decision
        to skip a phase (e.g. forcing past `auth_attempt` when
        you've tried 8 default creds with no captured session).

    Returns:
      `{success: True, transitioned: True, current_phase, message}`
      on success; `{success: False, error, current_phase, message}`
      when the gate refused.

    Forward transitions (recon → auth → post_auth_recon → probe →
    chain_correlation → report) require each preceding phase's
    completion criteria. Backwards transitions (e.g. probe → recon
    to crawl a newly-found endpoint) are always allowed.
    """
    ws = _ws()
    target_norm = (target or "").strip().lower()
    if target_norm not in ws.PHASES:
        return {
            "success": False,
            "error": "invalid_target_phase",
            "message": (
                f"unknown phase: {target!r}. Valid phases: "
                f"{', '.join(ws.PHASES)}."
            ),
            "valid_phases": list(ws.PHASES),
        }

    transitioned, message = ws.advance_phase(
        target=target_norm,  # type: ignore[arg-type]
        reason=reason,
        force=bool(force),
    )

    snap = ws.snapshot()
    return {
        "success": transitioned,
        "transitioned": transitioned,
        "current_phase": snap["current_phase"],
        "message": message,
        # Surface the next recommended actions so the lead doesn't
        # have to make a separate workflow_status() call after a
        # successful transition.
        "next_recommended_actions": snap["next_recommended_actions"],
    }
