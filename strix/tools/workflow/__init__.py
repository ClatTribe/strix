"""Workflow state-machine tools (Phase 3d / PR-α).

Two tools the lead invokes to interact with the workflow:

  * `workflow_status()` — read the current phase + structured
    completion gates + suggested next actions. The lead calls this
    each turn to know "where am I in the workflow?" without
    relying on prompt-text directives.

  * `advance_workflow_phase(target, reason, force=False)` —
    transition to a new phase. Gated by `_validate_transition`
    in workflow_state.py — e.g. you can't enter `auth_attempt`
    until a login form has been discovered.

The state itself lives in `strix.agents.workflow_state` so any
specialist tool can record progress (endpoint discovered, auth
captured, finding emitted) without needing the lead to mediate.
"""

from strix.tools.workflow.workflow_actions import (
    advance_workflow_phase,
    workflow_status,
)


__all__ = ["advance_workflow_phase", "workflow_status"]
