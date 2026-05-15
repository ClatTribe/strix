"""Workflow tools (Phase 3d).

Three lead-facing tools:

  * **PR-α** — `workflow_status()` and `advance_workflow_phase()`:
    read the current phase + structured completion gates +
    suggested next actions; transition between phases gated by
    prerequisites in `workflow_state.py`.

  * **PR-β** — `probe_endpoint(endpoint_url, kind=...)`: the
    composite specialist fan-out. Dispatches the matching set
    of probes for an endpoint's shape (form / api / search /
    auth / files / id_in_path / state_changing), aggregates
    findings into one result, and records the endpoint as
    probed in the workflow state. Replaces the 4-6 individual
    specialist calls the lead would otherwise have to pick
    one-by-one.

State itself lives in `strix.agents.workflow_state` so any
specialist tool can record progress (endpoint discovered, auth
captured, finding emitted, endpoint probed) without needing the
lead to mediate.
"""

from strix.tools.workflow.probe_endpoint import probe_endpoint
from strix.tools.workflow.specialist_dispatch import (
    complete_objective,
    dispatch_specialist,
)
from strix.tools.workflow.workflow_actions import (
    advance_workflow_phase,
    workflow_status,
)


__all__ = [
    "advance_workflow_phase",
    "complete_objective",
    "dispatch_specialist",
    "probe_endpoint",
    "workflow_status",
]
