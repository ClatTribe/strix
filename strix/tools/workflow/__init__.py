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

from strix.tools.workflow.kg_tools import (
    kg_create_edge,
    kg_create_node,
    kg_query_nodes,
    kg_query_paths,
    kg_stats,
)
from strix.tools.workflow.objective_tools import (
    add_child_objective,
    create_objective,
    get_objective,
    list_objectives,
    update_objective,
)
from strix.tools.workflow.patcher_tools import (
    auto_verify_patch,
    list_patches,
    mark_patch_applied,
    propose_patch,
    verify_patch,
)
from strix.tools.workflow.probe_endpoint import probe_endpoint
from strix.tools.workflow.specialist_dispatch import (
    complete_objective,
    dispatch_specialist,
)
from strix.tools.workflow.verification_tools import (
    advance_verification_stage,
    record_verification_evidence,
    register_finding_for_verification,
    verification_status,
)
from strix.tools.workflow.workflow_actions import (
    advance_workflow_phase,
    workflow_status,
)


__all__ = [
    "add_child_objective",
    "advance_verification_stage",
    "advance_workflow_phase",
    "auto_verify_patch",
    "complete_objective",
    "create_objective",
    "dispatch_specialist",
    "get_objective",
    "kg_create_edge",
    "kg_create_node",
    "kg_query_nodes",
    "kg_query_paths",
    "kg_stats",
    "list_objectives",
    "list_patches",
    "mark_patch_applied",
    "probe_endpoint",
    "propose_patch",
    "record_verification_evidence",
    "register_finding_for_verification",
    "update_objective",
    "verification_status",
    "verify_patch",
    "workflow_status",
]
