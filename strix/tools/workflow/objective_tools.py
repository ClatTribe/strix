"""Lead-facing objective CRUD tools (§2 OPPLAN-style state machine).

Five tools matching Decepticon's OPPLANMiddleware shape:

  * `create_objective(...)`   — add a new objective to the plan
  * `list_objectives(...)`    — read the plan (filter by status / category / phase)
  * `update_objective(...)`   — change status / evidence / acceptance
  * `get_objective(id)`       — fetch one objective by ID
  * `add_child_objective(parent_id, ...)` — decompose an objective

The progress table is automatically injected into the system prompt
by `strix/llm/llm.py` (no tool needed for that).

Same lazy-import pattern as `specialist_dispatch.py` /
`workflow_actions.py` — avoid circular re-entry via
`strix.agents.__init__` → `BaseAgent` → `strix.llm`.
"""

from __future__ import annotations

from typing import Any

from strix.tools.registry import register_tool


def _tracker():
    """Resolve the tracker singleton. Lazy import."""
    from strix.agents.objective_tracker import get_tracker  # noqa: PLC0415
    return get_tracker()


@register_tool(sandbox_execution=False, mitre_techniques=[])
def create_objective(
    title: str,
    phase: str,
    category: str,
    surface: str = "",
    depends_on: str = "",
    acceptance: str = "",
    evidence_required: int = 1,
    parent_id: str | None = None,
) -> dict[str, Any]:
    """Add a new objective to the plan.

    Args:
      title: human-readable goal ("Verify IDOR on /api/users/{id}").
      phase: workflow phase this belongs to (`recon`, `auth_attempt`,
        `post_auth_recon`, `probe`, `chain_correlation`, `report`).
      category: specialist category (`sqli`, `xss`, `idor`, `recon`,
        `auth`, `fingerprint`, …). Should match a key the
        `dispatch_specialist` orchestrator (or the existing
        specialist registry) knows.
      surface: optional URL / endpoint / asset under test.
      depends_on: comma-separated IDs of objectives that must
        complete first (e.g. "OBJ-001,OBJ-003"). An objective with
        unresolved deps stays `pending` until they complete.
      acceptance: free-text acceptance criterion. The specialist
        reads this to decide when to call `complete_objective(PASSED)`.
      evidence_required: multi-method floor (§4) — number of
        independent evidence items before this objective can flip
        to `completed`. Default 1.
      parent_id: when this objective decomposes another, set parent.

    Returns the newly-created objective as a dict (incl. the
    auto-assigned `id` like `OBJ-007`).
    """
    deps_list: list[str] = []
    if depends_on:
        deps_list = [d.strip() for d in depends_on.split(",") if d.strip()]

    obj = _tracker().create(
        title=title,
        phase=phase,
        category=category,
        surface=surface,
        depends_on=deps_list,
        acceptance=acceptance,
        evidence_required=evidence_required,
        parent_id=parent_id,
    )
    return {
        "success": True,
        "objective": obj.to_dict(),
    }


@register_tool(sandbox_execution=False, mitre_techniques=[])
def list_objectives(
    status: str | None = None,
    category: str | None = None,
    phase: str | None = None,
) -> dict[str, Any]:
    """Read the plan. Empty filters returns everything.

    Args:
      status: when given, only objectives with this status. One of
        `pending`, `in_progress`, `completed`, `blocked`, `cancelled`.
      category: filter by specialist category.
      phase: filter by workflow phase.

    Returns:
      `{"objectives": [<dict>, ...], "total": <int>}`. The list is
      sorted by ID (== creation order, since IDs are sequential).
    """
    objs = _tracker().list(status=status, category=category, phase=phase)  # type: ignore[arg-type]
    return {
        "total": len(objs),
        "objectives": [o.to_dict() for o in objs],
    }


@register_tool(sandbox_execution=False, mitre_techniques=[])
def update_objective(
    id: str,  # noqa: A002 — matches Decepticon's OPPLAN field name
    status: str | None = None,
    evidence_count: int | None = None,
    acceptance: str | None = None,
) -> dict[str, Any]:
    """Update an objective's status / evidence / acceptance.

    Args:
      id: the objective ID (`OBJ-001`).
      status: new status. Allowed transitions are checked — e.g.
        `completed → pending` is rejected as a fat-finger; reopen
        a completed objective via `cancelled` first then re-create.
      evidence_count: overwrite the evidence count (use this when
        you've manually verified a finding contributes to the
        acceptance criterion).
      acceptance: revise the acceptance criterion (when scope
        clarification arrives mid-scan).

    Returns the updated objective dict; or `{"success": False,
    "error": "not_found"}` when ID is unknown.
    """
    try:
        obj = _tracker().update(
            id,
            status=status,  # type: ignore[arg-type]
            evidence_count=evidence_count,
            acceptance=acceptance,
        )
    except ValueError as e:
        return {"success": False, "error": str(e)}

    if obj is None:
        return {"success": False, "error": "not_found", "id": id}

    return {
        "success": True,
        "objective": obj.to_dict(),
    }


@register_tool(sandbox_execution=False, mitre_techniques=[])
def get_objective(id: str) -> dict[str, Any]:  # noqa: A002
    """Fetch one objective by ID. Use when you need full detail
    (acceptance text, evidence count, deps) without grabbing the
    whole plan.

    Returns:
      `{"objective": {...}}` on success, or
      `{"success": False, "error": "not_found"}` when ID unknown.
    """
    obj = _tracker().get(id)
    if obj is None:
        return {"success": False, "error": "not_found", "id": id}
    return {
        "success": True,
        "objective": obj.to_dict(),
        "can_start": _tracker().can_start(id),
    }


@register_tool(sandbox_execution=False, mitre_techniques=[])
def add_child_objective(
    parent_id: str,
    title: str,
    category: str | None = None,
    surface: str = "",
    acceptance: str = "",
    evidence_required: int = 1,
) -> dict[str, Any]:
    """Decompose an objective into a child sub-objective.

    The child inherits `phase` from the parent (and `category` if
    not given). Useful when a high-level objective ("Verify auth
    bypass on /admin") needs three concrete sub-tasks ("Test JWT
    none-alg", "Test JWT key-confusion", "Test cookie tampering").

    Args:
      parent_id: ID of the parent objective.
      title: child goal.
      category: optional category override (defaults to parent's).
      surface: optional surface (defaults to parent's).
      acceptance: child acceptance criterion.
      evidence_required: child evidence floor.

    Returns the newly-created child objective dict.
    """
    parent = _tracker().get(parent_id)
    if parent is None:
        return {"success": False, "error": "parent_not_found", "id": parent_id}

    obj = _tracker().create(
        title=title,
        phase=parent.phase,
        category=category or parent.category,
        surface=surface or parent.surface,
        acceptance=acceptance,
        evidence_required=evidence_required,
        parent_id=parent_id,
    )
    return {
        "success": True,
        "objective": obj.to_dict(),
        "parent_id": parent_id,
    }
