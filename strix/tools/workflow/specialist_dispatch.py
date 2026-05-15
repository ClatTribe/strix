"""Lead-facing tools for the §1 fresh-context orchestrator.

Two tools:

  * `dispatch_specialist(category, objective, target=None, ...)` —
    the lead's primary action in orchestrator mode. Spawns a
    bounded multi-round specialist with fresh context, blocks
    until the specialist completes, returns structured result.

  * `complete_objective(status, reason=None, summary=None)` — the
    specialist's exit tool. Signals the orchestrator that the
    bounded loop should exit. PASSED = objective achieved;
    BLOCKED = couldn't complete (with reason).

The orchestrator-mode catalog filter in `tool_catalog.py` ensures:
  - Lead sees `dispatch_specialist` (always)
  - Specialist sees `complete_objective` (always, but only inside
    its bounded loop's allowed_tool_subset — v0 implementation
    routes via the inner_call_fn)

## When this fires

`STRIX_ORCHESTRATOR_MODE` must be set to a truthy value
(`true` / `1` / `yes`). When unset (default), the existing
single-lead architecture is used unchanged.
"""

from __future__ import annotations

from typing import Any

from strix.tools.registry import register_tool


# NOTE: same lazy-import pattern as the workflow tools — avoid
# circular re-entry via `strix.agents.__init__` → `BaseAgent` →
# `strix.llm`.
def _orchestrator():
    import strix.agents.specialist_orchestrator as m  # noqa: PLC0415
    return m


@register_tool(sandbox_execution=False, mitre_techniques=[])
def dispatch_specialist(
    category: str,
    objective: str,
    target: str | None = None,
    max_iterations: int | None = None,
    max_cost_usd: float | None = None,
) -> dict[str, Any]:
    """Spawn a bounded fresh-context specialist for one objective.

    This is the lead's primary action in orchestrator mode. The
    specialist runs in its own conversation history (no
    inheritance from the lead's context), bounded to
    `max_iterations` (default 50) and `max_cost_usd` (per-profile
    default). When the specialist completes, the lead receives a
    structured result and can decide what to dispatch next.

    Args:
      category: specialist category. One of: `sqli`, `xss`,
        `idor`, `recon`, `auth`, or any other category (falls
        through to a generic profile).
      objective: the specific task. Be precise — e.g. "Verify
        SQLi on POST /login with username/password fields"
        not "look for SQLi". The specialist's behaviour quality
        scales with objective specificity.
      target: optional target URL for scope clarity. Included
        in the specialist's system prompt.
      max_iterations: override the profile default (default 50).
      max_cost_usd: override the profile default.

    Returns:
      Dict with `status` (PASSED / BLOCKED / ITERATION_CAP_REACHED
      / BUDGET_EXCEEDED / ERROR), `reason`, `iterations_used`,
      `findings_count`, `duration_s`, `summary`.

    Idiomatic use (orchestrator pattern):
      1. Recon: dispatch_specialist('recon', 'enumerate endpoints', target=URL)
      2. Per-endpoint: dispatch_specialist('sqli', 'verify SQLi on /api/users')
      3. Coverage: dispatch_specialist('xss', 'verify reflected XSS on /search')
      4. When done: finish_scan
    """
    return _orchestrator().dispatch_specialist(
        category=category,
        objective=objective,
        target=target,
        max_iterations=max_iterations,
        max_cost_usd=max_cost_usd,
    )


@register_tool(sandbox_execution=False, mitre_techniques=[])
def complete_objective(
    status: str = "PASSED",
    reason: str | None = None,
    summary: str | None = None,
) -> dict[str, Any]:
    """Specialist's exit tool. Signals the orchestrator that the
    bounded loop should return.

    Args:
      status: PASSED — objective achieved (finding emitted, or
        surface confidently determined safe). BLOCKED — couldn't
        complete (missing prerequisite, scope boundary, etc.).
      reason: required when status=BLOCKED, optional otherwise.
        Single-sentence explanation the orchestrator reads.
      summary: optional short summary of what was probed +
        outcome. Surfaces in run_meta.json telemetry.

    Returns:
      Confirmation dict. The actual exit happens in the
      orchestrator's loop, which polls for the signal after each
      iteration.
    """
    _orchestrator().signal_specialist_complete(
        status=status, reason=reason, summary=summary,
    )
    return {
        "success": True,
        "signaled": "complete_objective",
        "status": str(status or "PASSED").upper(),
        "reason": reason,
        "summary": summary,
    }
