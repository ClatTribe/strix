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
    skills_override: list[str] | None = None,
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
      skills_override: Phase 1C — override the category's
        auto-attached skills for this dispatch. Pass a list of
        skill names (e.g. `['saml_xsw', 'oauth_oidc']`) to use a
        custom bundle, or `[]` to suppress skill injection
        entirely. When omitted (default), the profile's
        recommended skills auto-attach.

    Returns:
      Dict with `status` (PASSED / BLOCKED / ITERATION_CAP_REACHED
      / BUDGET_EXCEEDED / DENIED_BY_SCAN_MODE / ERROR), `reason`,
      `iterations_used`, `findings_count`, `duration_s`, `summary`.

    Scan-mode cap (phase 1 of cost optimization): `--scan-mode quick`
    caps dispatches at 0 (deterministic probes only); `--scan-mode
    standard` caps at 8; `--scan-mode deep` is unbounded. Over-cap
    calls return immediately with status=DENIED_BY_SCAN_MODE — fall
    back to running the deterministic specialist tool directly
    (e.g. `scan_sqli`) instead of retrying dispatch.

    Idiomatic use (orchestrator pattern):
      1. Recon: dispatch_specialist('recon', 'enumerate endpoints', target=URL)
      2. Per-endpoint: dispatch_specialist('sqli', 'verify SQLi on /api/users')
      3. Coverage: dispatch_specialist('xss', 'verify reflected XSS on /search')
      4. Custom skill bundle: dispatch_specialist('generic', 'verify SAML XSW
         on /saml/acs', skills_override=['saml_xsw'])
      5. When done: finish_scan
    """
    return _orchestrator().dispatch_specialist(
        category=category,
        objective=objective,
        target=target,
        max_iterations=max_iterations,
        max_cost_usd=max_cost_usd,
        skills_override=skills_override,
    )


@register_tool(sandbox_execution=False, mitre_techniques=[])
def complete_objective(
    status: str = "PASSED",
    reason: str | None = None,
    summary: str | None = None,
    target: str | None = None,
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
      target: v2 step 3 — when called inside a batched dispatch
        (`dispatch_specialist_batch`), set `target` to the
        specific endpoint this completion is for. The orchestrator
        tracks per-target completions and exits when every batched
        target has been signaled. Leave None for single-dispatch
        completions (the default, backwards-compatible).

    Returns:
      Confirmation dict. The actual exit happens in the
      orchestrator's loop, which polls for the signal after each
      iteration.
    """
    _orchestrator().signal_specialist_complete(
        status=status, reason=reason, summary=summary, target=target,
    )
    return {
        "success": True,
        "signaled": "complete_objective",
        "status": str(status or "PASSED").upper(),
        "reason": reason,
        "summary": summary,
        "target": target,
    }


@register_tool(sandbox_execution=False, mitre_techniques=[])
def dispatch_specialist_batch(
    category: str,
    objectives: list[dict[str, str]],
    max_iterations: int | None = None,
    max_cost_usd: float | None = None,
    skills_override: list[str] | None = None,
) -> dict[str, Any]:
    """Spawn ONE fresh-context specialist that probes N related
    objectives in a single bounded loop.

    Use this when you would otherwise dispatch the same category
    to several near-identical endpoints (e.g. SQLi probes on
    `/api/users/{id}`, `/api/orders/{id}`, `/api/items/{id}`).
    The specialist pays the 25K-token system prompt ONCE and
    works through each objective sequentially.

    Args:
      category: specialist category (e.g. 'sqli', 'idor'). All
        objectives in the batch share this category.
      objectives: list of `{"target": "...", "objective": "..."}`
        dicts. Two objectives with the same `target` are
        deduplicated.
      max_iterations: total iteration cap across the batch.
        Defaults to `2 + N × 6` so per-objective reasoning
        bandwidth scales with batch size.
      max_cost_usd: cost cap for the whole batch. Defaults to
        `profile.max_cost_usd × N`.
      skills_override: same semantics as `dispatch_specialist`.

    Returns:
      Dict with:
        - `batch_results`: per-target SpecialistRunResult dicts
          (status, reason, summary).
        - `iterations_used`: total iterations the batch ran.
        - `duration_s`: wall-clock seconds.
        - `findings_count`: total findings emitted across all
          targets in the batch.
        - `cache_hits`: number of objectives short-circuited via
          the verdict cache (cost-free).
        - `dispatched`: 1 if the LLM loop ran (counts against the
          scan-mode dispatch budget), 0 if every objective was
          served by the cache.

    When to use this vs `dispatch_specialist`:
      * Use BATCH when you have 3+ endpoints of the same category
        with similar structure. Saves boot cost.
      * Use SINGLE when the objective is complex enough that you
        want the full per-dispatch iteration budget for one
        target. Multi-step chains, deep auth flows.
      * On `standard` scan mode, the batch counts as ONE dispatch
        against the per-run cap — a 4-objective batch leaves 7
        more dispatches available for other categories.

    Caveat: per-target finding attribution is approximate in
    batch mode (we attribute total findings_count to the batch,
    not per-target). Use single dispatch when you need precise
    per-endpoint attribution.
    """
    return _orchestrator().dispatch_specialist_batch(
        category=category,
        objectives=objectives,
        max_iterations=max_iterations,
        max_cost_usd=max_cost_usd,
        skills_override=skills_override,
    )
