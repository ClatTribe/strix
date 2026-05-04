"""`agent_self_audit` tool — structured between-phase reflection
(roadmap §17.6 / §18 row 9 second-half).

Today the lead's "did I cover the surface_map?" reflection is
implicit (in the LLM's chain-of-thought). This tool makes it
EXPLICIT, structured, and gradeable.

Designed to be called by the lead at every phase boundary:
  recon → exploit
  exploit → validate
  validate → report

Each call emits an `agent.self_audit` event with:

```json
{
  "agent_id": "agent_4f3a2c1b",
  "phase_completed": "recon",
  "phase_starting": "exploit",
  "categories_covered": ["sql_injection", "xss", "...", ...],
  "categories_skipped": [
    {"category": "ssrf", "reason": "no internal-network surface"}
  ],
  "stuck_sub_agents": [
    {"agent_id": "agent-x", "category": "auth", "reason": "rate-limited"}
  ],
  "open_hypotheses_count": <int>,
  "concern": "<plain-text concern, optional>",
  "next_phase_plan": "<plain-text next-phase plan, optional>"
}
```

The wrapper renders these as a phase-by-phase audit panel; the
RLHF FP-loop grades whether the agent's "I covered X" claim
matched what actually happened.

Validation
----------

`phase_completed` and `phase_starting` are validated against the
canonical phase set (`recon` / `exploit` / `validate` / `report`).
`categories_skipped[]` entries must include both `category` and
`reason`. Lists capped at 50 entries each.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


# Canonical phase set — mirrors `Tracer.enter_phase` / `complete_phase`.
_VALID_PHASES = frozenset({"recon", "exploit", "validate", "report"})

# Caps so a single audit event payload stays bounded.
_MAX_CATEGORIES = 50
_MAX_STUCK_SUB_AGENTS = 50
_MAX_TEXT_FIELD = 2048


def _emit_event(payload: dict[str, Any]) -> bool:
    """Emit `agent.self_audit` via the global tracer. Best-effort —
    failures swallowed so the agent loop never breaks because of
    bookkeeping."""
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return False
    tracer = get_global_tracer()
    if tracer is None:
        return False
    try:
        tracer._emit_event(  # noqa: SLF001
            "agent.self_audit",
            actor={
                "agent_id": payload.get("agent_id"),
            },
            payload=payload,
            status="audited",
            source="strix.agents.self_audit",
        )
    except Exception:  # noqa: BLE001
        logger.debug("agent.self_audit emit failed", exc_info=True)
        return False
    return True


def _normalize_categories(items: list[Any] | None) -> list[str]:
    """Coerce to a list of stripped lowercase strings, deduped, capped."""
    if not isinstance(items, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            continue
        v = item.strip().lower()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
        if len(out) >= _MAX_CATEGORIES:
            break
    return out


def _normalize_skipped(items: list[Any] | None) -> list[dict[str, str]]:
    """Each entry must be `{category, reason}`. Coerce + drop invalid."""
    if not isinstance(items, list):
        return []
    out: list[dict[str, str]] = []
    seen_keys: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        cat = (item.get("category") or "").strip().lower() if isinstance(
            item.get("category"), str
        ) else ""
        reason = (item.get("reason") or "").strip() if isinstance(
            item.get("reason"), str
        ) else ""
        if not cat or not reason:
            continue
        if cat in seen_keys:
            continue
        seen_keys.add(cat)
        out.append({"category": cat, "reason": reason[:_MAX_TEXT_FIELD]})
        if len(out) >= _MAX_CATEGORIES:
            break
    return out


def _normalize_stuck(items: list[Any] | None) -> list[dict[str, str]]:
    if not isinstance(items, list):
        return []
    out: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        agent_id = (item.get("agent_id") or "").strip() if isinstance(
            item.get("agent_id"), str
        ) else ""
        category = (item.get("category") or "").strip().lower() if isinstance(
            item.get("category"), str
        ) else ""
        reason = (item.get("reason") or "").strip() if isinstance(
            item.get("reason"), str
        ) else ""
        if not agent_id and not category:
            continue
        out.append({
            "agent_id": agent_id,
            "category": category,
            "reason": reason[:_MAX_TEXT_FIELD],
        })
        if len(out) >= _MAX_STUCK_SUB_AGENTS:
            break
    return out


@register_tool(
    sandbox_execution=False,
    mitre_techniques=[],
    provenance="framework",  # internal Strix output
)
def agent_self_audit(
    phase_completed: str,
    phase_starting: str | None = None,
    categories_covered: list[str] | None = None,
    categories_skipped: list[dict[str, str]] | None = None,
    stuck_sub_agents: list[dict[str, str]] | None = None,
    open_hypotheses_count: int | None = None,
    concern: str | None = None,
    next_phase_plan: str | None = None,
) -> dict[str, Any]:
    """Emit a structured between-phase self-audit.

    Call this at every phase boundary BEFORE entering the next
    phase. The LLM's reflection becomes a gradeable artifact.

    Args:
        phase_completed: which phase just finished. Required.
            Valid: 'recon' / 'exploit' / 'validate' / 'report'.
        phase_starting: which phase is about to begin. Optional
            (omit on the final 'report' boundary).
        categories_covered: list of vuln categories you tested
            (lowercase, deduped). Mirrors finding categories so the
            wrapper can join "covered" vs "found" per category.
        categories_skipped: list of `{category, reason}` for
            categories you DIDN'T test, with reasons (e.g.
            "no internal-network surface", "out of scope per
            --exclude-path"). Honest negative coverage.
        stuck_sub_agents: list of `{agent_id, category, reason}`
            for sub-agents that hit walls (rate-limit, budget,
            error). Helps the wrapper surface "needs attention"
            cards.
        open_hypotheses_count: count from `list_hypotheses(only_status='investigating')`.
            Lets the wrapper render "5 hypotheses still in flight"
            badge.
        concern: optional free-text concern about coverage gaps,
            quality, or unknowns going into the next phase.
        next_phase_plan: optional plain-text plan for the next
            phase (1-3 sentences).

    Returns:
        ```
        {
          success: bool,
          message: str,
          phase_completed: str,
          phase_starting: str | None,
          categories_covered_count: int,
          categories_skipped_count: int,
          stuck_sub_agents_count: int,
        }
        ```
    """
    # Required field validation.
    if not isinstance(phase_completed, str) or not phase_completed.strip():
        return {"success": False, "message": "phase_completed is required"}
    p_done = phase_completed.strip().lower()
    if p_done not in _VALID_PHASES:
        return {
            "success": False,
            "message": (
                f"phase_completed {phase_completed!r} not in canonical set. "
                f"Valid: {sorted(_VALID_PHASES)}"
            ),
        }

    p_next: str | None = None
    if phase_starting is not None:
        if not isinstance(phase_starting, str):
            return {"success": False, "message": "phase_starting must be a string"}
        candidate = phase_starting.strip().lower()
        if not candidate:
            p_next = None
        elif candidate not in _VALID_PHASES:
            return {
                "success": False,
                "message": (
                    f"phase_starting {phase_starting!r} not in canonical set. "
                    f"Valid: {sorted(_VALID_PHASES)}"
                ),
            }
        else:
            p_next = candidate

    # Normalise inputs.
    norm_covered = _normalize_categories(categories_covered)
    norm_skipped = _normalize_skipped(categories_skipped)
    norm_stuck = _normalize_stuck(stuck_sub_agents)

    open_count: int | None = None
    if open_hypotheses_count is not None:
        try:
            open_count = max(0, int(open_hypotheses_count))
        except (TypeError, ValueError):
            open_count = None

    # Cap free-text fields.
    concern_str: str | None = None
    if isinstance(concern, str) and concern.strip():
        concern_str = concern.strip()[:_MAX_TEXT_FIELD]
    next_plan_str: str | None = None
    if isinstance(next_phase_plan, str) and next_phase_plan.strip():
        next_plan_str = next_phase_plan.strip()[:_MAX_TEXT_FIELD]

    payload = {
        "phase_completed": p_done,
        "phase_starting": p_next,
        "categories_covered": norm_covered,
        "categories_skipped": norm_skipped,
        "stuck_sub_agents": norm_stuck,
        "open_hypotheses_count": open_count,
        "concern": concern_str,
        "next_phase_plan": next_plan_str,
    }
    _emit_event(payload)

    return {
        "success": True,
        "message": "agent.self_audit event emitted",
        "phase_completed": p_done,
        "phase_starting": p_next,
        "categories_covered_count": len(norm_covered),
        "categories_skipped_count": len(norm_skipped),
        "stuck_sub_agents_count": len(norm_stuck),
    }
