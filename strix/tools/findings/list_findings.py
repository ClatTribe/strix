"""iter-26.2 + 26.7 — `list_pending_findings` Lead-facing catalog.

The Lead Orchestrator currently sees findings via raw inspection of
`vulnerability_reports` — every finding shown in emission order with
no ranking. iter-25 added L1.5 enrichment (exploitability, surface
priority, noise flag, role flag) but the LLM still has to read those
fields itself and decide what to focus on first.

This tool returns the current finding set **ranked by L1.5 signals
and filtered to suppress demoted noise**, so the Lead's next-action
decision is "dispatch the top of the list" rather than "scan 60
findings for the 3 that matter."

Sort key (descending priority):
  1. surface_priority.label rank (critical=3 > high=2 > normal=1 > low=0)
  2. exploitability.composite (descending)
  3. severity rank (critical=4 > high=3 > medium=2 > low=1 > info=0)
  4. emission order (stable tiebreaker — earliest first)

Filter rules (default):
  * `noise=True` → hidden (set `include_demoted=True` to surface)
  * `role=corroborator` → hidden (already attached to its parent
    via corroborated_by[])

Output format is compact enough to fit in a single LLM tool result —
findings beyond `limit` get a tail-summary line ("+ 32 more
findings; raise limit= to see them"). The default limit is 25
which covers the worst-case noisy targets (vibe-app, sast-vibe)
without overflowing context.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_SURFACE_RANK: dict[str, int] = {
    "critical": 3,
    "high": 2,
    "normal": 1,
    "low": 0,
}
_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "informational": 0,
}


def _sort_key(finding: dict[str, Any]) -> tuple[int, float, int]:
    """Tuple → sort descending. Returns (surface_rank,
    exploitability_composite, severity_rank).

    Stable tiebreaker (emission order) handled by Python's stable sort
    + the input being in emission order.
    """
    surface = finding.get("surface_priority") or {}
    s_label = (surface.get("label") if isinstance(surface, dict) else "") or ""
    s_rank = _SURFACE_RANK.get(s_label, 1)

    expl = finding.get("exploitability") or {}
    composite = (
        expl.get("composite") if isinstance(expl, dict) else None
    )
    if not isinstance(composite, (int, float)):
        composite = 0.5  # neutral default for findings without L1.5 score

    sev = (finding.get("severity") or "").lower().strip()
    sev_rank = _SEVERITY_RANK.get(sev, 1)

    return (s_rank, float(composite), sev_rank)


def _is_demoted(finding: dict[str, Any]) -> bool:
    """Should this finding be hidden from the default catalog?"""
    if finding.get("noise") is True:
        return True
    if finding.get("role") == "corroborator":
        return True
    return False


def _format_row(finding: dict[str, Any]) -> dict[str, Any]:
    """Project a finding into a compact catalog row.

    Includes only the L1.5 fields the LLM needs to make a dispatch
    decision; full detail lives in `vulnerabilities.json`.
    """
    fid = finding.get("id") or "?"
    sev = (finding.get("severity") or "").lower()
    title = (finding.get("title") or "").strip()
    cwe = finding.get("cwe") or ""

    surface = finding.get("surface_priority") or {}
    surface_label = (
        surface.get("label") if isinstance(surface, dict) else ""
    ) or "unknown"

    expl = finding.get("exploitability") or {}
    composite = (
        expl.get("composite") if isinstance(expl, dict) else None
    )

    target = (
        finding.get("endpoint")
        or finding.get("url")
        or finding.get("target")
        or ""
    )

    annotations: list[str] = []
    kev = finding.get("kev")
    if isinstance(kev, dict) and kev.get("is_kev"):
        annotations.append("KEV")
    camp = finding.get("campaigns")
    if isinstance(camp, dict) and (camp.get("matched_pulse_count") or 0) > 0:
        annotations.append(f"campaign×{camp.get('matched_pulse_count')}")
    cb = finding.get("corroborated_by")
    if isinstance(cb, list) and cb:
        annotations.append(f"corroborated×{len(cb)}")
    pending = finding.get("pending_confirmations")
    if isinstance(pending, list) and pending:
        annotations.append(f"pending-dast×{len(pending)}")
    bundles = finding.get("triggered_probes")
    if isinstance(bundles, list) and bundles:
        annotations.append(f"bundle×{len(bundles)}")
    vstat = (finding.get("verification_status") or "").lower()
    if vstat == "exploited":
        annotations.append("EXPLOITED")

    row: dict[str, Any] = {
        "id": fid,
        "severity": sev,
        "title": title[:100],
        "cwe": cwe,
        "surface_priority": surface_label,
        "target": target[:80] if target else "",
    }
    if composite is not None:
        row["exploitability"] = round(float(composite), 2)
    if annotations:
        row["annotations"] = annotations
    return row


@register_tool(sandbox_execution=False, provenance="framework")
def list_pending_findings(
    limit: int = 25,
    include_demoted: bool = False,
    severity_floor: str | None = None,
) -> dict[str, Any]:
    """Return current findings ranked by L1.5 signals.

    The Lead Orchestrator calls this between specialist dispatches to
    figure out *what to work on next*. The ranking puts the highest-
    leverage finding first — the one a human security engineer would
    pick up given the same evidence:

      1. critical-surface (admin / auth / payment) before everything else
      2. highest composite exploitability (code × route × auth × data)
      3. then severity rank (critical > high > medium > low > info)
      4. emission order as the stable tiebreaker

    Args:
        limit: max rows returned (default 25; raise to see more).
        include_demoted: when True, surfaces findings tagged
            ``noise=True`` or ``role=corroborator`` that L1.5 demoted.
            Default False — keeps the catalog focused on actionable
            findings.
        severity_floor: optional minimum severity ("medium" hides
            low/info, etc.). Default None — show everything.

    Returns:
        ```
        {
          success: bool, status: "ok",
          total: int,                  # total findings on file
          shown: int,                  # rows in the result
          findings: [<row>, ...],      # sorted catalog
          truncated_tail: int | 0,     # rows hidden by limit
          demoted_hidden: int | 0,     # rows hidden by noise/corroborator
        }
        ```
    """
    try:
        # Late-import the live tracer so we always see the most recent
        # set; importing at module load would freeze the count at 0.
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return {
                "success": True, "status": "partial",
                "reason": "tracer not initialised yet",
                "total": 0, "shown": 0, "findings": [],
                "truncated_tail": 0, "demoted_hidden": 0,
            }
        all_findings = list(getattr(tracer, "vulnerability_reports", []) or [])
    except Exception as e:  # noqa: BLE001
        logger.debug("list_pending_findings tracer lookup failed: %s", e)
        return {
            "success": False, "status": "error",
            "reason": f"could not read findings: {type(e).__name__}",
            "total": 0, "shown": 0, "findings": [],
            "truncated_tail": 0, "demoted_hidden": 0,
        }

    total = len(all_findings)

    # Severity floor filter
    sev_floor_rank = _SEVERITY_RANK.get(
        (severity_floor or "").lower().strip(), -1,
    ) if severity_floor else -1

    # Apply filters
    visible: list[dict[str, Any]] = []
    demoted_hidden = 0
    for f in all_findings:
        if not include_demoted and _is_demoted(f):
            demoted_hidden += 1
            continue
        if sev_floor_rank >= 0:
            sev = (f.get("severity") or "").lower().strip()
            if _SEVERITY_RANK.get(sev, 1) < sev_floor_rank:
                continue
        visible.append(f)

    # Sort descending by composite key
    visible.sort(key=_sort_key, reverse=True)

    # Truncate
    shown = visible[:max(0, int(limit))]
    truncated = max(0, len(visible) - len(shown))

    rows = [_format_row(f) for f in shown]
    return {
        "success": True, "status": "ok",
        "total": total,
        "shown": len(rows),
        "findings": rows,
        "truncated_tail": truncated,
        "demoted_hidden": demoted_hidden,
    }
