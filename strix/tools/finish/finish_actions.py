from typing import Any

from strix.tools.registry import register_tool


def _check_open_hypotheses(*, force: bool) -> dict[str, Any] | None:
    """Recall-lift PR-1 — block `finish_scan` when probes are
    unresolved.

    The hypothesis tools (`open_hypothesis` / `confirm_hypothesis` /
    `dismiss_hypothesis`) are how the lead tracks "I see a suspicious
    surface, I need to probe it." Without this check, the lead can
    open hypotheses and then call `finish_scan` without resolving
    them — leaving probes incomplete. That's the recall-lossiness
    pattern observed on the testfire scan (lead emitted 2 findings,
    had additional open hypotheses, called finish_scan anyway).

    The fix is to refuse termination while open hypotheses remain,
    and force the lead to either confirm them (emit a finding) or
    dismiss them (explicitly decide they're false positives). When
    the lead has genuinely exhausted options it can pass `force=True`
    to override — but the default refusal pushes it toward complete
    coverage.

    Returns None when termination is allowed; a structured error
    dict when blocked.
    """
    if force:
        return None
    try:
        # The same lazy-import trick the hypothesis tool module
        # itself uses — avoid circular import at module-load time.
        import strix.agents.active_hypotheses as _h

        # `investigating` is the in-flight status; `dismissed` /
        # `confirmed` are terminal. Block on the in-flight set only.
        open_h = _h.list_active_hypotheses(only_status="investigating")
    except Exception:
        # Best-effort — if the hypothesis module isn't loadable or
        # returns nothing, fail open. Never block finish_scan due
        # to a bug in the hypothesis subsystem.
        return None

    if not open_h:
        return None

    summaries = [
        {
            "id": str(h.get("id", "")),
            "category": h.get("category", "unknown"),
            "surface": (h.get("surface") or "")[:80],
            "summary": (h.get("summary") or h.get("hypothesis") or "")[:120],
        }
        for h in open_h[:6]
    ]
    return {
        "success": False,
        "error": "open_hypotheses_remain",
        "message": (
            f"Cannot finish_scan: {len(open_h)} hypotheses are still "
            f"in 'investigating' status. Resolve each by probing → "
            f"`confirm_hypothesis` (emit a finding) or "
            f"`dismiss_hypothesis` (explicit decision it's not "
            f"exploitable). When you've genuinely exhausted probes "
            f"on a hypothesis but the surface still warrants the "
            f"open state, dismiss it with reasoning; do NOT leave "
            f"it open through finish_scan."
        ),
        "open_count": len(open_h),
        "open_hypothesis_summaries": summaries,
        "suggestions": [
            "Call list_active_hypotheses() to see the full list",
            "For each: probe → confirm_hypothesis OR dismiss_hypothesis",
            "If you've truly exhausted options, pass force=True to override",
        ],
    }


def _validate_root_agent(agent_state: Any) -> dict[str, Any] | None:
    if agent_state and hasattr(agent_state, "parent_id") and agent_state.parent_id is not None:
        return {
            "success": False,
            "error": "finish_scan_wrong_agent",
            "message": "This tool can only be used by the root/main agent",
            "suggestion": "If you are a subagent, use agent_finish from agents_graph tool instead",
        }
    return None


def _check_active_agents(agent_state: Any = None) -> dict[str, Any] | None:
    try:
        from strix.tools.agents_graph.agents_graph_actions import _agent_graph

        if agent_state and agent_state.agent_id:
            current_agent_id = agent_state.agent_id
        else:
            return None

        active_agents = []
        stopping_agents = []

        for agent_id, node in _agent_graph["nodes"].items():
            if agent_id == current_agent_id:
                continue

            status = node.get("status", "unknown")
            if status == "running":
                active_agents.append(
                    {
                        "id": agent_id,
                        "name": node.get("name", "Unknown"),
                        "task": node.get("task", "Unknown task")[:300],
                        "status": status,
                    }
                )
            elif status == "stopping":
                stopping_agents.append(
                    {
                        "id": agent_id,
                        "name": node.get("name", "Unknown"),
                        "task": node.get("task", "Unknown task")[:300],
                        "status": status,
                    }
                )

        if active_agents or stopping_agents:
            response: dict[str, Any] = {
                "success": False,
                "error": "agents_still_active",
                "message": "Cannot finish scan: agents are still active",
            }

            if active_agents:
                response["active_agents"] = active_agents

            if stopping_agents:
                response["stopping_agents"] = stopping_agents

            response["suggestions"] = [
                "Use wait_for_message to wait for all agents to complete",
                "Use send_message_to_agent if you need agents to complete immediately",
                "Check agent_status to see current agent states",
            ]

            response["total_active"] = len(active_agents) + len(stopping_agents)

            return response

    except ImportError:
        pass
    except Exception:
        import logging

        logging.exception("Error checking active agents")

    return None


@register_tool(sandbox_execution=False)
def finish_scan(
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    force: bool = False,
    agent_state: Any = None,
) -> dict[str, Any]:
    """Finalise the scan run and emit the executive summary.

    Args:
        executive_summary: high-level summary of findings + risk
        methodology: how the scan was executed (recon → probe → emit)
        technical_analysis: technical narrative of the findings
        recommendations: prioritised remediation suggestions
        force: when True, bypass the open-hypotheses guard
            (recall-lift PR-1). Use only when you've genuinely
            decided to skip probing open hypotheses — the default
            `False` pushes you toward resolving each one before
            terminating. Wrappers don't need to set this; the lead
            agent itself passes True when its own reasoning
            concludes the open hypotheses are exhausted.
    """
    validation_error = _validate_root_agent(agent_state)
    if validation_error:
        return validation_error

    active_agents_error = _check_active_agents(agent_state)
    if active_agents_error:
        return active_agents_error

    open_hypotheses_error = _check_open_hypotheses(force=force)
    if open_hypotheses_error:
        return open_hypotheses_error

    validation_errors = []

    if not executive_summary or not executive_summary.strip():
        validation_errors.append("Executive summary cannot be empty")
    if not methodology or not methodology.strip():
        validation_errors.append("Methodology cannot be empty")
    if not technical_analysis or not technical_analysis.strip():
        validation_errors.append("Technical analysis cannot be empty")
    if not recommendations or not recommendations.strip():
        validation_errors.append("Recommendations cannot be empty")

    if validation_errors:
        return {"success": False, "message": "Validation failed", "errors": validation_errors}

    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer:
            tracer.update_scan_final_fields(
                executive_summary=executive_summary.strip(),
                methodology=methodology.strip(),
                technical_analysis=technical_analysis.strip(),
                recommendations=recommendations.strip(),
            )

            vulnerability_count = len(tracer.vulnerability_reports)

            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed successfully",
                "vulnerabilities_found": vulnerability_count,
            }

        import logging

        logging.warning("Current tracer not available - scan results not stored")

    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to complete scan: {e!s}"}
    else:
        return {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed (not persisted)",
            "warning": "Results could not be persisted - tracer unavailable",
        }
