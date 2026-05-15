from typing import Any

from strix.tools.registry import register_tool


def _check_workflow_phase(*, force: bool) -> dict[str, Any] | None:
    """Phase 3d / PR-α — block `finish_scan` outside the `report`
    phase.

    The workflow state machine in `strix.agents.workflow_state`
    tracks which phase the scan is in. `report` is the terminal
    phase reachable only via explicit `advance_workflow_phase`
    transition (or `force=True` here). Without this guard, the
    lead could call `finish_scan` while still in `recon` /
    `probe` / etc., bypassing the workflow entirely.

    Honours `STRIX_WORKFLOW_DISABLED=1` — when the workflow is
    opted out, this guard is a no-op.

    Fails open on any internal error — never blocks finish_scan
    due to a bug in the workflow subsystem.
    """
    if force:
        return None
    try:
        from strix.agents.workflow_state import (
            get_current_phase, is_workflow_disabled, snapshot,
        )
    except Exception:
        return None

    if is_workflow_disabled():
        return None

    try:
        phase = get_current_phase()
    except Exception:
        return None

    if phase == "report":
        return None

    # OODA-loop-breaker (PR-#232) — check the auto-bypass first.
    # When the lead has been rejected `AUTO_BYPASS_THRESHOLD` times
    # in a row, let finish_scan proceed (the run is tagged
    # `auto_bypassed=True` in the response so the wrapper /
    # benchmark pipeline can flag it for review). Without this,
    # the lead burns ~$0.50 of inference on retry loops (observed
    # 36 consecutive rejections in the Phase 3d benchmark).
    try:
        from strix.agents.rejection_tracker import (
            build_ooda_response,
            should_auto_bypass,
        )
    except Exception:
        # Fall back to the pre-OODA response if the tracker fails
        # to import (e.g. test isolation issue).
        return {
            "success": False, "error": "workflow_not_in_report_phase",
            "current_phase": phase,
        }
    if should_auto_bypass("finish_scan"):
        return None    # let finish_scan proceed; tracker logs the bypass

    try:
        snap = snapshot()
        next_actions = snap.get("next_recommended_actions") or []
        gates = snap.get("gates") or {}
    except Exception:
        snap = {}
        next_actions = []
        gates = {}

    # OODA-structured rejection — the lead's LLM should treat
    # `ooda.act` as the authoritative next-step list. Each entry
    # is a concrete tool-call template (tool name + arg dict).
    decide_steps = [
        f"Current phase is '{phase}' — must reach 'report' before finish_scan succeeds.",
    ]
    act_calls: list[dict[str, Any]] = []

    # Build the act-plan based on remaining gates.
    if not gates.get("recon_has_endpoints"):
        decide_steps.append(
            "Recon hasn't produced any endpoints yet — crawl first."
        )
        act_calls.append({
            "tool": "webapp_recon_pipeline",
            "args": {"url": "<the target URL from this scan>"},
        })
    elif (gates.get("recon_found_login_form")
          and not gates.get("auth_attempted")):
        decide_steps.append(
            "A login form was found and auth hasn't been attempted — "
            "try default + tenant-supplied credentials before probing."
        )
        act_calls.append({
            "tool": "advance_workflow_phase",
            "args": {"target": "auth_attempt", "reason": "login form found"},
        })
        act_calls.append({
            "tool": "scan_auth_flow",
            "args": {"login_url": "<the discovered login URL>"},
        })
    elif phase in ("recon", "auth_attempt", "post_auth_recon"):
        decide_steps.append(
            "Recon and any auth captures are done — advance to probe."
        )
        act_calls.append({
            "tool": "advance_workflow_phase",
            "args": {"target": "probe",
                     "reason": "recon complete; probe discovered endpoints"},
        })
    elif phase == "probe":
        decide_steps.append(
            "Probe phase — fan out specialists on each discovered "
            "endpoint via `probe_endpoint` before advancing."
        )
        unprobed = snap.get("unprobed_endpoints_sample") or []
        if unprobed:
            act_calls.append({
                "tool": "probe_endpoint",
                "args": {"endpoint_url": unprobed[0]},
            })
        else:
            act_calls.append({
                "tool": "advance_workflow_phase",
                "args": {"target": "chain_correlation",
                         "reason": "probe complete"},
            })
    elif phase == "chain_correlation":
        decide_steps.append(
            "Emit finding chains, then advance to report."
        )
        act_calls.append({"tool": "correlate_findings", "args": {}})
        act_calls.append({
            "tool": "advance_workflow_phase",
            "args": {"target": "report", "reason": "chains emitted"},
        })

    # Always end with the retry-finish_scan call so the lead has
    # the full ordered plan in front of it.
    act_calls.append({
        "tool": "finish_scan",
        "args": {
            "executive_summary": "<your summary>",
            "methodology": "<your methodology>",
            "technical_analysis": "<your analysis>",
            "recommendations": "<your recs>",
        },
    })

    return build_ooda_response(
        tool_name="finish_scan",
        error="workflow_not_in_report_phase",
        observe=(
            f"Workflow is in '{phase}' phase. finish_scan requires "
            f"'report' phase to proceed."
        ),
        orient=(
            f"The pentest workflow runs recon → auth_attempt (if "
            f"login form found) → post_auth_recon (if auth "
            f"captured) → probe → chain_correlation → report. "
            f"Each forward transition has gate prerequisites. "
            f"You're blocked from finish_scan because the workflow "
            f"hasn't completed the phases leading to 'report'."
        ),
        decide=decide_steps,
        act=act_calls,
        extra_fields={
            "current_phase": phase,
            "workflow_gates": gates,
            "next_recommended_actions": next_actions,
        },
    )


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

    # OODA-loop-breaker (PR-#232) — auto-bypass after N consecutive
    # rejections. See _check_workflow_phase for the rationale.
    try:
        from strix.agents.rejection_tracker import (
            build_ooda_response,
            should_auto_bypass,
        )
    except Exception:
        return {
            "success": False, "error": "open_hypotheses_remain",
            "open_count": len(open_h),
        }
    if should_auto_bypass("finish_scan"):
        return None    # let finish_scan proceed; tracker logs the bypass

    summaries = [
        {
            "id": str(h.get("id", "")),
            "category": h.get("category", "unknown"),
            "surface": (h.get("surface") or "")[:80],
            "summary": (h.get("summary") or h.get("hypothesis") or "")[:120],
        }
        for h in open_h[:6]
    ]

    # Build the concrete dismiss_hypothesis calls — one per open
    # hypothesis. The lead executes these to clear the gate.
    dismiss_calls: list[dict[str, Any]] = [
        {
            "tool": "dismiss_hypothesis",
            "args": {
                "hypothesis_id": s["id"],
                "reason": (
                    f"Probed during scan; surface {s['surface']!r} "
                    f"did not yield exploitable evidence."
                ),
            },
        }
        for s in summaries
    ]
    # After the dismisses, the lead retries finish_scan.
    dismiss_calls.append({
        "tool": "finish_scan",
        "args": {
            "executive_summary": "<your summary>",
            "methodology": "<your methodology>",
            "technical_analysis": "<your analysis>",
            "recommendations": "<your recs>",
        },
    })

    return build_ooda_response(
        tool_name="finish_scan",
        error="open_hypotheses_remain",
        observe=(
            f"{len(open_h)} hypotheses are still in 'investigating' "
            f"status. The lead has open probe threads it hasn't "
            f"resolved."
        ),
        orient=(
            "An open hypothesis represents an unresolved probe — "
            "either confirm it (call `confirm_hypothesis`, which "
            "should accompany a finding emission) or dismiss it "
            "(call `dismiss_hypothesis` with a reason). Leaving "
            "them open through finish_scan would suggest the scan "
            "report is incomplete. If you've truly exhausted "
            "probes, dismiss with that reasoning; if you actually "
            "have evidence, confirm via create_vulnerability_report."
        ),
        decide=[
            "For each of the {n} open hypotheses, decide: did the probe produce evidence?".format(n=len(open_h)),
            "If YES: emit a finding via create_vulnerability_report, then confirm_hypothesis.",
            "If NO: dismiss_hypothesis with the reasoning of why it's not exploitable.",
            "After ALL hypotheses are resolved, retry finish_scan.",
            "Alternative: pass `force=True` to finish_scan if you've genuinely decided to skip resolving them.",
        ],
        act=dismiss_calls,
        extra_fields={
            "open_count": len(open_h),
            "open_hypothesis_summaries": summaries,
        },
    )


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

    workflow_phase_error = _check_workflow_phase(force=force)
    if workflow_phase_error:
        return workflow_phase_error

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
            response = {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed successfully",
                "vulnerabilities_found": vulnerability_count,
            }
            _annotate_success_response(response)
            return response

        import logging

        logging.warning("Current tracer not available - scan results not stored")

    except (ImportError, AttributeError) as e:
        return {"success": False, "message": f"Failed to complete scan: {e!s}"}
    else:
        response = {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed (not persisted)",
            "warning": "Results could not be persisted - tracer unavailable",
        }
        _annotate_success_response(response)
        return response


def _annotate_success_response(response: dict[str, Any]) -> None:
    """When finish_scan succeeds, reset the rejection counter and
    (if a loop was auto-bypassed) annotate the response with the
    auto-bypass marker so the wrapper / benchmark pipeline can
    flag the scan for review."""
    try:
        from strix.agents.rejection_tracker import (
            build_auto_bypass_marker,
            get_rejection_count,
            record_success,
        )
    except Exception:
        return
    count_at_success = get_rejection_count("finish_scan")
    record_success("finish_scan")
    if count_at_success >= 6:    # AUTO_BYPASS_THRESHOLD
        response.update(build_auto_bypass_marker("finish_scan"))
