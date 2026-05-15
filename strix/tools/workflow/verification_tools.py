"""Lead-facing verification-pipeline tools (§4).

Four tools matching the five-stage pipeline shape:

  * `register_finding_for_verification(finding_id, severity)` —
    enter the pipeline (idempotent).
  * `record_verification_evidence(finding_id, method, outcome, tool, detail=)` —
    log one independent verification attempt.
  * `advance_verification_stage(finding_id, target_stage, reason=)` —
    move the finding through the pipeline. The 2-method floor for
    HIGH/CRITICAL is enforced here.
  * `verification_status(finding_id=, severity=, stage=)` —
    query state. With no args, returns the whole pipeline.

Same lazy-import pattern as the other workflow tools.
"""

from __future__ import annotations

from typing import Any

from strix.tools.registry import register_tool


def _pipeline():
    from strix.agents.verification_pipeline import get_pipeline  # noqa: PLC0415
    return get_pipeline()


@register_tool(sandbox_execution=False, mitre_techniques=[])
def register_finding_for_verification(
    finding_id: str,
    severity: str,
) -> dict[str, Any]:
    """Enter a finding into the verification pipeline (idempotent).

    Args:
      finding_id: stable ID of the finding (matches the tracer's
        finding records).
      severity: one of `info`, `low`, `medium`, `high`, `critical`.
        Drives the 2-method floor on HIGH/CRITICAL.

    Returns the initial pipeline record (`stage=SCANNED`).
    """
    rec = _pipeline().register(finding_id=finding_id, severity=severity)
    return {"success": True, "record": rec.to_dict()}


@register_tool(sandbox_execution=False, mitre_techniques=[])
def record_verification_evidence(
    finding_id: str,
    method: str,
    outcome: str,
    tool: str,
    detail: str = "",
) -> dict[str, Any]:
    """Log one independent verification attempt against a finding.

    Args:
      finding_id: the registered finding.
      method: one of `payload_response`, `timing`, `dom`, `oob`,
        `differential`, `static_match`, `external_corroboration`.
        Distinctness of methods is what counts toward the 2-method
        floor — two `payload_response` entries still count as one.
      outcome: `PASSED` / `FAILED` / `INCONCLUSIVE`.
      tool: human-readable tool name that produced this evidence
        (`sqlmap`, `payload-fuzzer`, `playwright`, ...).
      detail: optional one-line note (payload variant, oracle threshold,
        captured response excerpt).

    Returns the updated record or `{"success": False, "error": ...}`.
    """
    try:
        rec = _pipeline().record_evidence(
            finding_id,
            method=method,  # type: ignore[arg-type]
            outcome=outcome,  # type: ignore[arg-type]
            tool=tool,
            detail=detail,
        )
    except ValueError as e:
        return {"success": False, "error": str(e)}
    if rec is None:
        return {
            "success": False,
            "error": "finding_not_registered",
            "finding_id": finding_id,
        }
    return {"success": True, "record": rec.to_dict()}


@register_tool(sandbox_execution=False, mitre_techniques=[])
def advance_verification_stage(
    finding_id: str,
    target_stage: str,
    reason: str = "",
) -> dict[str, Any]:
    """Try to move a finding forward in the pipeline.

    Stages (canonical order):
      `SCANNED → DETECTED → VERIFYING → VERIFIED → EXPLOITED → PATCHED`
    Plus `FAILED` as a terminal state when verification doesn't hold.

    Critical rule: VERIFYING → VERIFIED requires ≥ 2 distinct
    independent verification methods (PASSED) for HIGH/CRITICAL
    severity findings, ≥ 1 for everything else. Tunable via
    `STRIX_VERIFICATION_MIN_METHODS_HIGH` / `_DEFAULT`.

    Args:
      finding_id: registered finding.
      target_stage: where to advance to.
      reason: optional audit string (lands in verification.jsonl).

    Returns `{"success": bool, "reason": str, "record": {...}}`. On
    failure the `record` may still be returned so the agent can
    see what's missing.
    """
    ok, reason_msg, rec = _pipeline().advance(
        finding_id,
        target_stage=target_stage,  # type: ignore[arg-type]
        reason=reason,
    )
    return {
        "success": ok,
        "reason": reason_msg,
        "record": rec.to_dict() if rec else None,
    }


@register_tool(sandbox_execution=False, mitre_techniques=[])
def verification_status(
    finding_id: str = "",
    severity: str = "",
    stage: str = "",
) -> dict[str, Any]:
    """Query pipeline state.

    Args:
      finding_id: when given, returns just that finding's record
        (or `error=not_found`).
      severity: filter list by severity (lowercased).
      stage: filter list by stage.

    Returns the full pipeline when no filters set.
    """
    p = _pipeline()

    if finding_id:
        rec = p.get(finding_id)
        if rec is None:
            return {"success": False, "error": "not_found", "finding_id": finding_id}
        return {"success": True, "record": rec.to_dict()}

    records = p.list_records(
        severity=severity or None,
        stage=stage or None,  # type: ignore[arg-type]
    )
    return {
        "total": len(records),
        "records": [r.to_dict() for r in records],
    }
