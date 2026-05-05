"""`update_finding` agent-callable tool (roadmap §8.5 Phase 5 /
single-agent.md §2.4).

Wraps `Tracer.update_finding(...)` so the agent can mutate an
already-emitted finding. Use after eager-emission (#137 finding-
quality signals + B.10 eager-emit-then-review) when follow-up
evidence arrives:

  * Validator confirmed → bump `verification_status` to `verified`,
    raise `confidence` toward 1.0, attach `poc_script_code`.
  * Validator refuted → drop `verification_status` to
    `could_not_verify`, attach `counter_proof`.
  * New evidence discovered → append via `additional_evidence`
    (each call appends to `update_evidence_log`).

Emits `finding.updated` event (additive per engine-usage.md §6
versioning contract — old wrappers ignoring unknown events keep
working). The wrapper-side persistence layer keyed on `fingerprint`
already supports this path (it's a strict subset of the existing
"see same finding again across runs" pattern).
"""

from __future__ import annotations

import logging
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


@register_tool(sandbox_execution=False, provenance="framework")
def update_finding(  # noqa: PLR0913
    *,
    fingerprint: str | None = None,
    report_id: str | None = None,
    verification_status: str | None = None,
    confidence: float | None = None,
    severity: str | None = None,
    reasoning_trace: list[str] | str | None = None,
    counter_proof: dict[str, Any] | None = None,
    poc_script_code: str | None = None,
    additional_evidence: str | None = None,
    update_reason: str | None = None,
) -> dict[str, Any]:
    """Mutate an already-emitted finding.

    Either `fingerprint` (cross-scan stable id) OR `report_id`
    (per-run id) must be provided. Validator typically passes
    `fingerprint` (survives across runs); per-run callers pass
    `report_id`.

    Args:
        fingerprint: stable cross-scan finding id (#11 / #137).
        report_id: per-run finding id (e.g. `vuln-0001`).
        verification_status: ∈ {`verified`, `pattern_match`,
            `inconclusive`, `needs_review`, `could_not_verify`}.
            Setting to `verified` clears any prior `auto_dismissed`
            state and records `re_promoted=True`.
        confidence: 0.0–1.0 (#137 quality signal).
        severity: ∈ {info, low, medium, high, critical}. Records
            prior value under `severity_pre_update` for audit.
        reasoning_trace: REPLACES the existing trace. Capped at
            20 bullets × 320 chars (#137 cap).
        counter_proof: REPLACES existing. Dict shape
            `{description: str, evidence: str}` (description
            ≤ 1024, evidence ≤ 2048).
        poc_script_code: REPLACES existing. When previously absent
            and verification_status not explicitly set, bumps the
            status toward `verified`.
        additional_evidence: APPENDS to `update_evidence_log`. Each
            call adds one entry with timestamp + agent id. Capped
            at 4096 chars per entry.
        update_reason: free-text justification for the
            `finding.updated` event payload (audit / wrapper-side
            rendering).

    Returns:
        ```python
        {
            "success": bool,
            "report_id": str | None,
            "fingerprint": str | None,
            "fields_changed": list[str],
            "previous_values": dict,  # one entry per changed field
            "error": str | None,
        }
        ```

    Side effects (all best-effort):
      * Mutates the finding in place.
      * Records audit fields (`last_updated_at`, `last_updated_by`,
        `update_evidence_log`).
      * Emits `finding.updated` event with delta payload.
      * Re-runs #142 features extraction so the FP classifier sees
        latest values.
      * Re-runs #86 contract validation — violations attach to the
        finding's `shape_violations` list rather than aborting.
      * Triggers `save_run_data` so `vulnerabilities.json` reflects
        the mutation.

    Wrapper-side impact: zero observable schema change.
    `vulnerabilities.json` post-update reflects merged values; old
    wrappers reading the artifact at run-end see no schema diff.
    """
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return {
                "success": False,
                "report_id": report_id,
                "fingerprint": fingerprint,
                "fields_changed": [],
                "previous_values": {},
                "error": "tracer unavailable",
            }
        return tracer.update_finding(
            fingerprint=fingerprint,
            report_id=report_id,
            verification_status=verification_status,
            confidence=confidence,
            severity=severity,
            reasoning_trace=reasoning_trace,
            counter_proof=counter_proof,
            poc_script_code=poc_script_code,
            additional_evidence=additional_evidence,
            update_reason=update_reason,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("update_finding tool failed: %s", e, exc_info=True)
        return {
            "success": False,
            "report_id": report_id,
            "fingerprint": fingerprint,
            "fields_changed": [],
            "previous_values": {},
            "error": f"{type(e).__name__}: {e}",
        }
