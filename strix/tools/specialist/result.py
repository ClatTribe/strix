"""`SpecialistResult` schema (roadmap §8.5 Phase 1 / single-agent.md B.8).

Every specialist-tool returns this typed result so the lead agent's
observe-step can route deterministically:
  * `findings`              → call `emit_finding` per draft.
  * `dismissed`             → call `dismiss_hypothesis` per entry.
  * `next_probes_suggested` → planner input for the lead's next turn.
  * `evidence`              → raw evidence excerpts (capped) for the
                              labeler / wrapper rendering.
  * `tool_metadata`         → specialist-specific opaque dict (e.g.
                              sqlmap session id, browser profile id)
                              that the lead can pass to follow-up
                              calls or include in audit trails.

The schema is stable. Wrapper-side impact: zero — `SpecialistResult`
is internal to the §8.5 single-lead architecture and never appears in
`events.jsonl` / `vulnerabilities.json`. Specialist-tool output is
funnelled through the existing `add_vulnerability_report` flow when
the lead converts `findings` to `finding.created` events.

Schema versioning: additive-only. Removing a field bumps
`SPECIALIST_RESULT_SCHEMA_VERSION` (currently 1).

Closed-enum invariants mirror engine-usage.md §6 / §3:
  * `severity`            ∈ {info, low, medium, high, critical}
  * `verification_status` ∈ {verified, pattern_match, inconclusive,
                             needs_review, could_not_verify}
  * `dismissal_reason`    ∈ 13-value FP_REASON enum from #118
  * `status`              ∈ {ok, error, partial}

Validation runs at construction-time via Pydantic; bad inputs raise
`pydantic.ValidationError` which the registry decorator catches and
coerces to a `status="error"` SpecialistResult — never crashes the
lead loop.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


SPECIALIST_RESULT_SCHEMA_VERSION: int = 1


# Closed enums — mirror the engine-usage.md / #118 / #142 contracts.
_VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_VALID_VERIFICATION_STATUSES = frozenset({
    "verified", "pattern_match", "inconclusive", "needs_review", "could_not_verify",
})
_VALID_DISMISSAL_REASONS = frozenset({
    "input_properly_encoded", "framework_default_blocked", "csrf_token_validated",
    "auth_enforced", "not_reflected", "different_origin", "out_of_scope",
    "false_positive_signature", "compensating_control", "intended_behavior",
    "test_fixture", "deprecated_path", "other",
})


# Caps mirror #137 reasoning_trace (≤ 20 bullets × 320 chars) +
# counter_proof (description ≤ 1024, evidence ≤ 2048) + #142 features.
_REASONING_TRACE_BULLET_CAP = 320
_REASONING_TRACE_COUNT_CAP = 20
_EVIDENCE_ITEM_CAP_CHARS = 4096
_EVIDENCE_LIST_COUNT_CAP = 50
_NEXT_PROBES_COUNT_CAP = 20
_NEXT_PROBE_ITEM_CAP_CHARS = 320


class FindingDraft(BaseModel):
    """Draft form of a finding emitted by a specialist-tool. The lead
    agent converts this into a `finding.created` event by calling
    `emit_finding(...)`. NOT a finalised finding — the canonical
    contract (#86) runs on the converted form, not on the draft."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str = Field(min_length=1, max_length=512)
    severity: Literal["info", "low", "medium", "high", "critical"]
    cwe: str | None = Field(default=None, max_length=32)
    endpoint: str | None = Field(default=None, max_length=2048)
    description: str | None = Field(default=None, max_length=8192)
    verification_status: Literal[
        "verified", "pattern_match", "inconclusive", "needs_review", "could_not_verify",
    ] = "pattern_match"
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    reasoning_trace: list[str] = Field(default_factory=list)
    counter_proof: dict[str, Any] | None = None
    category: str | None = Field(default=None, max_length=128)
    poc_script_code: str | None = Field(default=None, max_length=16384)


class DismissedHypothesis(BaseModel):
    """Negative-evidence record. Lead converts via `dismiss_hypothesis(...)`
    or `dismiss_finding(...)` so the auto-dismiss + RLHF trajectory
    pipelines see structured negative signal."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    surface: str | None = Field(default=None, max_length=2048)
    hypothesis: str = Field(min_length=1, max_length=2048)
    dismissal_reason: Literal[
        "input_properly_encoded", "framework_default_blocked", "csrf_token_validated",
        "auth_enforced", "not_reflected", "different_origin", "out_of_scope",
        "false_positive_signature", "compensating_control", "intended_behavior",
        "test_fixture", "deprecated_path", "other",
    ]
    evidence: str | None = Field(default=None, max_length=4096)


class SpecialistResult(BaseModel):
    """Typed return shape every specialist-tool produces.

    The lead's observe-step routes on each list:
      * `findings`              → `emit_finding(...)` per draft.
      * `dismissed`             → `dismiss_hypothesis(...)` per entry.
      * `next_probes_suggested` → planner input.
      * `evidence`              → raw excerpt rendering.
      * `tool_metadata`         → opaque carryover.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = SPECIALIST_RESULT_SCHEMA_VERSION
    status: Literal["ok", "error", "partial"] = "ok"
    findings: list[FindingDraft] = Field(default_factory=list)
    dismissed: list[DismissedHypothesis] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list, max_length=_EVIDENCE_LIST_COUNT_CAP)
    next_probes_suggested: list[str] = Field(
        default_factory=list, max_length=_NEXT_PROBES_COUNT_CAP,
    )
    tool_metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = Field(default=None, max_length=2048)


def coerce_to_result(value: Any) -> SpecialistResult:
    """Best-effort coerce a specialist-tool return to `SpecialistResult`.

    Accepts:
      * already-`SpecialistResult` → return unchanged.
      * `dict` → construct (raises `pydantic.ValidationError` on bad shape).
      * anything else → wrap as `status="error"` with a one-line summary.

    Used by the registry decorator's wrapper to enforce the result-
    shape discipline (B.8) without crashing the lead loop on a
    misbehaving specialist."""
    if isinstance(value, SpecialistResult):
        return value
    if isinstance(value, dict):
        return SpecialistResult(**value)
    return SpecialistResult(
        status="error",
        error=f"specialist returned unexpected type: {type(value).__name__}",
    )
