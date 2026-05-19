"""Five-stage verification pipeline (§4 of strixredteam.md).

Strix already has `verification_status` ∈ {`verified`,
`pattern_match`, `inconclusive`, `needs_review`} but it's set
heuristically per tool. Findings reach the report without a
deterministic confirmation discipline. Reviewers see
`needs_review` without a clear protocol for how it got there.

This module adds a **structured pipeline**:

```
SCANNED → DETECTED → VERIFYING → VERIFIED → EXPLOITED → PATCHED
```

Each finding tracks:
  * `stage` — current pipeline position
  * `evidence[]` — list of independent verification methods that fired
  * `severity` — copied from the finding payload so the rule engine
    can apply the HIGH/CRITICAL floor

**Critical rule** (per the §4 doc): CRITICAL / HIGH severity findings
require **≥2 independent verification methods** before being
allowed to advance VERIFYING → VERIFIED. MEDIUM and below allow 1.
The bar is on *independence* — `payload_response` + `payload_response`
counts as one method.

Independent methods (categories):
  * `payload_response` — input/output oracle (e.g. union-based SQLi,
    reflected XSS via payload reflection)
  * `timing` — time-based oracle (e.g. blind SQLi via `SLEEP`)
  * `dom` — DOM-based oracle (e.g. stored XSS via mutation observer)
  * `oob` — out-of-band callback (Burp Collaborator, DNS hit)
  * `differential` — A/B response diff with/without payload
  * `static_match` — semgrep / SAST rule with verified taint flow
  * `external_corroboration` — CVE match + version match (SCA)

## Persistence

Append-only `<run_dir>/verification.jsonl` — one record per
state-change event. Same shape as `objectives.jsonl` / `events.jsonl`.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `STRIX_VERIFICATION_DISABLED` | unset | Kill switch — no state, no enforcement |
| `STRIX_VERIFICATION_PERSIST` | "1" | Set to "0" to skip the jsonl append |
| `STRIX_VERIFICATION_MIN_METHODS_HIGH` | 2 | Floor for HIGH/CRITICAL severity |
| `STRIX_VERIFICATION_MIN_METHODS_DEFAULT` | 1 | Floor for everything else |
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal


logger = logging.getLogger(__name__)


Stage = Literal[
    "SCANNED",
    "DETECTED",
    "VERIFYING",
    "VERIFIED",
    "EXPLOITED",
    "PATCHED",
    "FAILED",
]
Method = Literal[
    "payload_response",
    "timing",
    "dom",
    "oob",
    "differential",
    "static_match",
    "external_corroboration",
]


_VALID_STAGES: frozenset[str] = frozenset({
    "SCANNED", "DETECTED", "VERIFYING", "VERIFIED",
    "EXPLOITED", "PATCHED", "FAILED",
})
_VALID_METHODS: frozenset[str] = frozenset({
    "payload_response", "timing", "dom", "oob",
    "differential", "static_match", "external_corroboration",
})


# Canonical forward transitions. Going backwards or skipping ahead
# is allowed only through explicit overrides (e.g. retract via FAILED).
_FORWARD_TRANSITIONS: dict[Stage, frozenset[Stage]] = {
    "SCANNED": frozenset({"DETECTED", "FAILED"}),
    "DETECTED": frozenset({"VERIFYING", "FAILED"}),
    "VERIFYING": frozenset({"VERIFIED", "FAILED"}),
    "VERIFIED": frozenset({"EXPLOITED", "FAILED"}),
    "EXPLOITED": frozenset({"PATCHED", "FAILED"}),
    "PATCHED": frozenset(),
    "FAILED": frozenset(),
}


# HIGH-tier severities subject to the ≥2 methods floor. Lowercased
# because that matches the existing `severity` strings emitted by
# `reporting_actions.py`.
_HIGH_TIER_SEVERITIES = frozenset({"high", "critical"})


@dataclass
class Evidence:
    """One independent verification method that fired."""
    method: Method
    outcome: Literal["PASSED", "FAILED", "INCONCLUSIVE"]
    tool: str
    detail: str = ""
    recorded_at: float = field(default_factory=time.time)


@dataclass
class VerificationRecord:
    """One finding's progress through the pipeline."""
    finding_id: str
    severity: str
    stage: Stage = "SCANNED"
    evidence: list[Evidence] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "severity": self.severity,
            "stage": self.stage,
            "evidence": [asdict(e) for e in self.evidence],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_reason": self.last_reason,
        }

    def distinct_passed_methods(self) -> set[str]:
        """Unique method types that fired with `PASSED`. The
        2-method rule is on this set's size."""
        return {e.method for e in self.evidence if e.outcome == "PASSED"}


class VerificationPipeline:
    """Process-global singleton — one tracker per scan."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, VerificationRecord] = {}

    def register(self, *, finding_id: str, severity: str) -> VerificationRecord:
        """Create a record for a newly-scanned finding. Idempotent
        — re-calling with the same `finding_id` returns the
        existing record."""
        with self._lock:
            existing = self._records.get(finding_id)
            if existing is not None:
                return existing
            rec = VerificationRecord(
                finding_id=finding_id,
                severity=(severity or "").strip().lower(),
            )
            self._records[finding_id] = rec
        _persist_event("registered", rec)
        return rec

    def record_evidence(
        self,
        finding_id: str,
        *,
        method: Method,
        outcome: Literal["PASSED", "FAILED", "INCONCLUSIVE"],
        tool: str,
        detail: str = "",
    ) -> VerificationRecord | None:
        """Append one evidence entry. Returns the record, or None
        when the finding is unknown."""
        if method not in _VALID_METHODS:
            raise ValueError(
                f"invalid method {method!r}; allowed: {sorted(_VALID_METHODS)}"
            )
        if outcome not in ("PASSED", "FAILED", "INCONCLUSIVE"):
            raise ValueError(
                f"invalid outcome {outcome!r}; allowed: PASSED, FAILED, INCONCLUSIVE"
            )
        with self._lock:
            rec = self._records.get(finding_id)
            if rec is None:
                return None
            rec.evidence.append(Evidence(
                method=method,
                outcome=outcome,
                tool=tool,
                detail=detail,
            ))
            rec.updated_at = time.time()
        _persist_event("evidence_recorded", rec)
        return rec

    def advance(
        self,
        finding_id: str,
        *,
        target_stage: Stage,
        reason: str = "",
    ) -> tuple[bool, str, VerificationRecord | None]:
        """Try to advance the finding's stage. Returns
        `(success, reason, record)`.

        Enforces:
          1. Stage transition must be in `_FORWARD_TRANSITIONS`.
          2. VERIFYING → VERIFIED requires ≥ N independent
             PASSED methods. N = `STRIX_VERIFICATION_MIN_METHODS_HIGH`
             for HIGH/CRITICAL, else `_DEFAULT`.

        `reason` is recorded on the record for audit visibility.
        """
        if target_stage not in _VALID_STAGES:
            return False, f"invalid stage {target_stage!r}", None

        with self._lock:
            rec = self._records.get(finding_id)
            if rec is None:
                return False, "finding not registered", None

            if target_stage == rec.stage:
                return True, "already at stage", rec

            allowed = _FORWARD_TRANSITIONS.get(rec.stage, frozenset())
            if target_stage not in allowed:
                return False, (
                    f"transition {rec.stage} → {target_stage} not allowed; "
                    f"valid: {sorted(allowed)}"
                ), rec

            # Rule: VERIFYING → VERIFIED gate
            if rec.stage == "VERIFYING" and target_stage == "VERIFIED":
                required = _required_methods_for(rec.severity)
                passed = rec.distinct_passed_methods()
                if len(passed) < required:
                    return False, (
                        f"insufficient independent verification methods: "
                        f"have {len(passed)} ({sorted(passed)}), need {required} "
                        f"for severity={rec.severity}"
                    ), rec

            rec.stage = target_stage
            rec.last_reason = reason
            rec.updated_at = time.time()

        _persist_event("stage_advanced", rec)
        return True, f"advanced to {target_stage}", rec

    def get(self, finding_id: str) -> VerificationRecord | None:
        return self._records.get(finding_id)

    def list_records(
        self,
        *,
        stage: Stage | None = None,
        severity: str | None = None,
    ) -> list[VerificationRecord]:
        with self._lock:
            records = list(self._records.values())
        if stage is not None:
            records = [r for r in records if r.stage == stage]
        if severity is not None:
            sev_lower = severity.strip().lower()
            records = [r for r in records if r.severity == sev_lower]
        return sorted(records, key=lambda r: r.finding_id)

    def reset(self) -> None:
        with self._lock:
            self._records = {}


# ---------------------------------------------------------------------------
# Module-level singleton + helpers
# ---------------------------------------------------------------------------


_pipeline: VerificationPipeline | None = None
_pipeline_lock = threading.Lock()


def get_pipeline() -> VerificationPipeline:
    global _pipeline  # noqa: PLW0603
    with _pipeline_lock:
        if _pipeline is None:
            _pipeline = VerificationPipeline()
        return _pipeline


def is_disabled() -> bool:
    return os.environ.get(
        "STRIX_VERIFICATION_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _persistence_enabled() -> bool:
    raw = os.environ.get("STRIX_VERIFICATION_PERSIST", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _required_methods_for(severity: str) -> int:
    """Read the per-severity method floor from env (defaults: 2 for
    high/critical, 1 otherwise)."""
    sev = (severity or "").strip().lower()
    if sev in _HIGH_TIER_SEVERITIES:
        return _read_env_int("STRIX_VERIFICATION_MIN_METHODS_HIGH", 2)
    return _read_env_int("STRIX_VERIFICATION_MIN_METHODS_DEFAULT", 1)


def _read_env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return max(1, int(float(raw)))
    except (ValueError, TypeError):
        return default


def reset_for_testing() -> None:
    global _pipeline  # noqa: PLW0603
    with _pipeline_lock:
        _pipeline = None


# ---------------------------------------------------------------------------
# V3-2 — auto-verify deterministic findings
# ---------------------------------------------------------------------------


def is_quick_skip_verifier_disabled() -> bool:
    """Kill switch for V3-2 (auto-verify deterministic findings in
    quick mode). When set, deterministic findings flow through
    the normal verifier path the same as LLM-discovered ones."""
    return os.environ.get(
        "STRIX_QUICK_SKIP_VERIFIER_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def should_auto_verify_deterministic() -> bool:
    """V3-2 — auto-verify only applies in `quick` and `initial`
    modes. Standard / deep keep the full LLM-verifier round-trips
    for every finding so the lead can chain off them.

    Kill switch (`STRIX_QUICK_SKIP_VERIFIER_DISABLED=1`) disables
    auto-verify regardless of mode.
    """
    if is_disabled() or is_quick_skip_verifier_disabled():
        return False
    mode = (os.environ.get("STRIX_SCAN_MODE") or "").strip().lower()
    return mode in ("quick", "initial")


def auto_verify_deterministic(
    *,
    finding_id: str,
    severity: str,
    source_tool: str,
    detail: str = "",
) -> VerificationRecord | None:
    """V3-2 — register + record evidence + advance to VERIFIED in
    one atomic call, for findings emitted by a deterministic
    specialist that already verified at the oracle level (payload
    reflected / time-based delta / static-analysis taint / SCA
    CVE match etc.).

    The agent doesn't have to issue a separate LLM round-trip to
    advance these through DETECTED → VERIFYING → VERIFIED — saves
    the lead's verify-phase calls when the deterministic stack
    already did the work.

    Recall-safety:
      * The synthesized evidence (`method='static_match'`,
        `outcome='PASSED'`) only counts toward the 1-method
        verification floor for non-HIGH/CRITICAL severities. The
        HIGH/CRITICAL floor (≥2 methods) is unchanged — those
        findings still require a second method (or the agent
        explicitly records one). This preserves the existing
        "≥2 independent methods for HIGH/CRITICAL" invariant.
      * `is_disabled()` + `should_auto_verify_deterministic()`
        are both checked; failures fall through to the normal
        path (the agent can still verify by hand).

    Args:
      finding_id: as emitted by the tracer
      severity: lowercased severity string (high/critical use the
        ≥2-method floor)
      source_tool: name of the deterministic specialist that
        emitted the finding (e.g. "scan_sqli")
      detail: optional one-line audit string

    Returns:
      The final `VerificationRecord` (status may be VERIFIED for
      non-HIGH/CRITICAL or VERIFYING for HIGH/CRITICAL pending a
      second method), or None when the pipeline is disabled.
    """
    if is_disabled():
        return None

    pipeline = get_pipeline()
    rec = pipeline.register(finding_id=finding_id, severity=severity)

    # SCANNED → DETECTED → VERIFYING transitions are unconditional —
    # all three are non-controversial state moves with no method
    # requirements.
    for stage in ("DETECTED", "VERIFYING"):
        pipeline.advance(
            finding_id, target_stage=stage,
            reason=f"v3-2 auto-verify from {source_tool}",
        )

    # Record the deterministic evidence. `static_match` is the
    # canonical method for deterministic detection (semgrep / SAST
    # rule / etc.); using it here unifies the evidence-method
    # taxonomy across LLM-driven + deterministic paths.
    pipeline.record_evidence(
        finding_id,
        method="static_match",
        outcome="PASSED",
        tool=source_tool,
        detail=detail or f"emitted directly by deterministic specialist {source_tool}",
    )

    # Attempt VERIFYING → VERIFIED. For HIGH/CRITICAL findings the
    # ≥2-method floor will block this — by design. The agent (or a
    # second deterministic method like timing oracle) can supply
    # the second method later.
    ok, reason_msg, final_rec = pipeline.advance(
        finding_id, target_stage="VERIFIED",
        reason=f"v3-2 auto-verify (deterministic source: {source_tool})",
    )
    if not ok:
        logger.debug(
            "auto_verify_deterministic: advance to VERIFIED blocked: %s",
            reason_msg,
        )
    return final_rec or rec


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _resolve_run_dir() -> Path | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is not None and hasattr(tracer, "get_run_dir"):
            d = tracer.get_run_dir()
            if d is not None:
                return Path(d)
    except Exception:  # noqa: BLE001
        pass
    env_dir = os.environ.get("STRIX_RUN_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    return None


def _persist_event(event_kind: str, rec: VerificationRecord) -> None:
    if not _persistence_enabled():
        return
    run_dir = _resolve_run_dir()
    if run_dir is None:
        return
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        out = run_dir / "verification.jsonl"
        record = {
            "event": event_kind,
            "ts": time.time(),
            "record": rec.to_dict(),
        }
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except OSError as e:
        logger.debug("could not append verification.jsonl: %s", e)


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


def get_pipeline_stats() -> dict[str, Any]:
    if is_disabled():
        return {"enabled": False, "records": 0}
    records = get_pipeline().list_records()
    stage_counts: dict[str, int] = {}
    for r in records:
        stage_counts[r.stage] = stage_counts.get(r.stage, 0) + 1
    return {
        "enabled": True,
        "records": len(records),
        "stage_counts": stage_counts,
    }
