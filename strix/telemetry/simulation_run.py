"""Adversarial-AI-simulation attestation — MA-S2 P0-APM-C.

## Why this exists

MA-S2 APM-1.2 requires "evidence of adversarial AI simulation"
as a per-run artefact. Strix already runs the simulation
(specialists, KG, chains); this module surfaces the counters
in a single auditor-readable JSON file.

## Output

`<run_dir>/simulation_run.json`:

```json
{
  "schema": "strix.simulation_run/v1",
  "run_id": "...",
  "scan_mode": "deep",
  "started_at": "2026-05-19T...",
  "ended_at": "2026-05-19T...",
  "duration_s": 3247,
  "models_used": [
    {"role": "lead",       "model": "anthropic/claude-opus-4-7"},
    {"role": "specialist", "model": "anthropic/claude-sonnet-4-6"}
  ],
  "specialists_dispatched": 14,
  "specialist_categories_exercised": ["sqli", "xss", "idor", ...],
  "mitre_techniques_exercised": ["T1190", "T1078", ...],
  "kg_node_count": 187,
  "kg_edge_count": 412,
  "ai_reasoning_calls": 318,
  "deterministic_tool_calls": 1024,
  "novel_findings_count": 5,
  "findings_count": 24
}
```

## MA-S2 attestation discipline

The output has a fixed shape — every key is always present.
When the source data isn't available, the value is the
canonical empty value for the type (`0` / `[]` / `null`).
Auditors see the absence as a positive signal: we tried,
and recorded the gap.

## Recall safety

This module never modifies what happens during the scan. It
only reads accumulated tracer state at scan completion.
Failures fall through to a `_build_minimal_summary` fallback
that at least preserves run_id + scan_mode.
"""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


_SCHEMA = "strix.simulation_run/v1"


def _safe_str(value: Any) -> str | None:
    """Coerce to string when possible, else None."""
    if value is None:
        return None
    try:
        s = str(value).strip()
        return s if s else None
    except Exception:  # noqa: BLE001
        return None


def _safe_int(value: Any) -> int:
    """Coerce to int. Returns 0 on failure (matches the
    'zero-when-unknown' attestation discipline)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _gather_models_used(run_metadata: dict[str, Any]) -> list[dict[str, str]]:
    """Read the lead + specialist model identifiers from
    run_metadata. The tracer's existing model-recording flow
    stores these at scan boot."""
    models: list[dict[str, str]] = []
    raw_model = (
        run_metadata.get("model")
        or run_metadata.get("strix_llm")
        or run_metadata.get("STRIX_LLM")
    )
    lead_model = _safe_str(raw_model)
    if lead_model:
        models.append({"role": "lead", "model": lead_model})
        # Today strix uses one model for both roles; when
        # STRIX_LEAD_LLM / STRIX_SPECIALIST_LLM (proposal phase 3
        # of v2 cost-optimization) lands, this surfaces them
        # both. Until then we emit the same model under both
        # roles so downstream consumers see a stable shape.
        models.append({"role": "specialist", "model": lead_model})
    return models


def _gather_specialist_counts(tracer: Any) -> dict[str, Any]:
    """Pull specialist-dispatch counters from
    `specialist_orchestrator` (process-global counters) and the
    tracer's tool_executions table (which categories ran)."""
    out: dict[str, Any] = {
        "specialists_dispatched": 0,
        "specialist_categories_exercised": [],
    }
    try:
        from strix.agents.specialist_orchestrator import get_dispatch_count
        out["specialists_dispatched"] = int(get_dispatch_count())
    except Exception:  # noqa: BLE001
        pass

    try:
        execs = getattr(tracer, "tool_executions", {}) or {}
        cats: set[str] = set()
        for ex in execs.values():
            if not isinstance(ex, dict):
                continue
            tn = (ex.get("tool_name") or "")
            if isinstance(tn, str) and tn.startswith("scan_"):
                # Specialist tools start with `scan_<category>`.
                # The category is the suffix; drop the prefix.
                cats.add(tn[len("scan_"):])
        out["specialist_categories_exercised"] = sorted(cats)
    except Exception as e:  # noqa: BLE001
        logger.debug("specialist categories enumeration failed: %s", e)

    return out


def _gather_mitre_techniques(tracer: Any) -> list[str]:
    """Pull all MITRE ATT&CK technique tags that fired during
    the run from the tracer's tool_executions records."""
    try:
        execs = getattr(tracer, "tool_executions", {}) or {}
    except Exception:  # noqa: BLE001
        return []
    techniques: set[str] = set()
    for ex in execs.values():
        if not isinstance(ex, dict):
            continue
        for t in (ex.get("mitre_techniques") or []):
            if isinstance(t, str) and t.strip():
                techniques.add(t.strip())
    return sorted(techniques)


def _gather_kg_counts(tracer: Any) -> dict[str, int]:
    """Pull KG node + edge counts from the tracer's delta lists.
    Each delta record represents one add (or removal) — for the
    attestation we report the total adds, which approximates
    'KG nodes touched during the scan'."""
    out = {"kg_node_count": 0, "kg_edge_count": 0}
    try:
        out["kg_node_count"] = len(getattr(tracer, "kg_node_deltas", []) or [])
        out["kg_edge_count"] = len(getattr(tracer, "kg_edge_deltas", []) or [])
    except Exception:  # noqa: BLE001
        pass
    return out


def _gather_tool_call_counts(tracer: Any) -> dict[str, int]:
    """Split the tool_executions table into AI-reasoning calls
    (LLM-driven tools like `think`, `dispatch_specialist`) vs
    deterministic tool calls (everything else)."""
    out = {"ai_reasoning_calls": 0, "deterministic_tool_calls": 0}
    try:
        execs = getattr(tracer, "tool_executions", {}) or {}
    except Exception:  # noqa: BLE001
        return out
    ai_tools = {
        "think",
        "dispatch_specialist",
        "dispatch_specialist_batch",
        "create_vulnerability_report",
        "complete_objective",
    }
    for ex in execs.values():
        if not isinstance(ex, dict):
            continue
        tn = (ex.get("tool_name") or "")
        if tn in ai_tools:
            out["ai_reasoning_calls"] += 1
        else:
            out["deterministic_tool_calls"] += 1
    return out


def _gather_findings_counts(tracer: Any) -> dict[str, int]:
    """Total findings + novel findings (those tagged via
    P0-CVS-D's `discovery_method.is_novel` once it ships)."""
    out = {"findings_count": 0, "novel_findings_count": 0}
    try:
        reports = getattr(tracer, "vulnerability_reports", []) or []
        out["findings_count"] = len(reports)
        novel = 0
        for r in reports:
            if not isinstance(r, dict):
                continue
            dm = r.get("discovery_method")
            if isinstance(dm, dict) and dm.get("is_novel") is True:
                novel += 1
        out["novel_findings_count"] = novel
    except Exception:  # noqa: BLE001
        pass
    return out


def _duration_seconds(
    started: str | None, ended: str | None,
) -> float | None:
    """Compute duration in seconds from ISO-8601 timestamps."""
    if not started or not ended:
        return None
    try:
        from datetime import datetime
        s = datetime.fromisoformat(started.replace("Z", "+00:00"))
        e = datetime.fromisoformat(ended.replace("Z", "+00:00"))
        delta = (e - s).total_seconds()
        return round(delta, 2) if delta >= 0 else None
    except Exception:  # noqa: BLE001
        return None


def _build_minimal_summary(tracer: Any) -> dict[str, Any]:
    """Last-resort fallback when the full builder fails. Returns
    a dict with the canonical shape — every field present, mostly
    null / empty / zero."""
    rm = getattr(tracer, "run_metadata", {}) or {}
    return {
        "schema": _SCHEMA,
        "run_id": _safe_str(rm.get("run_id")),
        "scan_mode": _safe_str(rm.get("scan_mode")),
        "started_at": _safe_str(rm.get("start_time")),
        "ended_at": _safe_str(rm.get("end_time")),
        "duration_s": None,
        "models_used": [],
        "specialists_dispatched": 0,
        "specialist_categories_exercised": [],
        "mitre_techniques_exercised": [],
        "kg_node_count": 0,
        "kg_edge_count": 0,
        "ai_reasoning_calls": 0,
        "deterministic_tool_calls": 0,
        "novel_findings_count": 0,
        "findings_count": 0,
    }


def build_simulation_run(tracer: Any) -> dict[str, Any]:
    """Build the simulation_run.json attestation dict from a
    tracer's accumulated state.

    Always returns a dict with the canonical schema shape —
    failures degrade to `_build_minimal_summary` rather than
    raising.
    """
    try:
        rm = getattr(tracer, "run_metadata", {}) or {}
        started = _safe_str(rm.get("start_time"))
        ended = _safe_str(rm.get("end_time"))
        summary: dict[str, Any] = {
            "schema": _SCHEMA,
            "run_id": _safe_str(rm.get("run_id")),
            "scan_mode": _safe_str(rm.get("scan_mode")),
            "started_at": started,
            "ended_at": ended,
            "duration_s": _duration_seconds(started, ended),
            "models_used": _gather_models_used(rm),
            "mitre_techniques_exercised": _gather_mitre_techniques(tracer),
        }
        summary.update(_gather_specialist_counts(tracer))
        summary.update(_gather_kg_counts(tracer))
        summary.update(_gather_tool_call_counts(tracer))
        summary.update(_gather_findings_counts(tracer))
        # iter-Q5.28 — surface anchor_prepass per-tool outcomes so
        # "0 findings" runs are debuggable post-hoc. Each target's
        # entry carries the per-tool status / findings_count /
        # error_reason so we can see e.g. "scan_sast ran ok, 2163
        # raw findings, propagated 200 to host tracer" vs the prior
        # opaque "no findings" black box.
        prepass = rm.get("oss_anchor_prepass")
        if prepass is not None:
            # Defensive: round-trip through json to guarantee the
            # value is fully serializable (no datetimes, no
            # dataclass instances, no Path objects sneaking through
            # PrepassSummary.to_dict()).
            try:
                import json as _json
                summary["oss_anchor_prepass"] = _json.loads(
                    _json.dumps(prepass, default=str),
                )
            except Exception:  # noqa: BLE001
                # If serialization fails, fall back to a minimal
                # marker so the absence-of-block doesn't mislead.
                summary["oss_anchor_prepass"] = [
                    {"target_summary": "(serialization failed)"}
                ]
        return summary
    except Exception as e:  # noqa: BLE001
        logger.debug("simulation_run build failed: %s", e, exc_info=True)
        return _build_minimal_summary(tracer)
