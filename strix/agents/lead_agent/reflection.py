"""Periodic reflection (roadmap §8.5 Phase 6 / §2.5.5 / Park et al. 2023).

Every N turns OR at every `phase.completed`, the lead invokes
`reflect()` to synthesise a high-level summary of recent activity.
The summary is written to `active_hypotheses.jsonl` as a
`reflection` record-type — durable across compactions, retrievable
via `list_reflections()` so the lead can recall past reflections
instead of re-summarising.

This is the [Park et al. 2023 "memory streams"](https://arxiv.org/abs/2304.03442)
pattern adapted to security work: raw observations crystallise into
reflections, which crystallise further into phase-level conclusions.

Schema (additive — wrappers ignoring unknown record-types per
[`engine-usage.md §6`](engine-usage.md#6-versioning--compatibility)
keep working):

```json
{
  "schema_version": 1,
  "record_type": "reflection",
  "reflection_id": "refl_<12hex>",
  "scope": "last_n_turns" | "current_phase" | "current_target",
  "n": <int>,
  "summary": "<1-2 paragraphs synthesised by the lead>",
  "created_at": "<ISO-8601 UTC>",
  "agent_id": "<lead's agent_id>"
}
```

Wrapper-side impact: zero shape change. The new `record_type:
"reflection"` is additive within `active_hypotheses.jsonl`.
Wrappers filtering on `hypothesis.opened/confirmed/dismissed` events
keep working. Wrappers that want to render reflections can add a
new panel; nothing breaks if they don't.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


REFLECTION_SCHEMA_VERSION: int = 1
_VALID_SCOPES = frozenset({"last_n_turns", "current_phase", "current_target"})

_WRITE_LOCK = threading.Lock()
_SUMMARY_CAP_CHARS = 4096
_DEFAULT_LOOKBACK_N = 30


def _gen_reflection_id() -> str:
    return f"refl_{uuid.uuid4().hex[:12]}"


def _artifact_path() -> Path | None:
    """Same `active_hypotheses.jsonl` file as the hypothesis primitives.
    Reflection records share storage so the file is the lead's
    full crystal-memory log."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        run_dir = tracer.get_run_dir()
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir / "active_hypotheses.jsonl"
    except Exception:  # noqa: BLE001
        logger.debug("reflection: path resolution failed", exc_info=True)
        return None


def _append_reflection(record: dict[str, Any]) -> bool:
    path = _artifact_path()
    if path is None:
        return False
    try:
        with _WRITE_LOCK, path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str))
            f.write("\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        return True
    except OSError:
        logger.debug("reflection: write failed", exc_info=True)
        return False


def _emit_event(event_type: str, payload: dict[str, Any]) -> None:
    """Optional event emission (Phase 6 doesn't strictly require it
    but lets wrappers render reflections in real-time rather than
    polling the file)."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return
        tracer._emit_event(
            event_type,
            payload=payload,
            status="ok",
            source="strix.agents.lead_agent.reflection",
        )
    except Exception:  # noqa: BLE001
        logger.debug("reflection: event emission failed", exc_info=True)


@register_tool(sandbox_execution=False, provenance="framework")
def reflect(
    *,
    scope: Literal["last_n_turns", "current_phase", "current_target"] = "last_n_turns",
    n: int = _DEFAULT_LOOKBACK_N,
    summary: str = "",
) -> dict[str, Any]:
    """Append a synthesised reflection to `active_hypotheses.jsonl`.

    The lead agent calls this every ~30 turns OR at every phase
    boundary. The `summary` is the agent's own LLM-generated
    synthesis of recent activity (1-2 paragraphs). Stored as a
    `reflection` record so the lead can recall via
    `list_reflections(scope=...)` instead of re-summarising.

    Args:
        scope: `last_n_turns` (default — reflect over the last N
            turns), `current_phase` (reflect over the active phase),
            `current_target` (reflect over the active target).
        n: number of turns when `scope='last_n_turns'`. Clamped
            non-negative; default 30.
        summary: the synthesised paragraph(s). Capped 4096 chars.
            Empty / whitespace-only summaries are rejected.

    Returns:
        ```python
        {
            "success": bool,
            "reflection_id": str | None,
            "scope": str,
            "error": str | None,
        }
        ```
    """
    if scope not in _VALID_SCOPES:
        return {
            "success": False, "reflection_id": None, "scope": scope,
            "error": f"scope must be one of {sorted(_VALID_SCOPES)}",
        }
    if not isinstance(summary, str) or not summary.strip():
        return {
            "success": False, "reflection_id": None, "scope": scope,
            "error": "summary required (non-empty string)",
        }
    n_clamped = max(0, int(n) if isinstance(n, int | float) else _DEFAULT_LOOKBACK_N)

    summary_clipped = summary.strip()[:_SUMMARY_CAP_CHARS]

    record = {
        "schema_version": REFLECTION_SCHEMA_VERSION,
        "record_type": "reflection",
        "reflection_id": _gen_reflection_id(),
        "scope": scope,
        "n": n_clamped,
        "summary": summary_clipped,
        "created_at": datetime.now(UTC).isoformat(),
    }

    written = _append_reflection(record)
    if not written:
        return {
            "success": False, "reflection_id": record["reflection_id"], "scope": scope,
            "error": "write failed (artifact path unavailable)",
        }

    _emit_event("reflection.recorded", {
        "reflection_id": record["reflection_id"],
        "scope": scope,
        "n": n_clamped,
    })

    return {
        "success": True,
        "reflection_id": record["reflection_id"],
        "scope": scope,
        "error": None,
    }


@register_tool(sandbox_execution=False, provenance="framework")
def list_reflections(
    *,
    scope: str | None = None,
) -> dict[str, Any]:
    """Read reflections from `active_hypotheses.jsonl`.

    The lead calls this when context-window utilisation is high — a
    reflection from turn 25 is cheaper to recall than re-summarising
    the underlying turns from compacted memory.

    Args:
        scope: filter by `last_n_turns` / `current_phase` /
            `current_target`. None = all reflections.

    Returns:
        ```python
        {"success": bool, "reflections": list[dict], "count": int, "error": str | None}
        ```
    """
    if scope is not None and scope not in _VALID_SCOPES:
        return {
            "success": False, "reflections": [], "count": 0,
            "error": f"scope must be one of {sorted(_VALID_SCOPES)} or None",
        }

    path = _artifact_path()
    if path is None or not path.exists():
        return {"success": True, "reflections": [], "count": 0, "error": None}

    out: list[dict[str, Any]] = []
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            if rec.get("record_type") != "reflection":
                continue
            if scope is not None and rec.get("scope") != scope:
                continue
            out.append(rec)
    except OSError:
        logger.debug("reflection: read failed", exc_info=True)
        return {
            "success": False, "reflections": [], "count": 0,
            "error": "read failed",
        }

    return {
        "success": True,
        "reflections": out,
        "count": len(out),
        "error": None,
    }
