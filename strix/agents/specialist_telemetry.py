"""Specialist call telemetry (workitem.md Phase 5.4).

Emits structured `specialist.hit` and `specialist.miss` events with
enough metadata to drive offline heuristic tuning (Phase 6.1) and
counter-example logging (Phase 5.3).

Schema (one line per event)::

    {
      "ts": "2026-05-10T...",
      "event_id": "t_<hex>",
      "event_kind": "specialist.hit" | "specialist.miss",
      "tool_name": "scan_sqli",
      "category": "sqli-specialist",
      "target": "http://example.com/api/items?id=1",
      "params": ["id"],
      "args_summary": {...},          # bounded subset of input args
      "result_summary": {             # bounded subset of result
        "status": "ok" | "error" | "partial",
        "findings_count": 3,
        "evidence_count": 5,
        "metadata": {...}
      },
      "decision_path": ["d_abc", "d_def", ...],   # decision_log IDs
      "elapsed_seconds": 4.21,
      "run_id": "run_..."             # optional run grouping
    }

Persistence: `<run_dir>/specialist_telemetry.jsonl`. Append-only;
also kept in an in-memory bounded buffer for cross-call queries.

Best-effort: every public function swallows exceptions so the
agent loop never breaks on telemetry. The complementary in-memory
list is bounded so long-running scans don't OOM.

Public API
----------

  * `record_specialist_call(...)` — log one hit/miss event after a
    specialist returns.
  * `list_telemetry_events()` — read back events (filter by tool /
    target / kind).
  * `last_call_for_target(target, tool_name)` — convenience for
    counter-example detection.
  * `reset_telemetry()` — test helper.

Schema versioning: additive-only. Keep `event_kind` enumeration
stable.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


logger = logging.getLogger(__name__)


_MAX_IN_MEMORY = 5000
_lock = threading.Lock()
_events: list["TelemetryEvent"] = []


@dataclass
class TelemetryEvent:
    """One specialist invocation telemetry record. `event_kind` is
    `specialist.hit` when findings_count > 0, `specialist.miss`
    otherwise."""
    event_id: str
    ts: str
    event_kind: str
    tool_name: str
    category: str
    target: str
    params: list[str] = field(default_factory=list)
    args_summary: dict[str, Any] = field(default_factory=dict)
    result_summary: dict[str, Any] = field(default_factory=dict)
    decision_path: list[str] = field(default_factory=list)
    elapsed_seconds: float | None = None
    run_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _make_id() -> str:
    return "t_" + secrets.token_hex(6)


def _bounded_summary(value: Any, *, max_items: int = 8, max_str: int = 240) -> Any:
    """Truncate dict/list/str values so the telemetry record stays
    small. Important — specialists can return huge result.evidence
    lists; we don't want that copied verbatim into every JSONL row."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= max_items:
                out["__truncated__"] = True
                break
            out[str(k)] = _bounded_summary(v, max_items=max_items, max_str=max_str)
        return out
    if isinstance(value, list):
        if len(value) > max_items:
            return [
                _bounded_summary(v, max_items=max_items, max_str=max_str)
                for v in value[:max_items]
            ] + [f"...+{len(value) - max_items} more"]
        return [
            _bounded_summary(v, max_items=max_items, max_str=max_str)
            for v in value
        ]
    if isinstance(value, str):
        if len(value) > max_str:
            return value[:max_str] + f"...+{len(value) - max_str}b"
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    # Fallback for unknown types.
    s = repr(value)
    return s[:max_str] + f"...+{len(s) - max_str}b" if len(s) > max_str else s


def _persist(event: TelemetryEvent) -> None:
    """Append one event to `<run_dir>/specialist_telemetry.jsonl`
    when `STRIX_RUN_DIR` is set. Best-effort."""
    rd = os.environ.get("STRIX_RUN_DIR")
    if not rd:
        return
    try:
        path = os.path.join(rd, "specialist_telemetry.jsonl")
        os.makedirs(rd, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict(), default=str) + "\n")
    except Exception:  # noqa: BLE001
        logger.debug("specialist_telemetry persist failed", exc_info=True)


def record_specialist_call(
    *,
    tool_name: str,
    category: str,
    target: str,
    params: list[str] | None = None,
    args: dict[str, Any] | None = None,
    result: dict[str, Any] | None = None,
    decision_path: list[str] | None = None,
    elapsed_seconds: float | None = None,
    run_id: str | None = None,
) -> str:
    """Record one specialist invocation. Returns the event_id.

    `event_kind` is auto-derived from the result:
      * `specialist.hit` when findings count > 0
      * `specialist.miss` otherwise

    Caller passes the FULL specialist result (status / findings /
    evidence / tool_metadata); this helper extracts a bounded summary
    and writes it to the telemetry stream.

    Best-effort: returns "" on any internal error so callers don't
    have to defensively wrap.
    """
    try:
        result = result or {}
        findings = result.get("findings", []) or []
        evidence = result.get("evidence", []) or []
        metadata = result.get("tool_metadata", {}) or {}
        status = result.get("status", "ok")

        findings_count = len(findings) if isinstance(findings, list) else 0
        evidence_count = len(evidence) if isinstance(evidence, list) else 0
        event_kind = (
            "specialist.hit" if findings_count > 0
            else "specialist.miss"
        )

        event = TelemetryEvent(
            event_id=_make_id(),
            ts=datetime.now(timezone.utc).isoformat(),
            event_kind=event_kind,
            tool_name=str(tool_name or ""),
            category=str(category or ""),
            target=str(target or "")[:1024],
            params=list(params or []),
            args_summary=_bounded_summary(args or {}),
            result_summary={
                "status": str(status),
                "findings_count": findings_count,
                "evidence_count": evidence_count,
                "metadata": _bounded_summary(metadata),
                # First 3 finding titles — enough for the "found
                # what?" question without bloating the row.
                "finding_titles": [
                    (f.get("title") if isinstance(f, dict) else str(f))[:120]
                    for f in (findings[:3] if isinstance(findings, list) else [])
                ],
            },
            decision_path=list(decision_path or []),
            elapsed_seconds=elapsed_seconds,
            run_id=run_id,
        )
        with _lock:
            _events.append(event)
            if len(_events) > _MAX_IN_MEMORY:
                _events[:] = _events[-_MAX_IN_MEMORY:]
        _persist(event)
        return event.event_id
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "record_specialist_call failed: %s", e, exc_info=True,
        )
        return ""


def list_telemetry_events(
    *,
    tool_name: str | None = None,
    target_substring: str | None = None,
    event_kind: str | None = None,
) -> list[TelemetryEvent]:
    """Return events in chronological order, optionally filtered.

    `tool_name`         — exact match
    `target_substring`  — case-insensitive substring on `target`
    `event_kind`        — exact match (`specialist.hit` / `specialist.miss`)
    """
    with _lock:
        out = list(_events)
    if tool_name is not None:
        out = [e for e in out if e.tool_name == tool_name]
    if event_kind is not None:
        out = [e for e in out if e.event_kind == event_kind]
    if target_substring is not None:
        ts = target_substring.lower()
        out = [e for e in out if ts in (e.target or "").lower()]
    return out


def last_call_for_target(
    target: str, *, tool_name: str | None = None,
) -> TelemetryEvent | None:
    """Return the most-recent telemetry event for `target` (optionally
    constrained to a specific tool). Used by Phase 5.3 counter-example
    detection: when a finding emits at endpoint X, the cross-specialist
    consistency check needs to know what OTHER specialists looked at X
    and missed."""
    target_lower = (target or "").lower()
    with _lock:
        candidates = [
            e for e in reversed(_events)
            if (e.target or "").lower() == target_lower
            and (tool_name is None or e.tool_name == tool_name)
        ]
    return candidates[0] if candidates else None


def hit_miss_counts(*, tool_name: str | None = None) -> dict[str, int]:
    """Aggregate counts. Useful for the lead's self-audit prompt:
    'scan_xss has 3 hits, 12 misses on this run'."""
    with _lock:
        events = list(_events)
    if tool_name is not None:
        events = [e for e in events if e.tool_name == tool_name]
    hits = sum(1 for e in events if e.event_kind == "specialist.hit")
    misses = sum(1 for e in events if e.event_kind == "specialist.miss")
    return {"hits": hits, "misses": misses, "total": len(events)}


def reset_telemetry() -> None:
    """Test-only helper. Clears the in-memory buffer."""
    global _events
    with _lock:
        _events = []
