"""ObjectiveTracker — OPPLAN-style structured objective state (§2).

Strix already has phase events (`workflow_state.py` — recon →
auth → probe → ... → report) and a coverage matrix, but no
first-class **objective** with status / dependencies / acceptance.
The agent can't reliably answer "what's left to do?" or "what
blocked us?" without re-reading the events log.

This module fixes that. Each `Objective` is a structured record
with:

  * Stable ID (`OBJ-001`, `OBJ-002`, …)
  * `title` — human-readable goal
  * `phase` — links to the workflow phase machine
  * `category` — specialist registry key (`sqli`, `idor`, `xss`, …)
  * `surface` — URL / endpoint / asset under test
  * `depends_on` — list of objective IDs that must complete first
  * `acceptance` — free-text acceptance criterion
  * `status` — pending | in_progress | completed | blocked | cancelled
  * `evidence_required` / `evidence_count` — multi-method floor (§4)
  * `created_at` / `updated_at` — wall-clock timestamps

The tracker is a process-global singleton (like
`workflow_state.py`, `security_context.py`). Tools that emit
findings or transition phases can mark objectives as
in_progress / completed without the lead mediating.

## Persistence

Objectives are append-logged to `<run_dir>/objectives.jsonl` — one
JSON record per state-change event. Reconstruction at startup
collapses the log into the current state.

The append-log shape is **identical** in spirit to
`strix_runs/<run>/events.jsonl` — wrappers already parse that
format. The new file is a focused projection: just objective
mutations, no other events.

## Prompt injection

`render_progress_table()` produces a compact markdown table of
the current objective set, suitable for system-prompt injection
between two blank lines. ~40 chars per objective; for a typical
scan with 6-12 objectives this is ~250-500 chars in the prompt.

The lead and specialists both see the same table on every render
— that's the OPPLAN-style "every LLM call sees the current plan"
invariant from Decepticon.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `STRIX_OBJECTIVES_DISABLED` | unset | Kill switch — tracker is no-op, prompt injection empty |
| `STRIX_OBJECTIVES_PERSIST` | "1" | Set to "0" to skip the objectives.jsonl append |
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


ObjectiveStatus = Literal[
    "pending",
    "in_progress",
    "completed",
    "blocked",
    "cancelled",
]

# Status terminals — once an objective lands here it doesn't move
# on its own. Reopening a `cancelled` or `completed` objective is
# always an explicit `update_objective` call.
_TERMINAL_STATUSES = frozenset({"completed", "cancelled"})

# Valid forward transitions from each status. Tightens the API
# so e.g. "completed → in_progress" isn't possible by accident.
_VALID_TRANSITIONS: dict[ObjectiveStatus, frozenset[ObjectiveStatus]] = {
    "pending": frozenset({"in_progress", "blocked", "cancelled", "completed"}),
    "in_progress": frozenset({"completed", "blocked", "cancelled"}),
    "blocked": frozenset({"pending", "in_progress", "cancelled"}),
    "completed": frozenset({"cancelled"}),  # rare — only when retracting
    "cancelled": frozenset(),
}


@dataclass
class Objective:
    """One tracked objective. The wide field set is deliberate —
    Decepticon's OPPLANs use the structure to drive specialist
    dispatch + acceptance verification. Strix gets the same
    handoff value for free."""
    id: str
    title: str
    phase: str
    category: str
    surface: str = ""
    depends_on: list[str] = field(default_factory=list)
    acceptance: str = ""
    status: ObjectiveStatus = "pending"
    evidence_required: int = 1
    evidence_count: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    parent_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ObjectiveTracker:
    """Process-global singleton (one per scan run). Manage via the
    module-level helpers below — tests use `reset_for_testing()`
    to get a clean slate."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._objectives: dict[str, Objective] = {}
        self._next_id: int = 1

    def create(
        self,
        *,
        title: str,
        phase: str,
        category: str,
        surface: str = "",
        depends_on: list[str] | None = None,
        acceptance: str = "",
        evidence_required: int = 1,
        parent_id: str | None = None,
    ) -> Objective:
        with self._lock:
            obj_id = f"OBJ-{self._next_id:03d}"
            self._next_id += 1
            obj = Objective(
                id=obj_id,
                title=title,
                phase=phase,
                category=category,
                surface=surface,
                depends_on=list(depends_on or []),
                acceptance=acceptance,
                evidence_required=max(1, int(evidence_required)),
                parent_id=parent_id,
            )
            self._objectives[obj_id] = obj
        _persist_event("created", obj)
        return obj

    def get(self, obj_id: str) -> Objective | None:
        return self._objectives.get(obj_id)

    def list(
        self,
        *,
        status: ObjectiveStatus | None = None,
        category: str | None = None,
        phase: str | None = None,
    ) -> list[Objective]:
        with self._lock:
            objs = list(self._objectives.values())
        if status is not None:
            objs = [o for o in objs if o.status == status]
        if category is not None:
            objs = [o for o in objs if o.category == category]
        if phase is not None:
            objs = [o for o in objs if o.phase == phase]
        return sorted(objs, key=lambda o: o.id)

    def update(
        self,
        obj_id: str,
        *,
        status: ObjectiveStatus | None = None,
        evidence_count: int | None = None,
        acceptance: str | None = None,
    ) -> Objective | None:
        with self._lock:
            obj = self._objectives.get(obj_id)
            if obj is None:
                return None

            if status is not None and status != obj.status:
                valid = _VALID_TRANSITIONS.get(obj.status, frozenset())
                if status not in valid:
                    raise ValueError(
                        f"invalid transition: {obj.status} → {status} "
                        f"for {obj_id} (allowed: {sorted(valid)})"
                    )
                obj.status = status

            if evidence_count is not None:
                obj.evidence_count = max(0, int(evidence_count))

            if acceptance is not None:
                obj.acceptance = acceptance

            obj.updated_at = time.time()

        _persist_event("updated", obj)
        return obj

    def mark_evidence(self, obj_id: str, *, n: int = 1) -> Objective | None:
        """Increment evidence_count. When the count reaches
        evidence_required AND the objective is in_progress, this is
        the natural moment to flip to completed — but we leave that
        decision to the caller (auto-completing on first-evidence
        would race specialist verification)."""
        with self._lock:
            obj = self._objectives.get(obj_id)
            if obj is None:
                return None
            obj.evidence_count += max(0, int(n))
            obj.updated_at = time.time()
        _persist_event("evidence_added", obj)
        return obj

    def can_start(self, obj_id: str) -> bool:
        """True when all `depends_on` objectives are `completed`.
        Used to gate `in_progress` transitions; the caller decides
        whether to skip or wait."""
        obj = self._objectives.get(obj_id)
        if obj is None:
            return False
        for dep_id in obj.depends_on:
            dep = self._objectives.get(dep_id)
            if dep is None or dep.status != "completed":
                return False
        return True

    def reset(self) -> None:
        """Test helper. Production code should never call this."""
        with self._lock:
            self._objectives = {}
            self._next_id = 1


# ---------------------------------------------------------------------------
# Module-level singleton + helpers
# ---------------------------------------------------------------------------


_tracker: ObjectiveTracker | None = None
_tracker_lock = threading.Lock()


def get_tracker() -> ObjectiveTracker:
    global _tracker  # noqa: PLW0603
    with _tracker_lock:
        if _tracker is None:
            _tracker = ObjectiveTracker()
        return _tracker


def is_disabled() -> bool:
    return os.environ.get(
        "STRIX_OBJECTIVES_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _persistence_enabled() -> bool:
    raw = os.environ.get("STRIX_OBJECTIVES_PERSIST", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def reset_for_testing() -> None:
    """Reset the module-global tracker. Tests MUST call this in
    fixtures so prior-test state doesn't leak. Production code
    should never call this."""
    global _tracker  # noqa: PLW0603
    with _tracker_lock:
        _tracker = None


# ---------------------------------------------------------------------------
# Persistence — append-only JSONL
# ---------------------------------------------------------------------------


def _resolve_run_dir() -> Path | None:
    """Find the active run's directory. Same lookup pattern as
    `strix/runtime/output_tiering.py::_resolve_run_dir`."""
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


def _persist_event(event_kind: str, obj: Objective) -> None:
    """Append a state-change event to `<run_dir>/objectives.jsonl`.
    Best-effort — never raise to the caller."""
    if not _persistence_enabled():
        return
    run_dir = _resolve_run_dir()
    if run_dir is None:
        return
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        out = run_dir / "objectives.jsonl"
        record = {
            "event": event_kind,
            "ts": time.time(),
            "objective": obj.to_dict(),
        }
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except OSError as e:
        logger.debug("could not append objectives.jsonl: %s", e)


# ---------------------------------------------------------------------------
# Prompt rendering — OPPLAN-style progress table
# ---------------------------------------------------------------------------


# Compact icons for quick visual scan in the prompt — matches the
# emoji-free single-character convention Decepticon uses.
_STATUS_ICON: dict[str, str] = {
    "pending": "·",
    "in_progress": "▶",
    "completed": "✓",
    "blocked": "✗",
    "cancelled": "—",
}


def render_progress_table() -> str:
    """Return a compact OPPLAN-style progress table for system-prompt
    injection. Returns the empty string when no objectives exist or
    the kill switch is set; the template should skip the section."""
    if is_disabled():
        return ""

    tracker = get_tracker()
    objs = tracker.list()
    if not objs:
        return ""

    # Group by phase so the table reads "what's done in recon",
    # "what's done in probe", etc. — matches the existing
    # workflow_state phase ordering.
    by_phase: dict[str, list[Objective]] = {}
    for obj in objs:
        by_phase.setdefault(obj.phase, []).append(obj)

    lines: list[str] = ["OBJECTIVES (current plan — update as you progress):"]

    summary_counts: dict[str, int] = {}
    for obj in objs:
        summary_counts[obj.status] = summary_counts.get(obj.status, 0) + 1
    lines.append(
        "  Status: "
        + ", ".join(
            f"{count} {status}"
            for status, count in sorted(summary_counts.items())
        )
    )
    lines.append("")

    for phase, phase_objs in by_phase.items():
        lines.append(f"  {phase}:")
        for obj in phase_objs:
            icon = _STATUS_ICON.get(obj.status, "?")
            tags = []
            if obj.depends_on:
                tags.append(f"deps={','.join(obj.depends_on)}")
            if obj.evidence_required > 1 or obj.evidence_count > 0:
                tags.append(f"evidence={obj.evidence_count}/{obj.evidence_required}")
            tag_str = f" [{'; '.join(tags)}]" if tags else ""
            target = f" → {obj.surface}" if obj.surface else ""
            lines.append(
                f"    {icon} {obj.id} {obj.title} ({obj.category}){target}{tag_str}"
            )
        lines.append("")

    lines.append(
        "Update objective status as you work (`update_objective`). "
        "An objective with all deps `completed` is ready to start. "
        "An objective `blocked` for >10 turns should be either "
        "resolved or cancelled — don't leave it stale."
    )
    return "\n".join(lines)


def get_tracker_stats() -> dict[str, Any]:
    """Snapshot for telemetry / run_meta.json."""
    if is_disabled():
        return {"enabled": False, "objectives": 0}
    objs = get_tracker().list()
    counts: dict[str, int] = {}
    for obj in objs:
        counts[obj.status] = counts.get(obj.status, 0) + 1
    return {
        "enabled": True,
        "objectives": len(objs),
        "status_counts": counts,
    }
