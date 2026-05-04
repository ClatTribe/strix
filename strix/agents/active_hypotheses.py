"""Active-hypothesis shared state across sub-agents (roadmap §17.6 / §18 row 9).

Today specialists work from `surface_map.json` (shared facts) but
don't see "things sister specialists are currently investigating."
Two parallel specialists can spend tokens on the same hypothesis.

This module is a process-wide append-only log of in-flight
hypotheses, persisted to `<run_dir>/active_hypotheses.jsonl`.
Specialists POST when they form a hypothesis; READ before they
form one to avoid duplicating sister-specialist work.

Schema (one line per hypothesis state-change):

```json
{
  "schema_version": 1,
  "hypothesis_id": "hyp_a1b2c3d4",
  "agent_id": "agent_4f3a2c1b",
  "agent_category": "auth-attacker",
  "hypothesis": "POST /password-reset is vulnerable to host-header-poisoning",
  "surface": "POST /password-reset",
  "category": "host_header_injection",
  "status": "investigating",   // investigating | confirmed | dismissed
  "opened_at": "2026-05-04T...",
  "resolved_at": "2026-05-04T...",  // set when status != investigating
  "resolution": "...",         // optional summary
  "linked_finding_id": "vuln-001",  // when confirmed
  "dismissal_reason": "...",   // when dismissed (mirrors #118 enum)
}
```

The artifact is **append-only** — every state change writes a new
line. The latest line per `hypothesis_id` wins for the read API.
This shape lets the wrapper render a timeline and the RLHF
pipeline grade hypothesis-resolution quality.

Why an artifact (not in-memory only)
------------------------------------

Sub-agents may run in separate processes / sandbox containers.
The shared file is the lowest-common-denominator coordination
primitive. JSONL is append-friendly so concurrent writes don't
require locking. The latest-line-wins rule for status is
intentionally simple — full conflict resolution is the §17.6
blackboard architecture (#D.11) which extends this primitive.

Best-effort everywhere — file-write failures fall back silently
so the agent loop never breaks because of bookkeeping.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


_VALID_STATUSES = frozenset({"investigating", "confirmed", "dismissed"})

# Mirror of the closed-enum dismissal_reason from #118 / dismiss_finding.
_VALID_DISMISSAL_REASONS = frozenset({
    "input_properly_encoded",
    "framework_default_blocked",
    "csrf_token_validated",
    "auth_enforced",
    "not_reflected",
    "different_origin",
    "out_of_scope",
    "false_positive_signature",
    "compensating_control",
    "intended_behavior",
    "test_fixture",
    "deprecated_path",
    "other",
})


# Process-wide write lock (per-file, but realistically one tracer
# per process — keep it simple).
_WRITE_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _gen_hypothesis_id() -> str:
    return f"hyp_{uuid.uuid4().hex[:12]}"


def _artifact_path() -> Path | None:
    """Resolve the active_hypotheses.jsonl path via the global tracer's
    run dir. Returns None when no tracer is set (best-effort)."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        run_dir = tracer.get_run_dir()
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir / "active_hypotheses.jsonl"
    except Exception:  # noqa: BLE001
        logger.debug("active_hypotheses path resolution failed", exc_info=True)
        return None


def _append_record(record: dict[str, Any]) -> bool:
    """Write one JSONL line. Returns True on success, False on failure
    (caller decides how to react; usually swallow)."""
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
        logger.debug("active_hypotheses write failed", exc_info=True)
        return False


def _emit_event(event_type: str, payload: dict[str, Any]) -> None:
    """Best-effort tracer event for wrapper consumption. Never raises."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return
        tracer._emit_event(  # noqa: SLF001
            event_type,
            payload=payload,
            status=payload.get("status", "ok"),
            source="strix.agents.active_hypotheses",
        )
    except Exception:  # noqa: BLE001
        logger.debug("active_hypotheses event emit failed", exc_info=True)


# ---------------------------------------------------------------------------
# Public API — POST
# ---------------------------------------------------------------------------


def open_hypothesis(
    *,
    hypothesis: str,
    surface: str,
    agent_id: str | None = None,
    agent_category: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    """Register a new in-flight hypothesis.

    Returns the full record (including the auto-generated
    `hypothesis_id`). Callers should retain the id and use it on
    subsequent confirm/dismiss calls.

    Best-effort: file-write failures don't propagate; the returned
    record is still valid for in-process use.
    """
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        return {"success": False, "message": "hypothesis text is required"}
    if not isinstance(surface, str) or not surface.strip():
        return {"success": False, "message": "surface is required"}

    record: dict[str, Any] = {
        "schema_version": 1,
        "hypothesis_id": _gen_hypothesis_id(),
        "agent_id": agent_id,
        "agent_category": agent_category,
        "hypothesis": hypothesis.strip()[:1024],
        "surface": surface.strip()[:512],
        "category": (category or "").strip().lower() or None,
        "status": "investigating",
        "opened_at": _now(),
        "resolved_at": None,
    }
    _append_record(record)
    _emit_event(
        "hypothesis.opened",
        {
            "hypothesis_id": record["hypothesis_id"],
            "agent_id": agent_id,
            "agent_category": agent_category,
            "surface": record["surface"],
            "hypothesis": record["hypothesis"],
            "category": record["category"],
            "status": "investigating",
        },
    )
    return {"success": True, **record}


def confirm_hypothesis(
    *,
    hypothesis_id: str,
    resolution: str = "",
    linked_finding_id: str | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    """Mark a hypothesis as confirmed (vuln found). When a finding
    was emitted, pass `linked_finding_id` so the wrapper can join
    the hypothesis timeline to the finding card."""
    if not isinstance(hypothesis_id, str) or not hypothesis_id.strip():
        return {"success": False, "message": "hypothesis_id is required"}

    record = {
        "schema_version": 1,
        "hypothesis_id": hypothesis_id.strip(),
        "agent_id": agent_id,
        "status": "confirmed",
        "resolved_at": _now(),
        "resolution": resolution.strip()[:1024] if isinstance(resolution, str) else "",
        "linked_finding_id": linked_finding_id,
    }
    _append_record(record)
    _emit_event(
        "hypothesis.confirmed",
        {
            "hypothesis_id": hypothesis_id,
            "agent_id": agent_id,
            "linked_finding_id": linked_finding_id,
            "status": "confirmed",
        },
    )
    return {"success": True, **record}


def dismiss_hypothesis(
    *,
    hypothesis_id: str,
    dismissal_reason: str,
    resolution: str = "",
    agent_id: str | None = None,
) -> dict[str, Any]:
    """Mark a hypothesis as dismissed (investigated, ruled out).
    `dismissal_reason` mirrors the closed-enum from #118
    `dismiss_finding`."""
    if not isinstance(hypothesis_id, str) or not hypothesis_id.strip():
        return {"success": False, "message": "hypothesis_id is required"}
    if dismissal_reason not in _VALID_DISMISSAL_REASONS:
        return {
            "success": False,
            "message": (
                f"dismissal_reason {dismissal_reason!r} not in allow-list. "
                f"Valid: {sorted(_VALID_DISMISSAL_REASONS)}"
            ),
        }

    record = {
        "schema_version": 1,
        "hypothesis_id": hypothesis_id.strip(),
        "agent_id": agent_id,
        "status": "dismissed",
        "resolved_at": _now(),
        "resolution": resolution.strip()[:1024] if isinstance(resolution, str) else "",
        "dismissal_reason": dismissal_reason,
    }
    _append_record(record)
    _emit_event(
        "hypothesis.dismissed",
        {
            "hypothesis_id": hypothesis_id,
            "agent_id": agent_id,
            "dismissal_reason": dismissal_reason,
            "status": "dismissed",
        },
    )
    return {"success": True, **record}


# ---------------------------------------------------------------------------
# Public API — READ
# ---------------------------------------------------------------------------


def list_active_hypotheses(
    *,
    only_status: str | None = None,
    surface: str | None = None,
    category: str | None = None,
) -> list[dict[str, Any]]:
    """Read the latest state per hypothesis_id from the artifact.

    Filters:
      only_status: 'investigating' / 'confirmed' / 'dismissed' / None (all)
      surface: substring match (case-insensitive) for de-duplication
        across naming variants ("/login" vs "POST /login")
      category: exact match against the opened record's category

    Returns a list ordered by `opened_at` (oldest first)."""
    path = _artifact_path()
    if path is None or not path.exists():
        return []

    # Collect latest record per hypothesis_id by walking the file.
    # Latest line wins; opened-record metadata (surface, category,
    # opened_at) is preserved by merging with the latest state line.
    by_id: dict[str, dict[str, Any]] = {}
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            hid = rec.get("hypothesis_id")
            if not isinstance(hid, str):
                continue
            if hid in by_id:
                # Merge: latest fields win, but keep the original
                # opened_at / hypothesis / surface / category from
                # the open record.
                merged = dict(by_id[hid])
                merged.update({k: v for k, v in rec.items() if v is not None})
                by_id[hid] = merged
            else:
                by_id[hid] = rec
    except OSError:
        return []

    out = list(by_id.values())

    if only_status is not None:
        if only_status not in _VALID_STATUSES:
            return []
        out = [r for r in out if r.get("status") == only_status]

    if surface is not None:
        s_lower = surface.lower()
        out = [
            r
            for r in out
            if isinstance(r.get("surface"), str) and s_lower in r["surface"].lower()
        ]

    if category is not None:
        c_lower = category.lower()
        out = [r for r in out if (r.get("category") or "").lower() == c_lower]

    out.sort(key=lambda r: r.get("opened_at") or "")
    return out


def is_surface_under_investigation(
    surface: str, *, category: str | None = None
) -> bool:
    """Sister-specialist guard: 'is anyone currently investigating
    this surface (and optionally this category)?' Returns True when
    at least one hypothesis matches and is still in `investigating`
    state."""
    if not isinstance(surface, str) or not surface.strip():
        return False
    matches = list_active_hypotheses(
        only_status="investigating",
        surface=surface,
        category=category,
    )
    return len(matches) > 0


def reset_for_testing() -> None:
    """Clear the artifact. Tests call this in fixtures."""
    path = _artifact_path()
    if path is not None and path.exists():
        try:
            path.unlink()
        except OSError:
            pass
