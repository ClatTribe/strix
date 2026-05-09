"""Decision provenance log (roadmap §8.5 Phase 1.6 / workitem.md
Phase 1.6).

Records each decision the agent makes — probe sent, signal observed,
hypothesis opened, finding emitted — into a JSONL log keyed by run.
The log lets downstream analysis reconstruct WHY each finding
emerged: which probe, which signal, which hypothesis chain. Also
the foundation for Phase 5.2 (chaining graph) and Phase 6.4
(automatic exploit-chain PoC generation).

Schema (one line per decision)::

    {
      "ts": "2026-05-10T...",
      "kind": "probe" | "signal" | "hypothesis" | "finding" |
              "specialist_invocation",
      "actor": {"agent_id": "...", "tool_name": "..."},
      "target": "url / endpoint / param",
      "input": {...},          # what was tested (payload, args)
      "output": {...},          # what was observed (status, fragment)
      "links": {                # cross-references for graph traversal
        "predecessors": ["decision_id", ...],
        "successors": [...],
        "hypothesis_id": "...",
        "finding_id": "...",
      }
    }

Persistence: `<run_dir>/decision_log.jsonl`. Append-only; each
record gets a stable `decision_id` so later events can link to it.

Best-effort: failures swallowed so the log never breaks the agent
loop. The complementary in-memory list is bounded so long-running
scans don't OOM.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


logger = logging.getLogger(__name__)


_MAX_IN_MEMORY = 5000
_lock = threading.Lock()
_decisions: list["Decision"] = []


@dataclass
class Decision:
    decision_id: str
    ts: str
    kind: str  # probe | signal | hypothesis | finding | specialist_invocation
    actor: dict[str, Any] = field(default_factory=dict)
    target: str = ""
    input: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)
    links: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _make_id() -> str:
    return "d_" + secrets.token_hex(6)


def _persist(decision: Decision) -> None:
    """Append the decision to `<run_dir>/decision_log.jsonl` when
    `STRIX_RUN_DIR` is set. Best-effort."""
    rd = os.environ.get("STRIX_RUN_DIR")
    if not rd:
        return
    try:
        path = os.path.join(rd, "decision_log.jsonl")
        os.makedirs(rd, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(decision.to_dict(), default=str) + "\n")
    except Exception:  # noqa: BLE001
        logger.debug("decision_log persist failed", exc_info=True)


def record_decision(
    *,
    kind: str,
    target: str = "",
    input: dict[str, Any] | None = None,
    output: dict[str, Any] | None = None,
    actor: dict[str, Any] | None = None,
    links: dict[str, Any] | None = None,
) -> str:
    """Record one decision. Returns the decision_id so later events
    can link to it via `links={'predecessors': [<id>]}`."""
    decision = Decision(
        decision_id=_make_id(),
        ts=datetime.now(timezone.utc).isoformat(),
        kind=kind,
        actor=dict(actor or {}),
        target=target,
        input=dict(input or {}),
        output=dict(output or {}),
        links=dict(links or {}),
    )
    with _lock:
        _decisions.append(decision)
        # Bound memory.
        if len(_decisions) > _MAX_IN_MEMORY:
            _decisions[:] = _decisions[-_MAX_IN_MEMORY:]
    _persist(decision)
    return decision.decision_id


def link_decisions(*, child_id: str, predecessor_ids: list[str]) -> None:
    """Add predecessor links to an existing decision. Used when the
    causal chain is known retroactively (e.g. a finding emits and
    links back to the probes that confirmed it)."""
    if not child_id or not predecessor_ids:
        return
    with _lock:
        for d in _decisions:
            if d.decision_id == child_id:
                preds = d.links.setdefault("predecessors", [])
                for p in predecessor_ids:
                    if p and p not in preds:
                        preds.append(p)
                return


def list_decisions(kind: str | None = None) -> list[Decision]:
    """Return decisions in chronological order, optionally filtered
    by kind."""
    with _lock:
        if kind is None:
            return list(_decisions)
        return [d for d in _decisions if d.kind == kind]


def reset_decision_log() -> None:
    """Reset the in-memory log. Mostly for tests."""
    global _decisions
    with _lock:
        _decisions = []


def reasoning_trace_for_finding(finding_id: str) -> list[str]:
    """Build a short human-readable reasoning trace for a finding by
    walking back through its predecessor decisions. Returns a list
    of one-line summary strings (newest-first), bounded to 10
    entries.

    Used to populate the `reasoning_trace` field on emitted findings
    so the lead's chain-of-thought is auditable post-hoc.
    """
    out: list[str] = []
    with _lock:
        # Find the finding's decision
        finding_decision = next(
            (d for d in _decisions
             if d.kind == "finding"
             and d.links.get("finding_id") == finding_id),
            None,
        )
        if not finding_decision:
            return out

        visited: set[str] = set()
        queue = [finding_decision.decision_id]
        while queue and len(out) < 10:
            did = queue.pop()
            if did in visited:
                continue
            visited.add(did)
            d = next((x for x in _decisions if x.decision_id == did), None)
            if not d:
                continue
            summary = _summarize_decision(d)
            if summary:
                out.append(summary)
            for p in d.links.get("predecessors", []) or []:
                if p not in visited:
                    queue.append(p)
    return out


def _summarize_decision(d: "Decision") -> str:
    """One-line human summary of a decision."""
    if d.kind == "probe":
        return f"Probed {d.target} with {d.input.get('payload_label', d.input.get('payload', '?'))[:60]}"
    if d.kind == "signal":
        return f"Signal at {d.target}: {d.output.get('signal', '?')[:80]}"
    if d.kind == "hypothesis":
        return f"Hypothesis: {d.input.get('hypothesis', '?')[:80]}"
    if d.kind == "finding":
        return f"Finding emitted: {d.output.get('title', '?')[:80]}"
    if d.kind == "specialist_invocation":
        return f"Specialist `{d.actor.get('tool_name', '?')}` invoked on {d.target}"
    return f"{d.kind}: {d.target}"
