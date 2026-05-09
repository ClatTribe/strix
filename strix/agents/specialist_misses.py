"""Counter-example logging (workitem.md Phase 5.3).

When a specialist EMITS a finding at endpoint X, but a related
specialist returned 0 findings on the SAME endpoint earlier in the
same run, that's strong evidence of a heuristic gap — the related
specialist's detection rules missed the signal that another tool
caught.

Logging these `(input, expected_output, actual_output)` tuples to
`<run_dir>/specialist_misses.jsonl` is the foundation for:
  * Phase 5.3 itself — silent-regression detection during scans
  * Phase 6.1 — active-learning heuristic tuning (the misses file
    is the training corpus for tightening regex thresholds, payload
    cohorts, etc.)

Schema (one line per counter-example)::

    {
      "ts": "...",
      "miss_id": "m_<hex>",
      "endpoint": "http://example.com/api/items?id=1",
      "missed_by_tool": "scan_xss",
      "missed_by_category": "xss-specialist",
      "caught_by_tool": "scan_sqli",
      "caught_by_category": "sqli-specialist",
      "caught_finding": {                # the finding that fired
        "title": "...", "severity": "high",
        "cwe": "CWE-89", "category": "sqli"
      },
      "missed_call": {                   # the prior call that missed
        "event_id": "t_...",
        "args_summary": {...},
        "result_summary": {...}
      },
      "relation_kind": "same_endpoint" | "shared_param"
    }

Logic for "related specialist":

  * **same_endpoint** — both calls used identical (path, method)
    on the same target. The miss is unambiguous: tool B saw the
    surface, tool A returned nothing.
  * **shared_param** — the missed call probed param P at endpoint
    X and the caught call also implicates param P.

Best-effort throughout. Failures swallowed.

Public API
----------

  * `record_caught_finding(...)` — called whenever a specialist
    emits a finding. Walks the recent telemetry stream looking
    for misses on the same endpoint by other tools and logs them.
  * `list_misses(...)` — read back; filter by missed_by_tool /
    endpoint.
  * `reset_misses()` — test helper.
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
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


_MAX_IN_MEMORY = 2000
_lock = threading.Lock()
_misses: list["SpecialistMiss"] = []


@dataclass
class SpecialistMiss:
    miss_id: str
    ts: str
    endpoint: str
    missed_by_tool: str
    missed_by_category: str
    caught_by_tool: str
    caught_by_category: str
    caught_finding: dict[str, Any] = field(default_factory=dict)
    missed_call: dict[str, Any] = field(default_factory=dict)
    relation_kind: str = "same_endpoint"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _make_id() -> str:
    return "m_" + secrets.token_hex(6)


def _normalize_endpoint(url: str) -> str:
    """Return scheme://host:port + path (drop query). Counter-example
    detection is endpoint-shaped, not query-string-exact — same path
    with different params still counts as the same endpoint."""
    if not isinstance(url, str):
        return ""
    try:
        parts = urlparse(url)
        return f"{parts.scheme}://{parts.netloc}{parts.path}"
    except Exception:  # noqa: BLE001
        return url


def _persist(miss: SpecialistMiss) -> None:
    rd = os.environ.get("STRIX_RUN_DIR")
    if not rd:
        return
    try:
        path = os.path.join(rd, "specialist_misses.jsonl")
        os.makedirs(rd, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(miss.to_dict(), default=str) + "\n")
    except Exception:  # noqa: BLE001
        logger.debug("specialist_misses persist failed", exc_info=True)


def record_caught_finding(
    *,
    endpoint: str,
    caught_by_tool: str,
    caught_by_category: str,
    caught_finding: dict[str, Any],
    caught_params: list[str] | None = None,
) -> list[str]:
    """Called whenever a specialist emits a finding. Walks recent
    telemetry events looking for misses on the same endpoint by
    OTHER tools, and logs each as a counter-example.

    Returns the list of miss_ids logged (empty when nothing related).

    Best-effort: returns [] on any internal error.
    """
    try:
        from strix.agents.specialist_telemetry import (
            list_telemetry_events,
        )
    except Exception:  # noqa: BLE001
        return []

    try:
        endpoint_norm = _normalize_endpoint(endpoint)
        if not endpoint_norm:
            return []

        # Find every miss event whose normalized target matches the
        # caught endpoint AND was produced by a DIFFERENT tool.
        all_events = list_telemetry_events(event_kind="specialist.miss")
        related = [
            ev for ev in all_events
            if _normalize_endpoint(ev.target) == endpoint_norm
            and ev.tool_name != caught_by_tool
        ]
        if not related:
            return []

        out_ids: list[str] = []
        caught_params_set = set(caught_params or [])

        for ev in related:
            # Determine relation_kind: shared_param when the missed
            # call's params overlap with the caught finding's params.
            ev_params = set(ev.params or [])
            relation_kind = (
                "shared_param"
                if caught_params_set and (caught_params_set & ev_params)
                else "same_endpoint"
            )

            miss = SpecialistMiss(
                miss_id=_make_id(),
                ts=datetime.now(timezone.utc).isoformat(),
                endpoint=endpoint_norm,
                missed_by_tool=ev.tool_name,
                missed_by_category=ev.category,
                caught_by_tool=caught_by_tool,
                caught_by_category=caught_by_category,
                caught_finding={
                    "title": str(caught_finding.get("title", ""))[:200],
                    "severity": caught_finding.get("severity"),
                    "cwe": caught_finding.get("cwe"),
                    "category": caught_finding.get("category"),
                },
                missed_call={
                    "event_id": ev.event_id,
                    "args_summary": ev.args_summary,
                    "result_summary": ev.result_summary,
                },
                relation_kind=relation_kind,
            )
            with _lock:
                _misses.append(miss)
                if len(_misses) > _MAX_IN_MEMORY:
                    _misses[:] = _misses[-_MAX_IN_MEMORY:]
            _persist(miss)
            out_ids.append(miss.miss_id)
        return out_ids
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "record_caught_finding failed: %s", e, exc_info=True,
        )
        return []


def list_misses(
    *,
    missed_by_tool: str | None = None,
    endpoint_substring: str | None = None,
) -> list[SpecialistMiss]:
    """Return recorded misses, optionally filtered."""
    with _lock:
        out = list(_misses)
    if missed_by_tool is not None:
        out = [m for m in out if m.missed_by_tool == missed_by_tool]
    if endpoint_substring is not None:
        ep = endpoint_substring.lower()
        out = [m for m in out if ep in (m.endpoint or "").lower()]
    return out


def reset_misses() -> None:
    """Test-only helper. Clears the in-memory buffer."""
    global _misses
    with _lock:
        _misses = []
