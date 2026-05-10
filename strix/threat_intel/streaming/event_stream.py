"""`event_stream.jsonl` ring buffer for streaming threat-intel.

Append-only JSONL with a hard line cap. When the cap is hit, the
oldest entries get rotated out (atomic rename). Bounded size so
a long-running daemon doesn't grow the file unboundedly.

Each event:
    {"ts": "2026-05-10T..", "kind": "kev_added"|"cve_update"|...,
     "id": "CVE-2024-...", "data": {...}}

Consumers (agent loop) subscribe via `EventStream.tail()` which
yields events newer than a given timestamp.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


logger = logging.getLogger(__name__)


# Default ring-buffer size. 10k events ≈ ~5 MB at typical line
# size; rotates on overflow. Tunable via env for stress-test
# scenarios.
DEFAULT_MAX_EVENTS = int(os.environ.get("STRIX_EVENT_STREAM_MAX", "10000"))


def default_stream_path() -> Path:
    """Where the production daemon writes events.

    Honours `STRIX_RUN_DIR` like the baselines store; otherwise
    falls back to `cwd / event_stream.jsonl`.
    """
    run_dir = os.environ.get("STRIX_RUN_DIR")
    if run_dir:
        return Path(run_dir) / "event_stream.jsonl"
    return Path.cwd() / "event_stream.jsonl"


@dataclass
class StreamEvent:
    """One event in the stream."""
    ts: str          # ISO-8601 UTC
    kind: str        # 'kev_added' | 'cve_update' | 'feed_polled' | ...
    id: str          # the affected CVE / advisory ID
    data: dict       # arbitrary structured payload

    def to_dict(self) -> dict:
        return {
            "ts": self.ts, "kind": self.kind,
            "id": self.id, "data": dict(self.data),
        }

    @classmethod
    def from_dict(cls, d: dict) -> StreamEvent:
        return cls(
            ts=str(d.get("ts", "")),
            kind=str(d.get("kind", "")),
            id=str(d.get("id", "")),
            data=dict(d.get("data") or {}),
        )


class EventStream:
    """Ring-buffered event log.

    Append-only writes; rotation on overflow. Reads are by
    timestamp tail (`tail(since=<iso>)`).
    """

    def __init__(
        self, *,
        path: Path | str | None = None,
        max_events: int = DEFAULT_MAX_EVENTS,
    ):
        self.path = Path(path) if path else default_stream_path()
        self.max_events = max(1, max_events)

    # ---- writes ---------------------------------------------------

    def append(self, event: StreamEvent) -> None:
        """Append `event` to the stream. Rotates when the line
        count exceeds `max_events`."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict()) + "\n")
        self._maybe_rotate()

    def append_kev_added(self, cve_id: str, *, vendor: str = "",
                         product: str = "", vuln_name: str = "") -> None:
        """Convenience: emit a `kev_added` event."""
        self.append(StreamEvent(
            ts=_now_iso(),
            kind="kev_added",
            id=cve_id,
            data={"vendor": vendor, "product": product,
                  "vuln_name": vuln_name},
        ))

    def append_feed_polled(
        self, feed_name: str, *,
        records_total: int = 0,
        new_records: int = 0,
        status: str = "ok",
    ) -> None:
        """Convenience: emit a `feed_polled` event so the agent
        loop can see daemon liveness."""
        self.append(StreamEvent(
            ts=_now_iso(),
            kind="feed_polled",
            id=feed_name,
            data={"records_total": records_total,
                  "new_records": new_records, "status": status},
        ))

    # ---- reads ----------------------------------------------------

    def tail(self, *, since: str | None = None,
             max_events: int = 1000) -> Iterator[StreamEvent]:
        """Yield events newer than `since` (ISO timestamp).
        Defaults to all events when `since=None`. Caps at
        `max_events` for bounded reads."""
        if not self.path.exists():
            return
        count = 0
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ev = StreamEvent.from_dict(d if isinstance(d, dict) else {})
                if not ev.ts:
                    continue
                if since and ev.ts <= since:
                    continue
                yield ev
                count += 1
                if count >= max_events:
                    return

    def all(self, max_events: int = 10000) -> list[StreamEvent]:
        """List of every event up to `max_events`. Convenience
        for tests + status reads."""
        return list(self.tail(since=None, max_events=max_events))

    # ---- rotation -------------------------------------------------

    def _line_count(self) -> int:
        if not self.path.exists():
            return 0
        try:
            with self.path.open("r", encoding="utf-8") as f:
                return sum(1 for _ in f)
        except OSError:
            return 0

    def _maybe_rotate(self) -> None:
        """If the line count exceeds `max_events`, drop the oldest
        rows by reading→keeping the last `max_events`→rewriting.

        Atomic via temp-file + rename. Critical: do NOT truncate
        the live file mid-write (an agent loop tailing the stream
        might miss an event during the truncate window).
        """
        n = self._line_count()
        if n <= self.max_events:
            return
        try:
            with self.path.open("r", encoding="utf-8") as f:
                lines = f.readlines()
            keep = lines[-self.max_events:]
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                f.writelines(keep)
            os.replace(tmp, self.path)
        except OSError as e:
            logger.debug("event_stream rotation failed: %s", e)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
