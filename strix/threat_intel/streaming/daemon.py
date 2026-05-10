"""Streaming daemon — 5-minute KEV poll loop with event-stream emission.

`run_streaming_daemon()` blocks forever; `streaming_iteration()`
runs a single poll cycle so tests + cron-based wrappers can
invoke without committing to a daemon.

CLI:
    python -m strix.threat_intel.streaming         # block + poll forever
    python -m strix.threat_intel.streaming --once  # single iteration

Run under systemd / Kubernetes / `docker run --restart=
unless-stopped` for production. The polling loop is
deliberately simple — no thread pool, no async — so it's easy
to reason about and easy to crash-restart.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from typing import Callable

from strix.threat_intel import cache as ti_cache
from strix.threat_intel.feeds.kev import poll_kev
from strix.threat_intel.streaming.event_stream import EventStream


logger = logging.getLogger(__name__)


# 5-minute default per the doc spec. Tunable via CLI flag.
DEFAULT_INTERVAL_SECONDS = 300


def streaming_iteration(
    *,
    stream: EventStream | None = None,
    poll_kev_fn: Callable | None = None,
    fetch: Callable | None = None,
) -> dict:
    """Run a single streaming-feed iteration.

    Args:
        stream: optional injected `EventStream`. Tests pass a
            `tmp_path`-backed stream; production gets the
            default-path stream.
        poll_kev_fn: optional injected poller (defaults to the
            real `poll_kev`). Tests inject a fake.
        fetch: passed through to the underlying poller for tests.

    Returns:
        {"status": "ok" | "error",
         "kev_diff": {"added": N, "total": N},
         "events_emitted": N}

    Side effects:
        * Writes to the threat-intel cache (KEV upsert).
        * Appends events to the EventStream for any newly-
          listed KEV CVEs since the last poll.
    """
    stream = stream or EventStream()
    poll_kev_fn = poll_kev_fn or poll_kev

    # Snapshot the cache's KEV set BEFORE poll so we can diff.
    try:
        prev_kev = {r.cve_id for r in ti_cache.fetch_kev_list(limit=10000)}
    except Exception as e:  # noqa: BLE001
        logger.debug("streaming: pre-poll kev snapshot failed: %s", e)
        prev_kev = set()

    # Poll.
    try:
        if fetch is not None:
            result = poll_kev_fn(fetch=fetch)
        else:
            result = poll_kev_fn()
    except Exception as e:  # noqa: BLE001
        logger.warning("streaming: poll_kev raised: %s", e)
        return {"status": "error", "error": str(e), "events_emitted": 0}

    if result.get("status") not in ("ok", "partial"):
        # Record liveness even on failure so tail readers see
        # the daemon is alive and what it observed.
        stream.append_feed_polled(
            "kev", status=result.get("status", "error"),
        )
        return {"status": "error", "error": result.get("error"),
                "events_emitted": 1}

    # Diff: anything in current_kev that wasn't in prev_kev →
    # emit `kev_added`.
    try:
        current_kev = ti_cache.fetch_kev_list(limit=10000)
    except Exception as e:  # noqa: BLE001
        logger.debug("streaming: post-poll snapshot failed: %s", e)
        current_kev = []

    added_ids = {r.cve_id for r in current_kev} - prev_kev
    events_emitted = 0
    for r in current_kev:
        if r.cve_id not in added_ids:
            continue
        meta = r.kev_meta or {}
        stream.append_kev_added(
            r.cve_id,
            vendor=str(meta.get("vendor") or ""),
            product=str(meta.get("product") or ""),
            vuln_name=str(meta.get("vuln_name") or ""),
        )
        events_emitted += 1

    # Liveness event.
    stream.append_feed_polled(
        "kev",
        records_total=len(current_kev),
        new_records=len(added_ids),
        status="ok",
    )
    events_emitted += 1

    return {
        "status": "ok",
        "kev_diff": {"added": len(added_ids), "total": len(current_kev)},
        "events_emitted": events_emitted,
    }


def run_streaming_daemon(
    *,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    stream: EventStream | None = None,
    iterations: int | None = None,
) -> None:
    """Block forever, polling every `interval_seconds`.

    `iterations=N` (test path) caps the loop at N iterations.
    Production uses `iterations=None` for unbounded.
    """
    stream = stream or EventStream()
    i = 0
    while True:
        i += 1
        try:
            streaming_iteration(stream=stream)
        except Exception as e:  # noqa: BLE001
            logger.warning("streaming iteration %d failed: %s", i, e)
        if iterations is not None and i >= iterations:
            return
        time.sleep(max(1, interval_seconds))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="strix.threat_intel.streaming",
        description=(
            "Streaming threat-intel daemon. Poll-based v1: "
            "5-minute KEV refresh + event_stream emission. "
            "GitHub webhook subscriber for GHSA, RSS, Bluesky "
            "are deferred to a follow-up PR."
        ),
    )
    parser.add_argument(
        "--interval", type=int, default=DEFAULT_INTERVAL_SECONDS,
        help="Polling interval in seconds (default 300 = 5 min).",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Single iteration then exit (for cron / tests).",
    )
    parser.add_argument(
        "--stream-path", default=None,
        help="Override the default event_stream.jsonl path.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    stream = EventStream(path=args.stream_path) if args.stream_path else None
    if args.once:
        result = streaming_iteration(stream=stream)
        print(f"streaming: status={result['status']} "
              f"events_emitted={result.get('events_emitted', 0)}")
        return 0 if result["status"] == "ok" else 1

    print(f"streaming: starting daemon — interval={args.interval}s")
    try:
        run_streaming_daemon(
            interval_seconds=args.interval, stream=stream,
        )
    except KeyboardInterrupt:
        print("\nstreaming: shutdown requested")
        return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
