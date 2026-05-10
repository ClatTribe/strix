"""Streaming threat-intel feeds (roadmap §8 / Phase 9.1).

Replaces the daily cron with sub-hour polling for the highest-
churn feeds:

  * **CISA KEV**: 5-minute poll (the catalog is small JSON;
    re-pulling every 5 minutes is cheap and means
    new-KEV-to-detection latency is < 5 minutes vs ~24h).
  * **`event_stream.jsonl` ring buffer**: every observed delta
    (new CVE in cache, new KEV listing) appends one line. The
    agent loop subscribes to this stream so a CVE published
    mid-scan can pivot ongoing probes.

Out of scope for v1 (deferred to follow-up PR):
  * GitHub App webhook subscriber for GHSA push notifications
    (needs deployment infra + webhook endpoint).
  * RSS subscriptions for HackerOne / exploit-db / vendor
    advisories (high-noise; needs moderation layer).
  * Bluesky firehose for `#infosec` keyword (needs auth +
    rate-limit handling).

The v1 daemon mode is a simple polling loop — `run_streaming
_daemon()` blocks and polls forever. Production usage runs it
under systemd / Kubernetes / a Docker `restart: unless-stopped`
container.
"""

from strix.threat_intel.streaming.daemon import (  # noqa: F401
    run_streaming_daemon,
    streaming_iteration,
)
from strix.threat_intel.streaming.event_stream import (  # noqa: F401
    EventStream,
    StreamEvent,
    default_stream_path,
)
