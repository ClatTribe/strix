"""Per-endpoint behavioural baselines (roadmap §8 / Phase 9.2).

For every recon-discovered endpoint, capture an "as-observed
normal" profile so subsequent probes can be diffed against it
to detect behavioural anomalies (Phase 9.3).

What's captured per endpoint:
  * Status-code distribution across N samples
  * Latency p50 / p99
  * Body-length p50 / p99
  * Content-Type
  * For JSON responses: top-level key set (used for new-key
    detection)
  * Auth-state delta (anon vs authenticated response shape)

Persistence: `behavioural_baselines.jsonl` — one line per
endpoint. Append-only; the latest line wins on read.

Out of scope for v1:
  * Auth-state baselines (we record both anon + auth samples
    when the caller supplies auth, but treat them as separate
    rows rather than a structured delta). Proper auth-state
    delta is a follow-up — needs `multi_role_auth` integration.
  * GraphQL-shape fingerprinting (different from JSON top-keys).
  * Streaming responses (SSE, WebSocket).
"""

from strix.baselines.capture import (  # noqa: F401
    EndpointBaseline,
    capture_baseline,
)
from strix.baselines.store import (  # noqa: F401
    BaselineStore,
    default_store_path,
)
