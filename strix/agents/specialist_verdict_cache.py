"""Specialist verdict cache — step 2 of the v2 cost-optimization
plan (docs/proposals/2026-05-19-scan-mode-cost-optimization.md,
workflow phase 4).

## Why this exists

After scan-mode caps the lead at 8 dispatches on `standard` (PR #334),
the next-biggest waste is **redundant negative dispatches**: the lead
dispatches `sqli` on `/api/users/{id}`, the specialist returns
BLOCKED with reason "no SQL backend, ORM only", and then the lead
dispatches `sqli` on `/api/users/{id}/profile` (same backend, same
verdict). The second dispatch was always going to BLOCKED — we paid
the 25K-token system prompt boot for nothing.

The cache short-circuits that. Cache key = `(category,
endpoint_shape, auth_state)`. On HIT, the dispatch returns
immediately with the cached verdict; no fresh-context loop, no LLM
cost.

## Recall-safety contract

**Only NEGATIVE verdicts are cached.** Never PASSED, never ERROR,
never ITERATION_CAP_REACHED, never BUDGET_EXCEEDED, never
DENIED_BY_SCAN_MODE. The cache exists to suppress *re-running a
known no-op*; it must never suppress a re-dispatch that might find
something new.

Even within BLOCKED, we only cache when the reason matches a
"no-signal" pattern — e.g. "no SQL backend", "no XSS sink",
"not vulnerable", "no auth bypass found". A BLOCKED reason that's
vague ("specialist exhausted iterations", "lost track of state")
does NOT get cached, because the next dispatch might succeed.

## Cache key — canonicalization rules

`endpoint_shape` collapses near-identical endpoints to the same
bucket. The discipline: bucket together endpoints that share a
*backend* (so the negative verdict applies to all of them), but
NOT endpoints that merely share a path prefix.

  /api/v1/users/12345     → /api/v1/users/{id}
  /api/v1/users/abc-uuid  → /api/v1/users/{uuid}
  /api/v1/users/{id}      → /api/v1/users/{id}        (unchanged)
  /api/v1/users/{id}/profile  → /api/v1/users/{id}/profile (kept distinct)

We do NOT collapse the last segment of the path — `/users/{id}/profile`
and `/users/{id}/settings` map to different shapes because they
typically hit different backend handlers. Only path-variable
canonicalization is performed.

`auth_state` is the label of the current auth context (e.g.
"anon", "user_a", "admin"). Same auth state required for the
cache to hit, because the same endpoint behaves differently
across auth levels.

## Kill switch

`STRIX_VERDICT_CACHE_DISABLED=1` bypasses the entire cache. Every
`should_skip()` returns None; every `record()` is a no-op.

## Telemetry

On every cache HIT, an event `verdict_cache.hit` lands in the
tracer. On every STORE, `verdict_cache.stored`. Operators can see
the cache savings in events.jsonl.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


# Patterns in a BLOCKED reason string that mark it as cacheable.
# Conservative — when the reason is vague, we don't cache (the
# next dispatch might succeed).
_CACHEABLE_BLOCKED_PATTERNS = (
    "no sql",
    "no sqli",
    "no xss",
    "no idor",
    "no ssrf",
    "no rce",
    "no command injection",
    "no path traversal",
    "no auth bypass",
    "no authentication bypass",
    "no privilege escalation",
    "no privesc",
    "no signal",
    "not vulnerable",
    "no vulnerability",
    "no exploitable",
    "no injection",
    "no reflection",
    "no oracle",
    "no callback",
    "no oob",
    "no backend",
    "no database",
    "no user input",
    "no sink",
    "no taint",
    "no parameter",
    "no payload reflected",
    "no payload reached",
    "no diff",
    "no behaviour change",
    "no behavior change",
    "no response change",
)

# UUID v4 shape, plus loose hex / short-hash matching for path segments.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_LONG_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
_NUMERIC_RE = re.compile(r"^\d+$")


@dataclass(frozen=True)
class CacheKey:
    """The cache key tuple. Frozen so it's hashable + can be
    used as a dict key directly."""
    category: str
    endpoint_shape: str
    auth_state: str


@dataclass
class CachedVerdict:
    """The value stored in the cache. Only BLOCKED-with-no-signal
    verdicts get cached, so the status is implicitly BLOCKED."""
    reason: str
    summary: str | None
    original_objective: str
    hit_count: int = 0


# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------


_CACHE: dict[CacheKey, CachedVerdict] = {}
_CACHE_LOCK = threading.Lock()


def is_disabled() -> bool:
    """Returns True when `STRIX_VERDICT_CACHE_DISABLED` is set to
    a truthy value. Opt-OUT — default behavior is cache-enabled
    because every cache entry is conservative-by-construction."""
    return os.environ.get(
        "STRIX_VERDICT_CACHE_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def reset() -> None:
    """Clear the cache. Called at scan boot + from tests."""
    with _CACHE_LOCK:
        _CACHE.clear()


def stats() -> dict[str, Any]:
    """Snapshot of cache contents for telemetry / debugging.
    Returns the entry count + total hit count across all entries."""
    with _CACHE_LOCK:
        return {
            "size": len(_CACHE),
            "total_hits": sum(v.hit_count for v in _CACHE.values()),
            "entries": [
                {
                    "category": k.category,
                    "endpoint_shape": k.endpoint_shape,
                    "auth_state": k.auth_state,
                    "reason": v.reason,
                    "hits": v.hit_count,
                }
                for k, v in _CACHE.items()
            ],
        }


# ---------------------------------------------------------------------------
# Key canonicalization
# ---------------------------------------------------------------------------


def _canonicalize_path_segment(seg: str) -> str:
    """Collapse path-variable patterns to typed placeholders so
    near-identical endpoints share a cache bucket.

    Numeric → {id}
    UUID    → {uuid}
    Long hex / hash → {hash}
    Everything else passes through unchanged.
    """
    if not seg:
        return seg
    if _NUMERIC_RE.match(seg):
        return "{id}"
    if _UUID_RE.match(seg):
        return "{uuid}"
    if _LONG_HEX_RE.match(seg):
        return "{hash}"
    return seg


def canonicalize_endpoint(endpoint: str | None) -> str:
    """Reduce an endpoint string to a stable shape for caching.

    - Drops scheme, host, port, query string, fragment
    - Strips the trailing slash
    - Replaces typed path variables (numeric / UUID / long hex)
      with `{id}` / `{uuid}` / `{hash}`
    - Lowercases the result
    - Returns "" when the endpoint is empty / non-stringy

    Note: we do NOT shorten the path. `/users/{id}` and
    `/users/{id}/profile` must remain distinct because they hit
    different handlers (and the negative verdict for one shouldn't
    suppress the dispatch on the other).
    """
    if not endpoint or not isinstance(endpoint, str):
        return ""
    raw = endpoint.strip()
    if not raw:
        return ""

    # Strip URL prefix if present
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            path = parsed.path or ""
        except Exception:  # noqa: BLE001
            return raw.lower()
    else:
        # Bare path — drop any query string / fragment
        path = raw.split("?", 1)[0].split("#", 1)[0]

    path = path.strip()
    if not path:
        return ""

    # Normalize trailing slashes (keep root "/").
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Tokenize, canonicalize each segment, re-join.
    if path.startswith("/"):
        segs = path[1:].split("/")
        canon = [_canonicalize_path_segment(s) for s in segs]
        return ("/" + "/".join(canon)).lower()
    # Relative path — keep as-is, just canonicalize segments.
    segs = path.split("/")
    canon = [_canonicalize_path_segment(s) for s in segs]
    return "/".join(canon).lower()


def _canonicalize_auth_state(auth_state: str | None) -> str:
    """Normalize the auth-state label. Defaults to 'anon' when
    unset so different runs always hit the same bucket."""
    if not auth_state or not isinstance(auth_state, str):
        return "anon"
    return auth_state.strip().lower() or "anon"


def make_key(
    *, category: str, endpoint: str | None, auth_state: str | None,
) -> CacheKey | None:
    """Build the cache key from a dispatch's coordinates. Returns
    None if the key is not buildable (e.g. empty endpoint —
    without an endpoint we can't say two dispatches are talking
    about the same surface).
    """
    cat = (category or "").strip().lower()
    if not cat:
        return None
    shape = canonicalize_endpoint(endpoint)
    if not shape:
        return None
    return CacheKey(
        category=cat,
        endpoint_shape=shape,
        auth_state=_canonicalize_auth_state(auth_state),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _reason_is_cacheable(reason: str | None) -> bool:
    """True when the BLOCKED reason matches a "no-signal" pattern
    that the next dispatch on a similar endpoint is unlikely to
    flip. Vague reasons ("iteration cap exhausted") are NOT
    cacheable."""
    if not reason or not isinstance(reason, str):
        return False
    lowered = reason.lower()
    return any(p in lowered for p in _CACHEABLE_BLOCKED_PATTERNS)


def should_skip(
    *, category: str, endpoint: str | None, auth_state: str | None = None,
) -> CachedVerdict | None:
    """Cache lookup. Called by `dispatch_specialist` before
    building the fresh-context loop. Returns the cached
    CachedVerdict on hit, None on miss.

    On a hit, the verdict's `hit_count` is incremented + a
    `verdict_cache.hit` telemetry event is emitted.
    """
    if is_disabled():
        return None
    key = make_key(category=category, endpoint=endpoint, auth_state=auth_state)
    if key is None:
        return None
    with _CACHE_LOCK:
        verdict = _CACHE.get(key)
        if verdict is None:
            return None
        verdict.hit_count += 1
    _emit_event("verdict_cache.hit", {
        "category": key.category,
        "endpoint_shape": key.endpoint_shape,
        "auth_state": key.auth_state,
        "reason": verdict.reason,
        "hit_count": verdict.hit_count,
    })
    logger.info(
        "verdict_cache HIT: %s on %s (auth=%s) — '%s'",
        key.category, key.endpoint_shape, key.auth_state, verdict.reason,
    )
    return verdict


def record(
    *,
    category: str,
    endpoint: str | None,
    auth_state: str | None,
    status: str,
    reason: str | None,
    objective: str,
    summary: str | None = None,
    findings_count: int = 0,
) -> bool:
    """Store a dispatch's result in the cache if (and only if)
    the result is cacheable.

    The "cacheable" predicate:
      1. status == "BLOCKED"
      2. findings_count == 0 (don't cache near a successful run)
      3. reason matches a "no-signal" pattern (e.g. "no SQL backend")
      4. cache is enabled

    Returns True if the entry was stored; False otherwise.
    """
    if is_disabled():
        return False
    if status != "BLOCKED":
        return False
    if findings_count > 0:
        # Defence-in-depth: BLOCKED with findings shouldn't exist,
        # but if it does, never cache it — a re-dispatch might
        # find more.
        return False
    if not _reason_is_cacheable(reason):
        return False
    key = make_key(category=category, endpoint=endpoint, auth_state=auth_state)
    if key is None:
        return False
    verdict = CachedVerdict(
        reason=reason or "",
        summary=summary,
        original_objective=objective,
        hit_count=0,
    )
    with _CACHE_LOCK:
        _CACHE[key] = verdict
    _emit_event("verdict_cache.stored", {
        "category": key.category,
        "endpoint_shape": key.endpoint_shape,
        "auth_state": key.auth_state,
        "reason": verdict.reason,
    })
    logger.info(
        "verdict_cache STORE: %s on %s (auth=%s) — '%s'",
        key.category, key.endpoint_shape, key.auth_state, verdict.reason,
    )
    return True


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


def _emit_event(event_name: str, payload: dict[str, Any]) -> None:
    """Best-effort event emission. Failures are logged + swallowed
    so the cache works even when the tracer is unavailable."""
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return
        evt = {"event": event_name, **payload}
        if hasattr(tracer, "emit_event"):
            tracer.emit_event(**evt)
        elif hasattr(tracer, "add_event"):
            tracer.add_event(evt)
    except Exception as e:  # noqa: BLE001
        logger.debug("verdict_cache telemetry suppressed: %s", e)
