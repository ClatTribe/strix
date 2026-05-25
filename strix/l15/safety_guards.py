"""iter-29.9 — Safety guards (destructive + rate-limit).

Two real-world deployment risks every DAST tool faces:

  1. **Destructive actions.** A scan that hits production may
     `DELETE /api/users/42` or `POST /admin/wipe-database` and damage
     real data. Real bug hunters NEVER fire payloads at such verbs
     without explicit authorization.

  2. **Rate-limit triggers.** A scan that hammers `/api/login` with
     1000 credential pairs can lock out real users (per-IP rate
     limits), trip WAF cooldowns, or alert the SOC. The scan should
     back off automatically.

This module provides two enforcement primitives the specialist
dispatcher consults BEFORE firing.

**Composes with iter-29.1 EndpointProfile.** The classifier marks
endpoints as `endpoint_class=destructive` or `idempotent=False`; this
module honors those flags.

Pure-python, no docker tools.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Destructive guard
# ---------------------------------------------------------------------------

# Verbs that strongly imply a state change the scan should not trigger
# without explicit operator authorization. RFC 7231 declares these
# unsafe + non-idempotent.
_UNSAFE_METHODS = frozenset({"DELETE", "PATCH"})  # PUT/POST sometimes legitimate

# Path substrings that indicate destructive intent regardless of verb.
# These mirror the `destructive` endpoint_class from iter-29.1's classifier.
_DESTRUCTIVE_PATH_TOKENS = (
    "delete", "remove", "purge", "drop", "truncate", "wipe", "destroy",
    "uninstall", "revoke",
)


def is_destructive_endpoint(
    url: str,
    method: str = "GET",
    endpoint_class: str | None = None,
) -> tuple[bool, str]:
    """Returns (is_destructive, reason).

    Destructive when ANY:
      * endpoint_class == "destructive" (from EndpointProfile)
      * method in {DELETE, PATCH}
      * path contains a known destructive substring (delete/wipe/...)
    """
    if endpoint_class == "destructive":
        return True, "endpoint_class=destructive"
    method_upper = (method or "GET").upper()
    if method_upper in _UNSAFE_METHODS:
        return True, f"method={method_upper}"
    path_lower = (url or "").lower()
    for token in _DESTRUCTIVE_PATH_TOKENS:
        if token in path_lower:
            return True, f"path contains {token!r}"
    return False, ""


def destructive_ok() -> bool:
    """Operator opt-in via env. Wrapper / CLI sets when target is
    explicitly NOT production."""
    return os.environ.get("STRIX_DESTRUCTIVE_OK", "").lower() in ("1", "true", "yes")


def check_destructive(
    url: str,
    method: str = "GET",
    endpoint_class: str | None = None,
) -> tuple[bool, str]:
    """Returns (allowed, reason).

    Use as a gate before firing any payload:
        ok, reason = check_destructive(url, method, profile.endpoint_class)
        if not ok:
            log.info("skipping %s: %s", url, reason)
            return

    `STRIX_DESTRUCTIVE_OK=1` opt-in bypasses the guard. Logged at info
    level so operators have an audit trail.
    """
    is_dest, why = is_destructive_endpoint(url, method, endpoint_class)
    if not is_dest:
        return True, ""
    if destructive_ok():
        return True, f"destructive ({why}) but STRIX_DESTRUCTIVE_OK=1"
    return False, f"destructive guard refused: {why}"


# ---------------------------------------------------------------------------
# Rate-limit governor
# ---------------------------------------------------------------------------

@dataclass
class RateLimitWindow:
    """Per-host sliding window of recent responses + delay state."""
    total: int = 0
    rate_limited: int = 0      # count of 429/503/Retry-After responses
    current_delay_s: float = 0.0
    last_429_at: float | None = None


class RateLimitGovernor:
    """Thread-safe per-host throttle.

    Specialists call `before_request(host)` (blocks if cooldown
    active) then `record_response(host, status, retry_after)` after.
    When the rate-limited ratio in a window crosses 10%, governor
    enters a backoff curve: 1× → 2× → 5× → 30s pause.

    Designed for safety, not optimization — better to be polite than
    locked out / detected.
    """

    _WINDOW_MIN_SAMPLES = 5       # need at least 5 samples to compute ratio
    _BACKOFF_RATIO_THRESHOLD = 0.10  # 10% rate-limited triggers backoff
    _DELAY_LADDER_S = (0.5, 1.0, 2.0, 5.0, 30.0)
    _COOLDOWN_AFTER_429_S = 30.0   # after a 429, hard pause this long

    def __init__(self) -> None:
        self._windows: dict[str, RateLimitWindow] = {}
        self._lock = threading.RLock()

    def _window_for(self, host: str) -> RateLimitWindow:
        if host not in self._windows:
            self._windows[host] = RateLimitWindow()
        return self._windows[host]

    def before_request(self, host: str) -> None:
        """Apply the current delay for `host` before issuing the next
        request. Blocks for self.delay_for(host) seconds."""
        delay = self.delay_for(host)
        if delay > 0:
            time.sleep(delay)

    def delay_for(self, host: str) -> float:
        with self._lock:
            return self._window_for(host).current_delay_s

    def record_response(
        self, host: str, status: int,
        retry_after: int | float | None = None,
    ) -> None:
        """Update the per-host window after a response."""
        with self._lock:
            w = self._window_for(host)
            w.total += 1
            if status in (429, 503) or retry_after:
                w.rate_limited += 1
                w.last_429_at = time.monotonic()
                w.current_delay_s = max(
                    w.current_delay_s,
                    float(retry_after) if retry_after else self._COOLDOWN_AFTER_429_S,
                )
            self._recompute_delay(w)

    def _recompute_delay(self, w: RateLimitWindow) -> None:
        """Set current_delay_s based on rate-limited ratio."""
        if w.total < self._WINDOW_MIN_SAMPLES:
            return
        ratio = w.rate_limited / w.total
        if ratio < self._BACKOFF_RATIO_THRESHOLD:
            # Healthy — release delay (but never below 0)
            w.current_delay_s = max(0.0, w.current_delay_s - 0.5)
            return
        # Walk up the ladder
        rung = min(
            int(ratio * 10),       # 0.10 → rung 1, 0.20 → rung 2, ...
            len(self._DELAY_LADDER_S) - 1,
        )
        w.current_delay_s = max(w.current_delay_s, self._DELAY_LADDER_S[rung])

    def stats_for(self, host: str) -> dict[str, Any]:
        """Snapshot of the per-host window (for logs / events)."""
        with self._lock:
            w = self._window_for(host)
            return {
                "host": host,
                "total": w.total,
                "rate_limited": w.rate_limited,
                "ratio": (w.rate_limited / w.total) if w.total else 0.0,
                "current_delay_s": w.current_delay_s,
            }

    def reset(self, host: str | None = None) -> None:
        """Reset window state. Pass host=None to clear all (tests)."""
        with self._lock:
            if host is None:
                self._windows.clear()
            else:
                self._windows.pop(host, None)


# Module-level singleton — the dispatcher and specialists share state.
_GOVERNOR = RateLimitGovernor()


def get_governor() -> RateLimitGovernor:
    """Return the process-wide rate-limit governor singleton."""
    return _GOVERNOR


__all__ = [
    "RateLimitGovernor",
    "RateLimitWindow",
    "check_destructive",
    "destructive_ok",
    "get_governor",
    "is_destructive_endpoint",
]
