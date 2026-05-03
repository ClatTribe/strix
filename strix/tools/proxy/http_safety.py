"""HTTP-safety middleware: auth-injection + rate-limit + exclude-path.

Read at request time inside the sandbox, populated from env vars forwarded
by `docker_runtime.py`. The values themselves NEVER cross back into the
agent's context — this module returns flat headers / decisions, not the
secret material.

Roadmap §2 (auth flags) + §3 (exclude-path, rate-limit).
"""

from __future__ import annotations

import base64
import fnmatch
import json
import logging
import os
import threading
import time
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


_RATE_LIMIT_LOCK = threading.Lock()
_RATE_LIMIT_LAST_REQUEST_TS: list[float] = []  # mutable single-element list


def inject_auth_headers(headers: dict[str, str]) -> dict[str, str]:
    """Merge configured auth headers into `headers`.

    Agent-supplied values win on conflict — if the agent already set
    `Authorization` or `Cookie`, we don't clobber it. This lets the agent
    test specific auth scenarios without the global override fighting back.
    """
    out = dict(headers or {})
    lower = {k.lower(): k for k in out}

    cookie = os.environ.get("STRIX_AUTH_COOKIE")
    if cookie and "cookie" not in lower:
        out["Cookie"] = cookie

    bearer = os.environ.get("STRIX_AUTH_BEARER")
    basic = os.environ.get("STRIX_AUTH_BASIC")
    if "authorization" not in lower:
        if bearer:
            out["Authorization"] = f"Bearer {bearer}"
        elif basic and ":" in basic:
            encoded = base64.b64encode(basic.encode("utf-8")).decode("ascii")
            out["Authorization"] = f"Basic {encoded}"

    raw_headers = os.environ.get("STRIX_HEADERS")
    if raw_headers:
        try:
            extra = json.loads(raw_headers)
        except (ValueError, TypeError):
            extra = []
        if isinstance(extra, list):
            for entry in extra:
                if not isinstance(entry, str) or ":" not in entry:
                    continue
                name, _, value = entry.partition(":")
                name = name.strip()
                value = value.strip()
                if not name:
                    continue
                # Don't clobber what the agent set explicitly; do clobber
                # earlier env-var injection so the user's --header always
                # takes precedence.
                if name.lower() in lower:
                    # Agent set it — respect.
                    continue
                out[name] = value

    return out


def _excluded_paths() -> list[str]:
    raw = os.environ.get("STRIX_EXCLUDE_PATHS")
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [p for p in parsed if isinstance(p, str) and p.strip()]


def is_path_excluded(url: str) -> tuple[bool, str | None]:
    """Check whether `url`'s path matches any configured exclude glob.

    Returns (excluded, matched_glob). Path-only matching — query string is
    discarded so `?path=/admin/delete` doesn't dodge `/admin/delete`.
    """
    globs = _excluded_paths()
    if not globs:
        return False, None
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, None
    path = parsed.path or "/"
    for pattern in globs:
        if fnmatch.fnmatch(path, pattern):
            return True, pattern
    return False, None


def excluded_response(url: str, matched_glob: str) -> dict[str, Any]:
    """The dict returned in place of the HTTP response when a path is
    blocked. Shape mirrors send_simple_request's normal return so callers
    can surface it without crashing."""
    return {
        "skipped": True,
        "reason": "excluded",
        "matched_glob": matched_glob,
        "url": url,
        "message": (
            f"Request blocked by --exclude-path glob '{matched_glob}'. The "
            "operator excluded this path; do not retry, do not encode around "
            "it. Continue with other surfaces."
        ),
    }


def _rate_limit_qps() -> float | None:
    raw = os.environ.get("STRIX_RATE_LIMIT")
    if not raw:
        return None
    try:
        qps = float(raw)
    except (ValueError, TypeError):
        return None
    return qps if qps > 0 else None


def throttle_for_rate_limit() -> None:
    """Block until enough time has passed since the last request.

    Single global token bucket — cap is across the whole sandbox process,
    not per-host. Trades simplicity for predictability; the cap is what the
    user asked for.
    """
    qps = _rate_limit_qps()
    if qps is None:
        return
    min_interval = 1.0 / qps
    with _RATE_LIMIT_LOCK:
        now = time.monotonic()
        last = _RATE_LIMIT_LAST_REQUEST_TS[0] if _RATE_LIMIT_LAST_REQUEST_TS else 0.0
        wait = (last + min_interval) - now
        if wait > 0:
            time.sleep(wait)
            now = time.monotonic()
        if _RATE_LIMIT_LAST_REQUEST_TS:
            _RATE_LIMIT_LAST_REQUEST_TS[0] = now
        else:
            _RATE_LIMIT_LAST_REQUEST_TS.append(now)


def reset_rate_limiter_for_testing() -> None:
    """Test-only — clears the global rate-limit state between tests."""
    with _RATE_LIMIT_LOCK:
        _RATE_LIMIT_LAST_REQUEST_TS.clear()
