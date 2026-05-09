"""OOB callback service — backend dispatch + public API.

The two key operations:

  * `register_callback()` — generate a unique token, hand back a
    callback URL the specialist embeds in its payload. Returns
    `OOBCallback(token, callback_url, expires_at, backend_name)`.
  * `poll_callback(token, timeout_seconds)` — block (or poll) until
    a callback hits the OOB infra OR the timeout expires. Returns
    `{hit: bool, source_ip: str|None, raw_request: dict|None}`.

Backend selection (priority order):
  1. `STRIX_OOB_BACKEND=disabled` → no-op.
  2. `STRIX_OOB_BACKEND=local` OR `STRIX_OOB_LOCAL_HOST` set → local
     HTTP listener.
  3. `interactsh-client` on PATH → interactsh.
  4. Else → disabled.

In tests, set `STRIX_OOB_BACKEND=disabled` so specialists that
register callbacks gracefully no-op.
"""

from __future__ import annotations

import logging
import os
import secrets
import shutil
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


logger = logging.getLogger(__name__)


@dataclass
class OOBCallback:
    """Handle returned by `register_callback()`."""
    token: str
    callback_url: str
    expires_at: str  # ISO timestamp
    backend_name: str


_lock = threading.Lock()
_backend: "Any | None" = None


def _resolve_backend() -> "Any | None":
    """Pick the OOB backend. Cached after first call."""
    explicit = (os.environ.get("STRIX_OOB_BACKEND") or "").strip().lower()
    if explicit == "disabled":
        return None
    if explicit == "local" or os.environ.get("STRIX_OOB_LOCAL_HOST"):
        try:
            from strix.tools.oob.local_listener import LocalListenerBackend
            return LocalListenerBackend()
        except Exception:  # noqa: BLE001
            logger.debug("local OOB backend init failed", exc_info=True)
    if explicit == "interactsh" or shutil.which("interactsh-client"):
        try:
            from strix.tools.oob.interactsh import InteractshBackend
            return InteractshBackend()
        except Exception:  # noqa: BLE001
            logger.debug("interactsh backend init failed", exc_info=True)
    return None


def _get_backend() -> "Any | None":
    global _backend
    with _lock:
        if _backend is None:
            _backend = _resolve_backend()
        return _backend


def reset_oob_service() -> None:
    """Reset for tests. Tears down the backend if one is active."""
    global _backend
    with _lock:
        if _backend is not None and hasattr(_backend, "shutdown"):
            try:
                _backend.shutdown()
            except Exception:  # noqa: BLE001
                pass
        _backend = None


def is_available() -> bool:
    """True when an OOB backend is wired up. Specialists check this
    before registering — when False, fall back to in-band detection
    only."""
    return _get_backend() is not None


def backend_name() -> str:
    """Return the backend name (`"interactsh"`, `"local"`,
    `"disabled"`). Useful for logging + telemetry."""
    b = _get_backend()
    if b is None:
        return "disabled"
    return getattr(b, "name", type(b).__name__)


def register_callback(*, ttl_seconds: int = 300) -> OOBCallback | None:
    """Generate a unique token + callback URL. Returns None when no
    backend is available (specialists should skip OOB then)."""
    b = _get_backend()
    if b is None:
        return None
    token = "strix" + secrets.token_hex(8)
    try:
        callback_url = b.callback_url_for(token)
    except Exception as e:  # noqa: BLE001
        logger.debug("OOB register_callback failed: %s", e, exc_info=True)
        return None
    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    ).isoformat()
    return OOBCallback(
        token=token,
        callback_url=callback_url,
        expires_at=expires_at,
        backend_name=backend_name(),
    )


def poll_callback(
    token: str, *, timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Poll the backend for a callback matching `token`. Returns
    `{hit, source_ip, raw_request}`. `hit=False` after timeout.

    The caller chooses how long to wait — short timeouts (1-3s) for
    optional confirmation; longer (10-30s) when blind detection is
    the primary signal.
    """
    b = _get_backend()
    if b is None:
        return {"hit": False, "source_ip": None, "raw_request": None}
    try:
        return b.poll(token, timeout_seconds=timeout_seconds)
    except Exception as e:  # noqa: BLE001
        logger.debug("OOB poll failed: %s", e, exc_info=True)
        return {"hit": False, "source_ip": None, "raw_request": None}
