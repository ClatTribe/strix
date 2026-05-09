"""OOB-DNS callback service (workitem.md Phase 1.3).

Provides an out-of-band callback infrastructure that specialists
use for blind-class vulnerability detection (blind XXE, blind SSRF,
blind RCE, blind SQLi via DNS, etc.). The model:

  1. Specialist requests a callback URL via `register_callback()`.
     Returns `{callback_url, token, expires_at}`.
  2. Specialist embeds the callback URL in its payload.
  3. Strix service polls the OOB infra (interactsh / dnslog / a
     local listener) for hits matching the token.
  4. When a hit lands, the original specialist's callback fires
     (synchronous wait or polling check) and the finding emits.

Three implementations selectable via `STRIX_OOB_BACKEND`:

  * `interactsh` (default when `interactsh-client` is on PATH) —
    spawns `interactsh-client -json` once per process; per-token
    callbacks register against the running client. Public URL is
    `<token>.interact.sh` (or self-hosted if `STRIX_OOB_HOST` set).
  * `local` — strix-internal HTTP+DNS listener bound to
    `STRIX_OOB_LOCAL_HOST` (default `0.0.0.0:8443` for HTTP).
    Useful when the test target can reach the host but external
    OOB infra is unreachable (e.g. air-gapped CI).
  * `disabled` — `register_callback()` returns None; specialists
    that depend on OOB skip blind detection. Default when neither
    `interactsh-client` is on PATH nor `STRIX_OOB_LOCAL_HOST` is
    set.

This module exposes the public interface; concrete backends live
in submodules (`interactsh.py`, `local.py`).
"""

from __future__ import annotations

from strix.tools.oob.service import (
    OOBCallback,
    backend_name,
    is_available,
    poll_callback,
    register_callback,
    reset_oob_service,
)

__all__ = [
    "OOBCallback",
    "backend_name",
    "is_available",
    "poll_callback",
    "register_callback",
    "reset_oob_service",
]
