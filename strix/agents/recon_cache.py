"""Disk-persistent recon cache — step 5 of the v2 cost-optimization
plan (docs/proposals/2026-05-19-scan-mode-cost-optimization.md,
workflow phase 2).

## Why this exists

The recon phase (`webapp_recon_pipeline`, `domain_recon_pipeline`,
etc.) runs once per scan and produces a surface map: discovered
endpoints, tech-stack fingerprint, well-known surface, TLS posture,
security-header audit. On iterative re-scans of the same target
(typical wrapper workflow — schedule daily, or scan-on-deploy),
the surface barely changes between runs, but we re-run the whole
recon pipeline every time. That's 5-15 LLM-supervised tool calls
re-paid on every re-scan.

This module caches successful recon pipeline results on disk,
keyed by `(pipeline_name, target_url, params_hash, scan_mode)`.
On a re-scan within the TTL, the cached result is returned
verbatim and the pipeline body is skipped.

## Recall-safety contract

Conservative by design — cache only fires when the *exact same*
recon shape would have run:
  * **Only successful runs are cached.** Any error in the
    pipeline's inner steps → cache miss, fresh run.
  * **Default TTL is 24 hours.** Long enough to help daily
    re-scans, short enough that "barely changes" doesn't grow
    stale.
  * **Cache key includes scan_mode.** A `quick` recon doesn't
    serve a `deep` re-scan.
  * **Cache key includes the pipeline's primary parameters**
    (e.g. `max_pages`, `max_depth`, `enable_*` flags for the
    webapp pipeline). Different parameter sets = different
    cache entries — we don't silently downgrade depth.
  * **Cache invalidates on schema changes.** A `cache_version`
    stamp lets us bump the schema and force full re-recon
    without manual cleanup.
  * **Kill switch:** `STRIX_RECON_CACHE_DISABLED=1` bypasses
    both lookup and store.

## Storage

Cache files live under `<cache_root>/recon_cache/<key>.json`.
The cache root is, in order of precedence:
  1. `$STRIX_RECON_CACHE_DIR` env var (test override or wrapper-
     side relocation)
  2. `$XDG_CACHE_HOME/strix/recon` if set
  3. `~/.cache/strix/recon`

Per-entry file:
```json
{
  "schema": "strix.recon_cache/v1",
  "key": "<key-hex>",
  "pipeline": "webapp_recon_pipeline",
  "target_url": "https://...",
  "params_hash": "...",
  "scan_mode": "standard",
  "stored_at": 1716000000,
  "ttl_hours": 24,
  "result": { ... pipeline result ... }
}
```

## Telemetry

`recon_cache.hit` and `recon_cache.stored` events emit to the
tracer when one is available. Lets operators see how much
re-scan recon got reused vs re-run.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


_CACHE_SCHEMA = "strix.recon_cache/v1"
_DEFAULT_TTL_HOURS = 24


def is_disabled() -> bool:
    """Returns True when `STRIX_RECON_CACHE_DISABLED` is set to
    a truthy value. Opt-OUT — cache is enabled by default since
    every entry is conservative-by-construction (TTL'd, scoped,
    and only stores successful runs)."""
    return os.environ.get(
        "STRIX_RECON_CACHE_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _cache_root() -> Path:
    """Locate the on-disk cache root. Test override via
    `STRIX_RECON_CACHE_DIR`; production default is
    `~/.cache/strix/recon` (or `$XDG_CACHE_HOME/strix/recon`)."""
    override = os.environ.get("STRIX_RECON_CACHE_DIR")
    if override:
        return Path(override).expanduser().resolve()
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return (base / "strix" / "recon").resolve()


def _ensure_root() -> Path:
    """Return the cache root, creating it on first use. Tolerates
    permission errors by returning a sentinel path that downstream
    `get`/`put` treat as a cache-miss."""
    root = _cache_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
        return root
    except OSError as e:
        logger.debug("recon_cache: cannot create cache root %s: %s", root, e)
        return root  # `get` / `put` will fail gracefully below


def _normalize_target(target_url: str) -> str:
    """Stable canonical form of a target URL. Lowercases scheme +
    host, strips port if it's the protocol default, drops trailing
    slash. Different paths on the same host are treated as
    different cache entries on purpose — recon shape can differ
    per path."""
    if not isinstance(target_url, str) or not target_url.strip():
        return ""
    raw = target_url.strip()
    if "://" not in raw:
        raw = "https://" + raw
    try:
        p = urlparse(raw)
    except Exception:  # noqa: BLE001
        return raw.lower()
    host = (p.hostname or "").lower()
    scheme = (p.scheme or "https").lower()
    default_port = 443 if scheme == "https" else 80
    port = p.port if p.port and p.port != default_port else None
    netloc = f"{host}:{port}" if port else host
    path = p.path or ""
    # Treat "/" same as "" — root-only path doesn't change the
    # cache key meaning. Strip trailing slashes elsewhere too.
    path = path.rstrip("/")
    return f"{scheme}://{netloc}{path}"


def make_key(
    *,
    pipeline: str,
    target_url: str,
    params: dict[str, Any] | None = None,
    scan_mode: str | None = None,
) -> str:
    """Build the on-disk cache key. Stable across re-runs (no
    timestamp / random salt) so re-scans of the same shape hit."""
    norm_target = _normalize_target(target_url)
    norm_pipeline = (pipeline or "").strip().lower()
    norm_mode = ((scan_mode or "").strip().lower()
                 or (os.environ.get("STRIX_SCAN_MODE") or "").strip().lower()
                 or "unset")

    # Serialize params deterministically — dict ordering doesn't
    # affect the key.
    param_blob = json.dumps(
        params or {}, sort_keys=True, default=str,
    )
    params_hash = hashlib.sha256(
        param_blob.encode("utf-8"),
    ).hexdigest()[:16]

    base = f"{_CACHE_SCHEMA}|{norm_pipeline}|{norm_target}|{params_hash}|{norm_mode}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:32]


def _entry_path(key: str) -> Path:
    return _ensure_root() / f"{key}.json"


def get(
    *,
    pipeline: str,
    target_url: str,
    params: dict[str, Any] | None = None,
    scan_mode: str | None = None,
    ttl_hours: int | None = None,
) -> dict[str, Any] | None:
    """Lookup. Returns the cached pipeline result dict on hit,
    or None on miss / disabled / expired / IO error.

    `ttl_hours` overrides the stored entry's TTL (useful for tests).
    """
    if is_disabled():
        return None
    if not target_url:
        return None
    key = make_key(
        pipeline=pipeline, target_url=target_url,
        params=params, scan_mode=scan_mode,
    )
    path = _entry_path(key)
    if not path.exists():
        return None
    try:
        with path.open(encoding="utf-8") as f:
            entry = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("recon_cache: failed to read %s: %s", path, e)
        return None

    if not isinstance(entry, dict):
        return None
    if entry.get("schema") != _CACHE_SCHEMA:
        return None

    stored_at = entry.get("stored_at")
    entry_ttl = ttl_hours if ttl_hours is not None else entry.get(
        "ttl_hours", _DEFAULT_TTL_HOURS,
    )
    if not isinstance(stored_at, (int, float)):
        return None
    age_hours = (time.time() - stored_at) / 3600
    if age_hours > entry_ttl:
        return None

    result = entry.get("result")
    if not isinstance(result, dict):
        return None

    _emit_event("recon_cache.hit", {
        "pipeline": pipeline,
        "target_url": target_url,
        "scan_mode": scan_mode,
        "age_hours": round(age_hours, 2),
    })
    logger.info(
        "recon_cache HIT: pipeline=%s target=%s age=%.1fh",
        pipeline, target_url, age_hours,
    )
    return result


def put(
    *,
    pipeline: str,
    target_url: str,
    result: dict[str, Any],
    params: dict[str, Any] | None = None,
    scan_mode: str | None = None,
    ttl_hours: int | None = None,
) -> bool:
    """Store a successful pipeline result. No-op when:
      * the cache is disabled, or
      * `result` indicates the pipeline failed
        (`result.get("success") is False`), or
      * IO writing fails

    Returns True on store, False otherwise.
    """
    if is_disabled():
        return False
    if not target_url:
        return False
    if not isinstance(result, dict):
        return False
    if result.get("success") is False:
        # Don't cache failed pipeline runs — a re-scan should
        # always retry a failure rather than replay the error.
        return False
    key = make_key(
        pipeline=pipeline, target_url=target_url,
        params=params, scan_mode=scan_mode,
    )
    path = _entry_path(key)
    entry = {
        "schema": _CACHE_SCHEMA,
        "key": key,
        "pipeline": pipeline,
        "target_url": target_url,
        "params_hash": hashlib.sha256(
            json.dumps(params or {}, sort_keys=True, default=str).encode("utf-8"),
        ).hexdigest()[:16],
        "scan_mode": (scan_mode
                      or (os.environ.get("STRIX_SCAN_MODE") or "").strip().lower()
                      or "unset"),
        "stored_at": time.time(),
        "ttl_hours": ttl_hours if ttl_hours is not None else _DEFAULT_TTL_HOURS,
        "result": result,
    }
    try:
        tmp_path = path.with_suffix(".json.tmp")
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(entry, f, default=str)
        tmp_path.replace(path)
    except OSError as e:
        logger.debug("recon_cache: failed to write %s: %s", path, e)
        return False

    _emit_event("recon_cache.stored", {
        "pipeline": pipeline,
        "target_url": target_url,
        "scan_mode": entry["scan_mode"],
        "ttl_hours": entry["ttl_hours"],
    })
    logger.info(
        "recon_cache STORE: pipeline=%s target=%s ttl=%dh",
        pipeline, target_url, entry["ttl_hours"],
    )
    return True


def clear() -> int:
    """Clear every entry in the cache dir. Returns the number of
    files removed. Used by tests + by operators to force a fresh
    recon run."""
    root = _cache_root()
    if not root.exists():
        return 0
    removed = 0
    for f in root.glob("*.json"):
        try:
            f.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def stats() -> dict[str, Any]:
    """Snapshot of cache contents for telemetry + debugging."""
    root = _cache_root()
    if not root.exists():
        return {"root": str(root), "entries": 0, "size_bytes": 0}
    entries = list(root.glob("*.json"))
    return {
        "root": str(root),
        "entries": len(entries),
        "size_bytes": sum(f.stat().st_size for f in entries if f.is_file()),
    }


def _emit_event(event_name: str, payload: dict[str, Any]) -> None:
    """Best-effort tracer event."""
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
        logger.debug("recon_cache telemetry suppressed: %s", e)
