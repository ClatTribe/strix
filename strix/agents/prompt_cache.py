"""Boot-prompt persistence — step 8 (final step) of the v2
cost-optimization plan
(docs/proposals/2026-05-19-scan-mode-cost-optimization.md,
workflow phase 1 — boot).

## Why this exists

Strix already wires Anthropic prompt caching (`cache_control:
{type: ephemeral}`) so back-to-back calls within a 5-minute TTL
share the system-prompt cost. A re-scan an hour later, or a
batch-mode wrapper run that fires N strix subprocesses, pays the
boot cost in full.

This module gives us:
  * **Disk persistence** of every rendered boot prompt. Each
    scan writes a single file the wrapper / operator can `cat`
    for audit ("which prompt did we actually send?").
  * **Content-hash dedup detection.** When two scans (same
    target, same scan_mode, same skills) render byte-identical
    prompts, we surface that fact via telemetry. Operators can
    see at-a-glance which re-scans would have benefited from a
    longer-TTL cache.
  * **Infrastructure for the future** "actually replay across
    runs" optimization. Once the rendered prompt is provably
    deterministic across processes, the wrapper can confidently
    batch back-to-back scans inside Anthropic's TTL.

Cost win today: **0 on the first scan**, modest savings on
re-scans within Anthropic's TTL (the API caches the prefix when
the content is byte-identical). The bigger long-term win is
visibility — operators see WHEN their re-scan benefited from
caching and WHEN it didn't.

## Recall-safety contract

This module never modifies the prompt content. It only
persists + hashes what the LLM layer already built. Every
guarantee is "writes-only" — no behavior change to the
production prompt path.

## Kill switch

`STRIX_PROMPT_CACHE_DISABLED=1` skips disk writes + dedup
detection. Useful for tests / air-gapped envs where filesystem
writes are unwanted.

## Storage

Cache root resolution (in order):
  1. `$STRIX_PROMPT_CACHE_DIR` (test override)
  2. `$XDG_CACHE_HOME/strix/prompts`
  3. `~/.cache/strix/prompts`

Files: `<content_hash>.txt` — the rendered prompt verbatim, no
metadata wrapping. The metadata (target, scan_mode, timestamp,
seen-count) lives in `index.json` alongside the content files.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


_INDEX_FILE = "index.json"


def is_disabled() -> bool:
    """Returns True when `STRIX_PROMPT_CACHE_DISABLED` is truthy."""
    return os.environ.get(
        "STRIX_PROMPT_CACHE_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _cache_root() -> Path:
    override = os.environ.get("STRIX_PROMPT_CACHE_DIR")
    if override:
        return Path(override).expanduser().resolve()
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return (base / "strix" / "prompts").resolve()


def _ensure_root() -> Path:
    root = _cache_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.debug("prompt_cache: cannot create cache root %s: %s", root, e)
    return root


def content_hash(prompt: str) -> str:
    """Stable SHA-256 of the prompt content. The cache uses the
    full hex so collisions across realistic prompt-content
    spaces are mathematically impossible. Empty / non-string
    input returns empty (no-op marker)."""
    if not isinstance(prompt, str) or not prompt:
        return ""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _load_index(root: Path) -> dict[str, Any]:
    idx_path = root / _INDEX_FILE
    if not idx_path.exists():
        return {}
    try:
        with idx_path.open(encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_index(root: Path, index: dict[str, Any]) -> None:
    idx_path = root / _INDEX_FILE
    try:
        tmp = idx_path.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(index, f)
        tmp.replace(idx_path)
    except OSError as e:
        logger.debug("prompt_cache: failed to save index: %s", e)


def persist(
    *,
    prompt: str,
    target: str | None = None,
    scan_mode: str | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    """Write the rendered prompt to disk (if not already there)
    and update the index. Returns a stats dict:

      {
        "hash": <sha256-hex>,
        "path": <str-path>,
        "first_seen": bool,         # True only on the first persist
        "seen_count": int,          # incremented each call
        "byte_size": int,
        "disabled": bool,
      }

    When the prompt is empty or the cache is disabled, returns a
    minimal dict with `disabled` / no-op semantics — never raises.
    """
    if is_disabled() or not isinstance(prompt, str) or not prompt:
        safe_prompt = prompt if isinstance(prompt, str) else ""
        return {
            "hash": content_hash(safe_prompt),
            "path": None,
            "first_seen": False,
            "seen_count": 0,
            "byte_size": len(safe_prompt),
            "disabled": is_disabled(),
        }
    h = content_hash(prompt)
    root = _ensure_root()
    body_path = root / f"{h}.txt"
    first_seen = not body_path.exists()
    if first_seen:
        try:
            body_path.write_text(prompt, encoding="utf-8")
        except OSError as e:
            logger.debug("prompt_cache: write failed for %s: %s", body_path, e)

    index = _load_index(root)
    entry = index.get(h) or {
        "hash": h,
        "first_seen_at": time.time(),
        "seen_count": 0,
        "byte_size": len(prompt),
        "targets": [],
        "scan_modes": [],
        "roles": [],
    }
    entry["seen_count"] = int(entry.get("seen_count", 0)) + 1
    entry["last_seen_at"] = time.time()
    if target and target not in entry["targets"]:
        entry["targets"] = (entry["targets"] + [target])[-10:]
    if scan_mode and scan_mode not in entry["scan_modes"]:
        entry["scan_modes"] = (entry["scan_modes"] + [scan_mode])[-5:]
    if role and role not in entry["roles"]:
        entry["roles"] = (entry["roles"] + [role])[-5:]
    index[h] = entry
    _save_index(root, index)

    _emit_event("prompt_cache.persisted", {
        "hash": h,
        "first_seen": first_seen,
        "seen_count": entry["seen_count"],
        "byte_size": entry["byte_size"],
        "target": target,
        "scan_mode": scan_mode,
        "role": role,
    })

    return {
        "hash": h,
        "path": str(body_path),
        "first_seen": first_seen,
        "seen_count": entry["seen_count"],
        "byte_size": entry["byte_size"],
        "disabled": False,
    }


def lookup(prompt_hash: str) -> str | None:
    """Read a cached prompt back by hash. Returns None on miss /
    disabled / IO error."""
    if is_disabled() or not isinstance(prompt_hash, str) or not prompt_hash:
        return None
    body_path = _cache_root() / f"{prompt_hash}.txt"
    if not body_path.exists():
        return None
    try:
        return body_path.read_text(encoding="utf-8")
    except OSError as e:
        logger.debug("prompt_cache: read failed for %s: %s", body_path, e)
        return None


def stats() -> dict[str, Any]:
    """Snapshot of cache contents: total entries + total seen
    count across all entries. For telemetry / debugging."""
    root = _cache_root()
    index = _load_index(root)
    return {
        "root": str(root),
        "entries": len(index),
        "total_seen_count": sum(int(e.get("seen_count", 0)) for e in index.values()),
        "total_byte_size": sum(int(e.get("byte_size", 0)) for e in index.values()),
    }


def clear() -> int:
    """Clear every cached prompt + the index. Returns the number
    of bodies removed."""
    root = _cache_root()
    if not root.exists():
        return 0
    removed = 0
    for f in root.glob("*.txt"):
        try:
            f.unlink()
            removed += 1
        except OSError:
            continue
    (root / _INDEX_FILE).unlink(missing_ok=True)
    return removed


def _emit_event(name: str, payload: dict[str, Any]) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return
        evt = {"event": name, **payload}
        if hasattr(tracer, "emit_event"):
            tracer.emit_event(**evt)
        elif hasattr(tracer, "add_event"):
            tracer.add_event(evt)
    except Exception as e:  # noqa: BLE001
        logger.debug("prompt_cache telemetry suppressed: %s", e)
