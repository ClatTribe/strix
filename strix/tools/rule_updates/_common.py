"""iter-24.1 — shared 24h-cache ETag refresh logic.

All `update_<X>_rules` tools call into `refresh_via_etag()` which:

  1. Looks up the cached file under ``~/.strix/cache/rules/<name>``
  2. If the cached file is younger than ``max_age_hours``, returns
     ``status="fresh"`` without any HTTP call (the lazy-update pattern).
  3. Otherwise issues a ``GET`` against the upstream URL using the
     previously stored ETag in a sibling ``<name>.etag`` file. A
     ``304 Not Modified`` response just touches the mtime and returns
     ``status="unchanged"``.
  4. A ``200 OK`` writes the body to the cache atomically (tmpfile +
     rename) and stores the new ETag.
  5. Any HTTP / IO / network failure leaves the existing cache alone
     and returns ``status="partial"`` — recall-safe per
     L1-optimization §5.1's "fails-safe back to the build-time static
     seed" guarantee.

The cache directory is created lazily. Both the build-time Dockerfile
seed and the run-time tools write to the same dir, so a fresh sandbox
already has every file populated.
"""

from __future__ import annotations

import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


_CACHE_ENV = "STRIX_RULES_CACHE_DIR"
_DEFAULT_CACHE = "~/.strix/cache/rules"
_DEFAULT_TIMEOUT = 15
_USER_AGENT = "strix-rule-updater/1.0"


def cache_root() -> Path:
    """Return the rules cache directory; create it on first call."""
    root_str = os.environ.get(_CACHE_ENV) or _DEFAULT_CACHE
    root = Path(root_str).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    return root


def cached_path(name: str) -> Path:
    """Return path to a cached file by name (may not exist yet)."""
    return cache_root() / name


def _etag_path(file_path: Path) -> Path:
    return file_path.with_name(file_path.name + ".etag")


def _read_etag(file_path: Path) -> str | None:
    p = _etag_path(file_path)
    try:
        return p.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _write_etag(file_path: Path, etag: str | None) -> None:
    p = _etag_path(file_path)
    if etag is None:
        try:
            p.unlink()
        except OSError:
            pass
        return
    try:
        p.write_text(etag, encoding="utf-8")
    except OSError as e:
        logger.debug("could not write etag %s: %s", p, e)


def _atomic_write(file_path: Path, data: bytes) -> None:
    tmp = file_path.with_name(file_path.name + ".tmp")
    try:
        tmp.write_bytes(data)
        tmp.replace(file_path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _file_age_hours(file_path: Path) -> float | None:
    try:
        st = file_path.stat()
    except OSError:
        return None
    return max(0.0, (time.time() - st.st_mtime) / 3600.0)


def refresh_via_etag(
    name: str,
    url: str,
    max_age_hours: float = 24.0,
    timeout: int = _DEFAULT_TIMEOUT,
    force: bool = False,
) -> dict[str, Any]:
    """Refresh a cached file using a 24h-stale ETag check.

    Args:
        name: cache key (e.g. ``"gitleaks.toml"``) — also the on-disk
            filename under ``cache_root()``.
        url: upstream URL to GET.
        max_age_hours: skip the HTTP call entirely if the cached
            file is younger than this.
        timeout: socket timeout in seconds.
        force: when True, ignore the freshness window and always
            issue an HTTP call.

    Returns:
        ```
        {success, status: fresh|updated|unchanged|partial|error,
         path: str, size_bytes?: int, age_hours?: float, reason?: str}
        ```

        - ``fresh``     : on-disk file is newer than max_age_hours; no HTTP.
        - ``unchanged`` : 304 Not Modified; mtime bumped, no rewrite.
        - ``updated``   : 200 OK; new body written atomically.
        - ``partial``   : network/HTTP error; existing cache untouched.
        - ``error``     : unexpected exception; existing cache untouched.
    """
    file_path = cached_path(name)
    age = _file_age_hours(file_path)

    if not force and age is not None and age < max_age_hours:
        return {
            "success": True, "status": "fresh", "path": str(file_path),
            "age_hours": round(age, 2),
            "size_bytes": file_path.stat().st_size,
        }

    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    etag = _read_etag(file_path) if file_path.exists() else None
    if etag and not force:
        req.add_header("If-None-Match", etag)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            new_etag = resp.headers.get("ETag")
            body = resp.read()
            _atomic_write(file_path, body)
            _write_etag(file_path, new_etag)
            return {
                "success": True, "status": "updated",
                "path": str(file_path),
                "size_bytes": len(body),
            }
    except urllib.error.HTTPError as e:
        if e.code == 304:
            # Bump mtime so future calls hit the freshness window.
            try:
                os.utime(file_path, None)
            except OSError:
                pass
            return {
                "success": True, "status": "unchanged",
                "path": str(file_path),
                "size_bytes": file_path.stat().st_size,
            }
        return {
            "success": True, "status": "partial",
            "path": str(file_path),
            "reason": f"HTTP {e.code}: {e.reason}",
        }
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {
            "success": True, "status": "partial",
            "path": str(file_path),
            "reason": f"{type(e).__name__}: {e}",
        }
    except Exception as e:  # noqa: BLE001
        return {
            "success": False, "status": "error",
            "path": str(file_path),
            "reason": f"{type(e).__name__}: {e}",
        }
