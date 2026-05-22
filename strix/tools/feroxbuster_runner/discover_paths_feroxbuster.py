"""iter-23.3 — `discover_paths_feroxbuster` subprocess wrapper.

feroxbuster is the Rust-based recursive content discovery tool from
epi052/feroxbuster. Compared to ffuf or dirsearch:

  * Rust concurrency — ~200 req/s on a 1 Gbps link
  * Recursive directory descent (auto-follows discovered dirs)
  * `--auto-tune` to back off on WAF/server overload
  * NDJSON output with status_code + content_length + word_count

Used at L1 to flesh out an asset's path surface after subfinder/httpx
have found the live hostname. Output feeds into the KG `Surface` node
list so replay_mutation / phase-2 specialists can target each path.

Recall safety: ``status=partial`` when binary missing.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_FEROX_BIN = "feroxbuster"
_DEFAULT_TIMEOUT_SECONDS = 240


def _ferox_available() -> bool:
    if os.environ.get(
        "STRIX_FEROXBUSTER_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_FEROX_BIN) is not None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1595.003"],  # Active Scanning: Wordlist Scanning
)
def discover_paths_feroxbuster(
    target_url: str,
    wordlist: str | None = None,
    depth: int = 2,
    threads: int = 50,
    max_results: int = 500,
) -> dict[str, Any]:
    """Recursive path discovery via feroxbuster.

    Args:
        target_url: starting URL.
        wordlist: path to a wordlist file. Defaults to ``None`` which
            lets feroxbuster pick its bundled default (raft-medium).
        depth: recursion depth cap (default 2).
        threads: concurrent worker count.
        max_results: cap on returned paths.

    Returns:
        ```
        {success, status, target, total_found: int,
         paths: [{url, status_code, content_length, word_count?}, ...],
         reason?}
        ```
    """
    if not target_url or not target_url.strip():
        return {
            "success": False, "status": "error", "target": target_url,
            "total_found": 0, "paths": [],
            "reason": "target_url required",
        }
    if not _ferox_available():
        return {
            "success": True, "status": "partial", "target": target_url,
            "total_found": 0, "paths": [],
            "reason": (
                "feroxbuster binary not on PATH (or "
                "STRIX_FEROXBUSTER_DISABLED=1). Install via "
                "release tarball from "
                "https://github.com/epi052/feroxbuster/releases."
            ),
        }

    cmd: list[str] = [
        _FEROX_BIN,
        "--url", target_url.strip(),
        "--depth", str(max(1, depth)),
        "--threads", str(max(1, threads)),
        "--json",          # NDJSON output to stdout
        "--silent",        # suppress banner
        "--no-state",      # don't litter cwd with .state
        "--auto-tune",     # back off if server saturates
    ]
    if wordlist:
        cmd.extend(["--wordlist", wordlist])

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error", "target": target_url,
            "total_found": 0, "paths": [],
            "reason": f"feroxbuster invocation failed: {type(e).__name__}: {e}",
        }

    paths: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(rec, dict):
            continue
        # feroxbuster NDJSON: {"type": "response", "url": ..., "status": 200,
        #                      "content_length": 1234, "word_count": 50}
        if rec.get("type") not in {"response", None}:
            continue
        url = rec.get("url") or rec.get("URL")
        if not url or not isinstance(url, str) or url in seen:
            continue
        seen.add(url)
        entry: dict[str, Any] = {
            "url": url,
            "status_code": rec.get("status") or rec.get("status_code"),
            "content_length": rec.get("content_length"),
        }
        if rec.get("word_count") is not None:
            entry["word_count"] = rec.get("word_count")
        paths.append(entry)
        if len(paths) >= max_results:
            break

    return {
        "success": True,
        "status": "ok",
        "target": target_url,
        "total_found": len(paths),
        "paths": paths,
    }
