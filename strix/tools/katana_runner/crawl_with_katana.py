"""iter-22.1 — `crawl_with_katana` subprocess wrapper.

Katana is ProjectDiscovery's Go-based JS-aware crawler. Compared
to strix's in-house `bfs_crawl` (single-threaded Python):

  * JS rendering (`-headless`) catches SPA-routed endpoints
  * Concurrent goroutines — 50-100x faster on large surfaces
  * Built-in form parsing + JS-link extraction
  * Output is one URL per line (jsonl with `-j`)

Returns the discovered endpoint list as strix's canonical
`endpoints=[{url, method, params}, ...]` shape so downstream
`replay_mutation(source="endpoints", ...)` / phase-2 specialists
can consume it directly.

Recall safety: `status=partial` when binary missing.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_KATANA_BIN = "katana"
_DEFAULT_TIMEOUT_SECONDS = 180


def _katana_available() -> bool:
    if os.environ.get(
        "STRIX_KATANA_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_KATANA_BIN) is not None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1595.002"],  # Vulnerability Scanning: Active Scanning
)
def crawl_with_katana(
    target_url: str,
    max_depth: int = 3,
    headless: bool = False,
    max_pages: int = 200,
) -> dict[str, Any]:
    """Katana-driven crawl of a target URL.

    Args:
        target_url: starting URL.
        max_depth: BFS depth cap (default 3).
        headless: when True, runs Chromium-driven crawl to catch
            JS-routed endpoints (SPAs). Slower (~30-60s vs 5-10s)
            but covers Angular / React / Vue routing.
        max_pages: cap on result count.

    Returns:
        ```
        {success, status, target, endpoints_discovered: int,
         endpoints: [{url, method, params}, ...], reason?}
        ```
    """
    if not target_url or not target_url.strip():
        return {
            "success": False, "status": "error", "target": target_url,
            "endpoints_discovered": 0, "endpoints": [],
            "reason": "target_url required",
        }
    if not _katana_available():
        return {
            "success": True, "status": "partial", "target": target_url,
            "endpoints_discovered": 0, "endpoints": [],
            "reason": (
                "katana binary not on PATH (or STRIX_KATANA_DISABLED=1). "
                "Install via go: `go install github.com/projectdiscovery"
                "/katana/cmd/katana@latest`."
            ),
        }

    cmd = [
        _KATANA_BIN,
        "-u", target_url.strip(),
        "-jsonl",
        "-depth", str(max_depth),
        "-silent",
    ]
    if headless:
        cmd.extend(["-headless", "-no-sandbox"])

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error", "target": target_url,
            "endpoints_discovered": 0, "endpoints": [],
            "reason": f"katana invocation failed: {type(e).__name__}: {e}",
        }

    endpoints: list[dict[str, Any]] = []
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
        # Katana jsonl shape: {"timestamp", "request": {"endpoint",
        # "method", ...}, ...}
        req = rec.get("request") or {}
        url = req.get("endpoint") or rec.get("endpoint") or rec.get("url")
        if not url or not isinstance(url, str) or url in seen:
            continue
        seen.add(url)
        method = (req.get("method") or "GET").upper()
        # Extract query params for downstream replay_mutation
        params: list[str] = []
        try:
            qs = urlparse(url).query
            if qs:
                from urllib.parse import parse_qs
                params = list(parse_qs(qs).keys())
        except Exception:  # noqa: BLE001
            pass
        endpoints.append({
            "url": url,
            "method": method,
            "params": params,
        })
        if len(endpoints) >= max_pages:
            break

    return {
        "success": True,
        "status": "ok",
        "target": target_url,
        "endpoints_discovered": len(endpoints),
        "endpoints": endpoints,
    }
