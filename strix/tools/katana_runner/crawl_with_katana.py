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
    headless: bool = True,
    max_pages: int = 200,
    js_crawl: bool = True,
    extract_forms: bool = True,
) -> dict[str, Any]:
    """Katana-driven crawl of a target URL.

    Args:
        target_url: starting URL.
        max_depth: BFS depth cap (default 3).
        headless: when True (default — iter-28.3), runs Chromium-driven
            crawl to catch JS-routed endpoints (SPAs). Slower (~30-60s
            vs 5-10s) but covers Angular / React / Vue routing.
            Disabling this regresses SPA coverage hard — only set
            False for known server-rendered targets.
        max_pages: cap on result count.
        js_crawl: when True (default — iter-28.3), runs `-jc -jsluice`
            so katana parses JS bundles for endpoint references. SPA
            apps stash their API routes in bundled JS; without this,
            those routes are invisible.
        extract_forms: when True (default — iter-28.3), runs `-fx` to
            emit form/input/textarea/select elements alongside endpoints.
            Surfaces in result["forms"] for downstream auth-seed +
            form-aware scan_sqli/xss probes.

    Returns:
        ```
        {
          success, status, target, endpoints_discovered: int,
          endpoints: [{url, method, params}, ...],
          forms: [{action, method, inputs: [{name, type}, ...]}, ...],
          reason?,
        }
        ```

    iter-28.3 — flipped headless / js-crawl / form-extraction defaults
    from off-by-default to on-by-default. Rationale: the L2 Juice Shop
    full-challenge bench (3/109) confirmed that the old defaults left
    SPA routes (which is most modern webapps) undiscovered. The L1
    floor for any auth-bearing or SPA-shaped target jumps materially
    once we see the real surface. Validated via
    `bench_validate_change.py` across ≥3 fixtures before merge.
    """
    if not target_url or not target_url.strip():
        return {
            "success": False, "status": "error", "target": target_url,
            "endpoints_discovered": 0, "endpoints": [], "forms": [],
            "reason": "target_url required",
        }
    if not _katana_available():
        return {
            "success": True, "status": "partial", "target": target_url,
            "endpoints_discovered": 0, "endpoints": [], "forms": [],
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
    if js_crawl:
        # -jc: parse JS files for endpoints.
        # -jsl: jsluice (memory-intensive but finds endpoints baked
        #       into bundled webpack/rollup output).
        cmd.extend(["-jc", "-jsl"])
    if extract_forms:
        cmd.append("-fx")

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
    forms: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_forms: set[tuple[str, str]] = set()  # (action, method)

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
        # "method", ...}, "response": {...}, "forms": [...]?}
        req = rec.get("request") or {}
        url = req.get("endpoint") or rec.get("endpoint") or rec.get("url")
        if not url or not isinstance(url, str):
            continue

        # ---- iter-28.3: extract forms from `-fx` output ----
        # Katana emits forms inline within the response/request record
        # under keys `forms` or `form`. Each form: {action, method,
        # enctype, parameters: [{name, type, value}, ...]}.
        rec_forms = rec.get("forms") or rec.get("form") or []
        if isinstance(rec_forms, dict):
            rec_forms = [rec_forms]
        for f in rec_forms or []:
            if not isinstance(f, dict):
                continue
            action = str(f.get("action") or url).strip()
            fmethod = str(f.get("method") or "POST").upper()
            inputs: list[dict[str, str]] = []
            for p in (f.get("parameters") or f.get("inputs") or []) or []:
                if not isinstance(p, dict):
                    continue
                inputs.append({
                    "name": str(p.get("name") or "").strip(),
                    "type": str(p.get("type") or "text").lower(),
                })
            key = (action, fmethod)
            if key in seen_forms:
                continue
            seen_forms.add(key)
            forms.append({
                "action": action, "method": fmethod, "inputs": inputs,
            })

        if url in seen:
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

    # iter-32.1 — route each katana-discovered endpoint through
    # workflow_state so iter-31.9 surface_discovery_breadth has a
    # numerator when only L2 (no L1 prepass) ran. Best-effort: failures
    # log + skip; never breaks the tool's return path.
    try:
        from strix.agents.workflow_state import record_endpoint_discovered
        for ep in endpoints:
            record_endpoint_discovered(ep["url"])
    except Exception:  # noqa: BLE001
        pass

    return {
        "success": True,
        "status": "ok",
        "target": target_url,
        "endpoints_discovered": len(endpoints),
        "endpoints": endpoints,
        "forms": forms,
        "forms_discovered": len(forms),
    }
