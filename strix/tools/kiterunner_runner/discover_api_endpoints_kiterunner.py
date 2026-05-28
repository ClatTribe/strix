"""iter-Q5.49 — `discover_api_endpoints_kiterunner` subprocess wrapper.

Assetnote's kiterunner (`kr`) brute-forces API routes using a curated
50k-route wordlist (`routes-large.kite`) optimised for modern API
shapes (REST + GraphQL + RPC) including OpenAPI-style verbs. Triages
candidate hits by Content-Length / response-shape signals so hits are
high-precision.

Why kiterunner over ffuf for APIs
---------------------------------

ffuf is content-discovery for unknown files (`/admin`, `/.env`).
kiterunner is API-route discovery — its wordlist contains
`/api/v1/users/{id}/profile` style routes, not file extensions. For
API targets, kiterunner finds endpoints ffuf misses (and vice-versa
for static-file paths).

Recall safety: `status=partial` when the binary is missing.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from typing import Any


logger = logging.getLogger(__name__)


_KR_BIN = "kr"
_DEFAULT_TIMEOUT_SECONDS = 600
_DEFAULT_WORDLIST = "/opt/kiterunner/wordlists/routes-large.kite"


def _kiterunner_available() -> bool:
    if os.environ.get(
        "STRIX_KITERUNNER_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_KR_BIN) is not None


from strix.tools.registry import register_tool  # noqa: E402


@register_tool(
    sandbox_execution=True,
    # T1595.003 Active Scanning: Wordlist Scanning.
    mitre_techniques=["T1595.003"],
)
def discover_api_endpoints_kiterunner(
    target_url: str,
    wordlist_path: str | None = None,
    max_endpoints: int = 500,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Brute-force API routes via kiterunner.

    Args:
        target_url: API base URL (e.g. ``https://api.example.com``).
            Scheme required. Required.
        wordlist_path: path to a `.kite` wordlist file. Defaults to
            ``/opt/kiterunner/wordlists/routes-large.kite`` (baked
            into the sandbox image). Env override:
            ``STRIX_KITERUNNER_WORDLIST``.
        max_endpoints: cap on returned endpoint count.
        timeout_seconds: kiterunner timeout. Default 600s.

    Returns:
        ```
        {success, status, target_url, total_found: int,
         endpoints: [{url, method, status_code, content_length},
                     ...], reason?}
        ```
    """
    if not isinstance(target_url, str) or not target_url.strip():
        return {
            "success": False, "status": "error",
            "target_url": target_url, "total_found": 0,
            "endpoints": [], "reason": "target_url required",
        }
    if not _kiterunner_available():
        return {
            "success": True, "status": "partial",
            "target_url": target_url, "total_found": 0,
            "endpoints": [],
            "reason": (
                "kiterunner (kr) binary not on PATH (or "
                "STRIX_KITERUNNER_DISABLED=1). Install via "
                "`go install github.com/assetnote/kiterunner/cmd/kr@latest`."
            ),
        }

    wl = (wordlist_path
          or os.environ.get("STRIX_KITERUNNER_WORDLIST", "").strip()
          or _DEFAULT_WORDLIST)

    cmd = [
        _KR_BIN, "scan", target_url.strip(),
        "-w", wl,
        "-o", "json",
        "-q",
    ]

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=timeout_seconds, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error",
            "target_url": target_url, "total_found": 0,
            "endpoints": [],
            "reason": f"kiterunner invocation failed: {type(e).__name__}: {e}",
        }

    endpoints: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
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
        # kiterunner JSON shape carries fields like:
        # {"url":"...", "method":"GET", "status_code":200, "content_length":1234}
        url = rec.get("url") or rec.get("uri")
        method = (rec.get("method") or "GET").upper()
        if not isinstance(url, str) or not url:
            continue
        key = (url, method)
        if key in seen:
            continue
        seen.add(key)
        endpoints.append({
            "url": url,
            "method": method,
            "status_code": rec.get("status_code") or rec.get("status"),
            "content_length": rec.get("content_length") or rec.get("length"),
        })
        if len(endpoints) >= max_endpoints:
            break

    return {
        "success": True,
        "status": "ok",
        "target_url": target_url,
        "total_found": len(endpoints),
        "endpoints": endpoints,
    }
