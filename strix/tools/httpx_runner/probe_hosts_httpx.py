"""iter-23.1 — `probe_hosts_httpx` subprocess wrapper.

httpx is ProjectDiscovery's Go-based concurrent HTTP prober. Given a
list of hosts, it returns status codes, technology fingerprints (via
`-tech-detect`), TLS info, content length, and title — letting us
prune dead subdomains before they are fed to expensive L2 planning.

Pairs naturally with `enumerate_subdomains_subfinder` output.

Recall safety: `status=partial` when binary missing.
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


_HTTPX_BIN = "httpx"
_DEFAULT_TIMEOUT_SECONDS = 180


def _httpx_available() -> bool:
    if os.environ.get(
        "STRIX_HTTPX_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_HTTPX_BIN) is not None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1595.002"],  # Vulnerability Scanning: Active Scanning
)
def probe_hosts_httpx(
    hosts: list[str] | str,
    detect_tech: bool = True,
    follow_redirects: bool = True,
    max_results: int = 500,
) -> dict[str, Any]:
    """HTTP-probe a list of hosts; return reachable ones with metadata.

    Args:
        hosts: list of hostnames/URLs, OR a single newline-separated
            string. Hosts may be bare (``example.com``) — httpx
            auto-detects scheme on probe.
        detect_tech: pass ``-tech-detect`` for Wappalyzer-style
            tech fingerprinting (Apache, nginx, Rails, etc.).
        follow_redirects: pass ``-follow-redirects`` for chained
            response codes.
        max_results: cap on returned probes.

    Returns:
        ```
        {success, status, total_probed: int, live_hosts: int,
         probes: [{url, status_code, title?, tech?, content_length?,
                    webserver?}, ...], reason?}
        ```
    """
    if isinstance(hosts, str):
        hosts_list = [h.strip() for h in hosts.splitlines() if h.strip()]
    else:
        hosts_list = [h.strip() for h in (hosts or []) if h and h.strip()]

    if not hosts_list:
        return {
            "success": False, "status": "error",
            "total_probed": 0, "live_hosts": 0, "probes": [],
            "reason": "hosts required",
        }

    if not _httpx_available():
        return {
            "success": True, "status": "partial",
            "total_probed": len(hosts_list), "live_hosts": 0, "probes": [],
            "reason": (
                "httpx binary not on PATH (or STRIX_HTTPX_DISABLED=1). "
                "Install via `go install github.com/projectdiscovery"
                "/httpx/cmd/httpx@latest`."
            ),
        }

    stdin_payload = "\n".join(hosts_list)
    cmd = [
        _HTTPX_BIN,
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-content-length",
        "-web-server",
    ]
    if detect_tech:
        cmd.append("-tech-detect")
    if follow_redirects:
        cmd.append("-follow-redirects")

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, input=stdin_payload, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error",
            "total_probed": len(hosts_list), "live_hosts": 0, "probes": [],
            "reason": f"httpx invocation failed: {type(e).__name__}: {e}",
        }

    probes: list[dict[str, Any]] = []
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
        url = rec.get("url") or rec.get("input")
        if not url or not isinstance(url, str):
            continue
        probe: dict[str, Any] = {
            "url": url,
            "status_code": rec.get("status_code") or rec.get("status-code"),
        }
        title = rec.get("title")
        if title:
            probe["title"] = title
        tech = rec.get("tech") or rec.get("technologies")
        if tech:
            probe["tech"] = tech if isinstance(tech, list) else [str(tech)]
        cl = rec.get("content_length") or rec.get("content-length")
        if cl is not None:
            probe["content_length"] = cl
        ws = rec.get("webserver") or rec.get("web-server")
        if ws:
            probe["webserver"] = ws
        probes.append(probe)
        if len(probes) >= max_results:
            break

    return {
        "success": True,
        "status": "ok",
        "total_probed": len(hosts_list),
        "live_hosts": len(probes),
        "probes": probes,
    }
