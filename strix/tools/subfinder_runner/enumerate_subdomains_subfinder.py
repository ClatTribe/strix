"""iter-23.1 — `enumerate_subdomains_subfinder` subprocess wrapper.

Subfinder is ProjectDiscovery's Go-based passive subdomain harvester.
Aggregates results across ~30+ passive sources (crt.sh, VirusTotal,
SecurityTrails, RapidDNS, AlienVault, etc.) without active DNS brute
force, making it ASM-friendly (no noisy queries to target authoritative).

Returns the canonical `subdomains=[...]` shape so the downstream
`httpx_probe` tool can chain probes directly off this output.

Recall safety: `status=partial` when binary missing.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from typing import Any


logger = logging.getLogger(__name__)


_SUBFINDER_BIN = "subfinder"
_DEFAULT_TIMEOUT_SECONDS = 180


def _subfinder_available() -> bool:
    if os.environ.get(
        "STRIX_SUBFINDER_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_SUBFINDER_BIN) is not None


from strix.tools.registry import register_tool  # noqa: E402


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1596.001"],  # Search Open Tech Databases: DNS/Passive
)
def enumerate_subdomains_subfinder(
    domain: str,
    max_results: int = 500,
    all_sources: bool = False,
) -> dict[str, Any]:
    """Passive subdomain enumeration via subfinder.

    Args:
        domain: apex domain (e.g. ``example.com``). Must not include
            scheme or path.
        max_results: cap on returned subdomains.
        all_sources: when True, passes ``-all`` to query every available
            source (slower; some sources require API keys to be useful).

    Returns:
        ```
        {success, status, domain, total_found: int,
         subdomains: [str, ...], reason?}
        ```
    """
    if not domain or not domain.strip():
        return {
            "success": False, "status": "error", "domain": domain,
            "total_found": 0, "subdomains": [],
            "reason": "domain required",
        }
    if not _subfinder_available():
        return {
            "success": True, "status": "partial", "domain": domain,
            "total_found": 0, "subdomains": [],
            "reason": (
                "subfinder binary not on PATH (or STRIX_SUBFINDER_DISABLED=1). "
                "Install via `go install github.com/projectdiscovery"
                "/subfinder/v2/cmd/subfinder@latest`."
            ),
        }

    cmd = [
        _SUBFINDER_BIN,
        "-d", domain.strip(),
        "-silent",
        "-json",
    ]
    if all_sources:
        cmd.append("-all")

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error", "domain": domain,
            "total_found": 0, "subdomains": [],
            "reason": f"subfinder invocation failed: {type(e).__name__}: {e}",
        }

    subdomains: list[str] = []
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
        host = rec.get("host") or rec.get("subdomain") or rec.get("input")
        if not host or not isinstance(host, str):
            continue
        host = host.strip().lower()
        if host in seen:
            continue
        seen.add(host)
        subdomains.append(host)
        if len(subdomains) >= max_results:
            break

    return {
        "success": True,
        "status": "ok",
        "domain": domain,
        "total_found": len(subdomains),
        "subdomains": subdomains,
    }
