"""iter-Q5.51 — `grab_banner_zgrab2` subprocess wrapper.

ZGrab2 (ZMap project, University of Michigan) is the standard
application-layer banner grabber paired with masscan. Probes specific
protocols on specific ports and emits structured JSON banners.

Why ZGrab2 in addition to nmap -sV
----------------------------------

* **Faster** for known protocols on known ports — single round-trip,
  no fingerprint matching DB lookup.
* **Structured output** — JSON per protocol module (http, ssh,
  modbus, smtp, …) with full handshake data nmap collapses.
* **Internet-scale** — designed for the ZMap+masscan pipeline; works
  cleanly with very large IP lists.

Feeds:
  * SecurityContext.tech_stack — server / version strings from HTTP
    banners drive subsequent CVE-template selection (nuclei + grype).
  * Service-version CVE lookup at the L1.5 enrichment hook.

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


_ZGRAB_BIN = "zgrab2"
_DEFAULT_TIMEOUT_SECONDS = 180
_VALID_MODULES = {
    "http", "ssh", "tls", "ftp", "smtp", "imap", "pop3",
    "mysql", "postgres", "redis", "telnet", "modbus", "ntp",
    "dnp3", "fox", "siemens", "smb", "mssql", "oracle",
}


def _zgrab_available() -> bool:
    if os.environ.get(
        "STRIX_ZGRAB_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_ZGRAB_BIN) is not None


from strix.tools.registry import register_tool  # noqa: E402


@register_tool(
    sandbox_execution=True,
    # T1592.002 Gather Victim Host Information: Software.
    mitre_techniques=["T1592.002"],
)
def grab_banner_zgrab2(
    target: str,
    module: str = "http",
    port: int | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Grab a service banner via ZGrab2.

    Args:
        target: IP literal or hostname. Required.
        module: protocol module — ``http`` (default), ``ssh``, ``tls``,
            ``ftp``, ``smtp``, etc. See ``_VALID_MODULES``.
        port: TCP port. When None, uses the module's default
            (``http`` → 80, ``ssh`` → 22, …).
        timeout_seconds: zgrab2 timeout. Default 180s.

    Returns:
        ```
        {success, status, target, module, port, banner: dict | None,
         reason?}
        ```

    `banner` is the parsed JSON record zgrab2 emits — module-specific
    shape (HTTP carries headers + status_line, SSH carries kex +
    server_id, etc.).
    """
    if not isinstance(target, str) or not target.strip():
        return {
            "success": False, "status": "error",
            "target": target, "module": module, "port": port,
            "banner": None, "reason": "target required",
        }
    mod = module.strip().lower()
    if mod not in _VALID_MODULES:
        return {
            "success": False, "status": "error",
            "target": target, "module": module, "port": port,
            "banner": None,
            "reason": f"unsupported module {module!r}; valid: {sorted(_VALID_MODULES)}",
        }
    if not _zgrab_available():
        return {
            "success": True, "status": "partial",
            "target": target, "module": module, "port": port,
            "banner": None,
            "reason": (
                "zgrab2 binary not on PATH (or STRIX_ZGRAB_DISABLED=1). "
                "Install via `go install github.com/zmap/zgrab2/cmd"
                "/zgrab2@latest`."
            ),
        }

    # ZGrab2 takes the target on stdin (one host per line).
    cmd = [_ZGRAB_BIN, mod]
    if port:
        cmd += ["--port", str(port)]

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=timeout_seconds, text=True,
            input=f"{target.strip()}\n",
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error",
            "target": target, "module": module, "port": port,
            "banner": None,
            "reason": f"zgrab2 invocation failed: {type(e).__name__}: {e}",
        }

    stdout = (result.stdout or "").strip()
    if not stdout:
        return {
            "success": False, "status": "error",
            "target": target, "module": module, "port": port,
            "banner": None,
            "reason": f"zgrab2 produced no output; stderr={(result.stderr or '').strip()[:200]}",
        }

    # ZGrab2 emits one JSON record per line.
    banner: dict[str, Any] | None = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(rec, dict):
            banner = rec
            break

    if banner is None:
        return {
            "success": False, "status": "error",
            "target": target, "module": module, "port": port,
            "banner": None,
            "reason": "zgrab2 output had no parseable JSON record",
        }

    return {
        "success": True,
        "status": "ok",
        "target": target,
        "module": mod,
        "port": port,
        "banner": banner,
    }
