"""iter-Q5.50 — `fingerprint_services_masscan` subprocess wrapper.

Masscan is the world's fastest port scanner — scans the entire IPv4
internet in ~6 minutes. For a single IP, completes a 65k-port sweep
in <1s where nmap takes 30+ seconds. Ships in parallel to nmap under
_ANCHORS_IP as a fast first-pass; nmap then does deeper
service-version probing on the discovered open ports.

Architecture: subprocess wrapper. Output parsed via `-oJ -` JSON
streaming mode. Recall safety: `status=partial` when the binary is
missing.

Defaults: rate-limited to 1000 pkt/s and top-1000 ports by default
to keep the scan polite. Operators override via kwargs / env for
internal lab use.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from typing import Any


logger = logging.getLogger(__name__)


_MASSCAN_BIN = "masscan"
_DEFAULT_TIMEOUT_SECONDS = 300
_DEFAULT_RATE = 1000           # packets/sec — polite default
_DEFAULT_TOP_PORTS = 1000


def _masscan_available() -> bool:
    if os.environ.get(
        "STRIX_MASSCAN_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_MASSCAN_BIN) is not None


from strix.tools.registry import register_tool  # noqa: E402


@register_tool(
    sandbox_execution=True,
    # T1046 Network Service Discovery.
    mitre_techniques=["T1046"],
)
def fingerprint_services_masscan(
    target: str,
    ports: str | None = None,
    rate: int = _DEFAULT_RATE,
    top_ports: int = _DEFAULT_TOP_PORTS,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Fast port discovery via masscan.

    Args:
        target: IP literal or CIDR (e.g. ``10.0.0.1``,
            ``10.0.0.0/24``). Required.
        ports: explicit port range (e.g. ``"22,80,443,8000-8100"``).
            When set, overrides ``top_ports``. Env override:
            ``STRIX_MASSCAN_PORTS``.
        rate: packets per second. Default 1000 — polite. Operators
            increase to 10000+ for internal lab use. Env override:
            ``STRIX_MASSCAN_RATE``.
        top_ports: scan top-N TCP ports when ``ports`` is not set.
            Default 1000. masscan emits this as ``-p0-65535``
            filtered against its top-port list.
        timeout_seconds: masscan timeout. Default 300s.

    Returns:
        ```
        {success, status, target, total_found: int,
         open_ports: [{port: int, protocol: str, banner: str | None},
                      ...], reason?}
        ```
    """
    if not isinstance(target, str) or not target.strip():
        return {
            "success": False, "status": "error",
            "target": target, "total_found": 0,
            "open_ports": [], "reason": "target required",
        }
    if not _masscan_available():
        return {
            "success": True, "status": "partial",
            "target": target, "total_found": 0,
            "open_ports": [],
            "reason": (
                "masscan binary not on PATH (or STRIX_MASSCAN_DISABLED=1). "
                "Install via `apt install masscan` or build from "
                "https://github.com/robertdavidgraham/masscan."
            ),
        }

    # Env overrides for ports + rate.
    ports = ports or os.environ.get("STRIX_MASSCAN_PORTS", "").strip() or None
    env_rate = os.environ.get("STRIX_MASSCAN_RATE", "").strip()
    if env_rate:
        try:
            rate = int(env_rate)
        except (TypeError, ValueError):
            pass

    cmd = [
        _MASSCAN_BIN, target.strip(),
        "-oJ", "-",
        "--rate", str(rate),
    ]
    if ports:
        cmd += ["-p", ports]
    else:
        # Top-N TCP via the canonical "top ports" shortcut.
        cmd += ["--top-ports", str(top_ports)]

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=timeout_seconds, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error",
            "target": target, "total_found": 0,
            "open_ports": [],
            "reason": f"masscan invocation failed: {type(e).__name__}: {e}",
        }

    # masscan JSON shape: one JSON array prefixed by a "finished" line.
    # Robust parser: try the full body as JSON; on failure, parse
    # line-by-line skipping comment headers.
    stdout = result.stdout or ""
    open_ports: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()

    parsed_any = False
    try:
        records = json.loads(stdout)
        if isinstance(records, list):
            parsed_any = True
            for rec in records:
                _absorb_record(rec, open_ports, seen)
    except (ValueError, TypeError):
        pass

    if not parsed_any:
        for line in stdout.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]") or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
            except (ValueError, TypeError):
                continue
            _absorb_record(rec, open_ports, seen)

    return {
        "success": True,
        "status": "ok",
        "target": target,
        "total_found": len(open_ports),
        "open_ports": open_ports,
    }


def _absorb_record(
    rec: Any,
    open_ports: list[dict[str, Any]],
    seen: set[tuple[int, str]],
) -> None:
    if not isinstance(rec, dict):
        return
    # masscan -oJ shape: {ip, ports: [{port, proto, status, ...}], ...}
    ports_block = rec.get("ports")
    if not isinstance(ports_block, list):
        return
    for p in ports_block:
        if not isinstance(p, dict):
            continue
        try:
            port_num = int(p.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if port_num <= 0:
            continue
        proto = str(p.get("proto") or "tcp").lower()
        key = (port_num, proto)
        if key in seen:
            continue
        seen.add(key)
        # Banner data only present in --banners runs.
        banner = None
        svc = p.get("service")
        if isinstance(svc, dict):
            banner = svc.get("banner")
        open_ports.append({
            "port": port_num,
            "protocol": proto,
            "banner": banner,
        })
