"""iter-23.1 — `fingerprint_services_nmap` subprocess wrapper.

Runs `nmap -sV` (service-version detection) against a host or CIDR and
parses the XML output (`-oX -`) into structured per-port records.

Service versions feed straight into the KG `Service` node — L2
hypothesis formation uses these to look up CVEs (e.g. ``Postgres 13.2``
→ CVE-2023-39418).

Recall safety: `status=partial` when binary missing.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess  # noqa: S404
import xml.etree.ElementTree as ET  # noqa: S405 — parsing our own subprocess
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_NMAP_BIN = "nmap"
_DEFAULT_TIMEOUT_SECONDS = 300


def _nmap_available() -> bool:
    if os.environ.get(
        "STRIX_NMAP_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_NMAP_BIN) is not None


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1046"],  # Network Service Discovery
)
def fingerprint_services_nmap(
    target: str,
    top_ports: int = 100,
    aggressive: bool = False,
) -> dict[str, Any]:
    """Service/version fingerprinting via ``nmap -sV``.

    Args:
        target: host (``example.com``) or CIDR (``10.0.0.0/24``).
        top_ports: scan only nmap's top-N most-common ports (default
            100 — fast). Set to 0 to scan all 65535 (slow).
        aggressive: when True, also passes ``-A`` to enable OS
            fingerprinting + traceroute + default scripts (much slower
            but richer; requires raw-socket capability).

    Returns:
        ```
        {success, status, target, total_open_ports: int,
         services: [{host, port, proto, service, product?, version?,
                     extrainfo?}, ...], reason?}
        ```
    """
    if not target or not target.strip():
        return {
            "success": False, "status": "error", "target": target,
            "total_open_ports": 0, "services": [],
            "reason": "target required",
        }
    if not _nmap_available():
        return {
            "success": True, "status": "partial", "target": target,
            "total_open_ports": 0, "services": [],
            "reason": (
                "nmap binary not on PATH (or STRIX_NMAP_DISABLED=1). "
                "Install via apt: `apt-get install nmap`."
            ),
        }

    cmd = [_NMAP_BIN, "-sV", "-oX", "-", "-Pn"]
    if top_ports > 0:
        cmd.extend(["--top-ports", str(top_ports)])
    if aggressive:
        cmd.append("-A")
    cmd.append(target.strip())

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error", "target": target,
            "total_open_ports": 0, "services": [],
            "reason": f"nmap invocation failed: {type(e).__name__}: {e}",
        }

    services: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(result.stdout or "<nmaprun/>")  # noqa: S314
    except ET.ParseError as e:
        return {
            "success": False, "status": "error", "target": target,
            "total_open_ports": 0, "services": [],
            "reason": f"nmap XML parse failed: {e}",
        }

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        host_addr = addr_el.get("addr") if addr_el is not None else ""
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            entry: dict[str, Any] = {
                "host": host_addr,
                "port": int(port_el.get("portid") or 0),
                "proto": port_el.get("protocol") or "tcp",
                "service": svc_el.get("name") if svc_el is not None else "",
            }
            if svc_el is not None:
                if svc_el.get("product"):
                    entry["product"] = svc_el.get("product")
                if svc_el.get("version"):
                    entry["version"] = svc_el.get("version")
                if svc_el.get("extrainfo"):
                    entry["extrainfo"] = svc_el.get("extrainfo")
            services.append(entry)

    return {
        "success": True,
        "status": "ok",
        "target": target,
        "total_open_ports": len(services),
        "services": services,
    }
