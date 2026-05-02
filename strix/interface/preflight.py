"""Preflight reachability check for network targets.

Roadmap §3 + §7. Before spawning the agent loop (which warms up the LLM,
pulls the Docker image, and runs for many minutes), do a fast host-side
sanity check: does the target resolve, and does at least one common
port answer?

The worst-feeling failure mode is a 10-minute scan that finds nothing
because the target was offline. Preflight collapses that to a 5-second
DNS-and-TCP probe with a clear diagnostic.

Behaviour:
- Network targets (`web_application`, `ip_address`) are probed.
- Code targets (`repository`, `local_code`) are skipped.
- Per-target budget: ~7s worst case (DNS + 1-2 TCP probes).
- Result classes:
  - `reachable` — DNS resolved and at least one TCP probe got a response.
  - `dns_failed` — host did not resolve.
  - `no_open_ports` — host resolved but every probed port refused / timed out.
  - `skipped` — target type is non-network.

Used by `main.py` to fail-fast when *all* network targets are
unreachable, and to warn-and-continue when *some* are.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)

_DEFAULT_DNS_TIMEOUT = 3.0
_DEFAULT_TCP_TIMEOUT = 4.0

# Ports probed per target type. Order matters: first-success wins, so put
# the most-likely-open port first.
_PROBE_PORTS_WEB: tuple[int, ...] = (443, 80)
_PROBE_PORTS_IP: tuple[int, ...] = (443, 80, 22, 25)


@dataclass
class PreflightResult:
    target: str
    target_type: str
    status: str  # "reachable" | "dns_failed" | "no_open_ports" | "skipped"
    resolved_ips: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in ("reachable", "skipped")


def _extract_host(target_info: dict[str, Any]) -> str | None:
    """Pull the hostname or IP out of a `target_info` dict."""
    target_type = target_info.get("type")
    details = target_info.get("details") or {}

    if target_type == "web_application":
        url = details.get("target_url") or target_info.get("original")
        if not url:
            return None
        parsed = urlparse(url if "://" in url else f"https://{url}")
        return parsed.hostname
    if target_type == "ip_address":
        return details.get("target_ip") or target_info.get("original")
    return None


def _resolve_host(host: str, *, timeout: float) -> list[str]:
    """Resolve `host` to a list of distinct IPs. Returns [] on failure."""
    # IP addresses are their own resolution.
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass

    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as e:
        logger.debug("preflight DNS lookup failed for %s: %s", host, e)
        return []
    finally:
        socket.setdefaulttimeout(None)

    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def _tcp_probe(host: str, port: int, *, timeout: float) -> bool:
    """Open a TCP connection to host:port. Returns True if it accepted."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, OSError):
        return False


def preflight_check_target(
    target_info: dict[str, Any],
    *,
    dns_timeout: float = _DEFAULT_DNS_TIMEOUT,
    tcp_timeout: float = _DEFAULT_TCP_TIMEOUT,
) -> PreflightResult:
    """Check reachability for a single target."""
    target_type = target_info.get("type", "")
    original = target_info.get("original") or ""

    if target_type not in ("web_application", "ip_address"):
        return PreflightResult(target=original, target_type=target_type, status="skipped")

    host = _extract_host(target_info)
    if not host:
        return PreflightResult(
            target=original,
            target_type=target_type,
            status="dns_failed",
            error="could not extract host from target",
        )

    ips = _resolve_host(host, timeout=dns_timeout)
    if not ips:
        return PreflightResult(
            target=original,
            target_type=target_type,
            status="dns_failed",
            error=f"DNS lookup failed for {host}",
        )

    ports = _PROBE_PORTS_IP if target_type == "ip_address" else _PROBE_PORTS_WEB
    open_ports: list[int] = []
    # Probe against the first resolved IP (most TCP probes resolving multiple
    # answers don't add useful coverage; modern hosts answer all of them
    # the same way). Ports are tried in order; we stop at the first OK.
    probe_target = ips[0]
    for port in ports:
        if _tcp_probe(probe_target, port, timeout=tcp_timeout):
            open_ports.append(port)
            break

    if not open_ports:
        return PreflightResult(
            target=original,
            target_type=target_type,
            status="no_open_ports",
            resolved_ips=ips,
            error=f"no response on ports {','.join(str(p) for p in ports)}",
        )

    return PreflightResult(
        target=original,
        target_type=target_type,
        status="reachable",
        resolved_ips=ips,
        open_ports=open_ports,
    )


def preflight_check_targets(
    targets_info: list[dict[str, Any]],
    *,
    dns_timeout: float = _DEFAULT_DNS_TIMEOUT,
    tcp_timeout: float = _DEFAULT_TCP_TIMEOUT,
) -> list[PreflightResult]:
    """Check reachability for every target in `targets_info`.

    Sequential probing — multi-target scans are rare in practice and the
    saved-time-from-parallelism is small relative to the total scan
    duration.
    """
    return [
        preflight_check_target(t, dns_timeout=dns_timeout, tcp_timeout=tcp_timeout)
        for t in targets_info
    ]


def render_preflight_panel(results: list[PreflightResult]) -> str:
    """Render a plain-text summary for the CLI panel.

    UI rendering uses Rich in main.py; this returns the inner text body.
    """
    lines: list[str] = []
    for r in results:
        if r.status == "reachable":
            ips = ",".join(r.resolved_ips[:2])
            ports = ",".join(str(p) for p in r.open_ports)
            lines.append(f"  ✓ {r.target}  (resolved: {ips}; open: {ports})")
        elif r.status == "skipped":
            lines.append(f"  - {r.target}  (skipped — {r.target_type})")
        elif r.status == "dns_failed":
            lines.append(f"  ✗ {r.target}  DNS FAILED — {r.error}")
        elif r.status == "no_open_ports":
            ips = ",".join(r.resolved_ips[:2])
            lines.append(f"  ✗ {r.target}  UNREACHABLE — resolved {ips} but no port answered")
        else:
            lines.append(f"  ? {r.target}  ({r.status})")
    return "\n".join(lines)


def all_network_targets_unreachable(results: list[PreflightResult]) -> bool:
    """True iff every network target is unreachable.

    A scan with zero network targets and only code targets returns False
    (those don't need preflight).
    """
    network_results = [r for r in results if r.status != "skipped"]
    if not network_results:
        return False
    return all(r.status != "reachable" for r in network_results)
