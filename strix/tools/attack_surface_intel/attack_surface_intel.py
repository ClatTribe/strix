"""Shodan + Censys attack-surface intelligence.

For a domain or IP target, queries Shodan and Censys for the
attacker's-view of the asset's internet exposure. Surfaces:

- **Open ports** that are visible on the public internet — including
  ones the target's own scans wouldn't show (because Shodan / Censys
  scan from outside the customer's network).
- **Service banners + software versions** — Shodan and Censys
  fingerprint the service running on each port. Pairs with
  `cve_lookup` (#61): the agent feeds the detected `(software,
  version)` triple into `cve_lookup` to find known CVEs.
- **Shodan-tagged CVEs** — the Shodan paid plan attaches a `vulns`
  array; we surface those as findings directly.
- **Historical scan timestamps** — `last_update` shows when the host
  was last seen by Shodan / Censys; stale data still useful for
  identifying long-running open services.

Two sources, both opt-in via env vars:

| Source | Auth | API | Free tier |
|---|---|---|---|
| **Shodan** | `STRIX_SHODAN_KEY` | `GET https://api.shodan.io/shodan/host/<ip>?key=...` | 100 queries/month |
| **Censys** | `STRIX_CENSYS_API_ID` + `STRIX_CENSYS_API_SECRET` | `GET https://search.censys.io/api/v2/hosts/<ip>` (Basic auth) | 250 queries/month |

Both sources skipped silently when keys aren't configured (recorded
under `source_errors`). Without any keys the tool is a no-op
(returns success=True with both sources skipped).

Auto-detects whether the target is a domain or IP. For domains,
resolves up to 3 A records and queries each IP through both sources.
URL-shaped input is auto-stripped to hostname. Private / loopback /
link-local IPs rejected.

Findings (severity tuned to attacker-impact, not pure presence):

- **High** (CWE-200, attack_surface_disclosure) — high-risk service
  exposed to the public internet: any of `ssh` / `telnet` / `rdp` /
  `vnc` / `smb` / `rsync` / `ftp` / `mysql` / `postgres` / `mssql` /
  `mongodb` / `redis` / `elasticsearch` / `memcached` / `kibana` /
  `docker-api` / `kubernetes-api` listening on a non-localhost
  interface. These are the highest-value attacker entry points and
  routinely appear in real compromise post-mortems.
- **High** (CWE-1395, vulnerable_software) — Shodan reports a CVE
  tagged on this host (only the paid Shodan plan returns the
  `vulns` array; severity is tagged high regardless because Shodan's
  internal CVE matching is conservative).
- **Medium** (CWE-200) — broad port surface (>10 distinct ports
  exposed) — signals a poorly-segmented host or production server
  doubling as jump-box.
- **Low** (CWE-200) — service banners that disclose specific software
  versions (e.g. `Apache/2.4.49`, `OpenSSH_7.4`) — feed-forward to
  `cve_lookup` rather than acting on directly.

Per-host dedup: at most one finding per (severity × class) per IP so
a host running both ssh and telnet emits ONE high-risk-service
finding listing both, not two.

Cache: per-target JSON cache under `~/.strix/attack_surface_cache/`,
6-hour TTL. Stale cache served on full-source failure (fail-open
with `error` populated). Disable with
`STRIX_ATTACK_SURFACE_NO_CACHE=1`.

Composes with cluster-A safety: rate-limit applies to outbound
requests; `--exclude-path` doesn't apply (URLs are Shodan / Censys,
not the customer's domain).

`verification_status=needs_review` since both sources can carry
stale data (services may have been firewalled / decommissioned since
the last scan).
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "attack_surface_intel"
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_CACHE_TTL_SECONDS = 6 * 3600
_MAX_RESOLVED_IPS = 3
_DNS_TIMEOUT_SECONDS = 4.0
_BROAD_SURFACE_THRESHOLD = 10  # >N distinct ports → medium finding

_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,63})+$"
)


# High-risk service names. Matched case-insensitively against Shodan's
# `product` field, Censys `service_name`, or banner-text substrings.
# When detected on a public IP, emits a high finding regardless of port.
_HIGH_RISK_SERVICES: dict[str, str] = {
    "ssh": "SSH",
    "openssh": "SSH",
    "telnet": "Telnet",
    "rdp": "RDP",
    "ms-wbt-server": "RDP",
    "vnc": "VNC",
    "smb": "SMB",
    "netbios": "SMB",
    "microsoft-ds": "SMB",
    "rsync": "rsync",
    "ftp": "FTP",
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "ms-sql-s": "MSSQL",
    "mssql": "MSSQL",
    "mongodb": "MongoDB",
    "mongo": "MongoDB",
    "redis": "Redis",
    "elasticsearch": "Elasticsearch",
    "memcached": "Memcached",
    "kibana": "Kibana",
    "docker": "Docker API",
    "kubernetes": "Kubernetes API",
    "etcd": "etcd",
}


# Default-port → service hint, used when the source doesn't fingerprint
# the service explicitly. Conservative — only well-known service ports
# that match the high-risk list above.
_PORT_TO_SERVICE: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    873: "rsync",
    1433: "MSSQL",
    2375: "Docker API",
    2376: "Docker API",
    2379: "etcd",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    5901: "VNC",
    5902: "VNC",
    6379: "Redis",
    6443: "Kubernetes API",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB",
    27019: "MongoDB",
}


# ---------------------------------------------------------------------------
# Target classification
# ---------------------------------------------------------------------------


def _classify_target(target: str) -> tuple[str, str]:
    if not target or not isinstance(target, str):
        return ("invalid", "")
    target = target.strip().rstrip(".")
    if not target:
        return ("invalid", "")
    if "://" in target:
        from urllib.parse import urlparse

        parsed = urlparse(target)
        target = parsed.hostname or ""
        if not target:
            return ("invalid", "")
    target = target.lower()
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return ("invalid", "")
        return ("ip", target)
    except ValueError:
        pass
    if len(target) > 253 or not _DOMAIN_RE.match(target):
        return ("invalid", "")
    return ("domain", target)


def _resolve_ips(domain: str, timeout: float = _DNS_TIMEOUT_SECONDS) -> list[str]:
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "A")
        ips: list[str] = []
        for r in answers:
            try:
                ip_str = str(r).strip()
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    continue
                ips.append(ip_str)
                if len(ips) >= _MAX_RESOLVED_IPS:
                    break
            except (ValueError, TypeError):
                continue
        return ips
    except Exception:  # noqa: BLE001
        return []


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_get(
    url: str, *, headers: dict[str, str] | None = None, timeout: float = _DEFAULT_TIMEOUT
) -> dict[str, Any]:
    headers = dict(headers or {})
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, headers=headers, timeout=int(timeout))
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": r.get("body") or "",
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)
    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            throttle_for_rate_limit,
        )

        merged = inject_auth_headers(headers)
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=True) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:512 * 1024],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Source: Shodan
# ---------------------------------------------------------------------------


_SHODAN_API = "https://api.shodan.io/shodan/host"


def _query_shodan(ip: str, key: str, timeout: float) -> dict[str, Any]:
    """Returns {present, ports, services, vulns, last_update, banners, error?}."""
    if not key:
        return {
            "present": False,
            "skipped": True,
            "reason": "no STRIX_SHODAN_KEY — Shodan skipped",
        }
    url = f"{_SHODAN_API}/{ip}?key={key}"
    response = _http_get(url, timeout=timeout)
    if response.get("error"):
        return {"present": False, "error": f"Shodan failed: {response['error']}"}
    if response.get("status", 0) == 404:
        # Host not in Shodan's index — treat as "no data" (clean).
        return {"present": False, "status": 404}
    if response.get("status", 0) == 401:
        return {"present": False, "error": "Shodan returned 401 (invalid API key)"}
    if response.get("status", 0) != 200:
        return {"present": False, "error": f"Shodan returned status {response.get('status')}"}
    try:
        payload = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError) as e:
        return {"present": False, "error": f"Shodan invalid JSON: {e}"}

    data = payload.get("data") or []
    if not isinstance(data, list):
        data = []

    services: list[dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        port = int(entry.get("port") or 0)
        product = entry.get("product")
        version = entry.get("version")
        transport = entry.get("transport") or "tcp"
        # Banner text — keep short for finding descriptions.
        banner_raw = entry.get("data") or ""
        banner = banner_raw.split("\n", 1)[0][:200] if isinstance(banner_raw, str) else ""
        services.append({
            "port": port,
            "transport": transport,
            "product": product,
            "version": version,
            "banner": banner,
        })

    vulns_raw = payload.get("vulns") or []
    if isinstance(vulns_raw, dict):
        # Older Shodan format: vulns is a dict {"CVE-X": {...}}.
        vulns = list(vulns_raw.keys())
    elif isinstance(vulns_raw, list):
        vulns = [v for v in vulns_raw if isinstance(v, str)]
    else:
        vulns = []

    return {
        "present": True,
        "ports": sorted({s["port"] for s in services if s["port"]}),
        "services": services,
        "vulns": vulns,
        "last_update": payload.get("last_update"),
        "country_code": payload.get("country_code"),
        "isp": payload.get("isp"),
        "org": payload.get("org"),
        "hostnames": payload.get("hostnames") or [],
    }


# ---------------------------------------------------------------------------
# Source: Censys
# ---------------------------------------------------------------------------


_CENSYS_API = "https://search.censys.io/api/v2/hosts"


def _query_censys(
    ip: str, api_id: str, api_secret: str, timeout: float
) -> dict[str, Any]:
    """Returns {present, services, last_updated, autonomous_system, error?}."""
    if not (api_id and api_secret):
        return {
            "present": False,
            "skipped": True,
            "reason": "no STRIX_CENSYS_API_ID / STRIX_CENSYS_API_SECRET — Censys skipped",
        }
    url = f"{_CENSYS_API}/{ip}"
    auth = base64.b64encode(f"{api_id}:{api_secret}".encode("utf-8")).decode("ascii")
    headers = {"Accept": "application/json", "Authorization": f"Basic {auth}"}
    response = _http_get(url, headers=headers, timeout=timeout)
    if response.get("error"):
        return {"present": False, "error": f"Censys failed: {response['error']}"}
    if response.get("status", 0) == 404:
        return {"present": False, "status": 404}
    if response.get("status", 0) == 401:
        return {"present": False, "error": "Censys returned 401 (invalid credentials)"}
    if response.get("status", 0) != 200:
        return {"present": False, "error": f"Censys returned status {response.get('status')}"}
    try:
        payload = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError) as e:
        return {"present": False, "error": f"Censys invalid JSON: {e}"}

    result = payload.get("result") or {}
    if not isinstance(result, dict):
        return {"present": False, "error": "Censys: unexpected result shape"}

    services_raw = result.get("services") or []
    if not isinstance(services_raw, list):
        services_raw = []
    services: list[dict[str, Any]] = []
    for entry in services_raw:
        if not isinstance(entry, dict):
            continue
        port = int(entry.get("port") or 0)
        service_name = entry.get("service_name")
        software = entry.get("software") or []
        # Pull the first software-name hint if available.
        product = None
        version = None
        if isinstance(software, list) and software:
            first = software[0]
            if isinstance(first, dict):
                product = first.get("product")
                version = first.get("version")
        services.append({
            "port": port,
            "transport": entry.get("transport_protocol") or "tcp",
            "service_name": service_name,
            "product": product,
            "version": version,
        })

    autonomous_system = result.get("autonomous_system") or {}
    return {
        "present": True,
        "ports": sorted({s["port"] for s in services if s["port"]}),
        "services": services,
        "last_updated": result.get("last_updated_at"),
        "autonomous_system": (
            {
                "asn": autonomous_system.get("asn"),
                "name": autonomous_system.get("name"),
                "country_code": autonomous_system.get("country_code"),
            }
            if isinstance(autonomous_system, dict)
            else None
        ),
        "location": result.get("location") if isinstance(result.get("location"), dict) else None,
    }


# ---------------------------------------------------------------------------
# High-risk service detection
# ---------------------------------------------------------------------------


def _detect_high_risk_services(
    services: list[dict[str, Any]]
) -> list[tuple[int, str]]:
    """Return list of (port, service-name) tuples for high-risk services."""
    out: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()
    for svc in services:
        port = int(svc.get("port") or 0)
        # Try product / service_name first.
        for hint_key in ("product", "service_name"):
            hint = svc.get(hint_key)
            if not hint or not isinstance(hint, str):
                continue
            hint_lower = hint.lower()
            for needle, label in _HIGH_RISK_SERVICES.items():
                if needle in hint_lower:
                    key = (port, label)
                    if key not in seen:
                        seen.add(key)
                        out.append(key)
                    break  # one label per service
        # Fallback: well-known port mapping.
        if port in _PORT_TO_SERVICE:
            label = _PORT_TO_SERVICE[port]
            key = (port, label)
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def _cache_dir() -> Path:
    return Path.home() / ".strix" / "attack_surface_cache"


def _cache_path(target: str) -> Path:
    safe = hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
    return _cache_dir() / f"{safe}.json"


def _cache_read(target: str, *, fresh_only: bool) -> dict[str, Any] | None:
    if os.environ.get("STRIX_ATTACK_SURFACE_NO_CACHE") == "1":
        return None
    path = _cache_path(target)
    if not path.exists():
        return None
    if fresh_only:
        age = time.time() - path.stat().st_mtime
        if age > _DEFAULT_CACHE_TTL_SECONDS:
            return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError) as e:
        logger.debug("attack_surface_intel cache read failed: %s", e)
        return None


def _cache_write(target: str, payload: dict[str, Any]) -> None:
    if os.environ.get("STRIX_ATTACK_SURFACE_NO_CACHE") == "1":
        return
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        with _cache_path(target).open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("attack_surface_intel cache write failed: %s", e)


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    category: str,
    cwe: str,
    target: str,
    description: str,
    description_plain: str,
    recommended_action: str,
    cve: str | None = None,
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category=category,
        cwe=cwe,
        cve=cve,
        target=target,
        endpoint=target,
        description=description,
        impact=(
            "Public scan-data sources (Shodan, Censys) tell attackers "
            "what's exposed before they probe directly. Open admin / "
            "database services on public IPs are the highest-converting "
            "compromise paths in real engagements: brute-force / default-"
            "credential / known-CVE exploitation against MongoDB / Redis "
            "/ Elasticsearch / Docker API / RDP / SSH appears in "
            "post-mortems for tens of thousands of breaches per year. "
            "Surfacing this via Shodan / Censys lets the agent prioritise "
            "before spending live-probe budget on lower-value paths."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
    )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    if t is None:
        return None
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME)


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is None:
        return
    t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(sandbox_execution=True)
def attack_surface_intel(
    target: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Look up Shodan + Censys attack-surface data for a domain or IP.

    Args:
        target: Domain (e.g. `example.com`) or IPv4 address (e.g.
            `8.8.8.8`). URL-shaped input auto-stripped to hostname.
            Private / loopback / link-local IPs rejected.
        timeout: Per-request timeout in seconds (default 15).

    Returns:
        {
          success, target, target_type, queried_at, from_cache,
          resolved_ips,            # for domain targets
          per_ip: [
            {
              ip,
              shodan: {present, ports, services, vulns, ...} | {skipped, reason},
              censys: {present, ports, services, ...} | {skipped, reason},
              high_risk_services: [{port, service}, ...],
              broad_surface: bool,
              version_disclosure: [{port, product, version}, ...],
              shodan_vulns_emitted: [CVE, ...],
            },
            ...
          ],
          source_errors: dict,
          findings_emitted: int,
        }

    Findings:
        - **High** (CWE-200, attack_surface_disclosure) — high-risk
          service exposed on a public IP.
        - **High** (CWE-1395, vulnerable_software) — Shodan-tagged
          CVE on the host.
        - **Medium** (CWE-200) — broad port surface (>10 distinct
          ports).
        - **Low** (CWE-200) — version disclosure in service banners.

    Notes:
        - Both sources opt-in via env vars (`STRIX_SHODAN_KEY`,
          `STRIX_CENSYS_API_ID` + `STRIX_CENSYS_API_SECRET`).
        - Per-host dedup: at most one finding per (severity × class)
          per IP.
        - 6-hour cache; stale-cache served on full-source failure
          (fail-open). Disable with `STRIX_ATTACK_SURFACE_NO_CACHE=1`.
        - `verification_status=needs_review` since Shodan / Censys
          can carry stale data (services may have been firewalled
          since the last scan).
    """
    target_kind, value = _classify_target(target)
    if target_kind == "invalid":
        return {"success": False, "error": f"invalid target (not a domain or public IP): {target!r}"}

    cev = _start_check("attack_surface_intel", value)

    cached = _cache_read(value, fresh_only=True)
    if cached is not None:
        cached["from_cache"] = True
        _complete_check(
            cev,
            result="vulnerable" if cached.get("findings_emitted") else "not_vulnerable",
            evidence=f"{cached.get('findings_emitted', 0)} attack-surface finding(s) for {value} (cached)",
        )
        return cached

    shodan_key = (os.environ.get("STRIX_SHODAN_KEY") or "").strip()
    censys_id = (os.environ.get("STRIX_CENSYS_API_ID") or "").strip()
    censys_secret = (os.environ.get("STRIX_CENSYS_API_SECRET") or "").strip()

    if target_kind == "ip":
        ips_to_check = [value]
        resolved_ips: list[str] = []
    else:
        resolved_ips = _resolve_ips(value)
        ips_to_check = resolved_ips

    per_ip_results: list[dict[str, Any]] = []
    source_errors: dict[str, str] = {}
    findings_emitted = 0
    seen_keys: set[tuple[str, str, str]] = set()  # (ip, severity, class)

    for ip in ips_to_check:
        shodan_v = _query_shodan(ip, shodan_key, timeout)
        if shodan_v.get("error"):
            source_errors[f"shodan[{ip}]"] = shodan_v["error"]
        censys_v = _query_censys(ip, censys_id, censys_secret, timeout)
        if censys_v.get("error"):
            source_errors[f"censys[{ip}]"] = censys_v["error"]

        # Aggregate services across both sources for analysis.
        all_services: list[dict[str, Any]] = []
        if shodan_v.get("present"):
            all_services.extend(shodan_v.get("services") or [])
        if censys_v.get("present"):
            all_services.extend(censys_v.get("services") or [])

        # Distinct port set.
        all_ports: set[int] = set()
        for src in (shodan_v, censys_v):
            for p in src.get("ports") or []:
                if isinstance(p, int) and p > 0:
                    all_ports.add(p)

        # ---- Detection 1: high-risk services ----
        high_risk = _detect_high_risk_services(all_services)
        # Aggregate by service-name for cleaner reporting.
        services_by_name: dict[str, set[int]] = {}
        for port, label in high_risk:
            services_by_name.setdefault(label, set()).add(port)

        # ---- Detection 2: Shodan-tagged CVEs ----
        shodan_vulns = list(shodan_v.get("vulns") or [])

        # ---- Detection 3: broad surface ----
        broad_surface = len(all_ports) > _BROAD_SURFACE_THRESHOLD

        # ---- Detection 4: version disclosure ----
        version_disclosures: list[dict[str, Any]] = []
        for svc in all_services:
            product = svc.get("product")
            version = svc.get("version")
            if product and version and isinstance(product, str) and isinstance(version, str):
                version_disclosures.append({
                    "port": svc.get("port"),
                    "product": product,
                    "version": version,
                })

        ip_record = {
            "ip": ip,
            "shodan": shodan_v,
            "censys": censys_v,
            "all_ports": sorted(all_ports),
            "high_risk_services": [
                {"port": p, "service": s} for p, s in high_risk
            ],
            "broad_surface": broad_surface,
            "version_disclosure": version_disclosures,
            "shodan_vulns": shodan_vulns,
        }

        # ---- Emit per-detection findings (with dedup) ----
        # 1. High-risk services → high
        if services_by_name:
            key = (ip, "high", "high_risk_service")
            if key not in seen_keys:
                seen_keys.add(key)
                services_text = ", ".join(
                    f"{name} (port {sorted(ports)[0]})"
                    for name, ports in sorted(services_by_name.items())
                )
                _emit_finding(
                    title=f"Internet-exposed high-risk service(s) on {ip}",
                    severity="high",
                    category="attack_surface_disclosure",
                    cwe="CWE-200",
                    target=ip,
                    description=(
                        f"Shodan + Censys report `{ip}` exposing "
                        f"{len(services_by_name)} high-risk service(s) "
                        f"to the public internet: {services_text}. "
                        f"All open ports: {sorted(all_ports)}. "
                        f"Last seen: Shodan={shodan_v.get('last_update')}, "
                        f"Censys={censys_v.get('last_updated')}."
                    ),
                    description_plain=(
                        f"`{ip}` exposes services to the public internet "
                        f"that should normally be locked down to private "
                        f"networks: {services_text}. These are the most "
                        "common attacker entry points (brute-force / "
                        "default-credential / known-CVE exploitation)."
                    ),
                    recommended_action=(
                        "Audit whether these services need public-internet "
                        "exposure. If the answer is no (almost always), "
                        "restrict via cloud security group / firewall to "
                        "specific source IPs (admin VPN, bastion, "
                        "internal-only). For services that DO need public "
                        "exposure (e.g. SSH on a bastion), enforce: SSH "
                        "key auth only (no passwords), rate-limited via "
                        "fail2ban, MFA via OTP, monitored login logs. "
                        "Database / cache services (MongoDB / Redis / "
                        "Elasticsearch / etcd / Memcached) should NEVER "
                        "be public-internet-accessible."
                    ),
                )
                findings_emitted += 1

        # 2. Shodan-tagged CVEs → high (one finding per CVE)
        if shodan_vulns:
            for cve in shodan_vulns[:20]:  # cap at 20 to avoid flood
                key = (ip, "high", f"shodan_cve_{cve}")
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                _emit_finding(
                    title=f"Shodan-tagged vulnerability {cve} on {ip}",
                    severity="high",
                    category="vulnerable_software",
                    cwe="CWE-1395",
                    cve=cve,
                    target=ip,
                    description=(
                        f"Shodan's vulnerability matching has tagged "
                        f"`{ip}` with `{cve}` based on its observed "
                        f"service banners. Open ports: "
                        f"{sorted(all_ports)}. Last seen: "
                        f"{shodan_v.get('last_update')}."
                    ),
                    description_plain=(
                        f"Shodan, a public scanner, has matched a known "
                        f"vulnerability (`{cve}`) against the services "
                        f"running on `{ip}`. The CVE's exploitability "
                        "depends on the specific service version; the "
                        "tracer auto-decorates this finding with KEV "
                        "data when applicable."
                    ),
                    recommended_action=(
                        f"Patch the affected service to a non-vulnerable "
                        f"version. Use `cve_lookup` to find the fixed "
                        f"version. If the fix isn't immediately "
                        f"deployable, restrict network exposure to the "
                        f"affected service via firewall."
                    ),
                )
                findings_emitted += 1

        # 3. Broad surface → medium
        if broad_surface:
            key = (ip, "medium", "broad_surface")
            if key not in seen_keys:
                seen_keys.add(key)
                _emit_finding(
                    title=f"Broad attack surface on {ip} ({len(all_ports)} ports)",
                    severity="medium",
                    category="attack_surface_disclosure",
                    cwe="CWE-200",
                    target=ip,
                    description=(
                        f"`{ip}` exposes {len(all_ports)} distinct ports "
                        f"to the public internet: {sorted(all_ports)}. "
                        f"This often signals a poorly-segmented host or "
                        f"a production server doubling as a jump-box / "
                        f"developer machine."
                    ),
                    description_plain=(
                        f"This server has {len(all_ports)} ports open to "
                        "the public internet. Typical web servers expose "
                        "1-3 ports (80, 443, sometimes 22 for admin); "
                        "more than 10 ports is a strong signal that "
                        "internal services are accidentally exposed."
                    ),
                    recommended_action=(
                        "Audit each open port — confirm it serves a "
                        "deliberate public-facing purpose. Close every "
                        "port that doesn't (move admin / database / "
                        "internal services to a private network or "
                        "VPN-gated bastion). Maintain an explicit "
                        "allow-list of public ports in your firewall / "
                        "security-group config."
                    ),
                )
                findings_emitted += 1

        # 4. Version disclosure → low (one finding aggregating all
        #    versions on this IP).
        if version_disclosures:
            key = (ip, "low", "version_disclosure")
            if key not in seen_keys:
                seen_keys.add(key)
                versions_text = ", ".join(
                    f"{v['product']}/{v['version']} on port {v['port']}"
                    for v in version_disclosures[:10]
                )
                _emit_finding(
                    title=f"Service version disclosure on {ip}",
                    severity="low",
                    category="attack_surface_disclosure",
                    cwe="CWE-200",
                    target=ip,
                    description=(
                        f"Shodan + Censys observe specific software "
                        f"versions on `{ip}`: {versions_text}. The agent "
                        "should feed these (product, version) pairs into "
                        "`cve_lookup` (#61) to find any known CVEs."
                    ),
                    description_plain=(
                        "Public scanners can fingerprint the exact "
                        "software versions running on this server. By "
                        "itself this isn't a vulnerability; combined "
                        "with the public CVE database it becomes the "
                        "first step of a targeted attack."
                    ),
                    recommended_action=(
                        "Strip or generic-ize Server / X-Powered-By / "
                        "version-disclosing banners where possible. For "
                        "services where banner suppression isn't "
                        "feasible, ensure all running versions are "
                        "patched to the latest non-vulnerable release."
                    ),
                )
                findings_emitted += 1

        per_ip_results.append(ip_record)

    result = {
        "success": True,
        "target": value,
        "target_type": target_kind,
        "queried_at": int(time.time()),
        "from_cache": False,
        "resolved_ips": resolved_ips,
        "per_ip": per_ip_results,
        "source_errors": source_errors,
        "findings_emitted": findings_emitted,
    }

    # Stale-cache fallback when every source failed for every IP.
    every_source_failed = bool(per_ip_results) and all(
        (rec["shodan"].get("error") is not None
         or rec["shodan"].get("skipped"))
        and (rec["censys"].get("error") is not None
             or rec["censys"].get("skipped"))
        for rec in per_ip_results
    )
    every_skipped = bool(per_ip_results) and all(
        rec["shodan"].get("skipped") and rec["censys"].get("skipped")
        for rec in per_ip_results
    )
    if every_source_failed and not every_skipped:
        stale = _cache_read(value, fresh_only=False)
        if stale is not None:
            stale["from_cache"] = True
            stale["error"] = "all live sources failed; served stale cache"
            _complete_check(
                cev,
                result="inconclusive",
                evidence=f"all live sources failed for {value}; stale cache",
            )
            return stale

    _cache_write(value, result)

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{findings_emitted} attack-surface finding(s) for {value}",
    )
    return result
