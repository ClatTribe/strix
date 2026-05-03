"""Reverse-IP discovery — find domains co-hosted on the target's IPs.

Roadmap §7.3. Given a target IP (or a domain that resolves to one or more
IPs), query free reverse-IP APIs to find other domains sharing the host.
Shared hosting is a real-world pivot vector: a vulnerable neighbour on the
same physical/virtual host can be a launchpad onto the target.

Provider matrix:
- **HackerTarget** (`api.hackertarget.com/reverseiplookup`) — free, no key,
  rate-limited (~50/day per source IP). Plain-text response, one domain
  per line. Primary source.
- **ViewDNS** (`api.viewdns.info/reverseip`) — requires
  `STRIX_VIEWDNS_KEY`; broader cross-reference data than HackerTarget
  when available. Optional secondary.

Returns the merged co-hosted-domain list and emits an info-severity
finding when the host has many co-tenants (suggests shared hosting,
which broadens the pivot surface).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import Any

from strix.tools.registry import register_tool

from ._common import (
    complete_check,
    dig,
    emit_finding,
    looks_like_domain,
    start_check,
)


logger = logging.getLogger(__name__)
_TOOL_NAME = "reverse_ip_discovery"
_HTTP_TIMEOUT = 12

# Min number of co-hosted domains for an info-severity finding to be emitted.
# Below this we still return the list, but it's not noteworthy on its own —
# many orgs legitimately serve multiple domains from one IP.
_SHARED_HOSTING_THRESHOLD = 5

# Cap per-IP results to avoid unbounded payloads from large shared-hosting
# providers (e.g. CDN edge IPs can return thousands of domains).
_MAX_RESULTS_PER_IP = 250

# Cap how many IPs we'll query when given a domain that resolves to many.
_MAX_IPS = 5


def _http_get_text(url: str, *, headers: dict[str, str] | None = None) -> tuple[int, str]:
    """GET returning (status, body). (0, '') on failure. Module-local
    so tests can monkeypatch on this module's namespace."""
    try:
        import httpx

        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True) as c:
            r = c.get(url, headers=headers or {})
            return r.status_code, r.text
    except Exception:  # noqa: BLE001
        try:
            import urllib.request

            req = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as r:  # noqa: S310
                return r.status, r.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return 0, ""


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_to_ips(domain: str) -> list[str]:
    """Return public A-record IPs for `domain`, deduped + capped."""
    out = dig(domain, "A")
    ips: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or not _is_valid_ip(line):
            continue
        try:
            addr = ipaddress.ip_address(line)
        except ValueError:
            continue
        # Skip private/loopback/link-local — reverse-IP services don't
        # return useful data for those, and we'd be leaking internal IPs
        # to the API.
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            continue
        if line not in ips:
            ips.append(line)
        if len(ips) >= _MAX_IPS:
            break
    return ips


# ---------------------------------------------------------------------------
# HackerTarget reverse-IP
# ---------------------------------------------------------------------------


# HackerTarget's free response is one domain per line. When rate-limited
# the body is "API count exceeded - this is a free service ..." — single
# line, matched by regex.
_HACKERTARGET_RATE_LIMIT_RE = re.compile(
    r"api count exceeded|rate limit|too many requests", re.IGNORECASE
)
_HACKERTARGET_ERROR_RE = re.compile(
    r"error check your|invalid|no records", re.IGNORECASE
)


def _hackertarget_reverse_ip(ip: str) -> dict[str, Any]:
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    status, body = _http_get_text(url)
    if status != 200:
        return {
            "provider": "hackertarget",
            "ip": ip,
            "success": False,
            "error": f"http_{status}",
            "domains": [],
        }
    body = body.strip()
    if _HACKERTARGET_RATE_LIMIT_RE.search(body):
        return {
            "provider": "hackertarget",
            "ip": ip,
            "success": False,
            "error": "rate_limited",
            "domains": [],
        }
    if _HACKERTARGET_ERROR_RE.search(body) and "\n" not in body:
        return {
            "provider": "hackertarget",
            "ip": ip,
            "success": False,
            "error": "no_data",
            "domains": [],
        }
    domains: list[str] = []
    for line in body.splitlines():
        d = line.strip().lower()
        if d and looks_like_domain(d) and d not in domains:
            domains.append(d)
        if len(domains) >= _MAX_RESULTS_PER_IP:
            break
    return {
        "provider": "hackertarget",
        "ip": ip,
        "success": True,
        "domains": domains,
    }


# ---------------------------------------------------------------------------
# ViewDNS reverse-IP (key required)
# ---------------------------------------------------------------------------


def _viewdns_reverse_ip(ip: str, api_key: str) -> dict[str, Any]:
    """ViewDNS Iris API. Free tier requires a key (registration). Output
    is JSON: `{response: {domains: [{name, last_resolved}, ...]}}`."""
    url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey={api_key}&output=json"
    status, body = _http_get_text(url)
    if status != 200:
        return {
            "provider": "viewdns",
            "ip": ip,
            "success": False,
            "error": f"http_{status}",
            "domains": [],
        }
    try:
        import json as _json

        data = _json.loads(body)
    except Exception:  # noqa: BLE001
        return {
            "provider": "viewdns",
            "ip": ip,
            "success": False,
            "error": "bad_json",
            "domains": [],
        }
    response = data.get("response", {}) if isinstance(data, dict) else {}
    raw_domains = response.get("domains") if isinstance(response, dict) else None
    domains: list[str] = []
    if isinstance(raw_domains, list):
        for entry in raw_domains:
            name: str | None = None
            if isinstance(entry, dict):
                candidate = entry.get("name") or entry.get("domain")
                if isinstance(candidate, str):
                    name = candidate.strip().lower()
            elif isinstance(entry, str):
                name = entry.strip().lower()
            if name and looks_like_domain(name) and name not in domains:
                domains.append(name)
            if len(domains) >= _MAX_RESULTS_PER_IP:
                break
    return {
        "provider": "viewdns",
        "ip": ip,
        "success": True,
        "domains": domains,
    }


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


_KNOWN_PROVIDERS = ("hackertarget", "viewdns")


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1590.005"],  # Gather Victim Network Info: IP Addresses
)
def reverse_ip_discovery(
    target: str,
    providers: str | None = None,
) -> dict[str, Any]:
    """Discover domains co-hosted on the target's IP(s).

    Args:
        target: an IPv4/IPv6 address, or a domain (resolved via DNS first).
        providers: comma-separated subset of {hackertarget, viewdns}.
                   Default: all (key-gated providers fall back gracefully).

    HackerTarget is free and key-less (rate-limited ~50/day). ViewDNS
    requires `STRIX_VIEWDNS_KEY` — when unset, it's silently skipped.

    Emits an info-severity finding (CWE-200, info_disclosure) when an IP
    has >= {threshold} co-hosted domains, signalling shared hosting and
    a broader pivot surface.

    Returns:
        {
          success, target, target_type,
          ips_queried: [...],
          providers_queried: [...],
          per_ip_results: [{ip, providers: [...]}],
          merged_domains: [...],
          merged_count
        }
    """
    if not target or not target.strip():
        return {"success": False, "error": "target required"}
    target = target.strip()

    if _is_valid_ip(target):
        ips = [target]
        target_type = "ip"
    elif looks_like_domain(target):
        ips = _resolve_to_ips(target)
        target_type = "domain"
        if not ips:
            return {
                "success": False,
                "error": "domain_did_not_resolve",
                "target": target,
            }
    else:
        return {"success": False, "error": f"invalid target: {target!r}"}

    # Resolve provider set.
    if providers is None or providers.strip().lower() == "all":
        active = list(_KNOWN_PROVIDERS)
    else:
        active = [p.strip().lower() for p in providers.split(",") if p.strip()]
        unknown = [p for p in active if p not in _KNOWN_PROVIDERS]
        if unknown:
            return {"success": False, "error": f"unknown providers: {unknown}"}

    viewdns_key = os.environ.get("STRIX_VIEWDNS_KEY")
    # Drop viewdns when no key configured — but only if it wasn't explicitly
    # requested. If the agent explicitly asked for viewdns and there's no
    # key, surface that so it doesn't fail silently.
    explicitly_requested = providers is not None and providers.strip().lower() != "all"
    if "viewdns" in active and not viewdns_key:
        if explicitly_requested:
            return {
                "success": False,
                "error_reason": "viewdns requested but STRIX_VIEWDNS_KEY not set",
                "target": target,
            }
        active = [p for p in active if p != "viewdns"]

    if not active:
        return {
            "success": False,
            "error_reason": "no providers available",
            "target": target,
        }

    per_ip_results: list[dict[str, Any]] = []
    merged: list[str] = []
    merged_seen: set[str] = set()
    target_lower = target.lower()
    target_apex = target_lower if target_type == "domain" else None

    for ip in ips:
        ip_block: dict[str, Any] = {"ip": ip, "providers": []}
        for provider in active:
            cev_id = start_check(
                category="reverse_ip", surface=ip, tool=_TOOL_NAME
            )
            try:
                if provider == "hackertarget":
                    r = _hackertarget_reverse_ip(ip)
                elif provider == "viewdns":
                    assert viewdns_key  # guarded above
                    r = _viewdns_reverse_ip(ip, viewdns_key)
                else:
                    continue
            except Exception as e:  # noqa: BLE001
                logger.exception("reverse-ip provider %s failed", provider)
                r = {
                    "provider": provider,
                    "ip": ip,
                    "success": False,
                    "error": str(e),
                    "domains": [],
                }
            ip_block["providers"].append(r)
            for d in r.get("domains", []):
                # Filter out the target itself from the neighbour list.
                if d == target_apex or d == target_lower:
                    continue
                if d not in merged_seen:
                    merged_seen.add(d)
                    merged.append(d)
            complete_check(
                cev_id,
                result=("not_vulnerable" if r.get("success") else "inconclusive"),
                evidence=f"{provider}@{ip}: {len(r.get('domains', []))} domains",
            )
        per_ip_results.append(ip_block)

    # Per-IP: emit info-severity finding when shared-hosting threshold met.
    for block in per_ip_results:
        ip = block["ip"]
        ip_domains: set[str] = set()
        for r in block["providers"]:
            for d in r.get("domains", []):
                if d != target_apex and d != target_lower:
                    ip_domains.add(d)
        if len(ip_domains) >= _SHARED_HOSTING_THRESHOLD:
            sample = sorted(ip_domains)[:10]
            emit_finding(
                title=f"Shared hosting detected on {ip} ({len(ip_domains)} co-tenants)",
                severity="info",
                category="info_disclosure",
                cwe="CWE-200",
                target=target,
                endpoint=ip,
                description=(
                    f"{len(ip_domains)} other domain(s) share the IP {ip}. "
                    f"Sample: {', '.join(sample)}"
                    + (f", … (+{len(ip_domains) - len(sample)} more)" if len(ip_domains) > len(sample) else "")
                ),
                impact=(
                    "Co-tenancy on shared hosting broadens the engagement's "
                    "pivot surface. A vulnerability on a neighbour can expose "
                    "the target via container/VM escape, weak isolation, or "
                    "shared filesystem permissions. Identify which domains "
                    "are also in scope, and which are out-of-scope but worth "
                    "fingerprinting for known-CMS / known-CVE shortcuts."
                ),
                remediation=(
                    "If the target is on shared hosting unintentionally, "
                    "migrate to an isolated host. Confirm tenant-isolation "
                    "guarantees with the hosting provider, and ensure any "
                    "shared services (database, file storage, log "
                    "aggregation) enforce per-tenant access controls."
                ),
                verification_status="verified",
            )

    return {
        "success": True,
        "target": target,
        "target_type": target_type,
        "ips_queried": ips,
        "providers_queried": active,
        "per_ip_results": per_ip_results,
        "merged_domains": merged,
        "merged_count": len(merged),
    }
