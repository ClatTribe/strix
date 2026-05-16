"""Domain / IP reputation lookups across free public blocklists.

For a domain or IP target, queries 5 reputation sources in parallel:

| Source | Covers | Auth | API |
|---|---|---|---|
| **URLhaus** | domain + IP | none | POST `https://urlhaus-api.abuse.ch/v1/host/` form-encoded |
| **Spamhaus DBL** | domain | none (low-volume) | DNS A query at `<domain>.dbl.spamhaus.org` |
| **Spamhaus ZEN** | IP | none (low-volume) | DNS A query at `<reversed-ip>.zen.spamhaus.org` |
| **Google Safe Browsing** | domain + URL | `STRIX_GSB_KEY` | POST `https://safebrowsing.googleapis.com/v4/threatMatches:find` |
| **AbuseIPDB** | IP | `STRIX_ABUSEIPDB_KEY` | GET `https://api.abuseipdb.com/api/v2/check?ipAddress=…` |

The tool auto-detects whether `target` is a domain or an IP address.
For domains it also resolves up to 3 A records and runs the IP-only
sources (ZEN, AbuseIPDB) against each; this catches "clean domain
pointed at compromised shared host" cases.

Findings:

- **High** (CWE-453, malicious_target) — target listed on URLhaus's
  active blocklist (currently serving malware) OR AbuseIPDB confidence
  score ≥ 75% (verified abusive).
- **Medium** (CWE-453) — Spamhaus DBL listed (spam / phishing source);
  AbuseIPDB confidence 25–74%; Google Safe Browsing flagged.
- **Low** (CWE-453) — historical URLhaus entry no longer active;
  AbuseIPDB confidence 1–24%; Spamhaus ZEN listed.
- *(no finding)* — clean across all sources.

Per-source dedup: at most one finding per (severity × source) so a
target on multiple URLhaus URLs emits ONE URLhaus finding, not one per
URL. Per-source verdicts still live in `result["sources"]` for the
agent.

Cache: per-target JSON cache under `~/.strix/domain_rep_cache/`. 6h
TTL — reputation data changes faster than CVE data so we use a
shorter TTL than `cve_lookup`'s 6h. Stale-cache served on full network
failure (fail-open with `error` populated). Disable with
`STRIX_DOMAIN_REP_NO_CACHE=1`.

Composes with cluster-A safety: rate-limit applies to outbound HTTP
requests; DNS-RBL queries are throttled by the DNS resolver's own
timeout. `--exclude-path` doesn't apply since URLs are
URLhaus / Google / AbuseIPDB / Spamhaus, not the customer's domain.

All findings carry `description_plain` + `recommended_action` (the §11
non-tech UX fields). The recommendation depends on the source:
- URLhaus / GSB hits → assume host is compromised; trigger IR
  workflow + check for unauthorized access; remove malware or rotate
  hosting.
- Spamhaus DBL hits → apply for delisting after fixing root cause
  (likely SPF/DMARC misconfig leading to spam).
- AbuseIPDB high-confidence hits → check for unauthorized access; if
  your own infra, revoke / rotate keys; if shared hosting, file a
  delisting after the host is cleaned.

`verification_status=needs_review` since reputation lists can carry
stale entries; the agent should follow up by inspecting the
URLhaus/GSB references in the finding before treating any single hit
as a confirmed compromise.
"""

from __future__ import annotations

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
_TOOL_NAME = "domain_reputation"
_DEFAULT_TIMEOUT = 12.0
_DEFAULT_CACHE_TTL_SECONDS = 6 * 3600
_MAX_RESOLVED_IPS = 3
_DNS_TIMEOUT_SECONDS = 4.0

_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,63})+$"
)


# ---------------------------------------------------------------------------
# Target normalization
# ---------------------------------------------------------------------------


def _classify_target(target: str) -> tuple[str, str]:
    """Return ('domain', value) or ('ip', value) or ('invalid', '')."""
    if not target or not isinstance(target, str):
        return ("invalid", "")
    target = target.strip().rstrip(".")
    if not target:
        return ("invalid", "")
    # Strip URL scheme + path if accidentally passed.
    if "://" in target:
        from urllib.parse import urlparse

        parsed = urlparse(target)
        target = parsed.hostname or ""
        if not target:
            return ("invalid", "")
    target = target.lower()
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return ("invalid", "")
        return ("ip", target)
    except ValueError:
        pass
    if len(target) > 253:
        return ("invalid", "")
    if not _DOMAIN_RE.match(target):
        return ("invalid", "")
    return ("domain", target)


def _resolve_ips(domain: str, timeout: float = _DNS_TIMEOUT_SECONDS) -> list[str]:
    """Resolve up to _MAX_RESOLVED_IPS A records for the domain.
    Returns empty list on resolution failure."""
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
                if ip.is_loopback or ip.is_private or ip.is_link_local:
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


def _http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """HTTP request via cluster-A safety. Returns
    {status, headers, body, error?}."""
    headers = dict(headers or {})
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request(
                method, url, headers=headers, body=body, timeout=int(timeout),
            )
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
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=True) as c:
            content = body.encode("utf-8") if body else None
            r = c.request(method, url, headers=merged, content=content)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:128 * 1024],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Source: URLhaus (free, no key)
# ---------------------------------------------------------------------------


_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"


def _query_urlhaus(host: str, timeout: float) -> dict[str, Any]:
    """Returns {listed: bool, status, urls_count, first_seen, last_seen, error?}.

    URLhaus returns:
      - query_status="ok" + urls[] when listed
      - query_status="no_results" when not listed
      - query_status="invalid_host" / unexpected → recorded as error
    """
    body = f"host={host}"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = _http_request("POST", _URLHAUS_API, headers=headers, body=body, timeout=timeout)

    if response.get("error"):
        return {"listed": False, "error": f"URLhaus query failed: {response['error']}"}
    if response.get("status", 0) != 200:
        return {"listed": False, "error": f"URLhaus returned status {response.get('status')}"}
    try:
        payload = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError) as e:
        return {"listed": False, "error": f"URLhaus invalid JSON: {e}"}

    qs = payload.get("query_status")
    if qs == "no_results":
        return {"listed": False, "status": "clean", "urls_count": 0}
    if qs == "ok":
        urls = payload.get("urls") or []
        if not isinstance(urls, list):
            urls = []
        active = [u for u in urls if isinstance(u, dict) and u.get("url_status") == "online"]
        return {
            "listed": True,
            "status": "active" if active else "historical",
            "urls_count": len(urls),
            "active_urls_count": len(active),
            "first_seen": payload.get("firstseen"),
            "url_count_total": payload.get("url_count"),
            "host_reference": payload.get("urlhaus_reference"),
        }
    return {"listed": False, "error": f"URLhaus query_status={qs}"}


# ---------------------------------------------------------------------------
# Source: Spamhaus DBL (DNS-RBL for domains)
# ---------------------------------------------------------------------------


_SPAMHAUS_DBL_RETURN_CODES = {
    "127.0.1.2": "spam",
    "127.0.1.4": "phishing",
    "127.0.1.5": "malware",
    "127.0.1.6": "botnet C&C",
}


def _query_spamhaus_dbl(domain: str, timeout: float = _DNS_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Returns {listed, codes, kinds, error?}. Lookup
    `<domain>.dbl.spamhaus.org`."""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        try:
            answers = resolver.resolve(f"{domain}.dbl.spamhaus.org", "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {"listed": False}
        codes: list[str] = []
        kinds: list[str] = []
        for r in answers:
            ip_str = str(r).strip()
            codes.append(ip_str)
            kind = _SPAMHAUS_DBL_RETURN_CODES.get(ip_str)
            if kind:
                kinds.append(kind)
        return {"listed": True, "codes": codes, "kinds": kinds or ["unknown"]}
    except Exception as e:  # noqa: BLE001
        return {"listed": False, "error": f"Spamhaus DBL: {type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# Source: Spamhaus ZEN (DNS-RBL for IPs)
# ---------------------------------------------------------------------------


_SPAMHAUS_ZEN_RETURN_CODES = {
    "127.0.0.2": "SBL (spam)",
    "127.0.0.3": "SBL CSS (snowshoe)",
    "127.0.0.4": "XBL (exploit)",
    "127.0.0.9": "DROP (hijacked)",
    "127.0.0.10": "PBL ISP",
    "127.0.0.11": "PBL Spamhaus",
}


def _reverse_ip(ip: str) -> str | None:
    """Reverse octet order for DNS-RBL queries. IPv4 only — Spamhaus
    ZEN doesn't support IPv6 in the public free tier."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not isinstance(addr, ipaddress.IPv4Address):
        return None
    return ".".join(reversed(ip.split(".")))


def _query_spamhaus_zen(ip: str, timeout: float = _DNS_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Returns {listed, codes, kinds, error?}."""
    reversed_ip = _reverse_ip(ip)
    if not reversed_ip:
        return {"listed": False}
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        try:
            answers = resolver.resolve(f"{reversed_ip}.zen.spamhaus.org", "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {"listed": False}
        codes: list[str] = []
        kinds: list[str] = []
        for r in answers:
            ip_str = str(r).strip()
            codes.append(ip_str)
            kind = _SPAMHAUS_ZEN_RETURN_CODES.get(ip_str)
            if kind:
                kinds.append(kind)
        return {"listed": True, "codes": codes, "kinds": kinds or ["unknown"]}
    except Exception as e:  # noqa: BLE001
        return {"listed": False, "error": f"Spamhaus ZEN: {type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# Source: Google Safe Browsing (key-gated)
# ---------------------------------------------------------------------------


_GSB_API_BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_GSB_THREAT_TYPES = (
    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
)


def _query_google_safe_browsing(
    target: str, key: str, timeout: float
) -> dict[str, Any]:
    """Returns {listed, threats, error?}. Skipped (returns
    {listed: False, skipped: True, reason}) without a key."""
    if not key:
        return {
            "listed": False,
            "skipped": True,
            "reason": "no STRIX_GSB_KEY — Google Safe Browsing skipped",
        }
    body = json.dumps({
        "client": {"clientId": "strix", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": list(_GSB_THREAT_TYPES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": f"http://{target}/"},
                {"url": f"https://{target}/"},
            ],
        },
    })
    url = f"{_GSB_API_BASE}?key={key}"
    headers = {"Content-Type": "application/json"}
    response = _http_request("POST", url, headers=headers, body=body, timeout=timeout)
    if response.get("error"):
        return {"listed": False, "error": f"Google Safe Browsing failed: {response['error']}"}
    if response.get("status", 0) != 200:
        return {"listed": False, "error": f"Google Safe Browsing returned status {response.get('status')}"}
    try:
        payload = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError) as e:
        return {"listed": False, "error": f"Google Safe Browsing invalid JSON: {e}"}
    matches = payload.get("matches") or []
    if not matches:
        return {"listed": False}
    threat_types = sorted({m.get("threatType") for m in matches if isinstance(m, dict)})
    return {"listed": True, "threats": [t for t in threat_types if t]}


# ---------------------------------------------------------------------------
# Source: AbuseIPDB (key-gated; IP only)
# ---------------------------------------------------------------------------


_ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"


def _query_abuseipdb(ip: str, key: str, timeout: float) -> dict[str, Any]:
    """Returns {listed, abuse_confidence, total_reports, last_reported_at, error?}.
    Skipped without `STRIX_ABUSEIPDB_KEY`."""
    if not key:
        return {
            "listed": False,
            "skipped": True,
            "reason": "no STRIX_ABUSEIPDB_KEY — AbuseIPDB skipped",
        }
    url = f"{_ABUSEIPDB_API}?ipAddress={ip}&maxAgeInDays=30"
    headers = {"Key": key, "Accept": "application/json"}
    response = _http_request("GET", url, headers=headers, timeout=timeout)
    if response.get("error"):
        return {"listed": False, "error": f"AbuseIPDB failed: {response['error']}"}
    if response.get("status", 0) != 200:
        return {"listed": False, "error": f"AbuseIPDB returned status {response.get('status')}"}
    try:
        payload = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError) as e:
        return {"listed": False, "error": f"AbuseIPDB invalid JSON: {e}"}
    data = payload.get("data") or {}
    if not isinstance(data, dict):
        return {"listed": False}
    confidence = int(data.get("abuseConfidenceScore") or 0)
    total = int(data.get("totalReports") or 0)
    last = data.get("lastReportedAt")
    return {
        "listed": confidence > 0 or total > 0,
        "abuse_confidence": confidence,
        "total_reports": total,
        "last_reported_at": last,
        "country_code": data.get("countryCode"),
        "domain": data.get("domain"),
    }


# ---------------------------------------------------------------------------
# Cache (per-target, 6h TTL)
# ---------------------------------------------------------------------------


def _cache_dir() -> Path:
    return Path.home() / ".strix" / "domain_rep_cache"


def _cache_path(target: str) -> Path:
    safe = hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
    return _cache_dir() / f"{safe}.json"


def _cache_read(target: str, *, fresh_only: bool) -> dict[str, Any] | None:
    if os.environ.get("STRIX_DOMAIN_REP_NO_CACHE") == "1":
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
        logger.debug("domain_reputation cache read failed: %s", e)
        return None


def _cache_write(target: str, payload: dict[str, Any]) -> None:
    if os.environ.get("STRIX_DOMAIN_REP_NO_CACHE") == "1":
        return
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        with _cache_path(target).open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("domain_reputation cache write failed: %s", e)


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    target: str,
    description: str,
    description_plain: str,
    recommended_action: str,
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    report_id = tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="malicious_target",
        cwe="CWE-453",
        target=target,
        endpoint=target,
        description=description,
        impact=(
            "Public reputation feeds are the consensus view of which "
            "hosts attackers, security vendors, and ISPs treat as "
            "malicious. A target on a reputable blocklist signals "
            "either: (a) the host is actively serving malware / "
            "phishing — likely compromised; (b) the host is sending "
            "spam / abusive traffic — likely misconfigured or "
            "compromised; or (c) the host is on shared infrastructure "
            "where someone else compromised a sibling tenant. All "
            "three demand immediate triage."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
    )

    # KG: record as a ThreatIntel observation about the Asset
    # (domain). Vuln-shape doesn't fit — reputation is an observed
    # property of the target, not a vuln at a surface.
    try:
        from strix.agents.kg_emit import record_threat_intel_in_kg

        record_threat_intel_in_kg(
            source="domain_reputation",
            asset_type="domain",
            asset_value=target,
            verdict="malicious" if severity in ("high", "critical") else "suspicious",
            detail=title,
            finding_id=report_id,
        )
    except Exception:  # noqa: BLE001
        logger.debug(
            "domain_reputation: ThreatIntel KG emit failed", exc_info=True,
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
# Severity derivation per source
# ---------------------------------------------------------------------------


def _urlhaus_severity(verdict: dict[str, Any]) -> str | None:
    if not verdict.get("listed"):
        return None
    if verdict.get("status") == "active":
        return "high"
    return "low"  # historical


def _spamhaus_dbl_severity(verdict: dict[str, Any]) -> str | None:
    if not verdict.get("listed"):
        return None
    return "medium"


def _spamhaus_zen_severity(verdict: dict[str, Any]) -> str | None:
    if not verdict.get("listed"):
        return None
    return "low"


def _gsb_severity(verdict: dict[str, Any]) -> str | None:
    if not verdict.get("listed"):
        return None
    return "medium"


def _abuseipdb_severity(verdict: dict[str, Any]) -> str | None:
    if not verdict.get("listed"):
        return None
    score = int(verdict.get("abuse_confidence") or 0)
    if score >= 75:
        return "high"
    if score >= 25:
        return "medium"
    if score >= 1:
        return "low"
    return None


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1596"],  # Search Open Technical Databases
)
def domain_reputation(
    target: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Look up a domain or IP across free reputation sources.

    Args:
        target: Domain (e.g. `example.com`) or IPv4 address (e.g.
            `198.51.100.42`). URL-shaped input is auto-stripped to
            its hostname. Private / loopback / link-local IPs are
            rejected.
        timeout: Per-source timeout in seconds (default 12).

    Returns:
        {
          success, target, target_type,
          resolved_ips: [ip, ...],   # for domain targets only
          queried_at, from_cache,
          sources: {
            urlhaus: {listed, status, urls_count, ...} | per-IP
                     {ip, urlhaus: {...}},
            spamhaus_dbl: {listed, codes, kinds, error?},   # domain only
            spamhaus_zen: [{ip, listed, codes, kinds}, ...],  # IP only
            google_safe_browsing: {listed, threats, skipped?, reason?},
            abuseipdb: [{ip, listed, abuse_confidence, ...}, ...],
          },
          findings_emitted, source_errors,
        }

    Findings:
        - **High** (CWE-453, malicious_target) — URLhaus active
          listing OR AbuseIPDB confidence ≥ 75%.
        - **Medium** — Spamhaus DBL listed; Google Safe Browsing
          flagged; AbuseIPDB confidence 25–74%.
        - **Low** — URLhaus historical entry; Spamhaus ZEN listed;
          AbuseIPDB confidence 1–24%.

    Notes:
        - Per-source dedup so multiple URLhaus URLs collapse to ONE
          finding.
        - 6-hour cache under `~/.strix/domain_rep_cache/`. Stale
          cache served on full-source failure (fail-open with
          `error` populated). Disable with
          `STRIX_DOMAIN_REP_NO_CACHE=1`.
        - Composes with cluster-A safety: rate-limit applies to
          outbound HTTP requests.
        - `verification_status=needs_review` since reputation lists
          can carry stale entries; the agent should follow up.
    """
    target_kind, value = _classify_target(target)
    if target_kind == "invalid":
        return {"success": False, "error": f"invalid target (not a domain or public IP): {target!r}"}

    cev = _start_check("domain_reputation", value)

    # ---- Cache ----
    cached = _cache_read(value, fresh_only=True)
    if cached is not None:
        cached["from_cache"] = True
        _complete_check(
            cev,
            result="vulnerable" if cached.get("findings_emitted") else "not_vulnerable",
            evidence=f"{cached.get('findings_emitted', 0)} reputation finding(s) for {value} (cached)",
        )
        return cached

    gsb_key = (os.environ.get("STRIX_GSB_KEY") or "").strip()
    abuseipdb_key = (os.environ.get("STRIX_ABUSEIPDB_KEY") or "").strip()

    sources: dict[str, Any] = {}
    source_errors: dict[str, str] = {}

    # ---- URLhaus on the canonical target ----
    urlhaus = _query_urlhaus(value, timeout)
    if urlhaus.get("error"):
        source_errors["urlhaus"] = urlhaus["error"]
    sources["urlhaus"] = urlhaus

    # ---- IP-only sources ----
    if target_kind == "ip":
        ips_to_check = [value]
        sources["resolved_ips"] = []
    else:
        ips_to_check = _resolve_ips(value)
        sources["resolved_ips"] = ips_to_check

    # ---- Spamhaus DBL (domain only) ----
    if target_kind == "domain":
        dbl = _query_spamhaus_dbl(value)
        if dbl.get("error"):
            source_errors["spamhaus_dbl"] = dbl["error"]
        sources["spamhaus_dbl"] = dbl
    else:
        sources["spamhaus_dbl"] = {"skipped": True, "reason": "target is an IP"}

    # ---- Spamhaus ZEN + AbuseIPDB (per IP) ----
    zen_results: list[dict[str, Any]] = []
    abuse_results: list[dict[str, Any]] = []
    for ip in ips_to_check:
        zen = _query_spamhaus_zen(ip)
        zen.update({"ip": ip})
        if zen.get("error"):
            source_errors[f"spamhaus_zen[{ip}]"] = zen["error"]
        zen_results.append(zen)

        abuse = _query_abuseipdb(ip, abuseipdb_key, timeout)
        abuse.update({"ip": ip})
        if abuse.get("error"):
            source_errors[f"abuseipdb[{ip}]"] = abuse["error"]
        abuse_results.append(abuse)
    sources["spamhaus_zen"] = zen_results
    sources["abuseipdb"] = abuse_results

    # ---- Google Safe Browsing (uses target string directly) ----
    gsb = _query_google_safe_browsing(value, gsb_key, timeout)
    if gsb.get("error"):
        source_errors["google_safe_browsing"] = gsb["error"]
    sources["google_safe_browsing"] = gsb

    # ---- Emit findings ----
    findings_emitted = 0
    seen_keys: set[tuple[str, str]] = set()  # (severity, source-id)

    def _emit_dedup(sev: str, source_id: str, title_suffix: str, desc_extra: str,
                    plain_extra: str, action_extra: str) -> int:
        key = (sev, source_id)
        if key in seen_keys:
            return 0
        seen_keys.add(key)
        title = f"Reputation hit on {value} — {title_suffix}"
        description = (
            f"Source `{source_id}`: {desc_extra}. Target: `{value}` "
            f"({target_kind}). Resolved IPs: {sources.get('resolved_ips')}."
        )
        description_plain = (
            f"Public reputation feed `{source_id}` flags `{value}` as "
            f"malicious. {plain_extra}"
        )
        recommended_action = action_extra
        _emit_finding(
            title=title,
            severity=sev,
            target=value,
            description=description,
            description_plain=description_plain,
            recommended_action=recommended_action,
        )
        return 1

    # URLhaus
    sev = _urlhaus_severity(urlhaus)
    if sev:
        findings_emitted += _emit_dedup(
            sev=sev,
            source_id="urlhaus",
            title_suffix=(
                "active malware listing on URLhaus"
                if sev == "high"
                else "historical malware listing on URLhaus"
            ),
            desc_extra=(
                f"URLhaus reports {urlhaus.get('urls_count')} URL(s) "
                f"associated with this host (active: "
                f"{urlhaus.get('active_urls_count', 0)}). Reference: "
                f"{urlhaus.get('host_reference')}"
            ),
            plain_extra=(
                "An attacker on this host is currently serving "
                "malware. Either the host is compromised or it is "
                "intentionally hosting attack content."
                if sev == "high"
                else "This host has historically served malware; the "
                "current malicious URLs may have been taken down "
                "but the host is on the security community's radar."
            ),
            action_extra=(
                "Treat as compromised: trigger your incident-response "
                "workflow, check for unauthorized access in server "
                "logs, rotate any credentials that touched this host, "
                "rebuild from a known-clean backup. After remediation, "
                "submit a delisting request to URLhaus with evidence "
                "of the cleanup."
            ),
        )

    # Spamhaus DBL
    sev = _spamhaus_dbl_severity(sources.get("spamhaus_dbl") or {})
    if sev:
        dbl = sources["spamhaus_dbl"]
        findings_emitted += _emit_dedup(
            sev=sev,
            source_id="spamhaus_dbl",
            title_suffix=f"Spamhaus DBL listed ({', '.join(dbl.get('kinds') or ['unknown'])})",
            desc_extra=(
                f"DBL return codes: {dbl.get('codes')}. "
                f"Categories: {dbl.get('kinds')}"
            ),
            plain_extra=(
                "Your domain is on Spamhaus's Domain Block List for "
                f"{', '.join(dbl.get('kinds') or ['unknown'])}. Mail "
                "from your domain (or links to your domain) will be "
                "filtered as spam by major mail providers."
            ),
            action_extra=(
                "Identify the root cause (typically: SPF/DMARC misconfig "
                "+ a compromised mailbox sending spam, or a "
                "subdomain redirecting to phishing content). Fix the "
                "underlying issue, then submit a delisting request to "
                "Spamhaus at https://www.spamhaus.org/lookup/."
            ),
        )

    # Spamhaus ZEN per IP — emit one finding per unique severity (low only)
    for entry in zen_results:
        sev = _spamhaus_zen_severity(entry)
        if not sev:
            continue
        findings_emitted += _emit_dedup(
            sev=sev,
            source_id=f"spamhaus_zen[{entry.get('ip')}]",
            title_suffix=f"Spamhaus ZEN listed ({entry.get('ip')})",
            desc_extra=(
                f"ZEN return codes: {entry.get('codes')}. "
                f"Categories: {entry.get('kinds')}"
            ),
            plain_extra=(
                f"IP `{entry.get('ip')}` is on Spamhaus's IP block list."
                " On shared hosting this often signals a noisy "
                "neighbour rather than your own server, but it still "
                "affects mail-deliverability for any service on this IP."
            ),
            action_extra=(
                f"If you control IP {entry.get('ip')}, audit for "
                "compromised mailboxes / outbound spam, fix the root "
                "cause, request delisting at "
                "https://www.spamhaus.org/lookup/. If on shared "
                "hosting, escalate to your hosting provider."
            ),
        )

    # Google Safe Browsing
    sev = _gsb_severity(gsb)
    if sev:
        findings_emitted += _emit_dedup(
            sev=sev,
            source_id="google_safe_browsing",
            title_suffix=f"Google Safe Browsing flagged ({', '.join(gsb.get('threats') or [])})",
            desc_extra=f"Threat types: {gsb.get('threats')}",
            plain_extra=(
                "Google Safe Browsing flags this host. Browsers using "
                "Safe Browsing data (Chrome, Firefox, Safari) will "
                f"warn users when they visit `{value}`."
            ),
            action_extra=(
                "Treat as compromised: scan for malware / phishing "
                "content, audit the file system + recent uploads, "
                "rebuild affected pages from a known-clean source. "
                "After remediation, request review via Google Search "
                "Console (Security Issues → Request review)."
            ),
        )

    # AbuseIPDB per IP — severity reflects the per-IP confidence score
    for entry in abuse_results:
        sev = _abuseipdb_severity(entry)
        if not sev:
            continue
        findings_emitted += _emit_dedup(
            sev=sev,
            source_id=f"abuseipdb[{entry.get('ip')}]",
            title_suffix=(
                f"AbuseIPDB flagged ({entry.get('ip')}, "
                f"confidence={entry.get('abuse_confidence')}%)"
            ),
            desc_extra=(
                f"Confidence score: {entry.get('abuse_confidence')}; "
                f"total reports: {entry.get('total_reports')}; "
                f"last reported: {entry.get('last_reported_at')}"
            ),
            plain_extra=(
                f"AbuseIPDB has {entry.get('total_reports')} community "
                f"reports against IP `{entry.get('ip')}` with "
                f"confidence score {entry.get('abuse_confidence')}%. "
                f"Common causes: brute-force / scanning / spam / DDoS "
                f"originating from this IP."
            ),
            action_extra=(
                f"If you control IP {entry.get('ip')}: investigate for "
                "compromised hosts / containers; rotate any credentials "
                "exposed; rebuild from known-clean state. If on shared "
                "hosting / cloud: escalate to provider; once cleaned, "
                "request delisting at "
                "https://www.abuseipdb.com/myip."
            ),
        )

    result = {
        "success": True,
        "target": value,
        "target_type": target_kind,
        "queried_at": int(time.time()),
        "from_cache": False,
        "sources": sources,
        "source_errors": source_errors,
        "findings_emitted": findings_emitted,
    }

    # If every source failed AND we have nothing fresh, fall back to
    # any stale cache.
    every_source_failed = (
        urlhaus.get("error") is not None
        and all(
            (z.get("error") is not None) for z in zen_results
        )
        and all(
            (a.get("error") is not None) for a in abuse_results
        )
        and (sources.get("google_safe_browsing", {}).get("error") is not None
             or sources.get("google_safe_browsing", {}).get("skipped"))
    )
    if every_source_failed:
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
        evidence=f"{findings_emitted} reputation finding(s) for {value}",
    )
    return result
