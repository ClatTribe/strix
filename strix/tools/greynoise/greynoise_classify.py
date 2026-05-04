"""GreyNoise targeted-vs-noise classification.

For an IPv4 address, queries GreyNoise's free Community API to
determine whether the IP is opportunistic-internet-noise or a
targeted attacker:

| Signal | Meaning |
|---|---|
| `noise: true, classification: benign` | Known-benign mass scanner (Shodan, Censys, search-engine bots) |
| `noise: true, classification: malicious` | Mass scanner that's also been observed performing malicious activity |
| `noise: true, classification: unknown` | Mass scanner — not yet classified |
| `noise: false, classification: malicious` | **Targeted attacker** (this IP isn't mass-scanning everyone, it's specifically interacting with you / a small subset) |
| `noise: false, classification: benign` | Targeted-but-benign (e.g. legitimate enterprise scanner) |
| `noise: false` (no record) | GreyNoise has no observation of this IP |

Plus the **RIOT** ("Rule It Out") signal: when an IP is on a known-
benign list (Apple iCloud relay, Cloudflare, Akamai edge, Microsoft
365, etc.), the response carries `riot: true` with a `name` /
`category` field describing what the IP belongs to. RIOT lets the
agent suppress alerts that are demonstrably benign infrastructure.

Severity tuning:

- **High** (CWE-453, malicious_target) — `noise: false, classification:
  malicious` (targeted malicious — this IP is specifically attacking
  you, not background scanning).
- **Medium** (CWE-453) — `noise: true, classification: malicious`
  (opportunistic but flagged-malicious mass scanner).
- *(no finding)* — `noise: true, classification: benign` (Shodan etc.),
  RIOT-listed benign IPs, or no observation. The IP is treated as
  background internet noise and shouldn't generate triage work.

Auth: optional `STRIX_GREYNOISE_KEY` for the paid tier (richer
per-IP context, higher rate limit). Without it, falls back to the
free Community API which doesn't require auth but has limited
fields. RIOT API requires the paid key — skipped silently when
absent.

Cache: per-IP JSON cache under `~/.strix/greynoise_cache/`,
6-hour TTL. Stale-cache served on network failure (fail-open with
`error` populated). Disable with `STRIX_GREYNOISE_NO_CACHE=1`.

Composes with cluster-A safety: rate-limit applies; `--exclude-path`
doesn't apply (URLs are api.greynoise.io, not the customer's domain).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "greynoise_classify"
_DEFAULT_TIMEOUT = 12.0
_DEFAULT_CACHE_TTL_SECONDS = 6 * 3600
_GREYNOISE_COMMUNITY_API = "https://api.greynoise.io/v3/community"
_GREYNOISE_RIOT_API = "https://api.greynoise.io/v2/riot"
_MAX_RESPONSE_BYTES = 64 * 1024


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------


def _validate_ip(value: str) -> str | None:
    """Return canonical IPv4 string or None on invalid / private."""
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if not isinstance(ip, ipaddress.IPv4Address):
        return None
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return None
    return str(ip)


# ---------------------------------------------------------------------------
# HTTP helper (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_get(
    url: str, *, headers: dict[str, str] | None = None, timeout: float = _DEFAULT_TIMEOUT
) -> dict[str, Any]:
    """GET via cluster-A safety. Returns {status, headers, body, error?}."""
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
                "body": r.text[:_MAX_RESPONSE_BYTES],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# GreyNoise queries
# ---------------------------------------------------------------------------


def _query_community(
    ip: str, api_key: str, timeout: float
) -> dict[str, Any]:
    """Query the Community v3 API. Returns {present, noise, classification,
    name, link, last_seen, riot, error?}."""
    url = f"{_GREYNOISE_COMMUNITY_API}/{ip}"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["key"] = api_key  # GreyNoise uses `key` header
    response = _http_get(url, headers=headers, timeout=timeout)
    if response.get("error"):
        return {"present": False, "error": f"GreyNoise community failed: {response['error']}"}
    if response.get("status", 0) == 404:
        return {"present": False, "status": 404}  # no observation
    if response.get("status", 0) == 401:
        return {"present": False, "error": "GreyNoise community: 401 (invalid key)"}
    if response.get("status", 0) == 429:
        return {"present": False, "error": "GreyNoise community: 429 (rate-limited)"}
    if response.get("status", 0) != 200:
        return {"present": False, "error": f"GreyNoise community status {response.get('status')}"}
    try:
        body = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError) as e:
        return {"present": False, "error": f"GreyNoise community invalid JSON: {e}"}
    if not isinstance(body, dict):
        return {"present": False, "error": "GreyNoise community: unexpected shape"}

    # Community API "code" field: "0x00" = unobserved; non-zero = observed.
    code = str(body.get("code") or "")
    message = body.get("message")
    if code in ("0x00",) or (message and "not seen" in str(message).lower()):
        return {"present": False, "code": code, "message": message}

    return {
        "present": True,
        "noise": bool(body.get("noise") or False),
        "classification": (body.get("classification") or "").lower(),
        "name": body.get("name"),
        "link": body.get("link"),
        "last_seen": body.get("last_seen"),
        "riot": bool(body.get("riot") or False),
        "code": code,
        "message": message,
    }


def _query_riot(
    ip: str, api_key: str, timeout: float
) -> dict[str, Any]:
    """Query the RIOT v2 API (paid-key-only). Returns {present, name,
    category, trust_level, description, error?}."""
    if not api_key:
        return {
            "present": False,
            "skipped": True,
            "reason": "no STRIX_GREYNOISE_KEY — RIOT API skipped",
        }
    url = f"{_GREYNOISE_RIOT_API}/{ip}"
    headers = {"Accept": "application/json", "key": api_key}
    response = _http_get(url, headers=headers, timeout=timeout)
    if response.get("error"):
        return {"present": False, "error": f"GreyNoise RIOT failed: {response['error']}"}
    if response.get("status", 0) == 404:
        return {"present": False, "status": 404}  # not on RIOT list
    if response.get("status", 0) == 401:
        return {"present": False, "error": "GreyNoise RIOT: 401 (invalid key)"}
    if response.get("status", 0) == 429:
        return {"present": False, "error": "GreyNoise RIOT: 429 (rate-limited)"}
    if response.get("status", 0) != 200:
        return {"present": False, "error": f"GreyNoise RIOT status {response.get('status')}"}
    try:
        body = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError) as e:
        return {"present": False, "error": f"GreyNoise RIOT invalid JSON: {e}"}
    if not isinstance(body, dict):
        return {"present": False, "error": "GreyNoise RIOT: unexpected shape"}
    if not body.get("riot"):
        return {"present": False}
    return {
        "present": True,
        "name": body.get("name"),
        "category": body.get("category"),
        "trust_level": body.get("trust_level"),
        "description": body.get("description"),
        "last_updated": body.get("last_updated"),
    }


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def _cache_dir() -> Path:
    return Path.home() / ".strix" / "greynoise_cache"


def _cache_path(ip: str) -> Path:
    safe = hashlib.sha256(ip.encode("utf-8")).hexdigest()[:16]
    return _cache_dir() / f"{safe}.json"


def _cache_read(ip: str, *, fresh_only: bool) -> dict[str, Any] | None:
    if os.environ.get("STRIX_GREYNOISE_NO_CACHE") == "1":
        return None
    path = _cache_path(ip)
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
        logger.debug("greynoise cache read failed: %s", e)
        return None


def _cache_write(ip: str, payload: dict[str, Any]) -> None:
    if os.environ.get("STRIX_GREYNOISE_NO_CACHE") == "1":
        return
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        with _cache_path(ip).open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("greynoise cache write failed: %s", e)


# ---------------------------------------------------------------------------
# Severity derivation
# ---------------------------------------------------------------------------


def _derive_severity(community: dict[str, Any]) -> str | None:
    """Map (noise, classification) → severity tier, or None for "no
    finding"."""
    if not community.get("present"):
        return None
    noise = bool(community.get("noise"))
    classification = (community.get("classification") or "").lower()
    if not noise and classification == "malicious":
        return "high"  # targeted attacker
    if noise and classification == "malicious":
        return "medium"  # opportunistic but malicious
    return None  # noise:benign, no observation, etc.


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
    tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="malicious_target",
        cwe="CWE-453",
        target=target,
        endpoint=target,
        description=description,
        impact=(
            "GreyNoise observes mass internet scanning across a "
            "global sensor network. The `noise` flag distinguishes "
            "an IP that's hitting everyone (background internet "
            "scanning) from one that's specifically interacting with "
            "the customer (targeted attacker). Combined with "
            "`classification` (benign / malicious / unknown), this "
            "is the canonical IR-triage signal: opportunistic noise "
            "doesn't need investigation; targeted-malicious IPs do."
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


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1596"],  # Search Open Technical Databases
)
def greynoise_classify(
    ip: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Classify an IPv4 address as targeted-attacker / opportunistic-
    noise / benign-known via GreyNoise.

    Args:
        ip: IPv4 address (private / loopback / link-local rejected).
        timeout: Per-request timeout in seconds (default 12).

    Returns:
        {
          success, ip, queried_at, from_cache,
          community: {present, noise, classification, name, link,
                      last_seen, riot, code, message, error?},
          riot: {present, name, category, trust_level, description,
                 last_updated, error?, skipped?, reason?},
          severity: high | medium | None,
          findings_emitted, error?,
        }

    Findings:
        - **High** (CWE-453, malicious_target) — `noise: false,
          classification: malicious` (**targeted attacker**).
        - **Medium** (CWE-453) — `noise: true, classification:
          malicious` (mass scanner, but flagged as malicious).
        - *(no finding)* — `noise: true, classification: benign`
          (Shodan / Censys / etc.), RIOT-listed benign IPs, or no
          observation.

    Notes:
        - Community API works without a key (anonymous tier);
          `STRIX_GREYNOISE_KEY` (paid tier) raises rate limit + adds
          richer per-IP context. RIOT API requires the paid key —
          silently skipped without it.
        - 6-hour cache under `~/.strix/greynoise_cache/`. Stale-
          cache served on network failure. Disable with
          `STRIX_GREYNOISE_NO_CACHE=1`.
        - `verification_status=needs_review`: classifications can
          shift as GreyNoise observes more activity.
    """
    canonical_ip = _validate_ip(ip)
    if canonical_ip is None:
        return {
            "success": False,
            "error": (
                f"invalid IPv4 address: {ip!r} (private / loopback / "
                "link-local / IPv6 rejected; only public IPv4 supported)"
            ),
        }

    cev = _start_check("greynoise_classify", canonical_ip)
    api_key = (os.environ.get("STRIX_GREYNOISE_KEY") or "").strip()

    cached = _cache_read(canonical_ip, fresh_only=True)
    if cached is not None:
        cached["from_cache"] = True
        emitted = _maybe_emit_from_data(cached, canonical_ip)
        cached["findings_emitted"] = emitted
        _complete_check(
            cev,
            result="vulnerable" if emitted else "not_vulnerable",
            evidence=f"GreyNoise verdict for {canonical_ip} (cached); findings={emitted}",
        )
        return cached

    community = _query_community(canonical_ip, api_key, timeout)
    riot = _query_riot(canonical_ip, api_key, timeout)

    # Stale-cache fallback when both endpoints failed.
    if community.get("error") and (riot.get("error") or riot.get("skipped")):
        stale = _cache_read(canonical_ip, fresh_only=False)
        if stale is not None:
            stale["from_cache"] = True
            stale["error"] = (
                f"GreyNoise request failed (community: {community.get('error')}); "
                "served stale cache"
            )
            emitted = _maybe_emit_from_data(stale, canonical_ip)
            stale["findings_emitted"] = emitted
            _complete_check(
                cev,
                result="inconclusive",
                evidence=f"GreyNoise failed; stale cache for {canonical_ip}",
            )
            return stale

    severity = _derive_severity(community)

    result = {
        "success": True,
        "ip": canonical_ip,
        "queried_at": int(time.time()),
        "from_cache": False,
        "community": community,
        "riot": riot,
        "severity": severity,
        "findings_emitted": 0,
    }
    findings_emitted = _maybe_emit_from_data(result, canonical_ip)
    result["findings_emitted"] = findings_emitted

    _cache_write(canonical_ip, result)

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"GreyNoise: {canonical_ip} → severity={severity}",
    )
    return result


def _maybe_emit_from_data(payload: dict[str, Any], canonical_ip: str) -> int:
    community = payload.get("community") or {}
    severity = _derive_severity(community)
    if severity is None:
        return 0
    classification = (community.get("classification") or "unknown").lower()
    noise = bool(community.get("noise"))
    name = community.get("name") or "(unnamed)"

    if severity == "high":
        title = (
            f"GreyNoise: targeted-malicious activity from {canonical_ip} "
            f"(`{name}`)"
        )
        description = (
            f"GreyNoise classifies `{canonical_ip}` as targeted "
            f"(noise=False) + classification=malicious. Tag: "
            f"`{name}`. Last seen: {community.get('last_seen')}. "
            f"Reference: {community.get('link')}"
        )
        description_plain = (
            f"`{canonical_ip}` is specifically targeting you (it's not "
            "background internet noise) and GreyNoise's sensor "
            "network has flagged it as malicious. This is the highest-"
            "priority IR signal — not opportunistic mass scanning."
        )
        recommended_action = (
            "Investigate as a targeted attack. Review your scan / "
            "WAF / IDS logs for activity from this IP, correlate "
            "against your scan findings, and consider blocking the IP "
            "at the perimeter while you investigate. Cross-reference "
            "with VirusTotal (`vt_reputation`) for additional vendor "
            "verdicts."
        )
    else:  # medium
        title = (
            f"GreyNoise: opportunistic-malicious mass scanner "
            f"{canonical_ip} (`{name}`)"
        )
        description = (
            f"GreyNoise classifies `{canonical_ip}` as opportunistic "
            f"(noise=True) but malicious. Tag: `{name}`. Last seen: "
            f"{community.get('last_seen')}. Reference: "
            f"{community.get('link')}"
        )
        description_plain = (
            f"`{canonical_ip}` is mass-scanning the internet (background "
            "noise) AND GreyNoise has flagged it as malicious. The "
            "scan is opportunistic rather than targeted — they're "
            "scanning everyone, not just you — but they're known to "
            "be hostile."
        )
        recommended_action = (
            "Lower-priority than a targeted attacker, but still "
            "worth blocking at the WAF / firewall. Add to your "
            "denylist if you maintain one. The fact that they're "
            "mass-scanning means they'll likely return when they "
            "rotate IPs."
        )

    _emit_finding(
        title=title,
        severity=severity,
        target=canonical_ip,
        description=description,
        description_plain=description_plain,
        recommended_action=recommended_action,
    )
    return 1
