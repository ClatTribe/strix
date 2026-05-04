"""VirusTotal IoC reputation lookup.

For an IoC (hash / IP / domain / URL), queries VirusTotal v3 API
and surfaces the multi-engine reputation verdict. Different signal
from the single-source feeds in `domain_reputation` (#63) —
VirusTotal's value is the *consensus* across 70+ AV/EDR vendors.

Auto-detects IoC type from input shape:

| IoC type | Detected by | VT endpoint |
|---|---|---|
| `md5` | 32-char hex | `/api/v3/files/<hash>` |
| `sha1` | 40-char hex | `/api/v3/files/<hash>` |
| `sha256` | 64-char hex | `/api/v3/files/<hash>` |
| `sha512` | 128-char hex | `/api/v3/files/<hash>` |
| `ip` | parses as `ipaddress.ip_address` (no private/loopback/link-local) | `/api/v3/ip_addresses/<ip>` |
| `domain` | apex/subdomain regex | `/api/v3/domains/<domain>` |
| `url` | starts with `http://` / `https://` | `/api/v3/urls/<base64-id>` |

VT response includes `last_analysis_stats: {malicious, suspicious,
harmless, undetected, timeout}` — the per-vendor verdict counts —
plus `last_analysis_results` (the per-vendor names + verdicts) and
the `reputation` score (community-sourced -100…+100).

Severity tuning:
- **High** (CWE-453, malicious_target) — `malicious >= 10` engines
  (high-confidence consensus across many vendors).
- **Medium** (CWE-453) — `malicious + suspicious >= 3` engines (at
  least three vendors flag it; not yet consensus).
- **Low** (CWE-453) — `malicious + suspicious >= 1` engines (any
  vendor flags it).
- *(no finding)* — clean across all vendors.

Auth: `STRIX_VT_KEY` env var. Without it, the tool returns
`success=False` with a clear error so the agent falls back to other
reputation sources (`domain_reputation` #63 single-source feeds).

Cache: per-(ioc_type, ioc_value) JSON cache under
`~/.strix/vt_cache/`, 6-hour TTL. Stale-cache served on network
failure (fail-open with `error` populated). Disable with
`STRIX_VT_NO_CACHE=1`.

VT free-tier rate limits: 4 requests/min, 500/day. The agent should
batch lookups carefully; the throttle isn't enforced by this tool
beyond the cluster-A `--rate-limit` setting.

Composes with cluster-A safety: rate-limit applies to the VT
request; `--exclude-path` doesn't apply (URL is api.virustotal.com,
not the customer's domain).
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
_TOOL_NAME = "vt_reputation"
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_CACHE_TTL_SECONDS = 6 * 3600
_VT_API_BASE = "https://www.virustotal.com/api/v3"
_MAX_RESPONSE_BYTES = 256 * 1024


_HASH_RE = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,63})+$"
)


# ---------------------------------------------------------------------------
# IoC type detection
# ---------------------------------------------------------------------------


def _detect_ioc_type(value: str) -> tuple[str, str] | None:
    """Return ('hash-md5'|'hash-sha1'|'hash-sha256'|'hash-sha512'|'ip'|'domain'|'url',
    normalised_value) or None on invalid."""
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None

    # URL has highest specificity (must start with scheme).
    lower = raw.lower()
    if lower.startswith(("http://", "https://")):
        return ("url", raw)

    # Hash by character set + length.
    if _HASH_RE.match(raw):
        n = len(raw)
        if n == 32:
            return ("hash-md5", raw.lower())
        if n == 40:
            return ("hash-sha1", raw.lower())
        if n == 64:
            return ("hash-sha256", raw.lower())
        if n == 128:
            return ("hash-sha512", raw.lower())
        # Hex-but-not-a-known-length: not a hash.

    # IP — try parsing as ipaddress.
    try:
        ip = ipaddress.ip_address(raw)
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return None
        return ("ip", raw)
    except ValueError:
        pass

    # Domain — strip trailing dot, lower-case.
    candidate = raw.rstrip(".").lower()
    if len(candidate) <= 253 and _DOMAIN_RE.match(candidate):
        return ("domain", candidate)

    return None


def _vt_endpoint_for(ioc_type: str, value: str) -> str:
    if ioc_type.startswith("hash-"):
        return f"{_VT_API_BASE}/files/{value}"
    if ioc_type == "ip":
        return f"{_VT_API_BASE}/ip_addresses/{value}"
    if ioc_type == "domain":
        return f"{_VT_API_BASE}/domains/{value}"
    if ioc_type == "url":
        # VT's URL API takes a URL-safe-base64 of the URL with no padding.
        encoded = base64.urlsafe_b64encode(value.encode("utf-8")).rstrip(b"=").decode("ascii")
        return f"{_VT_API_BASE}/urls/{encoded}"
    raise ValueError(f"unknown ioc_type: {ioc_type}")


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
# Cache
# ---------------------------------------------------------------------------


def _cache_dir() -> Path:
    return Path.home() / ".strix" / "vt_cache"


def _cache_path(ioc_type: str, value: str) -> Path:
    raw = f"{ioc_type}|{value.lower()}"
    safe = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return _cache_dir() / f"{safe}.json"


def _cache_read(ioc_type: str, value: str, *, fresh_only: bool) -> dict[str, Any] | None:
    if os.environ.get("STRIX_VT_NO_CACHE") == "1":
        return None
    path = _cache_path(ioc_type, value)
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
        logger.debug("vt_reputation cache read failed: %s", e)
        return None


def _cache_write(ioc_type: str, value: str, payload: dict[str, Any]) -> None:
    if os.environ.get("STRIX_VT_NO_CACHE") == "1":
        return
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        with _cache_path(ioc_type, value).open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("vt_reputation cache write failed: %s", e)


# ---------------------------------------------------------------------------
# Severity tuning
# ---------------------------------------------------------------------------


def _derive_severity(stats: dict[str, Any]) -> tuple[str | None, dict[str, int]]:
    """Return (severity, normalized_stats) where severity ∈
    {high, medium, low, None}."""
    if not isinstance(stats, dict):
        return None, {}
    norm = {
        "malicious": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "harmless": int(stats.get("harmless") or 0),
        "undetected": int(stats.get("undetected") or 0),
        "timeout": int(stats.get("timeout") or 0),
    }
    flagged = norm["malicious"] + norm["suspicious"]
    if norm["malicious"] >= 10:
        return "high", norm
    if flagged >= 3:
        return "medium", norm
    if flagged >= 1:
        return "low", norm
    return None, norm


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
            "VirusTotal aggregates reputation verdicts from 70+ "
            "AV/EDR vendors. A consensus signal (multiple engines "
            "flagging the same IoC) is a strong indicator that the "
            "asset is on attacker-of-the-day lists, distributing "
            "malware, hosting phishing kits, or otherwise tainted. "
            "Different signal from single-source blocklists "
            "(URLhaus / AbuseIPDB / Spamhaus) — VT's value is the "
            "*number* of vendors that converge."
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
def vt_reputation(
    ioc: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Look up an IoC in VirusTotal.

    Args:
        ioc: Indicator value. Auto-detected as one of:
            - MD5 / SHA-1 / SHA-256 / SHA-512 hash (hex string of
              32 / 40 / 64 / 128 chars)
            - IPv4 / IPv6 address (private / loopback / link-local
              rejected)
            - Domain (apex / subdomain shape)
            - URL (must start with `http://` or `https://`)
        timeout: Per-request timeout in seconds (default 15).

    Returns:
        {
          success, ioc, ioc_type, vt_url, queried_at, from_cache,
          stats: {malicious, suspicious, harmless, undetected, timeout},
          severity: high | medium | low | None,
          reputation: int,           # community-sourced -100…+100
          flagging_engines: [name, ...],   # vendors that flagged it
          attributes: {              # subset of VT's data shape
            last_analysis_date, last_modification_date,
            country_code (IPs), as_owner (IPs), categories (URLs),
            ...
          },
          findings_emitted, error?,
        }

    Findings:
        - **High** (CWE-453, malicious_target) — `malicious >= 10`.
        - **Medium** (CWE-453) — `malicious + suspicious >= 3`.
        - **Low** (CWE-453) — `malicious + suspicious >= 1`.

    Notes:
        - Requires `STRIX_VT_KEY` env var. Without it, returns
          `success=False` with a clear error.
        - 6-hour cache under `~/.strix/vt_cache/`. Stale cache
          served on network failure. Disable with
          `STRIX_VT_NO_CACHE=1`.
        - VT free-tier rate limits: 4 req/min, 500/day. Cluster-A
          rate-limit applies; daily budget is the user's
          responsibility.
        - `verification_status=needs_review` since reputation
          verdicts can carry stale data.
    """
    detected = _detect_ioc_type(ioc)
    if detected is None:
        return {
            "success": False,
            "error": (
                f"could not classify IoC {ioc!r}: not a hash, IP, "
                "domain, or URL (private / loopback / link-local IPs "
                "rejected)"
            ),
        }
    ioc_type, ioc_value = detected

    api_key = (os.environ.get("STRIX_VT_KEY") or "").strip()
    cev = _start_check("vt_reputation", ioc_value)

    if not api_key:
        _complete_check(cev, "inconclusive", "no STRIX_VT_KEY")
        return {
            "success": False,
            "ioc": ioc_value,
            "ioc_type": ioc_type,
            "error": "no STRIX_VT_KEY configured (free tier available at virustotal.com)",
            "findings_emitted": 0,
            "from_cache": False,
        }

    cached = _cache_read(ioc_type, ioc_value, fresh_only=True)
    if cached is not None:
        cached["from_cache"] = True
        # Re-emit findings from cached stats.
        emitted = _maybe_emit_from_data(
            cached.get("stats") or {},
            cached.get("flagging_engines") or [],
            cached.get("attributes") or {},
            ioc_type, ioc_value,
        )
        cached["findings_emitted"] = emitted
        _complete_check(
            cev,
            result="vulnerable" if emitted else "not_vulnerable",
            evidence=f"VT result for {ioc_type}/{ioc_value} (cached); findings={emitted}",
        )
        return cached

    url = _vt_endpoint_for(ioc_type, ioc_value)
    headers = {
        "Accept": "application/json",
        "x-apikey": api_key,
    }
    response = _http_get(url, headers=headers, timeout=timeout)

    # 404 = "VT hasn't seen this IoC" — treat as success with empty
    # stats. Must come BEFORE the generic >= 400 failure path.
    if response.get("status") == 404 and not response.get("error"):
        result = {
            "success": True,
            "ioc": ioc_value,
            "ioc_type": ioc_type,
            "vt_url": url,
            "queried_at": int(time.time()),
            "from_cache": False,
            "stats": {},
            "severity": None,
            "reputation": 0,
            "flagging_engines": [],
            "attributes": {},
            "findings_emitted": 0,
            "no_data": True,
        }
        _cache_write(ioc_type, ioc_value, result)
        _complete_check(cev, "not_vulnerable", f"VT 404 for {ioc_value} (no data)")
        return result

    # Failure → fall back to stale cache when present.
    if (
        response.get("error")
        or response.get("status", 0) >= 400
        or response.get("skipped")
    ):
        stale = _cache_read(ioc_type, ioc_value, fresh_only=False)
        if stale is not None:
            stale["from_cache"] = True
            err_text = (
                response.get("error")
                or (
                    "filtered by --exclude-path"
                    if response.get("skipped")
                    else f"HTTP {response.get('status')}"
                )
            )
            stale["error"] = f"VT request failed ({err_text}); served stale cache"
            emitted = _maybe_emit_from_data(
                stale.get("stats") or {},
                stale.get("flagging_engines") or [],
                stale.get("attributes") or {},
                ioc_type, ioc_value,
            )
            stale["findings_emitted"] = emitted
            _complete_check(
                cev,
                result="inconclusive",
                evidence=f"VT failed; stale cache for {ioc_value}",
            )
            return stale
        err_text = (
            response.get("error")
            or (
                "filtered by --exclude-path"
                if response.get("skipped")
                else f"HTTP {response.get('status')}"
            )
        )
        _complete_check(cev, "inconclusive", f"VT failed: {err_text}")
        return {
            "success": False,
            "ioc": ioc_value,
            "ioc_type": ioc_type,
            "error": err_text,
            "findings_emitted": 0,
            "from_cache": False,
        }

    try:
        body = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError) as e:
        _complete_check(cev, "inconclusive", f"VT invalid JSON: {e}")
        return {
            "success": False,
            "ioc": ioc_value,
            "ioc_type": ioc_type,
            "error": f"VT invalid JSON: {e}",
            "findings_emitted": 0,
            "from_cache": False,
        }

    data = body.get("data") if isinstance(body, dict) else None
    attributes: dict[str, Any] = {}
    if isinstance(data, dict):
        raw_attrs = data.get("attributes")
        if isinstance(raw_attrs, dict):
            attributes = raw_attrs

    stats = attributes.get("last_analysis_stats") or {}
    if not isinstance(stats, dict):
        stats = {}

    flagging_engines: list[str] = []
    results_obj = attributes.get("last_analysis_results")
    if isinstance(results_obj, dict):
        for engine_name, engine_data in results_obj.items():
            if not isinstance(engine_data, dict):
                continue
            verdict = (engine_data.get("category") or "").lower()
            if verdict in ("malicious", "suspicious"):
                flagging_engines.append(str(engine_name))

    reputation = int(attributes.get("reputation") or 0)

    # Subset of attributes that are useful for the agent without
    # leaking the entire VT response.
    attrs_subset: dict[str, Any] = {}
    for key in (
        "last_analysis_date",
        "last_modification_date",
        "country",
        "country_code",
        "as_owner",
        "asn",
        "categories",
        "tld",
        "creation_date",
        "registrar",
        "names",
    ):
        if key in attributes:
            attrs_subset[key] = attributes[key]

    severity, norm_stats = _derive_severity(stats)

    result = {
        "success": True,
        "ioc": ioc_value,
        "ioc_type": ioc_type,
        "vt_url": url,
        "queried_at": int(time.time()),
        "from_cache": False,
        "stats": norm_stats,
        "severity": severity,
        "reputation": reputation,
        "flagging_engines": sorted(set(flagging_engines)),
        "attributes": attrs_subset,
        "findings_emitted": 0,
    }

    findings_emitted = _maybe_emit_from_data(
        norm_stats, result["flagging_engines"], attrs_subset, ioc_type, ioc_value,
    )
    result["findings_emitted"] = findings_emitted

    _cache_write(ioc_type, ioc_value, result)

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"VT verdict for {ioc_type}/{ioc_value}: {severity}",
    )
    return result


def _maybe_emit_from_data(
    stats: dict[str, Any],
    flagging_engines: list[str],
    attributes: dict[str, Any],
    ioc_type: str,
    ioc_value: str,
) -> int:
    severity, norm_stats = _derive_severity(stats)
    if severity is None:
        return 0
    flagging_text = ", ".join(flagging_engines[:8]) or "(none captured)"
    if len(flagging_engines) > 8:
        flagging_text += f", +{len(flagging_engines) - 8} more"
    title = (
        f"VirusTotal flags `{ioc_value}` ({ioc_type}) — "
        f"{norm_stats.get('malicious', 0)} malicious / "
        f"{norm_stats.get('suspicious', 0)} suspicious"
    )
    description = (
        f"VirusTotal: malicious={norm_stats.get('malicious', 0)}, "
        f"suspicious={norm_stats.get('suspicious', 0)}, "
        f"harmless={norm_stats.get('harmless', 0)}, "
        f"undetected={norm_stats.get('undetected', 0)}. "
        f"Flagging vendors: {flagging_text}. "
        f"Attributes: {attributes}."
    )
    description_plain = (
        f"VirusTotal aggregates verdicts from 70+ AV/EDR vendors. "
        f"For `{ioc_value}`, "
        f"{norm_stats.get('malicious', 0)} flag it as malicious and "
        f"{norm_stats.get('suspicious', 0)} as suspicious. "
        f"This is a multi-vendor consensus signal, distinct from "
        f"single-source blocklists."
    )
    if severity == "high":
        recommended_action = (
            "Treat as compromised: trigger incident-response, "
            "rebuild from a known-clean state for any host on this "
            f"IoC ({ioc_value}), rotate any credentials that "
            f"touched it. After remediation, request a re-scan via "
            f"VirusTotal so the verdict can clear."
        )
    elif severity == "medium":
        recommended_action = (
            "Investigate: cross-reference the flagging vendors' "
            f"detection names against your tooling. If the IoC is on "
            f"shared infrastructure, escalate to your hosting "
            f"provider; if on your own infra, audit for compromise."
        )
    else:
        recommended_action = (
            "Note as informational. A single-vendor flag may be a "
            "false positive; cross-reference with other reputation "
            "sources (URLhaus / AbuseIPDB / Spamhaus via "
            "`domain_reputation`) before acting."
        )
    _emit_finding(
        title=title,
        severity=severity,
        target=ioc_value,
        description=description,
        description_plain=description_plain,
        recommended_action=recommended_action,
    )
    return 1
