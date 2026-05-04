"""AlienVault OTX (Open Threat Exchange) IoC lookup.

For an IoC (IP / domain / hostname / hash / URL / CVE), queries
AT&T's OTX API for the **pulses** that reference it — community-
authored threat-intel records describing campaigns, actors, and
TTPs. Different signal from VirusTotal (#71): VT tells you "57/72
engines flag this as malicious" (consensus); OTX tells you "this
IoC appears in pulse 'APT29 Q4 2024' authored by `<analyst>` along
with 12 other indicators" (attribution + campaign context).

Auto-detects IoC type from input shape:

| IoC type | Detected by | OTX endpoint type |
|---|---|---|
| `IPv4` | parses as IPv4 (private/loopback/link-local rejected) | `IPv4` |
| `IPv6` | parses as IPv6 | `IPv6` |
| `domain` | apex/subdomain regex | `domain` |
| `file-md5` | 32-char hex | `file` |
| `file-sha1` | 40-char hex | `file` |
| `file-sha256` | 64-char hex | `file` |
| `url` | starts with `http://` / `https://` | `url` |
| `CVE` | `CVE-YYYY-NNNN` | `cve` |

API endpoints (all under `https://otx.alienvault.com/api/v1/`):
- `indicators/IPv4/<ip>/general`
- `indicators/IPv6/<ip>/general`
- `indicators/domain/<domain>/general`
- `indicators/file/<hash>/general`
- `indicators/url/<url>/general`
- `indicators/cve/<cve>/general`

Auth via `STRIX_OTX_KEY` env var (free at otx.alienvault.com).
Without it, the tool returns `success=False` with a clear error.
The `X-OTX-API-KEY` header carries the key.

Severity tuning (based on `pulse_info.count` — number of pulses
referencing this IoC):

- **High** (CWE-453, malicious_target) — `pulse_count >= 3`
  (multiple independent analysts have tagged this IoC; strong
  consensus that it's part of attacker infrastructure).
- **Medium** (CWE-453) — `pulse_count` 1-2 (at least one analyst
  flagged it; investigate the pulse for attribution context).
- *(no finding)* — no pulses reference the IoC.

Each finding lists the top 5 pulses (name, author, modified date,
description excerpt) so the agent / user can investigate the
attribution context.

Cache: per-(ioc_type, ioc_value) JSON cache under
`~/.strix/otx_cache/`, 6-hour TTL. Stale-cache served on network
failure (fail-open with `error` populated). Disable with
`STRIX_OTX_NO_CACHE=1`.

Composes with cluster-A safety: rate-limit applies; `--exclude-path`
doesn't apply (URL is otx.alienvault.com, not the customer's
domain).
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
from urllib.parse import quote

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "otx_lookup"
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_CACHE_TTL_SECONDS = 6 * 3600
_OTX_API_BASE = "https://otx.alienvault.com/api/v1/indicators"
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_PULSES_LISTED = 5


_HASH_RE = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,63})+$"
)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


# ---------------------------------------------------------------------------
# IoC type detection
# ---------------------------------------------------------------------------


def _detect_ioc_type(value: str) -> tuple[str, str] | None:
    """Return (ioc_type, normalised_value) or None on invalid.

    ioc_type: 'IPv4' / 'IPv6' / 'domain' / 'file-md5' / 'file-sha1' /
    'file-sha256' / 'url' / 'cve'.
    """
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None

    # URL: explicit scheme.
    lower = raw.lower()
    if lower.startswith(("http://", "https://")):
        return ("url", raw)

    # CVE.
    cve_upper = raw.upper()
    if _CVE_RE.match(cve_upper):
        return ("cve", cve_upper)

    # Hash by hex length.
    if _HASH_RE.match(raw):
        n = len(raw)
        if n == 32:
            return ("file-md5", raw.lower())
        if n == 40:
            return ("file-sha1", raw.lower())
        if n == 64:
            return ("file-sha256", raw.lower())

    # IP.
    try:
        ip = ipaddress.ip_address(raw)
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return None
        if isinstance(ip, ipaddress.IPv4Address):
            return ("IPv4", str(ip))
        return ("IPv6", str(ip))
    except ValueError:
        pass

    # Domain (lowercase, strip trailing dot).
    candidate = raw.rstrip(".").lower()
    if len(candidate) <= 253 and _DOMAIN_RE.match(candidate):
        return ("domain", candidate)

    return None


def _otx_endpoint_for(ioc_type: str, value: str) -> str:
    if ioc_type == "IPv4":
        return f"{_OTX_API_BASE}/IPv4/{value}/general"
    if ioc_type == "IPv6":
        return f"{_OTX_API_BASE}/IPv6/{value}/general"
    if ioc_type == "domain":
        return f"{_OTX_API_BASE}/domain/{value}/general"
    if ioc_type in ("file-md5", "file-sha1", "file-sha256"):
        return f"{_OTX_API_BASE}/file/{value}/general"
    if ioc_type == "url":
        # OTX expects URL-encoded URLs.
        return f"{_OTX_API_BASE}/url/{quote(value, safe='')}/general"
    if ioc_type == "cve":
        return f"{_OTX_API_BASE}/cve/{value}/general"
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
    return Path.home() / ".strix" / "otx_cache"


def _cache_path(ioc_type: str, value: str) -> Path:
    raw = f"{ioc_type}|{value.lower()}"
    safe = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return _cache_dir() / f"{safe}.json"


def _cache_read(ioc_type: str, value: str, *, fresh_only: bool) -> dict[str, Any] | None:
    if os.environ.get("STRIX_OTX_NO_CACHE") == "1":
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
        logger.debug("otx cache read failed: %s", e)
        return None


def _cache_write(ioc_type: str, value: str, payload: dict[str, Any]) -> None:
    if os.environ.get("STRIX_OTX_NO_CACHE") == "1":
        return
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        with _cache_path(ioc_type, value).open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("otx cache write failed: %s", e)


# ---------------------------------------------------------------------------
# Pulse extraction + severity
# ---------------------------------------------------------------------------


def _extract_pulses(pulse_info: Any) -> list[dict[str, Any]]:
    """Pull a curated subset of fields from each pulse (keeps payload
    bounded; never returns the entire OTX response)."""
    if not isinstance(pulse_info, dict):
        return []
    raw_pulses = pulse_info.get("pulses") or []
    if not isinstance(raw_pulses, list):
        return []
    out: list[dict[str, Any]] = []
    for p in raw_pulses[:_MAX_PULSES_LISTED]:
        if not isinstance(p, dict):
            continue
        author_obj = p.get("author") or {}
        out.append({
            "id": p.get("id"),
            "name": p.get("name"),
            "author": (
                author_obj.get("username")
                if isinstance(author_obj, dict)
                else None
            ),
            "modified": p.get("modified"),
            "created": p.get("created"),
            "tags": list(p.get("tags") or []) if isinstance(p.get("tags"), list) else [],
            "description": (p.get("description") or "")[:300],
            "tlp": p.get("TLP"),
            "industries": list(p.get("industries") or []) if isinstance(p.get("industries"), list) else [],
            "targeted_countries": (
                list(p.get("targeted_countries") or [])
                if isinstance(p.get("targeted_countries"), list)
                else []
            ),
        })
    return out


def _derive_severity(pulse_count: int) -> str | None:
    if pulse_count >= 3:
        return "high"
    if pulse_count >= 1:
        return "medium"
    return None


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
            "AlienVault OTX is a free community threat-intel platform "
            "where security researchers publish 'pulses' — curated "
            "indicator lists tied to specific actors / campaigns / "
            "TTPs. When an IoC appears in multiple OTX pulses, it's "
            "attributed to specific threat actors by independent "
            "analysts. Different signal from VirusTotal (consensus "
            "across AV engines): OTX gives the attribution context."
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
def otx_lookup(
    ioc: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Look up an IoC in AlienVault OTX.

    Args:
        ioc: Indicator value. Auto-detected as one of:
            - IPv4 / IPv6 (private/loopback/link-local rejected)
            - Domain (apex / subdomain)
            - MD5 / SHA-1 / SHA-256 hash (hex string)
            - URL (must start with `http://` or `https://`)
            - CVE (`CVE-YYYY-NNNN`)
        timeout: Per-request timeout in seconds (default 15).

    Returns:
        {
          success, ioc, ioc_type, otx_url, queried_at, from_cache,
          pulse_count, severity,
          pulses: [{id, name, author, modified, created, tags,
                    description, tlp, industries,
                    targeted_countries}, ...],
          general: {                # subset of OTX 'general' response
            indicator, type, type_title, false_positive,
            validation, ...
          },
          findings_emitted, error?, no_data?,
        }

    Findings:
        - **High** (CWE-453, malicious_target) — `pulse_count >= 3`
          (multi-analyst attribution).
        - **Medium** (CWE-453) — `pulse_count` 1-2.
        - *(no finding)* — no pulses reference the IoC.

    Notes:
        - Requires `STRIX_OTX_KEY` env var (free at
          otx.alienvault.com).
        - 6-hour cache under `~/.strix/otx_cache/`. Stale-cache
          served on network failure. Cache hit re-emits findings.
          Disable with `STRIX_OTX_NO_CACHE=1`.
        - `verification_status=needs_review` since pulse data is
          community-authored.
    """
    detected = _detect_ioc_type(ioc)
    if detected is None:
        return {
            "success": False,
            "error": (
                f"could not classify IoC {ioc!r}: not an IP, domain, "
                "hash, URL, or CVE (private/loopback/link-local IPs "
                "rejected)"
            ),
        }
    ioc_type, ioc_value = detected

    api_key = (os.environ.get("STRIX_OTX_KEY") or "").strip()
    cev = _start_check("otx_lookup", ioc_value)

    if not api_key:
        _complete_check(cev, "inconclusive", "no STRIX_OTX_KEY")
        return {
            "success": False,
            "ioc": ioc_value,
            "ioc_type": ioc_type,
            "error": "no STRIX_OTX_KEY configured (free at otx.alienvault.com)",
            "findings_emitted": 0,
            "from_cache": False,
        }

    cached = _cache_read(ioc_type, ioc_value, fresh_only=True)
    if cached is not None:
        cached["from_cache"] = True
        emitted = _maybe_emit_from_data(cached, ioc_type, ioc_value)
        cached["findings_emitted"] = emitted
        _complete_check(
            cev,
            result="vulnerable" if emitted else "not_vulnerable",
            evidence=f"OTX cached for {ioc_value}; findings={emitted}",
        )
        return cached

    url = _otx_endpoint_for(ioc_type, ioc_value)
    headers = {
        "Accept": "application/json",
        "X-OTX-API-KEY": api_key,
    }
    response = _http_get(url, headers=headers, timeout=timeout)

    # 404 → "no data on this IoC" (success).
    if response.get("status") == 404 and not response.get("error"):
        result = {
            "success": True,
            "ioc": ioc_value,
            "ioc_type": ioc_type,
            "otx_url": url,
            "queried_at": int(time.time()),
            "from_cache": False,
            "no_data": True,
            "pulse_count": 0,
            "severity": None,
            "pulses": [],
            "general": {},
            "findings_emitted": 0,
        }
        _cache_write(ioc_type, ioc_value, result)
        _complete_check(cev, "not_vulnerable", f"OTX 404 for {ioc_value}")
        return result

    if (
        response.get("error")
        or response.get("status", 0) >= 400
        or response.get("skipped")
    ):
        # Stale-cache fallback.
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
            stale["error"] = f"OTX request failed ({err_text}); served stale cache"
            emitted = _maybe_emit_from_data(stale, ioc_type, ioc_value)
            stale["findings_emitted"] = emitted
            _complete_check(
                cev,
                result="inconclusive",
                evidence=f"OTX failed; stale cache for {ioc_value}",
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
        _complete_check(cev, "inconclusive", f"OTX failed: {err_text}")
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
        _complete_check(cev, "inconclusive", f"OTX invalid JSON: {e}")
        return {
            "success": False,
            "ioc": ioc_value,
            "ioc_type": ioc_type,
            "error": f"OTX invalid JSON: {e}",
            "findings_emitted": 0,
            "from_cache": False,
        }
    if not isinstance(body, dict):
        body = {}

    pulse_info = body.get("pulse_info") or {}
    pulses = _extract_pulses(pulse_info)
    pulse_count = (
        int(pulse_info.get("count") or 0)
        if isinstance(pulse_info, dict)
        else 0
    )
    severity = _derive_severity(pulse_count)

    # Curated subset of `general` fields (capped to bounded payload).
    general_subset: dict[str, Any] = {}
    for key in ("indicator", "type", "type_title", "validation",
                "base_indicator", "false_positive", "asn", "country_code",
                "country_name", "city", "alexa", "whois"):
        if key in body:
            general_subset[key] = body[key]

    result = {
        "success": True,
        "ioc": ioc_value,
        "ioc_type": ioc_type,
        "otx_url": url,
        "queried_at": int(time.time()),
        "from_cache": False,
        "pulse_count": pulse_count,
        "severity": severity,
        "pulses": pulses,
        "general": general_subset,
        "findings_emitted": 0,
    }
    findings_emitted = _maybe_emit_from_data(result, ioc_type, ioc_value)
    result["findings_emitted"] = findings_emitted

    _cache_write(ioc_type, ioc_value, result)

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"OTX: {ioc_value} → {pulse_count} pulse(s), severity={severity}",
    )
    return result


def _maybe_emit_from_data(
    payload: dict[str, Any], ioc_type: str, ioc_value: str
) -> int:
    pulse_count = int(payload.get("pulse_count") or 0)
    severity = _derive_severity(pulse_count)
    if severity is None:
        return 0
    pulses = payload.get("pulses") or []
    pulse_summary = "; ".join(
        f"{p.get('name', '(unnamed)')} (by {p.get('author', '?')}, "
        f"modified {p.get('modified', '?')})"
        for p in pulses
    ) or "(no pulse details)"

    title = (
        f"OTX: {ioc_value} ({ioc_type}) referenced by {pulse_count} "
        f"threat-intel pulse(s)"
    )
    description = (
        f"AlienVault OTX records {pulse_count} pulse(s) referencing "
        f"`{ioc_value}` ({ioc_type}). Top {len(pulses)} pulse(s): "
        f"{pulse_summary}"
    )
    if severity == "high":
        description_plain = (
            f"`{ioc_value}` is referenced in {pulse_count} OTX threat-"
            f"intel pulses — multiple independent analysts have tagged "
            f"this indicator as part of attacker infrastructure. "
            f"Different signal from VirusTotal (multi-vendor consensus): "
            f"OTX gives attribution context — which actor / campaign / "
            f"TTP is associated with this IoC."
        )
        recommended_action = (
            f"Review the top OTX pulses to identify the attributed "
            f"actor / campaign. Cross-reference any IoCs from those "
            f"pulses against your scan findings — if the attacker is "
            f"using a known TTP set, your scan posture should reflect "
            f"that. Consider blocking related infrastructure at the "
            f"perimeter."
        )
    else:  # medium
        description_plain = (
            f"`{ioc_value}` is referenced in {pulse_count} OTX threat-"
            f"intel pulse(s). At least one analyst has flagged this "
            f"indicator. Investigate the pulse to understand the "
            f"attribution context — benign for some pulses (e.g. "
            f"trackers / scanner research), malicious for others."
        )
        recommended_action = (
            f"Review the OTX pulse(s) to understand the attribution. "
            f"If the pulse is from a reputable source (verified author, "
            f"recent modification, malicious-tagged), treat as "
            f"medium-priority threat signal."
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
