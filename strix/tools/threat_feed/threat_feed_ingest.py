"""Threat-intelligence feed ingestion (MISP / STIX 2.x / TAXII 2.1).

Fetches a JSON feed URL and extracts indicators-of-compromise (IoCs)
in a uniform shape regardless of the source format. Three formats
auto-detected:

| Format | Detection signal | Extraction path |
|---|---|---|
| **MISP** | response wraps an `Event` / has `Attribute[]` array | `Attribute.type` ∈ {ip-src, ip-dst, domain, hostname, url, md5, sha1, sha256, ...}; value from `Attribute.value` |
| **STIX 2.x bundle** | `"type": "bundle"` + `"objects": [...]` with `"type": "indicator"` | parse `pattern` field (`[ipv4-addr:value = '1.2.3.4']`, etc.) |
| **TAXII 2.1 collection** | `"objects": [...]` with `"id": "indicator--<uuid>"` shape | same as STIX 2.x indicators |

When `target_filter` is supplied (a domain or IP), each extracted IoC
is matched against it. **Domain match**: equality OR suffix (`.target`).
**IP match**: exact-string. Each match emits an info finding so the
agent can prioritise scan posture against the customer's threat
model.

Auth: the tool accepts an optional `auth_token` (bearer / API key)
or `auth_basic` (`user:pass`). For MISP, the typical auth is
`Authorization: <api-key>` (no `Bearer` prefix); we send `auth_token`
verbatim as that header. For TAXII / STIX servers, `auth_basic` is
the common shape.

Cache: per-(feed_url, auth fingerprint) JSON cache under
`~/.strix/threat_feed_cache/`, 1-hour TTL (threat-intel feeds change
fast; shorter than other intel tools). Stale cache served on
network failure (fail-open). Disable with
`STRIX_THREAT_FEED_NO_CACHE=1`.

Composes with cluster-A safety: rate-limit applies; exclude-path is
no-op since URLs target the threat-intel server, not the customer.
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
_TOOL_NAME = "threat_feed_ingest"
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_CACHE_TTL_SECONDS = 1 * 3600
_DEFAULT_MAX_RECORDS = 500
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024  # 8 MiB cap (large feeds are common)


# ---------------------------------------------------------------------------
# IoC type normalization
# ---------------------------------------------------------------------------


# MISP attribute types we care about, mapped to a normalised IoC type.
_MISP_TYPE_MAP: dict[str, str] = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip",
    "ip-dst|port": "ip",
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "url": "url",
    "uri": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "filename|md5": "md5",
    "filename|sha1": "sha1",
    "filename|sha256": "sha256",
    "email-src": "email",
    "email-dst": "email",
    "regkey": "regkey",
    "x509-fingerprint-sha1": "x509-sha1",
    "x509-fingerprint-sha256": "x509-sha256",
}


# STIX 2.x pattern → IoC extraction. Patterns look like
# `[ipv4-addr:value = '1.2.3.4']` or `[file:hashes.'SHA-256' = 'abc']`.
_STIX_PATTERN_RE = re.compile(
    r"\[(?P<type>[a-z0-9:.\-_'\"]+?)\s*=\s*'(?P<value>[^']+)'\]",
    re.IGNORECASE,
)
_STIX_PATTERN_MULTI_RE = re.compile(
    r"(?:\[(?P<type>[a-z0-9:.\-_'\"]+?)\s*=\s*'(?P<value>[^']+)'\]\s*(?:OR|AND)?\s*)",
    re.IGNORECASE,
)


def _stix_object_path_to_ioc_type(path: str) -> str | None:
    """Normalise a STIX `<sco>:<field>` path to one of our IoC types.

    Examples:
        `ipv4-addr:value` → `ip`
        `domain-name:value` → `domain`
        `url:value` → `url`
        `file:hashes.'SHA-256'` → `sha256`
        `email-addr:value` → `email`
    """
    p = path.strip().lower().strip("'\"")
    if p.startswith("ipv4-addr:") or p.startswith("ipv6-addr:"):
        return "ip"
    if p.startswith("domain-name:") or p.startswith("hostname:"):
        return "domain"
    if p.startswith("url:"):
        return "url"
    if p.startswith("email-addr:"):
        return "email"
    if "hashes." in p:
        # file:hashes.'SHA-256' → sha256
        suffix = p.split("hashes.", 1)[1].strip().strip("'\"").lower()
        suffix = suffix.replace("-", "")
        if suffix in {"md5", "sha1", "sha256", "sha512"}:
            return suffix
    return None


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
    return Path.home() / ".strix" / "threat_feed_cache"


def _cache_key(feed_url: str, auth_fp: str) -> str:
    raw = f"{feed_url.lower()}|{auth_fp}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _auth_fingerprint(auth_token: str, auth_basic: str) -> str:
    """Stable, non-reversible fingerprint of the auth so cache keys
    don't collide across users. We hash the auth material rather than
    storing it."""
    if not auth_token and not auth_basic:
        return "anon"
    return hashlib.sha256(
        f"{auth_token}|{auth_basic}".encode("utf-8"),
    ).hexdigest()[:8]


def _cache_path(feed_url: str, auth_fp: str) -> Path:
    return _cache_dir() / f"{_cache_key(feed_url, auth_fp)}.json"


def _cache_read(feed_url: str, auth_fp: str, *, fresh_only: bool) -> dict[str, Any] | None:
    if os.environ.get("STRIX_THREAT_FEED_NO_CACHE") == "1":
        return None
    path = _cache_path(feed_url, auth_fp)
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
        logger.debug("threat_feed cache read failed: %s", e)
        return None


def _cache_write(feed_url: str, auth_fp: str, payload: dict[str, Any]) -> None:
    if os.environ.get("STRIX_THREAT_FEED_NO_CACHE") == "1":
        return
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        with _cache_path(feed_url, auth_fp).open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("threat_feed cache write failed: %s", e)


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


def _detect_format(payload: Any) -> str:
    """Return one of: 'misp', 'stix2_bundle', 'taxii2_collection',
    'unknown'."""
    if not isinstance(payload, dict):
        return "unknown"

    # MISP rest-search responses: {"response": [{"Event": {...}}]}, OR
    # event-export: {"Event": {"Attribute": [...]}}, OR
    # attribute-rest-search: {"response": {"Attribute": [...]}}.
    if "response" in payload:
        return "misp"
    if "Event" in payload and isinstance(payload["Event"], dict):
        return "misp"

    # STIX 2.x bundle: {"type": "bundle", "objects": [...]}.
    if payload.get("type") == "bundle" and isinstance(payload.get("objects"), list):
        return "stix2_bundle"

    # TAXII 2.1 collection: {"objects": [...]} with indicator-shaped IDs.
    objs = payload.get("objects")
    if isinstance(objs, list) and objs:
        first = objs[0] if isinstance(objs[0], dict) else None
        if first and isinstance(first.get("id"), str) and first["id"].startswith("indicator--"):
            return "taxii2_collection"

    return "unknown"


# ---------------------------------------------------------------------------
# Extractors per format
# ---------------------------------------------------------------------------


def _extract_misp(payload: dict[str, Any], cap: int) -> list[dict[str, Any]]:
    """Walk a MISP response and pull indicators."""
    indicators: list[dict[str, Any]] = []

    def _walk_attribute(attr: dict[str, Any], event_meta: dict[str, Any]) -> None:
        if len(indicators) >= cap:
            return
        attr_type = (attr.get("type") or "").lower()
        normalised = _MISP_TYPE_MAP.get(attr_type)
        if not normalised:
            return
        value = attr.get("value")
        if not isinstance(value, str) or not value:
            return
        # MISP composite values like "domain|ip" come as "domain.tld|1.2.3.4"
        if "|" in attr_type and "|" in value:
            domain_part, ip_part = value.split("|", 1)
            if normalised == "domain":
                value_for_record = domain_part
            else:
                value_for_record = ip_part
        else:
            value_for_record = value

        tags: list[str] = []
        for t in attr.get("Tag") or []:
            if isinstance(t, dict) and isinstance(t.get("name"), str):
                tags.append(t["name"])

        indicators.append({
            "type": normalised,
            "value": value_for_record,
            "source": "misp",
            "tags": tags,
            "first_seen": attr.get("first_seen"),
            "last_seen": attr.get("last_seen"),
            "comment": attr.get("comment") or "",
            "event_id": event_meta.get("id"),
            "event_info": event_meta.get("info"),
            "event_threat_level": event_meta.get("threat_level_id"),
        })

    def _walk_event(event: dict[str, Any]) -> None:
        meta = {
            "id": event.get("id"),
            "info": event.get("info"),
            "threat_level_id": event.get("threat_level_id"),
        }
        for attr in event.get("Attribute") or []:
            if isinstance(attr, dict):
                _walk_attribute(attr, meta)
            if len(indicators) >= cap:
                return

    response_field = payload.get("response")
    if isinstance(response_field, list):
        for entry in response_field:
            if not isinstance(entry, dict):
                continue
            event = entry.get("Event")
            if isinstance(event, dict):
                _walk_event(event)
            attrs = entry.get("Attribute")
            if isinstance(attrs, list):
                for attr in attrs:
                    if isinstance(attr, dict):
                        _walk_attribute(attr, {})
    elif isinstance(response_field, dict):
        attrs = response_field.get("Attribute")
        if isinstance(attrs, list):
            for attr in attrs:
                if isinstance(attr, dict):
                    _walk_attribute(attr, {})
        events = response_field.get("Event")
        if isinstance(events, list):
            for event in events:
                if isinstance(event, dict):
                    _walk_event(event)
        elif isinstance(events, dict):
            _walk_event(events)
    elif "Event" in payload and isinstance(payload["Event"], dict):
        _walk_event(payload["Event"])

    return indicators


def _extract_stix_indicator(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull (type, value) pairs from a single STIX indicator object."""
    pattern = obj.get("pattern")
    if not isinstance(pattern, str):
        return []
    out: list[dict[str, Any]] = []
    for m in _STIX_PATTERN_RE.finditer(pattern):
        sco_path = m.group("type")
        value = m.group("value")
        ioc_type = _stix_object_path_to_ioc_type(sco_path)
        if not ioc_type:
            continue
        out.append({
            "type": ioc_type,
            "value": value,
            "source": "stix2",
            "tags": list(obj.get("labels") or []),
            "first_seen": obj.get("valid_from"),
            "last_seen": obj.get("valid_until"),
            "comment": obj.get("description") or obj.get("name") or "",
            "stix_id": obj.get("id"),
            "stix_pattern": pattern,
        })
    return out


def _extract_stix2(payload: dict[str, Any], cap: int) -> list[dict[str, Any]]:
    """Walk a STIX 2.x bundle / TAXII 2.1 collection for indicators."""
    indicators: list[dict[str, Any]] = []
    for obj in payload.get("objects") or []:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "indicator":
            continue
        for ioc in _extract_stix_indicator(obj):
            indicators.append(ioc)
            if len(indicators) >= cap:
                return indicators
    return indicators


def _extract_indicators(payload: dict[str, Any], feed_format: str, cap: int) -> list[dict[str, Any]]:
    if feed_format == "misp":
        return _extract_misp(payload, cap)
    if feed_format in ("stix2_bundle", "taxii2_collection"):
        return _extract_stix2(payload, cap)
    return []


# ---------------------------------------------------------------------------
# Target-filter matching
# ---------------------------------------------------------------------------


def _normalize_target_filter(target: str) -> tuple[str, str] | None:
    """Return ('ip', value) or ('domain', value) or None on invalid."""
    if not target or not isinstance(target, str):
        return None
    target = target.strip().rstrip(".").lower()
    if not target:
        return None
    if "://" in target:
        from urllib.parse import urlparse

        parsed = urlparse(target)
        target = (parsed.hostname or "").lower()
        if not target:
            return None
    try:
        ipaddress.ip_address(target)
        return ("ip", target)
    except ValueError:
        pass
    return ("domain", target)


def _matches_target(
    ioc: dict[str, Any], target_kind: str, target_value: str
) -> bool:
    """Return True if the IoC matches the target filter.

    Domain match: equality OR suffix (`.target`).
    IP match: exact-string.
    """
    ioc_type = (ioc.get("type") or "").lower()
    ioc_value = (ioc.get("value") or "").lower()
    if not ioc_value:
        return False

    if target_kind == "ip" and ioc_type == "ip":
        return ioc_value == target_value
    if target_kind == "domain":
        if ioc_type == "domain":
            return ioc_value == target_value or ioc_value.endswith("." + target_value)
        if ioc_type == "url":
            from urllib.parse import urlparse

            try:
                host = (urlparse(ioc_value).hostname or "").lower()
            except Exception:  # noqa: BLE001
                return False
            return bool(
                host and (host == target_value or host.endswith("." + target_value))
            )
    return False


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
        category="threat_feed_match",
        cwe="CWE-200",
        target=target,
        endpoint=target,
        description=description,
        impact=(
            "Curated threat-intel feeds (MISP / STIX / TAXII) "
            "represent the customer's own threat model. When an IoC "
            "from one of those feeds matches a scan target, the "
            "scan's prioritisation should reflect that this asset is "
            "specifically part of the customer's adversary picture."
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
    mitre_techniques=["T1597"],  # Search Closed Sources (threat-intel feeds)
)
def threat_feed_ingest(
    feed_url: str,
    auth_token: str = "",
    auth_basic: str = "",
    target_filter: str = "",
    max_records: int = _DEFAULT_MAX_RECORDS,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Fetch a threat-intel feed and extract indicators.

    Args:
        feed_url: URL returning a JSON document. Supported formats
            (auto-detected): MISP rest-search response, STIX 2.x
            bundle, TAXII 2.1 collection.
        auth_token: API key / bearer-style token sent verbatim as
            the `Authorization` header. For MISP this is the API key
            (no `Bearer` prefix needed). Empty string = no auth.
        auth_basic: `user:pass` for HTTP Basic auth (TAXII servers
            often require this). Mutually exclusive with `auth_token`
            — if both are set, `auth_token` wins.
        target_filter: Optional domain or IP. When supplied, IoCs
            matching the filter (exact for IPs; equality OR suffix
            for domains/URLs) emit info findings so the agent can
            prioritise scan posture against the customer's threat
            model.
        max_records: Hard cap on extracted indicators (default 500).
            Avoids flooding when a feed returns thousands of
            indicators.
        timeout: Per-request timeout in seconds (default 30).

    Returns:
        {
          success, feed_url, feed_format, fetched_at, from_cache,
          record_count, indicators: [
            {type, value, source, tags, first_seen, last_seen,
             comment, ...},
            ...
          ],
          target_filter, matched_count,
          findings_emitted, error?,
        }

    Findings:
        - **Info** (CWE-200, threat_feed_match) — per IoC match
          against `target_filter`. Per-(target, ioc-type, ioc-value)
          dedup so the same indicator doesn't emit twice.

    Notes:
        - 1-hour cache under `~/.strix/threat_feed_cache/`. Stale
          cache served on network failure (fail-open with `error`
          populated). Disable with `STRIX_THREAT_FEED_NO_CACHE=1`.
        - Auth material is hashed for cache key (not stored).
        - Composes with cluster-A safety: rate-limit applies.
        - `verification_status=needs_review` since threat-intel
          feeds carry varying levels of confidence; the agent should
          review the feed source before treating any single match
          as definitive.
    """
    feed_url = (feed_url or "").strip()
    if not feed_url:
        return {"success": False, "error": "feed_url is required"}
    if "://" not in feed_url:
        return {"success": False, "error": "feed_url must be an absolute http(s) URL"}

    auth_token = (auth_token or "").strip()
    auth_basic = (auth_basic or "").strip()
    target_filter = (target_filter or "").strip()
    if not isinstance(max_records, int) or max_records <= 0:
        max_records = _DEFAULT_MAX_RECORDS

    auth_fp = _auth_fingerprint(auth_token, auth_basic)
    cev = _start_check("threat_feed_ingest", feed_url)

    # Fresh cache fast path.
    cached = _cache_read(feed_url, auth_fp, fresh_only=True)
    if cached is not None:
        cached["from_cache"] = True
        # Re-emit findings for cached IoCs that match the filter — the
        # tracer state isn't preserved in the cache.
        findings_emitted = _emit_target_findings(
            cached.get("indicators") or [], target_filter,
        )
        cached["findings_emitted"] = findings_emitted
        cached["target_filter"] = target_filter
        cached["matched_count"] = findings_emitted
        _complete_check(
            cev,
            result="vulnerable" if findings_emitted else "not_vulnerable",
            evidence=(
                f"{cached.get('record_count')} IoC(s); "
                f"{findings_emitted} matched (cached)"
            ),
        )
        return cached

    # Live fetch.
    headers: dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": "strix-threat-feed-ingest/1.0",
    }
    if auth_token:
        headers["Authorization"] = auth_token
    elif auth_basic and ":" in auth_basic:
        import base64

        encoded = base64.b64encode(auth_basic.encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"

    response = _http_get(feed_url, headers=headers, timeout=timeout)
    if response.get("error") or response.get("status", 0) >= 400 or response.get("skipped"):
        # Stale-cache fallback.
        stale = _cache_read(feed_url, auth_fp, fresh_only=False)
        if stale is not None:
            stale["from_cache"] = True
            err = (
                response.get("error")
                or f"HTTP {response.get('status')}"
                if not response.get("skipped")
                else "filtered by --exclude-path"
            )
            stale["error"] = f"feed fetch failed ({err}); served stale cache"
            findings_emitted = _emit_target_findings(
                stale.get("indicators") or [], target_filter,
            )
            stale["findings_emitted"] = findings_emitted
            stale["target_filter"] = target_filter
            stale["matched_count"] = findings_emitted
            _complete_check(
                cev,
                result="vulnerable" if findings_emitted else "not_vulnerable",
                evidence=f"feed failed; stale cache served (matched={findings_emitted})",
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
        _complete_check(cev, "inconclusive", f"feed fetch failed: {err_text}")
        return {
            "success": False,
            "feed_url": feed_url,
            "error": err_text,
            "indicators": [],
            "record_count": 0,
            "target_filter": target_filter,
            "matched_count": 0,
            "findings_emitted": 0,
            "from_cache": False,
        }

    body = response.get("body") or ""
    try:
        payload = json.loads(body)
    except (ValueError, TypeError) as e:
        _complete_check(cev, "inconclusive", f"feed invalid JSON: {e}")
        return {
            "success": False,
            "feed_url": feed_url,
            "error": f"feed invalid JSON: {e}",
            "indicators": [],
            "record_count": 0,
            "target_filter": target_filter,
            "matched_count": 0,
            "findings_emitted": 0,
            "from_cache": False,
        }

    feed_format = _detect_format(payload)
    indicators = _extract_indicators(payload, feed_format, max_records)
    record_count = len(indicators)

    findings_emitted = _emit_target_findings(indicators, target_filter)

    result = {
        "success": True,
        "feed_url": feed_url,
        "feed_format": feed_format,
        "fetched_at": int(time.time()),
        "from_cache": False,
        "indicators": indicators,
        "record_count": record_count,
        "target_filter": target_filter,
        "matched_count": findings_emitted,
        "findings_emitted": findings_emitted,
    }
    _cache_write(feed_url, auth_fp, result)

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{record_count} IoC(s) extracted; {findings_emitted} matched filter",
    )
    return result


def _emit_target_findings(
    indicators: list[dict[str, Any]], target_filter: str
) -> int:
    """Match indicators against `target_filter` and emit per-match
    findings. Per-(type, value) dedup. Returns the number of findings
    emitted."""
    if not target_filter:
        return 0
    parsed = _normalize_target_filter(target_filter)
    if parsed is None:
        return 0
    target_kind, target_value = parsed

    seen: set[tuple[str, str]] = set()
    emitted = 0
    for ioc in indicators:
        if not _matches_target(ioc, target_kind, target_value):
            continue
        key = (str(ioc.get("type") or ""), str(ioc.get("value") or ""))
        if key in seen:
            continue
        seen.add(key)
        comment = (ioc.get("comment") or "")[:200]
        tags = ", ".join(ioc.get("tags") or []) or "(none)"
        title = (
            f"Threat feed IoC match: {ioc.get('type')}={ioc.get('value')} "
            f"on {target_value}"
        )
        description = (
            f"Threat-intel feed reports `{ioc.get('value')}` "
            f"(type=`{ioc.get('type')}`, source=`{ioc.get('source')}`) "
            f"matching scan target `{target_value}`. Tags: {tags}. "
            f"Comment: {comment or '(none)'}"
        )
        description_plain = (
            "Your own threat-intelligence feed flags an indicator that "
            f"matches the target you're scanning. The IoC type "
            f"`{ioc.get('type')}` indicates {comment or 'the feed has tagged this indicator'}. "
            "Treat the scan against this target with appropriate priority."
        )
        recommended_action = (
            "Review the originating feed entry for full context "
            "(threat actor, campaign, observed activity). Cross-"
            "reference scan findings against the IoC tags. If the "
            "feed flags this asset as malicious, escalate to your "
            "incident-response process before continuing live "
            "testing."
        )
        _emit_finding(
            title=title,
            severity="info",
            target=target_value,
            description=description,
            description_plain=description_plain,
            recommended_action=recommended_action,
        )
        emitted += 1
    return emitted
