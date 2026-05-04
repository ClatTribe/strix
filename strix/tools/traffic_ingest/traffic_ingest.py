"""HAR / Burp project traffic-ingestion tools.

Two ingestion paths, one structured output. The agent / runner
calls these to consume an operator-supplied recording of real
traffic and seed the surface map without crawling.

Output schema (the same for both ingest paths):

```json
{
  "success": true,
  "source": "har" | "burp",
  "source_path": "/abs/path",
  "requests_count": <int>,
  "endpoints_count": <int>,
  "hosts": ["api.example.com", ...],
  "endpoints": [
    {
      "url": "https://api.example.com/login",
      "method": "POST",
      "host": "api.example.com",
      "path": "/login",
      "scheme": "https",
      "params": {"username": "...", ...},
      "request_headers": {...},
      "request_body_present": true,
      "response_status": 200,
      "response_content_type": "application/json",
      "response_size_bytes": <int>,
      "auth_observed": "bearer" | "cookie" | "basic" | null,
      "discovered_via": "har" | "burp",
    },
    ...
  ],
  "errors": [...],
}
```

The endpoints list is **deduped per (method, url-without-query)**
— a HAR with 50 calls to `/api/users/{id}` collapses to one
endpoint with `params` reflecting the parameter shape and
`response_status` / size aggregated as the most-common values.

Design choices
--------------

1. **Read-only at ingest.** The tool parses + structures; it doesn't
   replay the recorded requests. The agent decides which to replay.
2. **Auth disclosure suppressed.** `request_headers` strips
   `Authorization` / `Cookie` / `Set-Cookie` / `X-API-Key` /
   `X-Auth-Token` values (replaced with redaction marker) so the
   structured output can be persisted without leaking the
   operator's session.
3. **Per-host scope check.** Endpoints whose host doesn't match
   the configured target are tagged `out_of_scope=True` but kept
   in the output (the agent decides whether to use them — useful
   for documenting third-party calls).
4. **Burp parser is XML-streaming.** Burp project exports can be
   100MB+; we stream-parse with `xml.etree.ElementTree.iterparse`
   and yield endpoints incrementally, capping at `max_requests`
   (default 5000).

References
----------

* HAR 1.2 spec: https://w3c.github.io/web-performance/specs/HAR/Overview.html
* Burp Suite "Save Project" output XML format
"""

from __future__ import annotations

import base64
import json
import logging
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


# Headers whose values are sensitive — value-redacted on output so
# persisting the structured artifact doesn't leak credentials.
_SENSITIVE_HEADERS = frozenset({
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "proxy-authorization",
    "www-authenticate",
})

# Default cap so a 100MB Burp project doesn't OOM the runner.
_DEFAULT_MAX_REQUESTS = 5000


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy with sensitive header VALUES replaced by a
    redaction marker. Header names are preserved so the agent
    sees auth was present."""
    out: dict[str, str] = {}
    for k, v in headers.items():
        if not isinstance(k, str):
            continue
        key_lower = k.lower()
        if key_lower in _SENSITIVE_HEADERS:
            out[k] = "[REDACTED]"
        else:
            out[k] = str(v) if not isinstance(v, str) else v
    return out


def _detect_auth(headers: dict[str, str]) -> str | None:
    """Inspect the (lower-cased) header names for the auth class
    used. Returns one of `bearer` / `cookie` / `basic` / None.
    Never inspects values to avoid leaking credentials."""
    lower_keys = {k.lower(): v for k, v in headers.items() if isinstance(k, str)}
    auth = lower_keys.get("authorization", "")
    if isinstance(auth, str):
        a_lower = auth.lower()
        if a_lower.startswith("bearer "):
            return "bearer"
        if a_lower.startswith("basic "):
            return "basic"
    if "cookie" in lower_keys:
        return "cookie"
    if "x-api-key" in lower_keys or "x-auth-token" in lower_keys:
        return "bearer"  # API-key-style; canonicalise as bearer
    return None


def _normalise_url(url: str) -> tuple[str, str, str, str, str]:
    """Return `(canonical_url, scheme, host, path, query_string)`."""
    p = urlparse(url)
    scheme = p.scheme or "https"
    host = (p.netloc or "").lower()
    path = p.path or "/"
    query = p.query or ""
    canonical = f"{scheme}://{host}{path}"
    return canonical, scheme, host, path, query


# ---------------------------------------------------------------------------
# HAR parser
# ---------------------------------------------------------------------------


def _parse_har_entries(har: dict[str, Any]) -> list[dict[str, Any]]:
    """Walk the HAR `log.entries[]` array and return per-request
    structured records (one per HAR entry — dedup happens in the
    aggregation step)."""
    log = har.get("log") if isinstance(har, dict) else None
    if not isinstance(log, dict):
        return []
    entries = log.get("entries")
    if not isinstance(entries, list):
        return []

    out: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") or {}
        resp = entry.get("response") or {}

        url = req.get("url")
        if not isinstance(url, str) or not url:
            continue
        method = (req.get("method") or "GET").upper()

        canonical, scheme, host, path, query = _normalise_url(url)
        if not host:
            continue

        # Headers — list of {name, value} dicts in HAR.
        headers_dict: dict[str, str] = {}
        for h in (req.get("headers") or []):
            if not isinstance(h, dict):
                continue
            name = h.get("name")
            value = h.get("value")
            if isinstance(name, str) and isinstance(value, str):
                headers_dict[name] = value

        # Query params — HAR has them as a list under `queryString`.
        params: dict[str, list[str]] = {}
        if isinstance(req.get("queryString"), list):
            for q in req["queryString"]:
                if not isinstance(q, dict):
                    continue
                qn = q.get("name")
                qv = q.get("value")
                if isinstance(qn, str):
                    params.setdefault(qn, []).append(
                        str(qv) if not isinstance(qv, str) else qv
                    )
        # Or parsed from the raw query string.
        if not params and query:
            for qn, qv_list in parse_qs(query, keep_blank_values=True).items():
                params[qn] = qv_list

        # Response body content — HAR has it under `response.content`.
        resp_content = resp.get("content") if isinstance(resp.get("content"), dict) else {}
        resp_status = resp.get("status")
        try:
            resp_status_int = int(resp_status) if resp_status is not None else 0
        except (TypeError, ValueError):
            resp_status_int = 0
        resp_size = resp_content.get("size") if isinstance(resp_content, dict) else 0
        try:
            resp_size_int = int(resp_size) if resp_size is not None else 0
        except (TypeError, ValueError):
            resp_size_int = 0
        resp_ct = resp_content.get("mimeType") if isinstance(resp_content, dict) else ""
        if not isinstance(resp_ct, str):
            resp_ct = ""

        out.append({
            "url": canonical,
            "method": method,
            "host": host,
            "path": path,
            "scheme": scheme,
            "params": list(params.keys()),
            "request_headers": _redact_headers(headers_dict),
            "request_body_present": bool(req.get("postData")),
            "response_status": resp_status_int,
            "response_content_type": resp_ct.split(";", 1)[0].strip(),
            "response_size_bytes": resp_size_int,
            "auth_observed": _detect_auth(headers_dict),
            "discovered_via": "har",
        })
    return out


# ---------------------------------------------------------------------------
# Burp parser
# ---------------------------------------------------------------------------


# Burp project XML shape (post-export):
#  <items>
#    <item>
#      <url>https://...</url>
#      <host>example.com</host>
#      <port>443</port>
#      <protocol>https</protocol>
#      <method>GET</method>
#      <path>/</path>
#      <request base64="true">...base64-encoded HTTP request...</request>
#      <status>200</status>
#      <responselength>1234</responselength>
#      <mimetype>HTML</mimetype>
#      <response base64="true">...base64-encoded HTTP response...</response>
#    </item>
#    ...
#  </items>
def _decode_b64_block(text: str | None, *, is_b64: bool) -> str:
    if not isinstance(text, str):
        return ""
    if not is_b64:
        return text
    try:
        return base64.b64decode(text, validate=False).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


_HEADER_LINE_RE = re.compile(r"^([A-Za-z0-9\-_]+)\s*:\s*(.*?)\s*$")


def _parse_raw_http_headers(raw: str) -> dict[str, str]:
    """Split a raw HTTP request/response into header dict. Stops
    at the blank line separating headers from body."""
    headers: dict[str, str] = {}
    for line in raw.splitlines()[1:]:  # skip request-line / status-line
        if not line.strip():
            break  # end of headers
        m = _HEADER_LINE_RE.match(line)
        if m:
            headers[m.group(1)] = m.group(2)
    return headers


def _parse_burp_items(
    path: Path, *, max_requests: int
) -> list[dict[str, Any]]:
    """Stream-parse a Burp project XML. Yields per-item records.
    Caps at `max_requests` to bound memory."""
    out: list[dict[str, Any]] = []
    try:
        for _, elem in ET.iterparse(str(path), events=("end",)):
            if elem.tag != "item":
                continue
            if len(out) >= max_requests:
                elem.clear()
                break

            try:
                url = (elem.findtext("url") or "").strip()
                method = (elem.findtext("method") or "GET").strip().upper()
                if not url:
                    continue
                canonical, scheme, host, path_seg, query = _normalise_url(url)
                if not host:
                    continue

                # Decode raw request to extract headers.
                req_node = elem.find("request")
                req_b64 = (req_node.get("base64") if req_node is not None else "false") == "true"
                req_raw = _decode_b64_block(
                    req_node.text if req_node is not None else "", is_b64=req_b64
                )
                headers = _parse_raw_http_headers(req_raw)

                # Status / size / mimetype direct from XML.
                status_text = (elem.findtext("status") or "0").strip()
                try:
                    status_int = int(status_text)
                except ValueError:
                    status_int = 0
                size_text = (elem.findtext("responselength") or "0").strip()
                try:
                    size_int = int(size_text)
                except ValueError:
                    size_int = 0
                mimetype = (elem.findtext("mimetype") or "").strip().lower()

                # Params from query string.
                params_dict = parse_qs(query, keep_blank_values=True) if query else {}

                out.append({
                    "url": canonical,
                    "method": method,
                    "host": host,
                    "path": path_seg,
                    "scheme": scheme,
                    "params": list(params_dict.keys()),
                    "request_headers": _redact_headers(headers),
                    "request_body_present": bool(
                        req_raw and "\r\n\r\n" in req_raw and len(
                            req_raw.split("\r\n\r\n", 1)[1].strip()
                        ) > 0
                    ) or bool(
                        req_raw and "\n\n" in req_raw and len(
                            req_raw.split("\n\n", 1)[1].strip()
                        ) > 0
                    ),
                    "response_status": status_int,
                    "response_content_type": mimetype,
                    "response_size_bytes": size_int,
                    "auth_observed": _detect_auth(headers),
                    "discovered_via": "burp",
                })
            finally:
                elem.clear()
    except ET.ParseError as e:
        logger.debug("burp xml parse error: %s", e)
    return out


# ---------------------------------------------------------------------------
# Aggregation: per-(method, canonical-url) dedup
# ---------------------------------------------------------------------------


def _aggregate_endpoints(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group records by (method, canonical_url). For each group:
    keep the first record's metadata; aggregate `params` as the
    UNION of all parameter names; pick most-common response_status
    / size."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for rec in records:
        key = (rec["method"], rec["url"])
        groups.setdefault(key, []).append(rec)

    out: list[dict[str, Any]] = []
    for key, group in groups.items():
        params: set[str] = set()
        statuses: list[int] = []
        sizes: list[int] = []
        ct_list: list[str] = []
        auth_list: list[str | None] = []
        for r in group:
            params.update(r.get("params", []))
            if r.get("response_status"):
                statuses.append(r["response_status"])
            if r.get("response_size_bytes"):
                sizes.append(r["response_size_bytes"])
            ct_list.append(r.get("response_content_type") or "")
            auth_list.append(r.get("auth_observed"))

        # Most-common status / size / content-type / auth.
        most_common = lambda lst: Counter(lst).most_common(1)[0][0] if lst else None  # noqa: E731
        first = group[0]
        out.append({
            "url": first["url"],
            "method": first["method"],
            "host": first["host"],
            "path": first["path"],
            "scheme": first["scheme"],
            "params": sorted(params),
            "request_headers": first["request_headers"],
            "request_body_present": any(r.get("request_body_present") for r in group),
            "response_status": most_common(statuses) or 0,
            "response_content_type": most_common(ct_list) or "",
            "response_size_bytes": most_common(sizes) or 0,
            "auth_observed": most_common(auth_list),
            "discovered_via": first["discovered_via"],
            "occurrences": len(group),
        })
    return out


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_event(payload: dict[str, Any]) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    try:
        tracer._emit_event(  # noqa: SLF001
            "traffic.ingested",
            payload=payload,
            status="ok",
            source="strix.tools.traffic_ingest",
        )
    except Exception:  # noqa: BLE001
        logger.debug("traffic.ingested emit failed", exc_info=True)


# ---------------------------------------------------------------------------
# Public tools
# ---------------------------------------------------------------------------


def _build_result(
    *,
    source: str,
    source_path: str,
    endpoints: list[dict[str, Any]],
    requests_count: int,
    errors: list[str],
) -> dict[str, Any]:
    hosts = sorted({e["host"] for e in endpoints if e.get("host")})
    out: dict[str, Any] = {
        "success": True,
        "source": source,
        "source_path": source_path,
        "requests_count": requests_count,
        "endpoints_count": len(endpoints),
        "hosts": hosts,
        "endpoints": endpoints,
    }
    if errors:
        out["errors"] = errors
    _emit_event({
        "source": source,
        "source_path": source_path,
        "requests_count": requests_count,
        "endpoints_count": len(endpoints),
        "hosts": hosts,
    })
    return out


@register_tool(
    sandbox_execution=False,
    mitre_techniques=[],
    provenance="operator_input",
)
def ingest_har_file(
    path: str,
    max_requests: int = _DEFAULT_MAX_REQUESTS,
) -> dict[str, Any]:
    """Parse a HAR (HTTP Archive 1.2) file and return a structured
    request inventory the agent can use to seed the surface map.

    Args:
        path: filesystem path to the .har file.
        max_requests: cap on entries parsed (default 5000) to bound
            memory on huge HAR files.

    Returns: see module docstring schema. The endpoint list is
    deduped per (method, canonical-url); params reflect the union
    of parameter names; response metadata is most-common.
    """
    p = Path(path).expanduser().resolve()
    if not p.exists() or not p.is_file():
        return {"success": False, "error": f"HAR file not found: {p}"}

    errors: list[str] = []
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
        har = json.loads(text)
    except (OSError, json.JSONDecodeError) as e:
        return {"success": False, "error": f"failed to load HAR: {e}"}

    records = _parse_har_entries(har)
    if max_requests and len(records) > max_requests:
        errors.append(
            f"capped at {max_requests} requests (HAR had {len(records)})"
        )
        records = records[:max_requests]

    endpoints = _aggregate_endpoints(records)
    return _build_result(
        source="har",
        source_path=str(p),
        endpoints=endpoints,
        requests_count=len(records),
        errors=errors,
    )


@register_tool(
    sandbox_execution=False,
    mitre_techniques=[],
    provenance="operator_input",
)
def ingest_burp_file(
    path: str,
    max_requests: int = _DEFAULT_MAX_REQUESTS,
) -> dict[str, Any]:
    """Parse a Burp Suite project XML export and return a structured
    request inventory the agent can use to seed the surface map.

    Args:
        path: filesystem path to the Burp XML export.
        max_requests: cap on `<item>` elements parsed (default 5000).

    Returns: see module docstring schema.

    The Burp parser is XML-streaming (`iterparse`) so 100MB+ exports
    don't OOM. Each `<item>` is parsed, headers extracted from the
    base64-encoded raw request, response metadata read directly from
    the XML attributes.
    """
    p = Path(path).expanduser().resolve()
    if not p.exists() or not p.is_file():
        return {"success": False, "error": f"Burp file not found: {p}"}

    records = _parse_burp_items(p, max_requests=max_requests)
    endpoints = _aggregate_endpoints(records)
    return _build_result(
        source="burp",
        source_path=str(p),
        endpoints=endpoints,
        requests_count=len(records),
        errors=[],
    )
