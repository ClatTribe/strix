"""`openapi_spec_ingest` — discover, fetch, parse, and KG-emit an
API target's OpenAPI / Swagger spec.

The single biggest unlock for the `api` target type. Today
`bfs_crawl` walks HTML for endpoints; APIs don't render HTML
(unless they include a Swagger-UI page), so crawling misses
endpoints documented only in the spec. This tool replaces the
crawl on API targets:

  1. **Discover** — probes the standard publishing paths
     (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, etc. —
     same allow-list `fingerprint._probe_openapi` uses) plus an
     optional caller-supplied URL.
  2. **Fetch + parse** — supports OpenAPI 3.x and Swagger 2.x.
     `paths` is the load-bearing field; `components.schemas` /
     `definitions` for the auth-scheme detection.
  3. **Emit** — one `Surface` node per (path, method). KG
     emission uses the existing `record_finding_in_kg` shape
     (URL + method) so specialists query the same Surface
     namespace whether the endpoint was crawled, ingested via
     HAR / Burp, or pulled from the spec.
  4. **Return** — structured inventory: every endpoint with its
     declared params + auth requirements + tags + the spec
     version + the spec URL itself (for audit / re-fetch).

## What this does NOT do

  * Doesn't probe the endpoints for vulnerabilities — that's
    the specialists' job (`scan_idor`, `scan_sqli`, etc.). This
    tool just builds the inventory.
  * Doesn't follow `$ref` cross-spec includes. We accept the
    inline-resolved view the server returns. Most APIs publish
    a single self-contained spec; multi-file specs are rare in
    production deployments.
  * Doesn't generate request bodies. Body fuzzing is the
    `scan_api_mass_assignment` follow-up's job.

Kill switch: `STRIX_OPENAPI_INGEST_DISABLED=1` short-circuits
everything and returns `{"success": False, "error": "kill_switch"}`.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.parse import urljoin, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_DEFAULT_TIMEOUT_SECONDS = 15.0


# Standard OpenAPI / Swagger publishing paths. Same list
# `fingerprint._probe_openapi` uses — keep in sync.
_OPENAPI_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/api/docs",
)


# HTTP methods we recognise from the spec. Other verbs (TRACE,
# CONNECT) appear in specs but aren't probe-worthy for AppSec.
_RECOGNISED_METHODS: frozenset[str] = frozenset({
    "get", "post", "put", "delete", "patch", "head", "options",
})


def _kill_switched() -> bool:
    return os.environ.get("STRIX_OPENAPI_INGEST_DISABLED") == "1"


def _looks_like_url(value: str) -> bool:
    try:
        p = urlparse(value)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except (ValueError, AttributeError):
        return False


def _http_fetch(
    url: str, *, timeout: float, fetcher=None,
) -> tuple[int, str]:
    """Fetch a URL. Returns (status_code, body). Defensive — any
    error returns (0, ""). The `fetcher` injection point lets
    tests stub HTTP without monkeypatching httpx.
    """
    if fetcher is not None:
        return fetcher(url, timeout=timeout)
    try:
        import httpx
    except ImportError:
        return 0, ""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as c:
            r = c.get(url)
            return r.status_code, r.text or ""
    except Exception:  # noqa: BLE001
        return 0, ""


def _parse_spec(body: str) -> dict[str, Any] | None:
    """Parse JSON. Returns None when the body doesn't look like a
    spec (must be a dict with `paths`)."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    if "paths" not in data or not isinstance(data["paths"], dict):
        return None
    # OpenAPI 3.x has `openapi`; Swagger 2.x has `swagger`. Reject
    # bodies that have `paths` but neither marker — likely a
    # different schema we don't understand.
    if "openapi" not in data and "swagger" not in data:
        return None
    return data


def _spec_version(spec: dict[str, Any]) -> str:
    """OpenAPI 3.x → 'openapi-3.x'; Swagger 2.x → 'swagger-2.0'."""
    if "openapi" in spec:
        return f"openapi-{spec['openapi']}"
    if "swagger" in spec:
        return f"swagger-{spec['swagger']}"
    return "unknown"


def _spec_base_url(spec: dict[str, Any], discovered_at: str) -> str:
    """Determine the API's base URL.

    Resolution order:
      1. OpenAPI 3.x `servers[0].url`
      2. Swagger 2.x `host` + `basePath`
      3. Fall back to the URL we discovered the spec at (strip
         the spec filename)
    """
    # OpenAPI 3.x
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        first = servers[0]
        if isinstance(first, dict):
            url = first.get("url")
            if isinstance(url, str) and url.strip():
                # Relative servers resolve against `discovered_at`.
                if url.startswith("/") or not _looks_like_url(url):
                    return urljoin(discovered_at, url)
                return url
    # Swagger 2.x
    host = spec.get("host")
    base_path = spec.get("basePath", "")
    schemes = spec.get("schemes") or ["https"]
    if isinstance(host, str) and host:
        scheme = (
            schemes[0] if isinstance(schemes, list) and schemes
            else "https"
        )
        return f"{scheme}://{host}{base_path or ''}"
    # Fallback — strip filename from the discovery URL.
    parsed = urlparse(discovered_at)
    return f"{parsed.scheme}://{parsed.netloc}"


def _extract_endpoints(
    spec: dict[str, Any], *, base_url: str,
) -> list[dict[str, Any]]:
    """Walk `paths` → emit one endpoint dict per (path, method).

    Each endpoint carries:
      * `path` — the templated path from the spec (`/users/{id}`)
      * `method` — uppercase HTTP method
      * `url` — `base_url + path` (templated; specialists will
        instantiate placeholders before probing)
      * `params` — list of `{name, in, required}` for the
        endpoint's declared parameters
      * `auth_required` — True when the spec attaches a
        security scheme to the operation (or globally) other
        than the open-access shape
      * `tags` — operation tags from the spec (for grouping)
      * `summary` — short description
    """
    endpoints: list[dict[str, Any]] = []
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return endpoints

    # Global security requirement — if set, operations inherit
    # unless they explicitly override.
    global_security_set = bool(spec.get("security"))

    for path, methods_block in paths.items():
        if not isinstance(path, str) or not isinstance(methods_block, dict):
            continue
        # Path-level parameters (apply to every method on this path).
        path_params = methods_block.get("parameters") or []
        if not isinstance(path_params, list):
            path_params = []

        for method, operation in methods_block.items():
            if not isinstance(method, str):
                continue
            method_lower = method.strip().lower()
            if method_lower not in _RECOGNISED_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            # Operation-level params + path-level params.
            op_params = operation.get("parameters") or []
            if not isinstance(op_params, list):
                op_params = []
            merged_params: list[dict[str, Any]] = []
            for p in list(path_params) + list(op_params):
                if not isinstance(p, dict):
                    continue
                merged_params.append({
                    "name": str(p.get("name") or ""),
                    "in": str(p.get("in") or "query"),
                    "required": bool(p.get("required", False)),
                })

            # Auth requirement: operation-level security (if set)
            # overrides global. Empty list `security: []` means
            # explicit no-auth even when global is set.
            op_security = operation.get("security")
            if op_security is None:
                auth_required = global_security_set
            else:
                auth_required = (
                    isinstance(op_security, list)
                    and len(op_security) > 0
                )

            endpoints.append({
                "path": path,
                "method": method_lower.upper(),
                "url": urljoin(base_url + "/", path.lstrip("/")),
                "params": merged_params,
                "auth_required": auth_required,
                "tags": [
                    str(t) for t in (operation.get("tags") or [])
                    if isinstance(t, str)
                ],
                "summary": str(operation.get("summary") or "")[:200],
                "operation_id": str(
                    operation.get("operationId") or ""
                )[:120],
            })

    return endpoints


def _emit_surfaces_to_kg(
    endpoints: list[dict[str, Any]], *, spec_url: str,
) -> int:
    """Emit one `Surface` KG node per endpoint via the existing
    `record_finding_in_kg` Surface dedup path — keeps API
    Surfaces in the same namespace DAST scanners use.

    Returns the count of Surfaces successfully recorded.

    We don't emit a Vuln node here — the endpoint isn't a finding
    on its own. Specialists fire later; their `record_finding_in_kg`
    calls hit the same dedup cache and attach Vulns to these
    Surfaces. To avoid the helper's Vuln-required signature, we
    call the KG directly here.
    """
    try:
        from strix.agents.knowledge_graph import get_kg, is_disabled
        from strix.agents.kg_emit import _canonicalise_url
    except ImportError:
        return 0

    if is_disabled():
        return 0

    try:
        from strix.agents.kg_emit import (
            _surface_cache,
            _surface_cache_lock,
        )
    except ImportError:
        return 0

    kg = get_kg()
    count = 0
    for ep in endpoints:
        url = ep.get("url", "")
        method = ep.get("method", "GET")
        if not isinstance(url, str) or not url:
            continue

        # Use an empty `param` for the Surface dedup key — the
        # parameters live as a property on the node. When a
        # specialist later probes `?id=` on this endpoint, its
        # own emit will create a Surface with `param=id` —
        # distinct cache key — that's the right shape (different
        # parameter = different probe target).
        canon = _canonicalise_url(url)
        cache_key = (canon, "", method.upper())

        try:
            with _surface_cache_lock:
                surface_id = _surface_cache.get(cache_key)
                if surface_id is None or kg.get_node(surface_id) is None:
                    surface_props: dict[str, Any] = {
                        "url": canon,
                        "param": "",
                        "method": method.upper(),
                        "kind": "api_endpoint",
                        "spec_url": spec_url,
                    }
                    if ep.get("auth_required"):
                        surface_props["auth_required"] = True
                    if ep.get("operation_id"):
                        surface_props["operation_id"] = ep["operation_id"]
                    if ep.get("tags"):
                        surface_props["tags"] = list(ep["tags"])
                    surface_node = kg.add_node(
                        type="Surface", props=surface_props,
                    )
                    surface_id = surface_node.id
                    _surface_cache[cache_key] = surface_id
                    count += 1
        except Exception:  # noqa: BLE001
            logger.debug(
                "openapi_ingest: KG emit failed for %s %s",
                method, url, exc_info=True,
            )
            continue

    return count


@register_tool(
    sandbox_execution=False,
    mitre_techniques=["T1592.001"],  # Gather Victim Host Information
    provenance="trusted_source",
)
def openapi_spec_ingest(
    target: str,
    spec_url: str | None = None,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Discover, fetch, parse, and KG-emit an API target's OpenAPI
    / Swagger spec.

    Args:
        target: target URL or base origin (e.g.
            `https://api.example.com`). Used as the discovery
            origin when `spec_url` isn't supplied.
        spec_url: optional explicit spec URL (skip discovery).
        timeout: per-request HTTP timeout in seconds (default 15).

    Returns:
        ```
        {
          success: bool,
          target,
          spec_url: str | None,            # discovered or supplied
          spec_version: str,               # "openapi-3.0.0" / "swagger-2.0"
          base_url: str,                   # resolved API base
          endpoints: [{
            path, method, url, params, auth_required,
            tags, summary, operation_id,
          }, ...],
          endpoint_count: int,
          surfaces_emitted: int,           # KG count
          error?: str,
        }
        ```

    Behaviour:
      * Probes the 11 standard OpenAPI publishing paths plus
        the optional explicit `spec_url`.
      * First hit wins. JSON-parses; rejects bodies that lack
        the `paths` + (`openapi` | `swagger`) shape.
      * Emits one Surface KG node per (path, method) so
        downstream specialists query the same Surface namespace
        DAST scanners use.

    Kill switch: `STRIX_OPENAPI_INGEST_DISABLED=1`.
    """
    if _kill_switched():
        return {
            "success": False,
            "target": target,
            "error": "kill_switch (STRIX_OPENAPI_INGEST_DISABLED)",
        }

    if not isinstance(target, str) or not _looks_like_url(target):
        return {
            "success": False,
            "target": target,
            "error": f"invalid target URL: {target!r}",
        }

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    discovery_urls: list[str] = []
    if spec_url:
        if not _looks_like_url(spec_url):
            return {
                "success": False,
                "target": target,
                "error": f"invalid spec_url: {spec_url!r}",
            }
        discovery_urls.append(spec_url)
    discovery_urls.extend(base + path for path in _OPENAPI_PATHS)

    spec: dict[str, Any] | None = None
    discovered_at: str | None = None

    for url in discovery_urls:
        status, body = _http_fetch(url, timeout=timeout)
        if status != 200 or not body:
            continue
        parsed_spec = _parse_spec(body)
        if parsed_spec is not None:
            spec = parsed_spec
            discovered_at = url
            break

    if spec is None or discovered_at is None:
        return {
            "success": False,
            "target": target,
            "spec_url": None,
            "error": "no parseable OpenAPI/Swagger spec found",
        }

    base_url = _spec_base_url(spec, discovered_at)
    endpoints = _extract_endpoints(spec, base_url=base_url)
    surfaces_emitted = _emit_surfaces_to_kg(
        endpoints, spec_url=discovered_at,
    )

    return {
        "success": True,
        "target": target,
        "spec_url": discovered_at,
        "spec_version": _spec_version(spec),
        "base_url": base_url,
        "endpoints": endpoints,
        "endpoint_count": len(endpoints),
        "surfaces_emitted": surfaces_emitted,
    }
