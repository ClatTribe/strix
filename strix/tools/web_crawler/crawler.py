"""BFS crawl + JS-bundle endpoint mining + OpenAPI consumption.

Cluster B of the web_application target work (roadmap §3 + §7.2). Composes
with cluster A's HTTP-safety middleware (`http_safety.py`) so the crawler
inherits auth-injection, exclude-path enforcement, and rate-limiting
automatically when invoked through the sandbox proxy. When the proxy isn't
available (e.g. host-side direct invocation in tests), falls back to a
direct `httpx`/`requests` call that still reads the same env vars.

Output shape:
    {
      "success": bool,
      "target": str,
      "started_at": iso8601,
      "ended_at": iso8601,
      "seed_urls": [...],
      "openapi_url": str | None,
      "config": {max_pages, max_depth, allowed_hosts: [...]},
      "endpoints": [{url, method, depth, discovered_via}],
      "forms": [{url, method, action, fields: [{name, type, value}]}],
      "js_bundles": [str],
      "errors": [str],
      "stats": {pages_visited, endpoints_discovered, forms_found,
                js_bundles_parsed, openapi_endpoints_imported}
    }
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import deque
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "bfs_crawl"
_HTTP_TIMEOUT = 12

# Defaults chosen to bound the work — most apps' attack surface is in the
# first few hundred pages. Operators tune via parameters.
_DEFAULT_MAX_PAGES = 200
_DEFAULT_MAX_DEPTH = 3
_HARD_MAX_PAGES = 2000
_HARD_MAX_DEPTH = 8

# JS body cap (per file) — large bundles eat memory; the regex pass is
# linear in bytes. 4 MB tolerates most modern app bundles.
_JS_BODY_MAX_BYTES = 4 * 1024 * 1024
# HTML body cap — SPAs sometimes serve huge HTML; cap at 2 MB.
_HTML_BODY_MAX_BYTES = 2 * 1024 * 1024

# JS-bundle path mining. LinkFinder-style: matches quoted path-shaped strings
# inside JS source. We catch:
#   "/api/users/123"        absolute paths
#   "/v1/foo?bar=1"         paths with query strings
#   "https://api.x.com/y"   full URLs
# Matches inside ", ', or ` quotes; captures the path/URL.
_JS_PATH_RE = re.compile(
    r"""(?P<quote>['"`])"""
    r"""(?P<u>"""
    r"""(?:https?:)?//[A-Za-z0-9._\-:/]+(?:[?#][^'"`\s<>{}|^\\]*)?"""  # full URL
    r"""|"""
    r"""/[A-Za-z0-9._/\-]+(?:\.[A-Za-z0-9]{1,8})?(?:[?#][^'"`\s<>{}|^\\]*)?"""  # path
    r""")"""
    r"""(?P=quote)"""
)

# Anchors / forms / scripts in HTML. We deliberately avoid dragging in a
# real HTML parser — regex on the source body covers >95% of crawl-relevant
# refs and keeps the dependency graph tiny. Comprehensive parsing would
# require lxml or BeautifulSoup4 in the sandbox.
_HTML_HREF_RE = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_HTML_SRC_RE = re.compile(r"""<script\b[^>]*?\bsrc\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_HTML_FORM_RE = re.compile(
    r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL
)
_FORM_ATTR_RE = re.compile(r"""\b(action|method)\s*=\s*['"]([^'"]*)['"]""", re.IGNORECASE)
_INPUT_RE = re.compile(r"<input\b([^>]*)/?>", re.IGNORECASE)
_INPUT_ATTR_RE = re.compile(r"""\b(name|type|value)\s*=\s*['"]([^'"]*)['"]""", re.IGNORECASE)


def _http_get(url: str, *, max_bytes: int) -> tuple[int, dict[str, str], str]:
    """GET returning (status, headers, body). (0, {}, '') on failure.

    Routes through the sandbox proxy when available so cluster-A safety
    middleware applies; falls back to direct httpx/urllib otherwise.
    """
    # Path 1: sandbox proxy. ProxyManager.send_simple_request honors
    # auth-injection, exclude-path, and rate-limit — exactly what we want.
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            result = manager.send_simple_request("GET", url, timeout=_HTTP_TIMEOUT)
            if result.get("skipped"):
                return 0, {}, ""
            if "error" in result:
                return 0, {}, ""
            body = result.get("body", "") or ""
            headers = result.get("headers", {}) or {}
            return int(result.get("status_code", 0)), headers, body[:max_bytes]
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)

    # Path 2: direct httpx (host-side or sandbox-without-Caido). The same
    # http_safety middleware applies so auth/exclude/rate-limit still work.
    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            excluded_response,
            inject_auth_headers,
            is_path_excluded,
            throttle_for_rate_limit,
        )

        excluded, _ = is_path_excluded(url)
        if excluded:
            return 0, {}, ""
        headers = inject_auth_headers({})
        throttle_for_rate_limit()
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, verify=False) as c:
            r = c.get(url, headers=headers)
            return r.status_code, dict(r.headers), r.text[:max_bytes]
    except Exception:  # noqa: BLE001
        return 0, {}, ""


def _normalize_url(raw: str, base: str) -> str | None:
    """Resolve `raw` against `base`, drop fragment, return absolute URL.

    Returns None for unsupported schemes (mailto:, javascript:, tel:, data:).
    """
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip()
    if not raw or raw.startswith(("#", "mailto:", "javascript:", "tel:", "data:")):
        return None
    try:
        absolute = urljoin(base, raw)
    except ValueError:
        return None
    absolute, _ = urldefrag(absolute)
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    # Bare-host URLs (no path) normalize to '/' so the home page has a
    # canonical key for the dedup set.
    if not parsed.path:
        absolute = f"{parsed.scheme}://{parsed.netloc}/"
        if parsed.query:
            absolute += f"?{parsed.query}"
    return absolute


def _allowed_hosts_for_target(target: str) -> set[str]:
    """The hostnames the crawler will visit. Default: the target's host
    plus any hostname that ends in `.<apex>` (subdomains in scope)."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = (parsed.hostname or "").lower()
    if not host:
        return set()
    parts = host.split(".")
    if len(parts) >= 2:
        apex = ".".join(parts[-2:])
    else:
        apex = host
    return {host, apex}


def _in_scope(url: str, allowed_hosts: set[str]) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in allowed_hosts:
        return True
    return any(host.endswith(f".{apex}") for apex in allowed_hosts)


def _is_html(headers: dict[str, str]) -> bool:
    ct = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
    return "html" in ct or ct.startswith("text/")


def _is_js(headers: dict[str, str], url: str) -> bool:
    ct = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
    if "javascript" in ct or "ecmascript" in ct:
        return True
    parsed = urlparse(url)
    return parsed.path.lower().endswith((".js", ".mjs", ".cjs"))


def _extract_html_links(body: str, base: str) -> tuple[list[str], list[str]]:
    """Return (anchors, script_srcs) — both as absolute, normalized URLs."""
    anchors: list[str] = []
    for match in _HTML_HREF_RE.finditer(body):
        n = _normalize_url(match.group(1), base)
        if n:
            anchors.append(n)
    scripts: list[str] = []
    for match in _HTML_SRC_RE.finditer(body):
        n = _normalize_url(match.group(1), base)
        if n:
            scripts.append(n)
    return anchors, scripts


def _extract_html_forms(body: str, base: str) -> list[dict[str, Any]]:
    """Per-form: action (resolved), method (default GET), input fields."""
    forms: list[dict[str, Any]] = []
    for fm in _HTML_FORM_RE.finditer(body):
        attrs_text = fm.group(1)
        body_text = fm.group(2)
        attrs: dict[str, str] = {}
        for am in _FORM_ATTR_RE.finditer(attrs_text):
            attrs[am.group(1).lower()] = am.group(2)
        action_raw = attrs.get("action") or ""
        method = (attrs.get("method") or "GET").upper()
        action = _normalize_url(action_raw, base) if action_raw else base
        if not action:
            continue
        fields: list[dict[str, str]] = []
        for im in _INPUT_RE.finditer(body_text):
            attrs_inner = im.group(1)
            field: dict[str, str] = {}
            for fam in _INPUT_ATTR_RE.finditer(attrs_inner):
                field[fam.group(1).lower()] = fam.group(2)
            if field.get("name"):
                fields.append(field)
        forms.append({"url": base, "method": method, "action": action, "fields": fields})
    return forms


def _extract_js_paths(body: str, base: str) -> list[str]:
    """Mine path-shaped string literals out of a JS bundle and resolve to
    absolute URLs against `base`."""
    out: list[str] = []
    seen: set[str] = set()
    for match in _JS_PATH_RE.finditer(body):
        candidate = match.group("u")
        # Heuristic filter: skip references to common static asset extensions
        # the agent doesn't need as endpoints.
        lower = candidate.lower()
        if any(lower.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot")):
            continue
        normalized = _normalize_url(candidate, base)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


# ---------------------------------------------------------------------------
# robots.txt + sitemap.xml — auto-seed paths the crawler would never otherwise
# reach. Agents improvise this; making it deterministic guarantees coverage.
# Roadmap §7.3 expert-pentester gap audit.
# ---------------------------------------------------------------------------


# Disallow / Allow lines may include `*` or `$` glob hints. Normalize to a
# concrete URL, drop wildcards (we'd hit a non-existent path).
_ROBOTS_LINE_RE = re.compile(
    r"^\s*(disallow|allow|sitemap)\s*:\s*(\S+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def _fetch_robots_txt(target_base: str) -> tuple[list[str], list[str]]:
    """Fetch `<base>/robots.txt`. Returns (paths, sitemap_urls).

    Paths are absolute URLs derived from `Disallow:` / `Allow:` lines.
    Wildcards (`*`, `$`) are dropped — we only enqueue concrete paths.
    """
    base_root = _origin_root(target_base)
    if not base_root:
        return [], []
    robots_url = urljoin(base_root, "/robots.txt")
    status, headers, body = _http_get(robots_url, max_bytes=128 * 1024)
    if status != 200 or not body:
        return [], []
    paths: list[str] = []
    sitemaps: list[str] = []
    for match in _ROBOTS_LINE_RE.finditer(body):
        directive = match.group(1).lower()
        value = match.group(2).strip()
        if not value:
            continue
        if directive == "sitemap":
            normalized = _normalize_url(value, base_root)
            if normalized:
                sitemaps.append(normalized)
            continue
        # Disallow / Allow — drop wildcards and patterns; keep concrete paths.
        if "*" in value or "$" in value:
            continue
        normalized = _normalize_url(value, base_root)
        if normalized:
            paths.append(normalized)
    # Dedup preserving order.
    seen: set[str] = set()
    unique_paths = [p for p in paths if not (p in seen or seen.add(p))]
    seen2: set[str] = set()
    unique_sitemaps = [s for s in sitemaps if not (s in seen2 or seen2.add(s))]
    return unique_paths, unique_sitemaps


def _fetch_sitemap_xml(sitemap_url: str, target_base: str) -> list[str]:
    """Fetch + parse a sitemap.xml. Returns absolute URLs from `<loc>` tags.

    Tolerant of sitemap-index format (`<sitemapindex>` containing nested
    `<sitemap><loc>` entries) — we treat both alike since for crawler purposes
    they're all URLs to add to the queue.
    """
    status, _headers, body = _http_get(sitemap_url, max_bytes=2 * 1024 * 1024)
    if status != 200 or not body:
        return []
    urls: list[str] = []
    for match in _SITEMAP_LOC_RE.finditer(body):
        normalized = _normalize_url(match.group(1), target_base)
        if normalized:
            urls.append(normalized)
    seen: set[str] = set()
    return [u for u in urls if not (u in seen or seen.add(u))]


def _origin_root(url: str) -> str | None:
    """Return `scheme://host/` from any URL, or None on parse failure."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}/"


# ---------------------------------------------------------------------------
# OpenAPI consumption
# ---------------------------------------------------------------------------


def _fetch_and_parse_openapi(spec_url: str, target_base: str) -> tuple[list[dict[str, Any]], str | None]:
    """Fetch the OpenAPI spec and return (endpoint list, error_message)."""
    status, _headers, body = _http_get(spec_url, max_bytes=4 * 1024 * 1024)
    if status != 200 or not body:
        return [], f"OpenAPI fetch failed (status {status})"
    try:
        spec = json.loads(body)
    except (ValueError, TypeError):
        # YAML support is intentionally NOT loaded — would require a
        # sandbox dep. Operators with YAML specs are expected to convert.
        return [], "OpenAPI spec is not valid JSON (YAML not supported)"
    if not isinstance(spec, dict):
        return [], "OpenAPI spec is not a JSON object"

    base = target_base
    base_path_prefix = ""
    # OpenAPI 3.x has servers[0].url; OpenAPI 2.x has host + basePath.
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url")
        if isinstance(url, str):
            base = url
    elif spec.get("host"):
        scheme = "https"
        if isinstance(spec.get("schemes"), list) and "http" in spec["schemes"] and "https" not in spec["schemes"]:
            scheme = "http"
        base = f"{scheme}://{spec['host']}/"
        # 2.x basePath is prepended to each path key (urljoin would strip it
        # because absolute paths replace the base path).
        base_path_prefix = (spec.get("basePath") or "").rstrip("/")

    endpoints: list[dict[str, Any]] = []
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return [], "OpenAPI spec has no paths object"
    for path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        for method, _operation in ops.items():
            method_upper = method.upper()
            if method_upper not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                continue
            joined_path = f"{base_path_prefix}{path}" if base_path_prefix else path
            full = _normalize_url(joined_path, base)
            if not full:
                continue
            endpoints.append({
                "url": full,
                "method": method_upper,
                "depth": 0,
                "discovered_via": "openapi",
            })
    return endpoints, None


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1595", "T1083"],  # Active Scanning + File/Directory Discovery
)
def bfs_crawl(
    target: str,
    max_pages: int = _DEFAULT_MAX_PAGES,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    seed_urls: str | None = None,
    openapi_url: str | None = None,
) -> dict[str, Any]:
    """Run a breadth-first crawl of the target and produce an endpoint inventory.

    Composes with cluster-A safety middleware: every fetch goes through the
    sandbox proxy (or the same env-driven http_safety middleware on the
    direct path), so `--auth-*` / `--exclude-path` / `--rate-limit` apply
    automatically.

    Args:
        target: the in-scope target URL (e.g. "https://example.com").
        max_pages: cap on pages visited. Default 200, hard-capped at 2000.
        max_depth: BFS depth cap. Default 3, hard-capped at 8.
        seed_urls: optional comma-separated extra start URLs. The CLI passes
                   `--seed-url` values via `STRIX_SEED_URLS`, which the agent
                   should forward to this parameter.
        openapi_url: optional OpenAPI spec URL. CLI: `--openapi` →
                     `STRIX_OPENAPI_URL`. Spec endpoints are seeded into
                     the crawl as starting points.

    Returns the structured crawl result. Always returns success=True even
    when individual fetches fail (errors are listed in `errors[]`); the
    agent reads `endpoints` and decides how to proceed.
    """
    if not target or not target.strip():
        return {"success": False, "error": "target required"}
    target = target.strip()
    if "://" not in target:
        target = f"https://{target}"
    parsed_target = urlparse(target)
    if parsed_target.scheme not in ("http", "https") or not parsed_target.netloc:
        return {"success": False, "error": f"invalid target URL: {target!r}"}

    capped_max_pages = max(1, min(max_pages, _HARD_MAX_PAGES))
    capped_max_depth = max(0, min(max_depth, _HARD_MAX_DEPTH))
    allowed_hosts = _allowed_hosts_for_target(target)

    # Resolve seeds: CLI env, then explicit param, then target itself.
    seeds: list[str] = []
    env_seeds = os.environ.get("STRIX_SEED_URLS")
    if env_seeds:
        seeds.extend(s.strip() for s in env_seeds.split(",") if s.strip())
    if seed_urls:
        seeds.extend(s.strip() for s in seed_urls.split(",") if s.strip())
    seeds.append(target)
    # Normalize + dedup + scope-filter.
    seen_seeds: set[str] = set()
    normalized_seeds: list[str] = []
    for s in seeds:
        n = _normalize_url(s, target)
        if n and _in_scope(n, allowed_hosts) and n not in seen_seeds:
            seen_seeds.add(n)
            normalized_seeds.append(n)

    # OpenAPI: env first, then param.
    openapi_url = openapi_url or os.environ.get("STRIX_OPENAPI_URL") or None
    openapi_endpoints: list[dict[str, Any]] = []
    openapi_error: str | None = None
    if openapi_url:
        openapi_endpoints, openapi_error = _fetch_and_parse_openapi(openapi_url, target)
        # Seed the crawl with the GET endpoints from the spec.
        for ep in openapi_endpoints:
            if ep["method"] == "GET" and _in_scope(ep["url"], allowed_hosts):
                if ep["url"] not in seen_seeds:
                    seen_seeds.add(ep["url"])
                    normalized_seeds.append(ep["url"])

    # robots.txt + sitemap.xml — auto-discovery of paths the crawler would
    # never find via link extraction. Each in-scope concrete path becomes
    # a seed with `discovered_via` tagged appropriately. Failures are silent
    # (surfaced in the result's `errors[]` list).
    robots_paths: list[str] = []
    sitemap_urls: list[str] = []
    sitemap_paths_total: list[str] = []
    try:
        robots_paths, robots_sitemaps = _fetch_robots_txt(target)
        for path in robots_paths:
            if _in_scope(path, allowed_hosts) and path not in seen_seeds:
                seen_seeds.add(path)
                normalized_seeds.append(path)
        # Try the explicit sitemap URLs from robots first, then the default
        # `/sitemap.xml` if no robots-listed sitemaps exist.
        candidate_sitemaps = list(robots_sitemaps)
        if not candidate_sitemaps:
            base_root = _origin_root(target)
            if base_root:
                candidate_sitemaps.append(urljoin(base_root, "/sitemap.xml"))
        for sm_url in candidate_sitemaps:
            if not _in_scope(sm_url, allowed_hosts):
                continue
            if sm_url in sitemap_urls:
                continue
            sitemap_urls.append(sm_url)
            sm_paths = _fetch_sitemap_xml(sm_url, target)
            for path in sm_paths:
                if _in_scope(path, allowed_hosts):
                    sitemap_paths_total.append(path)
                    if path not in seen_seeds:
                        seen_seeds.add(path)
                        normalized_seeds.append(path)
    except Exception:  # noqa: BLE001
        logger.debug("robots/sitemap fetch failed", exc_info=True)

    started_at = datetime.now(UTC).isoformat()

    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque((s, 0) for s in normalized_seeds)
    endpoints: list[dict[str, Any]] = list(openapi_endpoints)
    # Tag the robots-discovered paths so downstream consumers can see they
    # came from a /robots.txt Disallow line (often higher-value endpoints).
    endpoint_keys: set[tuple[str, str]] = {(e["url"], e["method"]) for e in endpoints}
    for path in robots_paths:
        if _in_scope(path, allowed_hosts) and (path, "GET") not in endpoint_keys:
            endpoint_keys.add((path, "GET"))
            endpoints.append({
                "url": path, "method": "GET", "depth": 0, "discovered_via": "robots_disallow",
            })
    for path in sitemap_paths_total:
        if (path, "GET") not in endpoint_keys:
            endpoint_keys.add((path, "GET"))
            endpoints.append({
                "url": path, "method": "GET", "depth": 0, "discovered_via": "sitemap",
            })
    forms: list[dict[str, Any]] = []
    js_bundles: list[str] = []
    js_bundles_parsed = 0
    errors: list[str] = []
    if openapi_error:
        errors.append(openapi_error)

    # endpoint_keys was already populated above with the OpenAPI / robots
    # / sitemap entries; we just reuse it for HTML / form / JS additions.

    def _record_endpoint(url: str, method: str, depth: int, source: str) -> None:
        key = (url, method)
        if key in endpoint_keys:
            return
        endpoint_keys.add(key)
        endpoints.append({
            "url": url,
            "method": method,
            "depth": depth,
            "discovered_via": source,
        })
        # iter-32.1 — route each newly-discovered endpoint through
        # workflow_state so iter-31.9 surface_discovery_breadth has a
        # numerator when only L2 (no L1 prepass) ran. Best-effort.
        try:
            from strix.agents.workflow_state import record_endpoint_discovered
            record_endpoint_discovered(url)
        except Exception:  # noqa: BLE001
            pass

    while queue and len(visited) < capped_max_pages:
        url, depth = queue.popleft()
        if url in visited:
            continue
        if not _in_scope(url, allowed_hosts):
            continue
        visited.add(url)

        # Tag the visited URL itself as a GET endpoint.
        _record_endpoint(url, "GET", depth, "seed" if url in seen_seeds else "html")

        if depth >= capped_max_depth:
            continue

        status, headers, body = _http_get(url, max_bytes=_HTML_BODY_MAX_BYTES)
        if status == 0:
            errors.append(f"{url}: fetch failed (or excluded / rate-limited)")
            continue
        if status >= 400:
            # 401/403/404/etc. are recorded as endpoints (status itself is
            # signal) but not crawled deeper.
            continue

        if _is_js(headers, url):
            # Re-fetch with the JS-body cap if we're crawling into a JS file
            # via a script-src link.
            if len(body) >= _HTML_BODY_MAX_BYTES:
                _, _, body = _http_get(url, max_bytes=_JS_BODY_MAX_BYTES)
            js_bundles_parsed += 1
            for path in _extract_js_paths(body, url):
                if not _in_scope(path, allowed_hosts):
                    continue
                _record_endpoint(path, "GET", depth + 1, "js_bundle")
                if path not in visited:
                    queue.append((path, depth + 1))
            continue

        if not _is_html(headers):
            continue

        anchors, scripts = _extract_html_links(body, url)
        for js in scripts:
            if not _in_scope(js, allowed_hosts):
                continue
            if js not in js_bundles:
                js_bundles.append(js)
            if js not in visited:
                queue.append((js, depth + 1))

        for link in anchors:
            if not _in_scope(link, allowed_hosts):
                continue
            _record_endpoint(link, "GET", depth + 1, "html")
            if link not in visited:
                queue.append((link, depth + 1))

        for form in _extract_html_forms(body, url):
            forms.append(form)
            _record_endpoint(form["action"], form["method"], depth + 1, "form")

    ended_at = datetime.now(UTC).isoformat()

    # iter-32.1 — defence-in-depth: ensure every endpoint in the final
    # list reaches workflow_state.record_endpoint_discovered(). Catches
    # the sitemap / openapi / robots paths that bypass _record_endpoint
    # above. Idempotent (record_endpoint_discovered uses a set).
    try:
        from strix.agents.workflow_state import record_endpoint_discovered as _rec
        for _ep in endpoints:
            _rec(_ep.get("url") or "")
    except Exception:  # noqa: BLE001
        pass

    return {
        "success": True,
        "target": target,
        "started_at": started_at,
        "ended_at": ended_at,
        "seed_urls": normalized_seeds,
        "openapi_url": openapi_url,
        "config": {
            "max_pages": capped_max_pages,
            "max_depth": capped_max_depth,
            "allowed_hosts": sorted(allowed_hosts),
        },
        "endpoints": endpoints,
        "forms": forms,
        "js_bundles": js_bundles,
        "robots_paths": robots_paths,
        "sitemap_urls": sitemap_urls,
        "errors": errors,
        "stats": {
            "pages_visited": len(visited),
            "endpoints_discovered": len(endpoints),
            "forms_found": len(forms),
            "js_bundles_parsed": js_bundles_parsed,
            "openapi_endpoints_imported": len(openapi_endpoints),
            "robots_paths_discovered": len(robots_paths),
            "sitemap_paths_discovered": len(sitemap_paths_total),
        },
    }
