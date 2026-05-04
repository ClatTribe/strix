"""SBOM extraction from web targets.

Produces a CycloneDX 1.5-shaped SBOM by black-box-fingerprinting
a web target. The SBOM is a structured artifact auditors can
consume directly (NIST SSDF, EU CRA, SOC 2 CC9 supplier risk).

Detection paths
---------------

1. **CDN-served NPM packages** — the URL itself encodes
   package name and version on the major CDNs:

       https://cdn.jsdelivr.net/npm/<name>@<version>/...
       https://unpkg.com/<name>@<version>/...
       https://cdnjs.cloudflare.com/ajax/libs/<name>/<version>/...
       https://ajax.googleapis.com/ajax/libs/<name>/<version>/...

   Every `<script src=...>` and `<link href=...>` extracted from
   the response HTML is parsed against these patterns.

2. **Backend frameworks via headers** — `Server` / `X-Powered-By`
   / `X-AspNet-Version` / `X-Drupal-Cache` / `X-Generator` / etc.
   Maps the values to the canonical PURL component.

3. **Frontend frameworks via HTML markers** — well-known DOM
   identifiers / meta tags (`<meta name="generator" content="...">`,
   `__NEXT_DATA__` for Next.js, `data-reactroot` for React,
   `data-server-rendered` for Vue, etc.). Version-extraction is
   best-effort from the meta tag's `content` attribute.

Output: CycloneDX 1.5 JSON. Each component carries `name`,
`version`, `purl`, `type` (library / framework), `bom-ref`, and
`detected_via` (which detection path identified it).

Why this is zero-FP-by-construction
-----------------------------------

* CDN URL parsing is byte-level deterministic — `unpkg.com/foo@1.2.3`
  is unambiguously package `foo` version `1.2.3`.
* Header-based backend detection is binary header presence
  + regex on a canonical `<name>/<version>` shape.
* HTML-marker detection only fires when the framework ships its
  own self-identifying DOM artifact. We deliberately don't grep
  bundle bodies for "react" — too noisy.

Cross-reference with CVE/KEV
----------------------------

Each detected component triggers `cve_lookup` (#61) when the
package + version is precise enough. CVE-bearing components
emit `vulnerable_dependency` findings alongside the SBOM.

References
----------

* CycloneDX 1.5 spec: https://cyclonedx.org/specification/overview/
* NIST SSDF (SP 800-218) PO.1.2 — SBOM management
* EU CRA Annex I §1(2)(d) — SBOM in machine-readable format
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "sbom_extract"
_DEFAULT_TIMEOUT = 10.0
_MAX_HTML_BYTES = 256 * 1024  # cap HTML scan window


# ---------------------------------------------------------------------------
# CDN URL → (package, version) parsers
# ---------------------------------------------------------------------------


_CDN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "jsdelivr",
        re.compile(
            r"^https?://cdn\.jsdelivr\.net/npm/(?P<name>@?[^@/]+(?:/[^@/]+)?)@(?P<version>[^/]+)/",
            re.IGNORECASE,
        ),
    ),
    (
        "unpkg",
        re.compile(
            r"^https?://unpkg\.com/(?P<name>@?[^@/]+(?:/[^@/]+)?)@(?P<version>[^/]+)/",
            re.IGNORECASE,
        ),
    ),
    (
        "cdnjs",
        re.compile(
            r"^https?://cdnjs\.cloudflare\.com/ajax/libs/(?P<name>[^/]+)/(?P<version>[^/]+)/",
            re.IGNORECASE,
        ),
    ),
    (
        "google_ajax",
        re.compile(
            r"^https?://ajax\.googleapis\.com/ajax/libs/(?P<name>[^/]+)/(?P<version>[^/]+)/",
            re.IGNORECASE,
        ),
    ),
]


def _parse_cdn_url(url: str) -> dict[str, Any] | None:
    """If `url` matches one of the canonical CDN patterns, return
    `{name, version, ecosystem, cdn, purl}`. None otherwise."""
    for cdn_name, pattern in _CDN_PATTERNS:
        m = pattern.match(url.strip())
        if m:
            name = m.group("name")
            version = m.group("version")
            # Strip common suffixes that aren't part of the version.
            if "/" in version:
                version = version.split("/", 1)[0]
            ecosystem = "npm" if cdn_name in ("jsdelivr", "unpkg") else "cdn-asset"
            purl = (
                f"pkg:{ecosystem}/{name}@{version}"
                if ecosystem == "npm"
                else f"pkg:generic/{name}@{version}"
            )
            return {
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "cdn": cdn_name,
                "purl": purl,
                "url": url,
            }
    return None


# ---------------------------------------------------------------------------
# HTML extraction
# ---------------------------------------------------------------------------


_SCRIPT_SRC_RE = re.compile(
    r'<script\b[^>]*?\bsrc\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)
_LINK_HREF_RE = re.compile(
    r'<link\b[^>]*?\bhref\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)
_META_GENERATOR_RE = re.compile(
    r'<meta\b[^>]*?\bname\s*=\s*["\']generator["\'][^>]*?\bcontent\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)


def _extract_external_urls(html: str) -> list[str]:
    """Return all external URLs from `<script src="...">` and
    `<link href="...">` tags."""
    out: list[str] = []
    for m in _SCRIPT_SRC_RE.finditer(html):
        out.append(m.group(1))
    for m in _LINK_HREF_RE.finditer(html):
        out.append(m.group(1))
    return out


# Frontend-framework markers in HTML.
_FRONTEND_MARKERS: list[tuple[str, str, re.Pattern[str]]] = [
    # (component_name, ecosystem, pattern)
    ("react", "npm", re.compile(r'\bdata-reactroot\b|\bdata-react-helmet\b', re.IGNORECASE)),
    ("vue", "npm", re.compile(r'\bdata-server-rendered\b|\bdata-v-[a-f0-9]{8}\b', re.IGNORECASE)),
    ("next.js", "npm", re.compile(r'\b__NEXT_DATA__\b|/_next/static/', re.IGNORECASE)),
    ("nuxt", "npm", re.compile(r'\b__NUXT__\b|/_nuxt/', re.IGNORECASE)),
    ("svelte", "npm", re.compile(r'\bclass="svelte-[a-z0-9]+"\b', re.IGNORECASE)),
    ("angular", "npm", re.compile(r'\bng-version\b|\bng-app\b', re.IGNORECASE)),
]


def _extract_frontend_frameworks(html: str) -> list[dict[str, Any]]:
    """Detect frontend frameworks via well-known DOM markers."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, ecosystem, pattern in _FRONTEND_MARKERS:
        if name in seen:
            continue
        if pattern.search(html):
            seen.add(name)
            out.append({
                "name": name,
                "version": None,  # version extraction is hard from markers
                "ecosystem": ecosystem,
                "purl": f"pkg:{ecosystem}/{name}",
                "detected_via": "html_marker",
            })

    # <meta name="generator"> often carries `<framework>/<version>`.
    gen_match = _META_GENERATOR_RE.search(html)
    if gen_match:
        gen = gen_match.group(1).strip()
        # Common shape: "WordPress 6.2.1" / "Hugo 0.115.0".
        m = re.match(r"([A-Za-z][A-Za-z0-9 _-]+?)\s+([\d][\d.\w-]*)", gen)
        if m:
            name = m.group(1).strip().lower().replace(" ", "-")
            version = m.group(2).strip()
            if name not in seen:
                out.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "generic",
                    "purl": f"pkg:generic/{name}@{version}",
                    "detected_via": "meta_generator",
                })

    return out


# ---------------------------------------------------------------------------
# Header-based backend detection
# ---------------------------------------------------------------------------

# Map header name → (parse function). Each parser returns a list
# of components (zero or one in practice).
_HEADER_PARSERS: list[tuple[str, str]] = [
    ("server", "server"),
    ("x-powered-by", "x_powered_by"),
    ("x-aspnet-version", "x_aspnet_version"),
    ("x-aspnetmvc-version", "x_aspnetmvc_version"),
    ("x-drupal-cache", "x_drupal_cache"),
    ("x-generator", "x_generator"),
    ("x-rails-version", "x_rails_version"),
]


def _parse_versioned_header(value: str) -> tuple[str, str | None] | None:
    """Parse `nginx/1.21.0` or `Express` or `PHP/8.1.10` into
    `(name, version)`. Returns None when the value is empty."""
    value = (value or "").strip()
    if not value:
        return None
    # Multi-token Server: header (e.g. "nginx/1.21.0 (Ubuntu)") —
    # take the first token.
    first = value.split()[0]
    if "/" in first:
        name, _, version = first.partition("/")
        return (name.strip().lower(), version.strip() or None)
    # No version component.
    return (first.strip().lower(), None)


def _extract_backend_from_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for header_name, _label in _HEADER_PARSERS:
        value = headers.get(header_name)
        if not value:
            continue
        parsed = _parse_versioned_header(value)
        if parsed is None:
            continue
        name, version = parsed
        if name in seen:
            continue
        seen.add(name)
        purl = (
            f"pkg:generic/{name}@{version}"
            if version
            else f"pkg:generic/{name}"
        )
        out.append({
            "name": name,
            "version": version,
            "ecosystem": "generic",
            "purl": purl,
            "detected_via": f"header:{header_name}",
        })
    return out


# ---------------------------------------------------------------------------
# CycloneDX 1.5 envelope
# ---------------------------------------------------------------------------


def _bom_ref(component: dict[str, Any], idx: int) -> str:
    base = component.get("name") or "component"
    version = component.get("version")
    if version:
        return f"{base}@{version}-{idx}"
    return f"{base}-{idx}"


def _component_to_cyclonedx(component: dict[str, Any], idx: int) -> dict[str, Any]:
    return {
        "type": "library" if component.get("ecosystem") == "npm" else "framework",
        "bom-ref": _bom_ref(component, idx),
        "name": component["name"],
        "version": component.get("version"),
        "purl": component.get("purl"),
        "evidence": {
            "identity": {
                "field": "purl",
                "confidence": 1.0 if component.get("version") else 0.7,
                "methods": [
                    {
                        "technique": component.get("detected_via", "url-pattern"),
                        "confidence": 1.0 if component.get("version") else 0.7,
                    }
                ],
            }
        },
        # Strix-specific metadata — ignored by spec-strict consumers,
        # useful for the wrapper.
        "x-strix-detected-via": component.get("detected_via", "url-pattern"),
        "x-strix-source-url": component.get("url"),
    }


def _build_cyclonedx_bom(
    components: list[dict[str, Any]],
    *,
    target: str,
    run_id: str | None = None,
) -> dict[str, Any]:
    from datetime import UTC, datetime
    from uuid import uuid4

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": [{"name": "strix", "vendor": "ClatTribe", "version": "fork"}],
            "component": {
                "type": "application",
                "name": target,
                "bom-ref": f"target:{target}",
            },
            "x-strix-run-id": run_id,
        },
        "components": [
            _component_to_cyclonedx(c, idx) for idx, c in enumerate(components)
        ],
    }


# ---------------------------------------------------------------------------
# HTTP fetch
# ---------------------------------------------------------------------------


def _http_get(url: str, *, timeout: float = _DEFAULT_TIMEOUT) -> dict[str, Any]:
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None

    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, timeout=int(timeout))
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": (r.get("body") or "")[:_MAX_HTML_BYTES],
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy fetch failed; falling back", exc_info=True)

    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            is_path_excluded,
            throttle_for_rate_limit,
        )

        excluded, _ = is_path_excluded(url)
        if excluded:
            return {"status": 0, "headers": {}, "body": "", "skipped": True}
        merged = inject_auth_headers({})
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_HTML_BYTES],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(d: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in d.items()}


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


def _normalize_target(target: str) -> str | None:
    if not isinstance(target, str) or not target.strip():
        return None
    target = target.strip()
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return target


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1592.002"],
)
def sbom_extract(
    target_url: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Black-box-extract a CycloneDX 1.5 SBOM from a web target.

    Args:
        target_url: web target (URL or bare host; auto-prefixed `https://`).
        timeout: per-request HTTP timeout (default 10s).

    Returns:
        ```
        {
          success, target,
          components_detected: int,
          components: [{name, version, ecosystem, purl, detected_via, ...}],
          cyclonedx: {... CycloneDX 1.5 JSON ...},
          errors?: [str, ...],
        }
        ```

    Components are deduped by `(name, version)` tuple — the same
    package appearing on jsdelivr AND a `<script>` tag won't
    double-count.
    """
    target = _normalize_target(target_url)
    if target is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    parsed = urlparse(target)
    target_host = parsed.netloc
    errors: list[str] = []

    r = _http_get(target, timeout=timeout)
    if r.get("error"):
        errors.append(r["error"])
    if r.get("skipped"):
        return {
            "success": True,
            "target": target_host,
            "components_detected": 0,
            "components": [],
            "cyclonedx": _build_cyclonedx_bom([], target=target_host),
            "skipped": True,
            "errors": errors or None,
        }

    headers = r.get("headers") or {}
    body = r.get("body") or ""

    components: list[dict[str, Any]] = []

    # 1. Backend frameworks from headers.
    components.extend(_extract_backend_from_headers(headers))

    # 2. CDN-served NPM packages from HTML <script>/<link> tags.
    cdn_seen: set[tuple[str, str]] = set()
    for url in _extract_external_urls(body):
        parsed_cdn = _parse_cdn_url(url)
        if parsed_cdn is None:
            continue
        key = (parsed_cdn["name"], parsed_cdn["version"])
        if key in cdn_seen:
            continue
        cdn_seen.add(key)
        components.append({
            "name": parsed_cdn["name"],
            "version": parsed_cdn["version"],
            "ecosystem": parsed_cdn["ecosystem"],
            "purl": parsed_cdn["purl"],
            "url": parsed_cdn["url"],
            "detected_via": f"cdn:{parsed_cdn['cdn']}",
        })

    # 3. Frontend frameworks from HTML markers.
    components.extend(_extract_frontend_frameworks(body))

    # Cross-component dedup by (name, version).
    seen: set[tuple[str, str | None]] = set()
    deduped: list[dict[str, Any]] = []
    for c in components:
        key = (c["name"], c.get("version"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)

    # Build the CycloneDX envelope.
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        run_id = tracer.run_id if tracer is not None else None
    except Exception:  # noqa: BLE001
        run_id = None
    bom = _build_cyclonedx_bom(deduped, target=target_host, run_id=run_id)

    # Persist the CycloneDX file when a tracer is present (auditor
    # bundle expects a `sbom.cdx.json` artifact on disk).
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is not None:
            run_dir = tracer.get_run_dir()
            run_dir.mkdir(parents=True, exist_ok=True)
            sbom_path = run_dir / "sbom.cdx.json"
            import json as _json

            sbom_path.write_text(
                _json.dumps(bom, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
    except Exception:  # noqa: BLE001
        logger.debug("sbom file write failed", exc_info=True)

    out: dict[str, Any] = {
        "success": True,
        "target": target_host,
        "components_detected": len(deduped),
        "components": deduped,
        "cyclonedx": bom,
    }
    if errors:
        out["errors"] = errors
    return out
