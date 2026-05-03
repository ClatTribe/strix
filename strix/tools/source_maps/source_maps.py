"""Source-map exposure probe.

Strategy (low-noise, deterministic):

1. Fetch the target's HTML root, extract `<script src>` URLs.
2. For each in-scope script, try `<src>.map`.
3. Probe a curated set of well-known bundle-name candidates at common
   asset roots: `/app.js.map`, `/main.js.map`, `/bundle.js.map`,
   `/static/js/main.js.map`, `/_next/static/<hash>/_app.js.map`, etc.
4. For each 200 hit:
   - Validate it parses as a v3 source-map JSON object (has `version`
     and either `sources` or `sourcesContent`).
   - Emit medium-severity finding with the discovered URL + source-file
     count + sample source paths.
   - If `sourcesContent` is present (full inlined source shipped to
     clients) AND secret-indicator regex hits, escalate to **high**
     and tag `category=secret_leak`.

Composes with cluster-A safety (auth-injection / exclude-path / rate-
limit) automatically. Findings carry `description_plain` +
`recommended_action` + `fix_time_estimate=1hr` (build-config tweak).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "source_map_probe"
_HTTP_TIMEOUT = 12

# Source-map files can be huge (entire bundle source inlined). Cap per-
# file at 8 MB so a single 100 MB asset doesn't blow up the sandbox.
_MAP_BODY_CAP_BYTES = 8 * 1024 * 1024
# Cap on script-src URLs harvested from the home page.
_MAX_HTML_SCRIPTS = 50
# Hard cap on the number of map probes per call (covers HTML scripts
# + bundle-name candidates combined).
_MAX_PROBES = 60

# HTML <script src="..."> extractor — same regex used in bfs_crawl.
_HTML_SCRIPT_SRC_RE = re.compile(
    r"""<script\b[^>]*?\bsrc\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE
)

# Modern SPAs (Next.js, Vite, Angular, Vue) ship most of their bundle
# URLs via <link rel="modulepreload"> or <link rel="preload" as="script">
# rather than inline <script> tags. The regex matches both patterns and
# captures the href value.
_HTML_LINK_PRELOAD_RE = re.compile(
    r"""<link\b(?=[^>]*?\brel\s*=\s*['"](?:modulepreload|preload)['"])"""
    r"""(?=[^>]*?\bhref\s*=\s*['"]([^'"]+)['"])"""
    r"""(?:[^>]*?\bas\s*=\s*['"](script|module)['"])?[^>]*?>""",
    re.IGNORECASE,
)

# Loose JS-source regex for URL-shaped strings inside inline <script>
# blocks. Modern SPA shells embed an array of chunk URLs inside an inline
# bootstrap script ("__NEXT_DATA__", "__VITE_PRELOAD__", build manifests).
# We capture path-shaped string literals that end with `.js` (with optional
# query / hash fragment).
_INLINE_SCRIPT_BLOCK_RE = re.compile(
    r"<script\b(?![^>]*\bsrc\s*=)[^>]*?>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
_INLINE_JS_PATH_RE = re.compile(
    r"""['"`]"""
    r"""(/[A-Za-z0-9._/\-]+?\.[mc]?js(?:\?[^'"`]*)?)"""
    r"""['"`]"""
)

# Common bundle-name candidates probed at the origin root and a few
# well-known asset directories. Keeps the probe count bounded; agents
# can supply additional URLs via `extra_urls`.
_BUNDLE_NAME_CANDIDATES: tuple[str, ...] = (
    # Generic / Webpack-default
    "/app.js.map",
    "/main.js.map",
    "/bundle.js.map",
    "/index.js.map",
    "/vendor.js.map",
    "/runtime.js.map",
    # Create-React-App / Webpack production layout
    "/static/js/main.js.map",
    "/static/js/app.js.map",
    "/static/js/bundle.js.map",
    "/static/js/runtime.js.map",
    "/static/js/runtime-main.js.map",
    "/static/js/vendors.js.map",
    "/static/js/vendors~main.js.map",
    "/static/js/2.chunk.js.map",
    # Vite default layout
    "/assets/index.js.map",
    "/assets/main.js.map",
    "/assets/app.js.map",
    "/assets/vendor.js.map",
    "/assets/index-legacy.js.map",
    # General /dist/ /build/ /js/ asset roots
    "/dist/main.js.map",
    "/dist/bundle.js.map",
    "/dist/app.js.map",
    "/build/main.js.map",
    "/build/static/js/main.js.map",
    "/js/main.js.map",
    "/js/app.js.map",
    "/js/bundle.js.map",
    # Angular CLI default layout (`/runtime.js.map` and `/vendor.js.map`
    # are already covered above; Angular-specific additions only)
    "/polyfills.js.map",
    "/styles.js.map",
    "/main-es2015.js.map",
    "/main-es5.js.map",
    # Next.js — best-effort guesses (chunk names are usually hashed)
    "/_next/static/chunks/main.js.map",
    "/_next/static/chunks/webpack.js.map",
    "/_next/static/chunks/framework.js.map",
    "/_next/static/chunks/pages/_app.js.map",
    # Nuxt / Vue
    "/_nuxt/main.js.map",
    "/_nuxt/app.js.map",
    "/_nuxt/entry.js.map",
)

# Reuse the secret-indicator regex used in code_search_for_domain. Without
# \b boundaries because `_` is a word-char and breaks tokens like
# AWS_SECRET_KEY. False positives here are acceptable — finding gets
# `verification_status=needs_review`.
_SECRET_INDICATOR_RE = re.compile(
    r"("
    r"api[_-]?key|access[_-]?key|secret[_-]?key|secret_access_key|"
    r"client[_-]?secret|auth[_-]?token|bearer\s|password|passwd|"
    r"private[_-]?key|aws_access|aws_secret|stripe_(?:live|test)_|"
    r"sk_(?:live|test)_|xox[abopr]-|ghp_[A-Za-z0-9]|gho_[A-Za-z0-9]|"
    r"glpat-|slack_token|github_token|credential"
    r")",
    re.IGNORECASE,
)


def _http_get(url: str, *, max_bytes: int = _MAP_BODY_CAP_BYTES) -> dict[str, Any]:
    """GET via cluster-A safety. Returns {status, headers, body, error?, skipped?}."""
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, timeout=_HTTP_TIMEOUT)
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": r.get("headers") or {},
                "body": (r.get("body") or "")[:max_bytes],
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)
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
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=False, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body": r.text[:max_bytes],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _origin_root(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}/"


def _in_same_origin(candidate: str, origin: str) -> bool:
    """True iff candidate's host == origin's host. Source-map probe stays
    same-origin — we don't follow off-origin script srcs (CDN-hosted libs
    almost never ship source maps, and probing them is noise)."""
    a = urlparse(candidate)
    b = urlparse(origin if "://" in origin else f"https://{origin}")
    return (a.hostname or "").lower() == (b.hostname or "").lower()


def _harvest_script_srcs(html_body: str, base: str) -> list[str]:
    """Pull JS bundle URLs out of HTML, resolve to absolute, same-origin only.

    Sources covered (in order, each contributes to the same dedup set):
    1. `<script src="...">` — classic.
    2. `<link rel="modulepreload" href="...">` — Vite, modern SPAs.
    3. `<link rel="preload" as="script" href="...">` — Next.js, others.
    4. JS path-shaped string literals inside inline `<script>` blocks —
       Next.js / Nuxt / Vite ship a build-manifest array embedded in the
       page bootstrap, listing every chunk URL. Bounded scan to keep
       regex cost predictable.
    """
    out: list[str] = []
    seen: set[str] = set()

    def _accept(raw: str) -> None:
        if not raw or raw.startswith(("data:", "javascript:")):
            return
        absolute = urljoin(base, raw)
        path = urlparse(absolute).path
        if not path.endswith((".js", ".mjs", ".cjs")):
            return
        if not _in_same_origin(absolute, base):
            return
        if absolute not in seen and len(out) < _MAX_HTML_SCRIPTS:
            seen.add(absolute)
            out.append(absolute)

    # 1. <script src>
    for match in _HTML_SCRIPT_SRC_RE.finditer(html_body):
        if len(out) >= _MAX_HTML_SCRIPTS:
            break
        _accept(match.group(1).strip())

    # 2. + 3. <link rel="modulepreload"> / <link rel="preload" as="script">
    if len(out) < _MAX_HTML_SCRIPTS:
        for match in _HTML_LINK_PRELOAD_RE.finditer(html_body):
            if len(out) >= _MAX_HTML_SCRIPTS:
                break
            _accept(match.group(1).strip())

    # 4. JS paths inside inline <script> blocks. Bounded total scan length
    # so a 5 MB minified runtime doesn't slow this regex pass.
    if len(out) < _MAX_HTML_SCRIPTS:
        scanned_bytes = 0
        scan_cap = 512 * 1024  # 512 KB cumulative across inline blocks
        for block in _INLINE_SCRIPT_BLOCK_RE.finditer(html_body):
            body = block.group(1) or ""
            if scanned_bytes + len(body) > scan_cap:
                body = body[: max(0, scan_cap - scanned_bytes)]
            scanned_bytes += len(body)
            for path_match in _INLINE_JS_PATH_RE.finditer(body):
                if len(out) >= _MAX_HTML_SCRIPTS:
                    break
                _accept(path_match.group(1).strip())
            if len(out) >= _MAX_HTML_SCRIPTS or scanned_bytes >= scan_cap:
                break

    return out


def _is_source_map_json(data: Any) -> bool:
    """v3 source map: object with `version` (3) and either `sources` or
    `sourcesContent`. Tolerant of older v2/v1 shapes too."""
    if not isinstance(data, dict):
        return False
    has_version = "version" in data
    has_sources = isinstance(data.get("sources"), list) or isinstance(
        data.get("sourcesContent"), list
    )
    return has_version and has_sources


def _scan_for_secrets(data: dict[str, Any]) -> list[dict[str, str]]:
    """Look for secret-indicator regex hits in `sourcesContent[]`.

    Returns a list of {file, snippet} matches (capped at 5; full source
    bodies are NEVER returned — only ≤120-char snippets centered on the
    match).
    """
    out: list[dict[str, str]] = []
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    if not isinstance(sources, list) or not isinstance(contents, list):
        return out
    for idx, content in enumerate(contents):
        if not isinstance(content, str) or not content.strip():
            continue
        match = _SECRET_INDICATOR_RE.search(content)
        if match:
            start = max(0, match.start() - 40)
            end = min(len(content), match.end() + 40)
            snippet = content[start:end].replace("\n", " ").strip()
            file_path = sources[idx] if idx < len(sources) and isinstance(sources[idx], str) else f"<sourcesContent[{idx}]>"
            out.append({"file": file_path, "snippet": snippet[:120]})
            if len(out) >= 5:
                break
    return out


def _emit_finding(
    *,
    title: str,
    severity: str,
    category: str,
    cwe: str,
    target_url: str,
    map_url: str,
    description: str,
    description_plain: str,
    recommended_action: str,
    verification_status: str = "verified",
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
        category=category,
        cwe=cwe,
        target=target_url,
        endpoint=map_url,
        description=description,
        impact=(
            "Source maps reverse the JS minification: every variable name, "
            "function name, file path, and (when sourcesContent is included) "
            "the entire pre-minified source is recovered. Attackers gain "
            "full visibility into client-side logic, internal API shapes, "
            "and any secrets the build accidentally baked into the bundle. "
            "This is a major leak even when no credentials are present — "
            "it removes obscurity layers the rest of the app's threat model "
            "may have implicitly depended on."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        fix_time_estimate="1hr",
        verification_status=verification_status,
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


@register_tool(sandbox_execution=True)
def source_map_probe(
    target_url: str,
    extra_urls: str | None = None,
) -> dict[str, Any]:
    """Probe a target for accessible `*.js.map` files.

    Args:
        target_url: target URL. The HTML at this URL is fetched + scanned
                    for `<script src>` attributes; each in-scope script
                    URL is probed at `<src>.map`. The origin root is also
                    probed against a curated ~23-name candidate list of
                    common bundle paths (`/app.js.map`, `/main.js.map`,
                    `/static/js/main.js.map`, etc.).
        extra_urls: comma-separated extra map URLs to probe (e.g. when
                    the agent already knows a non-standard path).

    Findings:
        - **Medium** (CWE-540, info_disclosure) per accessible source-map
          with `version` + (`sources` OR `sourcesContent`) shape.
        - Escalates to **High** (CWE-200, secret_leak,
          `verification_status=needs_review`) when `sourcesContent[]`
          contains secret-indicator tokens (`api_key`, `aws_secret`,
          `Bearer`, `ghp_*`, etc.).

    Composes with cluster-A safety. Returns:
        {success, target_url, probed: int, hits: [{url, source_count,
         has_sources_content, secret_hits: [...]}], stats}
    """
    if not target_url or not target_url.strip():
        return {"success": False, "error": "target_url required"}
    target_url = target_url.strip()
    if "://" not in target_url:
        target_url = f"https://{target_url}"
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {"success": False, "error": f"invalid target URL: {target_url!r}"}

    cev = _start_check("source_map_probe", target_url)

    origin = _origin_root(target_url)
    if not origin:
        _complete_check(cev, "inconclusive", "origin extraction failed")
        return {"success": False, "error": "origin extraction failed"}

    # Step 1: harvest script srcs from the target HTML.
    html_response = _http_get(target_url, max_bytes=2 * 1024 * 1024)
    script_srcs: list[str] = []
    if html_response.get("status") == 200:
        ct = (html_response.get("headers", {}).get("content-type")
              or html_response.get("headers", {}).get("Content-Type")
              or "").lower()
        if "html" in ct or ct.startswith("text/"):
            script_srcs = _harvest_script_srcs(
                html_response.get("body", "") or "", target_url
            )

    # Step 2: build the candidate map-URL list.
    candidates: list[str] = []
    seen: set[str] = set()
    for src in script_srcs:
        candidate = f"{src}.map"
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)
    for path in _BUNDLE_NAME_CANDIDATES:
        candidate = urljoin(origin, path)
        if candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)
    if extra_urls:
        for extra in extra_urls.split(","):
            extra = extra.strip()
            if not extra:
                continue
            candidate = urljoin(origin, extra)
            if not _in_same_origin(candidate, origin):
                continue
            if candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)

    candidates = candidates[:_MAX_PROBES]

    # Step 3: probe each candidate.
    hits: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    secret_hit_count = 0
    for url in candidates:
        response = _http_get(url)
        if response.get("skipped"):
            errors.append({"url": url, "error": "excluded by --exclude-path"})
            continue
        if response.get("error"):
            errors.append({"url": url, "error": str(response["error"])[:200]})
            continue
        status = response.get("status") or 0
        if status != 200:
            continue
        body = response.get("body", "") or ""
        if not body.strip():
            continue
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            continue
        if not _is_source_map_json(data):
            continue
        sources = data.get("sources") or []
        contents = data.get("sourcesContent") or []
        sample_sources = sources[:10] if isinstance(sources, list) else []
        secret_hits = _scan_for_secrets(data) if isinstance(contents, list) and contents else []
        if secret_hits:
            secret_hit_count += len(secret_hits)
        has_contents = bool(contents)

        hit = {
            "url": url,
            "source_count": len(sources) if isinstance(sources, list) else 0,
            "has_sources_content": has_contents,
            "sample_sources": sample_sources,
            "secret_hits": secret_hits,
        }
        hits.append(hit)

        # Emit finding.
        if secret_hits:
            sample_files = ", ".join(h["file"] for h in secret_hits[:3])
            _emit_finding(
                title=f"Source map exposes secrets at {url}",
                severity="high",
                category="secret_leak",
                cwe="CWE-200",
                target_url=target_url,
                map_url=url,
                description=(
                    f"Source map at {url} is publicly accessible AND its "
                    f"`sourcesContent[]` contains secret-indicator tokens in "
                    f"{len(secret_hits)} file(s) "
                    f"(sample: {sample_files}). The pre-minified source ships "
                    "to every client; any credential baked in is reachable by "
                    "any visitor. Treat as exposed and rotate immediately."
                ),
                description_plain=(
                    "We found a debug file on your site that's leaking what "
                    "look like API keys or passwords inside your source code. "
                    "Anyone visiting the site can read these — rotate the "
                    "credentials right now."
                ),
                recommended_action=(
                    "Rotate every credential present in the leaked source. "
                    "Then disable source-map generation in your production "
                    "build (Webpack: `devtool: false` or `'hidden-source-map'`; "
                    "Vite: `build.sourcemap: false`; Next.js: "
                    "`productionBrowserSourceMaps: false`). Strip any "
                    "existing `*.js.map` files from your CDN / static-asset "
                    "host. Add a CI check that fails the build if `.map` "
                    "files end up in the deploy artifact."
                ),
                verification_status="needs_review",
            )
        else:
            _emit_finding(
                title=f"Source map publicly accessible at {url}",
                severity="medium",
                category="info_disclosure",
                cwe="CWE-540",
                target_url=target_url,
                map_url=url,
                description=(
                    f"Source map at {url} is publicly accessible. "
                    f"References {len(sources)} source file(s); "
                    f"`sourcesContent` "
                    + ("is included (full pre-minified source ships)"
                       if has_contents else "is not included")
                    + ". This reverses the JS minification — internal file "
                    "paths, variable names, and (when sourcesContent is "
                    "present) the entire source are recoverable by any "
                    "visitor. No credential indicators detected by the "
                    "automated scan, but the agent should review the file "
                    "manually before treating that as confirmed."
                ),
                description_plain=(
                    "We found a 'debug map' file on your site that lets "
                    "anyone reverse-engineer your code. It's not directly "
                    "exposing passwords, but it removes a layer of "
                    "protection that makes attacks easier."
                ),
                recommended_action=(
                    "Disable source-map generation in your production build "
                    "(Webpack: `devtool: false` or `'hidden-source-map'`; "
                    "Vite: `build.sourcemap: false`; Next.js: "
                    "`productionBrowserSourceMaps: false`). Strip any "
                    "existing `*.js.map` files from your CDN. Add a CI "
                    "check that fails the build if `.map` files end up in "
                    "the deploy artifact."
                ),
            )

    issues = len(hits)
    _complete_check(
        cev,
        result="vulnerable" if issues else "not_vulnerable",
        evidence=f"{issues} source-map(s) accessible across {len(candidates)} probe(s); "
        f"{secret_hit_count} secret-indicator hit(s)",
    )

    return {
        "success": True,
        "target_url": target_url,
        "probed": len(candidates),
        "hits": hits,
        "errors": errors,
        "stats": {
            "candidates": len(candidates),
            "scripts_from_html": len(script_srcs),
            "hits_count": len(hits),
            "secret_hits_count": secret_hit_count,
        },
    }
