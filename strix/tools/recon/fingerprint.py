"""Tech-stack fingerprinting + deterministic skill loading.

Probes a target via 1-2 cheap HTTP requests, parses the response for
well-known tech-stack markers (server header, framework cookies, body
generator metadata, GraphQL/Firebase/Supabase signatures), and — when the
detection is high-confidence — auto-loads the matching strix skills into
the calling agent's prompt context.

This is the deterministic complement to the agent's `load_skill` decision-
making: when a target's stack is unambiguous, the right skills load without
the agent having to ask. When detection is ambiguous, the tool still
returns a recommendation so the agent can decide.

Roadmap §7.0. Closes the "agent skipped MTA-STS / framework-specific
checks even though the target was clearly Django/Next.js/etc." failure
mode by ensuring the relevant playbook is loaded before the exploit phase
starts.

Host-side (sandbox_execution=False) because it needs `agent_state` to
reach the skill-loader. Network probing is bounded — at most one HEAD +
one short GET per call, with hard timeouts.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_HTTP_TIMEOUT_SECONDS = 8
_BODY_PROBE_BYTES = 32 * 1024


@dataclass
class Detection:
    """One tech-stack detection. Multiple detections may map to the same skill."""

    technology: str          # canonical name, e.g. "nextjs", "graphql"
    label: str               # human-readable, e.g. "Next.js", "GraphQL"
    version: str | None = None
    confidence: str = "medium"  # "high" | "medium" | "low"
    evidence: list[str] = field(default_factory=list)
    skill: str | None = None  # strix skill to load when this detects high-confidence

    def to_dict(self) -> dict[str, Any]:
        d = {
            "technology": self.technology,
            "label": self.label,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }
        if self.version:
            d["version"] = self.version
        if self.skill:
            d["skill"] = self.skill
        return d


# Always-relevant web vulnerability skills. We don't load all of them on
# every web target (the load_skill cap is 5); we top up to that cap from
# this list after framework/technology/protocol-specific skills have been
# placed.
_DEFAULT_WEB_VULN_SKILLS: tuple[str, ...] = (
    "sql_injection",
    "xss",
    "idor",
    "ssrf",
    "csrf",
)


# ---------------------------------------------------------------------------
# Detection probes — one function per signal source.
# ---------------------------------------------------------------------------


def _probe_http(url: str) -> tuple[int, dict[str, str], str]:
    """One HEAD + (if useful) one GET. Returns (status, headers, body).
    Headers are normalised to lower-case keys. Body is empty on HEAD-only."""
    try:
        import httpx
    except ImportError:
        return _probe_http_stdlib(url)

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=True) as c:
            head = c.head(url)
            headers = {k.lower(): v for k, v in head.headers.items()}
            # Also do one short GET so we can inspect body markers and Set-Cookie
            # (some servers don't echo Set-Cookie on HEAD).
            get = c.get(url, headers={"Accept": "text/html,*/*"})
            for k, v in get.headers.items():
                headers.setdefault(k.lower(), v)
            body = get.text[:_BODY_PROBE_BYTES] if get.text else ""
            return get.status_code, headers, body
    except Exception:  # noqa: BLE001
        logger.warning("httpx probe failed for %s", url, exc_info=True)
        return 0, {}, ""


def _probe_http_stdlib(url: str) -> tuple[int, dict[str, str], str]:
    """Fallback when httpx isn't available."""
    import urllib.request

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "strix-fingerprint/1.0"})
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SECONDS) as r:  # noqa: S310
            headers = {k.lower(): v for k, v in r.getheaders()}
            body = r.read(_BODY_PROBE_BYTES).decode(errors="replace")
            return r.status, headers, body
    except Exception:  # noqa: BLE001
        return 0, {}, ""


_VERSION_RE = re.compile(r"([\d.]+)")


def _detect_from_headers(headers: dict[str, str]) -> list[Detection]:
    out: list[Detection] = []

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")

    # Next.js — high confidence on X-Powered-By
    if "next.js" in powered_by.lower():
        out.append(
            Detection(
                technology="nextjs",
                label="Next.js",
                confidence="high",
                evidence=[f"X-Powered-By: {powered_by}"],
                skill="nextjs",
            )
        )
    elif "next" in headers.get("x-nextjs-data", "").lower() or "_next/data" in headers.get("link", ""):
        out.append(
            Detection(
                technology="nextjs",
                label="Next.js",
                confidence="medium",
                evidence=["X-NextJS-Data or _next/data link header"],
                skill="nextjs",
            )
        )

    # NestJS rarely exposes itself via headers; we'll catch it via cookies.
    if "nestjs" in powered_by.lower():
        out.append(
            Detection(
                technology="nestjs",
                label="NestJS",
                confidence="high",
                evidence=[f"X-Powered-By: {powered_by}"],
                skill="nestjs",
            )
        )

    # Express
    if "express" in powered_by.lower():
        out.append(
            Detection(
                technology="express",
                label="Express",
                confidence="high",
                evidence=[f"X-Powered-By: {powered_by}"],
                skill=None,  # no dedicated skill yet; recommend xss/sql_injection
            )
        )

    # FastAPI / uvicorn
    if "uvicorn" in server.lower():
        ver_match = _VERSION_RE.search(server)
        out.append(
            Detection(
                technology="fastapi",
                label="FastAPI / uvicorn",
                version=ver_match.group(1) if ver_match else None,
                confidence="medium",  # uvicorn could host other ASGI apps
                evidence=[f"Server: {server}"],
                skill="fastapi",
            )
        )

    # PHP
    if "php" in powered_by.lower():
        ver_match = _VERSION_RE.search(powered_by)
        out.append(
            Detection(
                technology="php",
                label="PHP",
                version=ver_match.group(1) if ver_match else None,
                confidence="high",
                evidence=[f"X-Powered-By: {powered_by}"],
                skill=None,
            )
        )

    # ASP.NET
    if "asp.net" in powered_by.lower() or "x-aspnet-version" in headers:
        ver = headers.get("x-aspnet-version") or _VERSION_RE.search(powered_by).group(1) if _VERSION_RE.search(powered_by) else None
        out.append(
            Detection(
                technology="aspnet",
                label="ASP.NET",
                version=ver,
                confidence="high",
                evidence=[f"X-AspNet-Version / X-Powered-By: {powered_by or '<none>'}"],
                skill=None,
            )
        )

    # nginx / Apache version disclosure (generic — informative, not skill-driving)
    if server and ("nginx/" in server.lower() or "apache/" in server.lower()):
        ver_match = _VERSION_RE.search(server)
        if ver_match:
            out.append(
                Detection(
                    technology="webserver_disclosure",
                    label=server.strip(),
                    version=ver_match.group(1),
                    confidence="high",
                    evidence=[f"Server: {server}"],
                    skill=None,
                )
            )

    # WAF / CDN
    if "cloudflare" in server.lower() or "cf-ray" in headers:
        out.append(
            Detection(
                technology="cloudflare",
                label="Cloudflare",
                confidence="high",
                evidence=["Server: cloudflare or CF-RAY header"],
                skill=None,
            )
        )
    if "akamai" in server.lower():
        out.append(
            Detection(
                technology="akamai",
                label="Akamai",
                confidence="high",
                evidence=[f"Server: {server}"],
                skill=None,
            )
        )

    return out


_COOKIE_SIGNALS: list[tuple[re.Pattern[str], str, str, str | None]] = [
    # (regex, technology, label, skill)
    (re.compile(r"\bnext-auth\.session-token=", re.IGNORECASE), "nextjs", "Next.js", "nextjs"),
    (re.compile(r"\bsessionid=.*; .*django", re.IGNORECASE | re.DOTALL), "django", "Django", None),
    (re.compile(r"\bcsrftoken=", re.IGNORECASE), "django", "Django", None),
    (re.compile(r"\bJSESSIONID=", re.IGNORECASE), "java", "Java (JSESSIONID)", None),
    (re.compile(r"\bASP\.NET_SessionId=", re.IGNORECASE), "aspnet", "ASP.NET", None),
    (re.compile(r"\bPHPSESSID=", re.IGNORECASE), "php", "PHP", None),
    (re.compile(r"\bconnect\.sid=", re.IGNORECASE), "express", "Express", None),
    (re.compile(r"\b_rails\.session=|\b_session_id=", re.IGNORECASE), "rails", "Ruby on Rails", None),
    (re.compile(r"\blaravel_session=", re.IGNORECASE), "laravel", "Laravel", None),
]


def _detect_from_cookies(headers: dict[str, str]) -> list[Detection]:
    cookies = headers.get("set-cookie", "")
    if not cookies:
        return []
    out: list[Detection] = []
    seen: set[str] = set()
    for pattern, tech, label, skill in _COOKIE_SIGNALS:
        if pattern.search(cookies) and tech not in seen:
            seen.add(tech)
            out.append(
                Detection(
                    technology=tech,
                    label=label,
                    confidence="high",
                    evidence=[f"Set-Cookie matches {pattern.pattern[:40]}"],
                    skill=skill,
                )
            )
    return out


_BODY_SIGNALS: list[tuple[re.Pattern[str], str, str, str, str | None]] = [
    # (regex, technology, label, confidence, skill)
    # CMS via <meta name="generator">
    (re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress", re.IGNORECASE), "wordpress", "WordPress", "high", None),
    (re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Drupal", re.IGNORECASE), "drupal", "Drupal", "high", None),
    (re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Joomla", re.IGNORECASE), "joomla", "Joomla", "high", None),
    (re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Hugo", re.IGNORECASE), "hugo", "Hugo (static site)", "high", None),
    (re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Jekyll", re.IGNORECASE), "jekyll", "Jekyll (static site)", "high", None),
    (re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Gatsby", re.IGNORECASE), "gatsby", "Gatsby", "high", None),
    (re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Astro", re.IGNORECASE), "astro", "Astro", "high", None),

    # BaaS / database services
    (re.compile(r"firebase-(?:app|auth|firestore|database)\.js|firebaseio\.com|gstatic\.com/firebasejs", re.IGNORECASE), "firebase", "Firebase", "high", "firebase_firestore"),
    (re.compile(r"\.supabase\.co|@supabase/supabase-js", re.IGNORECASE), "supabase", "Supabase", "high", "supabase"),

    # SPA frameworks — modern markers first (more specific), then legacy fallbacks.
    # Next.js
    (re.compile(r"window\.__NEXT_DATA__|<script id=\"__NEXT_DATA__\"|/_next/static/", re.IGNORECASE), "nextjs", "Next.js", "high", "nextjs"),
    # Nuxt 2 (`__NUXT__`) + Nuxt 3 (`__NUXT_DATA__`, `nuxt-build-id`)
    (re.compile(r"window\.__NUXT__|window\.__NUXT_DATA__|<script id=\"__NUXT_DATA__\"|nuxt-link|/_nuxt/", re.IGNORECASE), "nuxtjs", "Nuxt.js", "high", None),
    # Remix
    (re.compile(r"window\.__remixContext|__remixManifest|__remixRouteModules|/build/manifest-[A-F0-9]+\.js", re.IGNORECASE), "remix", "Remix", "high", None),
    # Astro (in addition to <meta generator>)
    (re.compile(r"<astro-island\b|<astro-slot\b|astro-island.js", re.IGNORECASE), "astro", "Astro", "high", None),
    # SvelteKit
    (re.compile(r"window\.__SVELTEKIT_PAYLOAD__|/_app/immutable/|svelte-[a-z0-9]{6}\b", re.IGNORECASE), "sveltekit", "SvelteKit", "high", None),
    # Svelte (non-kit)
    (re.compile(r"__SVELTE__|svelte-hmr|svelte/internal", re.IGNORECASE), "svelte", "Svelte", "medium", None),
    # SolidJS
    (re.compile(r"_\$DX_DELEGATE\b|solid-js/web|solid-js/store", re.IGNORECASE), "solidjs", "SolidJS", "high", None),
    # Webpack runtime (low — many frameworks bundle with Webpack)
    (re.compile(r"__webpack_require__|webpackJsonp|webpackChunk_", re.IGNORECASE), "webpack", "Webpack-bundled JS", "low", None),
    # Angular — multiple markers including `ng-version` ATTRIBUTE form +
    # `<app-root>` (the default CLI shell) + ng-server-context.
    (re.compile(r"\bng-version=|<app-root\b|<app-component\b|ng-server-context|@angular/", re.IGNORECASE), "angular", "Angular", "high", None),
    # React: data-reactroot (legacy) + new `__REACT_DEVTOOLS_GLOBAL_HOOK__` +
    # createRoot fingerprint.
    (re.compile(r"data-reactroot|react-dom|__REACT_DEVTOOLS_GLOBAL_HOOK__|_reactRootContainer", re.IGNORECASE), "react", "React", "high", None),
    # Vue 3 (`__VUE__` global, `data-v-` scope attrs) + Vue 2 (`Vue.config`, `v-app`).
    (re.compile(r"\bdata-v-[a-f0-9]{6,}\b|window\.__VUE__|Vue\.config|\bv-app\b|<v-app\b", re.IGNORECASE), "vue", "Vue.js", "high", None),

    # E-commerce
    (re.compile(r"shopify\.com|x-shopify", re.IGNORECASE), "shopify", "Shopify", "high", None),

    # GraphQL — the dedicated _probe_graphql (deep mode) is more reliable;
    # this body sniff just catches obvious form actions.
    (re.compile(r"<form[^>]+action=[\"'][^\"']*\"?graphql", re.IGNORECASE), "graphql", "GraphQL", "medium", "graphql"),
]


def _detect_from_body(body: str) -> list[Detection]:
    if not body:
        return []
    out: list[Detection] = []
    seen: set[str] = set()
    for pattern, tech, label, conf, skill in _BODY_SIGNALS:
        if pattern.search(body) and tech not in seen:
            seen.add(tech)
            out.append(
                Detection(
                    technology=tech,
                    label=label,
                    confidence=conf,
                    evidence=[f"Body matches {pattern.pattern[:60]}"],
                    skill=skill,
                )
            )
    return out


def _probe_graphql(target_url: str) -> Detection | None:
    """A focused probe: POST a GraphQL introspection-shaped query to common
    paths. If any returns a __schema response shape, that's GraphQL."""
    paths = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql"]
    try:
        import httpx
    except ImportError:
        return None
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    payload = '{"query":"{__typename}"}'
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=False) as c:
            for path in paths:
                try:
                    r = c.post(
                        base + path,
                        content=payload,
                        headers={"Content-Type": "application/json"},
                    )
                except Exception:  # noqa: BLE001
                    continue
                if r.status_code in (200, 400) and "data" in r.text and "__typename" in r.text:
                    return Detection(
                        technology="graphql",
                        label="GraphQL",
                        confidence="high",
                        evidence=[f"POST {path} returned __typename"],
                        skill="graphql",
                    )
    except Exception:  # noqa: BLE001
        return None
    return None


# OpenAPI / Swagger spec discovery. Probes the standard publishing paths.
# When a JSON spec is found, captures the path-count for downstream tools
# (`bfs_crawl(openapi_url=...)` can then ingest the full endpoint list).
_OPENAPI_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/swagger-ui.html",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api-docs.json",
    "/docs",
    "/api/docs",
    "/redoc",
)


def _probe_openapi(target_url: str) -> Detection | None:
    """Probe the standard OpenAPI / Swagger publishing paths.

    Returns a Detection when:
    - A JSON spec is found (200 + parses as a dict with `paths` or `openapi`/`swagger` key),
      OR
    - A Swagger-UI HTML page is found (200 + body contains a `swagger-ui` reference).

    The detection's `evidence` includes the discovered URL and the path count
    when JSON-parsed, so the agent can decide whether to invoke
    `bfs_crawl(openapi_url=...)` to ingest the full endpoint list.
    """
    try:
        import httpx
    except ImportError:
        return None
    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    spec_url: str | None = None
    spec_path_count: int = 0
    swagger_ui_url: str | None = None
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS, follow_redirects=False) as c:
            for path in _OPENAPI_PATHS:
                url = base + path
                try:
                    r = c.get(url)
                except Exception:  # noqa: BLE001
                    continue
                if r.status_code != 200:
                    continue
                # Headers may be a plain dict or a CaseInsensitiveDict; check both.
                ct_raw = (
                    r.headers.get("content-type")
                    or r.headers.get("Content-Type")
                    or ""
                )
                ct = ct_raw.split(";")[0].strip().lower()
                body = r.text or ""
                # JSON spec — most reliable signal.
                if "json" in ct or path.endswith(".json"):
                    try:
                        import json as _json

                        data = _json.loads(body)
                    except (ValueError, TypeError):
                        continue
                    if not isinstance(data, dict):
                        continue
                    # OpenAPI 3.x / Swagger 2.x both have `paths` dict.
                    is_openapi_3 = isinstance(data.get("openapi"), str)
                    is_swagger_2 = isinstance(data.get("swagger"), str)
                    paths = data.get("paths")
                    if (is_openapi_3 or is_swagger_2) and isinstance(paths, dict):
                        spec_url = url
                        spec_path_count = len(paths)
                        break
                    # Some servers serve the spec with no `openapi`/`swagger`
                    # version key but with a `paths` object — accept it as a
                    # weaker signal.
                    if isinstance(paths, dict) and any(p.startswith("/") for p in paths.keys()):
                        spec_url = url
                        spec_path_count = len(paths)
                        break
                # Swagger-UI HTML page — secondary signal; the spec URL is
                # usually loaded from the page but we don't parse the page.
                elif "html" in ct and "swagger-ui" in body.lower():
                    swagger_ui_url = url
    except Exception:  # noqa: BLE001
        return None

    if spec_url:
        evidence = [
            f"GET {spec_url} returned an OpenAPI / Swagger spec",
            f"{spec_path_count} path(s) declared in the spec",
        ]
        if swagger_ui_url:
            evidence.append(f"Swagger UI also exposed at {swagger_ui_url}")
        return Detection(
            technology="openapi",
            label=f"OpenAPI / Swagger spec ({spec_path_count} paths)",
            confidence="high",
            evidence=evidence,
            skill=None,  # No dedicated skill — the agent feeds the URL into bfs_crawl.
        )
    if swagger_ui_url:
        return Detection(
            technology="swagger_ui",
            label="Swagger UI page",
            confidence="medium",
            evidence=[f"GET {swagger_ui_url} returned a Swagger UI HTML page"],
            skill=None,
        )
    return None


# ---------------------------------------------------------------------------
# Skill selection — the "deterministic" part.
# ---------------------------------------------------------------------------


_LOAD_SKILL_CAP = 5  # mirrors load_skill's max_skills cap


def _select_skills(detections: list[Detection]) -> list[str]:
    """Pick which skills to auto-load, given a set of detections.

    Priority:
    1. High-confidence framework / technology / protocol skills that have a
       direct mapping in the strix skill registry.
    2. Fill remaining slots up to _LOAD_SKILL_CAP from a curated list of
       always-relevant web vulnerability skills (sql_injection, xss, idor,
       ssrf, csrf) — but only when at least one web-stack detection happened
       (don't load web-vuln skills for a pure DNS recon target).
    3. Validate against the live skill registry — drop anything unknown.
    """
    from strix.skills import get_all_skill_names

    available = get_all_skill_names()
    chosen: list[str] = []

    # Step 1: high-confidence skill-bearing detections.
    for det in detections:
        if det.skill and det.confidence == "high" and det.skill in available:
            if det.skill not in chosen:
                chosen.append(det.skill)
        if len(chosen) >= _LOAD_SKILL_CAP:
            return chosen

    # Step 2: fill with web-vuln defaults if the target looks like a web app.
    web_indicator = any(
        d.technology
        in {
            "nextjs",
            "nestjs",
            "express",
            "fastapi",
            "django",
            "rails",
            "laravel",
            "php",
            "aspnet",
            "wordpress",
            "drupal",
            "joomla",
            "shopify",
            "react",
            "vue",
            "angular",
            "graphql",
            "firebase",
            "supabase",
        }
        for d in detections
    )
    if web_indicator:
        for skill in _DEFAULT_WEB_VULN_SKILLS:
            if skill in available and skill not in chosen:
                chosen.append(skill)
            if len(chosen) >= _LOAD_SKILL_CAP:
                break

    return chosen


def _load_skills_into_agent(agent_state: Any, skill_names: list[str]) -> dict[str, Any]:
    """Use the same internal API that load_skill uses."""
    if not skill_names:
        return {"loaded_skills": [], "newly_loaded_skills": [], "error": None}
    try:
        from strix.tools.agents_graph.agents_graph_actions import _agent_instances

        current_agent = _agent_instances.get(agent_state.agent_id)
        if current_agent is None or not hasattr(current_agent, "llm"):
            return {
                "loaded_skills": [],
                "newly_loaded_skills": [],
                "error": "no running agent instance for runtime skill loading",
            }
        newly_loaded = current_agent.llm.add_skills(skill_names)
        prior = agent_state.context.get("loaded_skills", [])
        if not isinstance(prior, list):
            prior = []
        merged = sorted(set(prior).union(skill_names))
        agent_state.update_context("loaded_skills", merged)
        return {
            "loaded_skills": skill_names,
            "newly_loaded_skills": newly_loaded,
            "error": None,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "loaded_skills": [],
            "newly_loaded_skills": [],
            "error": f"skill load failed: {e}",
        }


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(sandbox_execution=False)
def fingerprint_tech_stack(
    agent_state: Any,
    target: str,
    deep: bool = False,
) -> dict[str, Any]:
    """Detect the target's tech stack and auto-load matching strix skills.

    Args:
        target: full URL to probe (e.g. "https://example.com/"). For domain-only
                targets, prepend https://.
        deep: when True, also issue a focused GraphQL probe on common paths.
              Default False (single HEAD + GET only).

    Behaviour:
        - 1-2 cheap HTTP requests to the given URL (HEAD + GET, both with an
          8s timeout). No multi-page crawling, no offensive probing.
        - Parses headers, cookies, and a 32 KiB body window for tech-stack
          markers.
        - For each high-confidence detection that maps to a strix skill,
          auto-loads the skill into this agent's prompt context (subject to
          the load_skill cap of 5).
        - Tops up remaining slots with sql_injection / xss / idor / ssrf /
          csrf when a web-stack signal was detected.

    Returns a structured dict the agent can read for further reasoning. Skill
    loading happens as a side effect; the agent does NOT need to follow up
    with a separate load_skill call for the skills listed in
    `skills_loaded`.
    """
    if not target or not isinstance(target, str):
        return {"success": False, "error": "target required"}

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    if not parsed.netloc:
        return {"success": False, "error": f"invalid target URL: {target!r}"}

    # Build root URL for the probe (avoid hammering deep paths).
    probe_url = f"{parsed.scheme}://{parsed.netloc}/"

    status, headers, body = _probe_http(probe_url)
    if status == 0 and not headers and not body:
        return {
            "success": False,
            "error": f"target unreachable: {probe_url}",
            "target": target,
        }

    detections: list[Detection] = []
    detections.extend(_detect_from_headers(headers))
    detections.extend(_detect_from_cookies(headers))
    detections.extend(_detect_from_body(body))

    # Dedup by technology — keep the highest-confidence detection per tech.
    by_tech: dict[str, Detection] = {}
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    for det in detections:
        existing = by_tech.get(det.technology)
        if existing is None or confidence_rank[det.confidence] > confidence_rank[existing.confidence]:
            by_tech[det.technology] = det
        else:
            existing.evidence = sorted(set(existing.evidence + det.evidence))
    detections = list(by_tech.values())

    # Optional GraphQL + OpenAPI probes — both are network-cost-bounded
    # (≤ ~13 GETs each) but skipped in shallow mode for speed.
    if deep:
        gql = _probe_graphql(target)
        if gql and gql.technology not in by_tech:
            detections.append(gql)
        openapi_det = _probe_openapi(target)
        if openapi_det and openapi_det.technology not in by_tech:
            detections.append(openapi_det)
            # Emit an info-severity finding so the wrapper sees this surface
            # like any other recon hit. The agent's downstream move is to
            # call `bfs_crawl(openapi_url=<discovered_url>)` to ingest paths.
            try:
                from strix.telemetry.tracer import get_global_tracer

                tracer = get_global_tracer()
                if tracer is not None:
                    spec_url = next(
                        (line.split(" ")[1] for line in (openapi_det.evidence or [])
                         if line.startswith("GET ")),
                        None,
                    )
                    tracer.add_vulnerability_report(
                        title=f"{openapi_det.label} discovered on {target}",
                        severity="info",
                        category="info_disclosure",
                        cwe="CWE-200",
                        target=target,
                        endpoint=spec_url or target,
                        description=(
                            f"{openapi_det.label} is reachable from this target. "
                            "Public OpenAPI / Swagger specs are recon goldmines: "
                            "every documented endpoint, parameter, and auth scheme "
                            "is enumerated up front. Feed this URL into "
                            "`bfs_crawl(openapi_url=...)` to ingest the full "
                            "endpoint inventory.\n\nEvidence:\n- "
                            + "\n- ".join(openapi_det.evidence or [])
                        ),
                        impact=(
                            "API documentation in production is not a vulnerability "
                            "on its own, but it removes a layer of obscurity and "
                            "accelerates downstream reconnaissance / fuzzing. "
                            "OWASP API9 (Improper Inventory Management) — when the "
                            "spec includes deprecated / internal / debug endpoints, "
                            "those become first-class attack candidates."
                        ),
                        remediation_steps=(
                            "If the spec is published intentionally for client "
                            "tooling, no action needed. If it's a framework default "
                            "left enabled in production (Django REST `coreapi` / "
                            "FastAPI `/docs` / Spring `springdoc`), gate it behind "
                            "auth or strip from the production build."
                        ),
                        description_plain=(
                            "We found the API documentation page. This isn't broken — "
                            "it's a normal published file — but it lists every URL the "
                            "API exposes, which speeds up further testing."
                        ),
                        verification_status="verified",
                    )
            except Exception:  # noqa: BLE001
                logger.debug("OpenAPI finding emission failed", exc_info=True)

    skill_candidates = _select_skills(detections)
    skill_load_result = _load_skills_into_agent(agent_state, skill_candidates)

    return {
        "success": True,
        "target": target,
        "probe_url": probe_url,
        "http_status": status,
        "technologies": [d.to_dict() for d in detections],
        "recommended_skills": skill_candidates,
        "skills_loaded": skill_load_result["loaded_skills"],
        "newly_loaded_skills": skill_load_result["newly_loaded_skills"],
        "skill_load_error": skill_load_result["error"],
    }
