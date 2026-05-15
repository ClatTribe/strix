"""Verbose-error / debug-bleed detector.

Three deterministic probe families that catch the standard
information_disclosure findings the agent doesn't reliably surface
on its own:

1.  **Parametric debug toggles** — common framework conventions for
    "turn debug mode on for this request". Replays the baseline URL
    with `?debug=1`, `?DEBUG=true`, `?_debug=1`, `?trace=1`,
    `?XDEBUG_SESSION_START=phpstorm`, `?wsdl`, `?test=1`. If the
    response body suddenly contains a stack-trace marker or framework
    name that the baseline didn't, the toggle was respected.

2.  **Framework debug pages** — well-known canonical paths that
    expose runtime internals without auth on misconfigured deploys:
    `/__debug__/`, `/_profiler/` (Symfony), `/actuator/*` (Spring
    Boot), `/server-status` / `/server-info` (Apache mod_status),
    `/_admin/`, `/grafana/api/health`, `/prometheus/api/v1/status/config`,
    `/console`, `/h2-console`, `/_ah/instances`, `/.well-known/health`,
    `/health`, `/heapdump`, `/dump`, `/env`, `/configprops`, `/trace`.
    Probe each with GET; flag responses that look like the canonical
    framework page rather than a 404 / 401.

3.  **Error-trigger payloads** — append `?strix_probe=<payload>` to
    the baseline URL. Payloads: single-quote (`'`), unmatched-paren
    (`(`), JSON-syntax-bait (`{"a":}`), null-byte (`%00`), oversized
    (1500 chars). If the response gains a stack-trace marker that the
    baseline didn't have, the application is bleeding internals on
    parse error.

Detection: stack-trace markers are framework-name + "at <package>" /
"in /var/www" / `Traceback (most recent call last)` / "Exception in"
+ file-path-with-extension regexes (`.py:42`, `.php on line 42`,
`.rb:42:in`, `.java:42`, `.js:42:18`). Also keys like `DEBUG = True`,
`<symfony-profiler`, `Whoops\\Run`, `Werkzeug Debugger`, `Rails.env`,
`X-Debug-Token`, `<?xml ... <env:Envelope` (SOAP wsdl leak).

Per-class dedup: each finding class (param toggle / framework page /
error trigger) emits at most one finding per (target_host, family);
the probe matrix produces a structured `probes` array for the agent
to consume but only the first hit per family becomes a finding.

Severity:

- **High** (CWE-200, info_disclosure) — response body contains a
  full stack trace AND framework debug header (`X-Debug-Token`,
  `X-Symfony-Cache`, etc.) — the application has its full debug
  surface exposed to the internet.
- **Medium** (CWE-200) — framework debug page reachable
  unauthenticated (`/_profiler/`, `/actuator/env`, `/server-status`).
- **Medium** (CWE-200) — parametric debug toggle observed (response
  shape changed under `?debug=1` etc.) but no full stack trace yet.
- **Low** (CWE-200) — error-trigger payload caused a verbose error
  message but stayed within the application's error template.

Skip / soft-fail:

- Baseline GET non-2xx → endpoint may require auth / be invalid.
  Tool exits with `inconclusive` and probes only the framework debug
  pages (those don't depend on the deep target's baseline).
- Cluster-A `--exclude-path` blocks the probe URL → skipped.

Each finding carries `description_plain` + `recommended_action`
(disable framework debug mode in production; require auth on
framework profiling routes; configure the framework to emit a
generic 500 page on parse error) and `verification_status=needs_review`.

Composes with cluster-A safety. MITRE T1592 (Gather Victim Host
Information).
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "debug_endpoint_check"
_DEFAULT_TIMEOUT = 10.0
_MAX_RESPONSE_SCAN = 64 * 1024


# ---------------------------------------------------------------------------
# Probe matrices
# ---------------------------------------------------------------------------


# Parametric debug toggles. Each is (param_name, value) pair appended
# to the URL's query string. Re-running the baseline URL with these
# tells us whether the framework respects the toggle.
_PARAMETRIC_TOGGLES: list[tuple[str, str]] = [
    ("debug", "1"),
    ("debug", "true"),
    ("DEBUG", "true"),
    ("_debug", "1"),
    ("trace", "1"),
    ("XDEBUG_SESSION_START", "phpstorm"),
    ("wsdl", ""),
    ("test", "1"),
]


# Framework debug pages — canonical paths to GET against the host
# root. We do NOT walk arbitrary paths; only this curated list.
_FRAMEWORK_PAGES: list[tuple[str, str]] = [
    # path, framework label
    ("/__debug__/", "django_debug_toolbar"),
    ("/_profiler/", "symfony_profiler"),
    ("/_profiler/phpinfo", "symfony_profiler"),
    ("/_wdt/", "symfony_web_debug_toolbar"),
    ("/actuator", "spring_actuator"),
    ("/actuator/env", "spring_actuator"),
    ("/actuator/health", "spring_actuator"),
    ("/actuator/heapdump", "spring_actuator"),
    ("/actuator/mappings", "spring_actuator"),
    ("/actuator/configprops", "spring_actuator"),
    ("/actuator/beans", "spring_actuator"),
    ("/actuator/loggers", "spring_actuator"),
    ("/actuator/threaddump", "spring_actuator"),
    ("/actuator/metrics", "spring_actuator"),
    ("/actuator/info", "spring_actuator"),
    ("/server-status", "apache_mod_status"),
    ("/server-info", "apache_mod_info"),
    ("/console", "h2_or_play_console"),
    ("/h2-console", "h2_database_console"),
    ("/_ah/instances", "appengine_admin"),
    ("/_ah/health", "appengine_admin"),
    ("/heapdump", "spring_heapdump_alt"),
    ("/dump", "framework_dump"),
    ("/env", "spring_env_alt"),
    ("/configprops", "spring_configprops_alt"),
    ("/trace", "spring_trace_alt"),
    ("/info", "spring_info_alt"),
    ("/health", "spring_health_alt"),
    ("/metrics", "prometheus_metrics"),
    ("/debug/pprof/", "go_pprof"),
    ("/debug/vars", "go_expvar"),
    ("/_admin/", "generic_admin"),
    ("/admin/info", "generic_admin"),
    ("/api-docs", "swagger"),
    ("/swagger-ui", "swagger"),
    ("/swagger-ui/index.html", "swagger"),
    ("/v2/api-docs", "swagger"),
    ("/v3/api-docs", "swagger"),
    ("/openapi.json", "openapi_spec"),
    ("/graphql", "graphql_endpoint"),
    ("/graphiql", "graphiql_explorer"),
    ("/.well-known/health", "well_known_health"),
    ("/grafana/api/health", "grafana"),
    ("/prometheus/api/v1/status/config", "prometheus"),
]


# Error-trigger payloads. Each goes onto the baseline URL via a
# `strix_probe` query parameter — single quote, unmatched paren,
# JSON-syntax-bait, null byte (URL-encoded), oversized.
_ERROR_TRIGGERS: list[tuple[str, str]] = [
    ("single_quote", "'"),
    ("unmatched_paren", "("),
    ("json_bait", '{"a":}'),
    ("null_byte", "%00"),
    ("oversized", "A" * 1500),
]


# Stack-trace / framework-debug regex markers. Each match in the
# response body that wasn't in the baseline is treated as evidence.
_TRACE_MARKERS: tuple[re.Pattern[str], ...] = (
    re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
    re.compile(r"Exception in thread", re.IGNORECASE),
    re.compile(r"\bat\s+[\w$.]+\([\w./]+\.java:\d+\)"),
    re.compile(r"\bin\s+/[\w/.\-]+\.\w+(?:\s+on\s+line\s+\d+)?", re.IGNORECASE),
    re.compile(r"\.py['\"]?[,\s]+line\s+\d+", re.IGNORECASE),
    re.compile(r"\.php\s+on\s+line\s+\d+", re.IGNORECASE),
    re.compile(r"\.rb:\d+:in\s+", re.IGNORECASE),
    re.compile(r"\.java:\d+\)"),
    re.compile(r"\.js:\d+:\d+", re.IGNORECASE),
    re.compile(r"Whoops\\Run", re.IGNORECASE),
    re.compile(r"Werkzeug Debugger", re.IGNORECASE),
    re.compile(r"<symfony-profiler", re.IGNORECASE),
    re.compile(r"WebApplicationContext", re.IGNORECASE),
    re.compile(r"NoMethodError", re.IGNORECASE),
    re.compile(r"NullPointerException", re.IGNORECASE),
    re.compile(r"undefined method `\w+' for", re.IGNORECASE),
    re.compile(r"DEBUG\s*=\s*True", re.IGNORECASE),
    re.compile(r"X-Debug-Token", re.IGNORECASE),
)


# Framework page identifiers — body content that signals the
# response IS the canonical debug page (vs a 404 / 401 redirect).
# Each (regex, label) is matched against response body.
_PAGE_MARKERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"<title>\s*Symfony Profiler", re.IGNORECASE), "symfony_profiler"),
    (re.compile(r"\"_links\"\s*:.*\"actuator\"", re.IGNORECASE | re.DOTALL), "spring_actuator"),
    (re.compile(r"\"systemProperties\"|\"systemEnvironment\"", re.IGNORECASE), "spring_env"),
    (re.compile(r"<title>\s*Apache Status", re.IGNORECASE), "apache_mod_status"),
    (re.compile(r"<title>\s*Server Information", re.IGNORECASE), "apache_mod_info"),
    (re.compile(r"<title>\s*H2 Console", re.IGNORECASE), "h2_console"),
    (re.compile(r"<title>\s*Django Debug Toolbar", re.IGNORECASE), "django_debug_toolbar"),
    (re.compile(r"<title>.*Swagger UI", re.IGNORECASE), "swagger_ui"),
    (re.compile(r"<title>.*GraphiQL", re.IGNORECASE), "graphiql"),
    (re.compile(r"\"swagger\"\s*:\s*\"", re.IGNORECASE), "swagger_json"),
    (re.compile(r"\"openapi\"\s*:\s*\"", re.IGNORECASE), "openapi_json"),
    (re.compile(r"<title>\s*pprof", re.IGNORECASE), "go_pprof"),
    (re.compile(r"^\{\"\w+\":\s*\d+", re.MULTILINE), "go_expvar"),
    (re.compile(r"^# HELP\s+\w+", re.MULTILINE), "prometheus_metrics"),
    (re.compile(r"\"GodMode\"|\"environment\"\s*:\s*\{", re.IGNORECASE), "generic_admin"),
    # GraphQL: 200/400 with `{"data":` or `{"errors":...,"locations":[...]}`
    (re.compile(r"\"locations\"\s*:\s*\[\s*\{\s*\"line\"", re.IGNORECASE), "graphql_endpoint"),
    # Java heap dump bytes — start with "JAVA PROFILE" or HPROF magic
    (re.compile(r"^JAVA PROFILE 1\.0\.|^hprof", re.IGNORECASE), "java_heap_dump"),
)


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_get(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """GET a URL via cluster-A safety. Returns
    {status, headers, body, error?, skipped?}."""
    headers = dict(headers or {})

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request(
                "GET", url, headers=headers, timeout=int(timeout)
            )
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": (r.get("body") or "")[:_MAX_RESPONSE_SCAN],
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
        merged = inject_auth_headers(headers)
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_RESPONSE_SCAN],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_target(target: str) -> str | None:
    if not target or not isinstance(target, str):
        return None
    target = target.strip()
    if not target:
        return None
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return target


def _trace_markers_in(body: str) -> list[str]:
    """Return the list of trace-marker labels present in the body."""
    if not body:
        return []
    hits: list[str] = []
    for pattern in _TRACE_MARKERS:
        if pattern.search(body):
            hits.append(pattern.pattern)
    return hits


def _page_markers_in(body: str) -> list[str]:
    """Return the list of framework-page labels matched in the body."""
    if not body:
        return []
    hits: list[str] = []
    for pattern, label in _PAGE_MARKERS:
        if pattern.search(body):
            hits.append(label)
    return hits


def _has_debug_header(headers: dict[str, str]) -> str | None:
    for key in ("x-debug-token", "x-debug-token-link", "x-symfony-cache",
                "x-runtime", "x-powered-by"):
        if key in headers:
            return f"{key}={headers[key]}"
    return None


def _append_query(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parsed.query
    addition = urlencode([(name, value)])
    new_qs = f"{qs}&{addition}" if qs else addition
    return parsed._replace(query=new_qs).geturl()


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    category: str,
    target: str,
    endpoint: str,
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
    finding_id = tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category=category,
        cwe="CWE-200",
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "Verbose error / debug-mode bleed leaks framework "
            "internals — stack traces, file paths, environment "
            "variables, request-context dumps. Each leak gives an "
            "attacker the framework / version (precondition for "
            "matching CVEs) and often direct access to "
            "configuration secrets, internal hostnames, or "
            "credential-shaped strings."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
    )
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        record_finding_in_kg(
            finding_id=finding_id, url=endpoint, param="debug_endpoint",
            cwe="CWE-200", severity=severity, category=category,
            method="GET", detection_kind=title[:60],
            confidence=0.85,
        )
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug(
            "debug_endpoint: kg record failed: %s", e, exc_info=True,
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
    mitre_techniques=["T1592"],  # Gather Victim Host Information
)
def debug_endpoint_check(
    target_url: str,
    timeout: float = _DEFAULT_TIMEOUT,
    skip_framework_pages: bool = False,
) -> dict[str, Any]:
    """Probe a URL for verbose-error / debug-mode bleed.

    Three probe families:
        1. Parametric debug toggles (`?debug=1`, `?DEBUG=true`, ...)
           replayed on the baseline URL — flag responses where a
           trace marker appears that the baseline didn't have.
        2. Framework debug pages (`/__debug__/`, `/_profiler/`,
           `/actuator/*`, `/server-status`, ...) GET'd at the host
           root — flag responses that match the canonical debug-page
           shape rather than a 404 / 401.
        3. Error-trigger payloads (`'`, `(`, `{"a":}`, `%00`,
           1500-char) appended via `?strix_probe=...` — flag
           responses that gain a stack-trace marker.

    Args:
        target_url: URL to probe. Bare hostnames auto-prefixed
            `https://`.
        timeout: Per-probe timeout in seconds (default 10).
        skip_framework_pages: When True, only probes 1 + 3 run (no
            host-root crawl). Useful when scanning a deep API path
            and the host-root has already been audited.

    Returns:
        {
          success, target_url, target_host, baseline,
          parametric_probes: [...], framework_probes: [...],
          error_probes: [...], findings_emitted
        }

    Findings:
        - **High** CWE-200 — full stack trace + framework debug
          header (`X-Debug-Token`, etc.) on a parametric probe.
        - **Medium** CWE-200 — framework debug page reachable
          unauth; or parametric toggle observed without full trace.
        - **Low** CWE-200 — error-trigger payload caused verbose
          error within app's error template.

    Notes:
        - Read-only (GET, no follow-redirects).
        - Composes with cluster-A safety; `--exclude-path` skips.
        - Per-class dedup: at most one finding per family.
        - `verification_status=needs_review`.
    """
    target_url_norm = _normalize_target(target_url)
    if target_url_norm is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    target_host = (urlparse(target_url_norm).hostname or "").lower()
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {target_url!r}"}

    cev = _start_check("debug_bleed", target_host)

    # ---- Baseline ----
    baseline = _http_get(target_url_norm, timeout=timeout)
    baseline_skipped = bool(baseline.get("skipped"))
    baseline_status = int(baseline.get("status") or 0)
    baseline_body = baseline.get("body") or ""
    baseline_traces = set(_trace_markers_in(baseline_body))
    baseline_summary = {
        "status": baseline_status,
        "body_length": len(baseline_body),
        "skipped": baseline_skipped,
        "error": baseline.get("error"),
        "trace_markers": sorted(baseline_traces),
    }

    findings_emitted = 0
    parametric_results: list[dict[str, Any]] = []
    framework_results: list[dict[str, Any]] = []
    error_results: list[dict[str, Any]] = []

    # Track per-family dedup so we emit at most one finding per
    # probe family per host.
    parametric_finding_emitted = False
    error_finding_emitted = False
    framework_pages_emitted: set[str] = set()

    # ---- Parametric debug toggles (only if baseline returned 2xx/3xx) ----
    parametric_runnable = (
        not baseline_skipped
        and 200 <= baseline_status < 400
    )
    if parametric_runnable:
        for name, value in _PARAMETRIC_TOGGLES:
            probe_url = _append_query(target_url_norm, name, value)
            response = _http_get(probe_url, timeout=timeout)
            if response.get("skipped"):
                parametric_results.append({
                    "param": f"{name}={value}",
                    "url": probe_url,
                    "status": 0,
                    "body_length": 0,
                    "new_trace_markers": [],
                    "debug_header": None,
                    "skipped": True,
                })
                continue
            response_body = response.get("body") or ""
            response_headers = response.get("headers") or {}
            response_traces = set(_trace_markers_in(response_body))
            new_traces = sorted(response_traces - baseline_traces)
            debug_header = _has_debug_header(response_headers)

            verdict = {
                "param": f"{name}={value}",
                "url": probe_url,
                "status": int(response.get("status") or 0),
                "body_length": len(response_body),
                "new_trace_markers": new_traces,
                "debug_header": debug_header,
                "skipped": False,
            }
            parametric_results.append(verdict)

            # Emit at most one parametric finding per host.
            if parametric_finding_emitted:
                continue

            if new_traces and debug_header:
                _emit_finding(
                    title=(
                        f"Debug mode toggleable via `{name}={value}` on "
                        f"{target_host} (full trace + debug header)"
                    ),
                    severity="high",
                    category="information_disclosure",
                    target=target_host,
                    endpoint=probe_url,
                    description=(
                        f"GET {probe_url} returned status "
                        f"{response.get('status')} with new trace "
                        f"markers that the baseline didn't have: "
                        f"{new_traces}; framework debug header "
                        f"present: {debug_header}."
                    ),
                    description_plain=(
                        "Your application has its full debug surface "
                        "exposed to the internet. Sending a request "
                        "with a debug-toggle query parameter caused "
                        "the response to include a stack trace AND a "
                        "framework debug header. This means an "
                        "attacker can read internal file paths, "
                        "environment variables, request context, and "
                        "session data from any URL that respects the "
                        "toggle."
                    ),
                    recommended_action=(
                        "Disable framework debug mode in production. "
                        "Django: `DEBUG = False` in settings; ensure "
                        "`DEBUG` is never set true in your production "
                        "container env. Symfony: build with "
                        "`APP_ENV=prod APP_DEBUG=0`; remove the "
                        "`/_profiler/` mount from prod. Spring Boot: "
                        "remove `spring-boot-starter-actuator` or "
                        "lock `management.endpoints.web.exposure.include` "
                        "to `health`. Strip `X-Debug-Token` and "
                        "similar response headers at the reverse-proxy."
                    ),
                )
                findings_emitted += 1
                parametric_finding_emitted = True
            elif new_traces or debug_header:
                _emit_finding(
                    title=(
                        f"Parametric debug toggle respected on "
                        f"{target_host} (`{name}={value}`)"
                    ),
                    severity="medium",
                    category="information_disclosure",
                    target=target_host,
                    endpoint=probe_url,
                    description=(
                        f"GET {probe_url} returned status "
                        f"{response.get('status')}. Response shape "
                        f"changed under the debug toggle: new trace "
                        f"markers={new_traces}; debug header="
                        f"{debug_header}."
                    ),
                    description_plain=(
                        "Your application changes its response when "
                        "a debug-toggle query parameter is present. "
                        "That tells an attacker the debug code path "
                        "is reachable; even if the response doesn't "
                        "yet contain a full stack trace, it is "
                        "leaking internals."
                    ),
                    recommended_action=(
                        "Disable framework debug mode in production "
                        "(see Django `DEBUG=False`, Symfony "
                        "`APP_DEBUG=0`, Spring "
                        "`management.endpoints.web.exposure.include=health`). "
                        "Audit middleware for code paths that branch on "
                        "request query params named `debug` / `_debug` / "
                        "`trace` / `XDEBUG_SESSION_START`."
                    ),
                )
                findings_emitted += 1
                parametric_finding_emitted = True

    # ---- Framework debug pages ----
    if not skip_framework_pages:
        host_root = f"{urlparse(target_url_norm).scheme}://{urlparse(target_url_norm).netloc}/"
        for path, label in _FRAMEWORK_PAGES:
            probe_url = urljoin(host_root, path.lstrip("/"))
            response = _http_get(probe_url, timeout=timeout)
            if response.get("skipped"):
                framework_results.append({
                    "path": path,
                    "label": label,
                    "url": probe_url,
                    "status": 0,
                    "body_length": 0,
                    "matched_markers": [],
                    "skipped": True,
                })
                continue
            status = int(response.get("status") or 0)
            body = response.get("body") or ""
            matched = _page_markers_in(body)
            verdict = {
                "path": path,
                "label": label,
                "url": probe_url,
                "status": status,
                "body_length": len(body),
                "matched_markers": matched,
                "skipped": False,
            }
            framework_results.append(verdict)

            # Heuristic: 2xx/3xx + matched marker → flag. Some
            # framework pages don't have a unique HTML title (e.g.
            # raw JSON dumps), so we also accept 2xx + body length
            # > 80 + content-type JSON when the path is in the
            # actuator family.
            framework_match = False
            if 200 <= status < 400 and matched:
                framework_match = True
            elif (
                200 <= status < 400
                and label == "spring_actuator"
                and len(body) > 80
                and "application/json"
                in (response.get("headers", {}) or {}).get("content-type", "").lower()
            ):
                framework_match = True

            if framework_match and label not in framework_pages_emitted:
                framework_pages_emitted.add(label)
                _emit_finding(
                    title=(
                        f"Framework debug page reachable "
                        f"unauthenticated: `{path}` on {target_host}"
                    ),
                    severity="medium",
                    category="information_disclosure",
                    target=target_host,
                    endpoint=probe_url,
                    description=(
                        f"GET {probe_url} returned status {status} "
                        f"with framework markers {matched}. Path is "
                        f"the canonical {label} debug surface."
                    ),
                    description_plain=(
                        f"Your server exposes the {label} debug page "
                        f"({path}) to the public internet without "
                        f"authentication. Attackers use these "
                        f"surfaces to dump environment variables, "
                        f"read request traces, and discover "
                        f"undocumented routes."
                    ),
                    recommended_action=(
                        f"Block `{path}` at the reverse-proxy edge "
                        f"in production, OR require authentication "
                        f"on it via the framework's built-in "
                        f"protection. Spring Actuator: bind to a "
                        f"separate port and firewall it (set "
                        f"`management.server.port` and exclude that "
                        f"port from the public LB). Symfony: ensure "
                        f"`profiler` is enabled only when "
                        f"`APP_ENV=dev`. Apache mod_status: restrict "
                        f"with `<Location /server-status> Require "
                        f"local </Location>` or remove the module."
                    ),
                )
                findings_emitted += 1

    # ---- Error-trigger payloads ----
    if parametric_runnable:
        for label, payload in _ERROR_TRIGGERS:
            probe_url = _append_query(target_url_norm, "strix_probe", payload)
            response = _http_get(probe_url, timeout=timeout)
            if response.get("skipped"):
                error_results.append({
                    "label": label,
                    "url": probe_url,
                    "status": 0,
                    "body_length": 0,
                    "new_trace_markers": [],
                    "skipped": True,
                })
                continue
            response_body = response.get("body") or ""
            response_traces = set(_trace_markers_in(response_body))
            new_traces = sorted(response_traces - baseline_traces)
            verdict = {
                "label": label,
                "url": probe_url,
                "status": int(response.get("status") or 0),
                "body_length": len(response_body),
                "new_trace_markers": new_traces,
                "skipped": False,
            }
            error_results.append(verdict)

            if error_finding_emitted:
                continue
            if new_traces:
                _emit_finding(
                    title=(
                        f"Error-trigger payload bleeds stack trace "
                        f"on {target_host} (`{label}`)"
                    ),
                    severity="low",
                    category="information_disclosure",
                    target=target_host,
                    endpoint=probe_url,
                    description=(
                        f"GET {probe_url} returned status "
                        f"{response.get('status')} with new trace "
                        f"markers absent from the baseline: "
                        f"{new_traces}. Payload class: {label}."
                    ),
                    description_plain=(
                        "An invalid query parameter caused your "
                        "server to return a verbose error message "
                        "containing internal file paths and / or a "
                        "framework name. Real attackers use this "
                        "leak to fingerprint the framework version "
                        "and select matching CVEs."
                    ),
                    recommended_action=(
                        "Configure the framework to emit a generic "
                        "500 page on parse error rather than a stack "
                        "trace. Django: ensure `DEBUG = False` and a "
                        "templated `500.html`. Rails: "
                        "`config.consider_all_requests_local = false` "
                        "in `production.rb`. Spring: implement "
                        "`@ControllerAdvice` that catches "
                        "exceptions and returns a generic body. "
                        "Strip stack-trace headers at the reverse-"
                        "proxy as a defense-in-depth."
                    ),
                )
                findings_emitted += 1
                error_finding_emitted = True

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{findings_emitted} debug-bleed finding(s) on {target_host}",
    )

    return {
        "success": True,
        "target_url": target_url_norm,
        "target_host": target_host,
        "baseline": baseline_summary,
        "parametric_probes": parametric_results,
        "framework_probes": framework_results,
        "error_probes": error_results,
        "findings_emitted": findings_emitted,
    }
