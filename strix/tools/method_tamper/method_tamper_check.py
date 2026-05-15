"""HTTP verb / method tampering prober.

Per-endpoint method matrix replay. Catches the standard verb-tampering
findings the agent doesn't think to test deterministically:

- **TRACE enabled** — XST primitive (Cross-Site Tracing). When the
  endpoint reflects request headers in the response, an XSS payload
  can read `Authorization` / `Cookie` headers via TRACE.
- **WebDAV exposure** — `OPTIONS` reveals `PROPFIND` / `MOVE` / `COPY`
  / `MKCOL` / `LOCK` / `UNLOCK`. Sensitive in non-WebDAV contexts;
  on a static asset route it can mean the entire filesystem is
  browsable.
- **Modifying methods on read-only endpoints** — `OPTIONS` advertises
  `PUT` / `PATCH` / `DELETE` on what should be a GET-only endpoint,
  signalling the agent that the documented method is one of several
  the route handler will accept. Information disclosure on its own;
  precondition for the destructive class below.
- **Method override translation** — opt-in cohort that sends `POST`
  with `X-HTTP-Method-Override: DELETE` (or `_method=DELETE` form
  param) and detects when the framework respects the override and
  routes to a different handler. Spring, Symfony, Rails default to
  honouring these.
- **Direct destructive verb acceptance** — opt-in cohort that sends
  `PUT` / `PATCH` / `DELETE` directly to the documented-GET endpoint
  and detects when the route handler responds. Real authz bypass
  vector when the framework wires verb routing without reading the
  documentation.

Probes (~5 default-safe + ~6 destructive when opted in):

| Label | Method | Headers | Body | Class |
|---|---|---|---|---|
| `baseline_get`         | GET    |                                 |   | baseline |
| `options`              | OPTIONS|                                 |   | discovery |
| `trace`                | TRACE  | `Test-Trace: strix-<n>`         |   | xst |
| `head`                 | HEAD   |                                 |   | head_asymmetry |
| `propfind`             | PROPFIND|                                |   | webdav |
| `override_put`         | POST   | `X-HTTP-Method-Override: PUT`   |   | override (destructive) |
| `override_patch`       | POST   | `X-HTTP-Method-Override: PATCH` |   | override (destructive) |
| `override_delete`      | POST   | `X-HTTP-Method-Override: DELETE`|   | override (destructive) |
| `_method_form_put`     | POST   | `Content-Type: application/x-www-form-urlencoded` | `_method=PUT` | form_method (destructive) |
| `_method_form_delete`  | POST   | `Content-Type: application/x-www-form-urlencoded` | `_method=DELETE`| form_method (destructive) |
| `direct_put`           | PUT    |                                 |   | direct (destructive) |
| `direct_patch`         | PATCH  |                                 |   | direct (destructive) |
| `direct_delete`        | DELETE |                                 |   | direct (destructive) |

Severity tuning:

- **High** (CWE-285, improper_authorization) — destructive verb
  (`PUT` / `PATCH` / `DELETE` direct, or via override translation)
  returns success-class status (2xx) on a documented-GET endpoint.
  Real authz bypass: the route handler accepts state-changing
  methods that aren't in the API surface.
- **Medium** (CWE-200, info_disclosure) — TRACE enabled and reflects
  custom request header in the response (XST primitive).
- **Medium** (CWE-200) — `OPTIONS` advertises WebDAV verbs
  (`PROPFIND`, `MOVE`, `COPY`, `MKCOL`, `LOCK`, `UNLOCK`) — the
  filesystem may be browsable.
- **Medium** (CWE-200) — `PROPFIND` returns 207 Multi-Status (WebDAV
  is wired up to this URL).
- **Low** (CWE-200) — `OPTIONS` advertises `PUT` / `PATCH` / `DELETE`
  that the endpoint's documented behaviour doesn't reveal.
- **Low** (CWE-200) — HEAD returns 405 / 501 when GET returns 200
  (cache asymmetry; some CDNs reveal real method-routing here).

Skip / soft-fail:

- Baseline GET non-2xx → endpoint may require auth or be invalid;
  tool exits gracefully with `inconclusive` and no probes dispatched.
- Cluster-A `--exclude-path` blocks the URL → graceful no-op.

Safety:

- **Destructive cohort is opt-in** via `include_destructive=True`.
  Default: only OPTIONS / TRACE / HEAD / PROPFIND probes run, all of
  which are read-only or no-op on production targets. The agent /
  operator must explicitly consent before any state-changing verb is
  dispatched.
- **PROPFIND is included by default** because in a non-WebDAV
  context it is a discovery-only verb that returns 405 / 501 on
  most servers; only on actual WebDAV endpoints does it return 207
  Multi-Status, in which case the WebDAV exposure itself is the
  finding.
- **Cluster-A composition** (auth-injection / exclude-path /
  rate-limit) applies to every probe — `--exclude-path` is the
  primary lever for blocking probes against specific endpoints.

Each finding carries `description_plain` + `recommended_action` (the
§11 non-tech UX fields). Recommendations: implement explicit
method-allow-list at the route handler level (don't rely on framework
default routing); strip `X-HTTP-Method-Override` and similar headers
at the edge; disable TRACE in the front-end; if WebDAV is intended,
require auth and deploy on a separate origin.

`verification_status=needs_review` since 2xx-on-DELETE doesn't
necessarily mean the resource was actually deleted (the framework
may return 200 for an unhandled method); the agent should follow up
to confirm semantic effect before treating any finding as a
confirmed exploit.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "method_tamper_check"
_DEFAULT_TIMEOUT = 10.0
_MAX_RESPONSE_SCAN = 64 * 1024


# Methods that imply state change. Acceptance of any of these on a
# GET-shaped endpoint is treated as high.
_DESTRUCTIVE_METHODS = ("PUT", "PATCH", "DELETE")

# WebDAV verbs to look for in OPTIONS Allow-header advertisement.
_WEBDAV_METHODS = ("PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK")


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Send an HTTP request via cluster-A safety. Returns
    {status, headers, body, error?, skipped?}."""
    headers = dict(headers or {})

    # Try sandbox proxy first.
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request(
                method, url, headers=headers, body=body, timeout=int(timeout)
            )
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": r.get("body") or "",
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)

    # Direct httpx fallback with manual cluster-A integration.
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
            content = body.encode("utf-8") if body else None
            r = c.request(method, url, headers=merged, content=content)
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
# Target / classification
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


def _status_class(status: int) -> str:
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "unknown"


def _parse_allow_methods(value: str | None) -> set[str]:
    if not value:
        return set()
    return {m.strip().upper() for m in value.split(",") if m.strip()}


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    cwe: str,
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
        cwe=cwe,
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "HTTP method tampering exposes parts of an application's "
            "API surface that the documented routes hide. The standard "
            "consequences: TRACE-driven Cross-Site Tracing (XSS payload "
            "exfiltrates Authorization/Cookie headers via reflected "
            "TRACE responses); WebDAV-method exposure on routes that "
            "weren't intended to be WebDAV; method-override-driven "
            "authz bypass when frameworks respect "
            "X-HTTP-Method-Override / _method form params; direct "
            "DELETE/PUT/PATCH on routes whose handler accepts more "
            "verbs than the docs reveal."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
    )
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        record_finding_in_kg(
            finding_id=finding_id, url=endpoint, param="http_method",
            cwe=cwe, severity=severity, category=category,
            method="VARIOUS", detection_kind=title[:60],
            confidence=0.85,
        )
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug(
            "method_tamper: kg record failed: %s", e, exc_info=True,
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
    mitre_techniques=["T1190"],  # Exploit Public-Facing Application
)
def method_tamper_check(
    target_url: str,
    include_destructive: bool = False,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe a URL for HTTP verb / method tampering vulnerabilities.

    Args:
        target_url: URL to probe. Bare hostnames are auto-prefixed
            with `https://`.
        include_destructive: When False (default), only the read-only
            cohort runs (OPTIONS / TRACE / HEAD / PROPFIND). When
            True, also probes `X-HTTP-Method-Override` / `_method` form
            param / direct PUT/PATCH/DELETE — these can mutate state
            on a vulnerable target. Set True only on staging targets
            where the operator has consented.
        timeout: Per-probe timeout in seconds (default 10).

    Returns:
        {
          success, target_url, target_host, include_destructive,
          baseline: {status, body_length, error?, skipped?},
          options_advertised: [method, ...],
          probes: [
            {label, method, class_, status, body_length,
             headers_subset, evidence, finding_severity},
            ...
          ],
          findings_emitted: int
        }

    Findings:
        - **High** (CWE-285, improper_authorization) — destructive
          verb (PUT/PATCH/DELETE direct or via override) returns
          success-class on the documented-GET endpoint.
        - **Medium** (CWE-200, info_disclosure) — TRACE enabled with
          request-header reflection (XST); WebDAV verbs advertised
          via OPTIONS or PROPFIND returns 207.
        - **Low** (CWE-200) — OPTIONS reveals modifying methods the
          docs don't show; HEAD returns 405/501 vs GET 200.

    Notes:
        - Read-only by default. `include_destructive=True` requires
          explicit operator consent.
        - Composes with cluster-A safety: `--exclude-path` /
          `--rate-limit` / `--auth-*` apply to every probe.
        - `verification_status=needs_review` — 2xx-on-DELETE doesn't
          necessarily mean the resource was deleted; agent should
          confirm semantic effect.
    """
    target_url_norm = _normalize_target(target_url)
    if target_url_norm is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    target_host = (urlparse(target_url_norm).hostname or "").lower()
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {target_url!r}"}

    cev = _start_check("method_tamper", target_host)
    nonce = secrets.token_hex(4)

    # ---- Baseline GET ----
    baseline_response = _http_request("GET", target_url_norm, timeout=timeout)
    if baseline_response.get("skipped"):
        _complete_check(cev, "inconclusive", "URL excluded by --exclude-path")
        return {
            "success": True,
            "target_url": target_url_norm,
            "target_host": target_host,
            "include_destructive": include_destructive,
            "baseline": {"skipped": True, "reason": "excluded by --exclude-path"},
            "options_advertised": [],
            "probes": [],
            "findings_emitted": 0,
        }

    baseline_status = baseline_response.get("status", 0)
    baseline_body = baseline_response.get("body") or ""
    baseline_summary = {
        "status": baseline_status,
        "status_class": _status_class(baseline_status),
        "body_length": len(baseline_body),
        "error": baseline_response.get("error"),
    }

    if _status_class(baseline_status) not in ("2xx", "3xx"):
        # Endpoint isn't returning useful baseline content — verb-
        # tampering acceptance can't be measured against an error
        # baseline.
        _complete_check(
            cev,
            "inconclusive",
            f"baseline GET returned {baseline_status}; can't measure verb acceptance",
        )
        return {
            "success": True,
            "target_url": target_url_norm,
            "target_host": target_host,
            "include_destructive": include_destructive,
            "baseline": baseline_summary,
            "options_advertised": [],
            "probes": [],
            "findings_emitted": 0,
        }

    findings_emitted = 0
    probe_results: list[dict[str, Any]] = []

    # ---- OPTIONS — capture allowed methods ----
    options_response = _http_request("OPTIONS", target_url_norm, timeout=timeout)
    options_allow = _parse_allow_methods(
        (options_response.get("headers") or {}).get("allow")
    )
    options_verdict = {
        "label": "options",
        "method": "OPTIONS",
        "class_": "discovery",
        "status": options_response.get("status", 0),
        "body_length": len(options_response.get("body") or ""),
        "headers_subset": {
            k: v for k, v in (options_response.get("headers") or {}).items()
            if k in ("allow", "access-control-allow-methods", "dav", "ms-author-via")
        },
        "evidence": f"Allow: {sorted(options_allow)}" if options_allow else "no Allow header",
        "finding_severity": None,
    }
    probe_results.append(options_verdict)

    advertised_webdav = options_allow & set(_WEBDAV_METHODS)
    if advertised_webdav:
        _emit_finding(
            title=f"WebDAV verbs advertised via OPTIONS on {target_host}",
            severity="medium",
            cwe="CWE-200",
            category="webdav_exposure",
            target=target_host,
            endpoint=target_url_norm,
            description=(
                f"OPTIONS response advertises WebDAV methods: "
                f"{sorted(advertised_webdav)}. Allow header: "
                f"{options_response.get('headers', {}).get('allow')}"
            ),
            description_plain=(
                "Your server advertises WebDAV methods (like PROPFIND, "
                "MOVE, COPY) on this URL. WebDAV is rarely the intent "
                "of a public web endpoint — when it's enabled by "
                "accident, an attacker can browse the filesystem, "
                "rename files, or upload via PUT."
            ),
            recommended_action=(
                "Disable WebDAV on this route. In nginx: don't load "
                "the `dav_module`. In Apache: ensure no `<Location>` "
                "block enables `Dav On` for the public-facing path. "
                "If WebDAV IS intended, require authentication and "
                "deploy on a separate origin (e.g. dav.example.com) "
                "with no overlap with the main app's cookies."
            ),
        )
        findings_emitted += 1

    # OPTIONS reveals destructive methods the GET-only endpoint shouldn't have.
    advertised_destructive = options_allow & set(_DESTRUCTIVE_METHODS)
    if advertised_destructive:
        options_verdict["finding_severity"] = "low"
        _emit_finding(
            title=f"OPTIONS advertises modifying methods on {target_host}",
            severity="low",
            cwe="CWE-200",
            category="method_disclosure",
            target=target_host,
            endpoint=target_url_norm,
            description=(
                f"GET endpoint also advertises {sorted(advertised_destructive)} "
                f"via OPTIONS. Full Allow: {sorted(options_allow)}"
            ),
            description_plain=(
                "Your server reveals via OPTIONS that this URL accepts "
                "state-changing HTTP methods (PUT / PATCH / DELETE) in "
                "addition to GET. By itself this is information "
                "disclosure; combined with weak authorization on the "
                "modifying methods it becomes account / data takeover."
            ),
            recommended_action=(
                "Audit the route handler for this URL. If only GET is "
                "intended, restrict the framework's method routing to "
                "GET (and HEAD). Set `Allow: GET, HEAD` explicitly in "
                "the OPTIONS response. If state-changing methods ARE "
                "intended, ensure each one runs the same authorization "
                "checks as the surrounding API."
            ),
        )
        findings_emitted += 1

    # ---- TRACE — XST primitive ----
    trace_marker = f"X-Strix-Trace-{nonce}"
    trace_response = _http_request(
        "TRACE", target_url_norm,
        headers={trace_marker: "echo-this-back"},
        timeout=timeout,
    )
    trace_class = _status_class(trace_response.get("status", 0))
    trace_body = trace_response.get("body") or ""
    trace_reflects_marker = trace_marker.lower() in trace_body.lower()
    trace_verdict = {
        "label": "trace",
        "method": "TRACE",
        "class_": "xst",
        "status": trace_response.get("status", 0),
        "body_length": len(trace_body),
        "headers_subset": {},
        "evidence": (
            f"TRACE returned {trace_response.get('status')}; "
            f"reflects request header: {trace_reflects_marker}"
        ),
        "finding_severity": None,
    }
    probe_results.append(trace_verdict)
    if trace_class == "2xx" and trace_reflects_marker:
        trace_verdict["finding_severity"] = "medium"
        _emit_finding(
            title=f"TRACE method enabled (XST primitive) on {target_host}",
            severity="medium",
            cwe="CWE-200",
            category="xst",
            target=target_host,
            endpoint=target_url_norm,
            description=(
                f"TRACE returned {trace_response.get('status')} with "
                f"the request header `{trace_marker}` reflected in "
                f"the response body — Cross-Site Tracing primitive."
            ),
            description_plain=(
                "Your server has the TRACE method enabled. TRACE echoes "
                "the request headers back in the response. Combined with "
                "an XSS payload elsewhere on the site, an attacker can "
                "use TRACE to read otherwise-HttpOnly cookies and the "
                "Authorization header — bypassing the HttpOnly flag."
            ),
            recommended_action=(
                "Disable TRACE in the front-end. nginx: TRACE is "
                "disabled by default; ensure nothing reverses that. "
                "Apache: `TraceEnable Off`. Cloud LBs (CloudFront / "
                "ALB / etc.): block TRACE in the WAF / origin request "
                "policy."
            ),
        )
        findings_emitted += 1

    # ---- HEAD — compare to GET ----
    head_response = _http_request("HEAD", target_url_norm, timeout=timeout)
    head_status = head_response.get("status", 0)
    head_class = _status_class(head_status)
    head_verdict = {
        "label": "head",
        "method": "HEAD",
        "class_": "head_asymmetry",
        "status": head_status,
        "body_length": len(head_response.get("body") or ""),
        "headers_subset": {},
        "evidence": f"HEAD returned {head_status} (baseline GET={baseline_status})",
        "finding_severity": None,
    }
    probe_results.append(head_verdict)
    if (
        head_status in (405, 501)
        and _status_class(baseline_status) == "2xx"
    ):
        head_verdict["finding_severity"] = "low"
        _emit_finding(
            title=f"HEAD/GET method asymmetry on {target_host}",
            severity="low",
            cwe="CWE-200",
            category="method_disclosure",
            target=target_host,
            endpoint=target_url_norm,
            description=(
                f"GET returned {baseline_status} but HEAD returned "
                f"{head_status}. This asymmetry can let CDN-fronted "
                f"caches reveal real method-routing on the origin."
            ),
            description_plain=(
                "Your server returns success for GET but rejects HEAD "
                "with a Method Not Allowed / Not Implemented status. "
                "Modern HTTP caches (CDNs) sometimes use HEAD probes "
                "to populate cache metadata; an asymmetry here reveals "
                "real method-routing on the origin to anyone who can "
                "send HEAD requests."
            ),
            recommended_action=(
                "Either implement HEAD as the head-only counterpart of "
                "GET (most frameworks do this automatically), OR "
                "explicitly return 200 with no body for HEAD on this "
                "URL. Don't rely on `405 Method Not Allowed` for HEAD."
            ),
        )
        findings_emitted += 1

    # ---- PROPFIND — WebDAV detection ----
    propfind_response = _http_request("PROPFIND", target_url_norm, timeout=timeout)
    propfind_status = propfind_response.get("status", 0)
    propfind_verdict = {
        "label": "propfind",
        "method": "PROPFIND",
        "class_": "webdav",
        "status": propfind_status,
        "body_length": len(propfind_response.get("body") or ""),
        "headers_subset": {
            k: v for k, v in (propfind_response.get("headers") or {}).items()
            if k in ("dav", "ms-author-via", "content-type")
        },
        "evidence": f"PROPFIND returned {propfind_status}",
        "finding_severity": None,
    }
    probe_results.append(propfind_verdict)
    # 207 Multi-Status is the canonical WebDAV success for PROPFIND.
    if propfind_status == 207 or (
        propfind_status == 200
        and "xml" in (propfind_response.get("headers") or {}).get("content-type", "").lower()
    ):
        # Dedup: if we already emitted a WebDAV-via-OPTIONS finding,
        # skip emitting a second one.
        if not advertised_webdav:
            propfind_verdict["finding_severity"] = "medium"
            _emit_finding(
                title=f"WebDAV PROPFIND succeeded on {target_host}",
                severity="medium",
                cwe="CWE-200",
                category="webdav_exposure",
                target=target_host,
                endpoint=target_url_norm,
                description=(
                    f"PROPFIND returned {propfind_status} with "
                    f"Content-Type "
                    f"{propfind_response.get('headers', {}).get('content-type')}. "
                    f"WebDAV is wired up to this URL."
                ),
                description_plain=(
                    "Your server responded to a PROPFIND request — the "
                    "WebDAV verb that lists files and directory contents. "
                    "WebDAV is rarely the intent of a public web "
                    "endpoint; when it's enabled by accident, an "
                    "attacker can browse the filesystem and discover "
                    "files the application's documented routes hide."
                ),
                recommended_action=(
                    "Disable WebDAV on this route. nginx: don't load "
                    "`dav_module`. Apache: ensure no `Dav On` directive "
                    "applies. If WebDAV IS intended, require auth and "
                    "deploy on a separate origin."
                ),
            )
            findings_emitted += 1

    # ---- Destructive cohort (opt-in) ----
    if include_destructive:
        destructive_probes = [
            ("override_put", "POST", {"X-HTTP-Method-Override": "PUT"}, "", "override"),
            ("override_patch", "POST", {"X-HTTP-Method-Override": "PATCH"}, "", "override"),
            ("override_delete", "POST", {"X-HTTP-Method-Override": "DELETE"}, "", "override"),
            ("_method_form_put", "POST",
             {"Content-Type": "application/x-www-form-urlencoded"}, "_method=PUT", "form_method"),
            ("_method_form_delete", "POST",
             {"Content-Type": "application/x-www-form-urlencoded"}, "_method=DELETE", "form_method"),
            ("direct_put", "PUT", {}, "", "direct"),
            ("direct_patch", "PATCH", {}, "", "direct"),
            ("direct_delete", "DELETE", {}, "", "direct"),
        ]

        seen_dedup_keys: set[str] = set()
        for label, method, headers, body, class_ in destructive_probes:
            response = _http_request(
                method, target_url_norm,
                headers=headers, body=body, timeout=timeout,
            )

            if response.get("skipped"):
                probe_results.append({
                    "label": label, "method": method, "class_": class_,
                    "status": 0, "body_length": 0, "headers_subset": {},
                    "evidence": "skipped by cluster-A path filter",
                    "finding_severity": None,
                })
                continue

            response_status = response.get("status", 0)
            response_class = _status_class(response_status)
            response_body_len = len(response.get("body") or "")
            verdict: dict[str, Any] = {
                "label": label, "method": method, "class_": class_,
                "status": response_status,
                "body_length": response_body_len,
                "headers_subset": {},
                "evidence": (
                    f"{method} returned {response_status}; "
                    f"baseline GET = {baseline_status}"
                ),
                "finding_severity": None,
            }

            # Acceptance heuristic: same success-class as baseline
            # GET, AND not a stock 405/501 method-rejection. The 2xx
            # range is the strongest signal; we also flag 3xx as
            # acceptance because some frameworks redirect after a
            # successful state change.
            if (
                response_class in ("2xx", "3xx")
                and response_status not in (405, 501)
                and _status_class(baseline_status) == "2xx"
            ):
                verdict["finding_severity"] = "high"
                # Dedup at the class level so the 3-variant override
                # cohort or 3-variant direct cohort emit one finding
                # apiece, not three.
                dedup_key = f"high::{class_}"
                if dedup_key not in seen_dedup_keys:
                    seen_dedup_keys.add(dedup_key)
                    if class_ == "direct":
                        title = (
                            f"Destructive verb `{method}` accepted on "
                            f"GET-documented endpoint at {target_host}"
                        )
                        description_plain = (
                            "Your route handler accepts state-changing "
                            "HTTP methods (PUT / PATCH / DELETE) on a "
                            "URL that the documented API only mentions "
                            "for GET. An attacker who finds this URL "
                            "(via crawl, source maps, OpenAPI leak) "
                            "can mutate data without going through the "
                            "documented API surface."
                        )
                        recommended_action = (
                            "Implement an explicit method allow-list in "
                            "the route handler. Don't rely on framework "
                            "default routing. Return `405 Method Not "
                            "Allowed` for verbs the route doesn't "
                            "implement (and ensure the WAF doesn't "
                            "rewrite that to 200)."
                        )
                    elif class_ == "override":
                        title = (
                            f"Method override (`X-HTTP-Method-Override`) "
                            f"respected on {target_host}"
                        )
                        description_plain = (
                            "Your application respects the "
                            "`X-HTTP-Method-Override` header — when an "
                            "attacker sends POST with this header, the "
                            "framework treats the request as PUT/PATCH/"
                            "DELETE. This bypasses any WAF / front-end "
                            "rule that filters by HTTP method (because "
                            "the bytes on the wire are still POST)."
                        )
                        recommended_action = (
                            "Strip `X-HTTP-Method-Override` and similar "
                            "headers (`X-HTTP-Method`, `X-Method-"
                            "Override`) at the reverse-proxy edge. If "
                            "the application requires method override "
                            "for legitimate reasons, restrict it to "
                            "specific routes via an explicit allow-"
                            "list, not framework default."
                        )
                    else:  # form_method
                        title = (
                            f"Method override (form `_method` param) "
                            f"respected on {target_host}"
                        )
                        description_plain = (
                            "Your application respects the `_method` "
                            "form parameter — when an attacker submits "
                            "a form with `_method=DELETE`, the framework "
                            "treats the request as DELETE. Same WAF-"
                            "bypass risk as header-based override."
                        )
                        recommended_action = (
                            "Disable form-method override in your "
                            "framework configuration (Rails: "
                            "`config.action_controller.allow_method_"
                            "override`; Symfony: "
                            "`framework.http_method_override`). If "
                            "required, restrict to specific routes."
                        )
                    description = (
                        f"Probe `{label}` ({method}) → status "
                        f"{response_status}, body length "
                        f"{response_body_len}. Baseline GET = "
                        f"{baseline_status}."
                    )
                    _emit_finding(
                        title=title,
                        severity="high",
                        cwe="CWE-285",
                        category="improper_authorization",
                        target=target_host,
                        endpoint=target_url_norm,
                        description=description,
                        description_plain=description_plain,
                        recommended_action=recommended_action,
                    )
                    findings_emitted += 1

            probe_results.append(verdict)

    # ---- Baseline verdict line ----
    probe_results.insert(0, {
        "label": "baseline_get",
        "method": "GET",
        "class_": "baseline",
        "status": baseline_status,
        "body_length": len(baseline_body),
        "headers_subset": {},
        "evidence": "baseline",
        "finding_severity": None,
    })

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{findings_emitted} method-tampering finding(s) on {target_host}",
    )

    return {
        "success": True,
        "target_url": target_url_norm,
        "target_host": target_host,
        "include_destructive": include_destructive,
        "baseline": baseline_summary,
        "options_advertised": sorted(options_allow),
        "probes": probe_results,
        "findings_emitted": findings_emitted,
    }
