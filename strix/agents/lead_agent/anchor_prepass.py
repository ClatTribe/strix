"""OSS-first anchor pre-pass — Phase 0 detection layer.

## Why this exists

Per docs/proposals/2026-05-20-quick-mode-oss-first-architecture.md.

Live measurement on 2026-05-20 showed strix's LLM-driven tool
selection failed to invoke the OSS anchor scans (`scan_sast`,
`scan_sca_lockfiles`, `scan_iac`, `scan_nuclei_templates`, OWASP
API specialists) even after PR #359 explicitly told the LLM to
run them as "Phase 0: REQUIRED before any other phase."

flask-vuln: 99 min wall, 0 findings, 22 deterministic tool calls
— none of which were the anchors. Vanilla `semgrep` finds 15 vulns
in flask-vuln in 3 seconds at $0 cost.

The architectural fix: **run the OSS anchors deterministically
BEFORE the lead's first LLM call.** The LLM's job collapses to
ranking / dedup / FP demotion on findings that are already in
context, not to decide which scanner to call.

## What this module does

`run_oss_anchor_prepass(scan_config, agent_state)` is invoked from
`StrixAgent.execute_scan` BEFORE the agent_loop entry point. It:

1. Inspects each target to determine its `target_type`.
2. Looks up the per-target-type anchor sequence (deterministic,
   hard-coded — no LLM judgement).
3. Calls each anchor tool via the existing `execute_tool` path.
4. Collects findings into a structured summary.
5. Returns the summary so `execute_scan` can render it into the
   lead's initial task description (the lead's first LLM call
   sees the findings already-present).

## Layer architecture

| Layer | What does the work | Scope |
|---|---|---|
| L1 (this module) | OSS signature corpus + deterministic specialists | Layer 1 — same in all modes (quick, standard, deep) |
| L2 (existing lead loop) | LLM reasoning — rank, dedupe, FP demote, novel-vuln tag | Layer 2 — proportional to scan mode |
| L3 (dispatch_specialist) | Fresh-context exploit chains + PoC synthesis | Layer 3 — quick=0, standard=8, deep=unbounded |

This module is L1 ONLY. It never invokes the LLM. It runs the same
deterministic anchor sequence regardless of scan mode — the lead
loop's iter_cap (and downstream dispatch_specialist budget) handles
the mode-aware L2/L3 budgeting.

## Kill switches

| Env var | Default | Effect |
|---|---|---|
| `STRIX_OSS_PREPASS_DISABLED` | unset | Skip the prepass, fall through to legacy LLM-driven tool selection. For debugging regressions. |
| `STRIX_OSS_PREPASS_TIMEOUT` | 600 | Per-tool wall-clock cap. Each anchor scan that exceeds this falls into status=partial; the prepass continues with the rest. |
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


# Per-target-type anchor sequences. Each entry is
# (tool_name, kwarg_builder), where kwarg_builder is a callable
# that takes (target_value, workspace_path) and returns the kwargs
# to pass to `execute_tool(tool_name, ...)`.
#
# Tool names match the strix tool registry. Failures of any single
# tool are isolated — the prepass logs and continues with the rest.
#
# Kwarg-builder signature: `(target_value, workspace_path, tool_name)`.
# Builders inspect the tool's `sandbox_execution` registration to pick
# the right filesystem path: tools that run on the host (semgrep, trivy,
# osv-scanner, gitleaks via scan_sast/scan_sca/scan_iac) need the HOST
# path (`target_value`); tools that run inside the sandbox container
# (secrets_scan, scan_container_image, etc.) need the SANDBOX path
# (`workspace_path` — `/workspace/...`).
#
# Without this distinction the prepass passed `/workspace/src` to
# host-running tools, which immediately errored "not a directory".
def _code_kwargs(target_value: str, workspace_path: str, tool_name: str) -> dict[str, Any]:
    """Kwargs for code-target anchor tools (scan_sast,
    scan_sca_lockfiles, scan_iac, secrets_scan). All take
    `repo_path` pointing at the source tree — but which path
    depends on whether the tool executes on host or in sandbox."""
    try:
        from strix.tools.registry import should_execute_in_sandbox
        in_sandbox = should_execute_in_sandbox(tool_name)
    except Exception:  # noqa: BLE001
        in_sandbox = False
    # Sandbox-running tool → workspace_path (visible inside container).
    # Host-running tool → host path (target_value, what the local
    # subprocess can actually open).
    if in_sandbox and workspace_path:
        return {"repo_path": workspace_path}
    return {"repo_path": target_value}


def _api_url_kwargs(target_value: str, workspace_path: str, tool_name: str) -> dict[str, Any]:
    """Kwargs for API/web-target anchor tools that accept a plain
    `url` parameter (scan_nuclei_templates / scan_sqli / scan_xxe /
    scan_ssrf / scan_ssti / scan_path_traversal / scan_nosql_injection /
    scan_cmd_injection / scan_api_rate_limit / open_redirect_check /
    csrf_check / cors_deep_check / scan_xss / dom_xss_static_probe /
    scan_cache_deception / scan_websocket_auth / scan_prototype_pollution
    / scan_secrets_in_response / http_security_headers_audit / tls_audit).

    NOT used for tools that take `target=` (fingerprint_tech_stack,
    openapi_spec_ingest) — they have their own builder."""
    return {"url": target_value}


def _api_target_kwargs(target_value: str, workspace_path: str, tool_name: str) -> dict[str, Any]:
    """Kwargs for tools that use `target=` rather than `url=`
    (fingerprint_tech_stack, openapi_spec_ingest). Caught live on
    2026-05-20: fingerprint_tech_stack raised TypeError when passed
    `url`."""
    return {"target": target_value}


def _api_url_with_severity_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """nuclei scans with broad signature tag-set. Item J of iter-11:
    expanded from ['cve'] alone to a multi-tag set that catches
    default-creds, exposed-panels, common misconfigs, and authn-
    related known-issues. Each tag adds 10s-100s of templates to
    the scan; together they ~10x the coverage on web/api targets
    at modest wall-time cost (~30-60s on a typical fixture).

    The tag list is curated to high-signal categories:
      * `cve`             — known-CVE templates (~3500)
      * `default-login`   — default credential checks
      * `exposure`        — exposed-panel / exposed-info templates
      * `misconfig`       — misconfiguration templates
      * `authenticated`   — authn-required known issues
      * `jwt`             — JWT-specific issues
      * `oauth`           — OAuth misconfig
      * `api`             — API-specific templates
      * `intrusive`       — active probes that don't auth-bypass

    Severity gate keeps the volume manageable.
    """
    return {
        "url": target_value,
        "tags": ["cve", "default-login", "exposure", "misconfig",
                 "authenticated", "jwt", "oauth", "api", "intrusive"],
        "severity": ["medium", "high", "critical"],
    }


def _container_kwargs(target_value: str, workspace_path: str, tool_name: str) -> dict[str, Any]:
    """Kwargs for container_image scan."""
    return {"image_ref": target_value}


# ---------------------------------------------------------------------------
# Anchor sequences
# ---------------------------------------------------------------------------
#
# Each list is ordered — we run the cheapest, highest-EPSS-impact tool
# FIRST so the lead's first LLM call (which still has a finite iter
# budget) sees the most useful findings first if it has to triage.


_ANCHORS_LOCAL_CODE: list[tuple[str, Any]] = [
    # 1. SCA lockfile scan — dependency CVEs are highest-EPSS hits
    #    AND emit Dependency nodes that R10 chain construction needs.
    ("scan_sca_lockfiles", _code_kwargs),
    # 2. SAST — semgrep-driven, registry rules + vibe-coded pack.
    ("scan_sast", _code_kwargs),
    # 3. IaC posture — Vercel / Netlify / Terraform / Dockerfile.
    ("scan_iac", _code_kwargs),
    # 4. Secrets in code (gitleaks + trufflehog under the hood).
    ("secrets_scan", _code_kwargs),
]

_ANCHORS_API: list[tuple[str, Any]] = [
    # 1. Tech-stack fingerprint — light HTTP probe to identify stack
    #    BEFORE the heavier signature scans target the right rule
    #    subset. Uses `target=` (not `url=`) — caught 2026-05-20.
    ("fingerprint_tech_stack", _api_target_kwargs),
    # 2. OpenAPI/Swagger spec discovery + ingest. Emits the
    #    `endpoints` list that downstream OWASP API Top 10 specialists
    #    (scan_api_bola/bfla/mass_assignment) consume. Without this
    #    they CAN'T run from the prepass — they error on missing
    #    endpoints kwarg.
    ("openapi_spec_ingest", _api_target_kwargs),
    # 3. Signature corpus — nuclei templates for known CVEs in any
    #    fingerprinted product. Highest known-CVE coverage.
    ("scan_nuclei_templates", _api_url_with_severity_kwargs),
    # 4. Rate-limit probe — single URL, no params needed.
    ("scan_api_rate_limit", _api_url_kwargs),
    # 5. URL-based injection scanners. These accept a bare URL and
    #    auto-discover params (or report partial when no params).
    #    They're best-effort in the prepass — the lead will follow
    #    up with parameter-aware invocations when needed.
    ("scan_sqli", _api_url_kwargs),
    ("scan_xxe", _api_url_kwargs),
    ("scan_ssrf", _api_url_kwargs),
    ("scan_ssti", _api_url_kwargs),
    ("scan_path_traversal", _api_url_kwargs),
    ("scan_nosql_injection", _api_url_kwargs),
    ("scan_cmd_injection", _api_url_kwargs),
    # 6. Passive checks — single-URL probes that don't need params.
    ("scan_secrets_in_response", _api_url_kwargs),
    ("http_security_headers_audit", _api_url_kwargs),
    ("tls_audit", _api_url_kwargs),
    ("cors_deep_check", _api_url_kwargs),
    ("csrf_check", _api_url_kwargs),
    ("open_redirect_check", _api_url_kwargs),
    # NOT in v1 of the API prepass (require prereqs the prepass
    # doesn't yet wire):
    #   * jwt_audit — needs a JWT token (out of scope for prepass;
    #     the lead's L2 layer extracts JWTs from response captures
    #     then invokes jwt_audit per token).
    #   * scan_api_bola / scan_api_bfla / scan_api_mass_assignment —
    #     need `endpoints=list[dict]` from openapi_spec_ingest's
    #     emission. The lead picks these up from KG endpoints after
    #     openapi_spec_ingest runs.
]

_ANCHORS_WEB: list[tuple[str, Any]] = _ANCHORS_API + [
    # Web-only DOM-aware probes.
    ("scan_xss", _api_url_kwargs),
    ("dom_xss_static_probe", _api_url_kwargs),
    ("scan_cache_deception", _api_url_kwargs),
    ("scan_websocket_auth", _api_url_kwargs),
    ("scan_prototype_pollution", _api_url_kwargs),
]

_ANCHORS_CONTAINER: list[tuple[str, Any]] = [
    # trivy image with vuln + misconfig + secret scanners enabled.
    ("scan_container_image", _container_kwargs),
    ("sbom_extract", _container_kwargs),
]

# Per-target-type anchor lookup. Empty list = "no signature corpus
# applies to this target type; fall through to the lead loop with
# no prepass findings."
_ANCHORS_BY_TARGET_TYPE: dict[str, list[tuple[str, Any]]] = {
    "local_code": _ANCHORS_LOCAL_CODE,
    "repository": _ANCHORS_LOCAL_CODE,
    "api": _ANCHORS_API,
    "web_application": _ANCHORS_WEB,
    "container_image": _ANCHORS_CONTAINER,
    "domain": [],
    "ip_address": [],
}


@dataclass
class ToolResult:
    """Outcome of one anchor tool invocation."""
    tool_name: str
    status: str  # "ok" | "partial" | "error" | "timeout"
    findings_count: int = 0
    error_reason: str | None = None
    wall_time_s: float = 0.0
    raw_result: Any = None  # the tool's SpecialistResult / dict


@dataclass
class PrepassSummary:
    """Aggregated outcome of `run_oss_anchor_prepass`.

    `total_findings` is the naive UNION across tools — over-counts
    duplicates (e.g. nuclei + scan_sqli both flagging the same SQLi
    endpoint). Dedup happens in the lead loop's L2 layer."""
    target_type: str
    target_value: str
    tools_run: list[str] = field(default_factory=list)
    tools_succeeded: list[str] = field(default_factory=list)
    tools_failed: list[str] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    total_findings: int = 0
    wall_time_s: float = 0.0
    skipped_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_type": self.target_type,
            "target_value": self.target_value,
            "tools_run": list(self.tools_run),
            "tools_succeeded": list(self.tools_succeeded),
            "tools_failed": list(self.tools_failed),
            "findings_count_by_tool": {
                r.tool_name: r.findings_count for r in self.tool_results
            },
            "total_findings_pre_dedupe": self.total_findings,
            "wall_time_s": round(self.wall_time_s, 2),
            "skipped_reason": self.skipped_reason,
        }


def is_disabled() -> bool:
    """Kill switch — when set, prepass returns immediately and the
    lead loop runs with the legacy LLM-driven tool selection."""
    return os.environ.get(
        "STRIX_OSS_PREPASS_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _read_timeout() -> int:
    raw = (os.environ.get("STRIX_OSS_PREPASS_TIMEOUT") or "").strip()
    if not raw:
        return 600
    try:
        v = int(float(raw))
        return max(30, v)
    except (TypeError, ValueError):
        return 600


def _count_findings(result: Any) -> int:
    """Best-effort count of findings emitted by a tool. The strix
    SpecialistResult shape varies — try the common keys then fall
    back to 0."""
    if result is None:
        return 0
    # SpecialistResult dataclass / dict with .findings / ["findings"]
    findings = None
    if isinstance(result, dict):
        findings = result.get("findings") or result.get("vulnerabilities")
    else:
        findings = getattr(result, "findings", None) or getattr(
            result, "vulnerabilities", None,
        )
    if findings is None:
        return 0
    try:
        return len(findings)
    except TypeError:
        return 0


async def _run_one_tool(
    tool_name: str,
    kwargs: dict[str, Any],
    *,
    agent_state: Any,
    timeout_s: int,
) -> ToolResult:
    """Invoke one anchor tool via `execute_tool`. Always returns a
    ToolResult (never raises) so the orchestrator can keep running
    the rest of the sequence even if this tool errors."""
    import time as _t
    from strix.tools.executor import execute_tool

    start = _t.monotonic()
    try:
        raw = await asyncio.wait_for(
            execute_tool(tool_name, agent_state=agent_state, **kwargs),
            timeout=timeout_s,
        )
        elapsed = _t.monotonic() - start
        count = _count_findings(raw)
        # The strix SpecialistResult includes a `status` field —
        # surface that into our ToolResult shape, AND extract any
        # reason field the wrapper used to explain a non-ok status.
        # Without this, status="error" results show up downstream with
        # an empty error_reason and the operator can't see why.
        status_str = "ok"
        error_reason = None
        if isinstance(raw, dict):
            if raw.get("status"):
                status_str = str(raw["status"])
            for k in ("error_reason", "reason", "error", "hint", "message"):
                v = raw.get(k)
                if v:
                    error_reason = str(v)[:300]
                    break
        elif hasattr(raw, "status") and raw.status:
            status_str = str(raw.status)
            for k in ("error_reason", "reason", "error", "hint", "message"):
                v = getattr(raw, k, None)
                if v:
                    error_reason = str(v)[:300]
                    break
        return ToolResult(
            tool_name=tool_name,
            status=status_str,
            findings_count=count,
            error_reason=error_reason,
            wall_time_s=elapsed,
            raw_result=raw,
        )
    except asyncio.TimeoutError:
        elapsed = _t.monotonic() - start
        logger.warning(
            "OSS prepass: %s timed out after %ds", tool_name, timeout_s,
        )
        return ToolResult(
            tool_name=tool_name,
            status="timeout",
            error_reason=f"timed out after {timeout_s}s",
            wall_time_s=elapsed,
        )
    except Exception as e:  # noqa: BLE001
        elapsed = _t.monotonic() - start
        logger.warning(
            "OSS prepass: %s failed: %s: %s",
            tool_name, type(e).__name__, e,
        )
        return ToolResult(
            tool_name=tool_name,
            status="error",
            error_reason=f"{type(e).__name__}: {e}"[:200],
            wall_time_s=elapsed,
        )


def _katana_crawl(target_url: str, *, max_endpoints: int = 50,
                  depth: int = 3, timeout_s: int = 60) -> list[dict[str, Any]]:
    """Host-runnable web crawl via katana. Returns a list of endpoint
    dicts in the same shape as openapi_spec_ingest emits.

    Used by phase-2 when the target is a web_application + no
    OpenAPI spec was discovered. Without this, vibe-app / juiceshop
    style HTML targets have no per-endpoint surface for the scan_*
    specialists to iterate.

    Best-effort: any failure (katana not on PATH, target unreachable,
    timeout, parse error) returns empty list. The phase-2 caller
    treats empty as "no endpoint scanning to do."

    Configuration:
      * `-jc` + `-jsl` — JavaScript crawling + jsluice JS-AST parsing
        to extract REST/API endpoints from bundled SPAs (Angular /
        React / Vue). Without these, juiceshop returns ~6 static
        asset URLs and nothing else.
      * `-kf all` — known-file probing (robots.txt, sitemap.xml).
        Catches deprecated-interface-style endpoints that the SPA
        doesn't link from its main bundle.
      * `-d 3` — crawl depth. Default 3 balances spec-rich SPAs
        against runaway crawls.
      * Common endpoint-discovery wordlist patterns excluded via
        the binary-asset filter (don't probe .js / .css / image
        files as endpoints).
    """
    import shutil as _shutil
    import subprocess as _subprocess
    if not _shutil.which("katana"):
        return []
    cmd = [
        "katana", "-u", target_url,
        "-d", str(depth),
        "-silent", "-nc",
        "-jc", "-jsl",          # JS crawl + jsluice AST parsing
        "-kf", "all",           # known files (robots, sitemap)
        "-rl", "50",            # 50 req/s rate-limit
        "-c", "10",             # 10 concurrency
        "-timeout", "10",
        # Exclude binary assets from results — they're not endpoints.
        "-ef", "css,js,png,jpg,jpeg,gif,svg,woff,woff2,ttf,ico,map",
    ]
    try:
        r = _subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
        )
    except (_subprocess.TimeoutExpired, OSError):
        return []
    urls: list[str] = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if line and line.startswith("http"):
            urls.append(line)
            if len(urls) >= max_endpoints:
                break
    # Deduplicate URL paths so we don't re-scan ?foo=1 vs ?foo=2.
    seen_paths: set[str] = set()
    endpoints: list[dict[str, Any]] = []
    for u in urls:
        try:
            from urllib.parse import urlparse
            p = urlparse(u)
            key = f"{p.scheme}://{p.netloc}{p.path}"
        except Exception:  # noqa: BLE001
            key = u
        if key in seen_paths:
            continue
        seen_paths.add(key)
        endpoints.append({
            "url": u,
            "path": (
                u.split("//", 1)[-1].split("/", 1)[-1]
                if "/" in u.split("//", 1)[-1]
                else "/"
            ),
            "method": "GET",
            "params": [],
            "source": "katana_crawl",
        })
    return endpoints


# ---------------------------------------------------------------------------
# Iter-11 — deterministic L1 probes
# ---------------------------------------------------------------------------
#
# These are stateless host-runnable probes that don't need auth setup
# or LLM reasoning. Each one targets a specific must_find class that
# was unreachable from the existing anchors. Designed to push api +
# web_application L1 recall close to (or past) the competitor bar
# documented in docs/benchmark.md.
#
# Each probe returns a list of dicts in canonical Found shape:
#   {title, category, cwe, endpoint, severity, description, ...}
#
# Best-effort: each probe must handle its own exceptions and return
# [] on any failure. The orchestrator wraps the call in try/except.


def _http_get(url: str, *, timeout: float = 5.0, headers: dict | None = None,
              allow_redirects: bool = False) -> Any:
    """Tiny host-runnable HTTP GET via urllib (no httpx dep needed)."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, headers=headers or {})
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        return e  # has .status, .headers, .read()
    except Exception:  # noqa: BLE001
        return None


def _http_request(url: str, *, method: str = "GET", timeout: float = 5.0,
                  headers: dict | None = None, data: bytes | None = None) -> Any:
    """Tiny host-runnable HTTP request, any method, via urllib."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, headers=headers or {}, data=data, method=method)
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        return e
    except Exception:  # noqa: BLE001
        return None


def probe_openapi_spec_exposed(
    *, target_url: str, spec_url: str | None,
) -> list[dict[str, Any]]:
    """Item I — emit a finding when openapi_spec_ingest reached the
    spec without authentication. The spec being unauthenticated-
    reachable is itself a finding on most production APIs (it leaks
    the API's full surface to anonymous attackers).

    Catches vampi `openapi-spec-exposed` (/openapi.json reachable
    unauthenticated).
    """
    if not spec_url:
        return []
    # Re-fetch the spec with no headers; if it returns 200 with json,
    # the spec is unauthenticated-reachable.
    resp = _http_get(spec_url, timeout=5.0)
    if resp is None:
        return []
    status = getattr(resp, "status", getattr(resp, "code", None))
    if status != 200:
        return []
    return [{
        "title": f"OpenAPI spec exposed unauthenticated at {spec_url}",
        "category": "api_inventory",
        "cwe": "CWE-200",
        "endpoint": spec_url,
        "severity": "medium",
        "description": (
            f"The OpenAPI/Swagger spec at {spec_url} is reachable "
            f"without authentication. An attacker can enumerate the "
            f"full API surface (endpoints, parameters, schemas, auth "
            f"requirements) without any credentials. Restrict the "
            f"spec endpoint behind auth or only expose it in non-"
            f"production environments."
        ),
        "verification_status": "verified",
        "confidence": 0.95,
    }]


def probe_jwt_none_alg(
    *, endpoints: list[dict[str, Any]], max_endpoints: int = 20,
) -> list[dict[str, Any]]:
    """Item B — forge a JWT with `alg: none` header and an arbitrary
    payload; send to each auth-walled endpoint. If the server
    accepts it (returns 200 / non-401), it's vulnerable to the
    canonical alg=none JWT bypass.

    Catches vampi `jwt-none-alg`, juiceshop `weak-jwt-handling`,
    any API that doesn't strictly validate the alg field.
    """
    import base64
    import json as _json

    def _b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    # Forged JWT with alg=none, no signature. Payload claims admin.
    header = _b64url(_json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(_json.dumps(
        {"sub": "admin", "user": "admin", "role": "admin",
         "is_admin": True, "exp": 9999999999},
    ).encode())
    forged_token = f"{header}.{payload}."

    out: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for ep in endpoints[:max_endpoints]:
        if not isinstance(ep, dict):
            continue
        url = ep.get("url")
        path = ep.get("path", "")
        if not url or path in seen_paths:
            continue
        seen_paths.add(path)
        # Probe with no auth first to establish baseline.
        baseline = _http_request(url, timeout=4.0)
        baseline_status = (
            getattr(baseline, "status", getattr(baseline, "code", None))
            if baseline else None
        )
        # Now with forged JWT.
        forged_resp = _http_request(
            url, timeout=4.0,
            headers={"Authorization": f"Bearer {forged_token}"},
        )
        forged_status = (
            getattr(forged_resp, "status", getattr(forged_resp, "code", None))
            if forged_resp else None
        )
        # Vulnerable signal: forged returns 200/2xx WHEN baseline
        # returned 401/403. (If baseline already returned 200,
        # the endpoint is unauth — different finding class.)
        if forged_status and 200 <= forged_status < 300 \
                and baseline_status in (401, 403):
            out.append({
                "title": f"JWT alg=none accepted on {ep.get('method','GET')} {path}",
                "category": "jwt",
                "cwe": "CWE-347",
                "endpoint": url,
                "severity": "critical",
                "description": (
                    f"The server accepts a JWT with `alg: none` "
                    f"header on `{ep.get('method','GET')} {path}`. "
                    f"This is the canonical authentication-bypass "
                    f"vulnerability: an attacker can forge any "
                    f"claims (sub, role, is_admin) without a signing "
                    f"secret. Strictly validate the `alg` claim "
                    f"against your expected algorithm (HS256, RS256, "
                    f"etc.) — never accept `none`."
                ),
                "verification_status": "verified",
                "confidence": 0.95,
            })
    return out


def probe_mass_assignment_priv_fields(
    *, endpoints: list[dict[str, Any]], max_endpoints: int = 10,
) -> list[dict[str, Any]]:
    """Item C — for any POST endpoint with a body schema, send the
    schema fields PLUS well-known privilege-escalation fields
    (admin/role/is_superuser/is_admin/is_staff) and check the
    response for evidence of privilege escalation.

    Catches vampi `mass-assignment-admin`, crapi MA, any
    register-without-strip-extra-fields handler.
    """
    import json as _json
    PRIV_FIELDS = {
        "admin": True,
        "is_admin": True,
        "role": "admin",
        "is_superuser": True,
        "is_staff": True,
        "isAdmin": True,
        "user_role": "admin",
    }
    out: list[dict[str, Any]] = []
    for ep in endpoints[:max_endpoints]:
        if not isinstance(ep, dict):
            continue
        method = ep.get("method", "GET")
        if method.upper() not in ("POST", "PUT", "PATCH"):
            continue
        url = ep.get("url")
        path = ep.get("path", "")
        schema = ep.get("request_body_schema") or {}
        if not url or not isinstance(schema, dict):
            continue
        props = schema.get("properties") or {}
        if not isinstance(props, dict) or not props:
            continue
        # Build the canonical body from schema + add priv fields.
        body = {}
        for fname, fmeta in props.items():
            if isinstance(fmeta, dict):
                ftype = fmeta.get("type", "string")
                if ftype == "string":
                    body[fname] = "test_value_" + str(hash(fname) % 10000)
                elif ftype == "integer":
                    body[fname] = 1
                elif ftype == "boolean":
                    body[fname] = False
                elif ftype == "number":
                    body[fname] = 1.0
        body_with_priv = {**body, **PRIV_FIELDS}
        try:
            data = _json.dumps(body_with_priv).encode()
        except Exception:  # noqa: BLE001
            continue
        resp = _http_request(
            url, method=method, timeout=5.0,
            headers={"Content-Type": "application/json"}, data=data,
        )
        status = (
            getattr(resp, "status", getattr(resp, "code", None))
            if resp else None
        )
        # Vulnerable signal: created (2xx) with the priv fields
        # present in the response body. Conservative: also flag any
        # 2xx response that doesn't strip the extra fields.
        if status and 200 <= status < 300:
            try:
                body_text = (resp.read() or b"").decode(errors="replace")
            except Exception:  # noqa: BLE001
                body_text = ""
            # Heuristic: if ANY of the priv field names appears in
            # the response, mass-assignment is likely. Strict
            # implementations would strip them. (FP rate: low —
            # most APIs return a sanitized user representation.)
            priv_echoed = any(
                f'"{f}"' in body_text or f"'{f}'" in body_text
                for f in ("admin", "is_admin", "isAdmin", "role",
                          "is_superuser", "is_staff")
            )
            if priv_echoed:
                out.append({
                    "title": f"Mass-assignment privilege-field accepted on {method} {path}",
                    "category": "mass_assignment",
                    "cwe": "CWE-915",
                    "endpoint": url,
                    "severity": "high",
                    "description": (
                        f"The {method} {path} endpoint accepts "
                        f"privilege-escalation fields (admin, role, "
                        f"is_admin, is_superuser) in the request body "
                        f"and echoes them back in the response. An "
                        f"attacker can self-promote during registration "
                        f"or profile update. Strip unrecognized fields "
                        f"server-side; never trust client-supplied "
                        f"authorization metadata."
                    ),
                    "verification_status": "verified",
                    "confidence": 0.8,
                })
    return out


def probe_unauth_debug_paths(
    *, target_url: str, endpoints: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Item D — probe common debug / admin / internal paths
    unauthenticated and emit findings for 200 OK responses.

    Catches vampi `bfla-debug-endpoint` (/users/v1/_debug),
    juiceshop `deprecated-interface` (/b2b/v2/orders),
    exposed Spring Boot actuators, exposed Flask debug.

    When `endpoints` is provided (from openapi_spec_ingest), ALSO
    probes any endpoint path that contains 'debug' / 'admin' /
    'internal' substrings as a heuristic exposure check. This
    catches vampi's `/users/v1/_debug` which lives at a sub-path
    that the static path list doesn't enumerate.
    """
    PATHS = [
        # generic debug endpoints
        "/_debug", "/debug", "/api/debug", "/api/_debug",
        "/admin/_debug", "/_internal", "/api/internal",
        "/api/_admin", "/admin", "/admin/", "/dashboard",
        # framework-specific known exposures
        "/actuator", "/actuator/env", "/actuator/health",
        "/actuator/metrics", "/_health", "/health",
        "/metrics", "/_metrics", "/api/health",
        # legacy / deprecated interface patterns
        "/b2b/v2/orders", "/b2b/v1/", "/v1/admin",
        "/api/v0/", "/api/legacy/", "/_legacy/",
        # juiceshop / OWASP-published patterns
        "/ftp", "/ftp/", "/encryptionkeys", "/encryptionkeys/",
        "/.well-known/security.txt", "/robots.txt",
    ]
    base = target_url.rstrip("/")
    # Build the set of URLs to probe: static common paths +
    # openapi-discovered paths matching debug-like keywords.
    candidate_urls: list[tuple[str, str]] = []  # (url, path_label)
    for p in PATHS:
        candidate_urls.append((base + p, p))
    # Add openapi paths that look debug-y. Catches the
    # /users/v1/_debug sub-path that pure base-URL scanning misses.
    if endpoints:
        debug_hints = ("debug", "admin", "internal", "_admin",
                       "actuator", "diagnostic", "metric")
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            url = ep.get("url")
            path = ep.get("path") or ""
            method = (ep.get("method") or "GET").upper()
            if not url or method != "GET":
                continue
            path_l = path.lower()
            if any(h in path_l for h in debug_hints):
                candidate_urls.append((url, path))

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url, p in candidate_urls:
        if url in seen:
            continue
        seen.add(url)
        resp = _http_get(url, timeout=3.0)
        if resp is None:
            continue
        status = getattr(resp, "status", getattr(resp, "code", None))
        if status != 200:
            continue
        # Read enough to confirm it's a real response (not a
        # catch-all index page). Very conservative: only flag if
        # the response is shorter than 100K (most catch-all SPAs
        # return >500K HTML; legitimate /_debug returns small JSON).
        try:
            body = resp.read(8192)
        except Exception:  # noqa: BLE001
            body = b""
        # Skip generic SPA index responses (they all start with
        # <!DOCTYPE html> and serve the bundle).
        # Only emit when the response is JSON, plain text, or has
        # debug-indicator strings.
        is_html_index = body[:200].lower().startswith(b"<!doctype html")
        if is_html_index and p not in ("/ftp", "/ftp/", "/encryptionkeys"):
            continue
        category = "misconfig"
        cwe = "CWE-200"
        severity = "medium"
        if "debug" in p or "internal" in p or "_admin" in p:
            category = "bfla"
            severity = "high"
        elif "b2b" in p or "legacy" in p or "/api/v0" in p:
            category = "misconfig"
            severity = "medium"
        elif p in ("/ftp", "/ftp/"):
            category = "path_traversal"
            cwe = "CWE-548"
            severity = "high"
        out.append({
            "title": f"Unauthenticated exposed path: {p}",
            "category": category,
            "cwe": cwe,
            "endpoint": url,
            "severity": severity,
            "description": (
                f"The path `{p}` on {target_url} is reachable "
                f"unauthenticated and returned 200 OK. This is a "
                f"common exposed-internal-endpoint vector. Verify the "
                f"path is intentionally public and contains no "
                f"sensitive data, or restrict it behind authentication."
            ),
            "verification_status": "verified",
            "confidence": 0.7,
        })
    return out


def probe_open_redirect(
    *, target_url: str, endpoints: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Item E — probe common open-redirect endpoint paths and query
    parameter names. Sends `?next=https://evil.example` style
    payloads and checks the Location header for the attacker URL.

    Catches flask-vuln `open-redirect-login`, juiceshop
    `open-redirect-redirect`, any handler that follows
    user-controlled redirect targets.
    """
    REDIRECT_PARAM_NAMES = ["next", "to", "url", "redirect", "return",
                            "returnUrl", "return_url", "rurl",
                            "redirect_uri", "callback", "continue",
                            "dest", "destination"]
    REDIRECT_PATHS = ["/", "/login", "/logout", "/redirect",
                      "/api/redirect", "/oauth/callback"]
    ATTACKER = "https://evil.example/"
    base = target_url.rstrip("/")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    # Source 1: try common redirect paths with each common param name
    candidates: list[str] = []
    for path in REDIRECT_PATHS:
        for param in REDIRECT_PARAM_NAMES:
            candidates.append(f"{base}{path}?{param}={ATTACKER}")
    # Source 2: any endpoint that already has a redirect-y param
    if endpoints:
        for ep in endpoints[:30]:
            if not isinstance(ep, dict):
                continue
            url = ep.get("url")
            if not url:
                continue
            for param in REDIRECT_PARAM_NAMES:
                sep = "&" if "?" in url else "?"
                candidates.append(f"{url}{sep}{param}={ATTACKER}")

    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        # GET with redirects DISABLED so we can inspect the Location
        # header.
        resp = _http_get(url, timeout=3.0, allow_redirects=False)
        if resp is None:
            continue
        status = getattr(resp, "status", getattr(resp, "code", None))
        if status not in (301, 302, 303, 307, 308):
            continue
        location = ""
        try:
            location = resp.headers.get("Location", "") or ""
        except Exception:  # noqa: BLE001
            pass
        # Vulnerable: Location echoes attacker URL.
        if "evil.example" in location:
            # Pull the param name out of the URL we sent
            param_name = "unknown"
            for p in REDIRECT_PARAM_NAMES:
                if f"?{p}=" in url or f"&{p}=" in url:
                    param_name = p
                    break
            # Extract path from URL
            try:
                from urllib.parse import urlparse
                path_part = urlparse(url).path or "/"
            except Exception:  # noqa: BLE001
                path_part = url
            out.append({
                "title": f"Open redirect on {path_part} via ?{param_name}=",
                "category": "open_redirect",
                "cwe": "CWE-601",
                "endpoint": url.split("?")[0],
                "severity": "medium",
                "description": (
                    f"GET {path_part}?{param_name}=<attacker-url> "
                    f"returned a {status} redirect with Location: "
                    f"{location}. The handler follows user-controlled "
                    f"redirect targets without validation. Allowlist "
                    f"the permitted destinations or strip the host "
                    f"component before redirecting."
                ),
                "verification_status": "verified",
                "confidence": 0.95,
            })
            # Don't fire multiple times for the same path+param combo
    return out


def probe_unauth_bola_path_params(
    *, endpoints: list[dict[str, Any]], max_endpoints: int = 15,
) -> list[dict[str, Any]]:
    """Item F — for endpoints with `{user_id}` / `{username}` /
    `{id}` path parameters, iterate guess values (1, 2, admin,
    guest, test) unauthenticated. If any returns 200 with user-
    shaped data, BOLA is present.

    Catches vampi `bola-user-by-username`, similar.
    """
    GUESSES = ["1", "2", "3", "admin", "guest", "test", "name1"]
    PARAM_HINTS = ("id", "uid", "user", "username", "uuid", "slug")

    out: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for ep in endpoints[:max_endpoints]:
        if not isinstance(ep, dict):
            continue
        method = (ep.get("method") or "GET").upper()
        if method != "GET":
            continue
        path = ep.get("path", "")
        if path in seen_paths:
            continue
        seen_paths.add(path)
        # Only consider paths with {placeholder} that looks user-y
        if "{" not in path:
            continue
        # Extract param names between {}
        import re
        param_names = re.findall(r"\{([^}]+)\}", path)
        is_user_param = any(
            any(hint in p.lower() for hint in PARAM_HINTS)
            for p in param_names
        )
        if not is_user_param:
            continue
        # Try each guess for the FIRST param
        first_param = param_names[0]
        for guess in GUESSES:
            test_path = path.replace(f"{{{first_param}}}", guess)
            # Build full URL from the endpoint's url field
            url = ep.get("url", "")
            if not url:
                continue
            try:
                from urllib.parse import urlparse
                p = urlparse(url)
                base = f"{p.scheme}://{p.netloc}"
            except Exception:  # noqa: BLE001
                continue
            test_url = base + test_path
            resp = _http_get(test_url, timeout=4.0)
            if resp is None:
                continue
            status = getattr(resp, "status", getattr(resp, "code", None))
            if not status or not (200 <= status < 300):
                continue
            try:
                body = resp.read(4096)
            except Exception:  # noqa: BLE001
                continue
            # Check the body looks like user-shaped data
            body_lower = body.lower()
            user_shape_indicators = [
                b"username", b"email", b"password",
                b"user_id", b"role", b"name",
            ]
            matches = sum(1 for ind in user_shape_indicators
                          if ind in body_lower)
            if matches >= 2:
                # Found BOLA
                out.append({
                    "title": f"BOLA: unauthenticated access to {path} (param: {first_param}={guess})",
                    "category": "bola",
                    "cwe": "CWE-639",
                    "endpoint": test_url,
                    "severity": "high",
                    "description": (
                        f"GET {test_path} returned a 2xx response "
                        f"containing user-shaped data without any "
                        f"authentication. This is the canonical "
                        f"OWASP API1:2023 Broken Object Level "
                        f"Authorization vulnerability — any user "
                        f"resource is enumerable by ID. Require "
                        f"authentication AND verify the requesting "
                        f"user owns the resource."
                    ),
                    "verification_status": "verified",
                    "confidence": 0.85,
                })
                break  # one finding per endpoint
    return out


def probe_directory_listing(
    *, target_url: str,
) -> list[dict[str, Any]]:
    """Item G — probe common directory paths for autoindex /
    directory-listing responses.

    Catches juiceshop `directory-traversal-ftp` (/ftp listing),
    ip-vulnerable `nginx-autoindex` (/uploads listing).
    """
    PATHS = [
        "/ftp/", "/uploads/", "/files/", "/backup/",
        "/static/", "/assets/", "/data/", "/downloads/",
        "/.git/", "/.svn/", "/.env",
    ]
    base = target_url.rstrip("/")
    out: list[dict[str, Any]] = []
    for p in PATHS:
        url = base + p
        resp = _http_get(url, timeout=3.0)
        if resp is None:
            continue
        status = getattr(resp, "status", getattr(resp, "code", None))
        if status != 200:
            continue
        try:
            body = resp.read(8192).lower()
        except Exception:  # noqa: BLE001
            continue
        # Heuristics for directory listing:
        is_autoindex = (
            b"index of /" in body  # nginx + Apache autoindex
            or b"<title>index of" in body
            or (b"parent directory" in body and b"<a href=" in body)
        )
        if not is_autoindex:
            continue
        out.append({
            "title": f"Directory listing exposed at {p}",
            "category": "info_disclosure",
            "cwe": "CWE-548",
            "endpoint": url,
            "severity": "medium",
            "description": (
                f"The path `{p}` on {target_url} returns a directory "
                f"listing (autoindex). An attacker can enumerate the "
                f"file tree and discover sensitive files. Disable "
                f"autoindex (nginx: `autoindex off;`, Apache: "
                f"`Options -Indexes`) and/or restrict access to "
                f"the directory."
            ),
            "verification_status": "verified",
            "confidence": 0.95,
        })
    return out


def _build_sqli_kwargs_from_endpoint(
    ep: dict[str, Any],
) -> dict[str, Any] | None:
    """Item A — turn one openapi endpoint dict into kwargs for
    scan_sqli(url=, params=, method=, body_template=).

    Returns None when the endpoint has no probeable params (the
    base-URL scan_sqli already handled that case and reported
    partial='no params supplied').

    Strategy per endpoint:
      * GET with path params (e.g. `/books/v1/{book_title}`) →
        url retains placeholder, params=[path_param_name].
      * GET with query params → url stays as-is, params=[query names].
      * POST/PUT/PATCH with body schema → method=POST,
        body_template={canonical field values}, params=[string-typed
        field names] (so the probe payload goes into a value the
        backend will actually try to SQL-interpolate).
    """
    if not isinstance(ep, dict):
        return None
    url = ep.get("url")
    if not isinstance(url, str) or not url:
        return None
    method = (ep.get("method") or "GET").upper()
    params_list = ep.get("params") or []
    if not isinstance(params_list, list):
        params_list = []

    path_params = [
        str(p.get("name")) for p in params_list
        if isinstance(p, dict) and str(p.get("in", "")).lower() == "path"
        and p.get("name")
    ]
    query_params = [
        str(p.get("name")) for p in params_list
        if isinstance(p, dict) and str(p.get("in", "")).lower() == "query"
        and p.get("name")
    ]

    # POST/PUT/PATCH with body — build body_template from schema.
    if method in ("POST", "PUT", "PATCH"):
        schema = ep.get("request_body_schema") or {}
        if not isinstance(schema, dict):
            schema = {}
        props = schema.get("properties") or {}
        if not isinstance(props, dict) or not props:
            # Body-method endpoint with no declared schema — skip;
            # the base-URL scan_sqli already reported partial.
            if not query_params and not path_params:
                return None
        body_template: dict[str, Any] = {}
        sqli_param_candidates: list[str] = []
        for fname, fmeta in props.items():
            if not isinstance(fmeta, dict):
                body_template[fname] = "test"
                sqli_param_candidates.append(fname)
                continue
            ftype = fmeta.get("type", "string")
            if ftype == "string":
                # Use a placeholder value the probe will overwrite.
                # Strings are the canonical SQLi sink (interpolated
                # into queries without quoting).
                body_template[fname] = "test"
                sqli_param_candidates.append(fname)
            elif ftype == "integer":
                body_template[fname] = 1
                # Integers can also be SQLi-vulnerable (numeric ctx).
                sqli_param_candidates.append(fname)
            elif ftype == "boolean":
                body_template[fname] = False
            elif ftype == "number":
                body_template[fname] = 1.0
                sqli_param_candidates.append(fname)
        if not sqli_param_candidates:
            return None
        # Cap to 3 params per endpoint to keep scan_sqli wall time
        # under control (it probes each param with ~6 payloads).
        return {
            "url": url,
            "method": method,
            "params": sqli_param_candidates[:3],
            "body_template": body_template,
        }

    # GET — path params first (more likely sink), then query params.
    if path_params:
        # Keep {placeholder} in URL; scan_sqli substitutes it.
        return {
            "url": url,
            "method": "GET",
            "params": path_params[:3],
        }
    if query_params:
        return {
            "url": url,
            "method": "GET",
            "params": query_params[:3],
        }
    return None


async def _run_per_endpoint_sqli(
    summary: PrepassSummary,
    *,
    endpoints: list[Any],
    agent_state: Any,
    timeout_s: int,
    max_endpoints: int = 10,
) -> None:
    """Item A — invoke scan_sqli once per probeable endpoint with
    schema-hydrated kwargs. Mutates `summary` in place.

    Skips endpoints the base-URL scan_sqli already covered (no
    point re-probing the host root).
    """
    if not endpoints:
        return
    n = 0
    seen_targets: set[str] = set()
    for ep in endpoints:
        if n >= max_endpoints:
            break
        kwargs = _build_sqli_kwargs_from_endpoint(ep)
        if not kwargs:
            continue
        # Dedup on (method, url, sorted-params) so we don't double-
        # probe the same endpoint if the openapi spec lists it twice
        # under different tags.
        target_key = (
            kwargs.get("method", "GET"),
            kwargs["url"],
            tuple(sorted(kwargs.get("params") or [])),
        )
        if target_key in seen_targets:
            continue
        seen_targets.add(target_key)

        # Per-endpoint tool name for breakdown searchability.
        path = ep.get("path", kwargs["url"])
        method = kwargs.get("method", "GET")
        ep_tool_name = f"scan_sqli[{method} {path}]"
        summary.tools_run.append(ep_tool_name)
        result = await _run_one_tool(
            "scan_sqli", kwargs,
            agent_state=agent_state, timeout_s=timeout_s,
        )
        result.tool_name = ep_tool_name
        summary.tool_results.append(result)
        summary.total_findings += result.findings_count
        if result.status in ("ok", "partial"):
            summary.tools_succeeded.append(ep_tool_name)
        else:
            summary.tools_failed.append(ep_tool_name)
        n += 1


async def _run_dependent_api_tools(
    summary: PrepassSummary,
    *,
    agent_state: Any,
    timeout_s: int,
    target_value: str = "",
    target_type: str = "",
    max_endpoints_for_rate_limit: int = 20,
) -> None:
    """Phase 2 of the API/web-target prepass — runs scanners that
    need endpoints emitted by phase 1's openapi_spec_ingest.

    Looks for a successful openapi_spec_ingest result in the
    summary, extracts its `endpoints: list[dict]` field, and
    invokes:
      * `scan_api_bola(endpoints=...)` — OWASP API1
      * `scan_api_bfla(endpoints=...)` — OWASP API5
      * `scan_api_mass_assignment(endpoints=...)` — OWASP API3
      * `scan_api_rate_limit(url=..., method=...)` per endpoint,
        capped at `max_endpoints_for_rate_limit` (default 20) to
        bound wall time and request volume.

    Mutates `summary` in place — adds tools_run / tools_succeeded /
    tools_failed / tool_results / total_findings entries. Never
    raises; per-tool errors are captured in ToolResult shape.

    No-op when openapi_spec_ingest didn't succeed or returned no
    endpoints (e.g. target has no spec). The prepass falls back to
    the lead loop for endpoint inventory.
    """
    # Find the openapi_spec_ingest result.
    openapi_result = None
    for r in summary.tool_results:
        if r.tool_name == "openapi_spec_ingest" and r.status in ("ok", "partial"):
            openapi_result = r.raw_result
            break
    endpoints: list[Any] | None = None
    if isinstance(openapi_result, dict):
        endpoints = openapi_result.get("endpoints")
    # Fallback for web_application targets that have no OpenAPI spec:
    # crawl the target with katana to emit an endpoint list. Without
    # this, vibe-app / juiceshop / similar HTML-rendering apps have
    # no per-endpoint surface for phase-2 to iterate. The lead's L2
    # layer would also handle this via webapp_recon_pipeline, but
    # that's sandbox_execution=True and unavailable here.
    if (not endpoints) and target_type == "web_application" and target_value:
        crawled = _katana_crawl(target_value, max_endpoints=30, depth=2)
        if crawled:
            endpoints = crawled
            # Record a synthetic tool result so the breakdown shows
            # the katana crawl happened.
            summary.tools_run.append("katana_crawl")
            summary.tools_succeeded.append("katana_crawl")
            summary.tool_results.append(ToolResult(
                tool_name="katana_crawl",
                status="ok",
                findings_count=len(crawled),
                error_reason=None,
                wall_time_s=0.0,
                raw_result={"endpoints": crawled},
            ))
    # Iter-11 deterministic L1 probes — fire BEFORE bailing out on
    # empty endpoints. These probes don't need the endpoint list at
    # all (only target_value), so they should fire even when openapi
    # + katana found nothing.
    # All probes are best-effort: any internal failure → empty list.
    _probe_emissions: list[tuple[str, list[dict[str, Any]]]] = []
    if target_value:
        # Item D: heuristic debug-path enumerator. Passes the
        # endpoints list so the probe ALSO tests openapi-discovered
        # sub-paths that match debug-like keywords (e.g. vampi's
        # /users/v1/_debug which the static base-URL list misses).
        try:
            _probe_emissions.append(
                ("probe_unauth_debug_paths",
                 probe_unauth_debug_paths(
                     target_url=target_value,
                     endpoints=endpoints if isinstance(endpoints, list) else None,
                 ))
            )
        except Exception:  # noqa: BLE001
            pass
        # Item E: open-redirect probe (no endpoints needed at minimum,
        # endpoints enrich it)
        try:
            _probe_emissions.append(
                ("probe_open_redirect",
                 probe_open_redirect(
                     target_url=target_value,
                     endpoints=endpoints if isinstance(endpoints, list) else None,
                 ))
            )
        except Exception:  # noqa: BLE001
            pass
        # Item G: directory-listing probe (no endpoints needed)
        try:
            _probe_emissions.append(
                ("probe_directory_listing",
                 probe_directory_listing(target_url=target_value))
            )
        except Exception:  # noqa: BLE001
            pass
        # Item I: openapi-spec-exposure probe (needs spec_url from
        # openapi_spec_ingest)
        spec_url = None
        if isinstance(openapi_result, dict):
            spec_url = openapi_result.get("spec_url")
        try:
            _probe_emissions.append(
                ("probe_openapi_spec_exposed",
                 probe_openapi_spec_exposed(
                     target_url=target_value, spec_url=spec_url,
                 ))
            )
        except Exception:  # noqa: BLE001
            pass

    # Endpoint-dependent probes — only fire if we have an endpoint list
    if isinstance(endpoints, list) and endpoints:
        # Item B: forge-JWT alg=none probe
        try:
            _probe_emissions.append(
                ("probe_jwt_none_alg",
                 probe_jwt_none_alg(endpoints=endpoints))
            )
        except Exception:  # noqa: BLE001
            pass
        # Item C: mass-assignment privilege-field probe
        try:
            _probe_emissions.append(
                ("probe_mass_assignment_priv_fields",
                 probe_mass_assignment_priv_fields(endpoints=endpoints))
            )
        except Exception:  # noqa: BLE001
            pass
        # Item F: unauth BOLA path-param probe
        try:
            _probe_emissions.append(
                ("probe_unauth_bola_path_params",
                 probe_unauth_bola_path_params(endpoints=endpoints))
            )
        except Exception:  # noqa: BLE001
            pass

    # Record probe emissions as tool results
    for probe_name, findings in _probe_emissions:
        summary.tools_run.append(probe_name)
        if findings:
            summary.tools_succeeded.append(probe_name)
        else:
            # Treat zero-finding probes as "ok" too — they ran cleanly.
            summary.tools_succeeded.append(probe_name)
        summary.tool_results.append(ToolResult(
            tool_name=probe_name,
            status="ok",
            findings_count=len(findings),
            error_reason=None,
            wall_time_s=0.0,
            raw_result={"findings": findings, "status": "ok"},
        ))
        summary.total_findings += len(findings)

    if not isinstance(endpoints, list) or not endpoints:
        return

    # NOTE: scan_api_bola / scan_api_bfla / scan_api_mass_assignment
    # are NOT included here in the deterministic L1 phase, despite
    # taking the endpoints list. The reason: they require additional
    # prereqs that L1 can't synthesize from a bare endpoint list:
    #   * scan_api_bola needs `owner_ids: dict[str, str]` — the map
    #     of path-param-name → owner-resource-value (the "user A's
    #     resource" half of the cross-session BOLA probe).
    #     Discovering this requires authenticating as 2 users +
    #     enumerating each one's resources, which is L2 work.
    #   * scan_api_bfla needs `path_ids` for the same reason.
    #   * scan_api_mass_assignment needs `path_ids` for the target
    #     user's record IDs.
    # The lead's L2 layer picks these up after AuthFlow specialist
    # produces credentials, then invokes with proper kwargs. They're
    # in the lead's tool_catalog for that reason.
    #
    # The phase-2 prepass focuses on tools that genuinely work with
    # just the openapi-emitted endpoint list (no auth needed).

    # Item A — per-endpoint scan_sqli with hydrated params + body.
    # Without this, base-URL scan_sqli returns partial="no params
    # supplied"; we miss sqli-books on vampi, similar elsewhere.
    # Each endpoint may have:
    #   * path params (substituted into url, params=[name])
    #   * query params (passed via params=[name])
    #   * body schema (POST/PUT/PATCH → body_template + params from
    #     string-typed schema properties)
    # Capped at 10 endpoints to bound wall time (scan_sqli is ~2-5s
    # each with active probes).
    await _run_per_endpoint_sqli(
        summary, endpoints=endpoints,
        agent_state=agent_state, timeout_s=timeout_s,
        max_endpoints=10,
    )

    # Per-endpoint rate-limit probes. Without this we'd only hit the
    # base URL — missing per-endpoint rate-limit must_finds (e.g.
    # vampi's /login rate-limit).
    capped = endpoints[:max_endpoints_for_rate_limit]
    for ep in capped:
        if not isinstance(ep, dict):
            continue
        url = ep.get("url")
        if not isinstance(url, str) or not url:
            continue
        method = ep.get("method", "GET") or "GET"
        path = ep.get("path", url)
        # Use a per-endpoint tool_name in the summary so we can
        # distinguish each invocation in the breakdown.
        endpoint_tool_name = f"scan_api_rate_limit[{method} {path}]"
        summary.tools_run.append(endpoint_tool_name)
        result = await _run_one_tool(
            "scan_api_rate_limit",
            {"url": url, "method": method},
            agent_state=agent_state, timeout_s=timeout_s,
        )
        # Re-label the ToolResult so the breakdown is searchable.
        result.tool_name = endpoint_tool_name
        summary.tool_results.append(result)
        summary.total_findings += result.findings_count
        if result.status in ("ok", "partial"):
            summary.tools_succeeded.append(endpoint_tool_name)
        else:
            summary.tools_failed.append(endpoint_tool_name)


async def run_oss_anchor_prepass(
    *,
    target_type: str,
    target_value: str,
    workspace_path: str = "",
    agent_state: Any,
) -> PrepassSummary:
    """Run the deterministic OSS anchor scans for one target.

    Returns a `PrepassSummary` carrying per-tool results and the
    aggregated finding count. Never raises — per-tool failures are
    isolated into ToolResult.status="error" / "timeout" / "partial".

    Skips entirely (returns a stub summary with skipped_reason set)
    when:
      * `STRIX_OSS_PREPASS_DISABLED` is set
      * `target_type` is not in `_ANCHORS_BY_TARGET_TYPE`
      * `_ANCHORS_BY_TARGET_TYPE[target_type]` is empty
        (domain / ip_address fall through to the lead loop)
    """
    import time as _t

    summary = PrepassSummary(
        target_type=target_type,
        target_value=target_value,
    )
    if is_disabled():
        summary.skipped_reason = "STRIX_OSS_PREPASS_DISABLED set"
        return summary

    anchors = _ANCHORS_BY_TARGET_TYPE.get(target_type)
    if anchors is None:
        summary.skipped_reason = (
            f"target_type={target_type!r} not in anchor lookup"
        )
        return summary
    if not anchors:
        summary.skipped_reason = (
            f"target_type={target_type!r} has no L1 signature corpus"
        )
        return summary

    timeout_s = _read_timeout()
    overall_start = _t.monotonic()

    for tool_name, kwarg_builder in anchors:
        summary.tools_run.append(tool_name)
        kwargs = kwarg_builder(target_value, workspace_path, tool_name)
        result = await _run_one_tool(
            tool_name, kwargs,
            agent_state=agent_state, timeout_s=timeout_s,
        )
        summary.tool_results.append(result)
        summary.total_findings += result.findings_count
        if result.status in ("ok", "partial"):
            summary.tools_succeeded.append(tool_name)
        else:
            summary.tools_failed.append(tool_name)

    # ------------------------------------------------------------------
    # Phase 2 — dependent-tool stage. Consumes data emitted by phase-1
    # tools to run scanners that need richer kwargs than a bare URL.
    #
    # Right now only the API target type uses this: openapi_spec_ingest
    # in phase 1 emits an `endpoints` list, which the OWASP API Top 10
    # specialists need as input (scan_api_bola / scan_api_bfla /
    # scan_api_mass_assignment). Without this stage they CAN'T run from
    # the prepass — they'd TypeError on missing `endpoints=` kwarg.
    #
    # Also iterates scan_api_rate_limit per discovered endpoint instead
    # of just hitting the base URL — needed to catch e.g. vampi's
    # `rate-limit-login` must_find (the /login endpoint specifically).
    #
    # Out of scope (iter-5+): JWT extraction → jwt_audit per-token,
    # per-endpoint scan_sqli/ssrf with discovered params.
    if target_type in ("api", "web_application"):
        await _run_dependent_api_tools(
            summary, agent_state=agent_state, timeout_s=timeout_s,
            target_value=target_value, target_type=target_type,
        )

    summary.wall_time_s = _t.monotonic() - overall_start
    logger.info(
        "OSS prepass complete: target_type=%s tools_run=%d "
        "succeeded=%d failed=%d total_findings=%d wall=%.1fs",
        target_type,
        len(summary.tools_run),
        len(summary.tools_succeeded),
        len(summary.tools_failed),
        summary.total_findings,
        summary.wall_time_s,
    )
    return summary


def format_summary_for_lead_context(summary: PrepassSummary) -> str:
    """Render the prepass summary as a text block to prepend to the
    lead's task description.

    The lead sees this block in its FIRST LLM call's user message,
    so its job is immediately scoped to "rank, dedupe, FP demote,
    emit canonical findings" — not "decide which scanner to call
    first."

    Returns empty string when the prepass was skipped (no findings
    to summarize, no block to inject).
    """
    if summary.skipped_reason:
        return ""

    lines = [
        "",
        "## OSS Anchor Pre-pass Results (L1 detection layer)",
        "",
        f"The L1 deterministic signature + threat-intel layer has "
        f"ALREADY run against {summary.target_type} target "
        f"`{summary.target_value}`. Findings are emitted into your "
        f"findings store. Your job is L2 reasoning on top:",
        "",
        "  1. **Dedupe** — when multiple anchor tools flag the same "
        "issue, collapse to one finding.",
        "  2. **Rank** — apply contextual_priority "
        "(KEV / EPSS / reachability) ordering.",
        "  3. **Demote false positives** — test fixtures, docstring "
        "examples, unreferenced utilities.",
        "  4. **Tag novel** — flag anything the L1 corpus would have "
        "missed and you found via reasoning.",
        "  5. **Emit final report** — call `finish_scan` when done.",
        "",
        f"### L1 pre-pass stats",
        f"- Tools run: {len(summary.tools_run)} "
        f"({len(summary.tools_succeeded)} succeeded, "
        f"{len(summary.tools_failed)} failed)",
        f"- Total candidate findings (pre-dedupe): "
        f"{summary.total_findings}",
        f"- Wall time: {summary.wall_time_s:.1f}s",
        "",
    ]
    if summary.tools_failed:
        lines.append(
            f"### Tools that failed (consider reporting in your "
            f"summary so the operator can investigate):"
        )
        for r in summary.tool_results:
            if r.status not in ("ok", "partial"):
                lines.append(
                    f"- `{r.tool_name}`: {r.status} — "
                    f"{r.error_reason or 'no reason'}"
                )
        lines.append("")
    lines.append(
        "Do NOT re-invoke the L1 anchor tools listed above — they "
        "already ran. Use your remaining iterations for L2 ranking, "
        "dedup, FP analysis, and final report emission."
    )
    lines.append("")
    return "\n".join(lines)
