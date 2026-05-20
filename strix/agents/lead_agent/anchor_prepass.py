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
    """nuclei scans with cve tag + high/critical severity gate."""
    return {
        "url": target_value,
        "tags": ["cve"],
        "severity": ["high", "critical"],
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


async def _run_dependent_api_tools(
    summary: PrepassSummary,
    *,
    agent_state: Any,
    timeout_s: int,
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
    if not isinstance(openapi_result, dict):
        return
    endpoints = openapi_result.get("endpoints")
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
