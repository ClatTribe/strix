"""`probe_endpoint` — composite specialist fan-out tool (Phase 3d / PR-β).

The Phase 3d architecture decomposition split the lead's per-turn
cognitive load into two parts:

  1. **Workflow navigation** (PR-α): "what phase am I in, what's
     next?" Solved by `workflow_status` / `advance_workflow_phase` +
     phase-filtered tool catalog.

  2. **Specialist selection** (this PR): "which specialists should
     I run on THIS endpoint?" Empirically the lead under-dispatches
     specialists when faced with the per-endpoint decision; the 13%
     testfire run showed 60+ `browser_action` calls but only ~5
     specialist invocations.

`probe_endpoint(endpoint_url, kind)` is the composite the lead
calls instead of picking 4-6 specialists individually. It:

  * Classifies the endpoint shape (`form` / `api` / `search` /
    `auth` / `files` / `id_in_path` / `state_changing`) if `kind`
    isn't supplied.
  * Dispatches the matching specialists internally (via the
    standard registered-tool registry — Phase 3b's adaptive-retry
    orchestrator still engages per-specialist when first-pass
    returns 0 findings).
  * Aggregates findings + evidence into one `SpecialistResult`.
  * Records the endpoint as probed in workflow state so
    `workflow_status()` reflects coverage progress.

The lead's per-turn decision goes from "pick 6 tools" to "pick the
right kind." A tactical decision Flash handles well, vs a
multi-step protocol it doesn't.

## What's intentionally NOT in v0

* Parallel dispatch — specialists run sequentially. v1 could
  parallelise with asyncio when specialists are async-capable;
  for now sequential keeps state-tracking + telemetry simple.
* Per-specialist budget caps — uses each specialist's existing
  default_budget. The run-level `--max-cost` / `--max-duration`
  caps wrap everything.
* Auto-inference of "post-auth required" — IDOR is only included
  for `id_in_path` when `workflow.auth_state_captured = True`.
  Other auth-required probes (multi_role_auth) are routed through
  the workflow's auth phase, not here.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool
from strix.tools.specialist.result import SpecialistResult


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Endpoint-shape → specialist mapping
# ---------------------------------------------------------------------------


# Canonical endpoint kinds. Anything else passed by the lead is
# normalised to `form` (the most generic fan-out) with a warning.
_KINDS: tuple[str, ...] = (
    "form",
    "search",
    "auth",
    "api",
    "files",
    "id_in_path",
    "state_changing",
)


# Per-kind specialist dispatch table. Each value is an ordered
# list of specialist tool names. The first 2-3 are the canonical
# fan-out for that shape; later entries are secondary.
#
# `id_in_path` includes `scan_idor` only if auth is captured —
# that's enforced at dispatch time (see _dispatch_for_kind).
_DISPATCH: dict[str, list[str]] = {
    "form":            ["scan_sqli", "scan_xss", "open_redirect_check"],
    "search":          ["scan_sqli", "scan_xss", "scan_xpath_injection",
                        "scan_ldap_injection"],
    "auth":            ["scan_auth_flow", "cookie_jwt_scoping_check",
                        "jwt_audit"],
    "api":             ["scan_sqli", "scan_nosql_injection", "scan_xss"],
    "files":           ["scan_path_traversal", "scan_secrets_in_response"],
    "id_in_path":      ["scan_idor", "scan_path_traversal"],
    "state_changing":  ["csrf_check", "scan_sqli", "scan_xss"],
}


# Heuristic regexes for kind classification from URL.
_AUTH_PATH_TOKENS = (
    "login", "signin", "log-in", "sign-in", "authenticate",
    "session", "auth/token", "oauth", "reset", "register",
    "signup", "sign-up",
)
_SEARCH_QUERY_KEYS = (
    "q", "query", "search", "s", "filter", "sort", "order_by",
    "orderby", "term", "keyword",
)
_FILE_PATH_TOKENS = (
    "download", "upload", "file", "image", "img", "media",
    "attachment", "doc", "static", "assets",
)
_API_PATH_TOKENS = ("api/", "/v1/", "/v2/", "/v3/", "rest/", "graphql")
# Compiled lazily.
_ID_IN_PATH_RE = None


def _id_re():  # noqa: ANN202
    global _ID_IN_PATH_RE
    if _ID_IN_PATH_RE is None:
        import re
        _ID_IN_PATH_RE = re.compile(
            r"/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}|[a-z0-9]{20,})/?",
            re.IGNORECASE,
        )
    return _ID_IN_PATH_RE


def _classify_endpoint(url: str) -> str:
    """Best-effort endpoint-kind classification from URL alone.
    Returns one of the canonical `_KINDS`. When the URL doesn't
    match a more-specific kind, returns `form` as the most
    general fan-out."""
    parsed = urlparse(url)
    path = (parsed.path or "").lower()
    query_keys = {
        kv.split("=", 1)[0].lower()
        for kv in (parsed.query or "").split("&") if kv
    }

    # Auth surface wins — login forms shouldn't be probed for
    # SQLi via `form`; the right tool is scan_auth_flow.
    if any(tok in path for tok in _AUTH_PATH_TOKENS):
        return "auth"

    # File-shaped endpoints.
    if any(tok in path for tok in _FILE_PATH_TOKENS):
        return "files"

    # ID in path → IDOR + path-traversal.
    if _id_re().search(path or ""):
        return "id_in_path"

    # API shape — JSON-ish.
    if any(tok in path for tok in _API_PATH_TOKENS):
        return "api"

    # Search / filter shapes via query keys.
    if query_keys & set(_SEARCH_QUERY_KEYS):
        return "search"

    # Default — generic form / query-string endpoint.
    return "form"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def _dispatch_for_kind(kind: str, *, auth_captured: bool) -> list[str]:
    """Return the ordered specialist list for `kind`, filtered
    where auth is required. scan_idor needs a captured auth state
    to do cross-session diff — skip it when auth isn't available
    (the workflow's auth phase is the right place to capture it)."""
    specialists = list(_DISPATCH.get(kind, _DISPATCH["form"]))
    if not auth_captured and "scan_idor" in specialists:
        specialists.remove("scan_idor")
    return specialists


def _invoke_specialist(
    name: str, **kwargs: Any,
) -> dict[str, Any] | None:
    """Look up `name` in the strix tool registry and call it with
    `kwargs`. Returns the specialist's coerced result dict (or None
    if the tool isn't registered / call raised)."""
    from strix.tools.registry import get_tool_by_name

    fn = get_tool_by_name(name)
    if fn is None:
        return None
    try:
        return fn(**kwargs)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "probe_endpoint: %s failed: %s", name, e, exc_info=True,
        )
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "findings": [],
            "evidence": [],
        }


def _aggregate(
    results: list[tuple[str, dict[str, Any] | None]],
) -> dict[str, Any]:
    """Combine N specialist results into one SpecialistResult-
    shaped dict. Findings accumulate; evidence lines get prefixed
    with the originating tool name; tool_metadata becomes a
    keyed-by-tool sub-dict."""
    findings: list[Any] = []
    evidence: list[str] = []
    next_probes: list[str] = []
    tool_meta: dict[str, Any] = {}
    statuses: list[str] = []

    for tool_name, r in results:
        if not isinstance(r, dict):
            continue
        statuses.append(str(r.get("status", "unknown")))
        for f in r.get("findings") or []:
            findings.append(f)
        for line in r.get("evidence") or []:
            evidence.append(f"[{tool_name}] {line}")
        for line in r.get("next_probes_suggested") or []:
            next_probes.append(f"[{tool_name}] {line}")
        meta = r.get("tool_metadata")
        if isinstance(meta, dict):
            tool_meta[tool_name] = meta

    # Overall status: 'error' if ALL underlying tools errored,
    # 'partial' if any errored but at least one succeeded, else 'ok'.
    if not statuses:
        overall = "error"
    elif all(s == "error" for s in statuses):
        overall = "error"
    elif any(s == "error" for s in statuses):
        overall = "partial"
    elif any(s == "ok" for s in statuses):
        overall = "ok"
    else:
        overall = statuses[0]

    return SpecialistResult(
        status=overall,                       # type: ignore[arg-type]
        findings=findings,
        evidence=evidence[:30],               # cap to keep payload bounded
        next_probes_suggested=next_probes[:10],
        tool_metadata={
            "composite": "probe_endpoint",
            "specialists_dispatched": [name for name, _ in results],
            "specialists_succeeded": [
                name for name, r in results
                if isinstance(r, dict) and r.get("status") in ("ok", "partial")
            ],
            "per_specialist": tool_meta,
            "findings_total": len(findings),
        },
    ).model_dump()


# ---------------------------------------------------------------------------
# Tool entry point
# ---------------------------------------------------------------------------


@register_tool(sandbox_execution=False, mitre_techniques=["T1190"])
def probe_endpoint(
    endpoint_url: str,
    kind: str | None = None,
    params: list[str] | None = None,
    method: str = "GET",
    body_template: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Composite probe: dispatch the standard specialist fan-out for
    a single endpoint, aggregating findings + evidence into one
    response.

    Args:
        endpoint_url: full URL to probe (e.g.
            `https://example.com/api/users/42?q=test`).
        kind: one of `form` / `search` / `auth` / `api` / `files` /
            `id_in_path` / `state_changing`. When None / unknown,
            inferred from the URL via heuristic classification.
            Passing an explicit kind is preferred when you know the
            endpoint shape — the lead's "I see a login form" judgment
            is more accurate than a URL-pattern classifier.
        params: parameter names to probe. Passed through to each
            specialist that accepts a `params=` arg. When None, each
            specialist's own param-inference applies.
        method: HTTP method. Passed through where applicable
            (scan_sqli, scan_xss, etc. accept method= today).
        body_template: optional baseline body. Passed through.
        extra_headers: optional headers (e.g. auth). Passed through.

    Returns:
        A `SpecialistResult` dict with aggregated findings + evidence.
        `tool_metadata.composite = "probe_endpoint"`,
        `tool_metadata.specialists_dispatched`,
        `tool_metadata.per_specialist[tool_name] = {...}` for per-tool
        traceability.

    Use this in the probe phase instead of picking 4-6 specialists
    one-by-one. Reduces the lead's per-turn decisions from
    "which-tool" to "which-kind"; the kind → tools mapping lives in
    code, not in your reasoning.
    """
    if not isinstance(endpoint_url, str) or not endpoint_url.strip():
        return SpecialistResult(
            status="error", error="endpoint_url required",
        ).model_dump()
    endpoint_url = endpoint_url.strip()

    # Normalise kind.
    requested = (kind or "").strip().lower()
    if requested in _KINDS:
        chosen_kind = requested
        kind_source = "explicit"
    else:
        chosen_kind = _classify_endpoint(endpoint_url)
        kind_source = "inferred"
        if requested and requested not in _KINDS:
            logger.debug(
                "probe_endpoint: unknown kind %r, inferred %r from URL",
                kind, chosen_kind,
            )

    # Check workflow state for auth-captured (gates IDOR dispatch).
    auth_captured = False
    try:
        from strix.agents.workflow_state import snapshot
        auth_captured = bool(snapshot().get("auth_state_captured"))
    except Exception:  # noqa: BLE001
        pass

    specialists = _dispatch_for_kind(chosen_kind, auth_captured=auth_captured)
    if not specialists:
        return SpecialistResult(
            status="error",
            error=f"no specialists dispatch for kind {chosen_kind!r}",
            tool_metadata={
                "composite": "probe_endpoint",
                "kind": chosen_kind,
                "kind_source": kind_source,
            },
        ).model_dump()

    # Build the common kwargs per specialist call. Each specialist
    # has slightly different arg names — we pass the union via
    # **kwargs and rely on the tool's signature to ignore unknown.
    # (Actually most specialists use keyword-only args + reject
    # unknown kwargs — so we need to be precise. Strategy: pass
    # only the args every specialist supports universally as the
    # common set; the specialist's `_request_builders` handles the
    # rest.)
    common_call_kwargs_base: dict[str, Any] = {
        "url": endpoint_url,
    }
    if params is not None:
        common_call_kwargs_base["params"] = params
    if method and method.upper() != "GET":
        common_call_kwargs_base["method"] = method
    if body_template is not None:
        common_call_kwargs_base["body_template"] = body_template
    if extra_headers is not None:
        common_call_kwargs_base["extra_headers"] = extra_headers

    # Dispatch — sequential, each specialist gets the common args
    # filtered to its accepted signature.
    results: list[tuple[str, dict[str, Any] | None]] = []
    for name in specialists:
        call_kwargs = _filter_kwargs_for_tool(name, common_call_kwargs_base)
        results.append((name, _invoke_specialist(name, **call_kwargs)))

    # Record progress in workflow state.
    try:
        from strix.agents.workflow_state import record_endpoint_probed
        record_endpoint_probed(endpoint_url)
    except Exception:  # noqa: BLE001
        pass

    out = _aggregate(results)
    # Annotate with the kind decision so the lead can see what
    # got dispatched and why.
    out.setdefault("tool_metadata", {}).update({
        "endpoint_url": endpoint_url,
        "kind": chosen_kind,
        "kind_source": kind_source,
        "auth_captured": auth_captured,
    })
    return out


def _filter_kwargs_for_tool(
    tool_name: str, candidate: dict[str, Any],
) -> dict[str, Any]:
    """Each specialist takes different args. We inspect the
    underlying function signature and pass only the keys it
    accepts — never crashes a specialist by passing an unexpected
    kwarg."""
    import inspect

    from strix.tools.registry import get_tool_by_name

    fn = get_tool_by_name(tool_name)
    if fn is None:
        return {}
    # The registered tool is decorator-wrapped. Walk __wrapped__
    # to find the underlying signature.
    inner = getattr(fn, "__wrapped__", fn)
    try:
        sig = inspect.signature(inner)
    except (ValueError, TypeError):
        return {}
    accepted = set(sig.parameters.keys())
    # Some tools accept **kwargs — in that case we pass everything.
    has_var_kwarg = any(
        p.kind == inspect.Parameter.VAR_KEYWORD
        for p in sig.parameters.values()
    )
    if has_var_kwarg:
        return dict(candidate)
    return {k: v for k, v in candidate.items() if k in accepted}
