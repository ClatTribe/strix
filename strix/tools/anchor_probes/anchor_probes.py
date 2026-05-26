"""iter-35.2 — sandbox-side registrations for the 11 anchor probes.

Each wrapper:
  * Lazy-imports the actual probe function from
    `strix/agents/lead_agent/anchor_prepass.py` to avoid circular
    imports at module-load time.
  * Calls the implementation (which uses urllib / sockets / ftplib)
    INSIDE the sandbox container's network namespace when dispatched
    via `execute_tool(..., agent_state=...)`.
  * Wraps the `list[dict]` return into a dict shape:
        {"findings": list[dict], "ok": True, "status": "ok"}
    so `_count_findings` in anchor_prepass picks up the findings via
    the canonical "result.findings" path.
  * Marks itself with `provenance="framework"` since these probes
    are L1 framework instrumentation, not OSS-anchored detection.

The wrapper names match the host-side function names. Python's module
system keeps them distinct — the host-side names live in
`strix.agents.lead_agent.anchor_prepass`; the registered tool names
live here. The tool-registry dispatch goes by tool name (string),
not by Python function identity.
"""

from __future__ import annotations

from typing import Any

from strix.tools.registry import register_tool


def _wrap(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap the raw list[dict] return into the canonical
    SpecialistResult-shaped dict so `_count_findings` picks it up."""
    return {
        "findings": findings or [],
        "ok": True,
        "status": "ok",
    }


# ---------------------------------------------------------------------------
# Web / API probes (URL- + endpoint-driven)
# ---------------------------------------------------------------------------


@register_tool(sandbox_execution=True, provenance="framework")
def probe_openapi_spec_exposed(
    *, target_url: str, spec_url: str | None,
) -> dict[str, Any]:
    """iter-35.2 — sandbox wrapper for the openapi-spec-exposure
    probe. Implementation: `anchor_prepass.probe_openapi_spec_exposed`.
    """
    from strix.agents.lead_agent import anchor_prepass as _ap
    return _wrap(_ap.probe_openapi_spec_exposed(
        target_url=target_url, spec_url=spec_url,
    ))


@register_tool(sandbox_execution=True, provenance="framework")
def probe_jwt_none_alg(
    *, endpoints: list[dict[str, Any]], max_endpoints: int = 20,
) -> dict[str, Any]:
    """iter-35.2 — sandbox wrapper for the JWT alg=none forge probe."""
    from strix.agents.lead_agent import anchor_prepass as _ap
    return _wrap(_ap.probe_jwt_none_alg(
        endpoints=endpoints, max_endpoints=max_endpoints,
    ))


@register_tool(sandbox_execution=True, provenance="framework")
def probe_mass_assignment_priv_fields(
    *, endpoints: list[dict[str, Any]], max_endpoints: int = 10,
) -> dict[str, Any]:
    """iter-35.2 — sandbox wrapper for the mass-assignment priv-field
    probe."""
    from strix.agents.lead_agent import anchor_prepass as _ap
    return _wrap(_ap.probe_mass_assignment_priv_fields(
        endpoints=endpoints, max_endpoints=max_endpoints,
    ))


@register_tool(sandbox_execution=True, provenance="framework")
def probe_unauth_debug_paths(
    *, target_url: str, endpoints: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """iter-35.2 — sandbox wrapper for the unauth debug-path probe."""
    from strix.agents.lead_agent import anchor_prepass as _ap
    return _wrap(_ap.probe_unauth_debug_paths(
        target_url=target_url, endpoints=endpoints,
    ))


@register_tool(sandbox_execution=True, provenance="framework")
def probe_open_redirect(
    *, target_url: str, endpoints: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """iter-35.2 — sandbox wrapper for the open-redirect probe."""
    from strix.agents.lead_agent import anchor_prepass as _ap
    return _wrap(_ap.probe_open_redirect(
        target_url=target_url, endpoints=endpoints,
    ))


@register_tool(sandbox_execution=True, provenance="framework")
def probe_unauth_bola_path_params(
    *, endpoints: list[dict[str, Any]],
) -> dict[str, Any]:
    """iter-35.2 — sandbox wrapper for the unauth BOLA path-param
    probe."""
    from strix.agents.lead_agent import anchor_prepass as _ap
    return _wrap(_ap.probe_unauth_bola_path_params(endpoints=endpoints))


@register_tool(sandbox_execution=True, provenance="framework")
def probe_directory_listing(
    *, target_url: str,
) -> dict[str, Any]:
    """iter-35.2 — sandbox wrapper for the directory-listing probe."""
    from strix.agents.lead_agent import anchor_prepass as _ap
    return _wrap(_ap.probe_directory_listing(target_url=target_url))


# ---------------------------------------------------------------------------
# IP / network probes (raw socket / ftplib)
# ---------------------------------------------------------------------------


@register_tool(sandbox_execution=True, provenance="framework")
def probe_open_tcp_ports(
    target_value: str,
) -> dict[str, Any]:
    """iter-35.2 — sandbox wrapper for the open-TCP-port discovery
    probe. NOTE: the host-side impl returns `list[int]` rather than
    `list[dict]`. We pass it through as `open_ports` so the
    orchestrator can read both shapes off the result dict."""
    from strix.agents.lead_agent import anchor_prepass as _ap
    open_ports = _ap.probe_open_tcp_ports(target_value)
    return {
        "findings": [],
        "open_ports": list(open_ports or []),
        "ok": True,
        "status": "ok",
    }


@register_tool(sandbox_execution=True, provenance="framework")
def probe_redis_no_auth(
    target_value: str, *, port: int = 6379,
) -> dict[str, Any]:
    """iter-35.2 — sandbox wrapper for the Redis no-auth probe."""
    from strix.agents.lead_agent import anchor_prepass as _ap
    return _wrap(_ap.probe_redis_no_auth(target_value, port=port))


@register_tool(sandbox_execution=True, provenance="framework")
def probe_http_port(
    host: str, port: int, *, scheme: str = "http",
) -> dict[str, Any]:
    """iter-35.2 — sandbox wrapper for the HTTP-port banner probe."""
    from strix.agents.lead_agent import anchor_prepass as _ap
    return _wrap(_ap.probe_http_port(host, port, scheme=scheme))


@register_tool(sandbox_execution=True, provenance="framework")
def probe_ftp_anonymous(
    target_value: str, *, port: int = 21,
) -> dict[str, Any]:
    """iter-35.2 — sandbox wrapper for the FTP anonymous-login probe."""
    from strix.agents.lead_agent import anchor_prepass as _ap
    return _wrap(_ap.probe_ftp_anonymous(target_value, port=port))
