"""E2E Phase D — per-target Lead-catalog membership.

Per `docs/E2E-test-proposal.md` §3.5. Each test asserts that
`get_lead_tool_catalog(["<target_type>"])` returns a set including the
asset-specific anchor tools PLUS the L1.5-aware core tools added in
iter-26 (`list_pending_findings`, `drain_amplify_queue`,
`execute_adaptive_probe`).

Pure registry inspection — no Tracer, no subprocess, no mocks needed.
"""

from __future__ import annotations

import pytest

from strix.agents.lead_agent.tool_catalog import (
    get_lead_tool_catalog,
    list_target_types,
)


# iter-37.10: this file documents the LEGACY per-target catalog
# shape — including iter-26's L1.5 core (drain_amplify_queue,
# execute_adaptive_probe) which was dropped from minimal core by
# iter-37.8/37.10. The legacy contract is still the one the test
# was written against, so opt into legacy mode for the file.
@pytest.fixture(autouse=True)
def _enable_legacy_catalog(monkeypatch):
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")


# iter-26 added these to _CORE_TOOLS; every target_type catalog must
# include them.
_L15_CORE_TOOLS = {
    "list_pending_findings",
    "drain_amplify_queue",
    "execute_adaptive_probe",
}


def _assert_l15_core(catalog: set[str]) -> None:
    missing = _L15_CORE_TOOLS - catalog
    assert not missing, (
        f"L1.5-aware core tools missing from catalog: {missing}"
    )


# =========================================================================
# E2E-L2-web-1 — web_application catalog
# =========================================================================

def test_web_application_catalog():
    catalog = get_lead_tool_catalog(target_types={"web_application"})
    _assert_l15_core(catalog)
    # Web-anchor recon + active specialists. crawl_with_katana
    # supersedes bfs_crawl; probe_hosts_httpx with -tech-detect
    # supersedes fingerprint_tech_stack (per docs/L2-optimization.md
    # §5.3) — those legacy tools intentionally dropped from the web
    # catalog to keep under the 90-tool prompt-token budget.
    required_web = {
        "crawl_with_katana",
        "probe_hosts_httpx",
        "discover_paths_feroxbuster",
        "scan_xss",
        "scan_sqli",
        "scan_xss_dalfox",
        "scan_sqli_sqlmap",
        "scan_xxe",
        "scan_nuclei_templates",
        "http_security_headers_audit",
        "tls_audit",
        "cors_deep_check",
        "csrf_check",
    }
    missing = required_web - catalog
    assert not missing, (
        f"web_application catalog missing essential tools: {missing}"
    )


# =========================================================================
# E2E-L2-api-1 — api catalog
# =========================================================================

def test_api_catalog():
    catalog = get_lead_tool_catalog(target_types={"api"})
    _assert_l15_core(catalog)
    # API-specific anchors
    required_api = {
        "openapi_spec_ingest",
        "scan_api_bola",
        "scan_api_bfla",
        "scan_api_mass_assignment",
        "scan_api_rate_limit",
        "jwt_audit",
        "scan_sqli",
        "scan_idor",
    }
    missing = required_api - catalog
    assert not missing, (
        f"api catalog missing essential tools: {missing}"
    )


# =========================================================================
# E2E-L2-repo-1 — repository catalog
# =========================================================================

def test_repository_catalog():
    catalog = get_lead_tool_catalog(target_types={"repository"})
    _assert_l15_core(catalog)
    # Repository / local_code anchors
    required_repo = {
        "scan_sast",
        "scan_sca_lockfiles",
        "secrets_scan",
        "scan_iac",
        "sbom_extract",
    }
    missing = required_repo - catalog
    assert not missing, (
        f"repository catalog missing essential tools: {missing}"
    )
    # iter-22.9 §5.4 guardrail — SAST/SCA must NOT leak into the
    # web_application catalog
    web_catalog = get_lead_tool_catalog(target_types={"web_application"})
    leaked = {"scan_sca_lockfiles", "scan_sast"} & web_catalog
    assert not leaked, (
        f"iter-22.9 §5.4 regression: SAST/SCA leaked into web "
        f"catalog: {leaked}"
    )


# =========================================================================
# E2E-L2-host-1 — ip_address catalog
# =========================================================================

def test_ip_address_catalog():
    catalog = get_lead_tool_catalog(target_types={"ip_address"})
    _assert_l15_core(catalog)
    # IP / host anchors — nmap is the primary IP-target tool from
    # iter-23.1; tls_audit_testssl is the TLS auditor; httpx for HTTP
    # ports.
    required_ip = {
        "fingerprint_services_nmap",
        "tls_audit_testssl",
        "probe_hosts_httpx",
    }
    missing = required_ip - catalog
    assert not missing, (
        f"ip_address catalog missing essential tools: {missing}"
    )


# =========================================================================
# E2E-L2-container-1 — container_image catalog
# =========================================================================

def test_container_image_catalog():
    catalog = get_lead_tool_catalog(target_types={"container_image"})
    _assert_l15_core(catalog)
    # Container anchors
    required_container = {
        "scan_container_image",
        "scan_image_dockle",
    }
    missing = required_container - catalog
    assert not missing, (
        f"container_image catalog missing essential tools: {missing}"
    )


# =========================================================================
# E2E-L2-cross-1 — every known target_type gets L1.5 core
# =========================================================================

def test_every_target_type_gets_l15_core_tools():
    """Cross-cutting: every target_type listed by `list_target_types()`
    must include the L1.5-aware core tools. iter-26 wired them via
    _CORE_TOOLS which is unioned with every per-type set in
    `get_lead_tool_catalog`. This test guards against a future
    refactor that accidentally drops _CORE_TOOLS from a specific
    target_type."""
    for tt in list_target_types():
        catalog = get_lead_tool_catalog(target_types={tt})
        missing = _L15_CORE_TOOLS - catalog
        assert not missing, (
            f"target_type {tt!r} missing L1.5 core: {missing}"
        )


# =========================================================================
# F.2 — domain target_type catalog
# =========================================================================

def test_domain_catalog():
    """The `domain` target_type appears in _TOOLS_BY_TARGET_TYPE but
    was never asserted by the Phase D tests. Domain-recon scans
    pivot on subdomain enumeration + DNS hygiene + cloud-asset
    discovery — those tools must all be in the catalog OR a
    domain-target scan has nothing to dispatch."""
    catalog = get_lead_tool_catalog(target_types={"domain"})
    _assert_l15_core(catalog)
    required_domain = {
        "subdomain_enum_tool",
        "dns_hygiene_check",
        "discover_cloud_assets",
        "subdomain_takeover_check",
        "mail_recon",
    }
    missing = required_domain - catalog
    assert not missing, (
        f"domain catalog missing essential tools: {missing}"
    )


# =========================================================================
# F.1 — meta-invariant: every registered sandbox-execution tool is
#       reachable from some target_type catalog (or in _CORE_TOOLS)
# =========================================================================

# Tools that are deliberately framework-only (NOT invoked by the
# Lead's `dispatch_specialist` call chain). Every entry is a
# justified exclusion. Adding to this list should require a comment.
_FRAMEWORK_ONLY_TOOLS = frozenset({
    # ─── Cron / scheduled-job-driven ruleset updaters ────────────────
    "update_gitleaks_rules",
    "update_wappalyzer_signatures",
    "update_hadolint_config",
    "nuclei_template_update",

    # ─── Composite / legacy recon (iter-25.11 / iter-26.12) ──────────
    # Kept registered so anchor_prepass can invoke directly, but
    # superseded for Lead use by the discrete trio (katana / httpx /
    # nmap).
    "webapp_recon_pipeline",
    "bfs_crawl",
    "fingerprint_tech_stack",

    # ─── Patcher-specialist-only ─────────────────────────────────────
    # The patcher profile (specialist_orchestrator.py) lists these in
    # its allowed_tool_subset; the Lead never calls them directly.
    "propose_patch", "mark_patch_applied", "auto_verify_patch",
    "verify_patch", "list_patches", "verification_status",
    "register_finding_for_verification",
    "record_verification_evidence", "advance_verification_stage",
    "str_replace_editor",

    # ─── Sub-agent / specialist runtime helpers ──────────────────────
    # Used by the inner specialist loop, not by the Lead's catalog
    # dispatch.
    "create_objective", "list_objectives", "get_objective",
    "add_child_objective", "update_objective",
    "create_todo", "list_todos", "update_todo", "delete_todo",
    "mark_todo_done", "mark_todo_pending",
    "list_hypotheses",     # Lead uses list_active_hypotheses instead
    "list_reflections", "reflect", "record_phase",
    "python_action",
    "agent_finish", "task_cancel", "task_status", "fire_async",
    "load_skill",
    "scope_rules",
    "list_files", "search_files",

    # ─── Request / sitemap inspection (sub-agent only) ───────────────
    "view_request", "list_requests", "repeat_request",
    "view_sitemap_entry", "list_sitemap",

    # ─── KG mutation primitives (Lead has kg_query_* read API) ───────
    "kg_create_node", "kg_create_edge", "kg_stats",

    # ─── Already blocked at catalog construction time ────────────────
    "create_agent", "spawn_webapp_specialist_team",
    "spawn_code_specialist_team", "spawn_webapp_subteam",

    # ─── Mobile asset support dropped in iter-21.5 ───────────────────
    "scan_mobile_app",

    # ─── iter-35.2 — anchor-prepass probes routed through sandbox ────
    # Registered with sandbox_execution=True so the prepass orchestrator
    # can dispatch them via the sandbox tool_server (host-side urllib /
    # socket / ftplib calls were a CLAUDE.md §3.6 violation). They're
    # framework-only — invoked by the deterministic prepass, never by
    # the LLM Lead.
    "probe_openapi_spec_exposed",
    "probe_jwt_none_alg",
    "probe_mass_assignment_priv_fields",
    "probe_unauth_debug_paths",
    "probe_open_redirect",
    "probe_unauth_bola_path_params",
    "probe_directory_listing",
    "probe_open_tcp_ports",
    "probe_redis_no_auth",
    "probe_http_port",
    "probe_ftp_anonymous",

    # ─── Renamed/aliased duplicates (registered under both old + new
    #     name during a refactor). The canonical name is in the
    #     catalog; the alias stays registered for back-compat.
    "subdomain_enum",          # canonical: subdomain_enum_tool
    "reverse_ip_discovery",    # canonical: reverse_ip
    "saas_leak_discovery",     # canonical: saas_leaks
    "debug_endpoint_check",    # canonical: probe_unauth_debug_paths
    "cache_deception_check",   # canonical: scan_cache_deception
    "race_condition_check",    # canonical: scan_race_condition
    "file_upload_abuse_check", # canonical: scan_file_upload
    "code_search_for_domain",  # internal helper
    "mx_fingerprint",          # rolled into mail_recon
})


def test_every_registered_tool_reachable_from_some_catalog():
    """Meta-invariant: any tool with @register_tool(sandbox_execution=
    True/False) must be reachable from at least one Lead catalog
    union — either via _CORE_TOOLS or one of the per-target-type
    sets in _TOOLS_BY_TARGET_TYPE — OR it must be in
    _FRAMEWORK_ONLY_TOOLS (the explicit private-helper allowlist).

    This is THE test that would have caught Phase D's 9 catalog gaps
    proactively. Without it, the next analogous bug (new tool
    registered, forgot to wire it into the catalog) slips past
    review just like iter-22.1's crawl_with_katana did for ~6 months.
    """
    import strix.tools  # noqa: F401 — trigger all tool registrations
    from strix.agents.lead_agent.tool_catalog import (
        _BLOCKED_TOOLS,
        _CORE_TOOLS,
        _TOOLS_BY_TARGET_TYPE,
        _ORCHESTRATOR_ALLOWED_TOOLS,
    )
    from strix.tools.registry import get_tool_names

    # Union of every catalog the Lead could ever see
    reachable: set[str] = set(_CORE_TOOLS) | set(
        _ORCHESTRATOR_ALLOWED_TOOLS,
    )
    for tools_for_type in _TOOLS_BY_TARGET_TYPE.values():
        reachable |= set(tools_for_type)

    # Tools that exist in the registry but never reach any catalog
    registered = set(get_tool_names())
    unreachable = (
        registered
        - reachable
        - _FRAMEWORK_ONLY_TOOLS
        - _BLOCKED_TOOLS
    )

    assert not unreachable, (
        f"\n\n  These tools are @register_tool-decorated but UNREACHABLE\n"
        f"  from any Lead catalog. The LLM has no way to call them.\n"
        f"  Either:\n"
        f"    1. Add them to the appropriate target_type catalog in\n"
        f"       strix/agents/lead_agent/tool_catalog.py, OR\n"
        f"    2. Add them to _FRAMEWORK_ONLY_TOOLS in this test file\n"
        f"       with a comment explaining why they're framework-only.\n\n"
        f"  Unreachable tools ({len(unreachable)}):\n"
        f"    " + "\n    ".join(sorted(unreachable))
    )
