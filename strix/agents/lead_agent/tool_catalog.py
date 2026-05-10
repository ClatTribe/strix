"""Per-target-type tool-catalog filtering (roadmap §8.5 Phase 3 / B.9).

Today every agent's tool catalog includes ~130 tool schemas (~100K
tokens). Under the single-lead architecture the lead agent's catalog
is filtered by target type at scan start: a `web_application` target
sees web-shaped tools + browser primitives + HTTP primitives; a
`repository` target sees code-shaped tools + AST primitives; etc.

~30-50 tools per catalog instead of 130. Saves 60-70K prompt tokens
per LLM call (compounds across the whole run). Plus a
`request_tool(category)` escape hatch for the lead to load a
specialist-tool schema mid-run when recon discovers an unexpected
target shape.

**`create_agent` is deliberately EXCLUDED from every catalog under
the single-lead architecture.** The lead does not spawn sub-agents —
that's the architectural commitment. Removing the tool from the
catalog is the simplest enforcement.

Wrapper-side impact: zero — the wrapper sees the same
`tool.execution.*` events. Whether the lead's catalog had 30 tools
or 130 isn't visible externally.
"""

from __future__ import annotations

from typing import Any, Iterable


# Always-on tools — every target type sees these.
_CORE_TOOLS: frozenset[str] = frozenset({
    # Coordination + planning
    "open_hypothesis", "confirm_hypothesis", "dismiss_hypothesis",
    "list_active_hypotheses", "is_surface_under_investigation",
    "agent_self_audit",
    # Findings
    "create_vulnerability_report", "update_finding", "dismiss_finding",
    "check_budget",
    # Threat intel — always-on (read-only, framework provenance)
    "cve_lookup", "nvd_lookup",
    # Local threat-intel cache (CISA KEV + FIRST EPSS + NVD recent).
    # Always-on so any specialist that fingerprints a tech stack can
    # pivot to "what known CVEs apply?".
    "lookup_known_cves", "lookup_cve_by_id",
    "list_actively_exploited_cves", "threat_intel_status",
    # Reasoning
    "think",
    # Termination
    "finish_scan",
    # Notes / scratchpad
    "create_note", "list_notes", "get_note", "update_note", "delete_note",
})


# Per-target-type tool sets. Union with `_CORE_TOOLS` at lookup time.
_TOOLS_BY_TARGET_TYPE: dict[str, frozenset[str]] = {
    "web_application": frozenset({
        # Specialist-tools — phase 3b/3a
        "scan_misconfig",
        "scan_xss",  # Phase 3b — deterministic reflected-XSS specialist
        "scan_sqli",  # Phase 3b — deterministic SQLi specialist
        "scan_xxe",  # Phase 6 — deterministic XXE specialist
        "scan_blind_ssrf",  # Phase 4.5 — OOB-first blind SSRF (CWE-918)
        "scan_deserialization",  # Phase 4.4 — stack-aware deserialization (CWE-502 / A08:2021)
        "scan_blind_cmd_injection",  # Phase 4.3 — OOB-DNS blind cmd injection (CWE-78)
        "scan_oob_xxe",  # Phase 4.2 — blind XXE via OOB-DNS (CWE-611)
        "scan_auth_flow",  # Phase 6 — default-creds + session capture
        "scan_business_logic",  # Phase 5.6 — workflow / business-rule abuse (A04:2021)
        "scan_idor",  # Phase 4.1 — cross-session IDOR (CWE-639/862)
        "scan_multi_role_auth",  # Phase 3.1 — multi-role authz orchestrator (IDOR precondition)
        "scan_oauth",  # Phase 2.11 — OAuth 2.0 / OIDC misconfiguration (CWE-352/602/601/922)
        "scan_request_smuggling_active",  # Phase 2.10 — timing-based smuggle confirmation (CWE-444)
        "scan_ldap_injection",  # Phase 2.8 — LDAP filter injection (CWE-90)
        "scan_xpath_injection",  # Phase 2.7 — XPath injection (CWE-643)
        "scan_cmd_injection",  # Phase 2.6 — in-band OS command injection (CWE-78)
        "scan_secrets_in_response",  # Phase 2.5 — passive credential exposure (CWE-798/200)
        "scan_nosql_injection",  # Phase 2.4 — MongoDB / Mongoose NoSQLi (CWE-943)
        "scan_ssti",  # Phase 2.3 — server-side template injection (CWE-1336)
        "scan_path_traversal",  # Phase 2.2 — CWE-22 file-traversal specialist
        "scan_ssrf",  # Phase 2.1 — deterministic SSRF specialist (A10:2021)
        # Community-corpus runner (nuclei-templates, ~9k probes,
        # daily-updated). Single-tool fan-out across CVE / exposed-
        # panel / default-cred / misconfig templates.
        "scan_nuclei_templates",
        # Phase 6 — SCA / dependency CVE detection. Useful for web-app
        # targets when the repo is co-located with the deployed URL
        # (typical vibe-coded SaaS workflow).
        "scan_sca_lockfiles",
        # Phase 7 — SAST. Same co-location rationale as scan_sca_lockfiles:
        # web-app target with a checked-in repo means we can flag
        # source-level bugs that DAST might miss.
        "scan_sast",
        # Phase 11 — IaC / cloud posture. Vercel / Netlify /
        # Cloudflare / Docker configs land in the repo for vibe-
        # coded SaaS; SAST rules don't cover them. Cross-asset:
        # IaC misconfigs (CORS-credentials, open redirects)
        # become DAST hypotheses for the deployed URL.
        "scan_iac",
        # Recon
        "fingerprint_tech_stack", "bfs_crawl",
        "well_known_harvest", "webapp_recon_pipeline",
        # HTTP / browser primitives
        "send_request", "browser_action", "extract_dom",
        # HAR / Burp ingestion (#141)
        "ingest_har_file", "ingest_burp_file",
        # Replay-with-mutation orchestrator — Phase 5.5
        "replay_mutation_on_endpoints",
        "replay_mutation_from_har_file",
        "replay_mutation_from_burp_file",
        # Web-app deterministic checks
        "http_security_headers_audit", "tls_audit",
        "csrf_check", "cors_deep_check", "session_entropy_check",
        "jwt_audit", "open_redirect_check", "request_smuggling_check",
        "race_check", "sqli_check", "graphql_specialist_check",
        "websocket_audit", "authz_matrix_check", "dom_xss_static_probe",
        "source_maps", "cookie_jwt_scoping_check",
        # Threat-intel for web targets
        "vt_reputation", "greynoise_classify",
    }),
    "repository": frozenset({
        # Specialist-tools
        "scan_misconfig",
        # Code-target specialists
        "build_code_map", "taint_analysis", "score_reachability",
        "secrets_scan", "sbom_extract",
        # Phase 6 — SCA / supply-chain (npm/pypi/cargo/ruby/composer/go)
        # backed by threat-intel cache (KEV / EPSS / NVD / GHSA).
        "scan_sca_lockfiles",
        # Phase 7 — semgrep-driven SAST with vibe-coded rule pack +
        # OWASP-Top-Ten registry pack. Severity-calibrated against
        # code_map routes + test-file demote.
        "scan_sast",
        # Phase 11 — IaC / cloud posture (vercel.json / netlify.toml
        # / wrangler.toml / Dockerfile / docker-compose.yml).
        "scan_iac",
        # File primitives
        "terminal_execute",
        # Threat-intel for code targets
        "lookup_known_cves", "lookup_cve_by_id",
    }),
    "local_code": frozenset({
        "scan_misconfig",
        "build_code_map", "taint_analysis", "score_reachability",
        "secrets_scan", "sbom_extract",
        "scan_sca_lockfiles",  # Phase 6 — SCA
        "scan_sast",            # Phase 7 — SAST
        "scan_iac",             # Phase 11 — IaC
        "terminal_execute",
        "lookup_known_cves", "lookup_cve_by_id",
    }),
    "domain": frozenset({
        "scan_misconfig",
        # Domain recon (§7.3)
        "domain_recon_pipeline", "subdomain_enum_tool", "dns_hygiene_check",
        "passive_dns_history", "org_fingerprint", "discover_cloud_assets",
        "subdomain_takeover_check", "reverse_ip", "mail_recon",
        "saas_leaks", "well_known_harvest",
        "scan_subdomain_takeover_active",  # Phase 2.9 — active CNAME takeover (CWE-1390)
        # HTTP primitives for spotting web-app on domain targets
        "send_request",
        # Threat-intel
        "vt_reputation", "greynoise_classify", "domain_rep",
    }),
    "ip_address": frozenset({
        "scan_misconfig",
        # IP / network
        "send_request", "terminal_execute",
        "tls_audit", "websocket_audit",
        # Threat-intel
        "vt_reputation", "greynoise_classify",
    }),
}


# Tools that the lead must NEVER see, regardless of target type.
# `create_agent` is the architectural commitment: the lead does NOT
# spawn sub-agents. Removing from the catalog is the simplest gate.
_BLOCKED_TOOLS: frozenset[str] = frozenset({
    "create_agent",
    "spawn_webapp_specialist_team",
    "spawn_code_specialist_team",
    "spawn_webapp_subteam",
    "wait_for_message",  # the lead has no children to wait for
    "send_message_to_agent",
    "stop_agent",
    "view_agent_graph",
})


def get_lead_tool_catalog(
    *,
    target_types: Iterable[str],
) -> set[str]:
    """Return the union of allowed tool names for the given target
    types, intersected with the always-on core, minus the blocked
    set.

    Args:
        target_types: target-type strings (e.g. ['web_application',
            'repository']). When the run targets multiple types, the
            catalog is the union — the lead sees every tool needed
            for any of them.

    Returns:
        A set of tool names. Tools NOT in this set should be omitted
        from the lead's prompt. The actual prompt rendering is
        owned by the LLM layer; this helper is the policy.
    """
    allowed: set[str] = set(_CORE_TOOLS)
    for tt in target_types:
        if not isinstance(tt, str):
            continue
        per_type = _TOOLS_BY_TARGET_TYPE.get(tt.strip().lower(), frozenset())
        allowed |= per_type
    # Always strip the blocked set last.
    return allowed - _BLOCKED_TOOLS


def is_tool_allowed_for_lead(
    tool_name: str,
    *,
    target_types: Iterable[str],
) -> bool:
    """Predicate variant. Returns True when the lead is allowed to
    invoke `tool_name` given the run's target-type set."""
    if not isinstance(tool_name, str):
        return False
    return tool_name in get_lead_tool_catalog(target_types=target_types)


def list_blocked_tools() -> set[str]:
    """Tools the lead can NEVER see — primarily `create_agent` and
    its sibling spawn helpers. The architectural commitment."""
    return set(_BLOCKED_TOOLS)


def list_core_tools() -> set[str]:
    """Tools every target type's lead always sees."""
    return set(_CORE_TOOLS)


def list_target_types() -> list[str]:
    """Registered target types. Used by tests + by the lead-agent
    init code to validate `target_types` arg."""
    return sorted(_TOOLS_BY_TARGET_TYPE.keys())
