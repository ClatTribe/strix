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
    # Phase 3d / PR-α — workflow state-machine tools. The lead
    # MUST be able to inspect/advance the workflow regardless of
    # phase, so these live in the core (and are also marked
    # phase-agnostic in workflow_state.py so phase filtering
    # never strips them).
    "workflow_status", "advance_workflow_phase",
    # Phase 3d / PR-β — composite specialist fan-out. Lives in
    # the core so it's always reachable; the phase filter still
    # makes sense per-target-type (web-only) but probe_endpoint
    # is universally useful when a probable endpoint is in hand.
    "probe_endpoint",
    # §1 / PR-#233 — fresh-context orchestrator dispatch. The
    # lead in orchestrator mode calls `dispatch_specialist`; the
    # spawned specialist calls `complete_objective` to exit. Both
    # in core so they're always reachable when the orchestrator
    # mode is on (catalog gate handled below).
    "dispatch_specialist", "complete_objective",
    # Coordination + planning
    "open_hypothesis", "confirm_hypothesis", "dismiss_hypothesis",
    "list_active_hypotheses", "is_surface_under_investigation",
    "agent_self_audit",
    # Findings
    "create_vulnerability_report", "update_finding", "dismiss_finding",
    "check_budget",
    # Threat intel — always-on (read-only, framework provenance).
    # iter-22.9: `cve_lookup` / `nvd_lookup` / `lookup_known_cves` /
    # `lookup_cve_by_id` / `list_actively_exploited_cves` were five
    # tools doing similar CVE-data queries (~3K of duplicate schema
    # tokens). Consolidated into `query_threat_intel(...)` per
    # `docs/l2-architecture-evaluation.md §5.1`. The unified tool
    # dispatches by which kwarg is supplied:
    #   cve_id → single-CVE; component → component lookup;
    #   actively_exploited=True → KEV/EPSS list.
    # `threat_intel_status()` remains separately registered as a
    # cache-freshness diagnostic.
    "query_threat_intel", "threat_intel_status",
    # Reasoning
    "think",
    # Termination
    "finish_scan",
    # Notes / scratchpad
    "create_note", "list_notes", "get_note", "update_note", "delete_note",
    # §4a v2 — cross-category finding-chain correlator. Runs at
    # the end of the scan to bundle related findings (SCA dep +
    # DAST exploit, SAST sink + IaC misconfig, etc.) into single
    # `FindingChain` entries. Always-on because correlation is
    # asset-type-agnostic — a chain can span any combination of
    # categories the lead happens to cover.
    "correlate_findings",
    # §4b — compliance evidence emission. Maps every emitted
    # finding to SOC 2 / ISO 27001 / PCI DSS / OWASP ASVS
    # control IDs via CWE + category, writes
    # `compliance_evidence.json`. Always-on; the wrapper
    # consumes the artifact for compliance dashboards / auditor
    # handoff.
    "emit_compliance_evidence",
    # iter-22.10 — promote knowledge-graph query primitives from
    # patcher-only to the Lead Orchestrator catalog per
    # `docs/l2-architecture-evaluation.md §4`. Without these in
    # the lead's view the orchestrator can't ask "which Assets is
    # this finding attached to?" / "is there a path from Surface
    # X to Vuln Y?" — the prior workaround was for the lead to
    # spawn a patcher specialist just to query the KG, which
    # burned an extra dispatch + fresh-context loop. Read-only
    # tools; no destructive surface.
    "kg_query_nodes", "kg_query_paths",
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
        "scan_saml_xsw",  # masterroadmap §1 P0 — SAML XML Signature Wrapping + SP config audit (CWE-347)
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
        # iter-22.9: removed `scan_sca_lockfiles` + `scan_sast` from
        # the web_application catalog per
        # `docs/l2-architecture-evaluation.md §5.4` —
        # `web_application` is by-definition a deployed live URL and
        # does not natively expose lockfiles or source code. When a
        # repository is paired with a deployed URL (the vibe-coded
        # SaaS pattern), the run uses paired targets
        # (`web_application` + `additional_targets=[repository]`)
        # and the catalog union restores SAST/SCA via the
        # repository entry. Keeping them here doubled the catalog
        # tokens AND let the LLM attempt source reads on live URLs.
        #
        # `scan_iac` stays — IaC config files (vercel.json,
        # netlify.toml, .well-known/*) are occasionally exposed via
        # live URLs, not strictly repo-bound.
        # Phase 11 — IaC / cloud posture.
        "scan_iac",
        # Phase 9 — behavioural anomaly diff + timing oracle.
        # Used as complementary signals alongside the static-
        # payload specialists: anomaly diff catches probe-vs-
        # baseline divergences; timing oracle confirms blind
        # injection via 50-sample statistical fit.
        "scan_response_anomaly",
        "scan_timing_oracle",
        # Recon.
        # iter-22.9: dropped `webapp_recon_pipeline` from the lead
        # tool catalog per `docs/l2-architecture-evaluation.md §5.3`
        # — the composite pipeline duplicated the work the lead can
        # already orchestrate by calling `fingerprint_tech_stack` +
        # `bfs_crawl` + `well_known_harvest` directly. The tool
        # STAYS registered in `strix.tools` (iter-18 / iter-20
        # anchor_prepass phase-2 invokes it directly for the
        # web_application target type before the lead loop begins).
        # Net effect: ~3K of duplicate schema tokens removed from
        # every web_application run; production behavior unchanged.
        "fingerprint_tech_stack", "bfs_crawl",
        "well_known_harvest",
        # HTTP / browser primitives
        "send_request", "browser_action", "extract_dom",
        # HAR / Burp ingestion (#141)
        "ingest_har_file", "ingest_burp_file",
        # Replay-with-mutation orchestrator — Phase 5.5.
        # iter-22.9: three source-specific tools consolidated into
        # one `replay_mutation(source=...)` per
        # `docs/l2-architecture-evaluation.md §5.2`. The unified
        # tool routes by `source="endpoints"|"har"|"burp"`.
        "replay_mutation",
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
        # Threat-intel — provided via `_CORE_TOOLS` /
        # `query_threat_intel` (iter-22.9). No per-target dup.
    }),
    "local_code": frozenset({
        "scan_misconfig",
        "build_code_map", "taint_analysis", "score_reachability",
        "secrets_scan", "sbom_extract",
        "scan_sca_lockfiles",  # Phase 6 — SCA
        "scan_sast",            # Phase 7 — SAST
        "scan_iac",             # Phase 11 — IaC
        "terminal_execute",
        # iter-22.9: threat-intel via _CORE_TOOLS / query_threat_intel
    }),
    "api": frozenset({
        # API targets — REST / GraphQL / gRPC HTTP-shaped endpoints
        # that don't render HTML. Tool set is the web_application
        # DAST cluster MINUS browser/DOM/source-map tools (waste
        # budget on non-rendered surfaces) PLUS the OpenAPI spec
        # ingester that replaces bfs_crawl as the endpoint-
        # inventory source.
        "scan_misconfig",
        # Specialist DAST — full carry-over EXCEPT scan_xss
        # (HTML-rendering only; APIs that return JSON don't
        # execute reflected scripts).
        "scan_sqli", "scan_xxe", "scan_blind_ssrf",
        "scan_deserialization", "scan_blind_cmd_injection",
        "scan_oob_xxe", "scan_auth_flow", "scan_business_logic",
        "scan_idor", "scan_multi_role_auth", "scan_oauth",
        "scan_saml_xsw",  # masterroadmap §1 P0 — SAML XSW + SP config audit
        "scan_request_smuggling_active", "scan_ldap_injection",
        "scan_xpath_injection", "scan_cmd_injection",
        "scan_secrets_in_response", "scan_nosql_injection",
        "scan_ssti", "scan_path_traversal", "scan_ssrf",
        "scan_nuclei_templates",
        "scan_sca_lockfiles", "scan_sast", "scan_iac",
        "scan_response_anomaly", "scan_timing_oracle",
        # API-shaped endpoint inventory. Replaces bfs_crawl —
        # OpenAPI spec is exact inventory; crawling misses
        # documented-but-unlinked endpoints.
        "openapi_spec_ingest",
        # API-specific specialists (OWASP API Top 10 — gaps not
        # covered by the web_application DAST set).
        "scan_api_rate_limit",       # API4 — Unrestricted Resource Consumption
        "scan_api_bola",             # API1 — Broken Object Level Authorization
        "scan_api_bfla",             # API5 — Broken Function Level Authorization
        "scan_api_mass_assignment",  # API3 — Broken Object Property Level Authorization
        "graphql_introspection_deep",  # GraphQL deep probe (intro+alias-DoS+depth+mutation auth)
        "scan_api_grpc_reflection",  # gRPC ServerReflection probe
        # Recon — keep the tech-stack identifier; drop bfs_crawl
        # since openapi_spec_ingest replaces it for API targets.
        "fingerprint_tech_stack", "well_known_harvest",
        # HTTP primitive + HAR/Burp ingestion (replaces browser).
        "send_request",
        "ingest_har_file", "ingest_burp_file",
        # Replay-mutation orchestrator (consolidated iter-22.9 —
        # see web_application catalog comment).
        "replay_mutation",
        # Deterministic checks that still apply to APIs.
        "http_security_headers_audit", "tls_audit",
        "csrf_check", "cors_deep_check", "session_entropy_check",
        "jwt_audit", "open_redirect_check",
        "request_smuggling_check",
        "race_check", "sqli_check", "graphql_specialist_check",
        "websocket_audit", "authz_matrix_check",
        "cookie_jwt_scoping_check",
        # Threat-intel.
        "vt_reputation", "greynoise_classify",
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
    "container_image": frozenset({
        # Container-image targets — registry-resident artefacts
        # (`nginx:1.25`, `registry.example.com/foo/bar@sha256:...`).
        # The image is scanned for vulnerable OS + language packages
        # via Trivy, with findings routed through strix's KEV / EPSS
        # enrichment + KG dependency emission. MOAK feed-trigger
        # consumes the emitted Dependency nodes so future CVE
        # arrivals against the customer's pinned versions can
        # synthesise an exploit automatically (same path repository
        # targets use).
        "scan_container_image",
        # iter-22.9: CVE lookup via _CORE_TOOLS / query_threat_intel.
        # SBOM extraction — when the wrapper wants the full
        # image manifest separately from the vuln list.
        "sbom_extract",
        # Shell for inspecting Trivy output / running additional
        # image probes (e.g. `docker image inspect`).
        "terminal_execute",
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


# §1 / PR-#233 — orchestrator mode. When the lead runs in
# orchestrator mode (STRIX_ORCHESTRATOR_MODE=true), its catalog is
# reduced to orchestration + dispatch tools. Probing specialists
# are HIDDEN from the lead's view because the orchestrator should
# never invoke them directly — they're called inside the bounded
# fresh-context loop spawned via `dispatch_specialist`.
#
# This is the architectural commitment of §1: lead has no probing
# tools, only `dispatch_specialist`, workflow control, hypothesis
# tracking, finding emission, threat-intel lookups, and finish.
_ORCHESTRATOR_ALLOWED_TOOLS: frozenset[str] = frozenset({
    # Dispatch — the lead's primary action
    "dispatch_specialist",
    # v2 step 3 — batched dispatch. Preferred when probing the
    # same category against multiple similar endpoints. The
    # specialist's 25K-token system prompt is paid once for the
    # whole batch; the batch counts as ONE call against the
    # scan-mode per-run dispatch cap.
    "dispatch_specialist_batch",
    # Workflow control
    "workflow_status", "advance_workflow_phase",
    # Coordination + planning
    "open_hypothesis", "confirm_hypothesis", "dismiss_hypothesis",
    "list_active_hypotheses", "is_surface_under_investigation",
    "agent_self_audit",
    # Finding emission (lead reads dispatch_specialist's structured
    # result; usually doesn't emit findings directly, but the tool
    # stays available for orchestrator-level findings like
    # "coverage gap" or "scope violation")
    "create_vulnerability_report", "update_finding", "dismiss_finding",
    "check_budget",
    # Threat-intel lookups (lead may need these for orchestration
    # decisions — "what CVEs apply to this tech stack?")
    # iter-22.9: 5 redundant lookup tools collapsed into one.
    "query_threat_intel", "threat_intel_status",
    # Reasoning + notes
    "think", "create_note", "list_notes", "get_note",
    "update_note", "delete_note",
    # Cross-category emission (orchestrator's final step before report)
    "correlate_findings", "emit_compliance_evidence",
    # Termination
    "finish_scan",
})


def is_orchestrator_mode_enabled() -> bool:
    """Re-exported here for the catalog-filter caller. The real
    impl lives in `specialist_orchestrator.py`; we read it lazily
    to avoid the circular-import pattern."""
    import os
    return os.environ.get(
        "STRIX_ORCHESTRATOR_MODE", ""
    ).lower() in ("1", "true", "yes", "on")


def get_lead_tool_catalog(
    *,
    target_types: Iterable[str],
    phase: str | None = None,
) -> set[str]:
    """Return the union of allowed tool names for the given target
    types, optionally further filtered by the current workflow phase
    AND by orchestrator mode.

    Args:
        target_types: target-type strings (e.g. ['web_application',
            'repository']). When the run targets multiple types, the
            catalog is the union — the lead sees every tool needed
            for any of them.
        phase: Phase 3d / PR-α — when set, the result is intersected
            with the phase's allowed tool surface. When None (default),
            no phase filtering — backwards-compatible with pre-3d
            callers. The workflow's kill-switch
            (STRIX_WORKFLOW_DISABLED=1) is honoured by callers
            BEFORE they pass `phase` — they should pass None when
            the kill-switch is set.

    Returns:
        A set of tool names. Tools NOT in this set should be omitted
        from the lead's prompt. The actual prompt rendering is
        owned by the LLM layer; this helper is the policy.

    Orchestrator mode (§1 / PR-#233):
        When `STRIX_ORCHESTRATOR_MODE=true`, this function REPLACES
        the result with `_ORCHESTRATOR_ALLOWED_TOOLS` — the lead's
        catalog becomes orchestration-only. Probing specialists
        (scan_xss, scan_sqli, etc.) are HIDDEN from the lead's
        view; the lead must call them via `dispatch_specialist`
        which runs them in a bounded fresh-context loop.
    """
    # §1 — orchestrator mode short-circuits to a fixed, narrow
    # catalog. Target-type + phase filters are bypassed since the
    # orchestrator's tools are universal across asset classes.
    if is_orchestrator_mode_enabled():
        return set(_ORCHESTRATOR_ALLOWED_TOOLS) - _BLOCKED_TOOLS

    allowed: set[str] = set(_CORE_TOOLS)
    for tt in target_types:
        if not isinstance(tt, str):
            continue
        per_type = _TOOLS_BY_TARGET_TYPE.get(tt.strip().lower(), frozenset())
        allowed |= per_type

    # Phase 3d / PR-α — intersect with phase's allowed surface.
    if phase is not None:
        from strix.agents.workflow_state import allowed_tools_for_phase

        phase_allowed = allowed_tools_for_phase(phase)  # type: ignore[arg-type]
        if phase_allowed:
            # Keep core tools (workflow_status etc. live there) +
            # tools the phase considers semantically appropriate.
            allowed = (allowed & phase_allowed) | set(_CORE_TOOLS)

    # Always strip the blocked set last.
    return allowed - _BLOCKED_TOOLS


def is_tool_allowed_for_lead(
    tool_name: str,
    *,
    target_types: Iterable[str],
    phase: str | None = None,
) -> bool:
    """Predicate variant. Returns True when the lead is allowed to
    invoke `tool_name` given the run's target-type set + optional
    workflow phase."""
    if not isinstance(tool_name, str):
        return False
    return tool_name in get_lead_tool_catalog(
        target_types=target_types, phase=phase,
    )


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
