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
    # iter-26.2 / 26.7 — L1.5-aware catalog listing. Returns the
    # current finding set ranked by surface_priority → exploitability
    # composite → severity, with noise=True / role=corroborator hidden
    # by default. The Lead calls this between specialist dispatches to
    # pick the highest-leverage next target.
    "list_pending_findings",
    # iter-Q5.6 — single-finding deep-read companion to
    # list_pending_findings. The list returns ~8 fields per row;
    # get_finding returns the FULL report dict for one ID. Used when
    # composing chain narratives or writing developer-facing prose
    # against a specific finding's full evidence + L1.5 enrichment.
    "get_finding",
    # iter-Q5.14 — read prepass-persisted recon artifacts.
    "get_recon_artifact",
    # iter-Q5.7 — unified threat-intel fetcher (collapses 4 wrappers).
    # FETCH EXTERNAL bucket; 24h cache.
    "query_threat_intel",
    # iter-Q5.8 — current compliance mappings (SOC2/PCI/HIPAA/GDPR/FedRAMP).
    "lookup_compliance_mapping",
    # iter-Q5.9 — re-fire an L1 OSS tool with new captured state.
    # Allow-list + budget-capped.
    "rescan",
    # iter-26.5 + 26.6 — dequeue & fire L1.5 auto-confirmations
    # (SAST→DAST) and finding-triggered probe bundles. Idempotent;
    # safe to call repeatedly between dispatches.
    "drain_amplify_queue",
    # iter-26.11 — adaptive-probe escape hatch. Routes through the
    # POSTURE gate (stealth-aware) and is per-scan call-capped at 10.
    # For the unforeseen 30% of follow-ups not covered by the
    # deterministic probe-bundle dispatcher.
    "execute_adaptive_probe",
    # iter-25.12 — narrative remediation plan output. Surfaced as a
    # catalog gap by E2E-test-proposal.md Phase F.1 meta-invariant.
    "generate_remediation_plan",
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
        # iter-Q5.10 — umbrella that routes to scan_idor / scan_auth_flow /
        # scan_business_logic. Kept in legacy catalog so the reachability
        # invariant test sees it; minimal mode hides the individual probes
        # and exposes only the umbrella.
        "dispatch_l2_probe",
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
        "well_known_harvest",
        # iter-22.1 / iter-23.1 / iter-23.3 — OSS recon wraps (Go-based
        # tooling, much faster than the in-house bfs_crawl /
        # fingerprint_tech_stack which they supersede). Surfaced by
        # E2E-test-proposal.md tests as a real catalog gap — the tools
        # had been registered since iter-22 but never wired into the
        # per-target catalog, so the LLM couldn't reach them.
        # Note: bfs_crawl + fingerprint_tech_stack DROPPED here (per
        # docs/L2-optimization.md §5.3) because:
        #   * crawl_with_katana strictly supersedes bfs_crawl
        #     (concurrent + JS-aware)
        #   * probe_hosts_httpx -tech-detect ships the same Wappalyzer
        #     signature DB inline; fingerprint_tech_stack is redundant
        # Keeps the catalog under the 90-tool prompt-token budget.
        "crawl_with_katana",            # iter-22.1 — JS-aware crawler
        "probe_hosts_httpx",            # iter-23.1 — concurrent HTTP probe + tech-detect
        "discover_paths_feroxbuster",   # iter-23.3 — recursive path discovery
        "scan_xss_dalfox",              # iter-22.8 — Go XSS scanner
        "scan_sqli_sqlmap",             # iter-23.2 — sqlmap batch wrapper
        "map_graphql_inql",             # iter-23.3 — GraphQL introspection
        "scan_credential_leaks_hibp",   # iter-22.6 — domain breach lookup
        # F.1 meta-invariant gaps — these specialists were registered
        # for years but never wired into the web catalog. The LLM
        # had no way to dispatch them.
        "scan_cache_deception",         # web-cache poisoning
        "scan_prototype_pollution",     # JS prototype pollution
        "scan_websocket_auth",          # WebSocket auth bypass
        "scan_race_condition",          # race condition specialist
        "scan_authn_metadata",          # OIDC/JWKS metadata audit
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
        # iter-28 L1 universal primitives (#449-respecting — pure
        # python + existing-binary based; no new docker tools):
        "seed_auth",                    # iter-28.4 — register test user, capture JWT/cookie
        "discover_graphql_endpoints",   # iter-28.5 — GraphQL endpoint discovery + introspection
        "probe_default_creds",          # iter-28.6 — SecLists default-credentials brute
        # iter-37.4 — 3 new OSS wrappers closing coverage gaps. Live
        # in the LEGACY catalog (reachable under STRIX_LEGACY_CATALOG=1
        # + via orchestrator-mode dispatch); the minimal catalog stays
        # ACT-only per iter-37.11. Move into minimal after iter-37.12
        # bench shows positive recall delta.
        "probe_default_creds_hydra",    # iter-37.4 — hydra-backed creds brute
        "scan_fuzz_ffuf",               # iter-37.4 — ffuf web fuzzer
        "scan_smuggling_smuggler",      # iter-37.4 — smuggler.py HTTP smuggling
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
        # iter-22.4 — Dockerfile linter (when repo contains Docker
        # build files). Surfaced as a catalog gap by E2E tests.
        "scan_dockerfile_hadolint",
        # iter-23.3 — trufflehog `--only-verified` mode: actively
        # verifies discovered secrets via API pings (AWS STS, Stripe
        # /balance, GitHub /user). Drops FPs before L2 ever sees them.
        "verify_credentials_trufflehog",
        # File primitives
        "terminal_execute",
        # iter-37.4 — mobsfscan (mobile-app static analysis on
        # Android Java/Kotlin + iOS Swift/Objective-C source +
        # AndroidManifest.xml audits). Legacy catalog only;
        # mobile_app isn't a registered minimal asset type yet.
        "scan_mobile_mobsfscan",
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
        # iter-37.4 — see comment on `repository`.
        "scan_mobile_mobsfscan",
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
        # iter-22/23 — OSS wraps usable on API surfaces. Surfaced as a
        # catalog gap by docs/E2E-test-proposal.md tests.
        "scan_sqli_sqlmap",             # iter-23.2 — sqlmap batch
        "scan_xss_dalfox",              # iter-22.8 — for hybrid REST/JSON
        "tls_audit_testssl",            # iter-22.3 — deeper TLS audit
        "probe_hosts_httpx",            # iter-23.1 — HTTP probe
        "map_graphql_inql",             # iter-23.3 — GraphQL introspection
        "scan_credential_leaks_hibp",   # iter-22.6 — domain-level breach
        # Threat-intel.
        "vt_reputation", "greynoise_classify",
        # iter-28 L1 universal primitives (#449-respecting):
        "seed_auth",                    # iter-28.4 — register test user, capture JWT/cookie
        "discover_graphql_endpoints",   # iter-28.5 — GraphQL endpoint discovery + introspection
        "probe_default_creds",          # iter-28.6 — SecLists default-credentials brute
        # iter-37.4 — 4 new OSS wrappers for API targets (legacy
        # catalog only — minimal stays ACT-only per iter-37.11).
        "probe_default_creds_hydra",    # iter-37.4 — hydra creds brute
        "scan_fuzz_ffuf",               # iter-37.4 — ffuf param/path fuzz
        "scan_api_schemathesis",        # iter-37.4 — OpenAPI property fuzzer
        "scan_smuggling_smuggler",      # iter-37.4 — HTTP smuggling
    }),
    "domain": frozenset({
        "scan_misconfig",
        # Domain recon (§7.3)
        "domain_recon_pipeline", "subdomain_enum_tool", "dns_hygiene_check",
        "passive_dns_history", "org_fingerprint", "discover_cloud_assets",
        "subdomain_takeover_check", "reverse_ip", "mail_recon",
        "saas_leaks", "well_known_harvest",
        "scan_subdomain_takeover_active",  # Phase 2.9 — active CNAME takeover (CWE-1390)
        # iter-22.6 / iter-23.1 / iter-23.3 — OSINT + domain-specific
        # OSS wraps surfaced as catalog gaps by F.1 meta-invariant.
        "enumerate_subdomains_subfinder",     # iter-23.1 — passive subdomains
        "scan_typosquats_dnstwist",           # iter-22.6 — typosquat detection
        "scan_dns_hygiene_checkdmarc",        # iter-22.4 — checkdmarc DMARC/SPF
        "scan_iocs_for_target_threatfox",     # iter-22.6 — ThreatFox IOC lookup
        "scan_credential_leaks_hibp",         # iter-22.6 — HIBP breach domain
        "scan_buckets_via_bbot",              # iter-21.6.1 — bbot bucket disco
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
        # iter-23.1 — nmap service-version fingerprinting; feeds the KG
        # `Service` nodes for L2 CVE hypothesis formation. Surfaced as
        # a real catalog gap by docs/E2E-test-proposal.md tests — was
        # registered but never reachable by the LLM.
        "fingerprint_services_nmap",
        # iter-23.1 — concurrent HTTP probe on discovered ports.
        "probe_hosts_httpx",
        # iter-22.3 — TLS audit on the wider scan port set.
        "tls_audit_testssl",
        # iter-21.6.2 — IMDS passthrough probe (cloud-hosted IPs).
        "scan_cloud_imds_passthrough",
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
        # iter-22.4 — dockle container-image linter (privilege
        # escalation vectors, root execution, leaked env credentials).
        "scan_image_dockle",
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


# ---------------------------------------------------------------------------
# iter-37.2 — Minimal OSS-anchored catalog (per docs/tool-catalog-
# rationalization.md). Replaces the 99-tool web catalog with 8 tools,
# all of them routing to widely-deployed OSS engines (nuclei, sqlmap,
# katana, semgrep, trivy, etc.).
#
# Why: the L2 Lead on Gemini Flash + 10-min standard mode found only
# 4-5/109 challenges on Juice Shop because 99 tools is decision-
# paralysis territory. Empirically the agent fixated on a small subset
# (scan_cache_deception over and over) and never invoked the broader
# OSS battery. With 8 tools per target, the LLM's choice space is
# tractable and each tool maps to a question it's trained to
# recognize ("run nuclei", "run sqlmap").
#
# Default: ON. Opt-out via `STRIX_LEGACY_CATALOG=1` for backwards-
# compat (e.g. existing tests that explicitly invoke scan_sqli or
# other deprecated tools).
#
# In-house tools NOT in these sets are still REGISTERED + EXECUTABLE
# (so direct invocation by tests / sandbox tool-server still works).
# They're just not surfaced to the LLM as choices.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# iter-37.11 — per-asset trim to ACT-only.
#
# Rationale: the OSS anchor prepass (anchor_prepass.py:
# `_ANCHORS_BY_TARGET_TYPE`) fires ~25 tools deterministically before
# the LLM wakes up — recon + broad-signature detection are the
# harness's job, not the LLM's. Tools that the prepass ALREADY runs
# don't belong in the LLM's catalog (their slots cost decision-
# paralysis tokens without buying new behavior — the LLM can't re-
# discover something the prepass discovered first).
#
# Per-asset rule: drop the recon + orient tools whose result is
# already in the prepass output; keep ONLY the ACT-stage tools the
# LLM must call to make progress on a finding (deep exploit, session-
# aware authz, LLM-orchestrated taint trace, etc.).
#
# Two assets stay unchanged because they have NO comprehensive
# prepass coverage:
#   * `ip_address` — prepass only runs `probe_open_tcp_ports` +
#     per-port banner probes; no nmap/httpx/nuclei. LLM still needs
#     them in catalog.
#   * `domain`     — no prepass at all. LLM drives all recon.
#
# Catalog impact (per-asset specialist set):
#   web_application: 10 → 5  ( drop crawl_with_katana, scan_nuclei_
#                              templates, seed_auth, tls_audit,
#                              browser_action — all in prepass or
#                              auto-included via dispatcher)
#   api:             10 → 5  ( drop openapi_spec_ingest,
#                              crawl_with_katana, scan_nuclei_
#                              templates, seed_auth, tls_audit)
#   repository:       8 → 4  ( drop scan_sast, secrets_scan,
#                              scan_sca_lockfiles, scan_iac)
#   local_code:       8 → 4  ( drop scan_sast, secrets_scan,
#                              scan_sca_lockfiles, scan_iac)
#   container_image:  4 → 2  ( drop scan_container_image,
#                              sbom_extract)
#   ip_address:       6 → 6  (unchanged — no comprehensive prepass)
#   domain:           7 → 7  (unchanged — no prepass)
#
# Total post-iter-37.11 (with iter-37.10's 5-tool core):
#   web_application:  10 tools
#   api:              10 tools
#   repository:        9 tools
#   ip_address:       11 tools
#   container_image:   7 tools
#   domain:           12 tools
#
# Dropped tools STAY REGISTERED + EXECUTABLE — sandbox tool-server,
# direct invocation by tests, orchestrator-mode dispatch all still
# see them. Only LLM-catalog visibility changes.
# ---------------------------------------------------------------------------

_MINIMAL_TOOLS_BY_TARGET_TYPE: dict[str, frozenset[str]] = {
    "web_application": frozenset({
        # iter-Q5.3 — deep-exploit OSS wrappers moved to anchor_prepass
        # per CLAUDE.md §1.5 (tools are the LLM's hands, not its brain).
        #
        # iter-Q5.10 — scan_idor + scan_auth_flow + scan_business_logic
        # collapsed under dispatch_l2_probe(kind, **kwargs). One catalog
        # slot, three probe shapes, same capability surface. The
        # underlying scan_* functions stay registered (orchestrator
        # mode + direct tests still reach them); the LLM only sees the
        # umbrella.
        #
        # === L2-NATIVE DETECTION (no OSS substitute — needs LLM
        # state-reasoning that anchor_prepass can't do) ===
        "dispatch_l2_probe",  # kind ∈ {idor, auth_flow, business_logic}
        # === PRIMITIVE escape hatch ===
        "send_request",
    }),
    "api": frozenset({
        # iter-Q5.3 + Q5.5 + Q5.10 — same collapse as web. dispatch_l2_probe
        # replaces scan_idor + scan_auth_flow. business_logic is also
        # available via kind="business_logic" (was previously not in
        # api minimal — Q5.10 surfaces it for free as part of the
        # umbrella).
        #
        # === L2-NATIVE DETECTION ===
        "dispatch_l2_probe",
        # === PRIMITIVE escape hatch ===
        "send_request",
    }),
    "repository": frozenset({
        # Sequential cap-pressure cleanup:
        #   iter-Q5.6: -scan_mobile_mobsfscan (prepass duplicate)
        #   iter-Q5.7: -taint_analysis (CLAUDE.md §11.1 violation;
        #              semgrep prepass has broader coverage)
        #   iter-Q5.9: -verify_credentials_trufflehog (folded into
        #              rescan allow-list — it's a verifier, fits
        #              the rescan pattern better; lead calls
        #              rescan(tool_name="verify_credentials_trufflehog",
        #              target=..., captured_state={"secret_path": ...})
        #              when it wants to confirm a specific surfaced
        #              secret is still credentialed)
        #
        # === ACT only — SAST + secrets + SCA + IaC fire in prepass ===
        # Code reasoning primitive (LLM-orchestrated, no OSS substitute)
        "build_code_map",
        # Terminal for opening files etc.
        "terminal_execute",
    }),
    "local_code": frozenset({
        # Same shape as repository.
        "build_code_map",
        "terminal_execute",
    }),
    "ip_address": frozenset({
        # iter-Q5.4: fingerprint_services_nmap + probe_hosts_httpx +
        # scan_nuclei_templates + tls_audit moved to _ANCHORS_IP. Per
        # CLAUDE.md §1.5 — recon and OSS signature detection fire
        # deterministically in prepass; the L2 lead reads results via
        # list_pending_findings.
        # === PRIMITIVE escape hatches (per-asset) ===
        "send_request",
        "terminal_execute",
    }),
    "container_image": frozenset({
        # trivy fires in prepass — drop scan_container_image.
        # dockle isn't in prepass; LLM still needs it for container
        # lint findings.
        "scan_image_dockle",            # dockle
        "terminal_execute",             # docker save / mount inspection
    }),
    "domain": frozenset({
        # iter-Q5.5: domain_recon_pipeline + subfinder + nuclei +
        # checkdmarc + dnstwist moved to _ANCHORS_DOMAIN. Per CLAUDE.md
        # §1.5 — domain recon fires deterministically in prepass.
        # === PRIMITIVE escape hatches ===
        "send_request",
        # iter-Q5.12: terminal_execute added to domain catalog (was
        # missing) — needed for ad-hoc dig / host / whois queries.
        "terminal_execute",
    }),
}


def is_legacy_catalog_enabled() -> bool:
    """iter-37.2 — opt-out of the minimal catalog for backwards-compat.

    Default: minimal catalog is ON (per
    docs/tool-catalog-rationalization.md). Set
    `STRIX_LEGACY_CATALOG=1` to restore the pre-iter-37.2 fat
    catalog (~99 tools per web target).

    Used by:
      * Tests that explicitly invoke deprecated tools (scan_sqli,
        scan_xss, etc.) — they should NOT be auto-broken by the
        catalog migration.
      * Operators running custom workflows that depend on the legacy
        per-asset surface.

    The wrapper-facing API (`get_lead_tool_catalog`) and the LLM's
    visible tool set both branch on this. Both the CORE set
    (iter-37.8) and the per-asset specialist set (iter-37.2)
    are affected.
    """
    import os
    return os.environ.get(
        "STRIX_LEGACY_CATALOG", "",
    ).strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# iter-37.8 — Minimal CORE tools.
#
# The legacy _CORE_TOOLS has 32 entries with substantial redundancy:
#   * 5 note tools (create/list/get/update/delete) — LLM scratchpad
#     functionality that `think` already provides
#   * 5 hypothesis tools (open/confirm/dismiss/list + is_surface...)
#     — planning aids the LLM rarely uses correctly
#   * 2 KG tools (query_nodes/query_paths) — niche; merge later
#   * Multiple introspection tools (agent_self_audit, check_budget,
#     drain_amplify_queue, execute_adaptive_probe) — almost never
#     improve the LLM's decisions; surface paralysis
#   * Orchestrator-mode-only tools (dispatch_specialist,
#     complete_objective) — handled separately by orchestrator mode
#
# iter-37.8 keeps ONLY the 12 tools every scan genuinely needs.
# Like iter-37.2, the removed tools STAY REGISTERED + EXECUTABLE for
# backwards-compat (sandbox tool-server + tests + legacy mode). They
# just aren't surfaced to the LLM as choices.
#
# Total catalog target after iter-37.8:
#   web_application: 12 core + 10 specialist = ~22 tools
#   api:             12 core + 9 specialist  = ~21 tools
#   repository:      12 core + 8 specialist  = ~20 tools
#   ip_address:      12 core + 6 specialist  = ~18 tools
#   container:       12 core + 4 specialist  = ~16 tools
#
# Set STRIX_LEGACY_CATALOG=1 to restore the 32-tool _CORE_TOOLS.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# iter-37.10 — minimal CORE trimmed from 13 → 5.
#
# Frame: OODA. The OSS prepass (anchor_prepass) already burns through
# OBSERVE + ORIENT before the LLM wakes up — recon and broad-signature
# detection are deterministic, not LLM-driven. The L1.5 hook chain
# auto-handles threat-intel enrichment (tracer.add_vulnerability_report
# calls threat_intel.enrich at emission time) and mid-scan correlation
# (mid_scan_correlate.correlate_at_phase_boundary fires at every phase
# transition). So the LLM's catalog should ONLY contain tools the LLM
# itself must call — not tools the harness already drives.
#
# Kept (5 tools — one per OODA phase + termination):
#   * workflow_status          — OBSERVE: where am I in the scan?
#   * list_pending_findings    — OBSERVE: what did L1 surface?
#   * think                    — ORIENT: reasoning scratchpad
#   * create_vulnerability_report — ACT: emit (now upsert-capable via
#                                  `existing_report_id`)
#   * finish_scan              — terminate (auto-fires compliance +
#                                remediation as terminal artifacts)
#
# Dropped (8 tools — covered by harness or auto-hooks):
#   * advance_workflow_phase   — phase gates are advisory; workflow
#                                state machine auto-advances on
#                                criteria. LLM-driven advancement
#                                is a footgun (PR-#232 OODA loop-
#                                breaker fights this exact problem).
#   * probe_endpoint           — folds into send_request (per-asset).
#   * update_finding           — fold into create_vulnerability_report
#                                via upsert semantics.
#   * correlate_findings       — mid_scan_correlate auto-fires at every
#                                phase boundary (iter-27.2). LLM call
#                                is redundant + invites paralysis.
#   * query_threat_intel       — tracer.add_vulnerability_report
#                                auto-enriches with CWE/CVE/KEV/EPSS at
#                                emission time. Pre-scan stack-CVE
#                                lookups are an orchestrator-mode
#                                concern, not core.
#   * emit_compliance_evidence — terminal artifact, auto-fires inside
#                                finish_scan now.
#   * generate_remediation_plan — same; auto-fires inside finish_scan.
#   * dispatch_specialist      — orchestrator-mode-only; surfaced via
#                                _ORCHESTRATOR_ALLOWED_TOOLS, not core.
#
# All dropped tools STAY REGISTERED + EXECUTABLE (sandbox tool-server,
# tests, legacy mode). They're just hidden from the LLM's choice space.
#
# Total catalog target per web target after iter-37.10:
#   5 core + 10 specialist (iter-37.2) = 15 tools (down from 23).
# After iter-37.11 (per-asset ACT-only trim):
#   5 core + 5 specialist = 10 tools (84% reduction vs 99 legacy).
#
# Set STRIX_LEGACY_CATALOG=1 to restore the 32-tool _CORE_TOOLS.
# ---------------------------------------------------------------------------

_MINIMAL_CORE_TOOLS: frozenset[str] = frozenset({
    # === OBSERVE: where am I? ===
    "workflow_status",

    # === OBSERVE: what did L1 surface? ===
    "list_pending_findings",

    # === OBSERVE: deep-read a single finding ===
    # iter-Q5.6 — companion to list_pending_findings. The list view
    # returns ~8 fields per finding; get_finding returns the FULL
    # report (description / evidence / code_locations / chain_summary
    # / corroborated_by / kill_chain / etc.) for ONE finding. Used
    # when composing a chain narrative or writing the developer-
    # facing description.
    "get_finding",

    # === OBSERVE: raw recon artifact access ===
    # iter-Q5.14 — read prepass-persisted artifacts (endpoints,
    # openapi_spec, graphql_schema, sbom, subdomains, tech_stack,
    # auth_endpoints) from <run_dir>/recon/. Closes Gap 2 from the
    # consolidated Q5 §7 — raw recon was previously lost to compaction.
    "get_recon_artifact",

    # === FETCH EXTERNAL: real-time threat intel ===
    # iter-Q5.7 + Q5.7a — unified threat-intel query that collapses
    # cve_lookup + nvd_lookup + cve_intel_search + kev_diff_check.
    # 24h cache. Returns CVSS + KEV + EPSS + advisories + exploit
    # availability. Domain-shape route (Q5.7a) adds passive DNS +
    # WHOIS + reputation. Per CLAUDE.md §1.5.6, this closes the
    # FETCH EXTERNAL bucket that was previously empty — the lead
    # no longer writes CVE/threat metadata from training-data memory.
    "query_threat_intel",

    # === FETCH EXTERNAL: compliance control mapping ===
    # iter-Q5.8 — versioned corpus of CWE → SOC2/PCI-DSS/HIPAA/GDPR/
    # FedRAMP control IDs. Refreshed on cron. The lead writes
    # compliance mapping from current corpus, not training-data memory.
    "lookup_compliance_mapping",

    # === RE-DISPATCH: re-fire an L1 OSS tool with new captured state ===
    # iter-Q5.9 — runs a prepass tool again with auth cookies / params
    # captured mid-scan. Allow-list validated; budget-capped at 5/scan.
    "rescan",

    # === ORIENT: scratchpad ===
    # No-op tool that gives the LLM a place to record reasoning.
    # Subsumes the 5 note tools + 5 hypothesis tools.
    "think",

    # === ACT: emit findings ===
    # Upsert-capable post iter-37.10 — pass `existing_report_id` to
    # mutate, omit to create.
    "create_vulnerability_report",

    # === ACT: terminate ===
    # Auto-fires emit_compliance_evidence + generate_remediation_plan
    # as terminal artifacts (iter-37.10). Set
    # STRIX_FINISH_AUTO_ARTIFACTS=0 to opt out.
    "finish_scan",
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
    # iter-26.2 / 26.7 — L1.5-aware ranked catalog.
    "list_pending_findings",
    # iter-26.5 + 26.6 — auto-fire L1.5 confirmations + probe bundles.
    "drain_amplify_queue",
    # iter-26.11 — adaptive-probe escape hatch (stealth-aware,
    # call-capped).
    "execute_adaptive_probe",
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

    # iter-37.2 — minimal OSS-anchored per-asset catalog (default ON).
    # iter-37.8 — minimal CORE tools (default ON).
    # Both gates flip via STRIX_LEGACY_CATALOG=1 for backwards-compat.
    # Per docs/tool-catalog-rationalization.md target: ~22 tools per
    # web target (vs 99 legacy).
    use_minimal = not is_legacy_catalog_enabled()
    per_target_table = (
        _MINIMAL_TOOLS_BY_TARGET_TYPE if use_minimal
        else _TOOLS_BY_TARGET_TYPE
    )
    core_table = _MINIMAL_CORE_TOOLS if use_minimal else _CORE_TOOLS

    allowed: set[str] = set(core_table)
    for tt in target_types:
        if not isinstance(tt, str):
            continue
        per_type = per_target_table.get(tt.strip().lower(), frozenset())
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
