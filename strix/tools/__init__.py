from .active_hypotheses import *  # noqa: F403
from .agents_graph import *  # noqa: F403
from .browser import *  # noqa: F403
from .executor import (
    execute_tool,
    execute_tool_invocation,
    execute_tool_with_validation,
    extract_screenshot_from_result,
    process_tool_invocations,
    remove_screenshot_from_result,
    validate_tool_availability,
)
from .file_edit import *  # noqa: F403
from .finish import *  # noqa: F403
from .load_skill import *  # noqa: F403
from .notes import *  # noqa: F403
from .proxy import *  # noqa: F403
from .python import *  # noqa: F403
from .recon import *  # noqa: F403
from .registry import (
    ImplementedInClientSideOnlyError,
    get_tool_by_name,
    get_tool_names,
    get_tools_prompt,
    needs_agent_state,
    register_tool,
    tools,
)
from .findings import *  # noqa: F403  # roadmap §8.5 Phase 5
from .reporting import *  # noqa: F403
from .self_audit import *  # noqa: F403
from .specialist import *  # noqa: F403  # roadmap §8.5 Phase 1
from .terminal import *  # noqa: F403
from .traffic_ingest import *  # noqa: F403
from .replay_mutation import *  # noqa: F403  # workitem.md Phase 5.5
from .nuclei_runner import *  # noqa: F403  # community-corpus runner
from .openapi_ingest import *  # noqa: F403  # OpenAPI / Swagger spec ingest for `api` target type
from .container_image import *  # noqa: F403  # Trivy wrapper for `container_image` target type
from .workflow import *  # noqa: F403  # Phase 3d / PR-α — workflow state machine

# iter-19 — 18 deterministic L1 anchor specialists that existed under
# strix/tools/<subdir>/ but were never imported here. Each module
# carries an `@register_tool` decorator that runs ONLY when the
# module is imported; without these import lines, the strix registry
# had no entry for these tools and any call to them returned
# "Tool '<name>' not found". The anchor_prepass already invokes them
# in `_ANCHORS_API` / `_ANCHORS_WEB` and the phase-2 dispatcher —
# they'd been silently failing in production too, not just bench.
# Caught 2026-05-21 during the iter-19 sandbox-bench wiring when
# api/vampi runs reported "Tool 'jwt_audit' not found" etc.
from .cors_check import *           # noqa: F403  # cors_deep_check
from .csrf_check import *           # noqa: F403  # csrf_check
from .cache_deception import *      # noqa: F403  # scan_cache_deception
from .cookie_scoping import *       # noqa: F403  # cookie_scoping
from .auth_seed import *            # noqa: F403  # iter-28.4 — seed_auth (registration discovery + JWT/cookie capture)
from .graphql_discover import *     # noqa: F403  # iter-28.5 — discover_graphql_endpoints
from .default_creds_probe import *  # noqa: F403  # iter-28.6 — probe_default_creds (pure-python brute-force)
from .debug_endpoint import *       # noqa: F403  # debug_endpoint_probe
from .dom_xss_static import *       # noqa: F403  # dom_xss_static_probe
from .file_upload import *          # noqa: F403  # file_upload-related probes
from .graphql import *              # noqa: F403  # graphql introspection probe
from .http_headers import *         # noqa: F403  # http_security_headers_audit
from .jwt_audit import *            # noqa: F403  # jwt_audit (alg=none, HS/RS brute, alg-confusion)
from .nuclei_templates import *     # noqa: F403  # nuclei_template_update
from .open_redirect import *        # noqa: F403  # open_redirect_check
from .race_check import *           # noqa: F403  # scan_race_condition
from .sbom_extract import *         # noqa: F403  # sbom_extract
from .secrets_scan import *         # noqa: F403  # secrets_scan (gitleaks/trufflehog)
from .tls_audit import *            # noqa: F403  # tls_audit
from .web_crawler import *          # noqa: F403  # web_crawler / bfs_crawl
from .websocket import *            # noqa: F403  # scan_websocket_auth
from .well_known import *           # noqa: F403  # well-known endpoint probes
# iter-21.3 — deterministic audit of OIDC / OAuth 2.0 / JWKS
# metadata exposed via `.well-known/`. Companion to
# `well_known_harvest` (which just discloses) — this module emits
# severity findings for `alg=none`, deprecated grants, HMAC keys
# leaked in JWKS, sub-2048-bit RSA, etc.
from .authn_metadata_audit import *  # noqa: F403  # scan_authn_metadata
# iter-21.5 — deterministic mobile-app (APK / IPA) static analysis.
# Pure-Python zip + xml + plist inspection; no docker dep, no
# mobsf. Closes the `asset_type=mobile_app` gap.
from .mobile_app_audit import *      # noqa: F403  # scan_mobile_app
# iter-21.6.2 — direct IMDS-passthrough probe. Complements
# `scan_ssrf` (which needs an SSRF param to drive payloads
# through) for routes that proxy 169.254.169.254 unconditionally
# (dev/debug leftovers, reverse-proxy misconfig, K8s sidecars).
from .cloud_exposure_audit import *   # noqa: F403  # scan_cloud_imds_passthrough
# iter-21.6.1 — wrapper around bbot's bucket-discovery modules.
# Multi-cloud (AWS S3 / GCP GCS / Azure Blob / DigitalOcean
# Spaces / Firebase / IBM COS). Replaces the in-house bucket
# probe from PR #400 (reverted via PR #401) — strix already
# wraps mature OSS scanners, so this sub-iter follows the same
# pattern. Subprocess wrapper around the bbot CLI installed
# via pipx in the sandbox image.
from .bbot_runner import *             # noqa: F403  # scan_buckets_via_bbot
# iter-22.4 — Dockerfile lint (hadolint), container CIS bench
# (dockle), DNS/email hygiene (checkdmarc). All small OSS wraps
# per `docs/L1-optimization.md §3.3 / §3.4 / §3.10`.
from .hadolint_runner import *         # noqa: F403  # scan_dockerfile_hadolint
from .dockle_runner import *           # noqa: F403  # scan_image_dockle
from .checkdmarc_runner import *       # noqa: F403  # scan_dns_hygiene_checkdmarc
# iter-22.6 — OSINT aggregator (commercial-feed-equivalent layer).
# Wraps free OSS / zero-auth threat-intel feeds:
#   * dnstwist — typosquat / brand-impersonation domain detection
#   * abuse.ch ThreatFox — active-malware IoC API (zero auth)
# Deferred follow-ups: ransomwatch, HIBP, GreyNoise, CertStream.
from .osint_aggregator import *        # noqa: F403
# iter-22 final omnibus — OSS-wrap completions per
# `docs/L1-optimization.md §6`:
#   iter-22.1 katana  — Go JS-aware crawler (replaces bfs_crawl)
#   iter-22.3 testssl — TLS posture audit (~50 checks vs ~5 in-house)
#   iter-22.8 dalfox  — Go XSS scanner (100+ payloads + filter bypass)
#   iter-22.6 HIBP    — domain credential-leak check
from .katana_runner import *           # noqa: F403  # crawl_with_katana
from .testssl_runner import *          # noqa: F403  # tls_audit_testssl
from .dalfox_runner import *           # noqa: F403  # scan_xss_dalfox
from .anchor_probes import *           # noqa: F403  # iter-35.2 — sandbox wrappers for the 11 anchor-prepass probes
# iter-37.4 — six new OSS-anchored wrappers closing the coverage gaps
# documented in docs/tool-catalog-rationalization.md §C.
from .hydra_runner import *            # noqa: F403  # probe_default_creds_hydra
from .ffuf_runner import *             # noqa: F403  # scan_fuzz_ffuf
from .schemathesis_runner import *     # noqa: F403  # scan_api_schemathesis
from .smuggler_runner import *         # noqa: F403  # scan_smuggling_smuggler
from .mobsf_runner import *            # noqa: F403  # scan_mobile_mobsfscan
# Note: iter-37.4's planned `scan_saml_xsw` wrapper was dropped —
# SAML Raider is a Burp Suite extension without a usable standalone
# CLI, and the existing in-house `strix/tools/specialist/scan_saml_xsw.py`
# already implements the canonical 8 XSW variants. See iter-37.4 PR
# discussion + docs/tool-catalog-rationalization.md §C update.
from .hibp_runner import *             # noqa: F403  # scan_credential_leaks_hibp
# iter-23.1 — recon bedrock: passive subdomain harvest (subfinder),
# concurrent HTTP probing (httpx), service/version fingerprinting (nmap).
# Replaces slow single-threaded in-house DNS bruteforce + bfs_crawl with
# Go-based concurrent tooling. httpx's -tech-detect gives Wappalyzer-style
# tech fingerprinting inline.
from .subfinder_runner import *        # noqa: F403  # enumerate_subdomains_subfinder
from .httpx_runner import *            # noqa: F403  # probe_hosts_httpx
from .nmap_runner import *             # noqa: F403  # fingerprint_services_nmap
# iter-23.2 — deterministic SQLi at L1. sqlmap covers in-band /
# boolean-blind / time-based blind / stacked queries across all the
# usual DBMS. Moves standard SQLi verification out of expensive L2
# conversational specialist loops, sparing them for bypass logic.
from .sqlmap_runner import *           # noqa: F403  # scan_sqli_sqlmap
# iter-23.3 — three lower-priority L1 wraps:
#   trufflehog --only-verified  : live credential verification (active API
#     pings — drops FP from regex matches that aren't current).
#   feroxbuster                  : Rust recursive path-discovery, faster
#     and more thorough than the in-house bfs_crawl.
#   inql                         : GraphQL schema mapping (introspection
#     reachable case). Complements the in-house graphql_introspect.
from .remediation_plan import *        # noqa: F403  # iter-25.12 — generate_remediation_plan
# iter-26.11 — register `execute_adaptive_probe` so the Lead Orchestrator
# can invoke L1 tools with custom args for the "unforeseen 30%" of
# follow-ups the deterministic probe-bundle dispatcher didn't cover.
# Importing strix.l15 triggers the @register_tool decorators inside.
import strix.l15  # noqa: F401, E402
from .trufflehog_runner import *       # noqa: F403  # verify_credentials_trufflehog
from .feroxbuster_runner import *      # noqa: F403  # discover_paths_feroxbuster
from .inql_runner import *             # noqa: F403  # map_graphql_inql
# iter-24.1 — ruleset/signature lazy-refresh infra. Three @register_tool
# updaters that refresh ~/.strix/cache/rules/<file> from upstream
# (gitleaks.toml, wappalyzer-technologies.json, hadolint.yaml), with a
# 24h ETag-guarded freshness window. secrets_scan + scan_dockerfile_hadolint
# auto-pick up the cached config if present, falling back to baked-in
# defaults — recall-safe per L1-optimization §5.1.
from .rule_updates import *            # noqa: F403

# SCA / supply-chain analysis (Phase 6) — registers
# `scan_sca_lockfiles`.
from strix.sca import tools as _sca_tools  # noqa: F401, E402
# SAST / semgrep-driven static analysis (Phase 7) — registers `scan_sast`.
from strix.sast import tools as _sast_tools  # noqa: F401, E402
# IaC / cloud-posture (Phase 11) — registers `scan_iac`.
from strix.iac import tools as _iac_tools  # noqa: F401, E402
# Phase 9 — behavioural anomaly diff + timing oracle.
from strix.tools.anomaly_diff import tools as _anomaly_tools  # noqa: F401, E402
from strix.tools.timing_oracle import tools as _timing_tools  # noqa: F401, E402
# §4a v2 — cross-category finding-chain artifact.
from strix.finding_chains import tools as _chain_tools  # noqa: F401, E402
# §4b — compliance evidence emission (SOC 2 / ISO 27001 / PCI / ASVS).
from strix.compliance import tools as _compliance_tools  # noqa: F401, E402
from .thinking import *  # noqa: F403
from .todo import *  # noqa: F403
from .web_search import *  # noqa: F403

# Threat-intel daemon — registers lookup_known_cves /
# lookup_cve_by_id / list_actively_exploited_cves / threat_intel_status.
from strix.threat_intel import tools as _threat_intel_tools  # noqa: F401, E402


__all__ = [
    "ImplementedInClientSideOnlyError",
    "execute_tool",
    "execute_tool_invocation",
    "execute_tool_with_validation",
    "extract_screenshot_from_result",
    "get_tool_by_name",
    "get_tool_names",
    "get_tools_prompt",
    "needs_agent_state",
    "process_tool_invocations",
    "register_tool",
    "remove_screenshot_from_result",
    "tools",
    "validate_tool_availability",
]
