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
