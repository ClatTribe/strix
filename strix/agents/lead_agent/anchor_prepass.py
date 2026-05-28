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
| L1 (this module) | OSS signature corpus + deterministic specialists. **Every L1 tool runs inside the strix-sandbox container in production** (PRs #384/#386/#387 collapsed the host-vs-sandbox split). Includes: scan_sast, scan_sca_lockfiles, scan_iac, secrets_scan, scan_nuclei_templates, scan_container_image, scan_api_rate_limit, scan_api_bola/bfla/mass_assignment, scan_idor, jwt_audit, webapp_recon_pipeline, http_security_headers_audit, tls_audit, cors_deep_check, csrf_check, open_redirect_check, dom_xss_static_probe, scan_cache_deception, scan_websocket_auth, scan_prototype_pollution, fingerprint_tech_stack, openapi_spec_ingest, sbom_extract. | Same in all modes (quick, standard, deep) |
| L2 (existing lead loop) | LLM reasoning — rank, dedupe, FP demote, novel-vuln tag, cross-asset SAST↔DAST correlation, multi-role role-picking | Proportional to scan mode |
| L3 (dispatch_specialist) | Fresh-context exploit chains + PoC synthesis | quick=0, standard=8, deep=unbounded |

This module is L1 ONLY. It never invokes the LLM. It runs the same
deterministic anchor sequence regardless of scan mode — the lead
loop's iter_cap (and downstream dispatch_specialist budget) handles
the mode-aware L2/L3 budgeting.

The "sandbox-only" terminology is deprecated — every L1 tool runs
in the sandbox. The `sandbox_execution` registry flag still routes
tool execution (sandbox vs in-process), but it's not a layer
indicator. The bench harness (`bench_l1_only.py`) has no sandbox
and shows a deliberate LOWER BOUND of L1 recall; production sees
the full anchor coverage including sandbox-routed tools.

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
import re as _re
import time
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
# ---------------------------------------------------------------------------
# iter-Q5.41 — repository file-tree skip patterns
# ---------------------------------------------------------------------------
# Single source of truth for what every L1-SAST tool should NOT scan on
# code-shape targets. Vendored deps belong to SCA (trivy fs / grype), not
# SAST; generated assets (minified JS, source maps, build/ output) have no
# source-level vulns to find; binaries blow up wall time without finding
# anything. Every major SAST tool we use natively supports glob-style
# exclude paths (semgrep `--exclude`, bandit `--exclude`, trivy fs
# `--skip-dirs`, gitleaks via config) — we centralize the patterns here
# so a single PR adjusts behavior across all tools.

_REPO_SKIP_PATTERNS_DEFAULT: tuple[str, ...] = (
    # Vendored / installed dependencies (SCA territory, not SAST).
    "node_modules",
    "vendor",
    "bower_components",
    "third_party",
    "site-packages",
    "venv", ".venv", "env", ".env",
    "Pods",                              # iOS CocoaPods
    "Carthage",                          # iOS Carthage
    # Version control internals.
    ".git",
    ".hg",
    ".svn",
    # Python build / cache trees.
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "*.egg-info",
    # JS build output / minified bundles.
    "dist",
    "build",
    "out",
    "*.min.js",
    "*.min.css",
    "*.map",                              # source maps
    "bundle.js",
    # Coverage / IDE droppings.
    ".coverage",
    "coverage",
    "htmlcov",
    ".idea",
    ".vscode",
    # Generated docs (rarely contains real vulns).
    "_site",                              # Jekyll
    ".docusaurus",
    ".next",                              # Next.js
    ".nuxt",                              # Nuxt.js
    "target",                             # Maven / Rust / sbt
    # Binaries / archives (semgrep can't analyze them anyway).
    "*.jar",
    "*.war",
    "*.zip",
    "*.tar",
    "*.tgz",
    "*.gz",
    "*.exe",
    "*.dll",
    "*.so",
    "*.dylib",
    "*.pyc",
    "*.class",
)


def _get_repo_skip_patterns() -> list[str]:
    """Canonical L1-SAST skip-pattern list, with env override.

    `STRIX_REPO_SKIP_PATTERNS_DISABLE=1` returns [] (ablation — every
    file scanned, useful for benchmark comparisons). Otherwise returns
    the constant set above, optionally extended by
    `STRIX_REPO_SKIP_PATTERNS_EXTRA=pat1,pat2,...`.
    """
    raw_disable = (
        os.environ.get("STRIX_REPO_SKIP_PATTERNS_DISABLE") or ""
    ).strip().lower()
    if raw_disable in ("1", "true", "yes", "on"):
        return []
    out = list(_REPO_SKIP_PATTERNS_DEFAULT)
    extra = (os.environ.get("STRIX_REPO_SKIP_PATTERNS_EXTRA") or "").strip()
    if extra:
        for pat in extra.split(","):
            p = pat.strip()
            if p and p not in out:
                out.append(p)
    return out


# All code-shape anchor tools (scan_sast, scan_sca_lockfiles, scan_iac,
# secrets_scan) now execute inside the sandbox container, so they always
# receive the in-sandbox workspace path (`/workspace/<subdir>`). The
# `target_value` fallback only fires when the caller failed to mount
# a workspace subdir (operator-direct CLI invocation against an ad-hoc
# path) — left in place so the tool returns a clean "not a directory"
# error instead of a NoneType crash.
def _code_kwargs(target_value: str, workspace_path: str, tool_name: str) -> dict[str, Any]:
    """Kwargs for code-target anchor tools (scan_sast,
    scan_sca_lockfiles, scan_iac, secrets_scan). All take `repo_path`
    pointing at the source tree inside the sandbox container."""
    if workspace_path:
        return {"repo_path": workspace_path}
    return {"repo_path": target_value}


def _code_target_path_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """iter-37.14 — kwargs for `scan_mobile_mobsfscan`. Same path
    resolution as `_code_kwargs` but the tool uses `target_path=`
    rather than `repo_path=` (the mobsfscan wrapper accepts BOTH
    source trees AND `.apk`/`.aab` files, hence the more generic
    parameter name)."""
    if workspace_path:
        return {"target_path": workspace_path}
    return {"target_path": target_value}


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
        # Default `max_templates=200` only reaches the first ~200
        # templates in corpus walk order — many high-impact CVE
        # templates (CVE-2021-41773 is at cves/2021/CVE-2021-41773.yaml,
        # deep in the tree) get silently dropped. Iter-16 native
        # raw-HTTP support unblocked these templates at the
        # interpreter level — raise the cap so they actually get
        # iterated.
        #
        # Empirical (2026-05-21): with the broad tag set above
        # (9 tags) + severity ≥ medium, CVE-2021-41773 is at
        # iteration #2057. 3000 covers it with margin.
        # Wall cost: ~250-300s for a clean-port target. Pure-Python
        # interpreter is fast for templates that miss; only matching
        # templates and slow targets dominate wall time.
        "max_templates": 3000,
    }


def _container_kwargs(target_value: str, workspace_path: str, tool_name: str) -> dict[str, Any]:
    """Kwargs for container_image scan.

    iter-Q5.42 — forward the base-layer-skip / multi-arch knobs from
    env to the underlying `scan_container_image` invocation so
    operators can opt into the filters at prepass time without
    threading kwargs through the harness. The tool also reads the
    same env vars itself, but forwarding them here makes the
    decision explicit in prepass logs (`tools_run` carries the
    kwargs).
    """
    kwargs: dict[str, Any] = {"image_ref": target_value}
    pkg_types_env = os.environ.get("STRIX_TRIVY_PKG_TYPES", "").strip()
    if pkg_types_env:
        kwargs["pkg_types"] = pkg_types_env
    if os.environ.get("STRIX_TRIVY_IGNORE_UNFIXED", "").strip() in {"1", "true", "yes"}:
        kwargs["ignore_unfixed"] = True
    platform_env = os.environ.get("STRIX_TRIVY_PLATFORM", "").strip()
    if platform_env:
        kwargs["platform"] = platform_env
    return kwargs


# ---------------------------------------------------------------------------
# iter-Q5.4 / Q5.5 — ip_address + domain kwarg builders
# ---------------------------------------------------------------------------


def _ip_target_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """Kwargs for ip-asset OSS tools that take `target=` (IP literal
    or CIDR). Used by: `fingerprint_services_nmap`, `tls_audit`."""
    return {"target": target_value}


def _ip_hosts_list_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """Kwargs for `probe_hosts_httpx` — accepts `hosts=` as a list.
    For ip_address asset, the single target becomes a 1-element list."""
    return {"hosts": [target_value]}


def _ip_url_synthesis_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """Kwargs for tools that take `url=` but the asset is an IP. Synthesize
    `http://<ip>` (the prepass nuclei tag set probes both HTTP and HTTPS
    via templates anyway; the URL scheme just seeds the first hit)."""
    base = target_value.strip()
    url = base if "://" in base else f"http://{base}"
    # Reuse the broad-signature kwargs (tags + severity + max_templates)
    # from _api_url_with_severity_kwargs for nuclei specifically.
    kwargs = _api_url_with_severity_kwargs(url, workspace_path, tool_name)
    return kwargs


def _domain_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """Kwargs for domain-asset OSS tools that take `domain=` (apex).
    Used by: `enumerate_subdomains_subfinder`, `scan_dns_hygiene_checkdmarc`,
    `scan_typosquats_dnstwist`, `domain_recon_pipeline`."""
    return {"domain": target_value}


def _domain_url_synthesis_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """Kwargs for nuclei on a domain asset. Synthesize
    `http://<domain>` (nuclei templates probe both HTTP and HTTPS)."""
    base = target_value.strip()
    url = base if "://" in base else f"http://{base}"
    return _api_url_with_severity_kwargs(url, workspace_path, tool_name)


# iter-21.5 followup: `_mobile_app_kwargs` was added with the
# `_ANCHORS_MOBILE` list + `mobile_app` asset-type entry below.
# That trio is intentionally NOT wired here yet — the upstream
# pipeline doesn't recognize `target.type = "mobile_app"`
# (CLI, preflight, target-type utilities, StrixAgent dispatch,
# bench fixtures, lead-agent prompts all branch only on
# local_code / repository / web_application / api /
# container_image / ip_address). Adding the anchor without the
# upstream plumbing was dead code — the anchor list would never
# fire because the asset-type detection never produces
# "mobile_app". Removed here so the prepass dict reflects the
# real asset-type surface.
#
# The `scan_mobile_app` tool itself remains registered under
# `strix.tools.mobile_app_audit`: LLM agents can call it
# explicitly when a user supplies a binary path. End-to-end
# mobile_app pipeline support (CLI flag + preflight + fixture +
# routing) is a future iter that needs to land BEFORE the
# anchor entry is restored.


def _sbom_extract_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """Kwargs for `sbom_extract` — it takes `target_url=`, not the
    generic `url=` or `target=` used by the rest of the anchor
    catalog. Caught 2026-05-21 when it was mis-wired into
    `_ANCHORS_CONTAINER` with `_container_kwargs` (image_ref=) and
    every container_image fixture errored `unexpected keyword
    argument 'image_ref'`. Moved here with its own builder."""
    return {"target_url": target_value}


def _api_target_url_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """Kwargs for L1 anchor tools that take `target_url=` (NOT the
    bare `url=` used by the scan_* specialists, and NOT `target=`
    used by fingerprint/openapi). Tools in this group:

      * http_security_headers_audit (header-policy audit)
      * cors_deep_check (CORS policy reflection)
      * csrf_check (Origin/Referer enforcement)
      * open_redirect_check (open-redirect param probe)
      * dom_xss_static_probe (JS bundle source→sink static)

    Caught 2026-05-21 in `l1_only_20260521_115852.md`: every
    web/api fixture had 5 anchor entries fail with `unexpected
    keyword argument 'url'` because the prepass uniformly used
    `_api_url_kwargs` (`{url=...}`) across all URL-shaped tools. The
    specialists under `tools/specialist/scan_*.py` were ported to
    `url=`; the original L1 OSS-corpus tools under
    `tools/{http_headers,cors_check,csrf_check,open_redirect,dom_
    xss_static}` stayed on the more descriptive `target_url=`.
    Reconciling the two would be a wider refactor — for now we
    route correctly per-tool."""
    return {"target_url": target_value}


def _api_schema_url_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """iter-37.14 — kwargs for `scan_api_schemathesis`. The tool
    accepts the OpenAPI / Swagger / GraphQL schema URL via
    `schema_url=`. The harness's default is to construct it from the
    target by appending `/openapi.json` — schemathesis returns
    `status="partial"` if that URL doesn't resolve, so the heuristic
    is safe (no spurious findings; just a cheap probe that confirms
    spec discovery worked). If openapi_spec_ingest captured a
    spec_url in an earlier prepass step, callers can pass that
    instead by overriding kwargs at dispatch time."""
    base = target_value.rstrip("/")
    return {"schema_url": f"{base}/openapi.json"}


def _tls_audit_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """Kwargs for `tls_audit` — takes `target=` (host / host:port /
    URL). Caught 2026-05-21 alongside the wider kwarg-mismatch sweep
    (every web/api fixture had this error)."""
    return {"target": target_value}


def _api_secrets_in_response_kwargs(
    target_value: str, workspace_path: str, tool_name: str,
) -> dict[str, Any]:
    """Kwargs for `scan_secrets_in_response` — takes `urls=`
    (list[str], plural), not `url=` (singular). The plural shape is
    intentional: the tool sweeps a batch of URLs in one call. From
    the prepass we only know the root target — wrap it as a single-
    element list. Caught 2026-05-21."""
    return {"urls": [target_value]}


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
    # 5. iter-37.14 — MobSF mobile-app SAST. Auto-detects Android +
    #    iOS source trees + `.apk` / `.aab` archives (unpacked via
    #    apktool). Returns partial when the repo isn't a mobile app
    #    (no AndroidManifest.xml, no `.apk`, no `Info.plist`), so
    #    firing it unconditionally is safe — no FPs on non-mobile
    #    repos, broad coverage on mobile ones.
    ("scan_mobile_mobsfscan", _code_target_path_kwargs),
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
    # 2a-bis. iter-35.3 — JS-AST web crawl. Pulls SPA routes from
    #     Angular/React/Vue bundles + robots.txt + sitemap.xml. This
    #     is what the L2 Lead in standard mode wasn't reliably
    #     invoking via the prompt directive (iter-32.2) — moving it
    #     into the deterministic prepass ensures recon ALWAYS runs,
    #     not just when the LLM remembers. Runs in sandbox
    #     (sandbox_execution=True), calls
    #     `workflow_state.record_endpoint_discovered` per iter-32.1
    #     so iter-31.9 surface_breadth metric lights up.
    #
    #     Returns partial on pure-API targets that don't serve HTML
    #     (no penalty — the openapi_spec_ingest above is the primary
    #     API recon).
    ("crawl_with_katana", _api_target_url_kwargs),
    # 2b. Black-box SBOM extraction (CycloneDX 1.5). Catches CDN-
    #     served NPM packages, backend frameworks from headers, and
    #     fingerprintable third-party JS — useful for `Dependency`
    #     graph nodes feeding R10 chain construction even when no
    #     repository is attached. Cheap single-URL probe. iter-19+:
    #     uses `target_url=` (NOT `url=` and NOT `image_ref=`) — has
    #     its own builder `_sbom_extract_kwargs`. Was mis-wired into
    #     `_ANCHORS_CONTAINER`; restored to its real home.
    ("sbom_extract", _sbom_extract_kwargs),
    # 2c. iter-28.5 — GraphQL endpoint discovery + introspection.
    #     Probes industry-standard GraphQL paths (`/graphql`,
    #     `/v1/graphql`, ...) and captures schemas. Surfaces
    #     Query/Mutation field lists that downstream specialists
    #     can target per-field. Generic across Apollo / Hasura /
    #     AppSync / Postgraphile / Strapi. Returns partial when
    #     target has no GraphQL endpoint (no penalty on REST-only).
    ("discover_graphql_endpoints", _api_target_url_kwargs),
    # 2c-bis. iter-Q5.5 — InQL deep schema mapping. Companion to the
    #     light `discover_graphql_endpoints` above: when a GraphQL
    #     endpoint is present, inql introspects + dumps every Query /
    #     Mutation with its argument types. Per the L2 audit
    #     (`docs/proposals/2026-05-27-l2-tool-audit.md` §11) this is
    #     an OSS wrapper, not L2-native — moved here from the L2
    #     catalog. Takes `target_url=`. Returns partial when
    #     introspection is disabled (a hardening posture, not a bug).
    ("map_graphql_inql", _api_target_url_kwargs),
    # 2d. iter-28.4 — auth seed: discover registration endpoint by
    #     shape, register a randomized test account, export captured
    #     JWT/cookie via STRIX_AUTH_BEARER / STRIX_AUTH_COOKIE for
    #     downstream auth-aware specialists (scan_idor,
    #     scan_api_bola, scan_api_bfla, jwt_audit). Universal across
    #     Django/Rails/Express/FastAPI/Spring auth conventions.
    #     Idempotent — no-op when STRIX_AUTH_* already set.
    ("seed_auth", _api_target_url_kwargs),
    # 2e. iter-28.6 — default-credentials probe (pure-python). Tries
    #     top SecLists defaults (admin/admin, root/toor, ...) against
    #     discovered login endpoint. Returns partial when no default
    #     credential accepted.
    #
    #     iter-37.14: now flanked by `probe_default_creds_hydra` (real
    #     hydra binary, broader corpus, retry/parallelism controls).
    #     Both run — the pure-python pass is a cheap fast-path; hydra
    #     catches non-HTTP services (ssh, ftp, mysql, …) and the
    #     long-tail web-form variants. Findings flow through the
    #     iter-35.4 sandbox→host propagation so L1.5 hooks fire either
    #     way.
    ("probe_default_creds", _api_target_url_kwargs),
    ("probe_default_creds_hydra", _api_target_url_kwargs),
    # 2f. iter-37.14 — ffuf content discovery. Catches exposed admin /
    #     debug / .env / .git / actuator / swagger / wp-* paths the
    #     katana crawler doesn't link to. Uses SecLists common.txt
    #     when present + a 40-entry high-signal fallback. Single-URL
    #     contract — emits findings on interesting status codes.
    ("scan_fuzz_ffuf", _api_target_url_kwargs),
    # 2g. iter-37.14 — schemathesis OpenAPI property-based fuzzing.
    #     Reads the spec ingested by openapi_spec_ingest, generates
    #     structurally-valid Hypothesis test cases, fires them at
    #     the API. Catches schema-conformance violations, server
    #     errors on valid inputs, ignored_auth (un-authed 200 on
    #     security: bearer endpoints). Returns partial when no
    #     reachable schema.
    ("scan_api_schemathesis", _api_schema_url_kwargs),
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
    #
    # iter-19+ (2026-05-21) kwarg-name reconciliation:
    #   * scan_secrets_in_response: takes `urls=` (plural list)
    #   * http_security_headers_audit / cors_deep_check / csrf_check
    #     / open_redirect_check: take `target_url=`
    #   * tls_audit: takes `target=`
    # Every web/api fixture in `l1_only_20260521_115852.md` had
    # 5+ of these tools fail with `unexpected keyword argument
    # 'url'` because the prepass uniformly used `_api_url_kwargs`
    # — silently dropped 5 anchor signals per target. Routed below.
    ("scan_secrets_in_response", _api_secrets_in_response_kwargs),
    ("http_security_headers_audit", _api_target_url_kwargs),
    ("tls_audit", _tls_audit_kwargs),
    ("cors_deep_check", _api_target_url_kwargs),
    ("csrf_check", _api_target_url_kwargs),
    ("open_redirect_check", _api_target_url_kwargs),
    # iter-21.3 — deterministic OIDC/OAuth/JWKS metadata audit.
    # Companion to `well_known_harvest` (which just discloses):
    # this probe AUDITS the metadata for `alg: none`, deprecated
    # grants (implicit / password), missing PKCE, HMAC keys leaked
    # in JWKS, sub-2048-bit RSA, weak EC curves, missing kids.
    # Uses `target_url=` like the other audit-style anchors.
    # Returns partial when the target isn't an OIDC/OAuth issuer
    # (no penalty on non-OIDC targets).
    ("scan_authn_metadata", _api_target_url_kwargs),
    # iter-21.6.2 — direct IMDS-passthrough probe. GETs a corpus
    # of 17 known IMDS-proxy paths (`/imds`, `/metadata`,
    # `/debug/imds`, `/.well-known/instance-data`, ...) and
    # fingerprints AWS/GCP/Azure/OCI response bodies. Complements
    # scan_ssrf (which needs a param) for the parameter-less
    # passthrough case.
    ("scan_cloud_imds_passthrough", _api_target_url_kwargs),
    # iter-21.6.1 — multi-cloud bucket discovery via bbot's
    # bucket modules (AWS S3 / GCP GCS / Azure Blob /
    # DigitalOcean Spaces / Firebase / IBM COS). Wraps the bbot
    # CLI; uses target's domain labels + bbot's own DNS / CT-log
    # chaining + wordlists to seed bucket-name candidates.
    # Returns partial when bbot isn't on PATH or target is a
    # bare IP. Replaces the in-house bucket probe from PR #400
    # (reverted via PR #401).
    ("scan_buckets_via_bbot", _api_target_url_kwargs),
    # iter-Q5.3 — deep-exploit OSS wrappers moved from the L2 minimal
    # catalog to prepass. Per CLAUDE.md §1.5 these are L1 detection
    # (the security-team-facing dashboard), not L2 translation work.
    # They were on the LLM-visible catalog only so the lead could
    # choose to fire them; under the L2-CAP invariant + the
    # "tools are the LLM's hands, not its brain" principle they fire
    # deterministically here instead. The L2 lead can still re-fire
    # them on candidates via the future `rescan(tool_name, ...)` (Q5.9).
    #
    # sqlmap: deep SQLi exploit on top of the light scan_sqli signal
    #   above. Takes `target_url=`. Q5.3 lands as opt-in via
    #   STRIX_PREPASS_DEEP_EXPLOITS=0 to skip when bench timing matters.
    ("scan_sqli_sqlmap", _api_target_url_kwargs),
    # smuggler.py: HTTP request-smuggling probes (TE/CL disagreements,
    #   transfer-encoding parsing differentials). Applies to any HTTP
    #   target — kept in _ANCHORS_API since _ANCHORS_WEB = _ANCHORS_API
    #   + [..] so it inherits.
    ("scan_smuggling_smuggler", _api_target_url_kwargs),
    # Tools wired via phase-2 (require runtime-captured state, not
    # just target_value), invoked in `_run_dependent_api_tools`:
    #   * jwt_audit — needs a JWT token. iter-17 auth-flow captures
    #     it from /login; phase-2 calls jwt_audit with the token.
    #   * scan_api_bola / scan_api_bfla / scan_api_mass_assignment /
    #     scan_idor — need `endpoints=list[dict]` from openapi_spec_
    #     ingest + auth state under user-a + user-b labels. iter-18
    #     auth-flow registers both users; phase-2 invokes the
    #     specialists.
    #   * webapp_recon_pipeline — playwright-driven SPA crawl;
    #     phase-2 calls it for web_application targets.
]

_ANCHORS_WEB: list[tuple[str, Any]] = _ANCHORS_API + [
    # Web-only DOM-aware probes.
    #   * scan_xss / scan_cache_deception / scan_websocket_auth /
    #     scan_prototype_pollution: take `url=` (scan_* specialist
    #     family — uniform `url=` interface).
    #   * dom_xss_static_probe: takes `target_url=` (legacy OSS-
    #     corpus signature, not the scan_* family). Caught
    #     2026-05-21 alongside the wider kwarg-mismatch sweep.
    ("scan_xss", _api_url_kwargs),
    ("dom_xss_static_probe", _api_target_url_kwargs),
    ("scan_cache_deception", _api_url_kwargs),
    ("scan_websocket_auth", _api_url_kwargs),
    ("scan_prototype_pollution", _api_url_kwargs),
    # iter-Q5.3 — dalfox moved from L2 minimal to prepass. Web-only
    # (DOM-focused — JSON API endpoints don't generally render into
    # the DOM, so dalfox is wasted there). Takes `target_url=`.
    ("scan_xss_dalfox", _api_target_url_kwargs),
]

_ANCHORS_CONTAINER: list[tuple[str, Any]] = [
    # trivy image with vuln + misconfig + secret scanners enabled.
    # trivy's `--scanners vuln,secret,misconfig,license` already
    # emits component-level SBOM data inline; `sbom_extract` is a
    # web-target tool (takes `target_url`, not `image_ref`) — it was
    # mis-wired here in iter-18 and produced a 100% `unexpected
    # keyword argument 'image_ref'` error on every container_image
    # fixture. Moved to `_ANCHORS_API` where it belongs (extracts
    # CycloneDX SBOM from black-box HTTP recon).
    ("scan_container_image", _container_kwargs),
]


# ---------------------------------------------------------------------------
# iter-Q5.4 — _ANCHORS_IP (was empty; ip_address had no prepass coverage)
# ---------------------------------------------------------------------------

_ANCHORS_IP: list[tuple[str, Any]] = [
    # Service / port fingerprinting — first because every other IP
    # tool benefits from knowing which ports are alive + what's on
    # them. Takes `target=` (IP literal or CIDR).
    ("fingerprint_services_nmap", _ip_target_kwargs),
    # HTTP probe — populates SecurityContext.tech_stack for any IP
    # that serves HTTP/HTTPS. Takes `hosts=` (list, even for single
    # target).
    ("probe_hosts_httpx", _ip_hosts_list_kwargs),
    # nuclei signature corpus on HTTP services. URL synthesized as
    # http://<ip>; templates also probe HTTPS via internal logic.
    ("scan_nuclei_templates", _ip_url_synthesis_kwargs),
    # TLS hygiene + cert audit. tls_audit takes `target=`.
    ("tls_audit", _ip_target_kwargs),
]


# ---------------------------------------------------------------------------
# iter-Q5.5 — _ANCHORS_DOMAIN (was empty; domain had no prepass coverage)
# ---------------------------------------------------------------------------

_ANCHORS_DOMAIN: list[tuple[str, Any]] = [
    # Comprehensive domain pipeline orchestrator (subfinder + bbot +
    # passive DNS + cloud-asset discovery + subdomain takeover).
    # Wraps several other tools so we fire the pipeline once instead
    # of each component. Takes `domain=`.
    ("domain_recon_pipeline", _domain_kwargs),
    # Passive subdomain enumeration (subfinder). Kept alongside the
    # pipeline so isolated subfinder findings still surface when the
    # pipeline returns partial.
    ("enumerate_subdomains_subfinder", _domain_kwargs),
    # iter-Q5.45 — amass (OWASP). Ships in parallel to subfinder;
    # passive by default. Catches subdomains subfinder misses via
    # ASN/BGP enumeration + extra cert-transparency sources. The
    # Q5.44 child-asset extractor already dedupes by host across
    # both enumerators so duplicates don't double-spawn child scans.
    # Operators flip to active mode via `STRIX_AMASS_ACTIVE=1`.
    ("enumerate_subdomains_amass", _domain_kwargs),
    # DNS hygiene posture (checkdmarc): SPF / DKIM / DMARC / MX / CAA
    # / MTA-STS. Always-on for every domain asset.
    ("scan_dns_hygiene_checkdmarc", _domain_kwargs),
    # Typosquat candidates (dnstwist). Generates similar-looking
    # domains + probes which exist.
    ("scan_typosquats_dnstwist", _domain_kwargs),
    # Nuclei against http://<domain> — catches CVE templates that
    # apply to the domain's web frontend.
    ("scan_nuclei_templates", _domain_url_synthesis_kwargs),
]

# iter-21.5 followup: the `_ANCHORS_MOBILE` list + `mobile_app`
# entry below were removed after the user pointed out that the
# upstream pipeline doesn't recognize the asset type — the
# anchor would never have fired. The `scan_mobile_app` tool
# itself stays registered (`strix.tools.mobile_app_audit`) so
# agents can invoke it explicitly; the asset-type wiring
# returns once CLI/preflight/runner support lands.

# Per-target-type anchor lookup. Empty list = "no signature corpus
# applies to this target type; fall through to the lead loop with
# no prepass findings."
_ANCHORS_BY_TARGET_TYPE: dict[str, list[tuple[str, Any]]] = {
    "local_code": _ANCHORS_LOCAL_CODE,
    "repository": _ANCHORS_LOCAL_CODE,
    "api": _ANCHORS_API,
    "web_application": _ANCHORS_WEB,
    "container_image": _ANCHORS_CONTAINER,
    # iter-Q5.4 / Q5.5 — domain + ip_address gained full prepass
    # coverage, replacing what was previously LLM-driven recon via the
    # L2 catalog. Per CLAUDE.md §1.5 — tools are LLM's hands, not its
    # brain; recon fires deterministically.
    "domain": _ANCHORS_DOMAIN,
    "ip_address": _ANCHORS_IP,
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
    endpoint). Dedup happens in the lead loop on top of L1."""
    target_type: str
    target_value: str
    tools_run: list[str] = field(default_factory=list)
    tools_succeeded: list[str] = field(default_factory=list)
    tools_failed: list[str] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    total_findings: int = 0
    wall_time_s: float = 0.0
    skipped_reason: str | None = None
    # iter-Q5.44 — sidecar for domain → child-asset pivoting.
    # Populated by `_extract_child_assets_from_domain_prepass` after
    # `_ANCHORS_DOMAIN` runs. Each entry shape:
    #   {
    #     "host": str,                  # subdomain (no scheme)
    #     "ip": str | None,             # resolved A record
    #     "asset_type": str,            # "web_application" | "ip_address"
    #     "scheme": str | None,         # "http" | "https" if probed
    #     "triage": str | None,         # "deep" | "shallow" if from pipeline
    #     "source": str,                # which tool surfaced it
    #   }
    # Downstream consumers: webappsec wrapper (spawns per-child scan),
    # the L2 lead (sees the list in its system prompt context), and
    # any future asset-graph emitter.
    child_assets_discovered: list[dict[str, Any]] = field(
        default_factory=list,
    )

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
            # iter-Q5.28b — per-tool status + error_reason so the
            # observability block in simulation_run.json reveals WHY
            # a tool failed, not just THAT it failed. Without this,
            # the iter-Q5.27 bench's "5/5 tools failed, 0 findings"
            # was opaque — we couldn't tell sandbox provisioning
            # from semgrep-missing from argument-validation-error.
            "tool_results": [
                {
                    "tool_name": r.tool_name,
                    "status": r.status,
                    "findings_count": r.findings_count,
                    "error_reason": r.error_reason,
                    "wall_time_s": round(r.wall_time_s, 2),
                }
                for r in self.tool_results
            ],
            # iter-Q5.44 — child-asset sidecar. Empty list when the
            # apex has no children OR target_type wasn't `domain`.
            "child_assets_discovered": list(self.child_assets_discovered),
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


# iter-35.1 — host-side katana crawl helper REMOVED.
#
# It was a host subprocess shell-out to the katana binary on the host
# PATH that bypassed the sandbox boundary (host PATH dependency,
# inconsistent network policy) and iter-32.1's
# `record_endpoint_discovered` hook (visibility gap — the bench
# reported `endpoints_discovered_total=0` even when katana found
# endpoints).
#
# Callers now route through the registered `crawl_with_katana` tool
# via the executor's HTTP dispatcher → sandbox tool-server →
# in-container katana binary. The registered tool already calls
# `record_endpoint_discovered` per iter-32.1 + emits to KG.
#
# See CLAUDE.md §3 for the host-vs-sandbox boundary specification.


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


# ---------------------------------------------------------------------------
# Iter-13 — ip_address probes (network surface mapping)
# ---------------------------------------------------------------------------
#
# ip_address targets have no signature corpus that takes a bare IP as
# input — the existing scan_* specialists want a URL (http://x/...).
# This bundle of host-runnable TCP probes closes the gap for the three
# canonical L1 findings on a network target:
#
#   * unauthenticated service exposure (Redis, MongoDB, memcached…)
#     — direct TCP send + parse the protocol's "are you authenticated"
#     response. No third-party deps.
#   * HTTP service discovery — connect_ex over the well-known web
#     ports; for each open one, run HTTP-probe class probes (autoindex,
#     server-version header).
#   * Anonymous-friendly FTP — connect, USER anonymous, parse banner.
#
# Coverage targets: ip/vulnerable-services fixture's must_finds
# (redis-no-auth, nginx-autoindex, nginx-version-disclosure). Without
# this, ip_address recall is structurally 0.

# Conservative port set — top-25 service ports that map to concrete
# probes below. Adding more bloats the scan time without changing
# what we can actually CHECK in code. nmap-style full /24 sweeps
# are out of scope for L1; iter-13 is "stuff the per-target prepass
# can actually act on."
_IP_COMMON_PORTS: list[int] = [
    21,    # FTP
    22,    # SSH
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    993,   # IMAPS
    995,   # POP3S
    1521,  # Oracle
    3306,  # MySQL
    3389,  # RDP
    5432,  # Postgres
    5984,  # CouchDB
    6379,  # Redis
    8000,  # HTTP alt
    8080,  # HTTP alt
    8443,  # HTTPS alt
    8888,  # HTTP alt
    9200,  # Elasticsearch
    9300,  # Elasticsearch internal
    11211, # memcached
    27017, # MongoDB
]
_IP_HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888}

# iter-Q5.43 — per-port nuclei tag routing. Each open port maps to the
# nuclei template tag set that template-corpus authors use for that
# service. Without this, nuclei runs the FULL ~5000-template corpus
# against every port; with routing, each port sees ~20-100 templates
# specific to its service. Massive speedup + better signal-to-noise.
#
# Reference: nuclei-templates `tags:` field convention.
_IP_PORT_TO_NUCLEI_TAGS: dict[int, tuple[str, ...]] = {
    21:    ("ftp",),
    22:    ("ssh", "openssh"),
    23:    ("telnet",),
    25:    ("smtp", "mail"),
    53:    ("dns",),
    80:    ("http", "tech", "default-login"),
    110:   ("pop3", "mail"),
    143:   ("imap", "mail"),
    161:   ("snmp",),
    389:   ("ldap",),
    443:   ("https", "tls", "ssl", "tech", "default-login"),
    445:   ("smb", "cifs"),
    465:   ("smtp", "mail"),
    587:   ("smtp", "mail"),
    636:   ("ldap", "ssl"),
    993:   ("imap", "mail", "ssl"),
    995:   ("pop3", "mail", "ssl"),
    1433:  ("mssql",),
    1521:  ("oracle",),
    1883:  ("mqtt",),
    2049:  ("nfs",),
    3306:  ("mysql",),
    3389:  ("rdp",),
    5432:  ("postgres", "postgresql"),
    5900:  ("vnc",),
    5984:  ("couchdb",),
    6379:  ("redis",),
    8000:  ("http", "tech", "default-login"),
    8080:  ("http", "tech", "tomcat", "jenkins", "default-login"),
    8443:  ("https", "tls", "ssl", "tech", "default-login"),
    8888:  ("http", "tech"),
    9000:  ("http", "sonarqube"),
    9092:  ("kafka",),
    9200:  ("elastic", "elasticsearch"),
    9300:  ("elastic",),
    11211: ("memcached",),
    15672: ("rabbitmq",),
    27017: ("mongodb",),
    27018: ("mongodb",),
}


def _ip_port_routing_enabled() -> bool:
    """iter-Q5.43 — opt-out via STRIX_IP_PORT_ROUTING=0 (ablation).
    Default ON; per-port nuclei tag-filter is the structural correct
    behavior. Disable to measure routing's effect on bench runs."""
    raw = (os.environ.get("STRIX_IP_PORT_ROUTING") or "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    return True


def _nuclei_tags_for_port(port: int) -> list[str]:
    """Tags the nuclei template corpus uses for this port's service.
    Empty list signals 'no specific tag — let nuclei pick from the
    generic http/tech set'."""
    return list(_IP_PORT_TO_NUCLEI_TAGS.get(port, ()))


def _nuclei_url_for_port(host: str, port: int) -> str:
    """Construct the right nuclei target URL for a host:port pair.

    HTTP-range ports get full URLs (http://host:port/, https://host:port/).
    Network-protocol ports use the bare host:port form that nuclei's
    network templates parse. The caller passes this as the `url=` kwarg
    on scan_nuclei_templates."""
    host = host.strip().lower()
    if port in {443, 8443, 9443}:
        return f"https://{host}:{port}/"
    if port in _IP_HTTP_PORTS:
        return f"http://{host}:{port}/"
    return f"{host}:{port}"


def probe_open_tcp_ports(
    target_ip: str, ports: list[int] | None = None, timeout: float = 1.0,
) -> list[int]:
    """Return the subset of `ports` that accept a TCP connection on
    `target_ip` within `timeout`. Used to gate the per-service probes
    so we don't waste time on closed ports."""
    import socket
    ports = ports or list(_IP_COMMON_PORTS)
    open_ports: list[int] = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((target_ip, port)) == 0:
                open_ports.append(port)
        except (OSError, socket.gaierror):
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass
    return open_ports


def probe_redis_no_auth(
    target_ip: str, port: int = 6379, timeout: float = 2.0,
) -> list[dict[str, Any]]:
    """Send `INFO\\r\\n` to Redis on `port`. A clean response means
    auth is OFF. A NOAUTH error means auth is on (safe).

    Catches `ip/vulnerable-services` redis-no-auth must_find.
    """
    import socket
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as s:
            s.sendall(b"INFO\r\n")
            data = s.recv(4096)
    except (OSError, socket.timeout):
        return []
    if not data:
        return []
    text = data.decode("utf-8", errors="replace")
    # `-NOAUTH Authentication required` → auth IS configured (safe)
    if "NOAUTH" in text or "authentication required" in text.lower():
        return []
    # Real INFO response starts with `$<len>\r\n# Server\r\nredis_version:...`
    # or `+OK` for some commands. Any `redis_version:` substring
    # confirms we're talking to redis AND we got past auth.
    if "redis_version:" not in text and not text.startswith("$"):
        return []
    return [{
        "title": f"Redis on port {port} accepts INFO without authentication",
        "category": "misconfig",
        "cwe": "CWE-306",
        "port": port,
        "endpoint": f"redis://{target_ip}:{port}/",
        "severity": "critical",
        "description": (
            f"The Redis instance on {target_ip}:{port} accepts the "
            f"INFO command without authentication. An attacker can "
            f"read configuration, dump keys, and (with FLUSHALL / "
            f"CONFIG SET dir + SAVE) achieve RCE on most stock "
            f"setups. Set `requirepass` in redis.conf, or restrict "
            f"the port to localhost / authenticated peers."
        ),
        "verification_status": "verified",
        "confidence": 0.95,
    }]


def probe_http_port(
    target_ip: str, port: int, *, scheme: str = "http", timeout: float = 3.0,
) -> list[dict[str, Any]]:
    """Probe one HTTP port for:
      * autoindex / directory-listing at common upload-paths
      * Server: header version disclosure
      * X-Powered-By disclosure

    Returns one finding per detected issue. Each finding carries the
    `port` field so the scorer can match against IP-target expecteds.
    """
    import urllib.request
    import urllib.error
    base = f"{scheme}://{target_ip}:{port}"
    out: list[dict[str, Any]] = []

    # ----- Server-header disclosure -----
    try:
        req = urllib.request.Request(base + "/", method="HEAD")
        resp = urllib.request.urlopen(req, timeout=timeout)
        headers = dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            headers = dict(e.headers)
        except AttributeError:
            headers = {}
    except (OSError, urllib.error.URLError):
        return out
    # Server header — flag when it includes a version digit.
    import re
    server_header = (
        headers.get("Server") or headers.get("server") or ""
    )
    has_version = bool(re.search(r"\d+\.\d+", server_header))
    if server_header and has_version:
        out.append({
            "title": f"Server header discloses version: {server_header}",
            "category": "info_disclosure",
            "cwe": "CWE-200",
            "port": port,
            "endpoint": base + "/",
            "severity": "low",
            "description": (
                f"The HTTP response from {base}/ includes a Server "
                f"header containing version information: "
                f"`{server_header}`. An attacker can correlate the "
                f"version with public CVEs. For nginx, set "
                f"`server_tokens off;`. For Apache, "
                f"`ServerTokens Prod`. For node/express, override "
                f"the X-Powered-By + Server headers explicitly."
            ),
            "verification_status": "verified",
            "confidence": 0.9,
        })
    # X-Powered-By disclosure
    xpb = headers.get("X-Powered-By") or headers.get("x-powered-by") or ""
    if xpb:
        out.append({
            "title": f"X-Powered-By header discloses framework: {xpb}",
            "category": "info_disclosure",
            "cwe": "CWE-200",
            "port": port,
            "endpoint": base + "/",
            "severity": "low",
            "description": (
                f"The HTTP response from {base}/ includes an "
                f"X-Powered-By header: `{xpb}`. Strip this header "
                f"from the response — it gives attackers free "
                f"reconnaissance with no functional benefit."
            ),
            "verification_status": "verified",
            "confidence": 0.95,
        })

    # ----- Directory listing on common paths -----
    autoindex_paths = [
        "/uploads/", "/files/", "/backup/", "/downloads/",
        "/static/", "/data/", "/ftp/", "/",
    ]
    for path in autoindex_paths:
        try:
            req = urllib.request.Request(base + path)
            resp = urllib.request.urlopen(req, timeout=timeout)
            body = resp.read(8192)
        except urllib.error.HTTPError:
            continue
        except (OSError, urllib.error.URLError):
            continue
        body_l = body.lower()
        is_autoindex = (
            b"index of /" in body_l
            or b"<title>index of" in body_l
            or (b"parent directory" in body_l and b"<a href=" in body_l)
        )
        if is_autoindex:
            out.append({
                "title": f"Directory listing exposed at {path} on port {port}",
                "category": "misconfig",
                "cwe": "CWE-548",
                "port": port,
                "endpoint": base + path,
                "severity": "medium",
                "description": (
                    f"The path `{path}` on {base} returns a directory "
                    f"listing. Attackers can enumerate uploaded files "
                    f"and discover sensitive content. Disable autoindex "
                    f"(nginx: `autoindex off;`, Apache: "
                    f"`Options -Indexes`)."
                ),
                "verification_status": "verified",
                "confidence": 0.95,
            })
            break  # one autoindex finding per port; don't double-flag
    return out


def probe_ftp_anonymous(
    target_ip: str, port: int = 21, timeout: float = 3.0,
) -> list[dict[str, Any]]:
    """Connect to FTP on `port` and try anonymous login.

    Returns a finding when USER anonymous + PASS anonymous yields a
    230 response (login OK).
    """
    import socket
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as s:
            banner = s.recv(2048)
            if not banner.startswith(b"220"):
                return []
            s.sendall(b"USER anonymous\r\n")
            user_resp = s.recv(2048)
            # `331` = need password. Accept either 230 (no pw needed)
            # or 331 (then we send password).
            if user_resp.startswith(b"230"):
                # Already logged in — anonymous accepted, no pw.
                pass
            elif user_resp.startswith(b"331"):
                s.sendall(b"PASS anonymous@example.com\r\n")
                pass_resp = s.recv(2048)
                if not pass_resp.startswith(b"230"):
                    return []
            else:
                return []
    except (OSError, socket.timeout):
        return []

    return [{
        "title": f"FTP anonymous login accepted on port {port}",
        "category": "misconfig",
        "cwe": "CWE-732",
        "port": port,
        "endpoint": f"ftp://{target_ip}:{port}/",
        "severity": "medium",
        "description": (
            f"The FTP server on {target_ip}:{port} accepts the "
            f"anonymous user with no real password. Attackers can "
            f"download anything the FTP root user can read. Disable "
            f"anonymous access in the FTP daemon config, or restrict "
            f"the port to authenticated users only."
        ),
        "verification_status": "verified",
        "confidence": 0.9,
    }]


async def _run_dependent_ip_tools(
    summary: PrepassSummary,
    *,
    target_value: str,
    agent_state: Any = None,
    timeout_s: int = 60,
) -> None:
    """Phase-2 dispatcher for ip_address targets.

    Runs:
      1. probe_open_tcp_ports — discovers open ports from the
         _IP_COMMON_PORTS set
      2. For each open port: targeted per-service probe
         (Redis INFO, HTTP autoindex+banner, FTP anon)

    Mutates `summary` in place. Never raises.

    iter-35.2 — every probe dispatches through `_run_one_tool` so the
    raw socket / urllib / ftplib calls fire inside the sandbox
    container's network namespace, not on the host. The host-side
    function bodies still live in this module; the sandbox tool_server
    lazy-imports them via the wrappers in `strix.tools.anchor_probes`.
    """
    # Step 1: port discovery.
    port_result = await _run_one_tool(
        "probe_open_tcp_ports",
        {"target_value": target_value},
        agent_state=agent_state, timeout_s=timeout_s,
    )
    raw = port_result.raw_result if isinstance(port_result.raw_result, dict) else {}
    open_ports: list[int] = list(raw.get("open_ports") or [])
    # Preserve the original tool_results.append shape (with the
    # human-readable error_reason summarising the open ports).
    summary.tools_run.append("probe_open_tcp_ports")
    summary.tools_succeeded.append("probe_open_tcp_ports")
    summary.tool_results.append(ToolResult(
        tool_name="probe_open_tcp_ports",
        status="ok",
        findings_count=0,  # not a finding-emitting probe
        error_reason=(
            f"open ports: {','.join(str(p) for p in open_ports)}"
            if open_ports else "no open ports in common set"
        ),
        wall_time_s=port_result.wall_time_s,
        raw_result={"open_ports": open_ports, "findings": []},
    ))
    if not open_ports:
        return

    # Step 2: per-port probes. Each is dispatched via _run_one_tool
    # so the socket / urllib / ftplib I/O fires in the sandbox.
    async def _dispatch_and_record(
        tool_name: str, kwargs: dict[str, Any], record_as: str | None = None,
    ) -> None:
        result = await _run_one_tool(
            tool_name, kwargs,
            agent_state=agent_state, timeout_s=timeout_s,
        )
        label = record_as or tool_name
        summary.tools_run.append(label)
        if result.status == "ok":
            summary.tools_succeeded.append(label)
        summary.tool_results.append(ToolResult(
            tool_name=label,
            status=result.status,
            findings_count=result.findings_count,
            error_reason=result.error_reason,
            wall_time_s=result.wall_time_s,
            raw_result=result.raw_result,
        ))
        summary.total_findings += result.findings_count

    # 2a — Redis (port 6379 typical).
    if 6379 in open_ports:
        await _dispatch_and_record(
            "probe_redis_no_auth",
            {"target_value": target_value, "port": 6379},
        )

    # 2b — HTTP ports. Try both http and https schemes.
    for port in open_ports:
        if port not in _IP_HTTP_PORTS:
            continue
        scheme = "https" if port in {443, 8443} else "http"
        await _dispatch_and_record(
            "probe_http_port",
            {"host": target_value, "port": port, "scheme": scheme},
            record_as=f"probe_http_port[{port}]",
        )

    # 2c — FTP (port 21).
    if 21 in open_ports:
        await _dispatch_and_record(
            "probe_ftp_anonymous",
            {"target_value": target_value, "port": 21},
        )

    # iter-Q5.43 — 2d: per-port nuclei dispatch with service-specific tag
    # filters. Without this, nuclei runs ~5000 templates against every
    # port; with routing each port sees ~20-100 templates relevant to
    # its detected service. ~50x speedup + better signal-to-noise.
    # STRIX_IP_PORT_ROUTING=0 ablates routing (every open port gets the
    # full template corpus — slow but maximally exhaustive).
    if _ip_port_routing_enabled():
        routed_count = 0
        unrouted_count = 0
        for port in open_ports:
            tags = _nuclei_tags_for_port(port)
            if not tags:
                unrouted_count += 1
                continue
            await _dispatch_and_record(
                "scan_nuclei_templates",
                {
                    "url": _nuclei_url_for_port(target_value, port),
                    "tags": tags,
                },
                record_as=f"scan_nuclei_templates[port-{port}]",
            )
            routed_count += 1
        if routed_count or unrouted_count:
            logger.info(
                "ip per-port nuclei routing: dispatched=%d ports, "
                "unrouted=%d ports (no port→tag mapping)",
                routed_count, unrouted_count,
            )
    else:
        # Ablation: single nuclei against the seed (no port-specific tags).
        await _dispatch_and_record(
            "scan_nuclei_templates",
            {"url": f"http://{target_value}/"},
            record_as="scan_nuclei_templates[ablation]",
        )


# ---------------------------------------------------------------------------
# Iter-17 — deterministic auth-flow for API targets
# ---------------------------------------------------------------------------
#
# Two-part architecture (per design discussion 2026-05-21):
#
#   Part 1 — Auth into L1 deterministically.
#     The OpenAPI spec already advertises /register + /login on most
#     modern APIs (vampi: /users/v1/register + /users/v1/login;
#     crapi: /identity/api/auth/signup + /identity/api/auth/login).
#     We can synthesize a working credential without an LLM by
#     building the documented register body, POSTing it, then doing
#     the same for login, and parsing the response for a token /
#     cookie / session field. The captured AuthState is then plumbed
#     into every downstream specialist that accepts extra_headers=.
#
#   Part 2 — OpenAPI spec is scope, not just discovery.
#     openapi_spec_ingest emits `endpoints[]` with full params + body
#     schema. Combined with the AuthState from Part 1, the bare-URL
#     signature scanners (scan_sqli, scan_ssrf, scan_path_traversal,
#     scan_nosql_injection, scan_cmd_injection, scan_xxe) stop
#     returning `partial="no params"` and actually exercise the
#     injection sinks. That's the bulk of the api-recall jump from
#     ~0.375 to ~0.875 on vampi.
#
# Without these, every "deterministic" auth-required specialist in
# the strix toolbox is dead code at L1.


@dataclass
class AuthState:
    """Captured auth context from the L1 auth-flow step.

    `header_name` / `token` are populated when the login response
    yields a Bearer-style JWT or API key. `cookies` is populated
    when the server uses Set-Cookie (session-based auth). Both
    can be present; the downstream caller forwards whatever's set."""
    token: str = ""
    header_name: str = "Authorization"
    header_value: str = ""    # e.g. "Bearer <token>" — pre-formatted
    cookies: dict[str, str] = field(default_factory=dict)
    username: str = ""
    password: str = ""
    register_endpoint: str = ""
    login_endpoint: str = ""

    @property
    def is_valid(self) -> bool:
        return bool(self.header_value) or bool(self.cookies)

    def as_headers(self) -> dict[str, str]:
        """Return the dict you'd pass as extra_headers= to a probe."""
        h: dict[str, str] = {}
        if self.header_value:
            h[self.header_name] = self.header_value
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        return h


@dataclass
class AuthEndpoints:
    register: dict[str, Any] | None = None
    login: dict[str, Any] | None = None


def _discover_auth_endpoints(
    endpoints: list[Any] | None,
) -> AuthEndpoints:
    """Find register + login endpoints from the openapi-emitted list.

    Heuristic: path contains `register` / `signup` / `sign_up`
    (case-insensitive) for register; `login` / `signin` / `sign_in` /
    `authenticate` for login. Prefer POST methods; require a body
    schema if available.

    Returns AuthEndpoints with possibly-None fields. Caller checks
    `register` and `login` before invoking the flow.
    """
    eps = AuthEndpoints()
    if not endpoints:
        return eps
    REG_KW = ("register", "signup", "sign_up", "sign-up", "create_user", "create-user")
    LOG_KW = ("login", "signin", "sign_in", "sign-in", "authenticate", "auth/login")
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        path = (ep.get("path") or "").lower()
        method = (ep.get("method") or "GET").upper()
        if method != "POST":
            continue
        if eps.register is None and any(k in path for k in REG_KW):
            eps.register = ep
        elif eps.login is None and any(k in path for k in LOG_KW):
            eps.login = ep
        if eps.register and eps.login:
            break
    return eps


# Static well-known auth-endpoint paths to probe when the openapi
# spec didn't yield register+login. Targeted at APIs that publish
# their spec behind auth (crapi: openapi requires bearer token →
# circular, can't discover register/login from the spec we can't
# read without a token).
#
# Listed in priority order — first 2xx response wins. Note that
# each entry is a (register_path, login_path) pair so we can co-
# locate the discovery on a service prefix.
_STATIC_AUTH_PATH_PAIRS: tuple[tuple[str, str], ...] = (
    # crapi-style identity service prefix
    ("/identity/api/auth/signup", "/identity/api/auth/login"),
    # generic /api/auth/
    ("/api/auth/register", "/api/auth/login"),
    ("/api/auth/signup", "/api/auth/login"),
    ("/api/auth/signup", "/api/auth/signin"),
    # versioned /api/v1
    ("/api/v1/auth/register", "/api/v1/auth/login"),
    ("/api/v1/register", "/api/v1/login"),
    ("/api/v1/users/register", "/api/v1/users/login"),
    ("/v1/register", "/v1/login"),
    ("/v1/auth/signup", "/v1/auth/login"),
    # generic root-level
    ("/api/register", "/api/login"),
    ("/api/signup", "/api/login"),
    ("/auth/register", "/auth/login"),
    ("/auth/signup", "/auth/login"),
    ("/register", "/login"),
    ("/signup", "/login"),
    ("/signup", "/signin"),
)


def _build_static_auth_body() -> tuple[dict[str, Any], str, str]:
    """Construct a generic register body that satisfies the most
    common API contracts (email + password + name + number).
    Used by the static-path fallback when we don't have a schema
    to follow.

    Returns (body, username, password). The username/password are
    returned separately so the caller can re-use them for /login.
    """
    import random as _random
    import string as _string
    username = (
        "strix_sf_"
        + "".join(_random.choices(_string.ascii_lowercase, k=8))
    )
    password = (
        "Strix_SF_"
        + "".join(_random.choices(_string.ascii_letters + _string.digits, k=10))
        + "!Aa1"
    )
    # Generic body covering: email + password + name (first/last) +
    # number/phone. Most signup endpoints across the API top-10
    # benchmark targets accept this superset.
    # Phone number is randomized to avoid uniqueness collisions
    # (crapi rejects duplicate phone with 403).
    phone = "555" + "".join(_random.choices("0123456789", k=7))
    body = {
        "email": f"{username}@strix-bench.local",
        "password": password,
        "name": "Strix Bench",
        "firstName": "Strix",
        "lastName": "Bench",
        "first_name": "Strix",
        "last_name": "Bench",
        "username": username,
        "number": phone,
        "phone": phone,
        "phone_number": phone,
    }
    return body, username, password


def _discover_auth_via_static_paths(
    target_value: str,
) -> AuthEndpoints | None:
    """Fallback when the openapi spec is unavailable or auth-walled
    (e.g. crapi 1.1.6-rc8 serves `/identity/v3/api-docs` behind a
    bearer token — circular: can't fetch spec without auth, can't
    auth without spec discovery).

    Strategy: POST a generic register body to each candidate
    register path. First one that returns 2xx → use that
    register path + the sibling login path.

    Returns AuthEndpoints synthesised from the discovered paths,
    or None when no candidate worked.
    """
    import json as _json
    from urllib.parse import urlparse
    # CRITICAL: drop any path from target_value before appending
    # static auth paths. Bench fixtures often set target to e.g.
    # `http://localhost:8888/identity/api/v2` — without stripping
    # the path we'd build URLs like `.../identity/api/v2/identity/
    # api/auth/signup` which 404. Caught 2026-05-21 during iter-17.6
    # crapi validation.
    try:
        parsed = urlparse(target_value)
        if parsed.scheme and parsed.netloc:
            base = f"{parsed.scheme}://{parsed.netloc}"
        else:
            base = target_value.rstrip("/")
    except Exception:  # noqa: BLE001
        base = target_value.rstrip("/")
    body, _username, _password = _build_static_auth_body()
    data = _json.dumps(body).encode()
    for reg_path, login_path in _STATIC_AUTH_PATH_PAIRS:
        reg_url = base + reg_path
        try:
            resp = _http_request(
                reg_url, method="POST", timeout=6.0,
                headers={"Content-Type": "application/json"},
                data=data,
            )
            status = (
                getattr(resp, "status", getattr(resp, "code", None))
                if resp else None
            )
        except Exception:  # noqa: BLE001
            continue
        # 2xx: register accepted. 4xx with body mentioning the
        # MISSING fields would be useful but we don't parse here.
        # 400-class is also a positive signal that the endpoint
        # EXISTS — vs 404 which means it doesn't.
        if not status:
            continue
        if status == 404:
            continue
        # Treat 2xx, 400 (validation error), 409 (already exists),
        # 422 (unprocessable) as "endpoint exists" — log and use
        # for login probing.
        if status >= 500:
            continue
        # Endpoint exists. Synthesise endpoint dicts compatible
        # with _build_schema_driven_body (no schema → uses the
        # static body via fallback path in _run_auth_flow).
        synthetic_reg = {
            "url": reg_url,
            "path": reg_path,
            "method": "POST",
            "params": [],
            "request_body_schema": None,
            "auth_required": False,
            "source": "static_path_discovery",
        }
        synthetic_login = {
            "url": base + login_path,
            "path": login_path,
            "method": "POST",
            "params": [],
            "request_body_schema": None,
            "auth_required": False,
            "source": "static_path_discovery",
        }
        return AuthEndpoints(register=synthetic_reg, login=synthetic_login)
    return None


def _build_schema_driven_body(
    endpoint: dict[str, Any],
    *,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    """Construct a JSON body that satisfies an endpoint's
    request_body_schema.

    The L1 contract: every documented `required` field gets a value
    that matches its declared type + format. We DON'T try to satisfy
    complex `pattern` / `enum` constraints — most register endpoints
    use plain string + email + password formats. When the spec is
    underspecified (no properties), return an empty dict and the
    server will tell us what's missing via 422 (caller can log).

    Convention:
      * field name contains `email` or format=email → email string
      * field name contains `password` → strong password
      * field name contains `username` / `user` → the supplied username
      * type=string → "strix_bench_{field}_{rand}"
      * type=integer → 1
      * type=boolean → False
      * type=number → 1.0
      * type=array → []
      * type=object → {}
      * unknown → ""
    """
    import random as _random
    import string as _string

    username = username or (
        "strix_bench_"
        + "".join(_random.choices(_string.ascii_lowercase, k=8))
    )
    password = password or (
        "Strix_Bench_"
        + "".join(_random.choices(_string.ascii_letters + _string.digits, k=12))
        + "!"
    )
    schema = endpoint.get("request_body_schema") or {}
    if not isinstance(schema, dict):
        schema = {}
    props = schema.get("properties") or {}
    if not isinstance(props, dict) or not props:
        # No schema available (e.g. static-path discovery fallback
        # where we don't know the endpoint's body shape). Return a
        # superset body covering the most common register/login
        # contracts.
        #
        # CRITICAL: the phone number must be RANDOMIZED per call.
        # Crapi-style APIs enforce uniqueness on `number` field
        # (caught 2026-05-21 — every retry was hitting "Number
        # already registered" because the static discovery probe
        # registered with one phone, then the main auth_flow re-
        # registered with the same phone). Use the username's hash
        # to derive a deterministic phone for this username, so
        # retries with the same username use the same phone.
        import random as _random
        phone = "555" + "".join(_random.choices("0123456789", k=7))
        return {
            "email": f"{username}@strix-bench.local",
            "password": password,
            "name": "Strix Bench",
            "firstName": "Strix",
            "lastName": "Bench",
            "first_name": "Strix",
            "last_name": "Bench",
            "username": username,
            "number": phone,
            "phone": phone,
            "phone_number": phone,
        }
    body: dict[str, Any] = {}
    for fname, fmeta in props.items():
        if not isinstance(fname, str):
            continue
        meta = fmeta if isinstance(fmeta, dict) else {}
        ftype = (meta.get("type") or "string").lower()
        ffmt = (meta.get("format") or "").lower()
        lower_name = fname.lower()
        # Email-shaped field
        if "email" in lower_name or ffmt == "email":
            body[fname] = f"{username}@strix-bench.local"
            continue
        # Password-shaped field
        if "password" in lower_name or "pwd" in lower_name or ffmt == "password":
            body[fname] = password
            continue
        # Username-shaped field
        if lower_name in ("username", "user", "login", "name") or "username" in lower_name:
            body[fname] = username
            continue
        # First name / last name (crapi requires these on signup)
        if "first" in lower_name and "name" in lower_name:
            body[fname] = "Strix"
            continue
        if "last" in lower_name and "name" in lower_name:
            body[fname] = "Bench"
            continue
        # Phone number (crapi: `number`)
        if "phone" in lower_name or lower_name == "number" or lower_name == "phone_number":
            body[fname] = "5551230000"
            continue
        # Generic by type
        if ftype == "string":
            body[fname] = f"strix_bench_{fname}_{_random.randint(1000, 9999)}"
        elif ftype == "integer":
            body[fname] = 1
        elif ftype == "boolean":
            body[fname] = False
        elif ftype == "number":
            body[fname] = 1.0
        elif ftype == "array":
            body[fname] = []
        elif ftype == "object":
            body[fname] = {}
        else:
            body[fname] = ""
    return body


def _extract_auth_from_response(resp: Any) -> tuple[str, str, dict[str, str]]:
    """Parse the login response for token / cookie. Returns
    (header_name, header_value, cookies). All empty when no auth
    material found.
    """
    import json as _json
    if resp is None:
        return ("", "", {})
    cookies: dict[str, str] = {}
    try:
        set_cookie = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else None
    except Exception:  # noqa: BLE001
        set_cookie = None
    if not set_cookie:
        try:
            sc = resp.headers.get("Set-Cookie")
            set_cookie = [sc] if sc else []
        except Exception:  # noqa: BLE001
            set_cookie = []
    for sc in (set_cookie or []):
        if not sc:
            continue
        # Take only "k=v" before the first `;`.
        first = sc.split(";", 1)[0].strip()
        if "=" in first:
            k, v = first.split("=", 1)
            if k and v:
                cookies[k.strip()] = v.strip()

    # Parse body for token-shaped fields. Look for common names.
    try:
        body = resp.read(4096)
    except Exception:  # noqa: BLE001
        body = b""
    text = body.decode("utf-8", errors="replace") if body else ""
    token = ""
    if text:
        try:
            parsed = _json.loads(text)
        except (ValueError, _json.JSONDecodeError):
            parsed = None
        if isinstance(parsed, dict):
            # Try common token field names (case-insensitive)
            for key_candidate in (
                "access_token", "accessToken", "token", "jwt", "auth_token",
                "authToken", "id_token", "idToken", "Authorization",
                "authorization", "session_token", "sessionToken",
            ):
                v = parsed.get(key_candidate)
                if isinstance(v, str) and v:
                    token = v
                    break
            # Nested under `data.token` / `result.token` / etc.
            if not token:
                for outer in ("data", "result", "user", "auth"):
                    sub = parsed.get(outer)
                    if isinstance(sub, dict):
                        for key_candidate in ("token", "jwt", "access_token", "accessToken"):
                            v = sub.get(key_candidate)
                            if isinstance(v, str) and v:
                                token = v
                                break
                    if token:
                        break

    # Bearer prefix when token looks like JWT (3 base64-segments)
    header_name = "Authorization"
    header_value = ""
    if token:
        if token.count(".") == 2:
            header_value = f"Bearer {token}"
        elif token.lower().startswith("bearer "):
            header_value = token
        else:
            # API-key-style — try Authorization: <token> raw
            header_value = f"Bearer {token}"
    return (header_name, header_value, cookies)


async def _run_auth_flow(
    summary: PrepassSummary,
    *,
    endpoints: list[Any] | None,
    target_value: str,
) -> AuthState | None:
    """Discover register + login endpoints, POST schema-driven
    bodies, capture token / cookies. Returns AuthState on success
    or None when no auth endpoints discovered / login failed.

    Best-effort: every step is wrapped; any failure returns None
    so downstream callers fall back to unauth probing.

    Records a synthetic ToolResult so the bench breakdown shows
    the auth-flow ran + whether it captured a token.
    """
    import json as _json
    state: AuthState = AuthState()

    auth_eps = _discover_auth_endpoints(endpoints)
    if not auth_eps.login:
        # Spec didn't yield a /login — try the static-path fallback
        # (crapi 1.1.6-rc8 serves its openapi spec behind a bearer
        # token; can't read the spec without auth, can't auth
        # without spec discovery — circular).
        static_eps = _discover_auth_via_static_paths(target_value)
        if static_eps is not None:
            auth_eps = static_eps
    if not auth_eps.login:
        summary.tools_run.append("probe_auth_flow")
        summary.tools_succeeded.append("probe_auth_flow")
        summary.tool_results.append(ToolResult(
            tool_name="probe_auth_flow",
            status="ok",
            findings_count=0,
            error_reason=(
                "no /login endpoint discovered in spec or static "
                "fallback paths"
            ),
            wall_time_s=0.0,
            raw_result={"findings": [], "status": "ok", "auth_state": None},
        ))
        return None

    # Build credentials for user-a (the primary captured user).
    import random as _random
    import string as _string
    state.username = (
        "strix_bench_"
        + "".join(_random.choices(_string.ascii_lowercase, k=8))
    )
    state.password = (
        "Strix_Bench_"
        + "".join(_random.choices(_string.ascii_letters + _string.digits, k=12))
        + "!"
    )

    # Helper: do one register+login cycle for a given user, return
    # (token_or_empty, cookies). Extracted so we can run TWICE — once
    # for user-a (the primary auth-state) and once for user-b (the
    # cross-session counterpart that BOLA/BFLA/IDOR probes need).
    # iter-18: previously we registered ONE user and reused that token
    # under both user-a + user-b labels. BOLA probes then degenerate
    # to "same user accessing their own resources" → 0 BOLA findings.
    # Now user-b is a DIFFERENT account → real cross-session probing.
    def _do_register_then_login(
        username: str, password: str,
    ) -> tuple[str, dict[str, str]]:
        if auth_eps.register:
            try:
                reg_body = _build_schema_driven_body(
                    auth_eps.register, username=username, password=password,
                )
                reg_url_inner = auth_eps.register.get("url") or (
                    target_value.rstrip("/") + (auth_eps.register.get("path") or "")
                )
                _http_request(
                    reg_url_inner, method="POST", timeout=8.0,
                    headers={"Content-Type": "application/json"},
                    data=_json.dumps(reg_body).encode(),
                )
            except Exception:  # noqa: BLE001
                pass
        login_url_inner = auth_eps.login.get("url") or (
            target_value.rstrip("/") + (auth_eps.login.get("path") or "")
        )
        try:
            login_body = _build_schema_driven_body(
                auth_eps.login, username=username, password=password,
            )
            resp = _http_request(
                login_url_inner, method="POST", timeout=8.0,
                headers={"Content-Type": "application/json"},
                data=_json.dumps(login_body).encode(),
            )
            status = getattr(resp, "status", getattr(resp, "code", None))
            if status and 200 <= status < 300:
                _, hdr_val, ck = _extract_auth_from_response(resp)
                return (hdr_val, ck)
        except Exception:  # noqa: BLE001
            pass
        return ("", {})

    # Step 1 — register + login user-a (primary)
    # Compute login_url once for use in downstream logs / notes /
    # finding endpoints. Falls back to the constructed URL if the
    # endpoint dict doesn't carry the absolute `url`.
    login_url = (
        auth_eps.login.get("url")
        or (target_value.rstrip("/") + (auth_eps.login.get("path") or ""))
    ) if auth_eps.login else ""
    state.register_endpoint = auth_eps.register.get("url", "") if auth_eps.register else ""
    state.login_endpoint = login_url
    user_a_token, user_a_cookies = _do_register_then_login(
        state.username, state.password,
    )
    if user_a_token or user_a_cookies:
        state.header_name = "Authorization"
        state.header_value = user_a_token
        state.cookies = user_a_cookies

    # Step 2 (iter-18) — register + login user-b for cross-session probes.
    # Different username + different password than user-a.
    user_b_username = (
        "strix_bench_"
        + "".join(_random.choices(_string.ascii_lowercase, k=8))
    )
    user_b_password = (
        "Strix_BenchB_"
        + "".join(_random.choices(_string.ascii_letters + _string.digits, k=12))
        + "!"
    )
    user_b_token, user_b_cookies = _do_register_then_login(
        user_b_username, user_b_password,
    )

    # Register both captured states in the SecurityContext auth
    # registry. Iter-18: user-a + user-b are now SEPARATE accounts
    # with distinct tokens. The OWASP API specialists read by label:
    #   * scan_api_bola: owner_label="user-a", accessor_label="user-b"
    #   * scan_api_bfla: admin_label="admin", role_labels=["viewer","member","user"]
    #   * scan_api_mass_assignment: auth_label="user-a"
    #   * scan_idor: owner_label="user-a", accessor_label="user-b"
    #
    # user-a's token registers under user-a + admin + viewer + member +
    # user (so BFLA defaults work even when we only have one role; the
    # probe becomes a self-as-self check — not a real BFLA but at
    # least the tool fires).
    # user-b's token (when distinct) registers under user-b ONLY — so
    # BOLA / IDOR see two different tokens and produce real
    # cross-session probes.
    def _to_bearer(hdr_val: str) -> str:
        if hdr_val and hdr_val.lower().startswith("bearer "):
            return hdr_val[len("Bearer "):].strip()
        return ""

    if state.is_valid or user_b_token or user_b_cookies:
        try:
            from strix.agents.security_context import record_auth_state
            # user-a registrations
            a_bearer = _to_bearer(state.header_value) if state.header_value else ""
            if state.is_valid:
                for label in ("user-a", "admin", "viewer", "member", "user"):
                    record_auth_state(
                        label=label,
                        cookies=state.cookies if state.cookies else None,
                        bearer=a_bearer or None,
                        notes=(
                            f"strix L1 user-a captured via openapi /login "
                            f"at {login_url}"
                        ),
                    )
            # user-b registration — separate token for real cross-session probes
            b_bearer = _to_bearer(user_b_token) if user_b_token else ""
            if b_bearer or user_b_cookies:
                record_auth_state(
                    label="user-b",
                    cookies=user_b_cookies if user_b_cookies else None,
                    bearer=b_bearer or None,
                    notes=(
                        f"strix L1 user-b (iter-18 cross-session) "
                        f"captured via openapi /login at {login_url}"
                    ),
                )
        except Exception:  # noqa: BLE001
            pass

    # Record the result
    summary.tools_run.append("probe_auth_flow")
    summary.tools_succeeded.append("probe_auth_flow")
    findings: list[dict[str, Any]] = []
    if state.is_valid:
        # Emit a *positive control* finding noting that L1 successfully
        # registered + logged in. Useful for operator visibility but
        # NOT a vuln per se — not counted as a vulnerability finding.
        findings.append({
            "title": (
                f"L1 auth-flow captured credentials via openapi-"
                f"discovered /register + /login"
            ),
            "category": "info_disclosure",
            "cwe": "CWE-1390",
            "endpoint": login_url,
            "severity": "info",
            "description": (
                f"strix L1 auth-flow successfully registered + logged "
                f"in as `{state.username}` via the openapi-documented "
                f"endpoints. The captured "
                f"{'Bearer token' if state.header_value else 'session cookie'} "
                f"is being plumbed into downstream specialists "
                f"(scan_sqli, scan_ssrf, scan_api_bola/bfla/"
                f"mass_assignment, jwt_audit) so they exercise the "
                f"authenticated surface."
            ),
            "verification_status": "verified",
            "confidence": 0.95,
        })
    summary.tool_results.append(ToolResult(
        tool_name="probe_auth_flow",
        status="ok",
        findings_count=0,  # not a real vuln finding
        error_reason=(
            None if state.is_valid
            else "login did not return a recognized token / cookie"
        ),
        wall_time_s=0.0,
        raw_result={
            "findings": findings,
            "status": "ok",
            "auth_captured": state.is_valid,
            "username": state.username,
            "login_endpoint": login_url,
            "header_name": state.header_name if state.is_valid else "",
            "has_token": bool(state.header_value),
            "has_cookies": bool(state.cookies),
        },
    ))
    return state if state.is_valid else None


def probe_mass_assignment_followup(
    *, endpoints: list[Any] | None, target_value: str,
) -> list[dict[str, Any]]:
    """Iter-17.5 — close the vampi `mass-assignment-admin` gap.

    The existing scan_api_mass_assignment + probe_mass_assignment_priv_fields
    require the server to ECHO the injected admin/role/is_admin
    field in the response body. Vampi silently accepts `admin: true`
    on /register but returns a generic success message — no echo,
    no baseline-diff signal, so both probes return 0.

    This probe closes the gap with a 3-step chain that L1.5 makes
    possible (once auth-flow exists):

      1. Build a schema-driven register body INCLUDING privilege
         fields (admin, is_admin, role=admin, is_superuser).
      2. POST /register → user created (or 4xx — bail).
      3. POST /login with the new creds → capture token.
      4. GET the user's own profile (try /me, /users/v1/{username},
         the path-param-of-the-spec's user resource, etc).
      5. If the profile response contains "admin": true (or
         equivalent), the privilege field PERSISTED — mass-assignment
         confirmed.

    Returns one finding per persistent privilege field detected.
    """
    import json as _json
    import random as _random
    import string as _string

    auth_eps = _discover_auth_endpoints(endpoints)
    if not (auth_eps.register and auth_eps.login):
        # Spec didn't yield it — try static-path fallback (crapi case).
        static_eps = _discover_auth_via_static_paths(target_value)
        if static_eps is not None:
            auth_eps = static_eps
    if not (auth_eps.register and auth_eps.login):
        return []

    # Build a register body with priv fields injected.
    username = (
        "strix_ma_followup_"
        + "".join(_random.choices(_string.ascii_lowercase, k=6))
    )
    password = (
        "Strix_MA_"
        + "".join(_random.choices(_string.ascii_letters + _string.digits, k=10))
        + "!"
    )
    base_body = _build_schema_driven_body(
        auth_eps.register, username=username, password=password,
    )
    PRIV_FIELDS = {
        "admin": True,
        "is_admin": True,
        "isAdmin": True,
        "role": "admin",
        "is_superuser": True,
        "is_staff": True,
    }
    injected_body = {**base_body, **PRIV_FIELDS}

    # Step 1: register with priv fields
    reg_url = auth_eps.register.get("url") or (
        target_value.rstrip("/") + (auth_eps.register.get("path") or "")
    )
    try:
        reg_resp = _http_request(
            reg_url, method="POST", timeout=8.0,
            headers={"Content-Type": "application/json"},
            data=_json.dumps(injected_body).encode(),
        )
        reg_status = (
            getattr(reg_resp, "status", getattr(reg_resp, "code", None))
            if reg_resp else None
        )
        if not reg_status or reg_status >= 400:
            return []
    except Exception:  # noqa: BLE001
        return []

    # Step 2: login as the new user (without priv fields — just
    # standard login body).
    login_url = auth_eps.login.get("url") or (
        target_value.rstrip("/") + (auth_eps.login.get("path") or "")
    )
    login_body = _build_schema_driven_body(
        auth_eps.login, username=username, password=password,
    )
    try:
        login_resp = _http_request(
            login_url, method="POST", timeout=8.0,
            headers={"Content-Type": "application/json"},
            data=_json.dumps(login_body).encode(),
        )
        login_status = (
            getattr(login_resp, "status", getattr(login_resp, "code", None))
            if login_resp else None
        )
        if not login_status or login_status >= 400:
            return []
        _, token_header_value, login_cookies = _extract_auth_from_response(login_resp)
    except Exception:  # noqa: BLE001
        return []
    if not token_header_value and not login_cookies:
        return []

    # Build auth headers
    auth_headers: dict[str, str] = {}
    if token_header_value:
        auth_headers["Authorization"] = token_header_value
    if login_cookies:
        auth_headers["Cookie"] = "; ".join(
            f"{k}={v}" for k, v in login_cookies.items()
        )

    # Step 3: GET the user's own profile to verify priv field
    # persisted. Try common patterns:
    #   /me / /api/me / /users/me
    #   /users/v1/{username} (with our username substituted)
    #   Look for an endpoint in the openapi spec with a path-param
    #     matching `username` / `userId` / `user_id` / `uid` and
    #     a GET method
    candidate_get_paths: list[str] = []
    # Strip any path from the target so we build URLs against the
    # base host only (handles crapi-style targets like
    # `http://localhost:8888/identity/api/v2`).
    from urllib.parse import urlparse
    try:
        parsed = urlparse(target_value)
        base = (
            f"{parsed.scheme}://{parsed.netloc}"
            if parsed.scheme and parsed.netloc
            else target_value.rstrip("/")
        )
    except Exception:  # noqa: BLE001
        base = target_value.rstrip("/")
    # Static path candidates — generic + service-prefixed.
    # crapi uses `/identity/api/v2/user/dashboard`; vampi uses
    # `/users/v1/{username}`; many generic apps use `/me`.
    # Add canonical patterns from multiple ecosystems.
    static_get_paths = (
        # Generic
        "/me", "/users/me", "/api/me", "/profile", "/user/me",
        "/api/users/me", "/api/v1/me", "/api/v1/users/me",
        # crapi-style microservice prefixes
        "/identity/api/v2/user/dashboard",
        "/identity/api/user/dashboard",
        "/identity/api/v2/user",
        "/identity/api/user",
        "/community/api/v2/user/dashboard",
        # Other common shapes
        "/api/v2/user/dashboard",
        "/users/v1/me",
        "/users/v1/{username}",
        "/account/profile",
        "/api/account/profile",
    )
    for p in static_get_paths:
        # Substitute {username} placeholder if present
        full_path = p.replace("{username}", username)
        candidate_get_paths.append(base + full_path)
    # Spec-discovered user-by-id GET endpoints
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        if (ep.get("method") or "GET").upper() != "GET":
            continue
        path = ep.get("path") or ""
        if not path:
            continue
        if any(p in path.lower() for p in ("{username}", "{user}", "{user_id}", "{userid}", "{uid}")):
            substituted = path
            for ph in ("{username}", "{user}", "{user_id}", "{userid}", "{uid}"):
                substituted = substituted.replace(ph, username).replace(
                    ph.upper(), username,
                )
            full = ep.get("url") or (base + substituted)
            if "{" not in full:
                candidate_get_paths.append(full)

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url in candidate_get_paths:
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = _http_request(url, method="GET", timeout=5.0, headers=auth_headers)
            status = (
                getattr(resp, "status", getattr(resp, "code", None))
                if resp else None
            )
            if not status or status >= 400:
                continue
            body_bytes = resp.read(8192) if resp else b""
            body_text = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
        except Exception:  # noqa: BLE001
            continue
        if not body_text:
            continue
        # Parse as JSON; check for priv fields = true / "admin"
        try:
            parsed = _json.loads(body_text)
        except (ValueError, _json.JSONDecodeError):
            parsed = None
        # Recursive search for priv field with truthy value
        persisted_fields: list[str] = []

        def _walk(obj: Any, depth: int = 0) -> None:
            if depth > 4:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    k_lower = str(k).lower()
                    if k_lower in ("admin", "is_admin", "isadmin",
                                   "is_superuser", "is_staff", "issuper"):
                        if v is True:
                            persisted_fields.append(f'{k}=true')
                    elif k_lower == "role":
                        if isinstance(v, str) and v.lower() in ("admin", "superuser", "root"):
                            persisted_fields.append(f'role={v}')
                    if isinstance(v, (dict, list)):
                        _walk(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item, depth + 1)

        if parsed is not None:
            _walk(parsed)
        # Also a simple substring fallback for non-JSON responses
        if not persisted_fields:
            body_lower = body_text.lower()
            if '"admin"' in body_lower and ("true" in body_lower or "1" in body_lower):
                # Only count if "admin" appears NEAR "true" (within 60 chars)
                idx = body_lower.find('"admin"')
                window = body_lower[idx:idx + 60]
                if "true" in window:
                    persisted_fields.append("admin field appears truthy in response")
        if persisted_fields:
            out.append({
                "title": (
                    f"Mass-assignment confirmed: privilege field "
                    f"persisted on {auth_eps.register.get('path')}"
                ),
                "category": "mass_assignment",
                "cwe": "CWE-915",
                "endpoint": auth_eps.register.get("path") or reg_url,
                "severity": "critical",
                "description": (
                    f"Registration accepted client-supplied privilege "
                    f"fields {list(PRIV_FIELDS.keys())[:3]}... and they "
                    f"PERSISTED to the user record (verified via GET "
                    f"after login). Evidence: {persisted_fields[:3]}. "
                    f"Strip unrecognized fields server-side; never trust "
                    f"client-supplied authorization metadata."
                ),
                "verification_status": "verified",
                "confidence": 0.95,
            })
            break   # one confirmation is enough
    return out


def _build_probe_kwargs_with_auth(
    ep: dict[str, Any],
    *,
    auth_headers: dict[str, str],
    probe_kind: str,
) -> dict[str, Any] | None:
    """Build kwargs for a per-endpoint signature scanner.

    Most signature scanners (scan_ssrf / scan_path_traversal /
    scan_nosql_injection / scan_cmd_injection) accept ONLY
    `url, params, extra_headers` — they auto-detect URL query
    params and probe them. scan_sqli has its own rich kwargs and
    is handled by _run_per_endpoint_sqli; this builder is for the
    simpler tools.

    Returns None when the endpoint has no probeable params or the
    URL contains unsubstituted path placeholders we can't resolve.

    Strategy:
      * GET with query params → pass url + params=[query names]
      * Path-param URL (`/users/{id}`) → substitute a default
        value into the URL so the scanner has a concrete target
      * POST/PUT/PATCH with body → skip (these tools don't support
        body-param probing)
    """
    if not isinstance(ep, dict):
        return None
    url = ep.get("url")
    if not isinstance(url, str) or not url:
        return None
    method = (ep.get("method") or "GET").upper()
    # POST/PUT/PATCH with body — skip; not supported by this
    # builder's target tools.
    if method != "GET":
        return None
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

    # If URL has {placeholder}, substitute a default value so the
    # scanner has a concrete URL to probe. The scanner mutates the
    # value with its payload.
    import re
    substituted_url = url
    placeholders = re.findall(r"\{([^}]+)\}", url)
    if placeholders:
        if not path_params:
            # Unknown placeholder — substitute "1" as best-guess
            for ph in placeholders:
                substituted_url = substituted_url.replace(f"{{{ph}}}", "1")
        else:
            # Substitute each declared path param with "1"; the
            # scanner will then try injection payloads against the
            # query params instead (since path is now concrete).
            for ph in placeholders:
                substituted_url = substituted_url.replace(f"{{{ph}}}", "1")

    # Build base kwargs: url + extra_headers always; params if any.
    out: dict[str, Any] = {
        "url": substituted_url,
        "extra_headers": auth_headers,
    }
    if query_params:
        out["params"] = query_params[:3]
    elif placeholders and path_params:
        # Path-param-only URL — without query params there's nothing
        # for the URL-mode scanners to probe. Skip.
        return None
    elif not placeholders:
        # GET with no params declared. Some endpoints respond to
        # ad-hoc query params anyway (probe with the canonical sink
        # name for that scanner type) but we don't have probe_kind-
        # specific defaults wired here. Skip.
        return None
    return out


async def _run_per_endpoint_signature_probe(
    summary: PrepassSummary,
    *,
    tool_name: str,
    endpoints: list[Any],
    auth_headers: dict[str, str],
    agent_state: Any,
    timeout_s: int,
    max_endpoints: int = 8,
) -> None:
    """Generic per-endpoint runner for signature scanners that
    accept (url, params, method, body_template, extra_headers).

    Used for scan_ssrf, scan_path_traversal, scan_nosql_injection,
    scan_cmd_injection, scan_xxe. Mutates `summary` in place.
    """
    if not endpoints:
        return
    n = 0
    seen_targets: set[tuple[str, str, tuple[str, ...]]] = set()
    for ep in endpoints:
        if n >= max_endpoints:
            break
        kwargs = _build_probe_kwargs_with_auth(
            ep, auth_headers=auth_headers, probe_kind=tool_name,
        )
        if not kwargs:
            continue
        target_key = (
            kwargs.get("method", "GET"),
            kwargs["url"],
            tuple(sorted(kwargs.get("params") or [])),
        )
        if target_key in seen_targets:
            continue
        seen_targets.add(target_key)
        path = ep.get("path", kwargs["url"])
        method = kwargs.get("method", "GET")
        ep_tool_name = f"{tool_name}[{method} {path}]"
        summary.tools_run.append(ep_tool_name)
        result = await _run_one_tool(
            tool_name, kwargs,
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


def probe_jwt_brute_secret(
    *, token: str, max_attempts: int = 20000,
) -> list[dict[str, Any]]:
    """Offline HMAC brute-force against a captured JWT. Tries a
    short wordlist of common JWT secrets (`secret`, `password`,
    `1234`, …) and the JWT's own component strings as candidates.

    No network requests. CPU-bound. Returns a finding when a secret
    is found that re-signs the token (i.e. matches HMAC), empty
    list otherwise.
    """
    import base64
    import hashlib
    import hmac
    if not token or token.count(".") != 2:
        return []
    parts = token.split(".")
    header_b64, payload_b64, sig_b64 = parts
    try:
        # Pad and decode for HMAC computation.
        def _b64url_decode(s: str) -> bytes:
            pad = "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s + pad)

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = _b64url_decode(sig_b64)
        # Parse the header to learn the HMAC variant.
        import json as _json
        try:
            header_json = _json.loads(_b64url_decode(header_b64).decode("utf-8"))
        except Exception:  # noqa: BLE001
            return []
        alg = (header_json.get("alg") or "").upper()
        if alg not in ("HS256", "HS384", "HS512"):
            return []
        hash_func = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                     "HS512": hashlib.sha512}[alg]
    except Exception:  # noqa: BLE001
        return []

    # Common-JWT-secret wordlist. Measured against vampi (`random`)
    # and standard generic-secret guesses. Not aiming for completeness
    # — that's what nuclei + dedicated wordlists are for. Keep
    # inline for zero-setup. ~70 candidates curated from the
    # observed defaults across vulnerable-API targets and common
    # framework placeholders.
    candidates = [
        # Vampi / generic placeholders
        "secret", "random", "password", "passwd", "admin", "root",
        "test", "qwerty", "1234", "12345", "123456", "1234567",
        "12345678", "letmein", "changeme", "default", "key",
        "private", "public", "demo", "example",
        # JWT-specific common defaults
        "your-256-bit-secret", "your_256_bit_secret",
        "jwt-secret", "jwt_secret", "jwtsecret",
        "supersecret", "topsecret", "very-secret-key",
        "super-secret-key", "mysecret", "myJwtSecret",
        "jsonwebtoken", "node-jwt", "jwttoken",
        "hmac-secret", "shared-secret", "shared_secret",
        # Common dev / training-app defaults
        "S3cr3t!", "secretkey", "secret_key", "SecretKey",
        "MySecretKey", "myverysecretkey", "ChangeThisSecret",
        # Crapi / juiceshop-class targets
        "crapisecret", "crapi", "juiceshop",
        "vulnerable", "owasp", "training",
        # Single-word common nouns (matches what a developer types
        # under deadline pressure; vampi literally uses "random")
        "string", "value", "token", "auth", "session",
        "production", "development", "staging", "local",
        # Spring Boot / Express defaults
        "spring-default", "jwt.io",
        # Empty + single chars (sometimes used in tutorials)
        "", "a", "x",
    ]
    # Cap to max_attempts in case the caller wants a faster check.
    for cand in candidates[:max_attempts]:
        try:
            sig = hmac.new(cand.encode(), signing_input, hash_func).digest()
        except Exception:  # noqa: BLE001
            continue
        if hmac.compare_digest(sig, expected_sig):
            return [{
                "title": f"JWT signed with weak secret: `{cand}`",
                "category": "jwt",
                "cwe": "CWE-326",
                "endpoint": "",   # token-level, not endpoint-level
                "severity": "critical",
                "description": (
                    f"The captured JWT is HMAC-{alg[2:]}-signed using "
                    f"the trivially-guessable secret `{cand}`. With the "
                    f"secret known, an attacker can forge ANY claims "
                    f"(sub, role, is_admin, exp) and produce a token "
                    f"the server will accept. Rotate the signing key "
                    f"to a 256-bit random value and store it in a "
                    f"secret manager (not in source / env file)."
                ),
                "verification_status": "verified",
                "confidence": 1.0,
            }]
    return []


def probe_password_reset_otp_space(
    *, endpoints: list[Any] | None, target_value: str,
    max_attempts: int = 10000,
) -> list[dict[str, Any]]:
    """When an OTP-verification endpoint is discovered, send a
    handful of guesses to estimate the OTP space + rate-limit
    posture. Doesn't actually brute-force successfully (would
    require knowing a valid user identifier); just confirms that
    the space is small enough that brute-force is feasible AND
    the endpoint doesn't rate-limit.

    Targeted at crapi's `/identity/api/auth/v3/check-otp` and
    similar.
    """
    # Find /check-otp / /verify-otp / similar from the openapi
    # spec OR from a curated static-path list when no spec.
    OTP_KW = ("check-otp", "check_otp", "verify-otp", "verify_otp",
              "otp/verify", "otp/check", "reset-password",
              "reset_password", "v3/check-otp", "v3/check_otp",
              "v2/check-otp", "v2/check_otp", "auth/forget-password",
              "auth/forgot-password", "auth/reset")
    otp_eps: list[dict[str, Any]] = []
    if endpoints:
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            path = (ep.get("path") or "").lower()
            if any(k in path for k in OTP_KW):
                otp_eps.append(ep)
    # Static fallback: probe well-known OTP endpoints even when
    # the openapi spec didn't yield any. crapi's
    # /identity/api/auth/v3/check-otp is the canonical target.
    if not otp_eps:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target_value)
            base = (
                f"{parsed.scheme}://{parsed.netloc}"
                if parsed.scheme and parsed.netloc
                else target_value.rstrip("/")
            )
        except Exception:  # noqa: BLE001
            base = target_value.rstrip("/")
        STATIC_OTP_PATHS = (
            "/identity/api/auth/v3/check-otp",
            "/identity/api/auth/v2/check-otp",
            "/identity/api/auth/check-otp",
            "/api/auth/v3/check-otp",
            "/api/auth/check-otp",
            "/api/auth/verify-otp",
            "/auth/check-otp",
            "/auth/verify-otp",
            "/api/v1/auth/reset-password",
            "/api/v1/users/reset-password",
        )
        for p in STATIC_OTP_PATHS:
            otp_eps.append({
                "url": base + p,
                "path": p,
                "method": "POST",
                "params": [],
                "request_body_schema": None,
                "source": "static_path_discovery_otp",
            })
    out: list[dict[str, Any]] = []
    for ep in otp_eps:
        url = ep.get("url")
        if not isinstance(url, str) or not url:
            continue
        method = (ep.get("method") or "POST").upper()
        if method not in ("POST", "PUT", "PATCH"):
            continue
        # Fire 30 guesses against the OTP endpoint with throwaway
        # 4-digit OTPs and a synthetic email. Watch for rate-limit.
        import json as _json
        sample_email = "strix-bench-otp@strix-bench.local"
        responses_seen: list[int | None] = []
        for guess in ("0000", "1234", "1111", "9999", "0001"):
            body = {"email": sample_email, "otp": guess}
            try:
                data = _json.dumps(body).encode()
                resp = _http_request(
                    url, method=method, timeout=4.0,
                    headers={"Content-Type": "application/json"},
                    data=data,
                )
                status = (
                    getattr(resp, "status", getattr(resp, "code", None))
                    if resp else None
                )
                responses_seen.append(status)
            except Exception:  # noqa: BLE001
                responses_seen.append(None)
        # Did the server ever return 429? If not, OTP-brute is
        # feasible on a small OTP space.
        had_429 = 429 in responses_seen
        # Heuristic: 5 quick requests went through without 429 →
        # likely no rate-limit + small OTP space.
        if not had_429:
            out.append({
                "title": f"OTP verification endpoint accepts unlimited guesses at {ep.get('path')}",
                "category": "rate_limit",
                "cwe": "CWE-307",
                "endpoint": url,
                "severity": "high",
                "description": (
                    f"POST {ep.get('path')} with synthetic OTP guesses "
                    f"did not return 429 / Retry-After across 5 quick "
                    f"requests. Combined with a typical 4-digit OTP "
                    f"space (10000 values), brute-force succeeds in "
                    f"seconds. Add rate-limiting (1 attempt per 30s "
                    f"per user-account, 5/hour total) AND increase the "
                    f"OTP entropy (6+ digits or alphanumeric)."
                ),
                "verification_status": "verified",
                "confidence": 0.85,
            })
    return out


async def _retry_default_creds_against_login_forms(
    summary: PrepassSummary,
    *,
    target_value: str,
    agent_state: Any,
    timeout_s: int,
) -> None:
    """iter-33.1 — re-fire probe_default_creds against each login URL
    that recon discovered.

    Reads `workflow_state.login_forms_found` (populated by recon
    tools / katana / webapp_recon_pipeline / web_crawler). For each
    URL, invokes the existing `probe_default_creds` tool with
    `login_url=` set so the tool tries the discovered URL instead of
    guessing one off the root.

    Idempotent:
      * No-op when `workflow_state.auth_state_captured` is already
        True (phase-1 anchor already landed a session).
      * No-op when no login forms were discovered.
      * Caps invocations at 5 distinct URLs per scan to bound wall-
        clock + request volume.

    Best-effort: any per-URL failure is captured in a ToolResult and
    the loop continues. Never raises.
    """
    # Read workflow state. Tolerant of the module being unavailable
    # in narrow test environments.
    try:
        from strix.agents.workflow_state import snapshot as ws_snapshot
        snap = ws_snapshot() or {}
    except Exception:  # noqa: BLE001
        return

    if bool(snap.get("auth_state_captured")):
        return  # phase-1 already captured a session

    login_urls_raw = snap.get("login_forms_found") or []
    if not isinstance(login_urls_raw, list) or not login_urls_raw:
        return

    # Dedup + cap. URL strings only.
    seen: set[str] = set()
    login_urls: list[str] = []
    for u in login_urls_raw:
        if isinstance(u, str) and u.strip() and u not in seen:
            seen.add(u)
            login_urls.append(u)
        if len(login_urls) >= 5:
            break
    if not login_urls:
        return

    # Per-URL invocation. We call the tool function directly (not via
    # _run_one_tool) because probe_default_creds is sync + already
    # wraps its work; this keeps the wall-time bounded by the
    # tool's internal timeout.
    try:
        from strix.tools.default_creds_probe.probe_default_creds import (
            probe_default_creds,
        )
    except ImportError:
        return

    for login_url in login_urls:
        t0 = time.monotonic()
        try:
            raw = probe_default_creds(
                target_url=target_value,
                login_url=login_url,
                timeout=8,
            )
        except Exception as e:  # noqa: BLE001
            elapsed = time.monotonic() - t0
            summary.tool_results.append(ToolResult(
                tool_name=f"probe_default_creds[{login_url}]",
                status="error",
                findings_count=0,
                error_reason=f"{type(e).__name__}: {e}",
                wall_time_s=round(elapsed, 2),
                raw_result=None,
            ))
            continue
        elapsed = time.monotonic() - t0
        status = "ok" if (
            isinstance(raw, dict) and raw.get("default_credential_found")
        ) else "partial"
        n_findings = _count_findings(raw)
        summary.tools_run.append("probe_default_creds_iter_33_1")
        if status == "ok":
            summary.tools_succeeded.append("probe_default_creds_iter_33_1")
        else:
            summary.tools_failed.append("probe_default_creds_iter_33_1")
        summary.total_findings += n_findings
        summary.tool_results.append(ToolResult(
            tool_name="probe_default_creds_iter_33_1",
            status=status,
            findings_count=n_findings,
            error_reason=None if status == "ok" else "no_default_credential_landed",
            wall_time_s=round(elapsed, 2),
            raw_result=raw if isinstance(raw, dict) else None,
        ))
        # Short-circuit on first success — one good session is
        # enough for downstream specialists. Trying further URLs
        # mostly wastes budget on the same SUT.
        if status == "ok":
            break


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
    # no per-endpoint surface for phase-2 to iterate.
    #
    # iter-18: ALSO call webapp_recon_pipeline (playwright-driven,
    # sandbox-resident). Where katana is a static JS-AST crawler,
    # webapp_recon_pipeline executes JS in headless Chrome → discovers
    # routes computed at runtime (Angular SPAs like juiceshop, React
    # SPAs, Vue, etc.). Both are deterministic L1 work; both run when
    # the sandbox is available (always in production, errors cleanly
    # in the bench harness without a sandbox).
    if (not endpoints) and target_type == "web_application" and target_value:
        # iter-35.1 — route through the registered `crawl_with_katana`
        # tool (sandbox_execution=True) instead of the deleted host-
        # side `_katana_crawl` helper. The registered tool:
        #   * runs in sandbox container (consistent network policy,
        #     no host PATH dependency)
        #   * already calls workflow_state.record_endpoint_discovered
        #     (iter-32.1 wiring) so iter-31.9 surface_breadth metric
        #     lights up on the next bench
        #   * emits to KG via the standard tool pipeline
        crawled_tr = await _run_one_tool(
            "crawl_with_katana",
            {"target_url": target_value, "max_pages": 30, "depth": 2},
            agent_state=agent_state, timeout_s=timeout_s,
        )
        if crawled_tr.status in ("ok", "partial") and isinstance(
            crawled_tr.raw_result, dict,
        ):
            crawled = crawled_tr.raw_result.get("endpoints") or []
            if crawled:
                endpoints = crawled
                summary.tools_run.append("crawl_with_katana")
                summary.tools_succeeded.append("crawl_with_katana")
                summary.tool_results.append(crawled_tr)
        else:
            # Tool failed — record the result so the bench shows it
            # was attempted. No endpoints captured.
            summary.tools_run.append("crawl_with_katana")
            summary.tools_failed.append("crawl_with_katana")
            summary.tool_results.append(crawled_tr)

    # iter-18: webapp_recon_pipeline runs unconditionally for
    # web_application targets — its playwright-driven crawl catches
    # SPA-routed endpoints katana misses (juiceshop's Angular bundle
    # builds routes at runtime). The pipeline ALSO emits its own
    # security findings (TLS, security-headers, well-known files).
    # We don't merge its endpoint output into the local `endpoints`
    # variable — its findings flow through the tracer into the
    # canonical store directly via `_emit_finding`. The phase-2
    # loop below uses katana/openapi-emitted endpoints regardless.
    if target_type == "web_application" and target_value:
        summary.tools_run.append("webapp_recon_pipeline")
        wrp_result = await _run_one_tool(
            "webapp_recon_pipeline",
            {"target_url": target_value},
            agent_state=agent_state, timeout_s=timeout_s,
        )
        summary.tool_results.append(wrp_result)
        summary.total_findings += wrp_result.findings_count
        if wrp_result.status in ("ok", "partial"):
            summary.tools_succeeded.append("webapp_recon_pipeline")
        else:
            summary.tools_failed.append("webapp_recon_pipeline")
        # If the pipeline returned endpoints AND we still have none,
        # use them for the downstream phase-2 loop.
        if (not endpoints) and isinstance(wrp_result.raw_result, dict):
            pipeline_endpoints = wrp_result.raw_result.get("endpoints")
            if isinstance(pipeline_endpoints, list) and pipeline_endpoints:
                endpoints = pipeline_endpoints

    # iter-33.1 — deterministic auth re-attempt against discovered
    # login forms.
    #
    # The phase-1 probe_default_creds anchor runs against the ROOT
    # target URL only. For SPAs / JS-rendered apps (juiceshop's
    # Angular bundle, React/Vue apps, etc.) the actual login endpoint
    # is at a different URL discovered DURING recon — never at the
    # root. So phase-1 probe_default_creds always fails on these
    # targets, leaving every post-auth challenge unreachable.
    #
    # This hook re-fires probe_default_creds against each login URL
    # that recon discovered + recorded into workflow_state. The
    # default-creds corpus is the same (~50 universal pairs:
    # admin/admin / admin/password / etc. — no SUT identifiers).
    # When a default credential lands, the resulting session is
    # auto-recorded via security_context.record_auth_state, and
    # downstream auth-aware specialists (scan_idor, scan_api_bola,
    # scan_api_bfla, jwt_audit) pick it up via SecurityContext.
    if target_type == "web_application" and target_value:
        try:
            await _retry_default_creds_against_login_forms(
                summary, target_value=target_value,
                agent_state=agent_state, timeout_s=timeout_s,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "iter-33.1 auth re-attempt failed: %s — passthrough", e,
            )

    # Iter-11 deterministic L1 probes — fire BEFORE bailing out on
    # empty endpoints. These probes don't need the endpoint list at
    # all (only target_value), so they should fire even when openapi
    # + katana found nothing.
    #
    # iter-35.2 — every probe now dispatches via `_run_one_tool` so
    # the underlying urllib / socket / ftplib I/O fires inside the
    # sandbox container, not on the host process. This restores the
    # invariant documented in CLAUDE.md §3 ("Only use sandbox-based
    # tools for any target analysis") and unlocks reachability for
    # targets that resolve only inside the sandbox network.
    #
    # All probes are best-effort: any dispatch failure → record an
    # error ToolResult and continue.
    async def _dispatch_probe(
        tool_name: str, kwargs: dict[str, Any],
    ) -> None:
        result = await _run_one_tool(
            tool_name, kwargs,
            agent_state=agent_state, timeout_s=timeout_s,
        )
        summary.tools_run.append(tool_name)
        if result.status == "ok":
            summary.tools_succeeded.append(tool_name)
        summary.tool_results.append(result)
        summary.total_findings += result.findings_count

    if target_value:
        # Item D: heuristic debug-path enumerator. Passes the
        # endpoints list so the probe ALSO tests openapi-discovered
        # sub-paths that match debug-like keywords (e.g. vampi's
        # /users/v1/_debug which the static base-URL list misses).
        await _dispatch_probe(
            "probe_unauth_debug_paths",
            {
                "target_url": target_value,
                "endpoints": endpoints if isinstance(endpoints, list) else None,
            },
        )
        # Item E: open-redirect probe (no endpoints needed at minimum,
        # endpoints enrich it)
        await _dispatch_probe(
            "probe_open_redirect",
            {
                "target_url": target_value,
                "endpoints": endpoints if isinstance(endpoints, list) else None,
            },
        )
        # Item G: directory-listing probe (no endpoints needed)
        await _dispatch_probe(
            "probe_directory_listing",
            {"target_url": target_value},
        )
        # iter-15: HTTP-port banner probe — catches Server-header
        # version disclosure + X-Powered-By + autoindex on common
        # upload paths. Parse host+port out of target_value to fit
        # probe_http_port's ip+port signature.
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target_value)
            host = parsed.hostname
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == "https" else 80
            scheme = parsed.scheme or "http"
        except Exception:  # noqa: BLE001
            host = None
            port = 80
            scheme = "http"
        if host:
            await _dispatch_probe(
                "probe_http_port",
                {"host": host, "port": port, "scheme": scheme},
            )
        # Item I: openapi-spec-exposure probe (needs spec_url from
        # openapi_spec_ingest)
        spec_url = None
        if isinstance(openapi_result, dict):
            spec_url = openapi_result.get("spec_url")
        await _dispatch_probe(
            "probe_openapi_spec_exposed",
            {"target_url": target_value, "spec_url": spec_url},
        )

    # Endpoint-dependent probes — only fire if we have an endpoint list
    if isinstance(endpoints, list) and endpoints:
        # Item B: forge-JWT alg=none probe
        await _dispatch_probe(
            "probe_jwt_none_alg", {"endpoints": endpoints},
        )
        # Item C: mass-assignment privilege-field probe
        await _dispatch_probe(
            "probe_mass_assignment_priv_fields", {"endpoints": endpoints},
        )
        # Item F: unauth BOLA path-param probe
        await _dispatch_probe(
            "probe_unauth_bola_path_params", {"endpoints": endpoints},
        )

    # Iter-17.6 — auth-flow MUST still run even when endpoints is
    # empty/None. crapi 1.1.6-rc8 serves its openapi spec behind a
    # bearer token (the very thing we're trying to obtain), so spec
    # discovery returns no endpoints. The static-path fallback in
    # _discover_auth_via_static_paths covers this case. We skip the
    # endpoint-list-required probes when there's nothing to iterate,
    # but the auth-flow + jwt-brute + OTP probes can fire on
    # `target_value` alone.
    if not isinstance(endpoints, list) or not endpoints:
        endpoints_for_auth: list[Any] = []
    else:
        # iter-Q5.40 — drop health / metrics / spec endpoints. These have no
        # vulnerability surface for the OWASP API specialists; firing
        # mass_assignment at /health is a guaranteed waste. Default-on;
        # disable via STRIX_API_ENDPOINT_ROUTING=0 for ablation.
        if _api_routing_enabled():
            endpoints, _ep_rejected = _filter_api_endpoints(endpoints)
            if any(_ep_rejected.values()):
                logger.info(
                    "api endpoint pre-filter dropped: %s; kept=%d",
                    {k: v for k, v in _ep_rejected.items() if v},
                    len(endpoints),
                )
        endpoints_for_auth = endpoints

    # iter-17/18: scan_api_bola / scan_api_bfla / scan_api_mass_
    # assignment / scan_idor ARE wired into the L1 phase-2 below.
    # They use:
    #   * endpoints emitted by openapi_spec_ingest / katana /
    #     webapp_recon_pipeline
    #   * AuthState registered by _run_auth_flow under user-a (and
    #     iter-18: user-b for real cross-session probing)
    # No L2 needed for these — they're deterministic specialists.
    # Some still need richer prereqs (path-id discovery for path-
    # param-driven BOLA on resources owned by user-a); those still
    # benefit from L2 reasoning to enumerate resources first.

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
    if endpoints_for_auth:
        await _run_per_endpoint_sqli(
            summary, endpoints=endpoints_for_auth,
            agent_state=agent_state, timeout_s=timeout_s,
            max_endpoints=10,
        )

    # ---- iter-17: auth-flow + spec-as-scope ----
    # Part 1: deterministic auth-flow via openapi-discovered OR
    # static-path-fallback /register + /login. Captures a token /
    # cookie. Part 2 below plumbs it into the auth-required
    # specialists.
    auth_state = await _run_auth_flow(
        summary, endpoints=endpoints_for_auth, target_value=target_value,
    )

    if auth_state and auth_state.is_valid:
        auth_headers = auth_state.as_headers()

        # ---- Part 2a: re-invoke scan_sqli with auth (catches
        # vampi sqli-books, which is auth-walled).
        await _run_per_endpoint_signature_probe(
            summary, tool_name="scan_sqli",
            endpoints=endpoints, auth_headers=auth_headers,
            agent_state=agent_state, timeout_s=timeout_s,
            max_endpoints=10,
        )

        # ---- Part 2b: per-endpoint scan_ssrf with auth (catches
        # crapi ssrf-profile-pic).
        await _run_per_endpoint_signature_probe(
            summary, tool_name="scan_ssrf",
            endpoints=endpoints, auth_headers=auth_headers,
            agent_state=agent_state, timeout_s=timeout_s,
            max_endpoints=8,
        )

        # ---- Part 2c: path-traversal / nosql / cmd with
        # auth-tunneled URLs. Each one is fast (mostly returns
        # `partial: no <kind>-shaped params found` for endpoints
        # without a matching sink-shaped param).
        # scan_xxe + scan_ssti excluded — different kwarg shape
        # (scan_xxe takes only url+soap; scan_ssti takes url+params
        # but no path-substitution support).
        for sig_tool in (
            "scan_path_traversal", "scan_nosql_injection",
            "scan_cmd_injection",
        ):
            await _run_per_endpoint_signature_probe(
                summary, tool_name=sig_tool,
                endpoints=endpoints, auth_headers=auth_headers,
                agent_state=agent_state, timeout_s=timeout_s,
                max_endpoints=8,
            )

        # ---- Part 2d: OWASP API specialists with auth.
        # These specialists pull AuthState from the global registry
        # via labels (auth_label / owner_label / admin_label) — NOT
        # via kwargs. We registered the captured token above under
        # multiple labels so each specialist's default kwargs find it.
        #
        # scan_api_bola / scan_api_bfla need `owner_ids` for the
        # 2-user cross-session probe — we don't have that in single-
        # user L1, so they'll mostly emit no findings. Still kick
        # them off; their single-user surface CAN catch some BFLA
        # patterns (admin-only endpoint reachable to non-admin token).
        # scan_api_mass_assignment catches the canonical PATCH/POST
        # with privilege fields if the body schema gives it the
        # priv field names to try — confirm_mutation MUST be True
        # to actually probe; we accept the state-mutation risk
        # because the captured user is a throwaway strix-bench
        # account.
        # iter-Q5.40 — per-tool endpoint subset. With routing ON each tool
        # only sees endpoints whose method/shape matches its vuln class:
        #   * mass_assignment ← POST/PUT/PATCH (DELETE has no body to mass-assign)
        #   * bola/idor       ← GET on resource-id paths (`/users/:id`)
        #   * bfla            ← state-changing methods (POST/PUT/PATCH/DELETE)
        # STRIX_API_ENDPOINT_ROUTING=0 restores the pre-iter-Q5.40 contract
        # (every tool gets every endpoint).
        _eps_mass = _endpoints_for_api_tool(endpoints, "scan_api_mass_assignment")
        _eps_bola = _endpoints_for_api_tool(endpoints, "scan_api_bola")
        _eps_bfla = _endpoints_for_api_tool(endpoints, "scan_api_bfla")
        _eps_idor = _endpoints_for_api_tool(endpoints, "scan_idor")
        if _api_routing_enabled():
            logger.info(
                "api per-tool routing: mass_assignment=%d bola=%d bfla=%d "
                "idor=%d (from %d total endpoints)",
                len(_eps_mass), len(_eps_bola), len(_eps_bfla), len(_eps_idor),
                len(endpoints or []),
            )

        for api_tool, extra_kwargs in (
            ("scan_api_mass_assignment", {
                "endpoints": _eps_mass,
                "auth_label": "user-a",
                "confirm_mutation": True,
            }),
            ("scan_api_bola", {
                "endpoints": _eps_bola,
                "owner_label": "user-a",
                "accessor_label": "user-b",
            }),
            ("scan_api_bfla", {
                "endpoints": _eps_bfla,
                "admin_label": "admin",
            }),
            # iter-18: scan_idor is a cross-session IDOR probe that
            # uses owner_label=user-a + accessor_label=user-b from
            # SecurityContext. With iter-18's two-user auth-flow, both
            # labels carry distinct tokens → real cross-session probe.
            # Takes a list of urls — use the openapi-emitted endpoint
            # URLs. Caps at max_urls=50 internally.
            # iter-Q5.40: pre-routed to GET-with-:id endpoints, so the
            # url list is the matching subset (not every endpoint).
            ("scan_idor", {
                "urls": [
                    ep.get("url") for ep in _eps_idor
                    if isinstance(ep, dict) and ep.get("url")
                ],
                "owner_label": "user-a",
                "accessor_label": "user-b",
                "test_anon": True,
            }),
        ):
            summary.tools_run.append(api_tool)
            result = await _run_one_tool(
                api_tool, extra_kwargs,
                agent_state=agent_state, timeout_s=timeout_s,
            )
            summary.tool_results.append(result)
            summary.total_findings += result.findings_count
            if result.status in ("ok", "partial"):
                summary.tools_succeeded.append(api_tool)
            else:
                summary.tools_failed.append(api_tool)

        # ---- Part 2e: jwt_audit on the captured token.
        # jwt_audit covers HS/RS/EC algorithms, alg-confusion (RSA
        # public-key → HMAC secret), alg=none acceptance, key
        # disclosure, JKU/X5U manipulation, dictionary brute. It runs
        # inside the sandbox in production (always available); the
        # bench's _FakeAgentState lacks a sandbox so it errors cleanly
        # in bench runs only. Our additive `probe_jwt_brute_secret`
        # below is a pure-Python lower-bound that ALWAYS runs.
        if auth_state.header_value and auth_state.header_value.lower().startswith("bearer "):
            raw_token = auth_state.header_value[len("Bearer "):].strip()
            summary.tools_run.append("jwt_audit")
            result = await _run_one_tool(
                "jwt_audit",
                {"token": raw_token, "test_endpoint_url": target_value},
                agent_state=agent_state, timeout_s=timeout_s,
            )
            summary.tool_results.append(result)
            summary.total_findings += result.findings_count
            if result.status in ("ok", "partial"):
                summary.tools_succeeded.append("jwt_audit")
            else:
                summary.tools_failed.append("jwt_audit")

            # Iter-17 add: offline HMAC brute against the token.
            # Closes vampi jwt-weak-secret + crapi weak-jwt-secret.
            try:
                brute_findings = probe_jwt_brute_secret(token=raw_token)
            except Exception:  # noqa: BLE001
                brute_findings = []
            summary.tools_run.append("probe_jwt_brute_secret")
            summary.tools_succeeded.append("probe_jwt_brute_secret")
            summary.tool_results.append(ToolResult(
                tool_name="probe_jwt_brute_secret",
                status="ok",
                findings_count=len(brute_findings),
                error_reason=None,
                wall_time_s=0.0,
                raw_result={"findings": brute_findings, "status": "ok"},
            ))
            summary.total_findings += len(brute_findings)

    # Iter-17.5 add: mass-assignment follow-up GET probe.
    # The auth-flow we just did proves /register + /login work; this
    # probe DOES THE SAME register/login chain but injects privilege
    # fields and then GETs the new user's profile to confirm the
    # privileges persisted. Closes vampi mass-assignment-admin which
    # the existing echo-based probes miss because vampi doesn't echo
    # the admin field in /register's response.
    try:
        ma_findings = probe_mass_assignment_followup(
            endpoints=endpoints, target_value=target_value,
        )
    except Exception:  # noqa: BLE001
        ma_findings = []
    summary.tools_run.append("probe_mass_assignment_followup")
    summary.tools_succeeded.append("probe_mass_assignment_followup")
    summary.tool_results.append(ToolResult(
        tool_name="probe_mass_assignment_followup",
        status="ok",
        findings_count=len(ma_findings),
        error_reason=None,
        wall_time_s=0.0,
        raw_result={"findings": ma_findings, "status": "ok"},
    ))
    summary.total_findings += len(ma_findings)

    # Iter-17 add: OTP-space brute probe (no auth required —
    # operates on the reset-password endpoint pattern directly).
    # Closes crapi password-reset-otp-brute.
    try:
        otp_findings = probe_password_reset_otp_space(
            endpoints=endpoints, target_value=target_value,
        )
    except Exception:  # noqa: BLE001
        otp_findings = []
    summary.tools_run.append("probe_password_reset_otp_space")
    summary.tools_succeeded.append("probe_password_reset_otp_space")
    summary.tool_results.append(ToolResult(
        tool_name="probe_password_reset_otp_space",
        status="ok",
        findings_count=len(otp_findings),
        error_reason=None,
        wall_time_s=0.0,
        raw_result={"findings": otp_findings, "status": "ok"},
    ))
    summary.total_findings += len(otp_findings)

    # Per-endpoint rate-limit probes. Without this we'd only hit the
    # base URL — missing per-endpoint rate-limit must_finds (e.g.
    # vampi's /login rate-limit). Use endpoints_for_auth so we
    # tolerate the static-fallback case where the source spec
    # yielded no endpoints (crapi).
    capped = (endpoints_for_auth or [])[:max_endpoints_for_rate_limit]
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


def _gather_surface_for_dispatcher(
    summary: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """iter-30 — extract forms[] and endpoints[] from prior tool
    results so the shape-aware dispatcher can probe per-form and
    per-endpoint.

    Reads from:
      * crawl_with_katana (iter-28.3) — `forms[]` + `endpoints[]`
      * openapi_spec_ingest — `endpoints[]`

    Returns (forms, endpoints). Either may be empty if the prior
    phase tools didn't run or returned nothing.
    """
    forms_out: list[dict[str, Any]] = []
    endpoints_out: list[dict[str, Any]] = []
    for tr in getattr(summary, "tool_results", []) or []:
        raw = getattr(tr, "raw_result", None)
        if not isinstance(raw, dict):
            continue
        rec_forms = raw.get("forms")
        if isinstance(rec_forms, list):
            for f in rec_forms:
                if isinstance(f, dict):
                    forms_out.append(f)
        rec_endpoints = raw.get("endpoints")
        if isinstance(rec_endpoints, list):
            for e in rec_endpoints:
                if isinstance(e, dict):
                    endpoints_out.append(e)
    return forms_out, endpoints_out


# ---------------------------------------------------------------------------
# iter-Q5.44 — domain → child-asset pivoting (subdomain promotion)
# ---------------------------------------------------------------------------
# After `_ANCHORS_DOMAIN` runs, the per-tool raw_result dicts carry
# the discovered subdomains. Today nothing reads them — the L2 lead
# sees the count via the run summary, but downstream orchestrators
# (webappsec wrapper) can't spawn per-subdomain child scans without a
# stable schema.
#
# This helper extracts the union of discovered subdomains across:
#   * domain_recon_pipeline — raw_result["surface_map"]["subdomain_enum"]["subdomains"]
#                              + raw_result["surface_map"]["subdomain_triage"][] (with IPs / schemes)
#   * enumerate_subdomains_subfinder — raw_result["findings"][].subdomain
#
# and shapes them into PrepassSummary.child_assets_discovered with a
# stable per-entry schema (host / ip / asset_type / scheme / triage / source).
#
# The classification rule: when triage data is present and the
# subdomain has an HTTP scheme, route it as `web_application`;
# otherwise route as `ip_address`. Operators / wrappers can override
# the asset_type by their own policy — we provide the most-likely
# default so the pivot is one step rather than two.


def _normalise_host(value: str) -> str:
    """Strip scheme + path + port off a string so it's a bare host."""
    s = value.strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    if "/" in s:
        s = s.split("/", 1)[0]
    if ":" in s and not s.startswith("["):  # leave IPv6 brackets alone
        s = s.rsplit(":", 1)[0]
    return s.rstrip(".")


def _extract_child_assets_from_domain_prepass(
    summary: Any, apex_domain: str,
) -> list[dict[str, Any]]:
    """Extract discovered subdomains from domain-prepass tool_results.

    Reads from:
      * `domain_recon_pipeline` — primary source. Carries triage
        results with per-subdomain IP + scheme + live status.
      * `enumerate_subdomains_subfinder` — secondary source for
        subdomains the pipeline missed or didn't triage.

    Dedupes by host. When the pipeline and subfinder both report a
    host, the pipeline entry wins (carries richer triage data).

    The apex itself is excluded from the child list — the prepass
    already scanned it.

    Returns a list of dicts ready to set on
    `summary.child_assets_discovered`. Empty list is the no-op signal.
    """
    apex = _normalise_host(apex_domain or "")
    seen: dict[str, dict[str, Any]] = {}

    # Pass 1: domain_recon_pipeline (richer data wins).
    for tr in getattr(summary, "tool_results", []) or []:
        if getattr(tr, "tool_name", None) != "domain_recon_pipeline":
            continue
        raw = getattr(tr, "raw_result", None)
        if not isinstance(raw, dict):
            continue
        surface_map = raw.get("surface_map")
        if not isinstance(surface_map, dict):
            continue

        # Triage entries — preferred (carries IP + scheme + status).
        triage_list = surface_map.get("subdomain_triage")
        if isinstance(triage_list, list):
            for entry in triage_list:
                if not isinstance(entry, dict):
                    continue
                host = _normalise_host(str(entry.get("host") or ""))
                if not host or host == apex:
                    continue
                # Skip entries the pipeline already classified as dead/skip.
                triage = str(entry.get("triage") or "").strip().lower() or None
                if triage == "skip":
                    continue
                scheme = entry.get("scheme")
                if scheme not in ("http", "https"):
                    scheme = None
                ip = entry.get("ip") or None
                asset_type = (
                    "web_application" if scheme in ("http", "https") else "ip_address"
                )
                seen[host] = {
                    "host": host,
                    "ip": ip,
                    "asset_type": asset_type,
                    "scheme": scheme,
                    "triage": triage,
                    "source": "domain_recon_pipeline",
                }

        # Bare subdomain list fallback (in case triage skipped this host).
        enum_block = surface_map.get("subdomain_enum")
        if isinstance(enum_block, dict):
            subs = enum_block.get("subdomains")
            if isinstance(subs, list):
                for raw_host in subs:
                    if not isinstance(raw_host, str):
                        continue
                    host = _normalise_host(raw_host)
                    if not host or host == apex or host in seen:
                        continue
                    seen[host] = {
                        "host": host,
                        "ip": None,
                        # Default to ip_address until triage proves otherwise.
                        # Wrappers can probe + reclassify on their side.
                        "asset_type": "ip_address",
                        "scheme": None,
                        "triage": None,
                        "source": "domain_recon_pipeline",
                    }

    # Pass 2: enumerate_subdomains_subfinder (only fills gaps).
    for tr in getattr(summary, "tool_results", []) or []:
        if getattr(tr, "tool_name", None) != "enumerate_subdomains_subfinder":
            continue
        raw = getattr(tr, "raw_result", None)
        if not isinstance(raw, dict):
            continue
        findings = raw.get("findings")
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            host = _normalise_host(str(f.get("subdomain") or f.get("host") or ""))
            if not host or host == apex or host in seen:
                continue
            seen[host] = {
                "host": host,
                "ip": f.get("ip") or None,
                "asset_type": "ip_address",
                "scheme": None,
                "triage": None,
                "source": "enumerate_subdomains_subfinder",
            }

    # Pass 3: enumerate_subdomains_amass — iter-Q5.45 sibling to
    # subfinder. amass returns subdomains in a top-level `subdomains`
    # list (not under `findings`); same gap-fill semantics as
    # subfinder — only adds hosts the pipeline missed.
    for tr in getattr(summary, "tool_results", []) or []:
        if getattr(tr, "tool_name", None) != "enumerate_subdomains_amass":
            continue
        raw = getattr(tr, "raw_result", None)
        if not isinstance(raw, dict):
            continue
        subs = raw.get("subdomains")
        if not isinstance(subs, list):
            continue
        for raw_host in subs:
            if not isinstance(raw_host, str):
                continue
            host = _normalise_host(raw_host)
            if not host or host == apex or host in seen:
                continue
            seen[host] = {
                "host": host,
                "ip": None,
                "asset_type": "ip_address",
                "scheme": None,
                "triage": None,
                "source": "enumerate_subdomains_amass",
            }

    # Stable order so downstream snapshots compare cleanly.
    return [seen[h] for h in sorted(seen)]


# ---------------------------------------------------------------------------
# iter-Q5.34e — anchor-prepass fan-out across crawled URLs
# ---------------------------------------------------------------------------
# Phase-1 anchors fire each tool ONCE against the seed URL. For
# `web_application` / `api` targets where katana / web_crawler /
# openapi_ingest discover dozens-to-thousands of additional URLs (e.g.
# WAVSEP's 1,133-case fixture surfaced via /wavsep/scan-entry-points.html),
# those discoveries today only reach the L2 lead — they never feed back
# into the L1 deep-specialist tools. Result: 0% recall against WAVSEP
# in `STRIX_L2_DISABLED=1` runs (iter-Q5.34d bench).
#
# This phase re-fires a curated subset of deep specialists per discovered
# URL. Capped per-tool so we don't fire e.g. sqlmap 1,133 times in a
# single run; uses STRIX_DISPATCH_CONCURRENCY for the same parallelism
# the shape-aware dispatcher already uses.
#
# Opt-in via STRIX_ANCHOR_FANOUT=1 (default off) — the existing recall
# numbers are the published baseline; turning this on changes them.

# Per-tool URL cap. Override via STRIX_ANCHOR_FANOUT_LIMIT=N.
_DEFAULT_FANOUT_LIMIT = 50

# The fan-out tool set is intentionally NARROWER than the per-seed
# anchor list. Each tool here costs O(N_urls) sandbox calls; fire only
# the highest-leverage detectors:
#   * scan_sqli_sqlmap — primary SQL-injection detector (CWE-89)
#   * scan_xss_dalfox — primary reflected/DOM XSS detector (CWE-79)
#   * open_redirect_check — open-redirect detector (CWE-601)
#   * scan_nuclei_templates — broad CVE/template coverage (catches
#     CWE-22 LFI and many others via the lfi/path-traversal tag set)
_FANOUT_DEEP_SPECIALISTS_WEB: list[tuple[str, Any]] = [
    ("scan_sqli_sqlmap", _api_target_url_kwargs),
    ("scan_xss_dalfox", _api_target_url_kwargs),
    ("open_redirect_check", _api_target_url_kwargs),
    ("scan_nuclei_templates", _api_url_kwargs),
]


# ---------------------------------------------------------------------------
# iter-Q5.34j — per-URL tool routing
# ---------------------------------------------------------------------------
# Commercial DASTs don't fire every detector at every URL — they route based
# on URL/param shape (Burp's "audit insertion points", Acunetix's
# "intelligent fuzzing", Netsparker's "vulnerability profile per URL"). Without
# routing, fan-out wastes ~50% of dispatches: e.g. sqlmap against a
# /static/.html with no params, dalfox against an /api/v1/users/123 with a
# numeric-only ID. Worse, total wall time scales linearly with N_tools ×
# N_urls when many of those pairs have no signal.
#
# Each fan-out specialist gets an "interest predicate" — a fast (no I/O)
# heuristic on the URL's path + query-param names. The predicate returns
# True iff the URL has at least one plausible attack surface for that tool.

# Param-name hints — common conventions across web frameworks. Sets so we can
# do O(1) intersect against the URL's actual param names.
_SQLI_PARAM_NAMES: frozenset[str] = frozenset({
    # IDs / FKs / pagination — typical SQLi targets.
    "id", "uid", "user_id", "userid", "pid", "product_id", "cat_id",
    "category_id", "item_id", "order_id", "page_id", "post_id",
    "ref_id", "session_id",
    # Credentials / login fields.
    "user", "username", "uname", "email", "login",
    "password", "passwd", "pwd", "pass",
    # Search / filter — heavily exercised by sqlmap.
    "q", "query", "search", "keyword", "kw", "term",
    "filter", "sort", "order", "orderby", "field", "select",
    # Pagination.
    "page", "limit", "offset", "count", "per_page", "pagesize",
    # Categorization.
    "category", "cat", "type", "kind", "role", "status",
    # Generic user input fields that get passed to backend queries.
    "name", "title", "tag", "alias", "label",
    "input", "data", "val", "value",
    "msg", "message", "comment", "subject",
})

# Params with file-path / include-path semantics — LFI / RFI / path-traversal
# territory, NOT SQLi or XSS.
_LFI_PARAM_NAMES: frozenset[str] = frozenset({
    "file", "filename", "path", "pathname",
    "include", "inc",
    "template", "tpl", "view", "viewname", "doc", "document",
    "show", "display", "open", "load",
    "img", "image",
})

# Params with URL semantics — open-redirect / SSRF candidates.
_REDIRECT_PARAM_NAMES: frozenset[str] = frozenset({
    "url", "redirect", "redir", "return", "returnurl", "return_url",
    "next", "next_url", "target", "dest", "destination",
    "goto", "to", "callback", "continue", "forward",
    "ref", "referrer", "referer",
    "redirect_uri", "redirect_url", "u",
    "r", "back", "back_url", "rurl",
})

# Path substrings that strongly hint a vuln class. Mostly populated by
# benchmark-style fixtures (WAVSEP, DVWA, Juice Shop) but real-world auth /
# search / login URLs also land here as a low-confidence signal.
_PATH_HINTS_SQLI: tuple[str, ...] = (
    "/sql-injection/", "/sqli/", "/sql_injection/",
    # iter-Q5.34k — `/login`, `/signin`, `/auth*` REMOVED from this list.
    # They're handled by `_PATH_HINTS_LOGIN` below — login URLs route to
    # nuclei only (NOT sqlmap), because sqlmap aggression against a
    # credential form triggers account lockout / CAPTCHA. Real auth
    # bypass goes through scan_auth_flow + probe_default_creds.
)
_PATH_HINTS_XSS: tuple[str, ...] = (
    "/xss/", "/rxss/", "/dom-xss/", "/reflected-xss/", "/stored-xss/",
    "/search", "/comment", "/feedback", "/contact",
)
_PATH_HINTS_REDIRECT: tuple[str, ...] = (
    "/redirect/", "/unvalidated-redirect/", "/open-redirect/",
    "/sso/", "/oauth/", "/logout",
)


def _routing_enabled() -> bool:
    """iter-Q5.34j — per-URL tool routing. Default ON; flip with
    `STRIX_ANCHOR_FANOUT_ROUTING=0` to fall back to firing every fan-out
    tool against every URL (useful for benchmark ablation)."""
    raw = (os.environ.get("STRIX_ANCHOR_FANOUT_ROUTING") or "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    return True


def _has_sqli_signal(parsed: Any, params: set[str]) -> bool:
    """sqlmap is expensive — fire only when there's at least one
    plausible injection surface."""
    if params & _SQLI_PARAM_NAMES:
        return True
    path = (parsed.path or "").lower()
    return any(h in path for h in _PATH_HINTS_SQLI)


def _has_xss_signal(parsed: Any, params: set[str]) -> bool:
    """dalfox is broader — checks reflection of every param it sees. Fire
    whenever the URL has any non-file/non-redirect-shaped param OR matches
    an XSS-hinting path."""
    text_params = params - _LFI_PARAM_NAMES - _REDIRECT_PARAM_NAMES - {
        "id", "uid", "user_id", "userid", "pid", "page_id",
    }
    if text_params:
        return True
    path = (parsed.path or "").lower()
    return any(h in path for h in _PATH_HINTS_XSS)


def _has_redirect_signal(parsed: Any, params: set[str]) -> bool:
    """open-redirect check needs a URL-shaped param OR a redirect-style
    path. Without those, it's a guaranteed no-op."""
    if params & _REDIRECT_PARAM_NAMES:
        return True
    path = (parsed.path or "").lower()
    return any(h in path for h in _PATH_HINTS_REDIRECT)


def _has_nuclei_signal(parsed: Any, params: set[str]) -> bool:
    """nuclei runs a broad template corpus (CVE / misconfig / LFI / SSRF /
    default-creds) — every URL is a potential template match. Fire always."""
    return True


# (tool_name, kwarg_builder, interest_predicate). The order is the order
# fan-out dispatches them; predicate gates each (URL, tool) pair.
_FANOUT_TOOL_INTEREST: list[tuple[str, Any, Any]] = [
    ("scan_sqli_sqlmap", _api_target_url_kwargs, _has_sqli_signal),
    ("scan_xss_dalfox", _api_target_url_kwargs, _has_xss_signal),
    ("open_redirect_check", _api_target_url_kwargs, _has_redirect_signal),
    ("scan_nuclei_templates", _api_url_kwargs, _has_nuclei_signal),
]


def _select_tools_for_url(url: str) -> list[tuple[str, Any]]:
    """Return the (tool_name, kwarg_builder) pairs whose interest predicate
    matches this URL. When STRIX_ANCHOR_FANOUT_ROUTING=0 the full
    `_FANOUT_DEEP_SPECIALISTS_WEB` list is returned (ablation mode).

    iter-Q5.34k — login URLs are short-circuited to nuclei ONLY. Firing
    sqlmap / dalfox against `?username=...&password=...` triggers account
    lockout / CAPTCHA on most real apps; auth bypass goes through
    scan_auth_flow + probe_default_creds (separate anchor tools that run
    once, not per-URL)."""
    if not _routing_enabled():
        return list(_FANOUT_DEEP_SPECIALISTS_WEB)
    from urllib.parse import parse_qs, urlparse
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return list(_FANOUT_DEEP_SPECIALISTS_WEB)
    # iter-Q5.34k — login protection. Match before any other predicate so
    # sqlmap NEVER fires against a login form.
    if _is_login_url(parsed):
        return [
            (name, builder)
            for name, builder, _pred in _FANOUT_TOOL_INTEREST
            if name == "scan_nuclei_templates"
        ]
    params = set((parse_qs(parsed.query) or {}).keys())
    out: list[tuple[str, Any]] = []
    for tool_name, builder, predicate in _FANOUT_TOOL_INTEREST:
        try:
            if predicate(parsed, params):
                out.append((tool_name, builder))
        except Exception:  # noqa: BLE001
            # A misbehaving predicate must NOT silently drop the tool.
            # Worst case: dispatch when we shouldn't — same as no routing.
            out.append((tool_name, builder))
    return out


# ---------------------------------------------------------------------------
# iter-Q5.40 — API per-endpoint routing
# ---------------------------------------------------------------------------
# Same shape as Q5.34j (per-URL routing for web_application) but applied to
# the API phase-2 dispatch. Without this, openapi_spec_ingest's endpoint
# list (often 100+ entries on real specs) is passed wholesale to every
# OWASP API specialist — BOLA fires on POST /users (no resource ID to
# probe), BFLA fires on GET /health (read-only), mass_assignment fires on
# DELETE /sessions (nothing to mass-assign). The waste is real on
# documented APIs + the noise dominates downstream triage.
#
# Routing rules:
#   * scan_api_bola / scan_idor    → GET methods AND path has `:id` segment
#                                    (path-param-driven object access)
#   * scan_api_bfla                → state-changing methods (POST/PUT/PATCH/DELETE)
#   * scan_api_mass_assignment     → POST/PUT/PATCH only (DELETE has no body to
#                                    mass-assign)
#
# Pre-filter drops endpoints that aren't worth probing at all:
#   * health / metrics / probes    → /health, /metrics, /ping, /version, ...
#   * spec endpoints               → /swagger, /openapi.json, /api-docs
#   * (GraphQL kept by default — gets routed to inql / graphql probes
#      elsewhere; not the REST-style specialist target)


_API_HEALTH_PATH_HINTS: tuple[str, ...] = (
    "/health", "/healthz", "/healthcheck", "/health-check",
    "/status", "/statusz",
    "/metrics", "/prometheus", "/stats",
    "/ping", "/pong",
    "/ready", "/readiness", "/readyz",
    "/live", "/liveness", "/livez",
    "/version", "/build-info", "/info",
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
)
_API_SPEC_PATH_HINTS: tuple[str, ...] = (
    "/swagger", "/openapi", "/api-docs", "/api/docs",
    "/redoc", "/rapidoc", "/v3/api-docs",
)
_API_GRAPHQL_PATH_HINTS: tuple[str, ...] = (
    "/graphql", "/graphiql", "/playground", "/altair",
)
_API_STATE_CHANGING_METHODS: frozenset[str] = frozenset({
    "POST", "PUT", "PATCH", "DELETE",
})
_API_MASS_ASSIGN_METHODS: frozenset[str] = frozenset({
    "POST", "PUT", "PATCH",
})
# Matches `{id}`, `{userId}`, `/:id`, `/:user_id` — the canonical path-param
# styles emitted by openapi_spec_ingest (OpenAPI / Express / Rails).
_API_PATH_ID_RE = _re.compile(r"\{[^/{}]+\}|/:[A-Za-z_][A-Za-z0-9_]*")


def _api_routing_enabled() -> bool:
    """iter-Q5.40 — opt-out via STRIX_API_ENDPOINT_ROUTING=0 (ablation).
    Default ON; the routing is structural to the API phase-2 dispatch and
    matches what every API security tool does at the route-table level."""
    raw = (os.environ.get("STRIX_API_ENDPOINT_ROUTING") or "").strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    return True


def _api_endpoint_path(ep: Any) -> str:
    """Extract just the URL path from an endpoint dict (openapi_spec_ingest
    sometimes emits absolute URLs, sometimes just paths)."""
    if not isinstance(ep, dict):
        return ""
    raw = str(ep.get("path") or ep.get("url") or "")
    if raw.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        try:
            return urlparse(raw).path or ""
        except Exception:  # noqa: BLE001
            return raw
    return raw


def _api_endpoint_method(ep: Any) -> str:
    if not isinstance(ep, dict):
        return "GET"
    return str(ep.get("method") or "GET").upper()


def _is_api_health_endpoint(ep: Any) -> bool:
    path = _api_endpoint_path(ep).lower().rstrip("/")
    return any(
        path == h or path.startswith(h + "/") or path.endswith(h)
        for h in _API_HEALTH_PATH_HINTS
    )


def _is_api_spec_endpoint(ep: Any) -> bool:
    path = _api_endpoint_path(ep).lower()
    return any(h in path for h in _API_SPEC_PATH_HINTS)


def _is_api_graphql_endpoint(ep: Any) -> bool:
    path = _api_endpoint_path(ep).lower()
    return any(h in path for h in _API_GRAPHQL_PATH_HINTS)


def _has_api_path_id(ep: Any) -> bool:
    """True when path contains an `:id`-style or `{id}`-style segment —
    i.e. the endpoint operates on a specific resource (BOLA candidate)."""
    return bool(_API_PATH_ID_RE.search(_api_endpoint_path(ep)))


def _filter_api_endpoints(
    endpoints: list[Any],
    *,
    drop_health: bool = True,
    drop_spec: bool = True,
    drop_graphql: bool = False,
) -> tuple[list[Any], dict[str, int]]:
    """Drop endpoints that aren't worth deep-probing. Returns
    (filtered_endpoints, rejected_counts)."""
    out: list[Any] = []
    rejected: dict[str, int] = {"health": 0, "spec": 0, "graphql": 0}
    for ep in endpoints or []:
        if drop_health and _is_api_health_endpoint(ep):
            rejected["health"] += 1
            continue
        if drop_spec and _is_api_spec_endpoint(ep):
            rejected["spec"] += 1
            continue
        if drop_graphql and _is_api_graphql_endpoint(ep):
            rejected["graphql"] += 1
            continue
        out.append(ep)
    return out, rejected


def _endpoints_for_api_tool(
    endpoints: list[Any], tool_name: str,
) -> list[Any]:
    """Per-tool endpoint subset. Returns only endpoints whose shape matches
    the tool's vulnerability class.

    When STRIX_API_ENDPOINT_ROUTING=0 (ablation), returns the full input —
    every tool gets every endpoint, the pre-iter-Q5.40 contract."""
    if not _api_routing_enabled():
        return list(endpoints or [])
    out: list[Any] = []
    for ep in endpoints or []:
        method = _api_endpoint_method(ep)
        has_id = _has_api_path_id(ep)
        if tool_name in ("scan_api_bola", "scan_idor"):
            if method == "GET" and has_id:
                out.append(ep)
        elif tool_name == "scan_api_bfla":
            if method in _API_STATE_CHANGING_METHODS:
                out.append(ep)
        elif tool_name == "scan_api_mass_assignment":
            if method in _API_MASS_ASSIGN_METHODS:
                out.append(ep)
        else:
            # No specific filter known — fall through (broad signature
            # probes like sqli / ssrf go everywhere).
            out.append(ep)
    return out


def _anchor_fanout_enabled() -> bool:
    """iter-Q5.34e — opt-in switch for the per-URL fan-out phase.
    Default off; flip with `STRIX_ANCHOR_FANOUT=1`."""
    return os.environ.get("STRIX_ANCHOR_FANOUT", "").lower() in (
        "1", "true", "yes", "on",
    )


def _anchor_fanout_limit() -> int:
    """iter-Q5.34e — per-tool URL cap. Default 50; override with
    `STRIX_ANCHOR_FANOUT_LIMIT=N`. Clamped to [1, 1000] so an
    accidental N=100_000 doesn't take a benchmark hostage."""
    raw = os.environ.get("STRIX_ANCHOR_FANOUT_LIMIT", "").strip()
    try:
        n = int(raw) if raw else _DEFAULT_FANOUT_LIMIT
    except (TypeError, ValueError):
        return _DEFAULT_FANOUT_LIMIT
    return max(1, min(1000, n))


# ---------------------------------------------------------------------------
# iter-Q5.34i — fan-out filters (static / destructive / shape-dedup)
# ---------------------------------------------------------------------------
# Every commercial DAST (Acunetix/Netsparker/Burp/ZAP) drops a large
# fraction of crawled URLs before per-URL probing: static assets can't
# be vulnerable; destructive URLs kill the scan session; query-value
# variations of the same path are the same shape. Without these
# filters, fan-out wastes O(N) sqlmap/dalfox calls on .css/.png/duplicates
# and risks tripping logout/delete URLs.
#
# We piggyback on the existing iter-29.1 `EndpointProfile` classifier
# (same code the shape-aware dispatcher uses). To keep fan-out cheap
# we run the classifier with `probe_if_no_response=False` — pure URL
# pattern + extension analysis, no extra HTTP round-trips.

# Shapes the fan-out specialists can't meaningfully probe.
_FANOUT_SKIP_SHAPES: frozenset[str] = frozenset({"static"})

# Endpoint classes the fan-out MUST NOT probe — destructive URLs
# would mutate the target's state and break a clean re-scan; logout
# would kill the scan session.
_FANOUT_SKIP_CLASSES: frozenset[str] = frozenset({
    "destructive", "auth-logout", "static-asset",
})


# ---------------------------------------------------------------------------
# iter-Q5.34k — scope + path-shape dedup + login protection
# ---------------------------------------------------------------------------
# Q5.34i covered extension/destructive/query-name dedup. Three critical
# gaps remained:
#
#   * Scope:  katana follows third-party `<a href>` (twitter, fb, cdn) →
#             without scope we'd probe other people's sites
#   * Path:   `/items/1`, `/items/2`, ..., `/items/N` were treated as N
#             distinct URLs, exploding sqlmap on catalog-style apps
#   * Auth:   `/login` matched the SQLi path hint → routing fired sqlmap,
#             triggering lockout / CAPTCHA. Login auth-bypass belongs to
#             scan_auth_flow + probe_default_creds, not fan-out's sqlmap.


_UUID_RE = _re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    _re.IGNORECASE,
)
_HASH_HEX_RE = _re.compile(r"^[0-9a-f]{20,}$", _re.IGNORECASE)
_DATE_RE = _re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _normalize_path_segment(seg: str) -> str:
    """Replace opaque variable segments with their shape placeholder.

    Conservative — segments that aren't unambiguously variable (e.g.
    `iphone-15`, `Case01.jsp`) are left as-is so legitimately-distinct
    paths don't get collapsed."""
    if not seg:
        return seg
    if seg.isdigit():
        return ":int"
    if _UUID_RE.match(seg):
        return ":uuid"
    if _HASH_HEX_RE.match(seg):
        return ":hash"
    if _DATE_RE.match(seg):
        return ":date"
    return seg


def _path_shape(path: str) -> str:
    """`/items/1` → `/items/:int`, `/users/<uuid>/profile` →
    `/users/:uuid/profile`. Keeps real path component names so the
    dedup doesn't collapse unrelated routes."""
    if not path:
        return "/"
    segments = [_normalize_path_segment(s) for s in path.strip("/").split("/")]
    return "/" + "/".join(segments)


def _normalize_host(host: str) -> str:
    """Strip `www.` so `www.x.com` and `x.com` are scope-equivalent."""
    if not host:
        return ""
    host = host.lower().strip()
    if host.startswith("www."):
        return host[4:]
    return host


def _scope_extra_hosts() -> set[str]:
    """`STRIX_ANCHOR_FANOUT_SCOPE_HOSTS=api.x.com,app.x.com` whitelists
    extra hostnames the default scope filter would otherwise reject.
    Useful for multi-domain SaaS apps where seed=x.com but the API lives
    on api.x.com."""
    raw = os.environ.get("STRIX_ANCHOR_FANOUT_SCOPE_HOSTS", "")
    return {_normalize_host(h) for h in raw.split(",") if h.strip()}


def _in_scope(url: str, seed_host: str) -> bool:
    """Default policy: same host or any subdomain of the seed host.

    Localhost / 127.0.0.1 / host.docker.internal are always in-scope —
    standard bench fixture conventions; disabling them would break every
    docker-compose-mounted target."""
    from urllib.parse import urlparse
    try:
        host = _normalize_host(urlparse(url).hostname or "")
    except Exception:  # noqa: BLE001
        return False
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "host.docker.internal"}:
        return True
    if host in _scope_extra_hosts():
        return True
    if not seed_host:
        return True
    if host == seed_host:
        return True
    return host.endswith("." + seed_host)


# Login / signin URL fragments. fan-out routes these to nuclei ONLY —
# sqlmap aggression triggers account lockout, dalfox payloads are wasted on
# credential forms. Real auth bypass goes through scan_auth_flow +
# probe_default_creds (separate anchor tools).
_PATH_HINTS_LOGIN: tuple[str, ...] = (
    "/login", "/signin", "/sign-in", "/sign_in",
    "/auth/login", "/auth/signin", "/auth/sign-in",
    "/account/login", "/user/login", "/users/sign_in",
    "/users/login", "/session/new", "/sessions/new",
)


def _is_login_url(parsed_or_url: Any) -> bool:
    """True if the URL's path matches a known login/signin pattern. Accepts
    either a urlparse result or a raw URL string."""
    from urllib.parse import urlparse
    if isinstance(parsed_or_url, str):
        try:
            parsed = urlparse(parsed_or_url)
        except Exception:  # noqa: BLE001
            return False
    else:
        parsed = parsed_or_url
    path = (parsed.path or "").lower()
    return any(h in path for h in _PATH_HINTS_LOGIN)


def _fanout_dedup_key(url: str) -> str:
    """Shape-key for deduplication: same host + path-SHAPE + sorted set of
    query parameter NAMES (values dropped).

    iter-Q5.34i normalized only query VALUES (`/p?id=1` and `?id=2`
    collapsed). iter-Q5.34k extends this to PATH segments so `/items/1`,
    `/items/2`, ..., `/items/N` also collapse to `/items/:int` —
    catalog-style apps with thousands of numerically-indexed pages no
    longer explode the dispatch budget."""
    from urllib.parse import urlparse, parse_qs
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return url
    host = _normalize_host(parsed.netloc or "")
    path = _path_shape(parsed.path or "/")
    query_keys = ",".join(sorted((parse_qs(parsed.query) or {}).keys()))
    return f"{parsed.scheme}://{host}{path}?{query_keys}"


def _should_skip_for_fanout(url: str) -> tuple[bool, str]:
    """Classifier-driven gate. Returns (should_skip, reason_tag)."""
    try:
        from strix.l15.endpoint_classifier import classify_endpoint
        profile = classify_endpoint(url, probe_if_no_response=False)
    except Exception:  # noqa: BLE001
        # Classifier failure is non-fatal — let the URL through. The
        # downstream specialist will handle malformed URLs itself.
        return False, ""
    if profile.shape in _FANOUT_SKIP_SHAPES:
        return True, f"shape={profile.shape}"
    if profile.endpoint_class in _FANOUT_SKIP_CLASSES:
        return True, f"class={profile.endpoint_class}"
    return False, ""


def _select_fanout_urls(
    seed_url: str,
    limit: int,
    summary: PrepassSummary | None = None,
) -> list[str]:
    """Select URLs to fan out across, in priority order:

    1. **Phase-1 tool results** — `summary.tool_results[i].raw_result.endpoints`
       carries the per-endpoint dicts emitted by crawl_with_katana /
       web_crawler / openapi_spec_ingest. This is the primary source
       because those tools execute in the sandbox container, write to
       the **sandbox-side** workflow_state singleton, and the only
       data that makes it back to the host is the tool's return value
       (the `raw_result` dict). See CLAUDE.md §5.1 / iter-35.4 for the
       same class of issue with vulnerability_reports.

    2. **Host-side workflow_state** — `get_endpoints_discovered_urls()`.
       Picks up URLs from any host-side recorders (lead-driven URL
       discovery, future sandbox→host workflow_state propagation).

    Filtering pipeline (iter-Q5.34i):
      * Filter to http(s) only
      * Drop the seed URL (already covered by phase 1's per-seed pass)
      * Drop URLs the EndpointProfile classifier rejects (static
        assets, destructive endpoints, logout) — matches what every
        commercial DAST does pre-probing
      * Shape-dedup by (host, path, sorted query-param NAMES) so
        `/x?id=1` and `/x?id=2` collapse to one
      * Sort for determinism + cap to `limit`
    """
    candidate_urls: set[str] = set()

    # Source 1: tool_results endpoints (sandbox→host sidecar).
    if summary is not None:
        for tr in getattr(summary, "tool_results", []) or []:
            raw = getattr(tr, "raw_result", None)
            if not isinstance(raw, dict):
                continue
            for ep in raw.get("endpoints") or []:
                if isinstance(ep, dict):
                    u = ep.get("url")
                    if isinstance(u, str):
                        candidate_urls.add(u)
                elif isinstance(ep, str):
                    candidate_urls.add(ep)

    # Source 2: host-side workflow_state.
    try:
        from strix.agents.workflow_state import get_endpoints_discovered_urls
        for u in get_endpoints_discovered_urls():
            if isinstance(u, str):
                candidate_urls.add(u)
    except Exception:  # noqa: BLE001
        pass

    seed_norm = (seed_url or "").rstrip("/")
    # iter-Q5.34k — scope filter against the seed's hostname.
    from urllib.parse import urlparse as _urlparse_q5k
    try:
        seed_host = _normalize_host(_urlparse_q5k(seed_url or "").hostname or "")
    except Exception:  # noqa: BLE001
        seed_host = ""

    out: list[str] = []
    seen_keys: set[str] = set()
    rejected: dict[str, int] = {
        "non_http": 0, "seed": 0, "out_of_scope": 0,
        "static": 0, "destructive": 0, "shape_dup": 0,
    }
    for url in sorted(candidate_urls):
        if not url.lower().startswith(("http://", "https://")):
            rejected["non_http"] += 1
            continue
        if url.rstrip("/") == seed_norm:
            rejected["seed"] += 1
            continue
        # iter-Q5.34k — scope filter. Drop URLs that katana followed off-site
        # (twitter share buttons, fb-pixel, CDNs, third-party widgets) so
        # fan-out never probes assets belonging to anyone else. Honors
        # STRIX_ANCHOR_FANOUT_SCOPE_HOSTS for multi-domain SaaS apps.
        if not _in_scope(url, seed_host):
            rejected["out_of_scope"] += 1
            continue
        # iter-Q5.34i — classifier filter (skip static / destructive /
        # logout). Mirrors what every commercial DAST does before its
        # per-URL probe loop.
        skip, reason = _should_skip_for_fanout(url)
        if skip:
            if reason.startswith("shape="):
                rejected["static"] += 1
            else:
                rejected["destructive"] += 1
            continue
        # iter-Q5.34i + Q5.34k — shape-dedup so query-value AND path-value
        # variations of the same endpoint don't each soak up a full
        # sqlmap/dalfox run. Q5.34k extends iter-Q5.34i's query-name dedup
        # to also normalize numeric / UUID / hash / date path segments so
        # /items/1, /items/2, ..., /items/N all collapse to /items/:int.
        key = _fanout_dedup_key(url)
        if key in seen_keys:
            rejected["shape_dup"] += 1
            continue
        seen_keys.add(key)
        out.append(url)
        if len(out) >= limit:
            break
    if any(rejected.values()):
        logger.info(
            "anchor fanout filters dropped urls: %s; kept=%d",
            {k: v for k, v in rejected.items() if v}, len(out),
        )
    return out


# ---------------------------------------------------------------------------
# iter-Q5.34h — bridge list-shape findings to the host tracer
# ---------------------------------------------------------------------------
# Maps each finding's natural key set (rule_id / category / cwe / param /
# payload / etc.) to `tracer.add_vulnerability_report`'s kwargs. Used by
# the fan-out phase to surface findings that wrappers like dalfox / ffuf
# return as a plain list in their result dict.

# Tool-specific category fallback when the finding dict doesn't carry one.
# CWE_TO_CATEGORY ↔ owasp_benchmark_scoring.OWASP_BENCHMARK_CATEGORIES,
# kept aligned so per-CWE scoring works across both SAST/DAST harnesses.
_FANOUT_TOOL_CATEGORY_HINTS: dict[str, str] = {
    "scan_sqli_sqlmap": "sqli",
    "scan_xss_dalfox": "xss",
    "open_redirect_check": "redirect",
    "scan_nuclei_templates": "vulnerability",  # generic
    "scan_fuzz_ffuf": "info_disclosure",
    "scan_smuggling_smuggler": "http_smuggling",
}


def _bridge_findings_to_tracer(
    findings: list[Any],
    *,
    tool_name: str,
    url: str,
) -> None:
    """Emit each list-shape finding via `tracer.add_vulnerability_report`.

    iter-Q5.34h — wrappers that produce findings in `result["findings"]`
    (vs calling tracer themselves) historically had their findings dropped
    by the prepass: the L1.5 sidecar (iter-35.4) only intercepts
    tracer-emitted reports. This helper bridges the gap.

    Robust to varied finding shapes — only the strict superset of fields
    that map to `add_vulnerability_report` kwargs is forwarded; unknown
    keys are ignored. Failures are logged + swallowed so a malformed
    finding never aborts the fan-out pass.
    """
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
    except Exception:  # noqa: BLE001
        return
    if tracer is None:
        return

    category_hint = _FANOUT_TOOL_CATEGORY_HINTS.get(tool_name)

    for f in findings:
        if not isinstance(f, dict):
            continue

        # Build the add_vulnerability_report kwargs. Each key is the
        # canonical name on the tracer side; the right-hand side is the
        # preferred finding-dict location followed by fallbacks.
        title = (
            f.get("title")
            or f.get("rule_id")
            or f"{tool_name} finding on {url}"
        )
        severity = str(f.get("severity") or "medium").lower()
        endpoint = (
            f.get("endpoint")
            or f.get("url")
            or url
        )
        kwargs: dict[str, Any] = {
            "title": str(title)[:300],
            "severity": severity,
            "endpoint": str(endpoint)[:600],
        }
        for src_key, dst_key in (
            ("cwe", "cwe"), ("cve", "cve"),
            ("description", "description"),
            ("evidence", "technical_analysis"),
            ("remediation", "remediation_steps"),
            ("category", "category"), ("method", "method"),
            ("confidence", "confidence"),
        ):
            v = f.get(src_key)
            if v is not None:
                kwargs[dst_key] = v
        if "category" not in kwargs and category_hint:
            kwargs["category"] = category_hint
        # Pattern-match by default — fanout dispatches haven't run the
        # post-emit verifier (iter-32.4).
        kwargs.setdefault("verification_status", "pattern_match")

        try:
            tracer.add_vulnerability_report(**kwargs)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "anchor fanout: failed to bridge %s finding to tracer "
                "(%s: %s)", tool_name, type(e).__name__, e,
            )


async def _fanout_deep_specialists_across_endpoints(
    summary: PrepassSummary,
    *,
    target_type: str,
    target_value: str,
    agent_state: Any,
    timeout_s: int,
) -> None:
    """iter-Q5.34e — re-fire the deep-specialist subset against each
    crawled URL (up to the per-tool cap). Mutates `summary` in place.

    Skips entirely when:
      * `STRIX_ANCHOR_FANOUT` is not set
      * `target_type` is not in {web_application, api}
      * No crawled URLs are available in either tool_results sidecar
        or host-side workflow_state
    """
    if not _anchor_fanout_enabled():
        return
    if target_type not in ("web_application", "api"):
        return

    limit = _anchor_fanout_limit()
    urls = _select_fanout_urls(target_value, limit, summary=summary)
    if not urls:
        logger.info(
            "anchor fanout: STRIX_ANCHOR_FANOUT=1 but no crawled URLs "
            "available — phase skipped",
        )
        return

    # iter-Q5.34h — fan-out concurrency MUST default to 1. The sandbox
    # `tool_server` has a one-tool-per-agent_id contract: every new
    # `/execute` request cancels the previously-running task for the
    # same agent_id (so the lead's stale tool-call requests don't
    # accumulate). With STRIX_DISPATCH_CONCURRENCY=4, fan-out's
    # asyncio.gather races N dispatches through the same agent_id and
    # each cancels its predecessor — verified by the iter-Q5.34g WAVSEP
    # run where all 40 fan-out dispatches errored with
    # "Cancelled by newer request".
    # Operator can still override via STRIX_ANCHOR_FANOUT_CONCURRENCY
    # for environments where the lead doesn't share the agent_id.
    raw_conc = os.environ.get("STRIX_ANCHOR_FANOUT_CONCURRENCY", "1").strip()
    try:
        concurrency = max(1, min(16, int(raw_conc))) if raw_conc else 1
    except (TypeError, ValueError):
        concurrency = 1

    logger.info(
        "anchor fanout: %d URL(s), %d specialist(s), concurrency=%d, "
        "cap=%d/tool",
        len(urls),
        len(_FANOUT_DEEP_SPECIALISTS_WEB),
        concurrency,
        limit,
    )

    sem = asyncio.Semaphore(concurrency)
    rollup: dict[str, dict[str, int]] = {}

    async def _dispatch_one(
        tool_name: str, builder: Any, url: str, idx: int, total: int,
    ) -> ToolResult:
        kwargs = builder(url, "", tool_name)
        async with sem:
            result = await _run_one_tool(
                tool_name, kwargs,
                agent_state=agent_state, timeout_s=timeout_s,
            )
        # Tag the result so it's distinguishable from the per-seed run
        # of the same tool in `summary.tool_results`.
        result = ToolResult(
            tool_name=f"{tool_name}[fanout {idx + 1}/{total}]",
            status=result.status,
            findings_count=result.findings_count,
            error_reason=result.error_reason,
            wall_time_s=result.wall_time_s,
            raw_result=result.raw_result,
        )

        # iter-Q5.34h — bridge list-shape findings to the host tracer.
        #
        # Many L1 wrappers (dalfox, sqlmap, ffuf, smuggler, schemathesis,
        # etc.) return findings as a plain list in `result["findings"]`.
        # The iter-35.4 sandbox→host sidecar only catches findings emitted
        # via `tracer.add_vulnerability_report`; list-shape findings get
        # silently dropped — they appear in `tool_results.findings_count`
        # but never reach `vulnerabilities.json`.
        #
        # For fan-out specifically the cost of NOT bridging is total: a
        # 10-URL × 4-tool dispatch produces 0 reportable findings in
        # vulnerabilities.json even when every dispatch succeeds (as
        # confirmed by the iter-Q5.34g WAVSEP run that emitted 10 dalfox
        # XSS findings into tool_results but 0 into vulnerabilities.json).
        # Bridge here so the L1.5 hook chain + bench harness see them.
        if result.status in ("ok", "partial") and isinstance(
            result.raw_result, dict,
        ):
            raw_findings = result.raw_result.get("findings") or []
            if isinstance(raw_findings, list):
                _bridge_findings_to_tracer(
                    raw_findings, tool_name=tool_name, url=url,
                )

        bucket = rollup.setdefault(tool_name, {
            "attempted": 0, "succeeded": 0, "findings": 0,
        })
        bucket["attempted"] += 1
        if result.status in ("ok", "partial"):
            bucket["succeeded"] += 1
        bucket["findings"] += result.findings_count
        return result

    # iter-Q5.34j — build (url, tool, builder) triples via per-URL routing.
    # `_select_tools_for_url` returns the full specialist list when
    # STRIX_ANCHOR_FANOUT_ROUTING=0 (ablation), otherwise filters to tools
    # whose interest predicate matched.
    url_tool_pairs: list[tuple[str, str, Any]] = []
    skipped_pairs: dict[str, int] = {}
    for url in urls[:limit]:
        routed = _select_tools_for_url(url)
        routed_names = {t for t, _ in routed}
        for tool_name, _ in _FANOUT_DEEP_SPECIALISTS_WEB:
            if tool_name not in routed_names:
                skipped_pairs[tool_name] = skipped_pairs.get(tool_name, 0) + 1
        for tool_name, builder in routed:
            url_tool_pairs.append((url, tool_name, builder))
    if skipped_pairs:
        logger.info(
            "anchor fanout routing: skipped %d (tool, url) pairs without "
            "signal: %s",
            sum(skipped_pairs.values()), skipped_pairs,
        )

    tasks: list[Any] = []
    for i, (url, tool_name, builder) in enumerate(url_tool_pairs):
        tasks.append(_dispatch_one(
            tool_name, builder, url, i, len(url_tool_pairs),
        ))
    results: list[Any] = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, ToolResult):
            summary.tool_results.append(r)
            summary.total_findings += r.findings_count
            if r.status in ("ok", "partial"):
                summary.tools_succeeded.append(r.tool_name)
            else:
                summary.tools_failed.append(r.tool_name)
            summary.tools_run.append(r.tool_name)

    # Roll-up tool_result so the markdown report shows what fan-out did
    # in one row instead of N rows. Mirrors the iter-30.3 dispatcher
    # summary pattern.
    baseline_dispatches = len(urls[:limit]) * len(_FANOUT_DEEP_SPECIALISTS_WEB)
    actual_dispatches = len(url_tool_pairs)
    savings_pct = (
        round(100 * (baseline_dispatches - actual_dispatches) /
              max(1, baseline_dispatches), 1)
        if baseline_dispatches else 0.0
    )
    summary.tool_results.append(ToolResult(
        tool_name="anchor_fanout_summary",
        status="ok",
        findings_count=sum(b["findings"] for b in rollup.values()),
        raw_result={
            "status": "ok",
            "findings": [],
            "urls_total": len(urls),
            "concurrency": concurrency,
            "per_tool": rollup,
            # iter-Q5.34j routing telemetry — surfaces in the bench
            # markdown so operators can see how much waste was saved.
            "routing_enabled": _routing_enabled(),
            "baseline_dispatches": baseline_dispatches,
            "actual_dispatches": actual_dispatches,
            "savings_pct": savings_pct,
            "skipped_pairs_per_tool": skipped_pairs,
        },
    ))
    summary.tools_run.append("anchor_fanout_summary")
    summary.tools_succeeded.append("anchor_fanout_summary")
    logger.info(
        "anchor fanout complete: urls=%d per_tool=%s",
        len(urls), rollup,
    )


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
    # Target types with empty phase-1 anchor lists still get phase-2
    # dispatch (e.g. ip_address — no scan_* tool takes a bare IP, but
    # iter-13 added a TCP-probe phase-2). Without this allowance, the
    # prepass early-returns and ip_address recall stays at 0.
    _HAS_PHASE_2_DISPATCH = {"ip_address"}
    if not anchors and target_type not in _HAS_PHASE_2_DISPATCH:
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

    # iter-Q5.44 — domain phase-2: extract discovered subdomains
    # from the recon-pipeline + subfinder raw_results and surface
    # them as a stable `child_assets_discovered[]` sidecar on the
    # PrepassSummary. The downstream consumer (webappsec wrapper,
    # the L2 lead's system prompt context, asset-graph emitter)
    # uses the sidecar to spawn per-child scans without re-parsing
    # tool-specific output shapes. Never raises — extraction is
    # best-effort.
    if target_type == "domain" and target_value:
        try:
            children = _extract_child_assets_from_domain_prepass(
                summary, apex_domain=target_value,
            )
            summary.child_assets_discovered = children
            logger.info(
                "domain prepass child-asset pivot: apex=%s discovered=%d",
                target_value, len(children),
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "domain child-asset extraction raised %s: %s — continuing "
                "with empty sidecar", type(e).__name__, e,
            )

    # ip_address phase-2 — TCP port discovery + per-service probes.
    # No phase-1 anchors exist for ip_address (the existing scan_*
    # tools require a URL), so this is the entire L1 surface for
    # network targets.
    if target_type == "ip_address" and target_value:
        # iter-35.2 — pass agent_state + timeout_s so the per-port
        # probes dispatch through the sandbox tool_server instead of
        # firing raw sockets from the host.
        await _run_dependent_ip_tools(
            summary, target_value=target_value,
            agent_state=agent_state, timeout_s=timeout_s,
        )

    # iter-30 — phase 2.5: shape-aware dispatcher. Consumes katana's
    # forms[] output + openapi endpoints[] from earlier phase tools,
    # then per-endpoint:
    #   * classify (29.1 EndpointProfile)
    #   * skip static / destructive (29.9 safety_guards)
    #   * apply rate-limit cooldown (29.9 RateLimitGovernor)
    #   * fire shape-aware payloads (29.3 payload_bins)
    #   * diff vs baseline (29.2 DiffSignal)
    #   * verify with PoC re-fire + variant (29.5 verify_finding)
    #   * emit at `verified` / `likely` confidence only
    # seed_auth's STRIX_AUTH_BEARER threads through automatically via
    # iter-29.4's list_auth_states() env-synthesis.
    if target_type in ("api", "web_application") and target_value:
        try:
            from strix.agents.lead_agent.shape_aware_dispatcher import (
                shape_aware_dispatch,
            )
            forms_aggregate, endpoints_aggregate = _gather_surface_for_dispatcher(summary)
            dispatch_summary = shape_aware_dispatch(
                target_value,
                forms=forms_aggregate,
                endpoints=endpoints_aggregate,
                timeout=timeout_s,
            )
            # iter-30.2 — surface dispatcher findings as proper
            # ToolResult entries on summary.tool_results. Each
            # dispatcher finding becomes a synthetic ToolResult with
            # `raw_result.findings = [{...}]` shaped like a
            # SpecialistResult, so the L1 bench harness's
            # `for r in summary.tool_results: for f in raw.get("findings")`
            # scoring path picks them up. Without this, dispatcher
            # findings are visible to L2 (via tracer) but invisible to
            # L1 bench recall scoring.
            #
            # Generic shape — works for any future post-prepass
            # dispatcher that produces findings.
            for f in dispatch_summary.findings:
                summary.total_findings += 1
                summary.tool_results.append(ToolResult(
                    tool_name=f"shape_aware_dispatcher[{f.vuln_class}@{f.method} {f.endpoint}]",
                    status="ok",
                    findings_count=1,
                    raw_result={
                        "status": "ok",
                        "findings": [{
                            "category": f.vuln_class,
                            "endpoint": f.endpoint,
                            "method": f.method,
                            "payload_excerpt": f.payload_excerpt,
                            "confidence": f.confidence,
                            "score": f.score,
                            "reasons": f.reasons,
                            "description": (
                                f"Shape-aware dispatcher: {f.vuln_class} on "
                                f"{f.method} {f.endpoint} (confidence={f.confidence}, "
                                f"score={f.score:.2f})"
                            ),
                            "evidence": "; ".join(f.reasons) if f.reasons else "",
                        }],
                    },
                ))
            # iter-30.3 — always emit a dispatcher-summary tool_result
            # so the bench markdown reflects what the dispatcher did
            # even when findings=[] (otherwise it's invisible —
            # indistinguishable from "didn't run").
            summary.tool_results.append(ToolResult(
                tool_name="shape_aware_dispatcher",
                status="ok" if dispatch_summary.findings else "partial",
                findings_count=len(dispatch_summary.findings),
                wall_time_s=dispatch_summary.wall_time_s,
                raw_result={
                    "status": "ok",
                    "findings": [],   # per-finding entries above carry actual findings
                    "endpoints_seen": dispatch_summary.endpoints_seen,
                    "endpoints_probed": dispatch_summary.endpoints_probed,
                    "endpoints_skipped_static": dispatch_summary.endpoints_skipped_static,
                    "endpoints_skipped_destructive": dispatch_summary.endpoints_skipped_destructive,
                    "payloads_fired": dispatch_summary.payloads_fired,
                    "signals_above_threshold": dispatch_summary.signals_above_threshold,
                },
                error_reason=(
                    None if dispatch_summary.findings
                    else (
                        f"fired {dispatch_summary.payloads_fired} payload(s) across "
                        f"{dispatch_summary.endpoints_probed} endpoint(s); "
                        f"{dispatch_summary.signals_above_threshold} signal(s) above 0.5 threshold; "
                        f"0 verified findings"
                    )
                ),
            ))
            summary.tools_run.append("shape_aware_dispatcher")
            summary.tools_succeeded.append("shape_aware_dispatcher")
            logger.info(
                "shape-aware dispatcher: endpoints_seen=%d probed=%d "
                "payloads=%d signals=%d findings=%d wall=%.1fs",
                dispatch_summary.endpoints_seen,
                dispatch_summary.endpoints_probed,
                dispatch_summary.payloads_fired,
                dispatch_summary.signals_above_threshold,
                len(dispatch_summary.findings),
                dispatch_summary.wall_time_s,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "shape-aware dispatcher raised %s: %s — continuing without "
                "phase-2.5 dispatch", type(e).__name__, e,
            )

    # iter-Q5.34e — phase 3: fan out deep specialists (sqlmap / dalfox /
    # open_redirect_check / nuclei) across the URLs katana / web_crawler
    # / openapi_ingest registered in workflow_state. The per-seed run
    # already ran in phase 1; this hits the crawl tree. Opt-in via
    # STRIX_ANCHOR_FANOUT=1.
    if target_type in ("api", "web_application"):
        try:
            await _fanout_deep_specialists_across_endpoints(
                summary, target_type=target_type, target_value=target_value,
                agent_state=agent_state, timeout_s=timeout_s,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "anchor fanout raised %s: %s — continuing without "
                "phase-3 fan-out", type(e).__name__, e,
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
        "already ran inside the sandbox. Use your remaining "
        "iterations for ranking, dedupe, FP analysis, novel-vuln "
        "tagging, cross-asset correlation (SAST↔DAST chains), and "
        "final report emission."
    )
    lines.append("")
    return "\n".join(lines)
