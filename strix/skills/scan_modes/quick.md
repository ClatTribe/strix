---
name: quick
description: Time-boxed rapid assessment targeting high-impact vulnerabilities
---

# Quick Testing Mode

Time-boxed assessment focused on high-impact vulnerabilities. Prioritize breadth over depth.

## Engine constraints

- **`dispatch_specialist` is disabled in quick mode** (cap = 0). The
  fresh-context specialist loop is the largest cost driver, and quick
  mode trades that depth for breadth + speed. Calls to
  `dispatch_specialist` return `status=DENIED_BY_SCAN_MODE` —
  treat this as "use the deterministic specialist tool directly"
  (e.g. `scan_sqli`, `scan_xss`, `scan_idor`) rather than retrying.
- Reasoning effort is medium.
- Wall-clock target: under 10 minutes per asset.

## Detection model — what the LLM is *for* in quick mode

Quick mode's primary detection layer is the **OSS signature corpus**
(nuclei templates, semgrep registry, trivy vuln DB, grype DB,
osv-scanner GHSA feed, checkov rule pack). All of these ship inside
the strix-sandbox image with their signature databases pre-populated.

Your job as the lead is **NOT to act as a scanner.** The OSS tools are
already better at signature-matching than you are. Your job is the
ranking/dedupe/triage layer on top:

1. **Invoke** the deterministic-specialist wrappers (Phase 0 below)
   that route to the OSS scanners with proper output structure and
   KG emission.
2. **Read** the findings they emit.
3. **Dedupe** — when semgrep, nuclei, and trivy all flag the same
   issue, collapse to one finding with `discovery_method` recording
   each engine.
4. **Rank** by `contextual_priority` (already populated by
   `scan_*` wrappers via the MA-S2 P0 layer — KEV / EPSS≥0.7 →
   p0_emergency; high+EPSS≥0.5 → p1_urgent; etc.).
5. **Demote obvious false positives** — code that's clearly a test
   fixture, a unit-test helper, a docstring example, an unreferenced
   utility script.
6. **Emit** the final report. Maybe 5-10 LLM reasoning calls total —
   if you're doing more, you're doing exploratory detection that
   belongs in standard mode.

If your `scan_*` wrapper returns `status="partial"` because a backend
isn't installed, **surface that explicitly in the report**. Don't
silently move on — a missing backend is a recall regression that
the operator needs to know about (e.g. "semgrep not on PATH;
SAST-class findings will be incomplete").

## Approach

Optimize for fast feedback on critical security issues. Skip exhaustive enumeration in favor of targeted testing on high-value attack surfaces.

## Phase 0: Anchor scans — **REQUIRED before any other phase**

Quick mode without these anchor calls collapses to "LLM reads files and guesses,"
which produces 0–30% recall on benchmarks. The bar is set by free OSS pipelines
running these same tools directly (semgrep finds 15 vulns in flask-vuln in 3
seconds; trivy/grype/osv-scanner one-shot the SCA fixtures). **Strix has to at
least invoke them.**

Anchor the run on the target-type-appropriate deterministic specialist tools
**before** doing any custom reasoning. If a backend is missing (`scan_sast`
returns `status="partial"` etc.), surface that explicitly in your findings —
don't silently move on.

- **API targets (REST / GraphQL / gRPC):**
  1. `fingerprint_tech_stack` first (3-5 sec, picks the right nuclei tags).
  2. `scan_nuclei_templates(tags=['cve'], severity=['high', 'critical'])` —
     canonical signature-match path for known-CVE coverage.
     ~9k templates ship in the sandbox image.
  3. `openapi_spec_ingest` if a spec exists, else `fingerprint_tech_stack`-driven
     endpoint inventory.
  4. **Full L1.5 deterministic specialist sweep** — every relevant
     specialist in the lead's API catalog
     (`strix/agents/lead_agent/tool_catalog.py`). These are bounded,
     deterministic, ~free per check (one API roundtrip each, no LLM
     spend). There is no cost reason to subset them in quick mode.
     - OWASP API Top 10: `scan_api_bola`, `scan_api_bfla`,
       `scan_api_mass_assignment`, `scan_api_rate_limit`, `scan_idor`,
       `scan_multi_role_auth`, `scan_oauth`, `scan_saml_xsw`.
     - Injection class: `scan_sqli`, `scan_xxe`, `scan_blind_ssrf`,
       `scan_deserialization`, `scan_blind_cmd_injection`, `scan_ssrf`,
       `scan_ssti`, `scan_path_traversal`, `scan_nosql_injection`,
       `scan_ldap_injection`, `scan_xpath_injection`,
       `scan_cmd_injection`, `scan_oob_xxe`,
       `scan_request_smuggling_active`, `scan_secrets_in_response`.
     - Deterministic checks: `jwt_audit`, `tls_audit`,
       `http_security_headers_audit`, `cors_deep_check`, `csrf_check`,
       `open_redirect_check`, `sqli_check`, `authz_matrix_check`,
       `websocket_audit`, `race_check`, `cookie_jwt_scoping_check`.
     - GraphQL / gRPC: `graphql_introspection_deep`,
       `scan_api_grpc_reflection`.
     - Signal complements: `scan_response_anomaly`, `scan_timing_oracle`.
  5. **Skip only `scan_business_logic`** — that one is LLM-driven and
     belongs in standard/deep mode. Everything else is deterministic
     and stays in quick.

- **Repository / local_code targets — full L1+L1.5+L1.7 sweep:**
  1. `scan_sca_lockfiles` FIRST — dependency CVEs are the highest-EPSS
     finding class. `attack_path_membership` chain construction depends
     on Dependency-node emission. KEV / EPSS≥0.5 always override
     `priority_tier`. Emits via trivy + grype + osv-scanner internally.
  2. `scan_sast` (semgrep-driven, registry rules + vibe-coded pack) —
     diff-aware on PR context, fast.
  3. `scan_iac` if any IaC files exist (`vercel.json` / `netlify.toml` /
     `terraform/` / `Dockerfile` / `docker-compose.yml`). Cross-asset:
     IaC misconfigs (CORS-credentials, open redirects) become DAST
     hypotheses for the deployed URL. Backed by checkov.
  4. `secrets_scan` (gitleaks + trufflehog).
  5. `build_code_map` + `taint_analysis` + `score_reachability` —
     these are L1.5 reachability primitives, deterministic. Cheap.
     Their output feeds R9 unreachable_high_downgrade in L2.
  6. `lookup_known_cves` / `lookup_cve_by_id` for the fingerprinted
     stack — pure threat-intel lookup, free.

- **Web-application targets (HTML-rendering) — full L1+L1.5+L1.7 sweep:**
  Same API-target anchor sequence above PLUS the DOM-aware L1.5
  specialists: `scan_xss`, `dom_xss_static_probe`,
  `scan_cache_deception`, `scan_websocket_auth`,
  `scan_prototype_pollution`. If the repo is co-located (vibe-coded
  SaaS), also run the full repository sweep against the source path.

- **Container-image targets — full L1+L1.5+L1.7 sweep:**
  1. `scan_container_image` (trivy with vuln + misconfig + secret
     scanners enabled). Emits Dependency nodes that arm MOAK feed-
     trigger for future-CVE pipeline.
  2. `sbom_extract` for the dependency manifest.
  3. `lookup_known_cves` / `lookup_cve_by_id` for any high-EPSS hits.

- **Domain targets — full L1.5 recon sweep:**
  No signature corpus for the asset root itself, but L1.5 attack-
  surface mapping is deterministic and cheap: `subdomain_enum_tool`,
  `domain_recon_pipeline`, `dns_hygiene_check`, `passive_dns_history`,
  `reverse_ip`, `mail_recon`, `saas_leaks`, `well_known_harvest`,
  `discover_cloud_assets`, `scan_subdomain_takeover_active`. Plus
  threat-intel: `domain_rep`, `vt_reputation`, `hibp_breach`,
  `greynoise_classify`. Discovered services drop into the
  web_application / api anchor sequence above.

- **IP-address targets:**
  Lighter L1.5 set: nmap-based service discovery via
  `terminal_execute`, `tls_audit`, `websocket_audit` on any discovered
  TLS / WebSocket endpoints. Threat-intel: `vt_reputation`,
  `greynoise_classify`.

Skipping these anchors is the single largest recall regression in quick mode.
The lead's tool catalog already exposes them (`strix/agents/lead_agent/tool_catalog.py`)
— this section is the **prompt-level instruction** that they must actually be
called.

## Phase 1: Rapid Orientation

**Whitebox (source available)**
- Focus on recent changes: git diffs, new commits, modified files—these are most likely to contain fresh bugs
- Read existing `wiki` notes first (`list_notes(category="wiki")` then `get_note(note_id=...)`) to avoid remapping from scratch
- Run a fast static triage on changed files first (`semgrep`, then targeted `sg` queries)
- Run at least one lightweight AST pass (`sg` or Tree-sitter) so structural mapping is not skipped
- Keep AST commands tightly scoped to changed or high-risk paths; avoid broad repository-wide pattern dumps
- Run quick secret and dependency checks (`gitleaks`, `trufflehog`, `trivy fs`) scoped to changed areas when possible
- Identify security-sensitive patterns in changed code: auth checks, input handling, database queries, file operations
- Trace user input through modified code paths
- Check if security controls were modified or bypassed
- Before completion, update the shared repo wiki with what changed and what needs dynamic follow-up

**Blackbox (no source)**
- Map authentication and critical user flows
- Identify exposed endpoints and entry points
- Skip deep content discovery—test what's immediately accessible

## Phase 2: High-Impact Targets

Test in priority order:

1. **Authentication bypass** - login flaws, session issues, token weaknesses
2. **Broken access control** - IDOR, privilege escalation, missing authorization
3. **Remote code execution** - command injection, deserialization, SSTI
4. **SQL injection** - authentication endpoints, search, filters
5. **SSRF** - URL parameters, webhooks, integrations
6. **Exposed secrets** - hardcoded credentials, API keys, config files

Skip for quick scans:
- Exhaustive subdomain enumeration
- Full directory bruteforcing
- Low-severity information disclosure
- Theoretical issues without working PoC

## Phase 3: Validation

- Confirm exploitability with minimal proof-of-concept
- Demonstrate real impact, not theoretical risk
- Report findings immediately as discovered

## Chaining

When a strong primitive is found (auth weakness, injection point, internal access), immediately attempt one high-impact pivot to demonstrate maximum severity. Don't stop at a low-context "maybe"—turn it into a concrete exploit sequence that reaches privileged action or sensitive data.

## Operational Guidelines

- Use browser tool for quick manual testing of critical flows
- Use terminal for targeted scans with fast presets (e.g., nuclei with critical/high templates only)
- Use proxy to inspect traffic on key endpoints
- Skip extensive fuzzing—use targeted payloads only
- Create subagents only for parallel high-priority tasks

## Mindset

Think like a time-boxed bug bounty hunter going for quick wins. Prioritize breadth over depth on critical areas. If something looks exploitable, validate quickly and move on. Don't get stuck—if an attack vector isn't yielding results quickly, pivot.
