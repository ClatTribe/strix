# Tool catalog rationalization — strix becomes an OSS orchestrator

**Status:** proposal (iter-37.1). Audit + migration plan.
**Last updated:** 2026-05-27.

## Why

Current state (run `get_lead_tool_catalog` to confirm):

| asset type | tools exposed to L2 Lead |
|---|---:|
| web_application | **99** |
| api | **98** |
| repository | 44 |
| local_code | 42 |
| ip_address | 43 |
| container_image | 36 |

At 99 tools per web target, the LLM hits **decision paralysis**. Empirically: v5 L2 Juice Shop standard run found only 4/109 challenges, despite invoking 132 tool calls — the agent fixated on a small handful of in-house scanners (`scan_cache_deception` over and over) and never invoked the broader OSS battery.

**Root cause:** strix has ~60 in-house `scan_*` / `*_check` tools that duplicate (and underperform) widely-deployed OSS scanners. The LLM has no way to know which is the "best" SQLi tool when the catalog offers `scan_sqli`, `sqli_check`, and `scan_sqli_sqlmap`. Three options is one too many.

## Architectural goal

**strix is an LLM orchestrator over best-in-class OSS security tools.**

It is **not** a vulnerability-detection company. The community has invested 10K+ engineering years in nuclei, sqlmap, semgrep, trivy, etc. — their detection logic is more accurate, their templates update daily, and they have public trust strix doesn't.

strix's value is:
1. Knowing which OSS tool to run for which scenario
2. Chaining findings across tools (L1.5 enrichment)
3. Multi-step exploit reasoning (L2 LLM)
4. Producing readable, actionable reports (L2 LLM)

The tools themselves should be community-maintained.

## The OSS tool stack (already wrapped in strix)

These 19 wrappers stay. They're the foundation.

| tool | OSS engine | covers | community |
|---|---|---|---|
| `scan_nuclei_templates` | **nuclei** (ProjectDiscovery) | 10K+ templates: OWASP Top 10, CVE classes, misconfigs, secrets | 17K stars, daily template updates via `nuclei -ut` |
| `scan_sqli_sqlmap` | **sqlmap** | Deep SQL exploitation (post-detection) | 30K stars, 15-year track record |
| `scan_xss_dalfox` | **dalfox** | Deep XSS exploitation + DOM payloads | 4K stars, active |
| `crawl_with_katana` | **katana** | JS-aware crawler + sitemap + robots + jsluice | 12K stars |
| `discover_paths_feroxbuster` | **feroxbuster** | Content discovery + wordlist enumeration | 5K stars |
| `probe_hosts_httpx` | **httpx** | HTTP probing + fingerprint + tech detection | 7K stars |
| `tls_audit` | **testssl.sh** | TLS cipher + cert + protocol audit | 8K stars |
| `fingerprint_services_nmap` | **nmap** | Port + service + OS fingerprint | classic |
| `enumerate_subdomains_subfinder` | **subfinder** | Passive subdomain enum | 10K stars |
| `domain_recon_pipeline` | **subfinder + bbot** | Full domain recon pipeline | active |
| `scan_buckets_via_bbot` | **bbot** | Cloud bucket discovery (S3 + GCS + Azure) | 5K stars |
| `scan_typosquats_dnstwist` | **dnstwist** | Typosquat domain detection | active |
| `map_graphql_inql` | **InQL** | GraphQL introspection + schema mining | 1K+ stars |
| `verify_credentials_trufflehog` | **trufflehog** | Live credential validation (cross-platform) | 15K stars |
| `secrets_scan` | **gitleaks** | Git history secret scanning | 15K stars |
| `scan_image_dockle` | **dockle** | Container image best practices | 3K stars |
| `scan_dockerfile_hadolint` | **hadolint** | Dockerfile lint | 10K stars |
| `scan_container_image` | **trivy** | Vuln + secret + misconfig + SBOM (all-in-one) | 22K stars |
| `scan_dns_hygiene_checkdmarc` | **checkdmarc** | SPF/DKIM/DMARC audit | active |

**That's strix's L0/L1 detection layer.** Everything else is orchestration around these tools.

## In-house scanners — migration verdicts

60 in-house `scan_*` / `*_check` tools. Verdict for each: **DELETE** (route to OSS), **KEEP** (LLM logic or niche), or **MERGE** (combine with an OSS tool).

### A. DELETE — duplicates an OSS tool (route through OSS wrapper)

| in-house | replace with | OSS engine | nuclei tag(s) |
|---|---|---|---|
| `scan_sqli` (specialist) | `scan_sqli_sqlmap` | sqlmap | `tags:sqli` |
| `scan_xss` (specialist) | `scan_xss_dalfox` + nuclei | dalfox / nuclei | `tags:xss` |
| `scan_ssrf` | `scan_nuclei_templates` | nuclei | `tags:ssrf` |
| `scan_blind_ssrf` | `scan_nuclei_templates` | nuclei | `tags:blind-ssrf` |
| `scan_xxe` | `scan_nuclei_templates` | nuclei | `tags:xxe` |
| `scan_oob_xxe` | `scan_nuclei_templates` | nuclei | `tags:xxe,oob` |
| `scan_cmd_injection` | `scan_nuclei_templates` | nuclei | `tags:cmdi,rce` |
| `scan_blind_cmd_injection` | `scan_nuclei_templates` | nuclei | `tags:blind-cmdi` |
| `scan_path_traversal` | `scan_nuclei_templates` | nuclei | `tags:lfi,traversal` |
| `scan_nosql_injection` | `scan_nuclei_templates` | nuclei | `tags:nosqli` |
| `scan_ldap_injection` | `scan_nuclei_templates` | nuclei | `tags:ldap` |
| `scan_xpath_injection` | `scan_nuclei_templates` | nuclei | `tags:xpath` |
| `scan_ssti` | `scan_nuclei_templates` | nuclei | `tags:ssti` |
| `scan_deserialization` | `scan_nuclei_templates` | nuclei | `tags:deserialization` |
| `scan_misconfig` | `scan_nuclei_templates` | nuclei | `tags:misconfig` |
| `scan_response_anomaly` | `scan_nuclei_templates` | nuclei | `tags:default-login,exposure` |
| `scan_secrets_in_response` | `scan_nuclei_templates` | nuclei | `tags:exposure,token-spray,secrets` |
| `scan_websocket_auth` | `scan_nuclei_templates` | nuclei | `tags:websocket` |
| `scan_cache_deception` | `scan_nuclei_templates` | nuclei | `tags:cache-deception,cache-poisoning` |
| `scan_prototype_pollution` | `scan_nuclei_templates` | nuclei | `tags:prototype-pollution` |
| `scan_request_smuggling_active` | `scan_nuclei_templates` + **smuggler.py** wrapper (TODO) | nuclei | `tags:smuggling` |
| `request_smuggling_check` | same as above | — | — |
| `scan_race_condition` | `scan_nuclei_templates` | nuclei | `tags:race-condition` |
| `race_condition_check` | same | — | — |
| `cors_deep_check` | `scan_nuclei_templates` | nuclei | `tags:cors` |
| `csrf_check` | `scan_nuclei_templates` | nuclei | `tags:csrf` |
| `open_redirect_check` | `scan_nuclei_templates` | nuclei | `tags:redirect` |
| `host_header_check` | `scan_nuclei_templates` | nuclei | `tags:host-header` |
| `method_tamper_check` | `scan_nuclei_templates` | nuclei | `tags:http-method` |
| `debug_endpoint_check` | `scan_nuclei_templates` | nuclei | `tags:debug,disclosure` |
| `file_upload_abuse_check` | `scan_nuclei_templates` | nuclei | `tags:fileupload` |
| `csv_injection_check` | `scan_nuclei_templates` | nuclei | `tags:csv-injection` |
| `cache_deception_check` | `scan_nuclei_templates` | nuclei | `tags:cache-deception` |
| `cookie_jwt_scoping_check` | `scan_nuclei_templates` | nuclei | `tags:cookie,jwt` |
| `session_entropy_check` | `scan_nuclei_templates` | nuclei | `tags:session-fixation` |
| `dns_hygiene_check` | `scan_dns_hygiene_checkdmarc` | checkdmarc | — |
| `subdomain_takeover_check` | `scan_nuclei_templates` | nuclei | `tags:takeover` |
| `scan_subdomain_takeover_active` | `scan_nuclei_templates` | nuclei | `tags:takeover` |
| `scan_authn_metadata` | `scan_nuclei_templates` | nuclei | `tags:oidc,oauth,well-known` |
| `scan_oauth` | `scan_nuclei_templates` | nuclei | `tags:oauth` |
| `scan_saml_xsw` | `scan_nuclei_templates` + **saml-raider** wrapper (TODO) | nuclei | `tags:saml` |
| `scan_api_rate_limit` | `scan_nuclei_templates` | nuclei | `tags:rate-limit` |
| `scan_api_grpc_reflection` | `scan_nuclei_templates` | nuclei | `tags:grpc` |
| `scan_credential_leaks_hibp` | `scan_credential_leaks_hibp` (already HIBP API wrapper) | HIBP | — |
| `hibp_breach_check` | merge with `scan_credential_leaks_hibp` | HIBP | — |
| `scan_cloud_imds_passthrough` | `scan_nuclei_templates` | nuclei | `tags:imds,cloud` |
| `kev_diff_check` | route through threat-intel KEV API | KEV catalog | — |
| `monitoring_posture_check` | route through security headers nuclei templates | nuclei | `tags:headers` |
| `mfa_attestation_check` | route through nuclei + `scan_authn_metadata` | nuclei | `tags:mfa` |

**Net: 47 in-house scanners → 0 in-house implementations.** They become thin aliases pointing at the appropriate nuclei tag filter or specialized OSS tool.

### B. KEEP — LLM logic, niche, or no good OSS equivalent

| in-house | rationale |
|---|---|
| `scan_idor` | Session-aware authz testing requires the LLM-driven multi-session orchestration. Nuclei has IDOR templates but they're URL-pattern-only — they can't simulate user-a vs user-b context. **Keep but rename to `idor_authz_check`** to make the LLM-driven nature explicit. |
| `scan_multi_role_auth` | Same reason — multi-session authz comparison. **Merge into `scan_idor`** as a parameter (`compare_roles=True`). |
| `scan_api_bola` / `scan_api_bfla` | API-shaped IDOR/BFLA. **Merge into `scan_idor`** (same logic, different surface). |
| `scan_business_logic` | LLM-led detection of app-specific logic flaws (negative quantities, coupon stacking, race-window edge cases). No OSS substitute — this IS the LLM's job. **Keep**, but reframe as "LLM-driven business logic auditor." |
| `scan_auth_flow` | Default-creds bruteforce + auth-flow analysis (registration → login → token refresh). Hydra handles bruteforce; the FLOW orchestration is LLM-led. **Keep** as orchestrator; route bruteforce to hydra (OSS) under the hood. |
| `seed_auth` | Shape-aware account registration. **Keep** — no OSS equivalent and it's what unlocks post-auth surface. |
| `probe_default_creds` | **Migrate to hydra** (already in sandbox image). Wrap it like `scan_sqli_sqlmap` wraps sqlmap. |
| `probe_endpoint` | Generic LLM-driven HTTP send. **Keep** — fundamental primitive. |
| `replay_mutation` | Per-request mutation testing (Burp-style). Use OWASP ZAP's automation framework as engine. **Migrate.** |
| `correlate_findings` / `mid_scan_correlate` | L1.5 chain reasoning. **Keep** — pure LLM/heuristic logic, no OSS. |
| `graphql_specialist_check` | Already wrapped by `map_graphql_inql` (InQL). **Delete**, route through InQL. |
| `scan_mobile_app` | Mobile app analysis (APK). **Migrate to MobSF** (mobsfscan) — popular OSS. |

**Survivors: ~8 in-house tools** (idor_authz_check, scan_business_logic, scan_auth_flow, seed_auth, probe_endpoint, replay_mutation, correlate_findings, mid_scan_correlate) — all of them LLM-orchestration logic, not detection engines.

### C. NEW OSS wrappers needed

A few categories have OSS but strix hasn't wrapped them yet:

| add | OSS engine | purpose |
|---|---|---|
| `scan_smuggling_smuggler` | **smuggler.py** (defparam) | HTTP request smuggling (TE.CL / CL.TE / TE.TE) — most accurate OSS detector |
| `scan_saml_raider` | **SAML Raider** (Burp plugin → standalone) | SAML XSW / signature-wrapping attacks |
| `probe_default_creds_hydra` | **hydra** (already in image) | Replace probe_default_creds with hydra wrapper |
| `scan_mobile_mobsfscan` | **mobsfscan** | APK static analysis |
| `scan_fuzz_ffuf` | **ffuf** | Generic web fuzzing (param discovery, vhost) |
| `scan_api_schemathesis` | **schemathesis** | OpenAPI-driven API fuzzer |

**6 new wrappers** to fill the gaps. Each is ~150 LOC following the existing `*_runner` pattern.

## Final per-asset-type catalog

After the migration:

### `web_application` — **8 tools** (vs 99 today)

| # | tool | engine |
|---|---|---|
| 1 | `crawl_with_katana` | katana (recon) |
| 2 | `scan_nuclei_templates` | nuclei (all detection) |
| 3 | `scan_sqli_sqlmap` | sqlmap (deep SQLi exploit) |
| 4 | `scan_xss_dalfox` | dalfox (deep XSS exploit) |
| 5 | `seed_auth` + `scan_auth_flow` | LLM-orchestrated auth |
| 6 | `idor_authz_check` | LLM-orchestrated session-aware authz |
| 7 | `tls_audit` | testssl.sh |
| 8 | `note` + `workflow_status` + `create_vulnerability_report` + `finish_scan` | framework |

### `api` — **9 tools**

| # | tool | engine |
|---|---|---|
| 1 | `openapi_spec_ingest` | spec parser (in-house — replaces HTML crawl on JSON APIs) |
| 2 | `scan_api_schemathesis` (NEW) | schemathesis (OpenAPI fuzzer) |
| 3 | `scan_nuclei_templates` | nuclei (API CVE templates) |
| 4 | `scan_sqli_sqlmap` | sqlmap |
| 5 | `map_graphql_inql` | InQL (when GraphQL detected) |
| 6 | `seed_auth` + `scan_auth_flow` | LLM-orchestrated |
| 7 | `idor_authz_check` | session-aware BOLA/BFLA |
| 8 | `tls_audit` | testssl.sh |
| 9 | framework tools | same |

### `repository` / `local_code` — **5 tools**

| # | tool | engine |
|---|---|---|
| 1 | `scan_sast` (NEW wrapper) | **semgrep** (1000+ rules, daily updates via Semgrep Registry) |
| 2 | `secrets_scan` | gitleaks |
| 3 | `verify_credentials_trufflehog` | trufflehog (live verify) |
| 4 | `scan_sca_lockfiles` (NEW wrapper) | **trivy fs** (covers all package managers) |
| 5 | framework tools | same |

### `ip_address` — **6 tools**

| # | tool | engine |
|---|---|---|
| 1 | `fingerprint_services_nmap` | nmap |
| 2 | `scan_nuclei_templates` | nuclei (network templates) |
| 3 | `enumerate_subdomains_subfinder` | subfinder (when domain attached) |
| 4 | `domain_recon_pipeline` | bbot |
| 5 | `tls_audit` | testssl.sh |
| 6 | framework tools | same |

### `container_image` — **4 tools**

| # | tool | engine |
|---|---|---|
| 1 | `scan_container_image` | **trivy** (vuln + secret + misconfig + SBOM in one) |
| 2 | `scan_dockerfile_hadolint` | hadolint |
| 3 | `scan_image_dockle` | dockle |
| 4 | framework tools | same |

### `mobile_app` — **3 tools**

| # | tool | engine |
|---|---|---|
| 1 | `scan_mobile_mobsfscan` (NEW) | **mobsfscan** (MobSF static) |
| 2 | `scan_nuclei_templates` | nuclei (mobile-specific templates if available) |
| 3 | framework tools | same |

## Migration plan (iter-37 series)

| iter | scope | cost |
|---|---|---|
| **iter-37.1** | This document. Stakeholder alignment. | DONE |
| **iter-37.2** | Per-asset-type catalog filter: `get_lead_tool_catalog` returns the minimal set. In-house duplicates become hidden from the LLM but stay executable for backward-compat. | 1 PR, ~150 LOC, ~30 tests |
| **iter-37.3** | Mark all 47 DELETE-class tools as `deprecated=True` in the registry. They warn on invocation + log a "use X instead" hint to the LLM. | 1 PR, ~100 LOC + ~50 test updates |
| **iter-37.4** | Add the 6 NEW OSS wrappers: smuggler.py, SAML Raider, hydra, mobsfscan, ffuf, schemathesis. Each ~150 LOC + sandbox image entry. | 6 PRs (one per wrapper), ~900 LOC total |
| **iter-37.5** | Delete the 47 DELETE-class tools entirely (after 1 release cycle of deprecation warnings). Their function module files removed. | 1 PR, -~5000 LOC |
| **iter-37.6** | Re-bench L2 Juice Shop. Expect recall to jump significantly because nuclei alone covers most of what's been being missed. | bench only |
| **iter-37.7** | Update CLAUDE.md §3.3 to state "strix is an LLM orchestrator over OSS tools; no in-house detection engines." Sandbox audit shows all surviving detection tools are OSS-backed. | 1 PR, docs |

**Total scope**: ~7 PRs, ~6,000 LOC net delta (most is deletion). Estimated 1-2 weeks of focused work.

## What this changes about strix

**Marketing/positioning**: "strix orchestrates the world's best OSS security tools with an LLM that knows which to invoke and how to chain findings."

That sentence:
- Removes the "but is your scanner accurate?" objection (we use nuclei + sqlmap + semgrep + trivy — community-trusted)
- Removes the "templates outdated?" objection (`nuclei -ut`, semgrep registry, trivy DB all auto-update)
- Keeps the unique value (LLM orchestration, chain detection, explanation, patcher)
- Reduces strix's maintenance burden by ~70% (no detection logic to maintain)
- Makes the L2 Lead's job tractable (8 tools per target instead of 99)

## Decision rule going forward

Add to CLAUDE.md §11 (coding conventions):

> **No new in-house detection engines.** Every new vulnerability category strix needs to detect must be added by:
> 1. Identifying the leading OSS tool for that category
> 2. Adding a `*_runner` wrapper following the existing pattern
> 3. Routing through `scan_nuclei_templates` first if a nuclei template exists for the category
>
> In-house tools are reserved for LLM orchestration logic (chain detection, multi-session authz, business logic), not detection engines.
