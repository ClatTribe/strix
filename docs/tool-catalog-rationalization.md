# Tool catalog rationalization — strix becomes an OSS orchestrator

**Status:** shipped (iter-37.2 → iter-37.11). Re-bench validation in iter-37.12 (in flight).
**Originally audited:** 2026-05-27 (iter-37.1).
**Last updated:** 2026-05-27 (iter-37.13 — synced to shipped reality).

> **Reading guide.** Sections 1-4 ("Why" → "In-house scanners — migration verdicts") are the original audit; they remain accurate as a record of the analysis that motivated the cut. Section 5 ("Final per-asset-type catalog") has been **rewritten to reflect what actually shipped** — the live numbers and the harness vs LLM split that emerged during execution. Section 6 ("Migration plan") is now a shipped-status table.

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

## Final per-asset-type catalog — **as shipped** (post iter-37.11)

The execution went deeper than the original audit projected. Two architectural shifts that didn't appear in the iter-37.1 draft:

1. **Two-track tool sets.** Tools split between (a) the deterministic OSS prepass that the harness fires before the LLM wakes up (`anchor_prepass.py:_ANCHORS_BY_TARGET_TYPE`), and (b) the LLM catalog. **Tools the harness already runs are removed from the LLM catalog** — duplicating them just burns decision-paralysis tokens.

2. **Core vs per-asset.** The 5-tool minimal CORE (`_MINIMAL_CORE_TOOLS`, iter-37.10) — one per OODA phase + terminate — is shared by every asset. The per-asset set is **ACT-only specialists** on top of that core. The audit's flat 8/9/5/6/4 counts conflated these.

### Minimal CORE — 5 tools, every asset (iter-37.10)

| # | tool | role | OODA phase |
|---|---|---|---|
| 1 | `workflow_status` | "where am I in the scan?" | OBSERVE |
| 2 | `list_pending_findings` | "what did L1 surface?" — L1.5-ranked queue | OBSERVE |
| 3 | `think` | reasoning scratchpad (subsumes 5 note tools + 5 hypothesis tools) | ORIENT |
| 4 | `create_vulnerability_report` | emit a finding (upsert via `existing_report_id=`) | ACT |
| 5 | `finish_scan` | terminate; auto-fires `emit_compliance_evidence` + `generate_remediation_plan` | TERMINATE |

The other 27 tools that used to be in `_CORE_TOOLS` either fold into these or auto-fire via L1.5 hooks (`mid_scan_correlate`, `tracer.threat_intel.enrich`) — see CLAUDE.md §5 for the hook chain.

### `web_application` — **10 tools** (vs 99 legacy, −90%)

**Harness-fired prepass** (`_ANCHORS_WEB` — runs in sandbox before LLM gets control):
`fingerprint_tech_stack`, `openapi_spec_ingest`, `crawl_with_katana`, `sbom_extract`, `discover_graphql_endpoints`, `seed_auth`, `probe_default_creds`, `scan_nuclei_templates`, `scan_api_rate_limit`, `scan_sqli`, `scan_xxe`, `scan_ssrf`, `scan_ssti`, `scan_path_traversal`, `scan_nosql_injection`, `scan_cmd_injection`, `scan_secrets_in_response`, `http_security_headers_audit`, `tls_audit`, `cors_deep_check`, `csrf_check`, `open_redirect_check`, `scan_authn_metadata`, `scan_cloud_imds_passthrough`, `scan_buckets_via_bbot`, `scan_xss`, `dom_xss_static_probe`, `scan_cache_deception`, `scan_websocket_auth`, `scan_prototype_pollution` + `shape_aware_dispatcher` (iter-30 payload-bin fan-out per endpoint).

**LLM catalog** (10 tools total = 5 core + 5 specialist):

| # | tool | engine |
|---|---|---|
| C1-C5 | minimal CORE (5) | framework |
| 6 | `scan_sqli_sqlmap` | sqlmap (deep SQLi when prepass flags candidates) |
| 7 | `scan_xss_dalfox` | dalfox (deep XSS) |
| 8 | `scan_idor` | LLM-orchestrated session-aware IDOR/BOLA/BFLA |
| 9 | `scan_auth_flow` | LLM-orchestrated multi-step auth (subsumes seed_auth) |
| 10 | `send_request` | generic HTTP fallback for cases prepass/dispatcher missed |

### `api` — **10 tools**

**Prepass**: same as web minus the web-only DOM probes (`scan_xss`, `dom_xss_static_probe`, `scan_cache_deception`, `scan_websocket_auth`, `scan_prototype_pollution`).

**LLM catalog**: 5 core + `scan_sqli_sqlmap`, `scan_idor`, `scan_auth_flow`, `map_graphql_inql`, `send_request`.

### `repository` / `local_code` — **9 tools**

**Prepass** (`_ANCHORS_LOCAL_CODE`): `scan_sca_lockfiles` (trivy fs), `scan_sast` (semgrep), `scan_iac`, `secrets_scan` (gitleaks).

**LLM catalog**: 5 core + `build_code_map`, `taint_analysis`, `verify_credentials_trufflehog`, `terminal_execute`.

### `container_image` — **7 tools**

**Prepass** (`_ANCHORS_CONTAINER`): `scan_container_image` (trivy — vuln + secrets + misconfig + SBOM in one tool).

**LLM catalog**: 5 core + `scan_image_dockle`, `terminal_execute`.

### `ip_address` — **11 tools**

**Prepass** (thin): `probe_open_tcp_ports` + per-port banner probes (Redis, FTP-anon, HTTP banner). No nmap/httpx/nuclei in the prepass.

**LLM catalog**: 5 core + `fingerprint_services_nmap`, `probe_hosts_httpx`, `scan_nuclei_templates`, `tls_audit`, `send_request`, `terminal_execute`. **IP keeps its recon tools in catalog because the prepass coverage is thin** — the LLM must drive comprehensive recon itself.

### `domain` — **11 tools**

**Prepass**: none.

**LLM catalog**: 5 core + `domain_recon_pipeline`, `enumerate_subdomains_subfinder`, `scan_nuclei_templates`, `scan_dns_hygiene_checkdmarc`, `scan_typosquats_dnstwist`, `send_request`. **Domain keeps recon tools in catalog because there's no prepass at all.**

### `mobile_app` — **deferred**

Not yet a registered asset type in `_MINIMAL_TOOLS_BY_TARGET_TYPE`. Will land alongside iter-37.4's `scan_mobile_mobsfscan` wrapper.

### Summary table

| asset | prepass tools | LLM-catalog tools | vs 99 legacy |
|---|---:|---:|---:|
| `web_application` | ~25 (auto) | **10** | −90% |
| `api` | ~20 (auto) | **10** | −90% |
| `repository` / `local_code` | 4 (auto) | **9** | −78% |
| `ip_address` | ~6 (auto, thin) | **11** | −74% |
| `container_image` | 1 (auto) | **7** | −81% |
| `domain` | 0 | **11** | n/a |

### Why the asset-specific differences

The trim went deeper for assets whose prepass is comprehensive (web/api/code/container — 5 ACT-only specialists each on top of core) and stayed conservative where the prepass is thin or absent (ip/domain — recon must remain in catalog because the harness can't be relied on to discover the surface). The OODA frame makes this explicit: **the LLM only needs catalog visibility for OBSERVE steps the harness can't do for it.**

## Migration plan (iter-37 series) — shipped status

| iter | scope | PR | status |
|---|---|---|---|
| **37.1** | This document. Stakeholder alignment. | #483 | ✓ shipped |
| **37.2** | Per-asset-type catalog filter: `get_lead_tool_catalog` returns the minimal set. In-house duplicates hidden from LLM but stay executable. | #484 | ✓ shipped |
| **37.3** | Mark all ~50 DELETE-class tools as deprecated in `strix/tools/deprecations.py`. Warn-on-call via `emit_deprecation_warning` hook in `executor.py`. | #485 | ✓ shipped |
| **37.7** | Update CLAUDE.md §11.1 with the "no new in-house detection engines" decision rule + iter-37 status table. | #486 | ✓ shipped |
| **37.8** | Minimal CORE 32 → 13. Drop 5 note tools, 5 hypothesis tools, KG paths/nodes, introspection tools (`check_budget`, `agent_self_audit`, `drain_amplify_queue`, etc.). | #487 | ✓ shipped |
| **37.9** | Update 24 specialist tests to set `STRIX_LEGACY_CATALOG=1` so their deprecated-tool catalog assertions keep passing. | #488 | ✓ shipped |
| **37.10** | Minimal CORE 13 → 5 (one per OODA phase + terminate). Auto-fire `emit_compliance_evidence` + `generate_remediation_plan` inside `finish_scan` (opt-out: `STRIX_FINISH_AUTO_ARTIFACTS=0`). | #489 | ✓ shipped |
| **37.11** | Per-asset trim to ACT-only. Drop prepass duplicates (`crawl_with_katana`, `scan_nuclei_templates`, `seed_auth`, `tls_audit`, `openapi_spec_ingest`, `scan_sast`, `secrets_scan`, `scan_sca_lockfiles`, `scan_iac`, `scan_container_image`) from the LLM catalog — they fire deterministically in the prepass. | #490 | ✓ shipped |
| **37.13** | This sync — bring the doc up to date with the shipped reality. | — | ✓ shipped (this PR) |
| **37.12** | Re-bench L2 Juice Shop with the 99 → 10 catalog trim. Validation gate for iter-37.4. | — | in flight |
| **37.4** | Add 6 NEW OSS wrappers: smuggler.py, SAML Raider, hydra, mobsfscan, ffuf, schemathesis. | — | gated on 37.12 |
| **37.5** | DELETE the ~50 deprecated tools entirely (after ≥1 release cycle of deprecation warnings — earliest 2026-06-15). | — | gated on time |
| **37.6** | (Original re-bench plan — superseded by 37.12, which covers the broader trim.) | — | superseded |

**Actual scope landed**: 9 PRs, ~1,000 LOC net delta (counting only iter-37.x). The 5,000-LOC deletion happens in iter-37.5 after the grace period.

### Things that shipped but the original plan didn't anticipate

The audit had a clean 7-step migration. Execution surfaced four things that weren't in the original draft and warranted their own iters:

1. **iter-37.8** — the original `_CORE_TOOLS` had 32 entries with substantial redundancy (note tools, hypothesis tools, KG queries, introspection). Trimming it from 32 → 13 was a precondition for hitting the audit's per-asset targets. The audit treated core as a small fixed cost; in reality it was the second-largest cut.

2. **iter-37.10** — even 13 tools in core was too many. OODA-loop analysis showed ~60% were redundant with L1.5 hooks (`mid_scan_correlate` auto-fires correlate_findings at phase boundaries; `tracer.threat_intel.enrich` auto-runs at emission; `finish_scan` can auto-fire compliance + remediation as terminal artifacts). Trim went from 13 → 5.

3. **iter-37.11** — ACT-only per-asset trim. The original plan kept `crawl_with_katana` + `scan_nuclei_templates` + `tls_audit` in the web catalog. But the **anchor prepass already fires them deterministically**. Catalog visibility just creates decision paralysis. Dropping them from catalog while keeping them in the prepass was the biggest single-cut reduction (web: 23 → 10 tools).

4. **iter-37.9 + iter-37.13** — test fallout + doc sync. Each catalog reshuffle invalidated a batch of catalog-shape tests. iter-37.9 fixed 24 specialist tests; iter-37.13 (this PR) syncs the audit doc.

### Key insight: the iter sequence revealed a layered enforcement model

The original audit framed the problem as "catalog too big → trim it." The shipped solution is actually **five enforcement layers** working together:

1. **Catalog visibility** (iter-37.2/37.10/37.11) — LLM can't call what it can't see.
2. **Deprecation warnings** (iter-37.3) — if LLM names a deprecated tool, warn + redirect.
3. **Prepass guarantee** (`anchor_prepass.py`) — harness fires recon/orient deterministically; LLM's contribution is purely upside.
4. **Auto-enrichment at emission** (L1.5 hook chain) — every finding auto-enriches with threat-intel, FP filter, surface_priority, exploitability, corroborator, cross-tool merge. LLM doesn't need to call those tools.
5. **Auto-fire on termination** (iter-37.10) — compliance + remediation artifacts always produced, even if LLM forgets.

That layered model is the actual architecture this iter series produced. The doc's original "trim the catalog" framing under-described it.

## What this changes about strix

**Marketing/positioning**: "strix orchestrates the world's best OSS security tools with an LLM that knows which to invoke and how to chain findings."

That sentence:
- Removes the "but is your scanner accurate?" objection (we use nuclei + sqlmap + semgrep + trivy — community-trusted)
- Removes the "templates outdated?" objection (`nuclei -ut`, semgrep registry, trivy DB all auto-update)
- Keeps the unique value (LLM orchestration, chain detection, explanation, patcher)
- Reduces strix's maintenance burden by ~70% (no detection logic to maintain)
- Makes the L2 Lead's job tractable (10 tools per web target instead of 99)

## Decision rule (codified in CLAUDE.md §11.1 — iter-37.7)

> **No new in-house detection engines.** Every new vulnerability category strix needs to detect must be added by:
> 1. Identifying the leading OSS tool for that category
> 2. Adding a `*_runner` wrapper following the existing pattern in `strix/tools/*_runner/`
> 3. Routing through `scan_nuclei_templates` (with the appropriate `tags:` filter) first if a nuclei template exists
> 4. Registering with `@register_tool(sandbox_execution=True)` — OSS tools run in the sandbox container
>
> In-house tools are reserved for **LLM orchestration logic** only:
> - Chain reasoning (`correlate_findings`, `mid_scan_correlate`)
> - Multi-session authz (`scan_idor` — absorbs BOLA, BFLA, multi-role)
> - Auth flow orchestration (`scan_auth_flow`, `seed_auth`)
> - Business-logic detection (`scan_business_logic`)
> - Generic primitives (`probe_endpoint`, `send_request`, `browser_action`)
> - Framework / state mgmt (workflow, notes, findings, threat-intel)
>
> Adding a new in-house `scan_*` detection scanner is **forbidden** without an explicit architectural ADR explaining why the leading OSS tool doesn't suffice.

This rule is enforced by code review + the iter-37.3 deprecation registry: any newly-introduced in-house detection scanner would need to be added to `_DEPRECATIONS` immediately, which is the signal to reject it at PR review.

## See also

- `CLAUDE.md` §3 — host vs sandbox execution boundary
- `CLAUDE.md` §5 — L1.5 hook chain order (FP filter → demote → corroborator → post_emit_verifier → cross-tool merge)
- `CLAUDE.md` §11.1 — codified decision rule
- `CLAUDE.md` §12 — iter-37 shipped-status table + per-asset specialist sets
- `strix/agents/lead_agent/tool_catalog.py` — `_MINIMAL_CORE_TOOLS` + `_MINIMAL_TOOLS_BY_TARGET_TYPE` (the live catalog)
- `strix/agents/lead_agent/anchor_prepass.py` — `_ANCHORS_BY_TARGET_TYPE` (the deterministic prepass)
- `strix/tools/deprecations.py` — the `_DEPRECATIONS` map (iter-37.3)
- `strix/tools/finish/finish_actions.py` — `_auto_fire_terminal_artifacts` (iter-37.10)
