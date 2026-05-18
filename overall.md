# Strix — strategic overview

A categorised view of the architecture and feature set we've shipped, through four lenses:

1. AI-native classification — Strix's OODA loop
2. Security benchmark positioning — public benchmarks and where we land
3. Per-target AI-native edge — vs a security engineer using off-the-shelf tools
4. Wrapper (webappsec) changes needed — to expose this capability to developers and non-tech users

**Snapshot date: 2026-05-18.** Reflects shipping through PR #321
(SAML XSW + SP config audit). Major arcs since this doc was first
written:

- **§10 threat-intel gap audit** (PRs #61–#76) — original baseline.
  18 deterministic threat-intel sources.
- **Cloud attack-paths arc** (PRs #293–#311) — graph + 27 patterns +
  reachability + multi-cloud (AWS + GCP + Azure) + multi-account +
  agentless VM CVE scan + CloudTrail-based CDR.
- **Web specialist arc** (PRs #295–#298, #320, #321) — cache poisoning,
  prototype pollution, websocket auth, race condition / TOCTOU, SAML XSW.
- **Decepticon uplift** (PRs #233–#244) — typed knowledge graph, 5-stage
  verification pipeline, OPPLAN objective tracker, specialist
  orchestrator with fresh-context dispatch, patcher runtime.
- **Engine-wishlist arc** (PRs #312–#319) — **all 8 org-scale items
  shipped**: batch mode, shared Researcher cache, `kg_delta.jsonl`,
  `STRIX_PROJECT_ID`, target-metadata pass-through, `--profile initial`,
  `assets.discovered.jsonl`, `--skip-if-unchanged`.

Companion docs: [`masterroadmap.md`](masterroadmap.md) for the
forward-looking competitive view, [`roadmap.md`](roadmap.md) for the
granular standing roadmap, [`single-agent.md`](single-agent.md) for the
lead-agent architecture.

---

## 1. AI-native classification — Strix's OODA loop

Strix's value isn't "another scanner". It's an **agent that runs the security-engineer OODA loop** (Observe → Orient → Decide → Act) over a target, with deterministic tool support at each loop stage. Each shipped tool slots into one phase.

### 1.1 Observe — gather raw signals

Deterministic tools that produce raw data the agent can reason about. No interpretation; no severity. Just facts.

**External-surface + threat-intel (original §10 + gap-audit arc, PRs #41–#76)**

| Tool | What it observes |
|---|---|
| `bfs_crawl` (#41) | URL surface, JS bundles, OpenAPI specs, robots/sitemap |
| `subdomain_enum` (#21) | Subdomain set across 5 sources (subfinder/amass/bruteforce/permutations/wayback) + CT logs (#48) |
| `dns_hygiene_check` (#8, #19) | DNS records, SPF/DMARC/DKIM/MTA-STS/CAA/DNSSEC posture |
| `well_known_harvest` (#46) | 13 standard `/.well-known/` paths |
| `m365_tenant_recon` (#52) | Microsoft 365 / Entra tenant ID + federation posture |
| `org_fingerprint` (#16) | WHOIS, ASN, GitHub-org, typosquats |
| `passive_dns_history` (#16) | Historical resolutions via SecurityTrails / VT |
| `mx_fingerprint` (#26) | MX banner + email auth headers |
| `code_search_for_domain` (#24) | Org-affiliated GitHub repos + leaked secrets |
| `reverse_ip_discovery` (#23) | Shared-hosting neighbors |
| `saas_leak_discovery` (#28) | Public SaaS leaks (Trello, Notion, Confluence, etc.) |
| `discover_cloud_assets` (#8, #22) | S3/GCS/Azure/Heroku/Netlify/Firebase/Supabase namespace discovery |
| `fingerprint_tech_stack` (#10) | Tech stack from headers/cookies/body/SANs |
| `source_map_probe` (#49) | Exposed `*.js.map` files + secrets |
| `http_security_headers_audit` (#47) | Security-header configuration |
| `tls_audit` (#53) | TLS protocol versions, cipher suites, cert validity |
| `attack_surface_intel` (#65) | Shodan/Censys host data — open ports, banners, CVEs |
| `cve_lookup` (#61) | OSV.dev CVE matches per `(name, version, ecosystem)` |
| `nvd_lookup` (#73) | NIST NVD authoritative CVSS/CWE/CPE per CVE |
| `cve_intel_search` (#67) | Perplexity-backed fresh CVE intel |
| `domain_reputation` (#63) | URLhaus / Spamhaus DBL / Spamhaus ZEN / GSB / AbuseIPDB |
| `vt_reputation` (#71) | VirusTotal multi-engine consensus |
| `greynoise_classify` (#72) | Targeted-vs-noise IP classification |
| `otx_lookup` (#76) | AlienVault OTX pulse / actor attribution |
| `hibp_breach_check` (#64) | Have I Been Pwned domain breach history |
| `threat_feed_ingest` (#69) | Customer's MISP/STIX/TAXII feeds |
| `kev_diff_check` (#75) | New CISA KEV entries since last scan |
| `nuclei_template_update` (#68) | Refresh of Nuclei CVE-detection templates |
| `exploit_refs` (#62) | ExploitDB/Metasploit/Nuclei rule references per CVE |
| `sigma_rules_for_technique` (#74) | Sigma detection rules per ATT&CK technique |

**Cloud (cloud-attack-paths arc, PRs #293–#311)**

| Tool | What it observes |
|---|---|
| `cspm/prowler.py` (#291) | Prowler-wrapped CSPM across AWS / GCP / Azure |
| `cloud_attack_paths/discovery.py` (#301) | AWS asset graph via boto3 — EC2, S3, IAM, RDS, Lambda, etc. |
| `cloud_attack_paths/azure_discovery.py` (#310) | Azure asset graph via Azure SDK |
| `cloud_attack_paths/gcp_discovery.py` (#311) | GCP asset graph via GCP SDK |
| `cloud_attack_paths/multi_account.py` (#304, #308) | AWS Organizations auto-enumeration + cross-account assume-role edges |
| `cloud_attack_paths/agentless_scan.py` (#305, #309) | Trivy EBS-snapshot CVE scan with auto-snapshot orchestration |
| `cloud_attack_paths/cloudtrail_detection.py` (#306) | CDR rule engine (root use, MFA-less console, after-hours IAM, bulk S3 GET, StopLogging, etc.) |
| `drift/correlator.py` (#292) | Drift between declared IaC + observed cloud state |

**Code (SCA / SAST / IaC / secrets)**

| Tool | What it observes |
|---|---|
| `sca/scanner.py` + parsers | Dependencies across npm/pypi/cargo/ruby/composer/go lockfiles |
| `sca/reachability.py` | Per-CVE reachability scoring (Python taint upstream) |
| `sca/malicious.py` | Malicious-package check against threat-intel feeds |
| `sca/licenses.py` | License classification + policy violations |
| `sast/semgrep_runner.py` | Semgrep SAST with `r/security-audit` + `vibe_coded` rule pack |
| `tools/taint/taint_analysis.py` | Python AST-based taint analysis |
| `iac/scanner.py` + `iac/rules/*` | IaC misconfigurations across TF, K8s, Helm, Docker, Vercel, Netlify, Cloudflare |
| `tools/secrets_scan/` | Secret pattern detection (incl. git-history scan, #288) |
| `tools/sbom_extract/` | SBOM extraction for container images + repos |

Observe-stage volume: **50+ deterministic data sources** across surface,
cloud, and code. Each one is a single tool call away.

### 1.2 Orient — enrich, contextualise, prioritise

What turns raw signals into security-engineer judgment. The agent rarely has to do this manually — it's pre-baked into the tracer / finding pipeline.

- **CWE → category enum auto-inference** (#6) — every CVE-bearing finding gets `category` derived from CWE.
- **OWASP Top 10 / API Top 10 / MITRE ATT&CK auto-tagging** (#9) — finding write site auto-attaches framework IDs.
- **CISA KEV auto-decoration** (#9) — every CVE finding gets `is_kev`, `kev_due_date`, `kev_ransomware_use`.
- **Severity tuning per source** — VirusTotal (≥10 engines = high), GreyNoise (`noise:false + malicious` = high), OTX (≥3 pulses = high), NVD (CVSS 9+ = critical), HIBP (recent + passwords + mass = high).
- **Per-tool MITRE ATT&CK technique tagging** (#66) — every `tool.execution.started` event carries the simulated attacker behaviours.
- **Coverage matrix per (target_type, scan_mode)** (#13) — `coverage.json` + `run.coverage_complete` / `run.coverage_gap` events make the agent's coverage explicit.
- **Phase events** (#11) — recon → exploit → validate → report. Forces the agent to ask "did I finish recon before exploiting?"
- **Check events** (#11) — per (attack-class × surface), with `vulnerable / not_vulnerable / inconclusive` verdict + confidence. Drives negative-coverage assertions in the report.
- **Verification status enum** (#6) — every finding labelled `verified` / `pattern_match` / `inconclusive` / `needs_review`.
- **Priority label derivation** (§11) — auto-derived from `severity × KEV × fix_time_estimate`. The user sees "fix in 5 minutes; reduces critical risk."
- **Plain-English UX fields** (#45+) — `description_plain`, `recommended_action`, `fix_time_estimate`, `exploitation_in_wild_plain` populated on every finding.
- **Kill-chain event** (#36) — multi-step findings carry the chain so the report shows the chain rather than the last step.

Orient-stage value: **the human security engineer never has to manually cross-reference CWE → OWASP → MITRE → KEV → CVSS** the way they do today with siloed tools.

### 1.3 Decide — plan, route, prioritise

The agent's reasoning loop. Strix doesn't make this opaque — every decision is observable.

- **`StrixAgent` planning loop** — main agent reasoning loop in `strix/agents/`.
- **`record_phase` tool** — agent explicitly records phase transitions (recon-done → exploit-start).
- **`run.test_plan` event** (#35) — emitted right after `run.configured` with the deterministic outer envelope of "things this run could find" per target type. Sets expectations before findings exist.
- **`spawn_webapp_subteam`** (#41+) — multi-agent orchestration with category-tagged sub-agents (auth-attacker / sqli-validator / xss-specialist / ssrf-scanner).
- **`domain_recon_pipeline`** (#17) — deterministic recon orchestrator that composes the recon tools in a fixed order, persists `surface_map.json`, classifies subdomains.
- **`load_skill`** — agent-driven skill loading; deterministic auto-load via fingerprint match (#10).
- **`agent.created` events** (#33) — every sub-agent spawn carries a `category` tag.
- **Coverage gap detection** (#13) — at run-end, surface "you intended to test X but didn't" rather than silently missing it.

Decide-stage observability: every decision is in `events.jsonl`. Audit trail is complete.

### 1.4 Act — probe, verify, report

The actual exploitation surface. All cluster-A safety-composed (#40, #50): rate-limit / exclude-path / auth-injection apply transparently.

**Web / API specialists (LLM-driven + deterministic)**

| Tool | Acts on |
|---|---|
| `scan_xss` | Reflected + stored + DOM XSS with 8 context-aware payload classes |
| `scan_sqli` | SQLi across 5 DB dialects with sqlmap orchestration runbook |
| `scan_xxe` / `scan_oob_xxe` | In-band + OOB-DNS blind XXE |
| `scan_ssrf` / `scan_blind_ssrf` | 29-cohort SSRF + OOB-first blind SSRF |
| `scan_idor` / `scan_multi_role_auth` | Cross-session IDOR + multi-role authz orchestration |
| `scan_oauth` | OAuth 2.0 / OIDC misconfiguration (state, PKCE, redirect_uri, implicit flow) |
| `scan_saml_xsw` (PR #321) | SAML XML Signature Wrapping (8 variants) + SP config audit |
| `scan_auth_flow` | Default-creds + session capture |
| `scan_business_logic` | Workflow / business-rule abuse (A04:2021) |
| `scan_deserialization` | Stack-aware deserialization (CWE-502 / A08:2021) |
| `scan_cmd_injection` / `scan_blind_cmd_injection` | In-band + OOB-DNS blind cmd injection |
| `scan_nosql_injection` | MongoDB / Mongoose NoSQLi (CWE-943) |
| `scan_path_traversal` | CWE-22 file-traversal |
| `scan_ssti` | Server-side template injection (CWE-1336) |
| `scan_ldap_injection` / `scan_xpath_injection` | Injection variants |
| `scan_secrets_in_response` | Passive credential exposure (CWE-798/200) |
| `scan_request_smuggling_active` | Timing-based smuggle confirmation (CWE-444) |
| `scan_cache_deception` (PR #296) | Web cache deception path-traversal variants |
| `scan_prototype_pollution` (PR #297) | Server-side prototype pollution |
| `scan_websocket_auth` (PR #298) | WebSocket / SSE auth probe |
| `scan_race_condition` (PR #320) | Parallel-fire TOCTOU detector |
| `scan_subdomain_takeover_active` | Active CNAME takeover (CWE-1390) |
| `scan_api_bola` / `scan_api_bfla` / `scan_api_mass_assignment` / `scan_api_rate_limit` | OWASP API1/3/4/5 |
| `graphql_introspection_deep` | Introspection + alias DoS + depth abuse + mutation auth |
| `scan_api_grpc_reflection` | gRPC ServerReflection probe |
| `scan_nuclei_templates` | Community-corpus fan-out (~13K templates, daily-updated) |
| `host_header_check` / `cache_deception_check` / `file_upload_abuse_check` / `open_redirect_check` / `method_tamper_check` / `authz_matrix_check` / `csrf_check` / `cors_deep_check` / `session_entropy_check` / `jwt_audit` / `dom_xss_static_probe` / `cookie_jwt_scoping_check` | Deterministic web/API checks |
| `add_vulnerability_report` | Finding emission with full enrichment |

**Cloud-side Act (PRs #293–#311)**

| Tool | Acts on |
|---|---|
| `cloud_attack_paths/patterns.py` | **27 attack-path patterns** — public-storage-creds-risk, internet-exposed-compute-with-IAM, world-assumable-role, wildcard-admin, public-DB / secrets-store / ECR, external-trust-without-external-id, pass-role-present, can-assume-chain-to-admin, GCP-default-compute-SA, GCP-public-BigQuery, Azure-public-blob, Azure-owner-role, Lambda-function-URL-no-auth, IAM-keys-no-MFA, cross-account-S3-share, unused-high-priv-role, default-VPC-with-resources, secrets-via-env, overpermissive-secrets-manager-policy, internet-resource-unencrypted, + more |
| `cloud_attack_paths/live_probes.py` (#299) | Live PoC probes — anonymous S3 GET / RDS handshake / SQS SendMessage / Lambda invoke |
| `cloud_attack_paths/reachability.py` (#302) | Graph-aware reachability scoring (Wiz's noise reducer) |

**Repo / code Act**

| Tool | Acts on |
|---|---|
| `scan_sca_lockfiles` | SCA scan with KEV/EPSS enrichment |
| `scan_sast` | Semgrep SAST with calibration against `code_map` |
| `scan_iac` | IaC misconfig scan across 8 frameworks (TF/K8s/Helm/Docker/Vercel/Netlify/Cloudflare) |
| `scan_container_image` | Trivy-wrapped image CVE + secret + misconfig scan |
| `agents/patcher.py` + `tools/workflow/patcher_tools.py` (PR #243) | Auto-diff generation + `verify_patch` close-loop (EXPLOITED → PATCHED) |

Cluster-A safety means **every act has guardrails**: --exclude-path blocks dangerous endpoints; --rate-limit budgets traffic; --auth-* injects credentials without leaking them into events.jsonl.

### 1.5 Why this matters

Most "security scanners" are pure Observe. Most "AI security agents" are unstructured Decide. Strix's architecture makes the full loop explicit and **observable** — `events.jsonl` is a complete, auditable record of one agent's OODA loop. That's the AI-native advantage: not just "AI does the testing," but **AI does the testing with a documented reasoning trail a human can review later**.

Post-Decepticon uplift (PRs #233–#244), the loop also gets:

- **Fresh-context specialist dispatch** (`agents/specialist_orchestrator.py`) — sub-agents boot with a clean LLM context so token cost stays bounded
- **OPPLAN objective tracking** (`agents/objective_tracker.py`) — first-class objectives with status / dependencies / acceptance criteria
- **Persistent typed knowledge graph** (`agents/knowledge_graph.py`) — 7 node types + 7 edge types, BFS path queries, atomic JSON persistence to `<run_dir>/kg.json`
- **5-stage verification pipeline** (`agents/verification_pipeline.py`) — SCANNED → DETECTED → VERIFYING → VERIFIED → EXPLOITED → PATCHED with ≥2-method floor for HIGH/CRITICAL
- **Patcher runtime** (`agents/patcher.py`) — closes the EXPLOITED → PATCHED stage with auto-diff + `verify_patch(probe_result_still_fires)`

---

## 2. Security benchmark positioning

### 2.1 Industry frameworks Strix maps against

| Framework | Mapping | Strix coverage |
|---|---|---|
| **OWASP Top 10 (2021)** | CWE → A0X auto-tag (#9) | ~85% deterministic coverage of A01-A10 detection. Reporting carries the A0X tag per finding. |
| **OWASP API Top 10 (2023)** | Skill pack (#43) | All 10 categories. Auto-tagging from CWE. |
| **OWASP WSTG** (Web Security Testing Guide) | Tool-by-tool mapping | ~70%. Strong on deterministic sections (config, identity, session, input, error-handling, crypto). Weaker on business-logic. |
| **NIST 800-115** (Information Security Testing) | Phase events (#11) | Discovery / attack / reporting phases mirror Strix's phase events. Planning is the operator's job. |
| **PTES** (Penetration Testing Execution Standard) | Phase + check events | Intel-gathering → vuln-analysis → exploitation → reporting all directly mappable. Pre-engagement and post-exploitation are out of scope. |
| **MITRE ATT&CK** | Per-tool technique tags (#66) + finding-level tags (#9) | Every tool tagged with primary technique; every finding tagged with technique IDs derived from CWE. |
| **CISA KEV** | Auto-decoration (#9) + diff (#75) | Every CVE finding decorated; daily diff highlights newly-actively-exploited CVEs. |
| **CVSS v3.1** | Auto-derived from NVD (#73), GHSA (#61), VT (#71) | NVD wins for canonical scoring; OSV's heuristic fills gaps; severity bands map cleanly. |

### 2.2 Public AI-security benchmarks

| Benchmark | Applicability to Strix | Result |
|---|---|---|
| **XBEN** (XBOW benchmark — 104 web security challenges) | Agentic web CTF, black-box mode | **96% (100/104)** — Strix v0.4.0. Level 1: 100% (45/45), Level 2: 96% (49/51), Level 3: 75% (6/8). See [`benchmarks/`](benchmarks/). |
| **HackTheBox / TryHackMe** | Agentic CTF | Strong on reconnaissance-heavy boxes; moderate on creative-pivot CTF puzzles. The deterministic recon stack accelerates the early phase materially. |
| **DARPA AIxCC** (2024-2025) | Automated cyber reasoning competition | Different shape (binary analysis + patching). Not directly applicable. |
| **NIST Cyber AI Profile** | Emerging | Likely maps to OODA-loop transparency requirements, where Strix's `events.jsonl` is a strong fit. |
| **OWASP LLM Top 10 (2024)** | About securing LLM apps, not testing-with-LLMs | Adjacent but inverted; Strix's web tools partially detect prompt-injection vectors in deployed LLM apps. |
| **Bug bounty platforms (HackerOne / Bugcrowd)** | Real-world acceptance signal | Findings carry `verification_status`, `fingerprint`, and `kill_chain` — directly maps to bug-bounty triage criteria. |

### 2.3 Where Strix performs well on benchmarks

- **Deterministic-checkable findings** — TLS misconfig, security headers, KEV-tagged CVEs, weak crypto, exposed credentials, open ports, certificate issues. Strix gets these right ~100% of the time because they're rule-based.
- **High-coverage recon** — post-#48 (CT logs) Strix is at industry-tool parity for subdomain enumeration depth.
- **Authz matrix testing** (#42) — deterministic per-(role × endpoint) testing that's frequently missed by manual pentesters.
- **API Top 10** (#43) — full coverage with skill pack + 6 dedicated API specialists.
- **Threat-intel breadth** — 18+ source feeds (§10 audit + gap audit). Most security tools have 1–3.
- **Multi-step workflow abuse** — `scan_race_condition` (PR #320) closes the previously-open race-condition gap with parallel-fire TOCTOU detection.
- **Cloud attack-path reasoning** — 27 patterns across AWS + GCP + Azure with live PoC verification; reachability scoring matches Wiz's noise reducer.
- **XBEN — 96%** (see above): top-tier on the largest published agentic web CTF benchmark.

### 2.4 Where Strix's relative performance is weaker

- **Business-logic flaws** — require domain understanding the agent doesn't have. Mitigated by `business_logic` skill + `scan_business_logic` specialist, but real-world performance still a gap.
- **Deeply interactive web apps** — DOM state machinery is browser-driven; the agent's headless model misses some.
- **Custom auth schemes** — recorded-login replay maturity (Burp macros) is the gap. `replay_mutation_*` + `browser_action` work but feel less battle-tested.
- **WAF bypass via novel obfuscation** — pattern-matching by definition; AI agents don't yet outperform skilled WAF engineers here.
- **IaC depth** — ~50 hand-written rules across 8 frameworks vs Checkov's 1000+. P0 wrap-Checkov pending.
- **Container runtime** — no CWPP wrap yet. Static container scanning is at parity; runtime is 2/2.

---

## 3. Per-target AI-native edge over manual tools

For each target type, comparison against a senior security engineer using best-in-class commercial tools.

### 3.1 web_application

**Manual baseline** — engineer using Burp Suite Pro + ZAP + nuclei + sqlmap + ffuf + browser dev tools. Time per serious pentest: **8-40 hours**.

**Strix coverage** of that baseline:

| Activity | Manual time | Strix time | Strix tool |
|---|---|---|---|
| URL surface mapping | 1-3h | <5 min | `bfs_crawl` (#41) + source_map (#49) + well_known (#46) |
| Tech-stack fingerprinting | 30 min | <30s | `fingerprint_tech_stack` (#10) |
| TLS audit | 30 min | <60s | `tls_audit` (#53) |
| Security headers | 15 min | <10s | `http_security_headers_audit` (#47) |
| Host-header injection | 1h | <30s | `host_header_check` (#55) |
| Web cache poisoning + deception | 1h | <30s | `cache_deception_check` (#56) + `scan_cache_deception` (#296) |
| Request smuggling | 2h | <30s | `request_smuggling_check` (#57) + `scan_request_smuggling_active` |
| File upload abuse | 1-2h | <2 min | `file_upload_abuse_check` (#58) |
| Open redirect | 30 min | <30s | `open_redirect_check` (#59) |
| Method tampering | 30 min | <30s | `method_tamper_check` (#60) |
| Authz matrix | 4-8h | <5 min | `authz_matrix_check` (#42) |
| GraphQL specialist | 1-2h | <60s | `graphql_specialist_check` (#44) + `graphql_introspection_deep` |
| OAuth/OIDC misconfig | 1-2h | <90s | `scan_oauth` + `tools/jwt_audit` |
| SAML XSW + SP config audit | 2-4h | <2 min | `scan_saml_xsw` (PR #321) — 8 XSW variants + unsigned/mangled-sig + WantAssertionsSigned + weak-alg |
| Prototype pollution | 1-2h | <60s | `scan_prototype_pollution` (PR #297) |
| WebSocket auth | 1h | <30s | `scan_websocket_auth` (PR #298) |
| Race condition / TOCTOU | 2-8h | <2 min | `scan_race_condition` (PR #320) — parallel-fire baseline + success-rate classification |
| CVE/exploit research per detected dep | 30 min/CVE | <10s/CVE | `cve_lookup` (#61) + `nvd_lookup` (#73) + `exploit_refs` (#62) |

**AI-native edge:**
- **Time compression**: 8h → 30 min for the deterministic ~70% of WSTG.
- **Consistency**: every scan does every check. A tired senior pentester at hour 6 skips checks. Strix doesn't.
- **Cross-correlation**: `fingerprint_tech_stack` → `cve_lookup` → `exploit_refs` → `sigma_rules_for_technique` happens in <30s. A human pentester would do this for 1-2 high-priority findings; Strix does it for everything.
- **Verification awareness**: every finding ships with `verification_status`, so consumers know which to trust without manual triage.

**Estimated AI-native coverage**: ~85% post-arc. The web specialist
arc (PRs #295–#298, #320, #321) closed the previously-noted holes —
race conditions, prototype pollution, websocket auth, cache poisoning,
SAML XSW. Custom auth flow replay maturity (Burp macros) and deep
business-logic understanding remain in the human's lane.

### 3.2 domain (external attack surface)

**Manual baseline** — engineer using amass/subfinder + theHarvester + Shodan/Censys UI + crt.sh + manual VT/HIBP/KEV cross-references. Time: **4-16 hours**.

**Strix coverage:**

| Activity | Manual time | Strix time | Strix tool |
|---|---|---|---|
| Subdomain enumeration | 1-3h | 2-5 min | `subdomain_enum` (#21) + CT logs (#48) |
| DNS hygiene | 30 min | <30s | `dns_hygiene_check` (#8, #19) |
| Email security depth | 30 min | <30s | DANE/BIMI/DMARC RUA/SPF flatten in (#19) |
| MX fingerprint + sample mail | 20 min | <60s | `mx_fingerprint` (#26) |
| Subdomain takeover | 30 min | <90s | `subdomain_takeover_check` (60+ provider matrix, #20, #27) |
| Cloud asset discovery | 1-2h | <2 min | `discover_cloud_assets` (#8, #22) |
| Org fingerprint + typosquats | 30 min | <60s | `org_fingerprint` (#16) |
| Passive DNS history | 15 min | <30s | `passive_dns_history` (#16) |
| Reverse-IP neighbours | 30 min | <30s | `reverse_ip_discovery` (#23) |
| SaaS leak discovery | 1h | <90s | `saas_leak_discovery` (#28) |
| Code-search for domain | 1h | <60s | `code_search_for_domain` (#24) |
| 5-source IoC reputation | 5 manual lookups (~10 min) | parallel, <30s | `domain_reputation` (#63) |
| VT consensus | 5 min | <10s | `vt_reputation` (#71) |
| GreyNoise IR triage | 5 min | <10s | `greynoise_classify` (#72) |
| OTX attribution | 5 min | <10s | `otx_lookup` (#76) |
| HIBP breach context | 10 min | <10s | `hibp_breach_check` (#64) |
| M365 tenant recon | 15 min | <10s | `m365_tenant_recon` (#52) |
| Customer threat-feed ingestion | manual / impossible | <30s | `threat_feed_ingest` (#69) |

**AI-native edge:**
- **Parallelism**: 5 IoC reputation sources hit simultaneously. A human serializes.
- **Memory**: agent retains everything across sub-tasks. A human pentester forgets half.
- **Threat-feed ingestion**: customer's own MISP/STIX/TAXII data integrated as scan context — impossible for a human pentester to do per-engagement.
- **Daily-scan workflow**: `kev_diff_check` (#75) runs every day, surfaces new actively-exploited CVEs since last run. Humans don't do this.

**Estimated AI-native coverage**: ~85%. Domain recon is highly deterministic — exactly where AI agents excel.

### 3.3 ip_address

**Manual baseline** — engineer using nmap/masscan + Shodan UI + whois. Time: **1-4 hours per IP**.

**Strix coverage:**

| Activity | Manual time | Strix time | Strix tool |
|---|---|---|---|
| Shodan + Censys exposure | 5 min each, manual UI | <30s parallel | `attack_surface_intel` (#65) |
| Open-port discovery | 5-30 min (nmap) | passive via Shodan/Censys | within `attack_surface_intel` |
| Service version fingerprint | 15-60 min | <10s (from Shodan banner) | within `attack_surface_intel` |
| CVE matching per service version | 20 min/service | <10s | `cve_lookup` + `nvd_lookup` |
| Reverse-IP / shared-host | 10 min | <30s | `reverse_ip_discovery` (#23) |
| GreyNoise classification | manual UI | <10s | `greynoise_classify` (#72) |
| OTX attribution | manual | <10s | `otx_lookup` (#76) |

**AI-native edge:**
- **Cross-target pivoting**: an IP finding immediately surfaces shared-hosting neighbours (`reverse_ip_discovery`), feeds them through `subdomain_enum` reversal, surfaces the broader surface. A human would scope to the single IP.
- **High-risk service detection**: 18 service-name patterns auto-flagged as high (Redis/MongoDB/Docker API/etc.). A human relies on their checklist + memory.

**Estimated AI-native coverage**: ~75%.

### 3.4 repository / local_code

**Manual baseline** — engineer using Semgrep/CodeQL + gitleaks/truffleHog + manual code review + Snyk. Time: **4-20 hours per repo**.

**Strix coverage:**

| Activity | Manual time | Strix time | Strix tool |
|---|---|---|---|
| Secret scan | 30 min | <30s | `secrets_scan` + git-history scan (PR #288) |
| Tech stack from manifest files | 15 min | <10s | fingerprint patterns |
| Dependency CVE scan | 30 min/dep | <10s/dep | `scan_sca_lockfiles` + `cve_lookup` (#61) per `(package, version, ecosystem)` |
| SCA reachability scoring | manual taint trace | <60s | `sca/reachability.py` + `tools/taint/taint_analysis.py` (Python) |
| Malicious-package check | manual | <30s | `sca/malicious.py` |
| License classification | manual | <10s | `sca/licenses.py` |
| SAST | manual code review | <2 min | `scan_sast` (semgrep `r/security-audit` + vibe_coded pack) calibrated against `code_map` |
| IaC misconfig scan | manual or Checkov run | <60s | `scan_iac` across 8 frameworks (TF/K8s/Helm/Docker/Vercel/Netlify/Cloudflare) |
| Container image CVE + secret + misconfig | manual Trivy run | <90s | `scan_container_image` + KEV/EPSS enrichment |
| Auto-fix verification | manual probe re-run | <30s | `agents/patcher.py` + `verify_patch` (PR #243) — closes EXPLOITED → PATCHED |
| Fresh CVE intel beyond OSV | 1h+ manual web search | <60s | `cve_intel_search` (#67) |
| NVD authoritative scoring | 5 min/CVE manual | <10s/CVE | `nvd_lookup` (#73) |
| Public exploit references | 15 min/CVE | <10s/CVE | `exploit_refs` (#62) |
| Detection-rule recommendations | manual SIEM-team work | <30s | `sigma_rules_for_technique` (#74) |

**AI-native edge:**
- **Cross-correlation with prod**: leaked credential in a repo → tested against the production target. A human would log the finding, file a ticket; Strix verifies in the same scan.
- **CVE chain enrichment**: `cve_lookup` → `nvd_lookup` → `exploit_refs` → `sigma_rules_for_technique` is one mental hop for the agent; for a human it's 3-5 different tools and SaaS dashboards.
- **Patcher close-loop**: when a fix lands, `verify_patch` replays the original probe against the patched code. If the probe no longer fires, the finding transitions to `patched` automatically. No competitor does this end-to-end today.

**Estimated AI-native coverage**: ~65% post-SCA-reachability + patcher.
The biggest remaining gap is **IaC depth** — ~50 hand-written rules vs
Checkov's 1000+. **Wrap-Checkov** is the §3 P0 in `masterroadmap.md`.

### 3.5 cloud_account

**Manual baseline** — engineer using Prowler + ScoutSuite + Pacu + manual IAM walks + CloudTrail grep. Time: **8-40 hours per account; days+ for multi-account orgs**.

**Strix coverage:**

| Activity | Manual time | Strix time | Strix tool |
|---|---|---|---|
| CSPM (AWS / GCP / Azure) | 1-2h | <5 min | `cspm/prowler.py` (PR #291) |
| Asset discovery (AWS) | 1-2h | <2 min | `cloud_attack_paths/discovery.py` via boto3 (PR #301) |
| Asset discovery (Azure / GCP) | 2-4h each | <2 min each | `azure_discovery.py` (PR #310) + `gcp_discovery.py` (PR #311) |
| Multi-account / Organisations | 4-12h | <5 min | `cloud_attack_paths/multi_account.py` (PRs #304, #308) |
| Attack-path detection | 4-16h manual graph walk | <30s | `cloud_attack_paths/patterns.py` — **27 patterns** across all 3 clouds |
| Reachability scoring | manual (no good tool) | <10s | `cloud_attack_paths/reachability.py` (PR #302) |
| Live PoC verification | 2-8h manual | <2 min | `cloud_attack_paths/live_probes.py` (PR #299) — anonymous S3 GET / RDS handshake / etc. |
| Agentless VM CVE scan | impossible without agents | <10 min per snapshot | `cloud_attack_paths/agentless_scan.py` (PR #305) — Trivy EBS-snapshot mode + auto-snapshot (PR #309) |
| Cloud Detection & Response | impossible without SIEM | <30s | `cloud_attack_paths/cloudtrail_detection.py` (PR #306) |
| Drift correlation IaC ↔ live | manual diff | <60s | `drift/correlator.py` (PR #292) |

**AI-native edge:**
- **One-shot cross-cloud**: AWS + GCP + Azure asset graphs land in the same KG. Wiz handles this with a graph DB and 4+ years of engineering; Strix matches the core surfaces with deterministic Python.
- **Verified attack paths**: 27 patterns × live PoC probes = the customer sees "we proved this path is exploitable" not "we computed a theoretical risk." Same exploit-synthesis moat as web, now on cloud.
- **Reachability scoring**: a vuln 3 hops from a public LB ranks above a vuln on an isolated bastion. The Wiz noise-reducer that justified their pricing.
- **CDR without SIEM**: deterministic rules over CloudTrail catch the canonical compromise patterns (root use, MFA-less console, AssumeRole from unknown account, bulk S3 GET, StopLogging) at zero ingest cost.

**Estimated AI-native coverage**: ~75% of the Wiz capability surface at
mid-market. Remaining gaps: per-cloud resource-type depth (Wiz covers
1000+; Strix covers ~50 top types), DSPM (data security posture
management — sample S3 / GCS / BigQuery for PII/PHI/PCI), and ML-
baseline CDR (v1 deterministic rules ship today).

### 3.6 Multi-target compounding

The biggest AI-native edge is **scope compounding**: one Strix run does (web + domain + IP + code) when the customer ships all four. A human team needs four specialists, four toolchains, four reports. Strix produces one cross-correlated report that surfaces:
- Subdomains pointing at IPs flagged on URLhaus
- CVEs in package versions detected via fingerprint AND in customer's own threat-feed
- Leaked credentials in a repo that match the production auth scheme
- Open RDP on an IP attributed to APT-X via OTX

A human team can produce this with 40+ hours of cross-team coordination. Strix does it in one scan, with `events.jsonl` proving the reasoning chain.

---

## 4. Wrapper changes (webappsec/) needed

The webappsec/ wrapper is the developer/non-tech-facing UI. Its job is
to make Strix's capability **legible to humans who aren't security
engineers**. Current state: surfaces findings but requires reading
events.jsonl / parsing markdown / cross-referencing CWE/CVE/ATT&CK
manually.

This is a delta list — what the wrapper needs to add to expose the AI
security engineer work.

### What's already been built engine-side that the wrapper can now consume

The **engine-wishlist arc** (PRs #312–#319) closed every org-scale
artifact the wrapper needs:

- **Batch mode** (PR #319) — `--target-list targets.jsonl`. One
  invocation, N targets, shared sandbox + LLM context. ~3-4× cheaper
  per-target than serial scans.
- **Shared Researcher cache** (PR #319) — Researcher phase runs once per
  project; subsequent target scans reuse the cached architectural map.
- **`assets.discovered.jsonl`** (PR #314) — engine emits enumerated
  resources; wrapper consumes without re-walking AWS/GCP/Azure SDKs.
- **`kg_delta.jsonl`** (PR #318) — engine emits KG deltas per scan; the
  wrapper's KG store unions them across project scans for cross-target
  path queries.
- **`STRIX_PROJECT_ID`** (PR #317) — project stamp on findings + assets
  so the wrapper's dedup ledger consolidates same-CVE-across-N-repos
  into one root finding with N target references.
- **`--profile initial`** (PR #315) — 2–5 min fast first-pass for newly-
  discovered assets at ~10% of standard-mode cost.
- **`--skip-if-unchanged`** (PR #313) — per-target fingerprint, exits in
  <5s on quiescent targets. The 95% case for daily-cadence scans.
- **Target-metadata pass-through** (PR #316) — wrapper forwards
  `language` / `framework_hints` / `tags` / `owner` into Researcher
  context, eliminating the cold-start cost.

The wrapper backlog below is now **purely UX**, not engine-side
plumbing.

### 4.1 Configuration UX

- **Pre-scan profile selector** — "external recon" / "web pentest" / "API audit" / "domain audit" / "compliance scan" / "deep scan". Each maps to a `scan_mode` + tool-enable subset. Today the wrapper exposes a flat target field; should expose an intent.
- **Threat-intel key onboarding wizard** — walks the user through getting free keys for VT, OTX, GreyNoise, Shodan, Censys, GSB, AbuseIPDB, NVD, Perplexity, HIBP. Detect which keys are present, show coverage tier explicitly: "you have 5/10 threat-intel sources configured. Missing: GreyNoise + VT (lower IR-triage signal); Shodan + Censys (no attacker-eye-view of exposed services)."
- **Compliance preset toggle** — "PCI-DSS", "SOC 2 readiness", "HIPAA". Emphasises specific finding categories in the report and adds compliance-control mappings from §16.
- **Daily-scan workflow** — schedule recurring scans against the same target. Surface `kev_diff_check` (#75) findings prominently as the daily highlight.
- **Target wizard** — validates the URL/domain/IP/repo, runs `--preflight` (#29) before queuing the scan. Avoids the "scan ran for 10 min and found nothing because the target was down" failure mode.

### 4.2 Live scan UX (during the run)

- **OODA loop visualisation** — render the 4-stage loop with the agent's current phase highlighted. Translates `phase.entered` events into a live state machine.
- **Tool-call ATT&CK chain** — render each `tool.execution.started` event (with `actor.mitre_techniques` from #66) as an ATT&CK kill-chain visualisation. Defenders see the simulated attack path live.
- **Per-finding live cards** — as findings emit, render in `priority_label` order with `description_plain` + `recommended_action` prominent. Hide CWE/CVE behind a "show technical details" toggle. Today the wrapper renders findings as a flat list.
- **Coverage progress bar** — from `run.test_plan` (#35) + `check.completed` (#11) events, show "12/14 planned check categories complete." When categories slip to `inconclusive`, surface them prominently.
- **Tool-call cost meter** — when §5 tokens-per-event ships, show running $-cost with budget alerts. Today users have no live cost signal.

### 4.3 Report UX (post-scan)

- **Non-tech report as the default landing page** — plain-English summary of "what was found", "what to fix first", "why it matters". Renders from `description_plain` + `recommended_action` + `priority_label` + `exploitation_in_wild_plain`. Today the default is a CWE/CVE-heavy markdown report.
- **Tech report behind a toggle** — full CWE/CVE/CVSS/CPE/ATT&CK technique IDs for security-engineer consumers.
- **Compliance overlay** — cross-reference findings to PCI-DSS / SOC 2 / HIPAA / etc. controls. Pulls from §16 compliance-control mapping (when shipped).
- **SIEM-rule export** — from `sigma_rules_for_technique` (#74), render Sigma rules per finding so the customer's blue team can deploy detection. Add a "copy as SPL/KQL/Lucene" widget per rule.
- **Triage workflow** — per-finding "fix" / "won't fix" / "false positive" buttons. Persists `verification_status` updates back to the agent (closes the loop on triage; pairs with §12 continuous-learning hooks).
- **Exploit verifier widget** — from `exploit_refs` (#62), per CVE finding show "12 PoCs available across ExploitDB / Metasploit / GitHub." Click → expanded list with stars-as-credibility-signal.
- **Daily-summary email/Slack** — KEV-diff findings, new high-severity discoveries, completed-scan list. Subscribe to a target.
- **Cross-scan diff** — between scan N and N+1: new findings, fixed findings, regressions. Today users compare reports manually.

### 4.4 Wrapper-side AI features

The wrapper should add its own AI layer ON TOP of Strix's structured output. Strix outputs structured data (events.jsonl, vulnerabilities.json, run_summary.json); the wrapper layers conversational + summarisation features on top.

- **Plain-language Q&A on the scan** — "Why is this finding high?" / "How do I fix CVE-X?" / "Which findings are credential-stuffing risks?" RAG over the scan's `events.jsonl` + `vulnerabilities.json`.
- **AI-generated executive summary** — 1-paragraph C-suite-friendly summary of the scan. Inputs: `run.summary` event + top 5 findings.
- **Auto-prioritisation** — cross-reference findings against threat-intel context (KEV / HIBP / threat-feed-ingest) to surface "fix this first because the customer's industry is being actively targeted by APT-X using this CVE."
- **AI-driven finding-cluster narrative** — group related findings into a single story. "Your authentication surface has 6 findings: 1 CSRF gap (medium), 2 weak session cookies (low), 1 HIBP breach exposure (high) + 2 password-policy issues. Together they create credential-stuffing risk; recommended fix order: X, Y, Z."
- **Customer-context override** — let the user paste a "we run on AWS / our threat model says this matters more / our biggest customer is in finance" paragraph; AI re-prioritises findings against that context.

### 4.5 Operational ergonomics

- **Cost dashboard** — from per-event token usage (when §5 ships), show $X spent per scan, per target. Budget alerts.
- **Cache hit rate** — across all the threat-intel tool caches (`vt_cache`, `otx_cache`, etc.). Helps users understand why repeat scans are fast.
- **Free-tier vs paid-tier coverage** — explicitly call out which intel sources are free vs paid; recommend upgrades when the user hits free-tier rate limits. Today this is invisible.
- **Run history archive** — searchable by target, date, finding, CWE, CVE, ATT&CK technique. Strix's `run_meta.json` + `events.jsonl` are sufficient inputs.
- **Skill / tool inventory page** — show what Strix can do, with which keys configured, which version of nuclei templates is in use (from `nuclei_template_update` #68), which threat-intel sources are operational. This is the wrapper's "demo this product to a CISO" page.

### 4.6 What the wrapper does NOT need to build

- Findings deduplication — Strix's `fingerprint` algorithm (#14) handles it.
- KEV / OWASP / ATT&CK enrichment — auto-decorated by the tracer (#9, #66).
- Severity normalisation — already lower-cased + bands-derived in events.jsonl (#5).
- Verification triage — `verification_status` enum (#6) is the contract.
- Coverage assertions — `# Coverage Assertions` markdown section already appended to the report (#14).

---

## Appendix A — §10 threat-intel audit (PRs #61–#76)

Original baseline: 2 ✅ (KEV + OWASP/ATT&CK auto-tag, both in #9).

Shipped this cycle:

| # | Tool | Tier | Effort |
|---|---|---|---|
| #61 | cve_lookup (OSV.dev) | original | M |
| #62 | exploit_refs (ExploitDB / Metasploit / Nuclei) | original | S |
| #63 | domain_reputation (5 sources) | original | S |
| #64 | hibp_breach_check | original | S |
| #65 | attack_surface_intel (Shodan + Censys) | original | M |
| #66 | MITRE ATT&CK technique tagging | original | S |
| #67 | cve_intel_search (Perplexity) | original | S |
| #68 | nuclei_template_update | original | S |
| #69 | threat_feed_ingest (MISP / STIX / TAXII) | original | L |
| #70 | gap audit docs | audit | docs |
| #71 | vt_reputation | 🔴 critical | S |
| #72 | greynoise_classify | 🔴 critical | S |
| #73 | nvd_lookup | 🔴 critical | S |
| #74 | sigma_rules_for_technique | 🟡 important | M |
| #75 | kev_diff_check | 🟡 important | S |
| #76 | otx_lookup | 🟡 important | S |

Across 16 PRs the §10 threat-intel surface went from **2 sources to 18
sources**, with consistent UX (`description_plain` + `recommended_action`
+ `verification_status`), full caching with stale-fallback, and uniform
composition with cluster-A safety + the MITRE ATT&CK tagging plumbing.

## Appendix B — major arcs since (PRs #200–#321)

### Decepticon uplift (PRs #233–#244)
Fresh-context specialist orchestration · OPPLAN objective tracker ·
typed knowledge graph (`kg.json`, 7 nodes + 7 edges) · 5-stage
verification pipeline (SCANNED → DETECTED → VERIFYING → VERIFIED →
EXPLOITED → PATCHED, with ≥2-method floor for HIGH/CRITICAL) · skills
middleware · tiered tool output · `strix.scope.yml` engagement scope ·
model fallback chain · patcher runtime (auto-diff + `verify_patch`
close-loop) · KG specialist adoption (scan_sqli + scan_xss populate
Vuln + Surface + AFFECTS).

### MOAK + cloud arc (PRs #270–#311)
MOAK Phase A/B (fingerprinted-products → HTTP exploit shape → live
probe) · cloud_attack_paths graph + 27 patterns · live PoC probes ·
reachability scoring · AWS/GCP/Azure asset discovery · multi-account
fan-out · agentless VM CVE scan (Trivy EBS-snapshot + auto-snapshot) ·
CloudTrail-based CDR · drift correlator · cosign + SLSA · IaC across 8
frameworks · git-history secret scan · CIS benchmarks.

### Web specialist arc (PRs #295–#298, #320–#321)
Web cache poisoning · server-side prototype pollution · WebSocket auth ·
race condition / TOCTOU · SAML XSW + SP config audit.

### Engine-wishlist arc (PRs #312–#319)
**All 8 org-scale items shipped**: `--skip-if-unchanged` ·
`assets.discovered.jsonl` · `--profile initial` · target-metadata pass-
through · `STRIX_PROJECT_ID` stamp · `kg_delta.jsonl` · multi-target
batch mode · shared Researcher cache.

### Benchmark
**XBEN 96% (100/104)** — Strix v0.4.0 black-box (see [`benchmarks/`](benchmarks/)).
- Level 1 (Easy): 45/45 (100%)
- Level 2 (Medium): 49/51 (96%)
- Level 3 (Hard): 6/8 (75%)
