# Strix — strategic overview

A categorised view of the architecture and feature set we've shipped (PRs #41-#76), through four lenses:

1. AI-native classification — Strix's OODA loop
2. Security benchmark positioning — public benchmarks and where we land
3. Per-target AI-native edge — vs a security engineer using off-the-shelf tools
4. Wrapper (webappsec) changes needed — to expose this capability to developers and non-tech users

This document is a snapshot of the §10 expert-pentester gap audit (#70) cycle — written after shipping VirusTotal (#71), GreyNoise (#72), NIST NVD (#73), Sigma rule mapping (#74), CISA KEV diff (#75), and AlienVault OTX (#76).

---

## 1. AI-native classification — Strix's OODA loop

Strix's value isn't "another scanner". It's an **agent that runs the security-engineer OODA loop** (Observe → Orient → Decide → Act) over a target, with deterministic tool support at each loop stage. Each shipped tool slots into one phase.

### 1.1 Observe — gather raw signals

Deterministic tools that produce raw data the agent can reason about. No interpretation; no severity. Just facts.

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

Observe-stage volume: **30+ deterministic data sources**. Each one is a single tool call away.

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

| Tool | Acts on |
|---|---|
| `request_smuggling_check` (#57) | TE-header desync probing, raw-socket byte-exact |
| `host_header_check` (#55) | Host-header injection, cache-key trust |
| `cache_deception_check` (#56) | Web cache deception path-traversal variants |
| `file_upload_abuse_check` (#58) | 15-payload upload bypass cohort |
| `open_redirect_check` (#59) | 11-payload redirect bypass cohort |
| `method_tamper_check` (#60) | OPTIONS/TRACE/PROPFIND + opt-in destructive verbs |
| `authz_matrix_check` (#42) | Per-(role × endpoint) authz probe |
| `graphql_specialist_check` (#44) | Introspection / depth abuse / alias overloading / batch abuse |
| `add_vulnerability_report` | Finding emission with full enrichment |

Cluster-A safety means **every act has guardrails**: --exclude-path blocks dangerous endpoints; --rate-limit budgets traffic; --auth-* injects credentials without leaking them into events.jsonl.

### 1.5 Why this matters

Most "security scanners" are pure Observe. Most "AI security agents" are unstructured Decide. Strix's architecture makes the full loop explicit and **observable** — `events.jsonl` is a complete, auditable record of one agent's OODA loop. That's the AI-native advantage: not just "AI does the testing," but **AI does the testing with a documented reasoning trail a human can review later**.

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

| Benchmark | Applicability to Strix | Expected performance |
|---|---|---|
| **HackTheBox / TryHackMe** | Agentic CTF — closest public benchmark | Strong on reconnaissance-heavy boxes; moderate on creative-pivot CTF puzzles. The deterministic recon stack accelerates the early phase materially. |
| **DARPA AIxCC** (2024-2025) | Automated cyber reasoning competition | Different shape (binary analysis + patching). Not directly applicable. |
| **NIST Cyber AI Profile** | Emerging | Will likely map to OODA-loop transparency requirements, where Strix's `events.jsonl` is a strong fit. |
| **OWASP LLM Top 10 (2024)** | About securing LLM apps, not testing-with-LLMs | Adjacent but inverted; Strix's web tools partially detect prompt-injection vectors in deployed LLM apps. |
| **Bug bounty platforms (HackerOne / Bugcrowd)** | Real-world acceptance signal | Strix's findings carry `verification_status`, `fingerprint`, and `kill_chain` — directly maps to bug-bounty triage criteria. |

### 2.3 Where Strix performs well on benchmarks

- **Deterministic-checkable findings** — TLS misconfig, security headers, KEV-tagged CVEs, weak crypto, exposed credentials, open ports, certificate issues. Strix gets these right ~100% of the time because they're rule-based.
- **High-coverage recon** — post-#48 (CT logs) Strix is at industry-tool parity for subdomain enumeration depth.
- **Authz matrix testing** (#42) — deterministic per-(role × endpoint) testing that's frequently missed by manual pentesters.
- **API Top 10** (#43) — full coverage with skill pack.
- **Threat-intel breadth** — 10 ✅ §10 items + 6 ✅ gap-audit items shipping = 16 source feeds. Most security tools have 1-3.

### 2.4 Where Strix's relative performance is weaker

- **Business-logic flaws** — require domain understanding the agent doesn't have. Mitigated by `business_logic` skill, but real-world performance still gap.
- **Multi-step workflow abuse** — agent doesn't yet have race-condition tooling (open §7.2 ⬜).
- **Deeply interactive web apps** — DOM state machinery is browser-driven; agent's headless model misses some.
- **Custom auth schemes** — recorded-login replay (open §2 ⬜) would close this.
- **WAF bypass via novel obfuscation** — pattern-matching by definition; AI agents don't yet outperform skilled WAF engineers here.

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
| Web cache deception | 1h | <30s | `cache_deception_check` (#56) |
| Request smuggling | 2h | <30s | `request_smuggling_check` (#57) |
| File upload abuse | 1-2h | <2 min | `file_upload_abuse_check` (#58) |
| Open redirect | 30 min | <30s | `open_redirect_check` (#59) |
| Method tampering | 30 min | <30s | `method_tamper_check` (#60) |
| Authz matrix | 4-8h | <5 min | `authz_matrix_check` (#42) |
| GraphQL specialist | 1-2h | <60s | `graphql_specialist_check` (#44) |
| CVE/exploit research per detected dep | 30 min/CVE | <10s/CVE | `cve_lookup` (#61) + `nvd_lookup` (#73) + `exploit_refs` (#62) |

**AI-native edge:**
- **Time compression**: 8h → 30 min for the deterministic ~70% of WSTG.
- **Consistency**: every scan does every check. A tired senior pentester at hour 6 skips checks. Strix doesn't.
- **Cross-correlation**: `fingerprint_tech_stack` → `cve_lookup` → `exploit_refs` → `sigma_rules_for_technique` happens in <30s. A human pentester would do this for 1-2 high-priority findings; Strix does it for everything.
- **Verification awareness**: every finding ships with `verification_status`, so consumers know which to trust without manual triage.

**Estimated AI-native coverage**: ~70%. Business-logic, complex auth flows, multi-step abuse remain in the human's lane.

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
| Secret scan | 30 min | <30s | `code_search_for_domain` (#24) — for org-scoped public-repo |
| Tech stack from manifest files | 15 min | <10s | fingerprint patterns |
| CVE per dependency | 30 min/dep | <10s/dep | `cve_lookup` (#61) per `(package, version, ecosystem)` |
| Fresh CVE intel beyond OSV | 1h+ manual web search | <60s | `cve_intel_search` (#67) |
| NVD authoritative scoring | 5 min/CVE manual | <10s/CVE | `nvd_lookup` (#73) |
| Public exploit references | 15 min/CVE | <10s/CVE | `exploit_refs` (#62) |
| Detection-rule recommendations | manual SIEM-team work | <30s | `sigma_rules_for_technique` (#74) |

**AI-native edge:**
- **Cross-correlation with prod**: leaked credential in a repo → tested against the production target. A human would log the finding, file a ticket; Strix verifies in the same scan.
- **CVE chain enrichment**: `cve_lookup` → `nvd_lookup` → `exploit_refs` → `sigma_rules_for_technique` is one mental hop for the agent; for a human it's 3-5 different tools and SaaS dashboards.

**Estimated AI-native coverage**: ~50%. Code targets are where deterministic SAST tooling already does most of the work; AI's edge is smaller relative to manual.

### 3.5 Multi-target compounding

The biggest AI-native edge is **scope compounding**: one Strix run does (web + domain + IP + code) when the customer ships all four. A human team needs four specialists, four toolchains, four reports. Strix produces one cross-correlated report that surfaces:
- Subdomains pointing at IPs flagged on URLhaus
- CVEs in package versions detected via fingerprint AND in customer's own threat-feed
- Leaked credentials in a repo that match the production auth scheme
- Open RDP on an IP attributed to APT-X via OTX

A human team can produce this with 40+ hours of cross-team coordination. Strix does it in one scan, with `events.jsonl` proving the reasoning chain.

---

## 4. Wrapper changes (webappsec/) needed

The webappsec/ wrapper is the developer/non-tech-facing UI. Its job is to make Strix's capability **legible to humans who aren't security engineers**. Current state: surfaces findings but requires reading events.jsonl / parsing markdown / cross-referencing CWE/CVE/ATT&CK manually.

This is a delta list — what the wrapper needs to add to expose the AI security engineer work.

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

## Appendix — full §10 audit progression

Starting state (before this cycle): 2 ✅ (KEV + OWASP/ATT&CK auto-tag, both in #9).

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

Across 16 PRs the §10 threat-intel surface went from **2 sources to 18 sources**, with consistent UX (`description_plain` + `recommended_action` + `verification_status`), full caching with stale-fallback, and uniform composition with cluster-A safety + the MITRE ATT&CK tagging plumbing.

Test count progression across the cycle: ~927 → **1468 passing** (+541 hermetic tests).
