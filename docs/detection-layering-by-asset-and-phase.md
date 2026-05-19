# Detection layering: per asset type, per phase

**What strix does at each detection phase, broken down by asset type and by the layer that does the work.**

The product is a layered architecture, not a monolithic LLM scanner. Each finding passes through ≥3 layers before it lands in the report:

| Layer | Engine | What it produces | Cost profile |
|---|---|---|---|
| **L1 — Signature / OSS corpus** | nuclei templates, semgrep registry, trivy DB, grype DB, osv-scanner GHSA feed, checkov, sqlmap, gitleaks, trufflehog, jwt_tool | Raw candidate findings against known-CVE / pattern signatures | $0, seconds, daily-refreshed corpus |
| **L1.5 — Targeted deterministic specialists** | `scan_idor`, `scan_sqli`, `scan_ssrf`, `scan_xxe`, `jwt_audit`, `cors_deep_check`, `scan_api_bola`, …  (~40 specialists) | Strix-bespoke deterministic probes that OSS tools don't ship — IDOR walks, BOLA cross-session, JWT none-alg + weak-secret, prototype pollution, SAML XSW, etc. | Negligible, single API roundtrip per check |
| **L1.7 — Threat-intel enrichment** | KEV (CISA), EPSS (FIRST.org), NVD, GHSA, OSV.dev, VirusTotal, GreyNoise, HIBP, domain reputation, **MOAK feed** | Per-finding `epss` block, `kev_listed` flag, `contextual_priority.priority_tier`, attack-paths chain hints | Free for OSS feeds; paid for VT/GreyNoise; offline-cached |
| **L2 — LLM reasoning (always-on)** | Lead-agent loop + `contextual_priority` + `contextual_triage_rules` (R9 + R10) + `fp_filter` + `dedupe` | Cross-engine dedupe, EPSS/KEV-aware ranking, R9 unreachable-FP demotion, R10 chain-first-link upgrade, business-logic detection, novel-vuln tagging | ~5-10 LLM calls in quick mode; 20-80 in standard/deep |
| **L3 — Agentic exploration + chain-building + PoC synthesis** | `dispatch_specialist` (fresh-context loops), `finding_chains`, `verify_findings`, exploit-builder, MOAK Researcher | Attack-path chains (`attack_paths.jsonl`), working exploit PoCs, zero-day candidates with reproduction steps, cross-asset pivots | $0.05-$0.50 per specialist dispatch; **disabled in quick mode**, capped at 8 in standard, unbounded in deep |

The marketing claim is **"layer the agentic reasoning on top of the OSS detection corpus, never replace it."** Anything strix could've found by just invoking `semgrep + trivy + nuclei` is found by L1 + L1.7 — fast and cheap. The LLM's job is what those tools structurally can't do.

---

## Detection phases (canonical 0-10)

| # | Phase | Purpose |
|---|---|---|
| P0 | Asset orientation | What is this target? Tech stack, framework, runtime version |
| P1 | Inventory enumeration | Endpoints, dependencies, subdomains, files, ports |
| P2 | Signature scan (L1) | OSS corpus sweep — nuclei, semgrep, trivy, grype, osv, checkov, sqlmap |
| P3 | Threat-intel enrichment (L1.7) | Attach EPSS / KEV / GHSA / OSV / VT / GreyNoise / MOAK data to every finding |
| P4 | Reachability + call-graph (L1.5) | Taint analysis, code-map, SCA reachability scoring → drives R9 |
| P5 | Targeted deterministic specialists (L1.5) | IDOR, BOLA, JWT, SAML XSW, SSTI, etc. — bespoke probes |
| P6 | LLM dedupe + rank + FP demote (L2) | One finding per real vuln, ranked by `contextual_priority`, R9/R10 fired |
| P7 | Specialist dispatch + custom exploration (L3) | Fresh-context loops for high-value surfaces (standard/deep only) |
| P8 | Attack-path chain construction (L3) | `attack_paths.jsonl` — multi-stage exploit chains across findings |
| P9 | Exploit PoC synthesis (L3) | Working PoC code attached to each finding (deep mode); MOAK feed-trigger arms future CVE→PoC pipelines |
| P10 | Report + attestation emit | `penetration_test_report.md`, `simulation_run.json`, `contextual_priority` rollup |

---

## Per-asset-type matrix

### Repository / local_code (whitebox source-available)

| Phase | L1 OSS tools | L1.5 specialists | L1.7 threat-intel | L2 / L3 LLM work |
|---|---|---|---|---|
| **P0 Orient** | `git log`, `tree`, `ast-grep`, `tree-sitter` parsers (8 langs) | `build_code_map`, `fingerprint_tech_stack` | — | LLM picks entry points + sink classes to prioritize |
| **P1 Inventory** | `tree-sitter`-driven file index, lockfile discovery | `sbom_extract`, lockfile parser | — | — |
| **P2 Signature (L1)** | `semgrep` (registry + vibe-coded + p/security-audit), `trivy fs`, `grype dir`, `osv-scanner -r`, `checkov` (IaC), `gitleaks`, `trufflehog`, `bandit` (Python) | `scan_sast`, `scan_sca_lockfiles`, `scan_iac`, `secrets_scan` (wrappers around the OSS layer) | — | — |
| **P3 Threat-intel** | — | — | OSV.dev, GHSA, NVD, EPSS lookup per CVE; KEV diff snapshot; **MOAK feed-trigger** consumes Dependency-node emissions for future-CVE pipeline | LLM reads enriched findings |
| **P4 Reachability** | — | `taint_analysis` (Python + JS taint propagation), `score_reachability` (SCA call-graph reachability — package vuln vs called function) | — | Reachability verdict drives R9 unreachable_high_downgrade |
| **P5 Specialists** | — | `scan_misconfig` (config file audit) | — | — |
| **P6 LLM dedupe + rank** | — | — | — | Collapse semgrep+osv+grype on same package; rank by `contextual_priority` (KEV → p0; EPSS≥0.7 → p0; high+EPSS≥0.5 → p1) |
| **P7 Specialist dispatch** | — | — | — | **(standard/deep only)** Fresh-context loops on highest-EPSS deps to validate exploitability |
| **P8 Chain construction** | — | — | — | `attack_paths.jsonl`: SAST taint sink → SCA vuln dep → privilege escalation chain |
| **P9 Exploit PoC** | — | — | — | **(deep only)** LLM crafts working PoC from SAST finding + reachability + dep version |
| **P10 Report** | — | — | — | Final emission with `contextual_priority` + `discovery_method` + `is_novel` flag |

### API target (REST / GraphQL / gRPC — JSON, no DOM)

| Phase | L1 OSS tools | L1.5 specialists | L1.7 threat-intel | L2 / L3 LLM work |
|---|---|---|---|---|
| **P0 Orient** | `httpx`, `nuclei -t tech-detect`, `wafw00f` | `fingerprint_tech_stack`, `well_known_harvest` (robots.txt, security.txt, .well-known/) | — | LLM identifies API style (REST / GraphQL / gRPC) → picks correct phase plan |
| **P1 Inventory** | `nuclei -t exposures/apis/`, OpenAPI/Swagger spec fetch, `katana` (links) | `openapi_spec_ingest` (canonical inventory), `ingest_har_file` / `ingest_burp_file` for proxy-captured traffic | — | — |
| **P2 Signature (L1)** | `nuclei -tags cve,sqli,xss,ssrf,rce,xxe` (~9k templates), `sqlmap` (when SQLi suspected), JWT tool | `scan_nuclei_templates`, `sqli_check`, `jwt_audit`, `tls_audit`, `http_security_headers_audit` | — | — |
| **P3 Threat-intel** | — | — | Per-fingerprinted-product CVE lookup against KEV/EPSS; `vt_reputation` for domain; `greynoise_classify` for attacker-IP context | — |
| **P4 Reachability** | — | `scan_response_anomaly`, `scan_timing_oracle` (statistical-fit blind-injection confirmation) | — | — |
| **P5 Specialists (the big one for APIs)** | — | **OWASP API Top 10 deterministic specialists**: `scan_api_bola`, `scan_api_bfla`, `scan_api_mass_assignment`, `scan_api_rate_limit`, `scan_idor`, `scan_multi_role_auth`, `scan_oauth`, `scan_saml_xsw`. Plus injection family: `scan_sqli`, `scan_xxe`, `scan_blind_ssrf`, `scan_deserialization`, `scan_blind_cmd_injection`, `scan_ssrf`, `scan_ssti`, `scan_path_traversal`, `scan_nosql_injection`, `scan_ldap_injection`, `scan_xpath_injection`, `scan_cmd_injection`, `scan_oob_xxe`, `scan_request_smuggling_active`, `scan_secrets_in_response`. Plus `scan_business_logic`, `graphql_introspection_deep`, `scan_api_grpc_reflection` | — | — |
| **P6 LLM dedupe + rank** | — | — | — | Dedupe nuclei + sqlmap + scan_sqli findings; rank by `contextual_priority` |
| **P7 Specialist dispatch** | — | — | — | **(standard/deep)** Fresh-context loops on auth flows, business-logic chains, multi-step bypasses |
| **P8 Chain construction** | — | — | — | E.g. `jwt_none_alg → bola_user_by_id → mass_assignment_admin` chain |
| **P9 Exploit PoC** | — | — | — | **(deep)** Full working PoC with token forging + endpoint walks |
| **P10 Report** | — | — | — | — |

### Web application (HTML-rendering)

API matrix above PLUS the web-only items:

| Phase | Additional L1 OSS tools | Additional L1.5 specialists | Notes |
|---|---|---|---|
| **P0 Orient** | `playwright` browser, JS-Snooper, source-maps fetch | `browser_action`, `extract_dom`, `source_maps` | DOM-aware tech detection |
| **P1 Inventory** | `katana` (browser crawl), `gospider`, `dirsearch`, JS-static link extraction | `bfs_crawl`, `webapp_recon_pipeline` | — |
| **P2 Signature (L1)** | ZAP baseline (when wired), wapiti, full nuclei web tag set | (same as API) | — |
| **P5 Specialists** | — | + `scan_xss`, `dom_xss_static_probe`, `cors_deep_check`, `cookie_jwt_scoping_check`, `csrf_check`, `open_redirect_check`, `scan_cache_deception`, `scan_websocket_auth`, `scan_prototype_pollution` (JS) | — |
| **P7-P9** | — | — | Browser-driven exploitation in deep mode |

### web+code (paired — vibe-coded SaaS pattern)

**Union of repository + web_application** matrices, run in parallel. The lead picks correlated findings:

- SAST sink in `app.py:42` → DAST endpoint at `/api/search` returns reflected query → confirmed SQLi chain.
- SCA dep CVE-2023-X in `package.json` → `/api/upload` accepts the vulnerable input pattern → arms MOAK feed-trigger for future CVE arrivals.
- IaC misconfig `cors: *` in `vercel.json` → `cors_deep_check` confirms `Access-Control-Allow-Credentials: true` is exploitable.

This is where strix's L2/L3 reasoning gives the strongest delta vs OSS-only — no single OSS tool correlates SAST + SCA + IaC + DAST findings into chains.

### container_image

| Phase | L1 OSS tools | L1.5 specialists | L1.7 threat-intel | L2 / L3 LLM work |
|---|---|---|---|---|
| **P0 Orient** | `docker image inspect`, `skopeo` | — | — | — |
| **P1 Inventory** | `trivy image --format spdx-json` (SBOM) | `sbom_extract`, `scan_container_image` | — | — |
| **P2 Signature (L1)** | `trivy image --scanners vuln,misconfig,secret` (the canonical container scanner) | `scan_container_image` wrapper | — | — |
| **P3 Threat-intel** | — | — | KEV diff + EPSS per CVE; **MOAK feed-trigger** consumes Dependency nodes — when a new CVE arrives against a customer's pinned base image, MOAK auto-synthesizes a PoC | — |
| **P5 Specialists** | — | `lookup_known_cves` / `lookup_cve_by_id` for cross-reference | — | — |
| **P6 LLM dedupe + rank** | — | — | — | Filter to KEV / high-EPSS subset; collapse "same CVE in 12 images" |
| **P7 Specialist dispatch** | — | — | — | **(deep)** Per-CVE exploit-feasibility validation |
| **P8 Chain construction** | — | — | — | Image vuln → runtime config exposure → container-escape chain |
| **P10 Report** | — | — | — | — |

### domain / ip_address (attack-surface mapping; no signature corpus for the asset itself)

| Phase | L1 OSS tools | L1.5 specialists | L1.7 threat-intel | L2 / L3 LLM work |
|---|---|---|---|---|
| **P0 Orient** | `nmap -sC -sV`, `naabu`, `httpx` | `fingerprint_tech_stack` on discovered services | `domain_rep`, `vt_reputation` (passive recon) | — |
| **P1 Inventory** | `subfinder`, `naabu`, `katana`, passive DNS history, `mail_recon`, `org_fingerprint`, `saas_leaks` | `subdomain_enum_tool`, `domain_recon_pipeline`, `discover_cloud_assets`, `dns_hygiene_check`, `passive_dns_history`, `reverse_ip` | — | LLM correlates discovered hosts → picks which to deep-scan |
| **P2 Signature (L1)** | (No corpus until a service is discovered; then web_application matrix kicks in per service) | — | — | — |
| **P5 Specialists** | — | `scan_subdomain_takeover_active`, `subdomain_takeover_check` | — | — |
| **P3 Threat-intel** | — | — | `hibp_breach` (org domain leaks), `greynoise_classify` (attacker reputation), `vt_reputation` | — |
| **P6-P10** | — | — | — | LLM-driven correlation: which discovered asset is the highest-risk pivot point |

---

## Per-mode layer depth

The same matrix above is invoked across all three modes; **modes differ in how deep into L2 and L3 the LLM goes**.

| Mode | L1 (signature) | L1.5 (specialists) | L1.7 (threat-intel) | L2 (LLM rank/dedupe) | L3 (dispatch + chains + PoC) |
|---|---|---|---|---|---|
| **quick** | ✅ Full anchor scans (Phase 0 — required) | ✅ Targeted only — JWT/BOLA/IDOR core set | ✅ Full enrichment (cheap) | ✅ Ranking, dedupe, R9/R10, FP demote, novel-vuln flag. ~5-10 LLM calls | ❌ **dispatch_cap=0** — no specialist team, no exploit synthesis. Quick is **OSS + L1.7 + light L2 triage** |
| **standard** | ✅ Full anchor scans | ✅ Full specialist sweep | ✅ Full enrichment | ✅ Same as quick + per-finding exploitation reasoning. ~20-50 LLM calls | ✅ **dispatch_cap=8** — fresh-context loops on highest-EPSS surfaces. Attack-path chain construction. Light PoC synthesis. |
| **deep** | ✅ Wider severity gates (low/medium too — chain first-link candidates) | ✅ Full specialist sweep | ✅ Full enrichment + cross-asset correlation | ✅ Exhaustive reasoning. ~50-200 LLM calls | ✅ **dispatch_cap=None** (unbounded) — full chain enumeration + working PoC for every finding + MOAK Researcher zero-day candidates |

---

## Where strix's value-add lives (vs running OSS tools yourself)

OSS finds the candidates. Strix's contribution:

1. **Single unified output format.** semgrep / nuclei / trivy / osv emit five different JSON schemas; strix normalizes to one canonical finding shape with `contextual_priority`, `discovery_method`, `epss`, `attack_path_membership`.
2. **Cross-tool dedupe.** When semgrep + nuclei + grype all flag the same SQLi or CVE, strix collapses to one finding with `discovery_method` listing each contributing engine.
3. **EPSS / KEV / OSV ranking.** Raw OSS output is severity-labelled by the tool. Strix overlays exploitability data so a "MEDIUM by CVSS, but KEV-listed and EPSS=0.91" finding gets `priority_tier: p0_emergency` instead of being lost in the medium pile.
4. **Reachability gating (R9).** A HIGH CVE in an unreachable code path gets `priority_tier: p4_suppressible`. OSS tools don't compute reachability; strix does via `score_reachability` + `taint_analysis`.
5. **Attack-path chains (R10).** Multi-stage findings — SAST taint sink + SCA vuln dep + IaC misconfig — become one ranked chain in `attack_paths.jsonl` with R10 promoting the first-stage finding to `p0_emergency`.
6. **Business-logic + zero-day detection.** No signature engine catches "the discount-code endpoint accepts negative quantities and credits the user's balance." That's L2 territory. Similarly, novel-vuln candidates (`discovery_method: llm_reasoning`, `is_novel: true`) come from L3.
7. **MOAK feed-trigger.** Customer's deployed-version inventory (Dependency nodes from `scan_sca_lockfiles` + `scan_container_image`) is persisted. When a new CVE drops against a pinned version, MOAK auto-synthesizes a PoC and routes it to the customer. **None of the OSS tools do this** — they're per-scan, not per-customer-inventory.
8. **Attestation artefacts.** Every run emits `simulation_run.json` + `attack_paths.jsonl` + per-finding `contextual_priority` for audit / compliance / MA-S2 procurement. OSS tools emit raw scanner output; strix emits attested scan transcripts.

The competitive position is: **a $0 OSS pipeline can compete with strix on raw candidate-finding volume.** It cannot compete on layers 2-3. The MA-S2 P0 work shipped 2026-05-19 wires the layer-2 substrate (EPSS / KEV / contextual_priority / R9 / R10 / attack_paths.jsonl); the layer-3 substrate (MOAK Researcher, exploit-builder, chain-builder) is older and lives in the standard / deep mode dispatch loops.

---

## Provenance

- Asset-type catalogs: `strix/agents/lead_agent/tool_catalog.py`
- Threat-intel tools: `strix/tools/{kev_diff,epss_enrichment,nvd_lookup,cve_intel,cve_lookup,vt_reputation,greynoise,hibp_breach,domain_reputation,threat_feed}`
- MOAK Researcher: `strix/interface/{batch_mode.py,researcher_cache.py}`; `strix/tools/container_image/scan_container_image.py` (feed-trigger emissions)
- L2 reasoning layer: `strix/llm/{contextual_priority,contextual_triage_rules,dedupe,fp_filter,epss_enrichment}.py`
- L3 chain construction: `strix/finding_chains/`, `strix/telemetry/attack_paths.py`
- Skill bodies: `strix/skills/scan_modes/{initial,quick,standard,deep}.md`
- Per-mode caps: `strix/agents/specialist_orchestrator.py` (`_SCAN_MODE_DISPATCH_CAP`), `strix/agents/lead_iter_cap.py`
- Sandbox OSS toolkit: `containers/Dockerfile`
- Knowledge graph: `strix/agents/knowledge_graph.py` (the data structure that holds Finding / Dependency / Asset / Vuln nodes across phases)

Document version: 2026-05-19, paired with PR #359.
