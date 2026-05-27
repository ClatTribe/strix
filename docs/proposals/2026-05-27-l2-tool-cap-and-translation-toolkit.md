# L2 tool catalog — first-principles design + ≤10 cap (consolidated)

**Status:** consolidated proposal — supersedes the earlier Q5/Q6 split between this doc and `2026-05-27-l2-from-first-principles.md`
**Owner:** ClatTribe/strix
**Created:** 2026-05-27
**Last consolidated:** 2026-05-27
**Depends on:** CLAUDE.md §1.5 (product-goal framing, L1 / L2 audience split, tool-existence principle)
**Related:** iter-37 series (`docs/tool-catalog-rationalization.md`), Q3 (`docs/proposals/2026-05-27-l1-parity-measurement.md`), L2 tool audit (`docs/proposals/2026-05-27-l2-tool-audit.md`)
**Companion (now folded into this doc):** `docs/proposals/2026-05-27-l2-from-first-principles.md` — kept as a historical companion; the canonical catalog lives here.

---

## 0. TL;DR

* The L2 catalog today carries 13–14 tools per asset (web/api violate the ≤10 cap by 3–4) and is dominated by deep-exploit OSS wrappers that belong in `anchor_prepass`, not in the LLM's choice space.
* The right catalog is built from one principle: **tools are the LLM's hands, not its brain.** A tool exists when the LLM either **CAN'T** do the thing (real-time external data, subprocess execution) or **SHOULDN'T** do it without a system-of-record (committing a finding, advancing workflow).
* That principle generates **4 buckets** (READ STATE / FETCH EXTERNAL / RE-DISPATCH / COMMIT) and **10 tools per asset**, where every tool is justifiable by what the LLM can't do alone.
* `think`, `propose_chain`, and `prioritize_findings` are dropped — they're reasoning, which happens in the LLM's response text. Where they commit (chain narrative, customer priority), they ride as parameters on `create_vulnerability_report`.
* A previously-empty bucket (FETCH EXTERNAL — real-time threat intel + compliance lookup) is the load-bearing addition; without it the lead writes CVE/threat metadata from training-data memory, months stale at best.
* Three remaining gaps after the catalog is rebuilt: **customer-context input** (per-scan config, not a tool), **raw recon artifact access** (`get_recon_artifact`), and **domain-asset intel** (extend `query_threat_intel` to domain shape + add `terminal_execute` to domain catalog).

---

## 1. The constraint and the audit

### 1.1 Constraint (from the user)

> *"Ensure we optimize in a way that the LLM doesn't have to handle more than 10 tools at a time. It doesn't [do] well with more than 10 tool calls."*

Empirical pattern across LLM tool-use evaluations: accuracy degrades steeply once visible tool count exceeds ~10, regardless of total model capability. Anthropic's own tool-use guidance and OpenAI's function-calling docs both recommend small catalogs.

> **Invariant L2-CAP:** For every asset type, the number of tools visible to the L2 Lead at any point in the scan is **≤ 10**. This is a hard architectural invariant. It counts what the LLM sees in the system prompt — minimal CORE + per-asset specialist set. It does NOT count tools that fire deterministically in `anchor_prepass` (the LLM never sees them) or tools that auto-fire inside `finish_scan` (terminal artifacts).

A CI invariant test (`tests/agents/lead_agent/test_l2_cap_invariant.py`, ships in iter-Q5.2) gates any PR that raises any asset's catalog past the cap.

### 1.2 Current state audit (2026-05-27, post iter-37.14)

| Asset type | CORE | Specialist | **Total L2-visible** | Honors L2-CAP? |
|---|---|---|---|---|
| `web_application` | 5 | 8 | **13** | ❌ +3 over cap |
| `api` | 5 | 9 | **14** | ❌ +4 over cap |
| `repository` / `local_code` | 5 | 5 | **10** | ✓ at limit |
| `container_image` | 5 | 2 | **7** | ✓ |
| `ip_address` | 5 | 6 | **11** | ❌ +1 over cap |
| `domain` | 5 | 6 | **11** | ❌ +1 over cap |

**4 of 6 asset types violate the cap.** The two most economically important asset types (`web_application` and `api`) are the worst offenders.

---

## 2. The principle

> **Tools are the LLM's hands, not its brain.**
>
> A tool exists when the LLM either **CAN'T** do the thing (real-time external data, subprocess execution, network I/O) or **SHOULDN'T** do it without a system-of-record (committing a finding, advancing workflow, terminating the scan).

**Tools belong in the catalog when at least one of these is true:**

| Condition | Why a tool is needed |
|---|---|
| **Real-time external data** | LLM training cutoff is stale. Threat feeds, current CVE/EPSS/KEV state, vendor advisories, current compliance-control text — all change after training. |
| **Re-trigger a deterministic scan** | The LLM can't run subprocess / network I/O. Re-firing `nuclei` against a new endpoint with new auth, or `scan_idor` with newly captured sessions, needs the tool. |
| **Persistent side-effect** | Committing a finding, advancing workflow phase, or terminating the scan are state changes the system-of-record must own. |
| **Reading state outside conversation context** | `workflow_status`, `list_pending_findings` — facts that live outside the conversation window. |

**Tools do NOT belong in the catalog when:**

| Anti-condition | Why it's not a tool |
|---|---|
| **Reasoning over data already in context** | Prioritization, chain narrative assembly, plain-English explanation, severity decision — pure reasoning. The LLM emits these as part of its response. |
| **Reformatting / templating** | Rendering a finding into markdown, formatting CVSS XML — the LLM is the renderer; no tool needed. |
| **Decisions encoded inline in the response** | "I think this is high severity" is part of the LLM's argument; it becomes a tool call only when COMMITTING to the system-of-record — and even then the commit can be a *parameter* on an existing emission tool. |

**Worked examples:**

* `think()` — **wrong tool.** No-op echo that returns char-count. The LLM can think in response text. If a reasoning audit trail is wanted, capture the `assistant_text` turns; don't synthesize a tool for it.
* `propose_chain(finding_ids, narrative)` — **wrong tool.** Chain narrative IS the LLM's response. Commit chains via a `chain_summary` parameter on `create_vulnerability_report`, not a separate tool.
* `prioritize_findings(customer_context)` — **wrong tool.** Customer ranking IS the LLM's response. Commit via a `customer_priority: int` parameter on `create_vulnerability_report`.
* `query_threat_intel(cve_id)` — **right tool.** LLM training data doesn't know whether CVE-2024-X was added to CISA KEV last week or whether EPSS moved this morning.
* `rescan(tool_name, target, captured_state)` — **right tool.** The LLM can't run subprocess. Re-firing `nuclei` against a newly authed endpoint requires the dispatcher.
* `create_vulnerability_report(...)` — **right tool.** Persistent side-effect to `tracer.vulnerability_reports`. System-of-record commit.

---

## 3. The 4-bucket taxonomy

Every tool in the L2 catalog must fit one of these four buckets. Tools that don't fit either belong in `anchor_prepass` (L1 detection) or as a terminal auto-artifact in `finish_scan`.

```
L2 catalog (≤ 10 tools per asset type)
├── READ STATE        — facts not in conversation context
├── FETCH EXTERNAL    — real-time data the LLM's training cutoff missed
├── RE-DISPATCH       — re-run a deterministic L1 scan or L2-native probe
└── COMMIT + PRIMITIVES  — write to system-of-record + escape hatches
```

**There is no REASONING bucket.** Reasoning lives in the LLM's response text; reasoning commits (chains, customer priorities) ride as parameters on `create_vulnerability_report`. This is the deliberate change from earlier drafts of this proposal.

---

## 4. The 10-tool catalog (each tool, what it does, status)

### READ STATE (3 — universal across every asset)

| # | Tool | Status | What it does |
|---|---|---|---|
| 1 | `workflow_status` | ✓ exists | Returns scan state: current phase, endpoints discovered, login forms found, findings emitted, gate checks (auth captured? recon done?), and 1–3 templated `next_recommended_actions`. The lead's "where am I" primitive. |
| 2 | `list_pending_findings` | ✓ exists | Up to 25 findings from tracer, **already ranked by L1.5 signals** (surface_priority × composite exploitability × severity). Filterable by `severity_floor`, `include_demoted`. Each row carries annotations (`pending-dast×3`, `bundle×2`, `EXPLOITED`). |
| 3 | `get_finding(id)` | **NEW (Q5.6)** | Single-finding deep-read companion. Returns full report dict (description, evidence, code_locations, chain_summary, corroborated_by, …). Saves tokens vs. dumping the whole list when composing a chain narrative. ~50 LOC + 5 tests. |

### FETCH EXTERNAL (2 — universal — currently EMPTY, this is the load-bearing addition)

Strix has 7 registered real-time-data tools (`cve_lookup`, `nvd_lookup`, `cve_intel_search`, `kev_diff_check`, `threat_feed_ingest`, `scan_iocs_for_target_threatfox`, `legal_compliance_probe`) — **zero are in the post-Q5 minimal L2 catalog.** The lead writes CVE/threat metadata from training-data memory, months stale at best. Two unifying tools fix this:

| # | Tool | Status | What it does |
|---|---|---|---|
| 4 | `query_threat_intel(cve_id|cwe_id|product|domain, ...)` | **NEW (Q5.7)** — collapses 4 existing wrappers | Unified real-time fetcher. Returns CVSS + KEV listing + EPSS score + vendor advisories + exploit-availability flags. **24h cache.** Replaces `cve_lookup` + `nvd_lookup` + `cve_intel_search` + `kev_diff_check`. Extended in Q5.7a to accept `domain=...` and dispatch to domain-intel sources (passive DNS, WHOIS, reputation) — closes a domain-asset gap. ~400 LOC + 20 tests. |
| 5 | `lookup_compliance_mapping(finding_shape, frameworks)` | **NEW (Q5.8)** | Args: `finding_shape={cwe, severity, …}`, `frameworks=["SOC2", "PCI-DSS", "HIPAA", "GDPR", …]`. Returns current control IDs per framework. Backed by a **versioned corpus refreshed on cron**, so it stays current as frameworks revise (SOC2 2025 vs 2017). ~250 LOC + 15 tests. |

### RE-DISPATCH (1–2 per asset)

| # | Tool | Status | What it does | Per-asset |
|---|---|---|---|---|
| 6 | `rescan(tool_name, target, captured_state)` | **NEW (Q5.9)** | Re-fires an L1 OSS tool with new state. E.g. after `scan_auth_flow` captures a session, the lead calls `rescan("scan_sqli_sqlmap", url, {auth_cookie: ...})` to re-test SQLi as the authed user. `tool_name` validated against an allow-list of OSS-wrappers from anchor_prepass. **Capped at 5 rescans/scan** (destructive-amplification guard, iter-29.9 pattern). ~200 LOC + 15 tests. | universal |
| 7 | `dispatch_l2_probe(kind, **kwargs)` | **NEW (Q5.10)** — collapses 3 tools | Umbrella for L2-native probes that require LLM state-reasoning. `kind ∈ {idor, auth_flow, business_logic}`. Docstring enumerates each kind's kwargs. Replaces 3 separate slots (`scan_idor` / `scan_auth_flow` / `scan_business_logic`) with 1. ~150 LOC refactor + 15 tests. | web + api only |
| 8 | `build_code_map(repo_path, ...)` | ✓ exists | Walks repo, regex-extracts routes + models + DB queries + external HTTP + auth boundaries across 8 languages, writes `code_map.json`. | repository / local_code only |

### COMMIT + PRIMITIVES (2 commit + 1 primitive per asset)

| # | Tool | Status | What it does | Per-asset |
|---|---|---|---|---|
| 9 | `create_vulnerability_report(...)` | ✓ exists — **extended (Q5.11)** | Persists finding to tracer. **Newly carries 2 parameters that replace previously-proposed standalone tools:** `chain_summary` (multi-finding narrative — replaces `propose_chain`) and `customer_priority: int` (re-ranked for customer context — replaces `prioritize_findings`). Reasoning is in the LLM's response; commit is on this tool. Q5.11a additionally splits the 21-parameter surface: **required-to-commit (7 fields)** + **render-on-finish** (description_plain, business_impact_plain, recommended_action, fix_time_estimate — auto-generated at `finish_scan` from finding context). ~250 LOC + 25 tests. | universal |
| 10 | `finish_scan(executive_summary, methodology, technical_analysis, recommendations)` | ✓ exists | Terminates scan. Hard-gates on workflow phase + open hypotheses + active agents. **Auto-fires `emit_compliance_evidence` + `generate_remediation_plan` as terminal artifacts** (no catalog slots). OODA-structured rejection on premature finish tells the LLM exactly what to fix. | universal |
| 11 | `send_request(method, url, headers, body, timeout)` | ✓ exists | Arbitrary-HTTP escape hatch. Auto-populates SecurityContext side-effects: records endpoint, captures tech-stack hints, marks `auth-required` on 401/403, parses Location header for value-reflection, extracts param names from query+body, detects OpenAPI/Swagger response shape and pre-populates SecurityContext with documented endpoints. | web / api / ip / domain |
| 12 | `terminal_execute(command, ...)` | ✓ exists — **needs docstring (Q5.12)** | Arbitrary-shell escape hatch. Passthrough to terminal_manager. Today has **no docstring** — LLM has no guidance on canonical per-asset uses (repo: `grep`/`find`/`sed`; ip: nmap follow-ups, `nc`; container: mount-and-inspect; domain: `dig`/`host`/`whois`). Adding a per-asset docstring is ~10 LOC and meaningfully improves aim. | repo / container / ip / domain |

---

## 5. Per-asset visibility (which tools each asset sees)

Universal: 3 READ STATE + 2 FETCH EXTERNAL + 1 RE-DISPATCH (`rescan`) + 2 COMMIT = **8 universal tools.** Then per-asset:

| Asset | + RE-DISPATCH slots | + PRIMITIVE slots | **Total** |
|---|---|---|---|
| `web_application` | `dispatch_l2_probe` | `send_request` | **10** |
| `api` | `dispatch_l2_probe` | `send_request` | **10** |
| `repository` / `local_code` | `build_code_map` | `terminal_execute` | **10** |
| `container_image` | — | `terminal_execute` | **9** |
| `ip_address` | — | `send_request`, `terminal_execute` | **10** |
| `domain` | — | `send_request`, `terminal_execute` ¹ | **10** |

¹ Domain catalog gets `terminal_execute` (was missing) — closes the "no `dig` / `whois`" gap. Pushes domain from 9 to 10, still at cap.

Every deep-exploit OSS wrapper (sqlmap, dalfox, hydra, ffuf, smuggler, nuclei, nmap, httpx, subfinder, checkdmarc, dnstwist, mobsfscan, schemathesis, …) fires in `anchor_prepass`, not on LLM choice. The LLM only sees state-readers, real-time fetchers, re-dispatch primitives, and commit tools.

---

## 6. What moves OUT of L2 (to anchor_prepass)

After the catalog refit, `anchor_prepass.py` becomes the comprehensive L1 detection layer for every asset type:

| Tool | Current home | Moves to | Why |
|---|---|---|---|
| `scan_sqli_sqlmap` | L2 web/api | `anchor_prepass` (web + api) | Deep-exploit detection. Fires when prepass `scan_sqli` flags a candidate. |
| `scan_xss_dalfox` | L2 web | `anchor_prepass` (web) | Same — fires when prepass `scan_xss` flags a candidate. |
| `probe_default_creds_hydra` | L2 web/api | `anchor_prepass` (web + api) | Already in prepass (iter-37.14). Removing duplicate L2 entry. |
| `scan_fuzz_ffuf` | L2 web/api | `anchor_prepass` (web + api) | Already in prepass (iter-37.14). Removing duplicate. |
| `scan_smuggling_smuggler` | L2 web/api | `anchor_prepass` (web + api) | Deep-exploit; fires as L1 always-on for high-throughput targets. |
| `scan_api_schemathesis` | L2 api | `anchor_prepass` (api) | Already in prepass (iter-37.14). Removing duplicate. |
| `verify_credentials_trufflehog` | L2 repo | `anchor_prepass` (repo) | Already wired alongside SAST/secrets in prepass. |
| `scan_mobile_mobsfscan` | L2 repo | `anchor_prepass` (repo) | Already prepass-wired in iter-37.14. |
| `fingerprint_services_nmap` | L2 ip | `anchor_prepass` (ip) | nmap is recon; belongs in prepass. |
| `probe_hosts_httpx` | L2 ip | `anchor_prepass` (ip) | httpx is recon. |
| `scan_nuclei_templates` | L2 ip + domain | `anchor_prepass` (ip + domain) | nuclei is L0 signature corpus — *the* canonical L1 detection. |
| `tls_audit` | L2 ip | `anchor_prepass` (ip) | TLS audit is a single-host probe — always fire on every IP asset. |
| `enumerate_subdomains_subfinder` | L2 domain | `anchor_prepass` (domain) | Recon. |
| `scan_dns_hygiene_checkdmarc` | L2 domain | `anchor_prepass` (domain) | Single-domain audit — always fire. |
| `scan_typosquats_dnstwist` | L2 domain | `anchor_prepass` (domain) | Always-on for domain assets. |
| `domain_recon_pipeline` | L2 domain | `anchor_prepass` (domain) | Deterministic prepass coverage. |
| `map_graphql_inql` | L2 api | `anchor_prepass` (api) | OSS wrapper, not L2-native. Per L2 tool audit. |

**Deprecation path (separate Q3 parity bench):**

| Tool | Status |
|---|---|
| `taint_analysis` | In-house Python-only AST taint analyzer. Violates CLAUDE.md §11.1 ("no in-house detection engines"). Q3 parity bench vs. `semgrep --config p/python`; if semgrep wins (likely), retire and reclaim slot. |

**Deliberately-dropped reasoning tools (do NOT add):**

| Tool | Why dropped | What replaces it |
|---|---|---|
| `think` | Pure no-op echo. LLM can think in response text. | Capture `assistant_text` turns → `run_summary.lead_reasoning_trace[]`. No LLM-visible tool. |
| `propose_chain` (was Q5.6) | Chain narrative IS the LLM's response. | `chain_summary` parameter on `create_vulnerability_report`. |
| `prioritize_findings` (was Q5.7) | Customer ranking IS the LLM's response. | `customer_priority: int` parameter on `create_vulnerability_report`. |
| `scan_auth_flow` (standalone) | Overlaps `probe_default_creds_hydra` in prepass. | Folded under `dispatch_l2_probe(kind="auth_flow")`. The bruteforce part fires in prepass; the session-setup part remains L2-native. |
| `scan_idor` (standalone) | One of 3 collapsible L2 probes. | `dispatch_l2_probe(kind="idor")`. |
| `scan_business_logic` (standalone) | One of 3 collapsible L2 probes. | `dispatch_l2_probe(kind="business_logic")`. |

---

## 7. Gap analysis — what the catalog still doesn't cover

The 10 tools above pass the principle test. Walking through what a security engineer actually does on each asset type surfaces 5 remaining gaps:

### Gap 1 — customer context input (biggest gap, NOT a tool)

The lead needs to know **what kind of customer this is** to make `customer_priority` decisions:
- Industry (fintech / healthcare / SaaS / govtech / e-commerce)
- Compliance targets (SOC2 / PCI-DSS / HIPAA / GDPR / FedRAMP)
- Critical assets / endpoint patterns / data classifications
- Threat model (insider vs external, sophistication)

Without this, `customer_priority` is a guess. Same for the chain narrative ("this matters for *this* customer because...").

**Solution: per-scan config passed via `system_prompt_context`** at scan start, rendered into the system prompt. **Not a tool** — costs 0 catalog slots. Needs implementation + documentation in CLAUDE.md §1.5. Ships as **Q5.13**.

### Gap 2 — raw recon artifact access

The prepass produces katana crawl output, OpenAPI specs, GraphQL schemas, SBOMs, subdomain lists, tech-stack fingerprints. These are NOT findings — they're raw recon data the lead may want to grep, re-read, or sample-inspect. Today they're embedded in tool outputs that the iter-Q2.1 stratified compactor drops to the COLD stratum after a few turns.

**Solution: add `get_recon_artifact(kind, name=None)`** — reads a specific artifact persisted to `<run_dir>/recon/`. Kinds: `endpoints`, `openapi_spec`, `graphql_schema`, `sbom`, `subdomains`, `tech_stack`, `auth_endpoints`. **One new tool, READ STATE bucket.** Ships as **Q5.14**.

**Cap pressure:** adding `get_recon_artifact` pushes web/api/repo to 11 tools. Three resolution options:

| Option | Trade-off |
|---|---|
| (a) Collapse `workflow_status` + `list_pending_findings` + `get_finding` + `get_recon_artifact` under a single `read_state(kind, ...)` umbrella (4 → 1) | Loses per-tool docstring clarity; LLM has to learn the kind taxonomy. |
| (b) Accept 11 tools on web/api/repo as the new cap. Test the 10→11 degradation curve empirically. | The ≤10 number is general guidance, not a strix-specific bench. Q4 (lead parallelism) is the right venue for this measurement. |
| (c) Defer `get_recon_artifact` — see whether the LLM works around it well enough. | Cheapest; loses the recon-grep capability. |

**Recommended: (b).** Measure 10 vs 11 in a Q4 sub-bench before committing.

### Gap 3 — domain asset gaps (folded into Q5.7a + Q5.12)

Two sub-gaps:
* Domain catalog doesn't include `terminal_execute` — `dig` / `host` / `whois` queries need shell. **Fix: add `terminal_execute` to domain catalog** (pushes 9 → 10, still at cap). Done via Q5.12.
* `query_threat_intel` is CVE/CWE-shaped. Domain-level intel (passive DNS, WHOIS history, reputation, related domains) is a separate signal type. **Fix: extend `query_threat_intel(domain=...)` to dispatch to domain-intel sources.** Done via Q5.7a.

### Gap 4 — inconclusive observations (minor)

Currently `create_vulnerability_report` only commits confirmed findings. A real engineer notes "saw a UUID in a response that could be a session ID — investigate later." Today the LLM has no place to put this except `think` (which is being dropped) or losing it.

**Solution: extend `create_vulnerability_report` with `severity="observation"` shape** — same structured record, lower commitment level. Surfaces in `list_pending_findings` with `include_demoted=True`. No new tool needed. Done via Q5.11b (folded into the CV-report extension).

### Gap 5 — repo file reading (defer)

`terminal_execute("sed -n '40,60p' file.py")` works but is awkward. A dedicated `read_file_excerpt(path, start_line, end_line)` would save tokens and remove a shell-escaping footgun.

**Solution: defer.** Adding it pushes repo to 11; not worth the cap pressure right now. Revisit if `bench_context.py` numbers show poor file-citation quality after the rest of Q5 ships.

---

## 8. Iter sequence (consolidated)

Numbers run continuously; the post-Q6-merge renumbering folds Q6.x iters back into the Q5.x line.

| iter | scope | size |
|---|---|---|
| **Q5.1** | This consolidated proposal + CLAUDE.md §1.5.5–9 updates (shipped as PR #509 + PR #512) | docs only, ✓ |
| **Q5.2** | CI invariant test `tests/agents/lead_agent/test_l2_cap_invariant.py` | ~80 LOC + tests |
| **Q5.3** | Move `scan_sqli_sqlmap`, `scan_xss_dalfox`, `scan_smuggling_smuggler` from L2 to `anchor_prepass._ANCHORS_WEB / _ANCHORS_API`. Re-run iter-37.12 baseline. | ~150 LOC |
| **Q5.4** | Move `fingerprint_services_nmap`, `probe_hosts_httpx`, `tls_audit`, `scan_nuclei_templates` from L2 to `_ANCHORS_IP`. | ~100 LOC + IP bench |
| **Q5.5** | Move `enumerate_subdomains_subfinder`, `scan_dns_hygiene_checkdmarc`, `scan_typosquats_dnstwist`, `scan_nuclei_templates`, `domain_recon_pipeline` from L2 to `_ANCHORS_DOMAIN`. Move `map_graphql_inql` to `_ANCHORS_API`. | ~120 LOC |
| **Q5.6** | New tool `get_finding(id)` | ~50 LOC + 5 tests |
| **Q5.7** | New tool `query_threat_intel` — collapses `cve_lookup` + `nvd_lookup` + `cve_intel_search` + `kev_diff_check`. 24h cache. | ~400 LOC + 20 tests |
| **Q5.7a** | Extend `query_threat_intel(domain=...)` for passive DNS / WHOIS / reputation | ~150 LOC + 10 tests |
| **Q5.8** | New tool `lookup_compliance_mapping` + versioned compliance corpus + cron refresher | ~250 LOC + 15 tests |
| **Q5.9** | New tool `rescan(tool_name, target, captured_state)` with allow-list + 5-call/scan cap | ~200 LOC + 15 tests |
| **Q5.10** | Collapse `scan_idor` + `scan_auth_flow` + `scan_business_logic` under `dispatch_l2_probe(kind, **kwargs)` | ~150 LOC + 15 tests |
| **Q5.11** | Extend `create_vulnerability_report` with `chain_summary` + `customer_priority` parameters. Drop the originally-planned standalone `propose_chain` + `prioritize_findings` tools from the plan. | ~100 LOC + 10 tests |
| **Q5.11a** | Split `create_vulnerability_report` 21→7 parameters (required-to-commit vs render-on-finish) — render-on-finish fields auto-generated at `finish_scan` from finding context | ~150 LOC + 15 tests |
| **Q5.11b** | Add `severity="observation"` shape to `create_vulnerability_report` for inconclusive partial signals | ~50 LOC + 5 tests |
| **Q5.12** | Add per-asset docstring to `terminal_execute`. Add `terminal_execute` to domain catalog (was missing) | ~20 LOC + 5 tests |
| **Q5.13** | Per-scan customer-context config passed via `system_prompt_context` — `industry`, `compliance_targets`, `critical_assets`, `threat_model`. Document in CLAUDE.md §1.5. | ~80 LOC + 10 tests + docs |
| **Q5.14** | New tool `get_recon_artifact(kind, name=None)` — persists prepass artifacts to `<run_dir>/recon/` + lets lead read them | ~150 LOC + 10 tests |
| **Q5.15** | Drop `think` from catalog. Either remove entirely OR thin-wrap to persist into `run_summary.lead_reasoning_trace[]`. | ~30 LOC + 5 tests |
| **Q5.16** | Update `docs/tool-catalog-rationalization.md` + CLAUDE.md §1.5.8 to reflect shipped reality | docs only |
| **Q5.17** | Re-run L1 parity benches (Q3.2–Q3.7) to confirm prepass migration didn't drop detection | bench run |
| **Q5.18** | Re-run `bench_l2_juiceshop_full.py` to confirm L2-audience metrics (`bench_context`, `bench_explanation`, `bench_chains`, `bench_severity`) improve with the new catalog | bench run |
| **Q5.19** *(conditional)* | Q3 parity bench `taint_analysis` vs. `semgrep --config p/python`. If semgrep wins, retire `taint_analysis`, replace in prepass. | ~150 LOC + fixture |
| **Q5.20** *(conditional, after Q5.14)* | Empirical 10 vs. 11 catalog-size bench (resolve Gap 2 cap pressure) | bench harness |

**Q5.2 ships before Q5.3–Q5.5** so the CI invariant is in place before catalog moves land. **Q5.17 + Q5.18 are gating benches** — no Q5.x merges if either regresses.

---

## 9. Risks + mitigations

| Risk | Mitigation |
|---|---|
| Moving deep-exploit tools to prepass = more deterministic L1 runtime cost (every scan fires sqlmap / dalfox / hydra) | Prepass dispatcher already conditions on iter-30 candidate signals. Unconditional sweep is bounded; cost is acceptable per iter-37.12 baseline. |
| L2 loses ability to fire sqlmap/dalfox on demand for an endpoint prepass missed | `rescan(tool_name=..., target=..., captured_state=...)` is the escape hatch. Allow-list keeps it safe. |
| `query_threat_intel` rate-limits hit on NVD / EPSS APIs in CI bench runs | 24h cache + fixture mode for benches (load from local snapshot). Q3 parity bench already uses this pattern. |
| `lookup_compliance_mapping` corpus drift — frameworks update yearly | Cron pager (like Vulhub corpus iter-Q1.3) flags when corpus is >90d stale. |
| `rescan` lets the LLM amplify a destructive scan | Validate `tool_name` against allow-list; cap rescans/scan at 5 (iter-29.9 destructive-guard pattern). |
| Dropping `think` confuses model trained to expect a scratchpad | Replace with system-prompt directive ("reason in your response text; tools are for external action"). Bench impact measured via `bench_explanation`. |
| Collapsing 3 L2 probes into `dispatch_l2_probe(kind=...)` loses per-probe docstrings | Umbrella tool's docstring enumerates each `kind` with its own kwargs list — same information surface, one slot. |
| L2-CAP invariant gets quietly violated again next iter | CI test `tests/agents/lead_agent/test_l2_cap_invariant.py` (Q5.2) blocks any PR pushing any asset's catalog over 10. |
| `get_recon_artifact` pushes web/api/repo to 11 | Q5.20 empirical bench measures degradation. If material, fall back to option (a) — collapse all READ STATE under a `read_state(kind, ...)` umbrella. |
| Customer-context config (Gap 1) doesn't reach the LLM reliably | Render into system prompt at every turn (same path as SecurityContext re-render in `llm.py:496`); tests pin the prompt-section presence. |
| Per the L2 tool audit, `taint_analysis` is in-house SAST (CLAUDE.md §11.1 violation) | Q5.19 parity bench against semgrep. If semgrep wins, deprecate. |

---

## 10. Acceptance criteria

1. `tests/agents/lead_agent/test_l2_cap_invariant.py` passes for every registered asset type (every asset ≤ 10).
2. `bench_owasp_benchmark.py` Youden index does NOT regress vs. the pre-Q5 baseline. (Prepass migration of deep-exploit tools should not change L1 recall — they just change WHERE the tool fires.)
3. `bench_l2_juiceshop_full.py` `completion_rate` does NOT regress vs. the iter-37.14 baseline.
4. Q3 parity benches (Q3.2–Q3.7) stay GREEN after the prepass migration.
5. `bench_chains.py` `chain_detection_rate` **improves** after Q5.11 ships (`chain_summary` parameter encourages explicit chain commitment).
6. `bench_severity.py` `severity_tier_accuracy` improves after Q5.11 ships (`customer_priority` separated from intrinsic `severity`).
7. `bench_context.py` `actionable_rate` improves after Q5.11a (21→7 parameter split — render-on-finish auto-fills fields the lead used to leave empty).
8. Every emitted CV-report carries `query_threat_intel`-sourced KEV/EPSS metadata in its description (verified by a new `bench_threat_intel_freshness` scorer — added in Q5.7).

Criteria 2–4 are **non-regression gates** (L1-audience artifact must stay constant). Criteria 5–8 are **value-capture gates** (L2-audience artifact should improve).

---

## 11. Connection to other Q-tracks

* **Q1** (`bench_owasp_benchmark.py` et al.) — non-regression gate.
* **Q2** (stratified compaction) — Q5 directly trims the tool-catalog section of the system prompt. Q2.3 (progressive tool disclosure) can be deprioritized once Q5 ships: with ≤10 tools, the progressive-disclosure savings are marginal.
* **Q3** (L1 parity) — Q5's deep-exploit moves to prepass *increase* the surface Q3 must measure. Q3 parity benches for sqlmap / dalfox / hydra / ffuf / smuggler / nmap / httpx / nuclei become load-bearing for Q5's non-regression gate.
* **Q4** (lead-loop parallelism) — should land AFTER Q5. With ≤10 tools per turn, parallel-dispatch decisions are simpler. Q5.20 is the natural home for the 10-vs-11 empirical bench Q4 needs.

---

## 12. Success criterion

> By the end of Q5.18, every L2 asset-type catalog is ≤ 10 tools and composed entirely of READ STATE + FETCH EXTERNAL + RE-DISPATCH + COMMIT/PRIMITIVE tools — no tool exists for "the LLM to do reasoning it could do in response text." Every CV-report carries threat-intel and compliance fields populated by scan-time fetches (not by training-data recall). Customer-context input lets the lead make customer-priority decisions on real signal, not a guess. A CI invariant blocks any future PR that pushes any asset's catalog over the cap or re-introduces a reasoning-shaped tool.

This is the L2 catalog you'd build if you started today, knowing what L1 and L1.5 already do, and treating tools as the LLM's hands rather than its brain. The L1 audience (security team) keeps full L1 detection coverage via the prepass migration. The L2 audience (developers, PMs) gets an AI security engineer with current threat-intel, current compliance mappings, customer-aware priorities, and chain narratives written for the audience that has to act on them.

---

## Appendix A — what we deliberately don't ship

For future Claude turns reading this doc, these tools were considered and rejected:

| Tool | Why not |
|---|---|
| `think()` | No-op echo. LLM thinks in response text. |
| `propose_chain(finding_ids, narrative)` | Chain narrative IS the response. Commit via `create_vulnerability_report.chain_summary`. |
| `prioritize_findings(customer_context)` | Customer ranking IS the response. Commit via `create_vulnerability_report.customer_priority`. |
| `explain_finding_for_developer(id)` | Plain-English explanation IS the response. Commit via `create_vulnerability_report.description_plain` (auto-generated post-Q5.11a). |
| `map_to_compliance_control(id)` | Use `lookup_compliance_mapping` to fetch current control IDs; the mapping decision IS the response. |
| `assemble_chain_narrative(ids)` | Narrative IS the response. Commit via `create_vulnerability_report.chain_summary`. |
| `generate_remediation_diff(id)` | Diff IS the response. Commit via `create_vulnerability_report.recommended_action` (render-on-finish, post-Q5.11a). |
| Per-asset variants of the L2-native probes (`scan_idor_web`, `scan_idor_api`, …) | Folded under `dispatch_l2_probe(kind=...)`. |
| Per-CVE-source wrappers (`cve_lookup`, `nvd_lookup`, `cve_intel_search`, `kev_diff_check` as separate L2 tools) | Folded under `query_threat_intel`. |

Every entry above failed one of two tests: (a) it's reasoning the LLM can do in its response, or (b) it duplicates a slot that's better filled by an umbrella tool with a `kind`/`source` parameter.

---

## Appendix B — historical companion docs

* `docs/proposals/2026-05-27-l2-from-first-principles.md` — the first-principles framing, now folded in here. Kept for historical context.
* `docs/proposals/2026-05-27-l2-tool-audit.md` — per-tool audit (read each tool's implementation, judge fit). Informs §4 and §7.
* `docs/proposals/2026-05-27-benchmark-suite-strategy.md` (Q1) — non-regression bench framework.
* `docs/proposals/2026-05-27-l1-parity-measurement.md` (Q3) — load-bearing measurement for the prepass-migration claim.
