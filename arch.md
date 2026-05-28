# arch.md — strix architecture overview

This document is the architecture map for strix's L1 + L1.5 + L2 detection
stack across all six asset types. It is the source of truth for "what tool
runs where, what filter applies, what the LLM sees, what we benchmark
against." Keep this updated when you change anchor lists, filter rules, or
L2 catalogs.

For deeper invariants (host vs sandbox boundary, the L1.5 hook order, the
≤12-tool cap), see [CLAUDE.md](CLAUDE.md).

---

## Table of contents

1. [Per-asset architecture matrix](#per-asset-architecture-matrix)
   - [web_application](#web_application--dast)
   - [api](#api--dast--spec-driven)
   - [repository / local_code](#repository--local_code--sast--sca)
   - [container_image](#container_image--image-scan)
   - [ip_address](#ip_address--network-scan)
   - [domain](#domain--asset-discovery--dns-hygiene)
2. [L1.5 hook chain](#l15-hook-chain)
3. [Sandbox → host findings propagation](#sandbox--host-findings-propagation)
4. [L2 OODA loop](#l2-ooda-loop)
5. [Detection layer model (L0 → L3)](#detection-layer-model-l0--l3)
6. [Host vs sandbox boundary](#host-vs-sandbox-boundary)
7. [Benchmark infrastructure](#benchmark-infrastructure)
8. [Workflow state machine](#workflow-state-machine)
9. [Anti-overfit + invariant gates](#anti-overfit--invariant-gates)
10. [The repeating pattern](#the-repeating-pattern)

---

## Per-asset architecture matrix

For each asset type: which OSS tools fire at L1, which filters apply before
those tools dispatch, which tools the L2 LLM sees, and what we measure
against.

### `web_application` — DAST

| Layer | Element | Detail |
|---|---|---|
| **L1 OSS tools** | Recon | **katana** (crawl), **webapp_recon_pipeline** (playwright SPA crawl), **openapi_spec_ingest**, **fingerprint_tech_stack** |
| | Deep exploit | **sqlmap** (sqlmap_runner), **dalfox** (XSS), **nuclei** (template corpus), **smuggler** (HTTP smuggling), **ffuf** (fuzz), **schemathesis** (API), **hydra** (default creds) |
| | DOM-aware | scan_xss, dom_xss_static_probe, scan_cache_deception, scan_websocket_auth, scan_prototype_pollution |
| | Hygiene | http_security_headers_audit, tls_audit, cors_deep_check, csrf_check, open_redirect_check |
| **L1 filtration (Q5.34i / Q5.34j / Q5.34k)** | Static asset drop | `.css`, `.png`, `.woff`, bundled JS — extension filter via `_FANOUT_SKIP_SHAPES = {"static"}` |
| | Destructive drop | `/admin/delete-*`, `/logout` — `_FANOUT_SKIP_CLASSES` |
| | Scope filter | Same host or subdomain only; off-host (twitter, CDN) dropped. `STRIX_ANCHOR_FANOUT_SCOPE_HOSTS=...` whitelists extras |
| | Shape dedup | `(host, path-shape, sorted-query-names)`; `/items/1` ≡ `/items/2` ≡ `/items/N` → `/items/:int`; UUID/hash/date placeholders too |
| | Login protection | `/login`, `/signin`, `/users/sign_in` → nuclei only (skip sqlmap to avoid lockout / CAPTCHA) |
| | Per-URL tool routing (Q5.34j) | sqlmap fires only on URLs with SQL-like params; dalfox on URLs with text params; open_redirect on URLs with `url=`/`redirect=`; nuclei always |
| **L1.5 enrichment** | (cross-asset, see below) | FP filter → surface_priority → exploitability → corroborator → post_emit_verifier → cross-tool merge → tracer |
| **L2 catalog (≤12 per Q5.14)** | READ STATE (4) | `workflow_status`, `list_pending_findings`, `get_finding`, `get_recon_artifact` |
| | FETCH EXTERNAL (2) | `query_threat_intel`, `lookup_compliance_mapping` |
| | RE-DISPATCH (2) | `rescan` (re-fire L1 OSS), `dispatch_l2_probe` (kind ∈ {idor, auth_flow, business_logic}) |
| | ORIENT (1) | `think` (persists to `run_summary.lead_reasoning_trace[]`) |
| | COMMIT (2) | `create_vulnerability_report` (with `chain_summary` + `customer_priority` params), `finish_scan` |
| | PRIMITIVES (1) | `send_request` (escape hatch) |
| **Bench** | Headline | `bench_wavsep.py` (1,133 cases, iter-Q5.34) |
| | Comparator | Acunetix 87% / Netsparker 87% / Burp Active 78% / HP WebInspect 76% / IBM AppScan 69% / ZAP 56% (Shay Chen WAVSEP, sectoolmarket.com) |
| **Status** | | ✓ filtration shipped (Q5.34g/h/i/j/k); WAVSEP bench live |

---

### `api` — DAST + spec-driven

| Layer | Element | Detail |
|---|---|---|
| **L1 OSS tools** | Recon | **openapi_spec_ingest**, fingerprint_tech_stack, discover_graphql_endpoints, sbom_extract |
| | Spec-driven fuzz | **schemathesis** (OpenAPI-driven), map_graphql_inql (GraphQL introspection) |
| | API specialists | scan_api_bola (OWASP API1), scan_api_bfla (API5), scan_api_mass_assignment (API3), scan_idor, scan_api_rate_limit, jwt_audit |
| | Broad signature | nuclei, scan_sqli, scan_xxe, scan_ssrf, scan_ssti, scan_path_traversal, scan_nosql_injection, scan_cmd_injection |
| **L1 filtration (Q5.40)** | Health endpoint drop | `/health`, `/metrics`, `/ping`, `/readyz`, `/version`, `/favicon.ico` |
| | Spec endpoint drop | `/swagger`, `/openapi.json`, `/v3/api-docs` |
| | Per-method routing | BOLA / IDOR → GET with `:id`; BFLA → POST/PUT/PATCH/DELETE; mass_assignment → POST/PUT/PATCH (no DELETE — nothing to mass-assign) |
| **L2 catalog** | Same shape as web | `dispatch_l2_probe(kind="business_logic")` is the API-specific re-dispatch |
| **Bench** | Headline | `bench_l1_only.py --fixture api/vampi` + `api/crapi` |
| | Comparator | No neutral leaderboard; closest: VAmPI / crAPI working-group writeups; Salt / Wallarm (commercial) |
| **Status** | | ✓ filtration shipped (Q5.40); needs **Q5.49 kiterunner** + **Q5.52 APIClarity** to close OSS gaps |

---

### `repository` / `local_code` — SAST + SCA

| Layer | Element | Detail |
|---|---|---|
| **L1 OSS tools** | SAST (pattern-match) | **semgrep** (Q5.32 lang-aware packs), **bandit** (Python), **mobsfscan** (Android/iOS) |
| | SCA (lockfiles) | **trivy fs**, planned: **grype** (Q5.47), osv-scanner |
| | Secrets | **gitleaks**, **trufflehog** |
| | IaC / Container Dockerfiles | **checkov**, **hadolint** |
| **L1 filtration** | Language detection (Q5.32 ✓) | semgrep packs chosen per language (`p/java` + `p/findsecbugs` + `p/cwe-top-25` for Java; `p/python` for Python; `p/javascript` + `p/nodejsscan` for JS; etc.) |
| | File-tree filter (Q5.41 — pending) | Skip `node_modules/`, `vendor/`, `.git/`, `__pycache__/`, `dist/`, `build/`, `*.min.js`, binaries > 5MB |
| **L2 catalog** | Specialists | `build_code_map`, `terminal_execute`; rest of catalog same as web |
| **Bench** | Headline | `bench_owasp_benchmark.py --target-type local_code` (2,740 cases, Q5.27) |
| | Comparator | **Veracode 51% / Checkmarx 47% / Fortify 35% / SonarQube 6%** (OWASP Benchmark v1.2 SAST leaderboard) |
| **Status** | | ✓ Q5.32 language packs. **Behind** pattern-match ceiling (~25%). Needs **Q5.35 CodeQL** (taint-flow) for Veracode/Checkmarx parity |

---

### `container_image` — Image scan

| Layer | Element | Detail |
|---|---|---|
| **L1 OSS tools** | CVE detection | **trivy image** (gold standard) |
| | Misconfig | **dockle** |
| | SBOM | trivy CycloneDX output (planned: **syft** Q5.48) |
| | Corroboration | (planned: **grype** Q5.47 — different CVE DB than trivy) |
| **L1 filtration (Q5.42)** | Base-layer skip (opt-in) | `--pkg-types library` (or env `STRIX_TRIVY_PKG_TYPES`) skips OS packages, surfacing only app-layer CVEs the operator can fix |
| | Unfixed-CVE drop (opt-in) | `--ignore-unfixed` (or env `STRIX_TRIVY_IGNORE_UNFIXED=1`) drops CVEs without an upstream patch |
| | Multi-arch pin (opt-in) | `--platform linux/amd64` (or env `STRIX_TRIVY_PLATFORM`) pins arch on a multi-arch manifest so the same CVE isn't double-reported |
| **L2 catalog** | Specialists | `scan_image_dockle`, `terminal_execute` |
| **Bench** | Headline | `bench_l1_only.py --fixture container/nginx-vuln` (needs flesh-out per Q5.61) |
| | Comparator | No neutral leaderboard; Trivy / Snyk Container / Anchore — self-published only |
| **Status** | | At-parity for CVE detection. Q5.42 base-skip ✓ shipped. Still wants Q5.47 grype corroboration + Q5.55 Anchore policy |

---

### `ip_address` — Network scan

| Layer | Element | Detail |
|---|---|---|
| **L1 OSS tools** | Port discovery | **nmap** (via fingerprint_services_nmap) |
| | HTTP probe | **httpx**, `probe_http_port` |
| | Service probes | `probe_redis_no_auth`, `probe_ftp_anonymous` |
| | Templates | **nuclei** (per-port tag-routed in Q5.43) |
| | TLS | **tls_audit** |
| **L1 filtration (Q5.43 ✓)** | Closed/filtered port skip | Only open ports get probed (nmap filters) |
| | Per-port nuclei tag-filter | 39 ports → service-specific tags. e.g. 22→`ssh,openssh`, 443→`https,tls,ssl,tech,default-login`, 3306→`mysql`, 6379→`redis`, 9200→`elastic,elasticsearch`, 27017→`mongodb` |
| | HTTP vs network URL form | `http(s)://host:port/` for HTTP ports; bare `host:port` for network templates |
| **L2 catalog** | Specialists | `send_request`, `terminal_execute` |
| **Bench** | Headline | `bench_l1_only.py --fixture ip/vulnerable-services` (+ Vulhub CVE recipes via Q5.30) |
| | Comparator | Tenable / Qualys / Rapid7 — no open scorecard |
| **Status** | | ✓ Q5.43 per-port routing. Behind Nessus on credentialed-scan (Q5.54). Needs **Q5.50 masscan** for large ranges |

---

### `domain` — Asset discovery + DNS hygiene

| Layer | Element | Detail |
|---|---|---|
| **L1 OSS tools** | Subdomain enum | **subfinder**, **bbot** (+ planned: **amass** Q5.45, **assetfinder**) |
| | DNS hygiene | **checkdmarc** (SPF/DKIM/DMARC/CAA/MTA-STS) |
| | Typosquats | **dnstwist** |
| | Pipeline | `domain_recon_pipeline` (orchestrates the above) |
| | Web hygiene | nuclei against `http(s)://<domain>` |
| **L1 filtration (Q5.44 — pending)** | Catch-all DNS skip | `*.x.com` resolving everywhere → suppress |
| | Child-asset pivot | Each active subdomain → spawn child `web_application` (if 80/443 open) or `ip_address` (otherwise) |
| **L2 catalog** | Specialists | `send_request`, `terminal_execute` |
| **Bench** | Headline | No fixture yet (gap per Q5.63) |
| | Comparator | subfinder vs amass vs assetfinder published rates — no neutral leaderboard |
| **Status** | | Behind on cert-transparency mining (Q5.46 crt.sh). Q5.44 pivot is the architectural unlock |

---

## L1.5 hook chain

Every asset shares the same enrichment pipeline. Hooks fire in this order
inside `tracer.add_vulnerability_report`:

```
1. pre_emission_fp_filter          → drops planted-decoy shapes; surfaces in l15_dismissals
2. fp_filter demote                → severity bumps per rule
3. surface_priority                → annotates surface_priority block
4. exploitability                  → annotates exploitability block; may bump severity
5. corroborator_ledger.check       → cross-source agreement → attaches corroborated_by[]
6. post_emit_verifier (Q5.32.4)    → re-fires fire_and_diff to upgrade pattern_match → verified
7. _maybe_merge_into_existing_finding → cross-tool dedup
8. tracer.vulnerability_reports.append
```

**Ablation**: `STRIX_L15_DISABLED=1` skips the entire chain. The delta vs.
the baseline at any asset's L1 bench is the L1.5 lift.

---

## Sandbox → host findings propagation

iter-35.4 + Q5.31 + Q5.34h built the cross-boundary plumbing. Without it,
sandbox-side tool calls to `tracer.add_vulnerability_report` would vanish
into a hookless sandbox-side tracer singleton.

```
sandbox tool calls tracer.add_vulnerability_report(...)
   ↓ (writes to sandbox tracer singleton)
sandbox tool_server snapshots vulnerability_reports diff post-call
   ↓ injects findings into ToolExecutionResponse.findings_emitted (Pydantic field)
[HTTP response]
host _execute_tool_in_sandbox
   ↓ extracts findings_emitted
   ↓ host_tracer.add_vulnerability_report(**filtered)   ← L1.5 hooks fire HERE
```

**Q5.34h list-shape findings bridge** — tools like dalfox/sqlmap return
findings in `result["findings"]` (not via tracer). The fan-out helper
bridges these to the host tracer with kwarg projection (`rule_id` →
`title`, `endpoint` from the URL kwarg, etc.).

---

## L2 OODA loop

The L2 Lead is the LLM agent. Its tool catalog maps directly onto OODA
buckets:

| OODA phase | Tools the LLM uses | What happens |
|---|---|---|
| **OBSERVE** | `workflow_status`, `list_pending_findings`, `get_finding`, `get_recon_artifact` | Read state outside conversation window — what phase am I in, what findings did L1 surface, what details on finding #N |
| **ORIENT** | `think` (persists to `lead_reasoning_trace[]`), `query_threat_intel`, `lookup_compliance_mapping` | Reason about prioritization, fetch external context (CVE/EPSS/KEV state, current SOC2/PCI control text) |
| **DECIDE** | (inline in LLM response — no tool) | Chain narrative + customer-priority decisions emit as **parameters** on `create_vulnerability_report`, not separate tools |
| **ACT** | `rescan(tool, target, state)`, `dispatch_l2_probe(kind=idor/auth_flow/business_logic, ...)`, `send_request`, `terminal_execute`, `create_vulnerability_report(chain_summary, customer_priority)`, `finish_scan` | Re-fire L1 OSS with new state (auth captured), dispatch L2-native probes, commit findings, terminate scan |

**The tool-existence principle** (CLAUDE.md §1.5.6): tools are the LLM's
hands, not its brain. A tool exists only when:

| Condition | Why a tool is needed |
|---|---|
| Real-time external data | LLM training cutoff is stale (CVE/EPSS/KEV state, vendor advisories) |
| Re-trigger a deterministic scan | LLM can't run subprocess / network I/O |
| Persistent side-effect | Committing a finding, advancing phase, terminating scan |
| Reading state outside conversation context | `workflow_status`, `list_pending_findings` |

Reasoning over data already in context, reformatting, and decisions
encoded inline in the response are **not** tools — those happen in the
LLM's response text. Reasoning **commits** (chain narrative, customer
priority) ride as parameters on `create_vulnerability_report`.

---

## Detection layer model (L0 → L3)

| Layer | What runs | Where | Refresh cadence |
|---|---|---|---|
| **L0** | OSS signature corpora — nuclei templates, semgrep rules, sqlmap payload corpus, KEV CVE list, Bandit | Sandbox | Cron-paged (`bench_vulhub_cve_corpus` pages at <90% KEV hit rate) |
| **L1** | Deterministic specialists — `anchor_prepass.py` orchestrates per-asset stack | Sandbox (every tool via `execute_tool` → tool_server) | Per-scan |
| **L1.5** | Enrichment hooks above | **Host** (around `tracer.add_vulnerability_report`) | Per-finding |
| **L2** | LLM Lead — `agent_loop` with the ≤12-tool catalog | Host drives sandbox tool calls | Per-scan, model-paced |
| **L2.5** | Verifier — `verify_finding`, `fire_and_diff`, benign-control payloads (Q5.34.4 / Q5.34.5) | Mixed | Per finding flagged for verification |
| **L3** | Portfolio-level (cross-scan dedup, multi-target correlation) | Host | Not yet built |

---

## Host vs sandbox boundary

CLAUDE.md §3 codifies this as the critical invariant. Strix tools run in
the sandbox; orchestration runs on the host.

| Concern | Host | Sandbox |
|---|---|---|
| Where strix CLI runs | ✓ | |
| Where `anchor_prepass` orchestration runs | ✓ | |
| Where `execute_tool` dispatches | ✓ (HTTP client) | ✓ (tool_server `/execute` endpoint) |
| Where OSS tool binaries live | (deprecated post-iter-35) | ✓ (`/opt/pipx/bin`, etc.) |
| Where katana / sqlmap / dalfox / nuclei / nmap / semgrep / trivy run | | ✓ (subprocess inside `@register_tool(sandbox_execution=True)`) |
| Where L1.5 hooks fire | ✓ | |
| Where workflow_state singleton lives | ✓ (host's singleton — sandbox's writes don't propagate; that's why fan-out reads endpoints from `tool_results.raw_result.endpoints` per Q5.34f) | (separate sandbox-side singleton — fresh each scan) |
| Where tracer lives | ✓ (with L1.5 hooks) | ✓ (hookless; findings shipped via sidecar) |

**Why this matters**: an L1 tool that calls `tracer.add_vulnerability_report`
from inside its body writes to the sandbox-side tracer (hookless). The
iter-35.4 sidecar + Q5.31 Pydantic field + Q5.34h list-shape bridge are
the three sequential fixes that get findings across the boundary.

---

## Benchmark infrastructure

| Asset | Bench | Headline metric | External comparison | Status |
|---|---|---|---|---|
| L0 | `bench_vulhub_cve_corpus.py` | KEV hit rate | n/a — cron pager | ✓ shipped |
| L1-SAST (`local_code`) | `bench_owasp_benchmark.py --target-type local_code` | Per-CWE Youden | Veracode 51%, Checkmarx 47%, Fortify 35%, SonarQube 6% | ✓ shipped (Q5.27/32/33) |
| L1-DAST (`web_application`) | `bench_wavsep.py` | Per-class Youden | Acunetix 87%, Netsparker 87%, Burp 78%, ZAP 56% | ✓ shipped (Q5.34) |
| L1-API (`api`) | `bench_l1_only.py --fixture api/vampi + api/crapi` | Must-find recall | None | Needs Q5.60 |
| L1-SCA (`local_code` lockfiles) | `bench_l1_only.py --fixture code/sca-*` | Must-find CVE recall | Snyk/Dependabot self-published | ✓ shipped |
| L1-container | `bench_l1_only.py --fixture container/nginx-vuln` | Must-find CVE recall | Trivy/Snyk/Anchore self-published | Needs Q5.61 flesh-out |
| L1-network | `bench_l1_only.py --fixture ip/vulnerable-services` | Must-find recall | Tenable/Qualys/Rapid7 — no scorecard | Needs Q5.62 |
| L1-recon | (none yet) | Subdomain enum rate | subfinder vs amass published | Needs Q5.63 |
| L1.5 (per asset) | Same harness + `STRIX_L15_DISABLED=1` | Δ-metric = L1.5 lift | Internal | ✓ shipped (Q1.4) |
| L2 | `bench_webgoat_dual.py` + `bench_l2_juiceshop_full.py` | (detection_rate, completion_rate) | None — internal attribution | ✓ shipped (Q1.2) |
| Multi-trial | `bench_multi_trial.py` | median + p10/p90 over N=5 | — | ✓ shipped (Q1.4) |

---

## Workflow state machine

`strix/agents/workflow_state.py` is a host-side singleton tracking the
current scan's phase + recon state:

| Phase | Entry condition | Exit condition |
|---|---|---|
| `recon` | scan start | endpoints discovered OR auth attempt fires |
| `auth_attempt` | login form found (`record_login_form_found`) | credentials captured OR all default-creds exhausted |
| `post_auth_recon` | auth captured | post-auth endpoints discovered |
| `probe` | endpoints surface complete | findings emitted on >50% endpoints OR budget exhausted |
| `chain` | ≥2 findings of compatible CWE classes | chain narrative emitted OR no compatible pair found |
| `done` | `finish_scan` called | terminal — auto-fires `emit_compliance_evidence` + `generate_remediation_plan` |

Phase transitions fire `mid_scan_correlate.correlate_at_phase_boundary`
(iter-31.6) → surfaces correlations across phases into
`run_summary.phase_correlations`.

---

## Anti-overfit + invariant gates

Test-pinned guards so a regression in the architecture breaks CI before
it ships:

| Gate | Where | What it pins |
|---|---|---|
| `test_l2_cap_invariant.py` | Lead agent | No asset's L2 catalog exceeds 12 tools |
| `test_owasp_benchmark_scoring.py::test_scoring_module_has_no_juiceshop_or_vampi_identifiers` | bench scoring | No SUT-specific identifiers in scoring math |
| `test_lang_packs_table_covers_advertised_languages` | semgrep | Every `_LANG_EXT_MAP` entry has a `_LANG_PACKS` entry |
| `test_port_to_tags_table_covers_common_ports` | IP routing | Every `_IP_COMMON_PORTS` entry has a `_IP_PORT_TO_NUCLEI_TAGS` entry |
| `test_fanout_specialist_list_is_narrow` | web fan-out | `_FANOUT_DEEP_SPECIALISTS_WEB` stays ≤ 6 tools |
| `test_render_report_includes_published_competitor_scores` | every L1 bench | Bench report cites neutral competitor numbers |
| `test_wavsep_categories_match_owasp_canonical_cwes` | bench scoring | sqli/xss/pathtraver CWE sets stay consistent between WAVSEP + OWASP Benchmark scorers |

---

## The repeating pattern

The pattern that recurs across the asset matrix:

> **L1 = OSS tool wrapping + per-asset filter + per-element routing →
> L1.5 enrichment → L2 LLM lead orchestrates over a ≤12-tool catalog
> tied to OODA.**

The asset types differ in *what gets filtered*:

| Asset | Filter dimension | Filter iter |
|---|---|---|
| web_application | URLs | Q5.34i/j/k |
| api | endpoints (method + path-shape) | Q5.40 |
| repository | files (extension + tree position) | Q5.41 (pending) |
| container_image | image layers | Q5.42 (shipped — opt-in pkg-types/unfixed/platform) |
| ip_address | open ports | Q5.43 |
| domain | subdomains | Q5.44 (pending) |

But the *shape* is identical — and the iter sequence Q5.40 / Q5.41 /
Q5.42 / Q5.43 / Q5.44 is just applying that shape to each asset's
specific filter dimension.

---

## Where to look in code

| File | Purpose |
|---|---|
| `strix/agents/lead_agent/anchor_prepass.py` | L1 orchestration; the master file. Contains `_ANCHORS_*` per-asset lists, `_run_dependent_*_tools` per-asset phase-2, fan-out helpers, all Q5.34/Q5.40/Q5.43 filters |
| `strix/tools/` | Per-tool wrappers (each `@register_tool(sandbox_execution=True)`) |
| `strix/runtime/tool_server.py` | Sandbox HTTP API. Hosts the tracer-snapshot + sidecar plumbing |
| `strix/runtime/docker_runtime.py` | Container lifecycle. `_get_or_create_container` is the (sometimes-troublesome) cache lookup |
| `strix/telemetry/tracer.py` | The tracer + L1.5 hook chain |
| `strix/agents/workflow_state.py` | Host-side phase + recon state singleton |
| `strix/l15/endpoint_classifier.py` | iter-29.1 `EndpointProfile` classifier used by Q5.34i + shape_aware_dispatcher |
| `strix/agents/lead_agent/shape_aware_dispatcher.py` | iter-30 pattern that Q5.34j routing now mirrors |
| `benchmarks/per_target/bench_*.py` | All bench harnesses |
| `CLAUDE.md` | The canonical architecture invariants (host/sandbox, ≤12-tool cap, tool existence principle) |
