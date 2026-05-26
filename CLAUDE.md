# CLAUDE.md — Architecture notes for the strix codebase

This file is loaded into every Claude turn working on this repo.
**Read this before proposing architectural changes.**

When you change something architectural, **update this file in the same PR**
so future turns see the new layout.

---

## 1. Repository identity

This is a fork of `usestrix/strix` maintained at `ClatTribe/strix`. Paired
with `ClatTribe/webappsec` (a wrapper that consumes strix outputs). Direct
push to `main` is blocked — **always ship via PR**.

**Roles:** strix is the agentic pentest engine. webappsec is the SaaS
wrapper that calls strix, persists findings, renders the dashboard.

---

## 2. The detection layer model (L0 → L3)

Mental model for every iter. When proposing a change, name the layer
it lives in:

| Layer | What runs | Where |
|---|---|---|
| **L0** | OSS signature corpora (nuclei templates, semgrep rules, sqlmap payload corpus, KEV CVE list, Bandit) | Sandbox container |
| **L1** | Deterministic specialist tools (`scan_sqli`, `scan_xss`, `scan_idor`, `csrf_check`, etc.) — pattern-driven, no LLM | Sandbox container |
| **L1.5** | Enrichment hooks: `pre_emission_fp_filter`, `corroborator_ledger`, `mid_scan_correlate`, `surface_priority`, `exploitability`, `git_blame`, `hygiene`, `post_emit_verifier` | **Host process** (around tracer.add_vulnerability_report) |
| **L2** | LLM-driven Lead agent — orchestrates L0+L1, reasons about findings, drives chain exploitation | Host process drives sandbox tool calls |
| **L2.5** | PoC verifier (iter-29.5 `verify_finding`), diff verifier (iter-29.2 `fire_and_diff`), benign-control payloads (iter-30.5) | Mixed — verifier orchestration on host, HTTP fires through sandbox |
| **L3** | Portfolio-level (cross-scan dedup, multi-target correlation) | Not yet built |

Targets: docs/metrics.md §2 has per-layer targets.
Roadmap: docs/metrics-roadmap.md (last updated 2026-05-25 — Wave 1-3 shipped).

---

## 3. The host vs sandbox boundary — CRITICAL

**This is the part I keep getting wrong. Read carefully.**

### 3.1 The two execution contexts

- **Host process** — the strix python entry point. Runs on the user's
  machine. Orchestrates everything. Has limited capabilities by design
  (no katana/nuclei/sqlmap/feroxbuster binaries assumed present).
- **Sandbox container** — `strix-sandbox:local` docker image. Has every
  security tool binary installed. Exposes an HTTP tool-server on a
  per-scan port (`tool_server_port` in `sandbox_info`). All security
  tooling SHOULD execute here.

### 3.2 The execution adapter

| File | Role |
|---|---|
| `strix/tools/executor.py:49` `execute_tool()` | **The dispatcher**. Reads tool's `sandbox_execution=True/False` flag at registration; if True + agent has sandbox_id, routes via HTTP POST to sandbox tool-server. |
| `strix/tools/executor.py:59` `_execute_tool_in_sandbox()` | HTTP client. Builds POST `{sandbox_url}/execute` with Bearer token from `agent_state.sandbox_token`. |
| `strix/tools/executor.py:121` `_execute_tool_locally()` | Fallback — imports the tool module + calls directly in host process. Subprocess in the tool runs on HOST. |
| `strix/runtime/docker_runtime.py` `create_sandbox()` / `destroy_sandbox()` | Container lifecycle. Returns `SandboxInfo` with `api_url`, `auth_token`, `tool_server_port`. |
| `strix/runtime/tool_server.py` | The HTTP API that runs INSIDE the sandbox container. Receives `/execute` POSTs, runs the tool, returns result. |

### 3.3 The `@register_tool` decorator + sandbox flag

Every tool registers with `@register_tool(sandbox_execution=...)`. **Default is `sandbox_execution=True`**. Opt-out only for framework-only tools (e.g. `generate_remediation_plan` which is pure LLM-side).

```python
# Example: strix/tools/katana_runner/crawl_with_katana.py:47
@register_tool(
    sandbox_execution=True,        # ← This is what matters
    mitre_techniques=["T1595.002"],
)
def crawl_with_katana(target_url: str, ...): ...
```

When the host agent calls `execute_tool("crawl_with_katana", ...)`:
1. Executor sees `sandbox_execution=True`
2. POSTs to sandbox `/execute` with `{tool_name, kwargs}`
3. Sandbox's `tool_server` receives, imports tool, calls it
4. The `subprocess.run(["katana", ...])` inside the tool fires **in the sandbox container**, not on the host
5. Result returned via HTTP

**Important:** subprocess.run inside a `@register_tool(sandbox_execution=True)` function is FINE — it runs in the sandbox. The host-side concern is only when the subprocess runs OUTSIDE this dispatch path.

### 3.4 The `agent_state` plumbing

`agent_state` is the bag passed around carrying:
- `sandbox_id` (docker container ID)
- `sandbox_token` (bearer for tool_server auth)
- `sandbox_info` (dict with `tool_server_port`, etc.)

Set by `StrixAgent._initialize_sandbox_and_state()` (`strix_agent.py:237`)
**before** the OSS prepass runs. Every subsequent `execute_tool` call
must pass `agent_state` so the executor knows where the sandbox is.

### 3.5 The anchor prepass execution context

`run_oss_anchor_prepass()` (`strix/agents/lead_agent/anchor_prepass.py:3833`)
runs **on the host** but dispatches every L1 anchor tool through
`execute_tool()` (and therefore through the sandbox). The prepass itself
is host-side orchestration; the tools fire in sandbox.

```
Host process:
  StrixAgent.execute_scan
    └─ run_oss_anchor_prepass             ← host
         └─ for anchor in _ANCHORS_WEB:
              └─ _run_one_tool             ← host
                   └─ execute_tool         ← host (HTTP client)
                        └─ [HTTP POST]
Sandbox container:
                            └─ tool_server.execute   ← sandbox
                                 └─ scan_sqli(...)    ← sandbox
                                      └─ subprocess.run(["sqlmap", ...])  ← sandbox
```

### 3.6 KNOWN host-side outliers in anchor_prepass.py

**These bypass the `execute_tool` adapter and run on the HOST.** They're
the source of the "iter-32.1 hooks don't fire" diagnostic gaps.

| Helper | Line | What it does | Why host-side (today) |
|---|---|---|---|
| `_katana_crawl` | 597 | shells `katana` on host PATH | Speed: avoids sandbox HTTP RTT in prepass |
| `_http_get` | 699 | `urllib.request.urlopen` from host | Speed |
| `_http_request` | 713 | `urllib.request.urlopen` from host | Speed |
| `probe_openapi_spec_exposed` | 727 | host HTTP via _http_get | Speed |
| `probe_jwt_none_alg` | 767 | host HTTP | Speed |
| `probe_mass_assignment_priv_fields` | 844 | host HTTP | Speed |
| `probe_unauth_debug_paths` | 946 | host HTTP | Speed |
| `probe_open_redirect` | 1060 | host HTTP | Speed |
| `probe_unauth_bola_path_params` | 1151 | host HTTP | Speed |
| `probe_directory_listing` | 1246 | host HTTP | Speed |
| `probe_open_tcp_ports` | 1514 | host socket | Speed |
| `probe_redis_no_auth` | 1539 | host socket | Speed |
| `probe_http_port` | 1585 | host urllib | Speed |
| `probe_ftp_anonymous` | 1701 | host ftplib | Speed |

**These should all be migrated to route through sandbox** (iter-35
candidate). Rationale: sandboxed network policy enforcement, internal-only
target reachability, telemetry consistency, iter-32.1 visibility hooks.

---

## 4. The telemetry plumbing (workflow_state, tracer)

These two are global singletons that L1/L1.5/L2 all write to and the
bench framework reads from.

### 4.1 `workflow_state` (`strix/agents/workflow_state.py`)

Process-singleton tracking the current scan's recon+phase state.
Public recorders:

| Recorder | Caller | Effect |
|---|---|---|
| `record_endpoint_discovered(url)` | Recon tools (katana, web_crawler, openapi_spec_ingest) | Adds to `endpoints_discovered` set; surfaced via `snapshot().endpoints_discovered_count` |
| `record_login_form_found(url)` | DOM-aware recon | Adds to `login_forms_found` list; gates iter-33.1 auth-retry |
| `record_progress(event, detail)` | Various | Pings `progress_watchdog` |
| `transition_phase(target_phase)` | Lead agent | Updates `current_phase`; fires iter-27.2 `correlate_at_phase_boundary` hook → iter-31.6 telemetry |
| `snapshot()` | tracer + bench scorers | Returns dict snapshot |

**iter-32.1 wiring**: `crawl_with_katana`, `web_crawler`, `openapi_spec_ingest`
call `record_endpoint_discovered`. **Anchor prepass host helpers
(`_katana_crawl`) do NOT.** That's the visibility gap.

### 4.2 `tracer` (`strix/telemetry/tracer.py`)

Process-singleton tracking findings + scan state. Key methods:

| Method | Effect |
|---|---|
| `add_vulnerability_report(...)` | Emit a finding. Runs L1.5 hook chain: FP filter → demote → root_cause_collapse → corroborator → post_emit_verifier (iter-32.4) → cross-tool merge → tracer.vulnerability_reports.append |
| `build_run_summary()` | Returns the run summary dict (read by bench scorers + run_summary.json) |
| `_collect_chains_emitted()` | iter-31.2 — scans vulnerability_reports for chain_summary blocks |
| `_build_*_summary()` | iter-31.5/6/7/9 — corroboration, phase_correlations, reproducibility_rate, surface_breadth rollups |

### 4.3 What the bench harness reads

Every iter-31.x bench scorer reads either:
- `run_summary.json` (via `tracer.build_run_summary()`) — for rollup metrics
- `vulnerabilities.json` (raw vulnerability_reports list) — for per-finding metrics

Both files live in `strix_runs/<run_id>/`.

---

## 5. The L1.5 hook chain — order matters

When `tracer.add_vulnerability_report(...)` is called, hooks fire in this
order. Each can mutate or drop the report:

```
1. pre_emission_fp_filter      → drops planted-decoy shapes, surfaces in l15_dismissals
2. fp_filter demote            → bumps severity down per rule
3. surface_priority            → annotates surface_priority block
4. exploitability              → annotates exploitability block + may bump severity
5. corroborator_ledger.check   → if cross-source agreement, attaches corroborated_by[]
6. post_emit_verifier          → iter-32.4 opt-in (STRIX_L15_POST_EMIT_VERIFY=1) — re-fires fire_and_diff to upgrade pattern_match → verified
7. _maybe_merge_into_existing_finding  → cross-tool dedup
8. tracer.vulnerability_reports.append
```

If you add a new hook, **append it to this list in CLAUDE.md** so the
order is documented.

---

## 6. The bench framework (iter-31 series)

11 bench scorers in `benchmarks/per_target/bench_*.py`. Each reads the
canonical run output + computes one metric:

| Bench | Metric | Reads |
|---|---|---|
| bench_fp_suppression | fp_rate, dismissal_accuracy | `run_summary.l15_dismissals` + fixture `expected_dismissed[]` |
| bench_chains | chain_detection_rate, chain_depth_p95 | `run_summary.chains_emitted` + fixture `expected_chains[]` |
| bench_severity | severity_tier_accuracy | per-finding `severity` + fixture `expected_findings[].severity` |
| bench_corroboration | corroboration_rate | `run_summary.corroborations[]` |
| bench_phase_correlate | phase_correlate_emissions | `run_summary.phase_correlations[]` |
| bench_reproducibility | reproducibility_rate | `run_summary.reproducibility_by_tier` |
| bench_context | context_completeness, actionable_rate | per-finding fields (file/line/author/fix_hint/exploit_vector) |
| bench_surface | surface_discovery_breadth | `run_summary.endpoints_discovered_total` + fixture `expected_endpoint_count` |
| bench_novel | novel_finding_rate | per-finding rule_id prefix + discovery_method.primary |
| bench_explanation | explanation_clarity | per-finding description (heuristic or LLM-as-judge) |
| bench_patcher_correctness | patch_correctness | `run_summary.patches_by_status` |

**Anti-overfit guard**: every bench has a source-grep test forbidding
SUT-specific identifiers (juice-shop, bkimminich, vampi, erev0s, etc.)
in its source. If you add a new bench, include this guard.

---

## 7. The L2 bench harness (juice shop full)

`benchmarks/per_target/bench_l2_juiceshop_full.py` spawns the strix CLI
as a subprocess, scans http://host.docker.internal:3001, then scores
against the `/api/Challenges` endpoint Juice Shop exposes.

**Required env vars** (set in `~/.zshenv`):
- `STRIX_LLM=gemini/gemini-3.5-flash` (or whatever model you're testing)
- `LLM_API_KEY=AIza...` (treat as compromised after the conversation
  that referenced it — rotate before public posting)

**Opt-in flags for full feature stack**:
- `STRIX_L15_POST_EMIT_VERIFY=1` — iter-32.4 post-emit verifier
- `STRIX_DISPATCH_CONCURRENCY=4` — iter-33.2 parallel dispatcher
- `STRIX_SKIP_CACHE_INIT=1` — speeds up sandbox boot

---

## 8. Iter sequence shipped this session (in order)

| iter | PR | what it did |
|---|---|---|
| 31.1 | #459 | FP suppression bench + L1.5 dismissal surfacing |
| 31.2 | #460 | Chain detection bench + chains_emitted rollup |
| 31.3 | #461 | Severity calibration bench |
| 31.5 | #462 | Corroboration rate bench + tracer rollup |
| 31.6 | #463 | Phase correlate emissions bench |
| 31.7 | #464 | Reproducibility rate bench |
| 31.8 | #465 | Context completeness + actionable rate |
| 31.9 | #466 | Surface discovery breadth bench |
| 31.10 | #467 | Novel finding rate bench |
| 31.12 | #468 | Explanation clarity bench (heuristic + LLM-as-judge) |
| 31.11 | #469 | Patcher correctness bench |
| docs | #470 | metrics-roadmap shipped-status update |
| 32.1 | #471 | Recon tools record endpoints to workflow_state |
| 30.5 | #472 | Shape-aware benign control payload for POST baselines |
| 32.2 | #473 | Recon-first directive in Lead system prompt |
| 32.3 | #474 | context_completeness handles missing-by-design dimensions |
| 32.4 | #475 | Post-emission verifier (opt-in via env) |
| 33.1 | #476 | Auth-first deterministic re-attempt on login forms |
| 33.2 | #477 | Parallel specialist dispatch |
| 33.3 | #478 | Heuristic shape-based chain linkers |
| 33.4 | #479 | Chain re-prompting on chain promotion |

---

## 9. Known open gaps (proposed iters)

| iter | gap | scope |
|---|---|---|
| **iter-35.1** | `_katana_crawl` host-side bypasses iter-32.1 hook | 5-line fix: call `record_endpoint_discovered` |
| **iter-35.2** | All `probe_*` helpers in anchor_prepass.py use host-side urllib | Larger: route through sandbox HTTP client OR add workflow_state hooks |
| **iter-35.3** | Anchor sequence missing `crawl_with_katana` / `webapp_recon_pipeline` | Add registered recon tools to `_ANCHORS_WEB` |
| **iter-36** | Bench harness measures via subprocess strix CLI — multi-run averaging missing | Run N=5, report median + p10/p90 |
| **iter-37** | Cost optimization: model-tier routing (cheap for recon, premium for chains) | Wire model selection per phase |

---

## 10. Things I've gotten wrong before

Updating this list when I make a mistake:

- **Treated `_katana_crawl` (host helper) as equivalent to `crawl_with_katana` (registered tool).** They're different code paths. The tool routes through sandbox; the helper doesn't.
- **Assumed phase gates were enforced.** `allowed_tools_for_phase()` is advisory, not enforcing. Tools the agent isn't supposed to call in a phase are still callable.
- **Wrote system-prompt directives expecting the LLM to follow them.** Gemini Flash on 10-min budget often ignores them. Better path: hard pipeline enforcement OR better model.
- **Assumed the L2 bench's `endpoints_discovered_total=0` meant recon didn't run.** Recon DID run (host-side `_katana_crawl`); telemetry recording was the gap.

---

## 11. Coding conventions

- Anti-overfit guards on every new bench: source-grep test forbidding SUT identifiers
- Iter naming: `iter-XX.Y` in commit messages, in `_RECON_FIRST_DIRECTIVE`-style comments, and in test file names
- Tests: regression check existing tests before merging (the iter-31 anti-pattern was shipping 4 PRs without re-running prior tests)
- PRs: squash-merge via `gh pr merge <N> --squash --delete-branch`
- Always update CLAUDE.md when architecture changes

### 11.1 No new in-house detection engines (iter-37.x policy)

Strix is **an LLM orchestrator over community-maintained OSS security tools**, not a vulnerability-detection company. Per `docs/tool-catalog-rationalization.md`:

**When adding a new vulnerability category to detect:**

1. Identify the leading OSS tool for that category (nuclei templates first, then specialized tools)
2. Add a `*_runner` wrapper following the existing pattern in `strix/tools/*_runner/`
3. Route through `scan_nuclei_templates` (with the appropriate `tags:` filter) first if a nuclei template exists
4. Register with `@register_tool(sandbox_execution=True)` — OSS tools run in the sandbox container

**In-house tools are reserved for LLM-orchestration logic only:**

- Chain reasoning (`correlate_findings`, `mid_scan_correlate`)
- Multi-session authz (`scan_idor` — absorbs BOLA, BFLA, multi-role)
- Auth flow orchestration (`scan_auth_flow`, `seed_auth`)
- Business-logic detection (`scan_business_logic` — LLM-led app-specific reasoning)
- Generic primitives (`probe_endpoint`, `send_request`, `browser_action`)
- Framework / state mgmt (workflow, notes, findings, threat-intel)

**Adding a new in-house `scan_*` detection scanner is forbidden without an explicit architectural ADR explaining why the leading OSS tool doesn't suffice.**

## 12. iter-37 — the OSS-orchestrator migration (in flight)

| iter | what | PR | status |
|---|---|---|---|
| 37.1 | Audit doc `docs/tool-catalog-rationalization.md` | #483 | ✓ shipped |
| 37.2 | Per-asset minimal catalog filter (default ON) — web 99 → 42 tools | #484 | ✓ shipped |
| 37.3 | Deprecation registry (`strix/tools/deprecations.py`) — 50+ tools warn-on-call | #485 | ✓ shipped |
| 37.7 | CLAUDE.md decision rule + iter-37 status table | #486 | ✓ shipped |
| 37.8 | Minimal CORE tools (32 → 13) | #487 | ✓ shipped |
| 37.9 | Update 24 specialist tests to set STRIX_LEGACY_CATALOG=1 | #488 | ✓ shipped |
| 37.10 | Minimal CORE 13 → 5; auto-fire compliance + remediation in finish_scan | #489 | ✓ shipped |
| 37.11 | Per-asset trim to ACT-only (drop prepass dupes — katana, nuclei, openapi_ingest, …) | — | in flight |
| 37.12 | Bench L2 Juice Shop with iter-37.10 + 37.11 trimmed catalog | — | pending |
| 37.4 | Add 6 NEW OSS wrappers: smuggler.py, SAML Raider, hydra, mobsfscan, ffuf, schemathesis | — | pending |
| 37.5 | DELETE the deprecated tools after grace period | — | pending |
| 37.6 | Re-bench L2 Juice Shop with minimal catalog active (superseded by 37.12) | — | superseded |

**Default for the L2 Lead today** (post iter-37.11): minimal ACT-only catalog. The agent sees ~10 tools per web target (5 core + 5 specialist), all of them OSS-backed deep-exploit or LLM-orchestration logic. Recon + broad-orient (katana, nuclei, openapi_ingest, semgrep, trivy, …) fire deterministically in `anchor_prepass.py` — the LLM only sees ACT-stage tools. Set `STRIX_LEGACY_CATALOG=1` to restore the pre-iter-37.2 99-tool catalog for backwards-compat.

**Per-asset specialist sets (post iter-37.11):**

| Asset | Specialist tools | Total catalog |
|---|---|---|
| `web_application` | scan_sqli_sqlmap, scan_xss_dalfox, scan_idor, scan_auth_flow, send_request | 10 |
| `api` | scan_sqli_sqlmap, scan_idor, scan_auth_flow, map_graphql_inql, send_request | 10 |
| `repository` / `local_code` | build_code_map, taint_analysis, verify_credentials_trufflehog, terminal_execute | 9 |
| `container_image` | scan_image_dockle, terminal_execute | 7 |
| `ip_address` | fingerprint_services_nmap, probe_hosts_httpx, scan_nuclei_templates, tls_audit, send_request, terminal_execute | 11 |
| `domain` | domain_recon_pipeline, enumerate_subdomains_subfinder, scan_nuclei_templates, scan_dns_hygiene_checkdmarc, scan_typosquats_dnstwist, send_request | 11 |

`ip_address` and `domain` keep recon tools in catalog because their prepass coverage is thin (IP) or absent (domain).

**Minimal CORE (5 tools)** — one per OODA phase + terminate:
  * `workflow_status` — OBSERVE: where am I in the scan?
  * `list_pending_findings` — OBSERVE: what did L1 surface?
  * `think` — ORIENT: reasoning scratchpad
  * `create_vulnerability_report` — ACT: emit findings (upsert via `existing_report_id`)
  * `finish_scan` — terminate (auto-fires compliance + remediation artifacts)

**iter-37.10 also auto-fires terminal artifacts** inside `finish_scan` — `emit_compliance_evidence` and `generate_remediation_plan` no longer take catalog slots. Opt-out: `STRIX_FINISH_AUTO_ARTIFACTS=0`.

**Why the trim**: per the OODA loop, the OSS prepass (`anchor_prepass`) already handles OBSERVE+ORIENT deterministically — recon and broad-signature detection fire ~25 tools before the LLM wakes up. The L1.5 hook chain auto-handles threat-intel enrichment (`tracer.add_vulnerability_report` calls `threat_intel.enrich` at emission) and mid-scan correlation (`mid_scan_correlate.correlate_at_phase_boundary` at each phase transition). Tools that were in the catalog purely so the LLM could request work the harness already does are now hidden — fewer choices, less decision paralysis.

**Deprecated tools** (50+ as of iter-37.3) STILL EXECUTE when invoked directly (sandbox tool-server / tests / legacy mode). They emit a WARNING log with the OSS replacement hint. See `strix/tools/deprecations.py` for the central registry.
