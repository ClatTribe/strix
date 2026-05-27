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

## 1.5 Product goal — the L1 / L2 audience split

**This is the mental model. Read this before proposing architectural changes
that touch detection, enrichment, prioritization, or the user-facing output.**

strix produces **two distinct artifacts for two distinct audiences**, and
every iter PR should be locatable in this 2×2:

| Layer | Audience | Artifact | "Best-in-class" means |
|---|---|---|---|
| **L0+L1** (sandbox OSS scanners) | **Security team** (knows how to read raw scanner output) | Per-tool dashboard: every finding emitted by nuclei / sqlmap / dalfox / semgrep / trufflehog / ffuf / etc. — surfaced verbatim with severity, CWE, endpoint, rule_id. Maps to MITRE ATT&CK techniques per `@register_tool(mitre_techniques=[...])`. | strix's per-wrapper recall **equals the standalone OSS tool**. Q3 measures this. If we drop findings the OSS tool would have found, we have failed at L1, regardless of what L2 does next. |
| **L1.5+L2** (enrichment + LLM lead) | **Non-security team** (developers, PMs) — cannot triage raw scanner output | AI-security-engineer translation: prioritized list of *what to fix first*, *why it matters*, *which findings chain together*, *the remediation patch*, *the compliance evidence*. | The developer / PM reading this output knows what action to take, in what order, without consulting a human security engineer. L2 is the translator, not the detector. |

### 1.5.1 What each audience needs

**Security team (L1 audience):**
* Raw, complete, comparable scanner output.
* Per-tool MITRE technique attribution.
* Reproducibility (can re-run any scanner against the same target and verify).
* No silent demotions — if nuclei flagged it, they see it.

**Non-security team (L2 audience):**
* Prioritization (which 5 of the 50 findings actually matter for this app, today).
* Chain reasoning (this CSRF + this open redirect = account takeover).
* Plain-English remediation steps tied to the codebase.
* Compliance mapping (this finding affects SOC-2 / PCI-DSS / HIPAA control X).
* False-positive suppression at L1.5 — they do not need to filter info-severity noise.

### 1.5.2 What this means for every iter PR

* **L1 / L1.5 iter PRs** are scored on detection recall vs. the standalone OSS tool (Q3 parity bench) and FP/FN tradeoffs from the L1.5 hooks. Token economy is *not* the gate.
* **L2 iter PRs** are scored on the developer-facing output quality:
  * `bench_context.py` — finding has file/line/author/fix-hint/exploit-vector
  * `bench_explanation.py` — plain-English description a non-security reader can act on
  * `bench_patcher_correctness.py` — proposed remediation actually fixes the vuln
  * `bench_chains.py` — chain assembly the way a human pentester would tell the story
  * `bench_severity.py` — severity tier matches a security engineer's read

* **L2 PRs that improve developer-facing metrics but regress L1 recall are rejected.** L2 cannot translate findings L1 didn't surface.
* **L2 PRs that reduce token usage but regress L1 recall are rejected.** Same reason — Q2's `<1pp regression gate` against the Q3 parity baseline is the load-bearing check.

### 1.5.3 Why this matters for the codebase shape

* No new in-house detection scanners — CLAUDE.md §11.1 already codifies this; the L1 layer **only** wraps OSS tools, because that's the only way to be "best-in-class" at detection.
* The L1.5 hook chain (FP filter, surface_priority, exploitability, corroborator, post_emit_verifier) exists to **add information for L2's translation job**, not to mutate the L1 dashboard the security team sees. The L1 dashboard renders pre-L1.5 findings; L2's developer-facing output renders post-L1.5 findings.
* Severity demotions, dismissals, and merges from L1.5 must be **logged + recoverable** so the L1 audience can audit them. `run_summary.l15_dismissals[]` (iter-31.1) is this audit log.

### 1.5.4 strix vs. webappsec, in this framing

* **strix** produces both artifacts in one scan: `vulnerabilities.json` (the L1 dashboard) + `run_summary.json` (which carries the L2 narrative: chains, surface_priority, exploitability, phase correlations).
* **webappsec** is the SaaS wrapper that splits the audiences in the UI: a "Security Dashboard" view for the L1 audience and a "Developer Action List" view for the L2 audience, both backed by the same scan run.

### 1.5.5 The ≤12-tool cap (Invariant L2-CAP, post-Q5.14)

> **L2-CAP:** For every asset type, the number of tools visible to the L2 Lead at any point in the scan is **≤ 12** (originally ≤ 10, bumped via iter-Q5.8/9/14 to accommodate the FETCH EXTERNAL + RE-DISPATCH buckets without dropping `think`). Past ~12, LLM tool-use accuracy degrades steeply. **iter-Q5.20 will empirically measure 10-vs-12 degradation;** if material, the cap reverts to 10 by dropping think back out + collapsing READ STATE under an umbrella.

The cap counts **what the LLM sees in the system prompt** — the minimal CORE tools + the per-asset specialist set. It does **NOT** count:

* Tools that fire deterministically in `anchor_prepass` (the LLM never sees them — they're L1 always-on coverage).
* Tools that auto-fire inside `finish_scan` (compliance evidence, remediation plan — terminal artifacts).

A CI invariant test (`tests/agents/lead_agent/test_l2_cap_invariant.py`, ships in iter-Q5.2) gates any PR that raises any asset's catalog past the cap.

### 1.5.6 The tool-existence principle

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

**Concrete examples of the principle, applied:**

* `think()` — **wrong tool.** It's a no-op echo that returns char-count. The LLM can think in response text. If a reasoning audit trail is wanted, capture the `assistant_text` turns; don't synthesize a tool for it.
* `propose_chain(finding_ids, narrative)` — **wrong tool.** The chain narrative *is* the LLM's response. Commit chains via a `chain_summary` parameter on `create_vulnerability_report`, not a separate tool.
* `prioritize_findings(customer_context)` — **wrong tool.** The customer-context ranking *is* the LLM's response. Commit via a `customer_priority: int` parameter on `create_vulnerability_report`.
* `query_threat_intel(cve_id)` — **right tool.** LLM training data doesn't know whether CVE-2024-X was added to CISA KEV last week or whether EPSS moved this morning.
* `rescan(tool_name, target, captured_state)` — **right tool.** The LLM can't run subprocess. Re-firing `nuclei` against a newly authed endpoint requires the dispatcher.
* `create_vulnerability_report(...)` — **right tool.** Persistent side-effect to `tracer.vulnerability_reports`. System-of-record commit.

### 1.5.7 L2 tool taxonomy — 4 buckets (first-principles)

Every tool in the L2 catalog must fit one of these four buckets:

```
L2 catalog (≤ 10 tools per asset type)
├── READ STATE        (3 — universal across asset types)
│     workflow_status         — phase + endpoints + gates + next_actions
│     list_pending_findings   — L1.5-ranked findings ledger
│     get_finding(id)         — single-finding deep read companion
│
├── FETCH EXTERNAL    (2 — universal — currently EMPTY in the shipped catalog, ←  THE GAP)
│     query_threat_intel      — collapses cve_lookup + nvd_lookup + cve_intel_search
│                              + kev_diff_check. Returns CVSS + KEV + EPSS +
│                              advisories + exploit availability. 24h cache.
│     lookup_compliance_mapping — current SOC2/PCI/HIPAA control IDs from a
│                              versioned corpus refreshed on cron.
│
├── RE-DISPATCH       (1–2 per asset)
│     rescan(tool, target, state)         — re-fire an L1 OSS tool with new state
│     dispatch_l2_probe(kind, **kwargs)   — collapses scan_idor / scan_auth_flow /
│                              scan_business_logic under one umbrella
│                              (kind ∈ {idor, auth_flow, business_logic})
│     build_code_map (repo)               — file-system walk
│
└── COMMIT + PRIMITIVES  (2 commit + 1 primitive per asset)
      create_vulnerability_report — emits finding; carries chain_summary +
                                    customer_priority parameters (the REASONING
                                    work commits HERE, no separate tool needed)
      finish_scan                 — terminate; auto-fires compliance + remediation
      send_request                — escape hatch: arbitrary HTTP
      terminal_execute            — escape hatch: arbitrary shell (repo / IP / container)
```

**There is NO "REASONING" bucket.** Reasoning lives in the LLM's response text; reasoning *commits* (chains, customer priorities) ride as parameters on `create_vulnerability_report`.

**The rule for adding a new L2 tool:** name the bucket. If you can't — and especially if the proposed tool's job is "let the LLM declare a thought / plan / preference" — the work belongs in the LLM's response text, with the commit folded into an existing emission tool's parameter set. Tools that don't fit either belong in `anchor_prepass` (L1 detection) or as a terminal auto-artifact in `finish_scan`.

### 1.5.8 Per-asset L2 catalog (shipped reality, post-Q5.14)

Q5.1–Q5.15 all shipped this session. Current state:

| Asset | CORE (10) | Specialists | **Total** |
|---|---|---|---|
| `web_application` | workflow_status, list_pending_findings, get_finding, get_recon_artifact, query_threat_intel, lookup_compliance_mapping, rescan, think, create_vulnerability_report, finish_scan | dispatch_l2_probe, send_request | **12** |
| `api` | same | dispatch_l2_probe, send_request | **12** |
| `repository` / `local_code` | same | build_code_map, terminal_execute | **12** |
| `container_image` | same | scan_image_dockle, terminal_execute | **12** |
| `ip_address` | same | send_request, terminal_execute | **12** |
| `domain` | same | send_request, terminal_execute | **12** |

All 6 asset types at 12 (Invariant L2-CAP honored under the
post-Q5.14 cap). CI gate:
`tests/agents/lead_agent/test_l2_cap_invariant.py`.

Buckets per CLAUDE.md §1.5.7:
* **READ STATE** (4): workflow_status, list_pending_findings, get_finding, get_recon_artifact
* **FETCH EXTERNAL** (2): query_threat_intel (4-wrapper collapse), lookup_compliance_mapping
* **RE-DISPATCH** (2-3): rescan (L1 re-fire), dispatch_l2_probe (L2-native umbrella), build_code_map (repo only)
* **ORIENT** (1): think (Q5.15 — now persists to run_summary)
* **COMMIT** (2): create_vulnerability_report (with Q5.11 chain_summary + customer_priority params), finish_scan
* **PRIMITIVES** (1-2 per asset): send_request, terminal_execute

Plus per-scan **customer-context config** (Q5.13) — not a tool, rendered into `system_prompt_context.customer_context` from `scan_config["customer_context"]`. Allow-listed keys: industry, compliance_targets, critical_assets, threat_model, data_classifications, regulatory_jurisdiction.

### 1.5.9 What this catalog deliberately drops

The post-Q5 plan included `propose_chain` and `prioritize_findings` as standalone tools. Neither survives the first-principles filter:

| Tool | Why wrong | What replaces it |
|---|---|---|
| `propose_chain` | Chain narrative IS the LLM's response | `chain_summary` parameter on `create_vulnerability_report` (Q5.11) |
| `prioritize_findings` | Customer ranking IS the LLM's response | `customer_priority: int` parameter on `create_vulnerability_report` (Q5.11) |
| `taint_analysis` | In-house Python-only SAST (CLAUDE.md §11.1 violation) | semgrep in anchor_prepass |
| `verify_credentials_trufflehog` (catalog slot) | Verifier on top of secrets_scan — fits rescan pattern better | rescan(tool_name="verify_credentials_trufflehog", ...) (Q5.9) |
| scan_idor / scan_auth_flow / scan_business_logic (separate slots) | Collapsed | dispatch_l2_probe(kind, ...) (Q5.10) |
| cve_lookup / nvd_lookup / cve_intel_search / kev_diff_check (separate slots) | Collapsed | query_threat_intel(...) (Q5.7) |
| sqlmap / dalfox / smuggler / hydra / ffuf / schemathesis / nuclei / nmap / httpx / tls_audit / subfinder / checkdmarc / dnstwist / domain_recon_pipeline / map_graphql_inql | L1 detection, not L2 translation | All fire in anchor_prepass (Q5.3 / Q5.4 / Q5.5) |

`think` survives — pre-Q5.15 it was a no-op echo, but Q5.15 converted it to persist to `run_summary.lead_reasoning_trace[]`. The PERSISTENCE side-effect is a legitimate system-of-record commit; that's what makes it a real tool now.

**Historical journey:** pre-Q5 catalog = web=13, api=14, repo=10, container=7, ip=11, domain=11 (4/6 violated ≤10). Post-Q5.14 catalog = all 6 at 12 (with cap bumped from 10 to 12 to accommodate FETCH EXTERNAL + RE-DISPATCH buckets). Q5.20 will empirically measure 10-vs-12 degradation.

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

| Helper | Status | Notes |
|---|---|---|
| `_katana_crawl` | ✓ migrated (iter-35.1, #481) | Replaced by `crawl_with_katana` sandbox tool. |
| `probe_openapi_spec_exposed` | ✓ sandbox-routed (iter-35.2) | Wrapper in `strix/tools/anchor_probes/`. Host function body kept; the orchestrator dispatches via `_run_one_tool` so urllib I/O fires in sandbox. |
| `probe_jwt_none_alg` | ✓ sandbox-routed (iter-35.2) | Same pattern. |
| `probe_mass_assignment_priv_fields` | ✓ sandbox-routed (iter-35.2) | Same pattern. |
| `probe_unauth_debug_paths` | ✓ sandbox-routed (iter-35.2) | Same pattern. |
| `probe_open_redirect` | ✓ sandbox-routed (iter-35.2) | Same pattern. |
| `probe_unauth_bola_path_params` | ✓ sandbox-routed (iter-35.2) | Same pattern. |
| `probe_directory_listing` | ✓ sandbox-routed (iter-35.2) | Same pattern. |
| `probe_open_tcp_ports` | ✓ sandbox-routed (iter-35.2) | Socket sweep now in sandbox netns. |
| `probe_redis_no_auth` | ✓ sandbox-routed (iter-35.2) | Same pattern. |
| `probe_http_port` | ✓ sandbox-routed (iter-35.2) | Same pattern. |
| `probe_ftp_anonymous` | ✓ sandbox-routed (iter-35.2) | ftplib I/O now in sandbox. |
| `_http_get`, `_http_request` | host-only (private) | Internal helpers for the probe function bodies (which themselves run in sandbox via the wrappers). Not call-sites — pure utilities inside the probe implementations. |

**All previously host-side specialists are now sandbox-routed** (iter-35.5, PR #494):
* `scan_idor` (`sandbox_execution=True`) — runs inside the sandbox; reads session state from sandbox-side `SecurityContext.AuthState` (which `scan_auth_flow` populated earlier in the same sandbox process).
* `scan_auth_flow` (`sandbox_execution=True`) — captured auth states travel back to the host via `tool_metadata.auth_states_captured` + the iter-35.5 propagation hook in `strix/tools/executor.py:_propagate_auth_states_to_host`. The host's `SecurityContext.AuthState` is kept in sync so the L2 lead's per-turn system-prompt renderer sees the captured sessions.

**The CLAUDE.md §3 sandbox-only invariant is now fully enforced.** No L1 / L1.5 detection tools execute on the host process. The 5-tool minimal CORE is the only set that still runs host-side, and those are framework state-management tools with no network I/O by design (`workflow_status`, `list_pending_findings`, `think`, `create_vulnerability_report`, `finish_scan`).

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

### 5.1 Sandbox tools and the L1.5 chain (iter-35.4)

Tools running inside the sandbox container that called
`tracer.add_vulnerability_report` from inside their body were
historically writing to the **sandbox-side tracer singleton** — a
fresh, hookless instance with no L1.5 chain attached. Findings landed
in a dead store: trajectory.jsonl + run_summary.findings_summary
counted them, but `vulnerabilities.json` showed `count: 0`, and
**none** of the L1.5 enrichment (FP filter, surface_priority,
exploitability, corroborator, post_emit_verifier) fired for those
findings. ~53 tools were affected.

**iter-35.4 fix (no per-tool changes):**

```
sandbox tool calls tracer.add_vulnerability_report(...)
   ↓ (writes to sandbox tracer singleton)
sandbox tool_server._run_tool                            ← strix/runtime/tool_server.py
   ↓ snapshots vulnerability_reports diff post-call
   ↓ truncates sandbox tracer back to pre-call state
   ↓ injects findings into result["_sandbox_emitted_findings"]
[HTTP response]
host _execute_tool_in_sandbox                            ← strix/tools/executor.py
   ↓ extracts _sandbox_emitted_findings sidecar
   ↓ strips L1.5-hook-attached fields per finding
   ↓ host_tracer.add_vulnerability_report(**filtered)    ← L1.5 hooks fire here
```

The propagation is best-effort — any failure during re-emission is
logged via posthog + swallowed; it never crashes the executor path.
The sidecar key (`_sandbox_emitted_findings`) is stripped from the
returned result so callers don't see implementation detail.

---

## 6. The bench framework

### 6.1 Per-layer recall matrix (iter-Q1 series, primary)

Per `docs/proposals/2026-05-27-benchmark-suite-strategy.md`, the canonical measurement is **per-layer recall** with neutral, competitor-cited benchmarks. Every iter PR must cite the relevant bench delta.

| Layer | Bench harness | Headline metric | External comparison |
|---|---|---|---|
| **L0** (CVE corpus freshness) | `bench_vulhub_cve_corpus.py` | KEV hit rate (cron pages at <90%) | n/a — cron pager |
| **L1** (detection) | `bench_owasp_benchmark.py` | Per-CWE Youden index | Veracode 51%, Checkmarx 47%, Fortify 35%, SonarQube 6%, ZAP 13% |
| **L1.5** (enrichment) | Same as L1 with `STRIX_L15_DISABLED=1` | Δ-Youden = L1.5's contribution | Internal — measures own value |
| **L2** (chain exploitation) | `bench_webgoat_dual.py` + `bench_l2_juiceshop_full.py` | (detection_rate, completion_rate). Gap = L2 chain value | n/a — internal attribution |
| Multi-trial wrapper | `bench_multi_trial.py` | median + p10/p90 over N=5 trials | Single-trial bench is noise |

**Decision rule (Q1 proposal, codified):**

> Every L1/L1.5 iter PR must run `bench_owasp_benchmark.py` and report the per-CWE Youden delta on affected categories. Every L2 iter PR must report both `detection_rate` and `completion_rate` from `bench_webgoat_dual.py`. PRs that improve L2 numbers but regress L1 numbers are **rejected** without explicit justification.

### 6.2 Per-metric scorers (iter-31 series, secondary)

11 narrow scorers in `benchmarks/per_target/bench_*.py`. Each reads the canonical run output + computes one metric. They feed the per-layer headline benches but are not themselves headline numbers:

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

### 6.3 Ablation flags (iter-Q1.4)

Both flags wired into the strix runtime (`tracer.add_vulnerability_report` + `StrixAgent.execute_scan`):

- `STRIX_L15_DISABLED=1` — skip the L1.5 hook chain (FP filter, surface_priority, exploitability, corroborator, post_emit_verifier, threat_intel.enrich). Findings land in `vulnerability_reports` raw. Use to isolate L1's contribution.
- `STRIX_L2_DISABLED=1` — `execute_scan` returns after `anchor_prepass` completes without spawning `agent_loop`. Use to measure pure L1 detection (no LLM).

### 6.4 Anti-overfit guards (mandatory on every new bench)

1. **Source-grep test** forbidding SUT-specific identifiers (`juice-shop`, `bkimminich`, `vampi`, `crapi`, `erev0s`, etc.) in the scoring module — catches the case where a heuristic tunes to one fixture's response shape.
2. **Mandatory competitor citation** in every bench report (enforced by render_report tests for L1; reported alongside L2 numbers).
3. **Multi-trial median + p10/p90** via `bench_multi_trial.py` — single-trial bench numbers are noise.
4. **Per-layer ablation** in any headline number — Δ with `STRIX_L15_DISABLED=1` reveals L1.5's contribution; Δ with `STRIX_L2_DISABLED=1` reveals L2's contribution.

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
| 37.11 | Per-asset trim to ACT-only (drop prepass dupes — katana, nuclei, openapi_ingest, …) | #490 | ✓ shipped |
| 37.13 | Sync `docs/tool-catalog-rationalization.md` to shipped reality (10/10/9/11/7 per-asset, layered enforcement model) | — | ✓ shipped (this PR) |
| 37.12 | Bench L2 Juice Shop with iter-37.10 + 37.11 trimmed catalog | — | in flight |
| 37.4 | Add 5 NEW OSS wrappers: smuggler.py, hydra, mobsfscan, ffuf, schemathesis (SAML Raider dropped — Burp extension with no usable standalone CLI; existing in-house scan_saml_xsw already covers the 8 XSW variants) | #495 | ✓ shipped |
| 37.14 | Promote iter-37.4 wrappers to MINIMAL catalog + wire recon/orient ones into anchor_prepass so they fire by default (not just under STRIX_LEGACY_CATALOG=1) | — | ✓ shipped (this PR) |
| 37.5 | DELETE the deprecated tools after grace period (≥ 2026-06-15) | — | gated on time |
| 37.6 | Re-bench L2 Juice Shop with minimal catalog active (superseded by 37.12) | — | superseded |

**Default for the L2 Lead today** (post iter-37.11): minimal ACT-only catalog. The agent sees ~10 tools per web target (5 core + 5 specialist), all of them OSS-backed deep-exploit or LLM-orchestration logic. Recon + broad-orient (katana, nuclei, openapi_ingest, semgrep, trivy, …) fire deterministically in `anchor_prepass.py` — the LLM only sees ACT-stage tools. Set `STRIX_LEGACY_CATALOG=1` to restore the pre-iter-37.2 99-tool catalog for backwards-compat.

**Per-asset specialist sets (post iter-37.11):**

| Asset | Specialist tools | Total catalog |
|---|---|---|
| `web_application` | scan_sqli_sqlmap, scan_xss_dalfox, scan_idor, scan_auth_flow, send_request, **probe_default_creds_hydra, scan_fuzz_ffuf, scan_smuggling_smuggler** | 13 |
| `api` | scan_sqli_sqlmap, scan_idor, scan_auth_flow, map_graphql_inql, send_request, **probe_default_creds_hydra, scan_fuzz_ffuf, scan_api_schemathesis, scan_smuggling_smuggler** | 14 |
| `repository` / `local_code` | build_code_map, taint_analysis, verify_credentials_trufflehog, terminal_execute, **scan_mobile_mobsfscan** | 10 |
| `container_image` | scan_image_dockle, terminal_execute | 7 |
| `ip_address` | fingerprint_services_nmap, probe_hosts_httpx, scan_nuclei_templates, tls_audit, send_request, terminal_execute | 11 |
| `domain` | domain_recon_pipeline, enumerate_subdomains_subfinder, scan_nuclei_templates, scan_dns_hygiene_checkdmarc, scan_typosquats_dnstwist, send_request | 11 |

**Bold tools are iter-37.14 additions** (promoted from iter-37.4 legacy-only). Hydra, ffuf, schemathesis, and mobsfscan also fire in `anchor_prepass.py` as deterministic recon/orient steps so the LLM doesn't have to choose; smuggler stays catalog-only because it's an expensive deep-exploit (LLM should target it at candidates).

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
