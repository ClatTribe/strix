# L2 catalog — per-tool audit

**Status:** audit / review doc (informs Q5.x implementation)
**Owner:** ClatTribe/strix
**Created:** 2026-05-27
**Companion to:** `docs/proposals/2026-05-27-l2-tool-cap-and-translation-toolkit.md`

---

## Method

Walked the registered implementation of every tool in the post-Q5
target L2 catalog (CLAUDE.md §1.5.7). For each, recorded:

- What the function actually does (read the body, not the docstring)
- Whether it fits the L2 goal codified in CLAUDE.md §1.5 — **"AI
  security engineer that translates L1 output into action items for
  non-security audiences (devs + PMs)"**
- Effectiveness signals (structured return shape, LOC, known issues)
- Alternative designs (auto-fire vs LLM-visible, single-purpose vs
  collapsed, keep vs remove)

The audit is **not a hit-list**. It's a structured second-read before
Q5.3-Q5.7 implementation, so we don't ship a refactor that just
shuffles the same problems.

---

## 1. CORE (5 tools — every asset type)

### 1.1 `workflow_status`  (`strix/tools/workflow/workflow_actions.py:44`)

**What it does.** Returns the snapshot from `strix.agents.workflow_state.snapshot()`: current phase, endpoints discovered, login forms found, findings emitted, phase history with timestamps, gate checks (`recon_has_endpoints`, `auth_state_captured`, …), and `next_recommended_actions` (1–3 templated suggestions).

**Fits L2 goal?** **Yes — the canonical OBSERVE primitive.** This is what makes the lead a *workflow-aware* AI engineer rather than a tool-call loop. Without it the lead can't tell "I'm in recon" from "I've moved to probe."

**Effectiveness.** Structured dict return. ~25 LOC delegation to workflow_state. No external I/O. The `next_recommended_actions` field is the highest-leverage piece — it's where the codebase tells the LLM what a human would do next. Quality of those suggestions is the bottleneck (`_suggest_next_actions` in `workflow_state.py:509`).

**Alternatives considered.**
- *Auto-inject into system prompt each turn instead of LLM-callable.* Already happens — the SecurityContext renderer re-renders every turn (`llm.py:496`). But making it pull-only would mean the lead can't ask for it explicitly, which is a worse model.
- *Collapse with `list_pending_findings`.* Different shape (workflow state ≠ findings list). Keeping them separate is right.

**Verdict.** Keep verbatim. Quality lever is `_suggest_next_actions` calibration, not the tool surface.

---

### 1.2 `list_pending_findings`  (`strix/tools/findings/list_findings.py:155`)

**What it does.** Returns up to 25 (default) findings from `tracer.vulnerability_reports`, ranked by L1.5 signals: surface_priority (admin/auth/payment first) × composite exploitability × severity × emission order. Each row is `{id, severity, title, cwe, surface_priority, target, exploitability, annotations}`. Filterable by `severity_floor` and `include_demoted`.

**Fits L2 goal?** **Yes — exactly the right OBSERVE shape for the translator.** The L1.5 enrichment chain already decided what's important; this tool surfaces the ranked list so the lead can pick *which finding to write a developer-friendly narrative for next*.

**Effectiveness.** Structured dict, well-shaped rows. Annotation strings (`pending-dast×N`, `bundle×N`, `EXPLOITED`) compress L1.5 metadata into glanceable text. Title + target truncation (100 + 80 chars) controls token spend.

**Alternatives considered.**
- *Pre-render into the system prompt instead of LLM-callable.* iter-Q2.2 already renders an enriched view into the compaction transcript. But the LLM needs a *pull* path too, so it can request `severity_floor="medium"` mid-scan after triaging the criticals.
- *Add a "fetch one finding's full detail" companion (`get_finding`).* Currently you have to scroll the report; a focused fetch would save tokens. Worth a small follow-up iter.

**Verdict.** Keep. Add `get_finding(id)` companion in a future iter (single-finding deep-read for chain narratives).

---

### 1.3 `think`  (`strix/tools/thinking/thinking_actions.py:7`)

**What it does.** Accepts a thought string. Validates it's non-empty. Returns `{"success": True, "characters": len(thought)}`. **Does not persist anywhere** — not to tracer, not to logs, not to workflow_state.

**Fits L2 goal?** **In intent yes, in implementation no.** A reasoning scratchpad is exactly what an AI security engineer needs. But the current impl is a no-op echo — the thought is dropped after the tool returns. The LLM's chain-of-thought stays only in the turn's response text; calling `think` adds nothing the model couldn't get from just thinking inline.

**Effectiveness.** ~12 LOC. No persistence = no replay = no debuggability when a scan goes sideways. No surfacing to the L2 audience artifact = the developer reading the action list never sees the reasoning.

**Alternatives.**
- **Make it persist** to `run_summary.lead_reasoning_trace[]`. Then it serves dual purpose: chain-of-thought scaffolding for the LLM + audit trail for the L2 audience ("here's why the AI security engineer thought this was the highest-priority finding"). ~15 extra LOC. **Recommended.**
- *Drop the tool entirely* — the LLM can think in its response text. Loses the explicit signal that the LLM *committed* to a chain of reasoning before acting, which is the main behavioral benefit per iter-22 design notes.
- *Replace with structured `propose_hypothesis(name, evidence, next_test)`* — more rigid, may not match the loose reasoning the lead does.

**Verdict.** Currently dead weight. Convert to a persisting log in iter-Q5.x or drop. **The drop costs nothing measurable; the persisting log adds a real L2-audience artifact.**

---

### 1.4 `create_vulnerability_report`  (`strix/tools/reporting/reporting_actions.py:249`)

**What it does.** Emits a finding. Validates 9 required text fields (title, description, impact, target, technical_analysis, poc_description, poc_script_code, remediation_steps, cvss_breakdown) + parses CVSS XML + parses kill-chain XML + parses code_locations + runs `check_duplicate()` (LLM-powered dedup) + calls `tracer.add_vulnerability_report()`. Supports upsert via `existing_report_id`. **21 parameters total.**

**Fits L2 goal?** **The right concept, the wrong surface area.** This is the actual translation artifact — every field on it is something the developer/PM audience reads. But 21 parameters is a huge tool-call to fill in correctly. Empirically (per iter-31.8 bench_context numbers) the lead leaves several optional fields empty most calls.

**Effectiveness.** ~150 LOC. Returns structured dict. The CVSS-XML and kill-chain-XML parsing is finicky — when the LLM emits malformed XML the tool rejects the whole call, losing the finding.

**Alternatives.**
- *Two-stage emission:* `create_finding_draft({title, target, evidence})` for the minimal draft, then `enrich_finding(id, {plain_english, fix_hint, compliance_mapping})` in a follow-up call. Trade-off: more tool calls, but each is filling in 3-4 fields not 21.
- *Drop the XML parameter shapes, accept structured dicts:* `cvss: dict` instead of `cvss_breakdown: str` containing XML. The LLM emits valid JSON-ish dicts more reliably than valid XML.
- *Make the verbose fields LLM-renderable post-emit:* lead emits the structured fact-base; a separate `render_developer_narrative` step (auto-fire on finish_scan) generates the plain-English description.

**Verdict.** Keep the tool but **split the field set into "required to commit" + "render-on-finish":** required = title + target + evidence + severity + cwe (the L1-audience fields). Render-on-finish = description_plain + business_impact_plain + recommended_action + fix_time_estimate (the L2-audience fields). Reduces per-call parameter count from 21 to ~7. Lands as iter-Q5.6.

---

### 1.5 `finish_scan`  (`strix/tools/finish/finish_actions.py:384`)

**What it does.** Terminates the scan. Hard-gates on workflow phase being `report`, open hypotheses, active agents. Validates 4 summary fields (executive_summary, methodology, technical_analysis, recommendations). Auto-fires `emit_compliance_evidence` + `generate_remediation_plan` (iter-37.10). On failure, returns an OODA-structured rejection with concrete next-action templates.

**Fits L2 goal?** **Yes — this IS the L2 deliverable.** The four summary fields are exactly what the developer/PM audience needs: what we did (methodology), what we found (technical_analysis), what to do about it (recommendations), and the executive overview.

**Effectiveness.** ~110 LOC. Gating logic is well-architected (OODA-structured rejection that tells the LLM exactly what to fix). Auto-fire of compliance + remediation per iter-37.10 means the terminal artifact bundle is always complete.

**Alternatives.**
- *Make the 4 summary fields optional:* loses determinism on what the L2 audience receives. Reject.
- *Stream the artifacts as they're built, not on finish:* would let the lead course-correct on a bad narrative mid-scan. Bigger architectural change; defer.

**Verdict.** Keep. The OODA-structured rejection on premature finish is a load-bearing piece of the lead's training-wheels surface; don't soften it.

---

## 2. REASONING (new tools — Q5 ships these)

### 2.1 `propose_chain` (new — Q5.6)

**What it does (planned).** LLM emits 2+ finding IDs that compose a chain narrative. Upserts into `run_summary.chains_emitted`. Distinct from the iter-33.3 heuristic auto-chain detector (which finds shape-matched candidates without LLM input).

**Fits L2 goal?** **Yes — pure L2 work.** Chain reasoning is what a human pentester does for a customer report. The current heuristic catches shape-matched chains (CSRF + open redirect) but misses the app-specific ones a human notices ("this exposed admin panel + that default cred = full-tenant takeover").

**Effectiveness (projected).** Should be ~200 LOC + 20 tests. Returns structured dict. Will feed `bench_chains` (iter-31.2).

**Alternatives.**
- *Skip the tool; rely on the heuristic.* Misses app-specific chains.
- *Make the lead embed chain narrative inside `create_vulnerability_report.kill_chain`.* That's the current shape and it's noisy — every report optionally carries chain XML, and most are empty. A dedicated tool is cleaner.

**Verdict.** Build per Q5.6.

---

### 2.2 `prioritize_findings` (new — Q5.7)

**What it does (planned).** Lead supplies `customer_context = {industry, compliance_targets, critical_assets, tech_stack_focus}`. Tool re-ranks pending findings with a per-finding `customer_priority` integer. Does not mutate findings.

**Fits L2 goal?** **Yes — separates intrinsic severity from customer relevance.** A `low`-severity info disclosure on a fintech's customer-PII endpoint should rank above a `high` SQLi on the marketing CMS. Today the lead bakes this into `severity` directly, conflating the two axes.

**Effectiveness (projected).** ~250 LOC + 25 tests. Feeds `bench_severity` (iter-31.3).

**Alternatives.**
- *Have L1.5's `surface_priority` cover it.* Already partially covers — but `surface_priority` is generic (admin / auth / payment surfaces). It doesn't know the customer is in fintech vs. healthcare.
- *Bake customer_context into the system prompt as static facts.* The lead would still need an explicit re-rank action; without it, ranks are implicit and the L2 audience can't audit them.

**Verdict.** Build per Q5.7. Open question (§8.2 of the Q5 proposal): collapse with `surface_priority` or keep separate? Recommended **keep separate** — `surface_priority` is L1.5 generic; `prioritize_findings` is L2 customer-specific. Different inputs, different consumers.

---

## 3. L2-NATIVE DETECTION (3-6 per asset)

### 3.1 `scan_idor`  (`strix/tools/specialist/scan_idor.py:394`)

**What it does.** Takes 2 captured auth sessions + a list of ID-shaped URLs. For each URL, probes with owner / accessor / anon. Compares response similarity (0.7 threshold). Auto-emits CWE-639 (IDOR) / CWE-862 findings when accessor or anon reads owner's data. Severity escalates to critical on sensitive-marker detection.

**Fits L2 goal?** **Yes — IDOR detection has no OSS substitute because it needs LLM-driven state setup.** Which two sessions? Which URLs are ID-shaped? Which markers matter for THIS app? These are reasoning calls a regex-driven scanner can't make.

**Effectiveness.** ~320 LOC. Structured `SpecialistResult`. MITRE-tagged. The 0.7 sequence-similarity threshold is empirical — could regress on apps with templated boilerplate (e.g. nav bar in every response). Records `decision_log` for audit.

**Alternatives.**
- *Move to an L1 OSS wrapper (Astra, ZAP active scan).* Astra has an IDOR module but it requires explicit user-session pairs as YAML — same setup problem we're solving with LLM reasoning. No standalone-OSS substitute that's actually plug-and-play.
- *Sub-agent / orchestrator-mode dispatch.* Already supported. The question is whether to make the lead see `scan_idor` directly or only through `dispatch_specialist`. For the ≤10 cap the direct visibility costs 1 slot; the dispatch indirection costs 1 slot AND a turn. Direct is better.

**Verdict.** Keep in L2 catalog. Calibrate the 0.7 similarity threshold against bench fixtures in a follow-up.

---

### 3.2 `scan_auth_flow`  (`strix/tools/specialist/scan_auth_flow.py:269`)

**What it does.** Tries 16 default-credential pairs (admin/admin, root/toor, …) + optional self-registration via `try_register=True`. Captures JWT / cookies on success → writes to `SecurityContext.AuthState`. Auto-invokes `jwt_audit` on captured JWT. Emits CWE-521 only for default-corpus hits (not user-supplied creds — distinguishes tenant-provided from exploitable defaults).

**Fits L2 goal?** **Partial — it's L1-style detection (default-cred bruteforce) PLUS L2 orchestration (session setup for downstream `scan_idor`).** The bruteforce part overlaps with `probe_default_creds_hydra` which fires in anchor_prepass. The orchestration part (writing AuthState so downstream tools can use it) is L2-native.

**Effectiveness.** ~420 LOC. Structured `SpecialistResult`. Reads `STRIX_LOGIN_CREDS` env var so user-supplied creds bypass the default corpus. Chains to `jwt_audit` automatically.

**Alternatives.**
- *Split into two tools:* `seed_auth_session(creds)` (state-setup only, no bruteforce) + leave the bruteforce to `probe_default_creds_hydra` in prepass. Costs 1 catalog slot for the seed; saves duplicated work.
- *Move bruteforce to prepass; keep `scan_auth_flow` as session-setup-only.* Cleaner separation. Loses the convenience of "the LLM calls this once and gets both bruteforce + session."

**Verdict.** Keep in L2 catalog but **rename and rescope to `seed_auth_session`** in a future iter — the bruteforce is duplicated by hydra in prepass. Today's shape is acceptable while we measure Q3 parity; revisit after Q3.

---

### 3.3 `scan_business_logic`  (`strix/tools/specialist/scan_business_logic.py:342`)

**What it does.** Probes 5 abuse families: `price_tampering`, `quantity_tampering`, `role_tampering`, `workflow_skip`, `param_pollution`. For each, mutates body fields and checks for success markers (`success:true`, `order_id`, `paid:true`, sensitive-value markers). Auto-emits CWE-840/841/235/269/682 findings. Auto-injects auth from SecurityContext.

**Fits L2 goal?** **Yes — business-logic abuse is the canonical "no OSS substitute" case.** No nuclei template knows what your app considers a successful purchase; only LLM-driven inspection of the body schema can guess at the right mutations.

**Effectiveness.** ~370 LOC. Structured `SpecialistResult`. Family-by-family probing means partial-success is meaningful (4 of 5 families clean is useful info). Introspects `body_template` to discover candidate fields.

**Alternatives.**
- *Replace with `schemathesis` for the API case.* schemathesis tests schema conformance, not abuse semantics. Different category. Both should ship — schemathesis in prepass (L1), `scan_business_logic` in L2 catalog for the abuse-shape probes.
- *Make each family a separate tool.* Would blow past the ≤10 cap. The 5-family grouping is right.

**Verdict.** Keep. Strong fit for L2's "where OSS can't help" niche.

---

### 3.4 `build_code_map`  (`strix/tools/code_map/code_map.py:716`)  *(repo / local_code only)*

**What it does.** Walks the repo. Regex-extracts routes, models, DB queries, external HTTP calls, auth boundaries across 8 languages (Flask/Django/FastAPI/Express/Rails/Spring/Go). Writes `code_map.json` to run directory. Returns structural artifact lists + next-steps hints.

**Fits L2 goal?** **Yes — repo-translation is the L2 work for the `repository` asset type.** A dev wants to know "where in my code does the auth boundary live", and `code_map.json` is the answer that downstream remediation pointers (file:line) hang off.

**Effectiveness.** ~110 LOC main loop. Regex-based per-language — fragile compared to real ASTs, but fast and language-portable. Returns structured dict + JSON artifact. Records phase-entry/completion events.

**Alternatives.**
- *Use tree-sitter or per-language AST tools.* More accurate, much more code + binary deps. Could be a Q3.x parity bench for SAST tools (we already wrap semgrep via taint_analysis; could add tree-sitter as a separate iter).
- *Drop entirely; rely on semgrep's `--config auto` output for code-structure facts.* Semgrep gives findings, not the code map. Different artifacts.

**Verdict.** Keep for repo assets. The regex fragility is real but the artifact's downstream consumers (taint_analysis, remediation pointers) tolerate partial coverage.

---

### 3.5 `taint_analysis`  (`strix/tools/taint/taint_analysis.py:578`)  *(repo / local_code only)*

**What it does.** AST-based taint analysis for Python only. Walks `.py` files, parses with `ast`, tracks sources (`request.*`, `sys.argv`, `os.environ`) → sinks (`eval`, `exec`, `os.system`, raw SQL, `subprocess`, `pickle.loads`). Intra-procedural (no cross-file flow, no sanitiser detection). Emits one finding per detected flow.

**Fits L2 goal?** **Borderline — this is L1-style detection in L2's catalog.** It does what semgrep + bandit + codeql do, with strictly less coverage (Python only, intra-procedural only, no sanitisers). The only reason it's L2-shaped today is the LLM gets to choose when to run it.

**Effectiveness.** ~110 LOC main loop. Structured dict + per-flow findings. Python-only is a hard ceiling.

**Alternatives.**
- **Move to anchor_prepass; replace LLM-visible entry with the existing semgrep wrapper.** Per CLAUDE.md §11.1, in-house detection engines are forbidden. `taint_analysis` is in-house detection with a curated coverage area. Semgrep + codeql + bandit have ~100x more rules and proper cross-file analysis. The right path: deprecate `taint_analysis`, fire semgrep `--config auto` in anchor_prepass, surface results via `list_pending_findings`.
- *Keep as a Python-specific fast-path complementing semgrep.* Possible, but justifying it requires Q3 parity numbers showing it catches things semgrep doesn't.

**Verdict.** **Deprecation candidate.** Park in iter-Q5.x backlog: ship a Q3 parity bench of `taint_analysis` vs. semgrep `--config p/python` on the same fixture; if semgrep wins (likely), retire `taint_analysis` and reclaim the L2 catalog slot for something more L2-shaped (e.g. `explain_finding_for_developer` for the repo asset).

---

### 3.6 `map_graphql_inql`  (`strix/tools/inql_runner/map_graphql_inql.py:97`)  *(api only)*

**What it does.** Wraps the `inql` CLI. POSTs introspection query, parses returned schema.json, returns the list of operations (queries + mutations + their argument types). Returns `partial` when introspection is disabled (which is correct OSS behavior — disabled introspection is a hardening practice, not a bug).

**Fits L2 goal?** **No — this is an L1 OSS wrapper.** Per CLAUDE.md §1.5 it should fire in `anchor_prepass` as deterministic L1 coverage, not as LLM-visible tool. The lead currently has to *decide* to call it on every GraphQL-shaped target, which is exactly the pattern iter-37 is moving away from.

**Effectiveness.** ~120 LOC wrapper. Structured dict return. Falls back gracefully when inql binary isn't on PATH.

**Alternatives.**
- **Move to `anchor_prepass._ANCHORS_API` alongside `discover_graphql_endpoints` (already there).** Fires automatically when a GraphQL endpoint is detected. Saves 1 L2 catalog slot for api assets.

**Verdict.** **Move to prepass.** Trivial change (1 line added to `_ANCHORS_API`, 1 line removed from `_MINIMAL_TOOLS_BY_TARGET_TYPE["api"]`). Lands as part of Q5.3.

---

## 4. PRIMITIVES (escape hatches)

### 4.1 `send_request`  (`strix/tools/proxy/proxy_actions.py:51`)

**What it does.** Issues an HTTP request via `proxy_manager.send_simple_request`. Best-effort side-effects: records endpoint into SecurityContext, captures tech-stack hints, marks `auth-required` on 401/403, parses Location header for value-reflection (open-redirect partial signal), extracts param names from query string + body, detects OpenAPI/Swagger response shape and pre-populates SecurityContext with documented endpoints.

**Fits L2 goal?** **Yes — load-bearing escape hatch.** When the prepass missed an endpoint, or when the lead is chasing a chain step that needs a custom auth header, `send_request` is the only way out. The OpenAPI pre-populate is a real value-add — turns a single GET into "and here are 30 documented endpoints we now know about."

**Effectiveness.** ~135 LOC. Structured dict return. The side-effect block is good engineering (silent on failure, never blocks the request).

**Alternatives.**
- *Drop; require all HTTP through prepass tools.* Loses chain-exploitation capacity. Reject.
- *Split into `send_request` (raw HTTP) + `inspect_response(metadata)` (side-effect-only).* Over-engineered. The current shape is fine.

**Verdict.** Keep verbatim. The OpenAPI pre-populate side-effect is doing real work.

---

### 4.2 `terminal_execute`  (`strix/tools/terminal/terminal_actions.py:7`)

**What it does.** Passthrough to `terminal_manager.execute_command()`. Returns `{status, exit_code, content, working_dir}`. Stateful via `terminal_id`. **No docstring.**

**Fits L2 goal?** **Borderline — escape hatch for repo / IP / container assets.** For `repository` asset type the lead needs `terminal_execute` to `grep` for credential patterns the LLM is curious about. For `ip_address` it's a way to run `nmap` follow-ups. For `container_image` it's how to mount and inspect.

**Effectiveness.** ~30 LOC. No docstring = LLM has minimal guidance on when to use it. Catches ValueError + RuntimeError only — other exceptions bubble up.

**Alternatives.**
- *Drop for repo / container; keep only on `ip_address` where the use case is clearest.* Loses repo-investigation capacity (grep, `find`, `wc -l`, etc.).
- *Replace with focused single-purpose tools (`grep_repo`, `mount_image`, `nmap_followup`).* Each costs a catalog slot; total exceeds ≤10 quickly.
- **Add a real docstring** that lists the 3-4 canonical uses per asset type. ~10 LOC. Improves LLM aim significantly.

**Verdict.** Keep, but **add a docstring** in a follow-up iter. The lack of guidance is currently throttling effectiveness.

---

## 5. Summary verdict table

| Tool | Fits L2 goal? | Verdict | Action |
|---|---|---|---|
| `workflow_status` | ✓ canonical OBSERVE | Keep verbatim | — |
| `list_pending_findings` | ✓ canonical OBSERVE | Keep | Add `get_finding(id)` companion later |
| `think` | ✗ no-op echo | Convert to persisting log or drop | iter-Q5.x — 15 LOC change |
| `create_vulnerability_report` | ⚠️ right concept, 21 params | Keep; split required/render-on-finish | iter-Q5.6 split |
| `finish_scan` | ✓ the L2 deliverable | Keep verbatim | — |
| `propose_chain` (new) | ✓ pure L2 work | Build | iter-Q5.6 |
| `prioritize_findings` (new) | ✓ pure L2 work | Build | iter-Q5.7 |
| `scan_idor` | ✓ no OSS substitute | Keep | — |
| `scan_auth_flow` | ⚠️ overlaps prepass hydra | Keep; rename to `seed_auth_session` later | post-Q3 rename |
| `scan_business_logic` | ✓ no OSS substitute | Keep | — |
| `build_code_map` | ✓ repo-translation primitive | Keep | — |
| `taint_analysis` | ✗ in-house SAST (CLAUDE.md §11.1 violation) | Deprecation candidate | Q3 parity bench → likely retire |
| `map_graphql_inql` | ✗ L1 OSS wrapper | Move to anchor_prepass | iter-Q5.3 |
| `send_request` | ✓ load-bearing escape hatch | Keep verbatim | — |
| `terminal_execute` | ⚠️ no docstring throttling use | Keep; add docstring | follow-up iter |

---

## 6. Headline findings

1. **`think` is dead weight** as currently implemented — a 12-LOC validator that returns char count and persists nothing. Either make it write to `run_summary.lead_reasoning_trace[]` (recommended) or drop it. The L2 audience never sees the LLM's reasoning today; persisting `think` calls is the lowest-friction path to changing that.

2. **`create_vulnerability_report` has 21 parameters.** Empirically (per `bench_context.py` numbers) the lead leaves several optional fields empty most calls. Split into "required to commit" (5–7 fields — title, target, evidence, severity, cwe) + "render-on-finish" (description_plain, business_impact_plain, recommended_action, fix_time_estimate). The L2-audience plain-English fields are exactly the kind of thing a separate render step can fill in once at scan-end with the full finding context.

3. **`taint_analysis` is an in-house SAST engine** — a direct violation of CLAUDE.md §11.1 ("no in-house detection engines"). It has strictly less coverage than semgrep (Python only, intra-procedural only, no sanitisers). Ship a Q3 parity bench `taint_analysis` vs. semgrep `--config p/python`; if semgrep wins (likely), retire and reclaim the L2 slot for an L2-shaped tool (`explain_finding_for_developer`).

4. **`map_graphql_inql` is an L1 OSS wrapper in L2 clothing.** Trivial move to anchor_prepass alongside `discover_graphql_endpoints`. Frees 1 catalog slot for api assets. Costs ~5 LOC.

5. **`scan_auth_flow` duplicates `probe_default_creds_hydra`** in the bruteforce dimension. Future rename to `seed_auth_session` (session-setup-only) clarifies the L2-native part. Defer until Q3 parity confirms hydra catches the same default corpus.

6. **`terminal_execute` has no docstring.** The LLM has no guidance on canonical uses per asset type — for repo: `grep`/`find`/`wc -l`; for ip: nmap follow-ups; for container: mount-and-inspect. Adding a docstring is ~10 LOC and meaningfully improves aim.

7. **Of the 13 current L2 tools, 9 are well-fitted to the L2 goal**, 2 need rework (`think`, `create_vulnerability_report`), and 2 should move to L1 (`taint_analysis`, `map_graphql_inql`). The Q5 reorg + these findings together get the catalog cleanly under ≤10 per asset with every tool justified by its L2 role.

---

## 7. Iter sequence (incremental, layered onto Q5)

| iter | scope | est. size |
|---|---|---|
| **Q5.3a** | Move `map_graphql_inql` to `anchor_prepass._ANCHORS_API`. Drop from `_MINIMAL_TOOLS_BY_TARGET_TYPE["api"]`. | trivial — 5 LOC |
| **Q5.6.1** | Split `create_vulnerability_report` parameter set. Required-to-commit (7 fields) vs render-on-finish (auto-generated from finding context at `finish_scan` time). | ~150 LOC + 15 tests |
| **Q5.x-think** | Convert `think` to persist to `run_summary.lead_reasoning_trace[]`. ~15 LOC + 5 tests. | small |
| **Q5.x-terminal** | Add per-asset docstring to `terminal_execute`. ~10 LOC. | trivial |
| **Q3.x-taint-parity** | Parity bench `taint_analysis` vs. semgrep on a Python repo fixture. Decision: retire or justify. | ~150 LOC + fixture |
| **Q5.x-auth-rename** | Rename `scan_auth_flow` → `seed_auth_session`, drop the bruteforce body (now in hydra prepass). Update tests. | ~80 LOC |

These can ship in any order — they're independent. The most leveraged is `Q5.6.1` (the 21→7 parameter split for create_vulnerability_report), because it unblocks the next jump in `bench_context` actionable-rate numbers.
