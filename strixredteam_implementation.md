# Strix Red-Team Uplift — Implementation Status

Companion to [`strixredteam.md`](strixredteam.md). Records what shipped, where it lives, how it's gated, and what remains.

Period covered: **all sequenced work from the blueprint plus three priority follow-ups derived from the Decepticon comparison.**

---

## TL;DR

| Section | Status | PR(s) | LOC | Tests |
|---|---|---|---|---|
| §1 Fresh-context specialists | shipped (MVP) | [#233](https://github.com/ClatTribe/strix/pull/233) | ~780 + tests | 31 |
| §2 OPPLAN objective state machine | shipped | [#239](https://github.com/ClatTribe/strix/pull/239) | 1,195 | 48 |
| §3 Persistent typed KG | shipped | [#240](https://github.com/ClatTribe/strix/pull/240) | 1,198 | 45 |
| §4 Verification pipeline | shipped (5-stage state machine) | [#241](https://github.com/ClatTribe/strix/pull/241) | 1,102 | 79 |
| §5 Skills menu middleware | shipped | [#236](https://github.com/ClatTribe/strix/pull/236) | 675 | 30 |
| §6 Tiered tool output | shipped | [#235](https://github.com/ClatTribe/strix/pull/235) | 769 | 29 |
| §7 `strix.scope.yml` engagement scope | shipped | [#238](https://github.com/ClatTribe/strix/pull/238) | 877 | 25 |
| §8 Multi-step fallback chain | shipped | [#237](https://github.com/ClatTribe/strix/pull/237) | 690 | 38 |
| **KG specialist adoption** (scan_sqli + scan_xss) | shipped | [#242](https://github.com/ClatTribe/strix/pull/242) | 473 | 15 |
| **Patcher + patch_verify** (closes §4 EXPLOITED → PATCHED) | shipped | [#243](https://github.com/ClatTribe/strix/pull/243) | 1,101 | 41 |
| **Operational depth** in sqli/xss/ssrf skills | shipped | [#244](https://github.com/ClatTribe/strix/pull/244) | 501 | 26 |

**Total**: 10 PRs (§2–§8 + 3 follow-ups), ~10,400 LOC added, ~407 tests added. All merged into `main` at `13e00e2`.

---

## Section detail

### §1 — Fresh-context specialist orchestration

- `strix/agents/specialist_orchestrator.py` — `dispatch_specialist(category, objective, ...)` boots a bounded inner-LLM loop in a fresh conversation context. Auto-exits on `complete_objective(status, reason)` or hitting the iteration / cost cap.
- Lead-facing tools: `dispatch_specialist`, `complete_objective` (`strix/tools/workflow/specialist_dispatch.py`).
- Built-in profiles: sqli, xss, idor, recon, auth + generic.
- Opt-in: `STRIX_ORCHESTRATOR_MODE=1`. Reduces lead catalog ~88 → 28 tools when on.
- v0 limitation: inner-LLM tools wired to `complete_objective` only; full per-specialist tool subsets are follow-up.

### §2 — OPPLAN objective state machine

- `strix/agents/objective_tracker.py` — `Objective` records with id/title/phase/category/surface/depends_on/acceptance/status/evidence_required/parent_id. Statuses: pending / in_progress / completed / blocked / cancelled. Transitions validated (rejects `completed → pending` etc).
- Five CRUD tools at `strix/tools/workflow/objective_tools.py`.
- Append-only persistence to `<run_dir>/objectives.jsonl`.
- Prompt rendering: `render_progress_table()` injects the current plan into every system prompt render with status icons (· pending, ▶ in_progress, ✓ completed, ✗ blocked, — cancelled).

### §3 — Persistent typed knowledge graph

- `strix/agents/knowledge_graph.py` — 7 node types (Surface, Asset, Vuln, Credential, Secret, Dependency, Role), 7 edge types (AFFECTS, REACHABLE_FROM, LEAKS, GRANTS_ACCESS_TO, CHAINS_TO, RUNS_ON, USES). Types enforced at `add_node`/`add_edge`. BFS path queries with hop cap + edge-type filter + cycle avoidance.
- Five lead-facing tools at `strix/tools/workflow/kg_tools.py`.
- Atomic JSON persistence to `<run_dir>/kg.json` (tmp → rename). Cross-engagement load via `load_kg_from_disk()`.
- **Specialist adoption** (PR #242): scan_sqli + scan_xss now populate Vuln + Surface + AFFECTS triples on every successful finding. Surface dedup cache so 10 probes against `/login?try=N` collapse to 1 surface but emit 10 vulns.

### §4 — Five-stage verification pipeline

- `strix/agents/verification_pipeline.py` — canonical stages: `SCANNED → DETECTED → VERIFYING → VERIFIED → EXPLOITED → PATCHED` (+ `FAILED` terminal). Forward-only transitions enforced.
- **Critical invariant**: VERIFYING → VERIFIED requires ≥2 *distinct independent* methods for HIGH/CRITICAL severity (defaults from `STRIX_VERIFICATION_MIN_METHODS_HIGH=2`; `_DEFAULT=1`). Method types: `payload_response`, `timing`, `dom`, `oob`, `differential`, `static_match`, `external_corroboration`.
- Four lead-facing tools at `strix/tools/workflow/verification_tools.py`.
- **Patcher runtime** (PR #243): `strix/agents/patcher.py` + `patcher_tools.py` close the EXPLOITED → PATCHED stage. `PatchRegistry` dedups on `sha1(diff)[:12]`. `verify_patch(probe_result_still_fires)` chains into §4 via `advance_finding_to_patched`. Defensive: probe-fn raising treated as `regressed`, never accidental success.

### §5 — Skills menu middleware

- `strix/skills/menu.py` — frontmatter parser + categorised menu generator. Walks `strix/skills/<category>/*.md`, emits `**name**: description (Triggers: keywords)` block into the system prompt at every render. Bodies still load on demand via existing `load_skill` tool (two-level disclosure).
- ~5K tokens added to system prompt (one-time per render); replaces speculative body loads (~5–20K each) that the agent used to issue blindly.
- **Operational depth** (PR #244): `sql_injection.md` / `xss.md` / `ssrf.md` gained ~340 lines of step-numbered runbooks (sqlmap orchestration, blind extraction blueprints, auth-bypass payload library; XSS canary sweep + context probing + CSP bypass; SSRF OAST oracle + cloud metadata sweep + gopher pivot + DNS rebinding).

### §6 — Tiered tool output

- `strix/runtime/output_tiering.py` — 3-tier policy: ≤15K inline, ≤100K save-to-scratch + summary, >5M defensive marker. Universal cleanups (ANSI strip, repeat-line compression ≥3 → "... [N more identical lines]") applied at every tier.
- Wired into `strix/tools/executor.py::_format_tool_result`; threads `execution_id` so scratch files are deterministically named under `<run_dir>/.tool_output_scratch/`. Companion `.json` metadata for tooling introspection.

### §7 — `strix.scope.yml` engagement scope

- `strix/scope/` package — `spec.py` (frozen dataclasses), `loader.py` (fail-fast `ScopeValidationError` collecting all errors at once), `render.py` (prompt-injection block).
- CLI flag `--scope-file` in `strix/interface/main.py`. Threaded through `cli.py` + `tui.py` → `_build_system_scope_context` → `system_prompt.jinja`.
- Security guard: `auth.inject_from` rendered as source descriptor only (`env:STRIX_BEARER`), never the resolved credential value. Pinned by test.

### §8 — Multi-step fallback chain

- `strix/llm/fallback_chain.py` — `pick_chain(role=, tier=)` returns ordered `ChainLink` list (provider, model, tier, credential_present). `next_link_after(model)` walks past the current model to find the next credentialed alternative.
- Per-role tier defaults (Decepticon `eco` profile): HIGH = taint/verifier/exploiter/lead, MID = sqli/idor/xss/auth, LOW = recon/fingerprint/scope.
- Replaces the old Phase 1.1 single-fallback. `_maybe_failover` walks the chain on repeat 429/5xx; chain exhaustion leaves agent on current model + lets retry loop handle.

---

## Env-var kill switches & knobs

Every new feature ships gated. Production rollout can disable any one without rebuilding the sandbox.

| Var | Default | Purpose |
|---|---|---|
| `STRIX_ORCHESTRATOR_MODE` | unset | Enable §1 fresh-context specialist mode |
| `STRIX_SPECIALIST_MAX_ITERATIONS` | 50 | §1 inner-LLM iteration cap |
| `STRIX_OBJECTIVES_DISABLED` | unset | §2 kill switch (tracker no-op, prompt block empty) |
| `STRIX_OBJECTIVES_PERSIST` | "1" | §2 set to "0" to skip jsonl |
| `STRIX_KG_DISABLED` | unset | §3 kill switch (graph + emit helper no-op) |
| `STRIX_KG_PERSIST` | "1" | §3 set to "0" for in-memory only |
| `STRIX_VERIFICATION_DISABLED` | unset | §4 kill switch |
| `STRIX_VERIFICATION_PERSIST` | "1" | §4 set to "0" to skip jsonl |
| `STRIX_VERIFICATION_MIN_METHODS_HIGH` | 2 | §4 HIGH/CRITICAL evidence floor |
| `STRIX_VERIFICATION_MIN_METHODS_DEFAULT` | 1 | §4 default-tier evidence floor |
| `STRIX_PATCHER_DISABLED` | unset | Patcher kill switch |
| `STRIX_PATCHER_PERSIST` | "1" | Patcher jsonl gate |
| `STRIX_SKILLS_MENU_DISABLED` | unset | §5 kill switch |
| `STRIX_SKILLS_MENU_CATEGORIES` | unset | §5 CSV category filter |
| `STRIX_SKILLS_MENU_MAX_PER_CATEGORY` | unset | §5 entry cap per category |
| `STRIX_OUTPUT_INLINE_MAX` | 15000 | §6 tier-1 ceiling |
| `STRIX_OUTPUT_SCRATCH_MAX` | 102400 | §6 tier-2 ceiling |
| `STRIX_OUTPUT_HARD_KILL` | 5242880 | §6 tier-3 boundary |
| `STRIX_OUTPUT_TIERING_DISABLED` | unset | §6 kill switch (reverts to legacy 10K truncation) |
| `STRIX_AUTH_PRIORITY` | `anthropic,openai,google` | §8 provider order |
| `STRIX_FALLBACK_TIER` | `MID` | §8 default tier |
| `STRIX_FALLBACK_TIER_<ROLE>` | per-role default | §8 override (e.g. `STRIX_FALLBACK_TIER_SQLI=LOW`) |
| `STRIX_FALLBACK_DISABLED` | unset | §8 kill switch |
| `STRIX_LLM_FAILOVER` | unset | §8 legacy explicit override (highest priority) |

---

## Run-dir layout (post-uplift)

Each scan now produces (in addition to existing strix outputs):

```
<run_dir>/
  ├── events.jsonl              (existing — strix telemetry stream)
  ├── findings.jsonl            (existing — strix findings)
  ├── objectives.jsonl          NEW — §2 OPPLAN state-change events
  ├── kg.json                   NEW — §3 typed knowledge graph (atomic write)
  ├── verification.jsonl        NEW — §4 pipeline state-change events
  ├── patches.jsonl             NEW — patch proposals + verify outcomes
  └── .tool_output_scratch/
      ├── tool_call_<id>.txt    NEW — §6 saved tier-2/3 outputs
      └── tool_call_<id>.json   NEW — §6 metadata companions
```

CI consumers can diff two runs' jsonl files to surface delta in objectives, verifications, patches between PR and main scans.

---

## Decepticon comparison — where we stand

### Reached parity

§1, §2, §3 (with adoption), §5 (with operational bodies), §6, §7, §8. These are now structurally equivalent or AppSec-tuned ports of the Decepticon patterns.

### Better than Decepticon (post-uplift)

- **Engineering polish** — pervasive `STRIX_*_DISABLED` kill switches make rollout safer than Decepticon's middleware composition (one bad middleware can break the whole agent).
- **Test depth** — ~4.5× test count vs. comparable Decepticon module surface.
- **AppSec-specific tooling** — threat intel integrations (`greynoise`, `hibp_breach`, `kev_diff`, `nvd_lookup`, `vt_reputation`, `otx_lookup`, `sigma_lookup`) and SCA reachability that Decepticon doesn't ship.
- **Single-file KG** — atomic JSON works for per-run scale, no Neo4j daemon.

### Still behind Decepticon

- **Patcher specialist runtime** — §4 state machine is in (PR #243); auto-diff generation via LLM specialist + automatic probe replay is follow-up. Currently the lead/patcher must call `verify_patch` with the probe outcome manually.
- **True multi-agent parallelism** — strix `dispatch_specialist` is sync-only; Decepticon's langgraph composition supports concurrent sub-agents.
- **AD / contracts / binary / cloud-exploit** — out of strix's AppSec scope by design (per `strixredteam.md` §11).

### Out of scope

Per `strixredteam.md` §11 — Active Directory tooling, smart contract auditing, binary reversing, C2 frameworks. Strix consciously omits these; webappsec wrapper calls only strix.

---

## What's NOT yet validated against a baseline

A live benchmark on juiceshop with the full post-§1–§8 + adoption + patcher + skills stack has not yet produced a clean comparison run as of `13e00e2`. Attempts during this work session hit Google Cloud account-level credential restrictions; the test suite (407 new tests, all passing) is the current evidence-of-correctness baseline.

When a stable Gemini paid-tier key (or Anthropic / OpenAI key) is available locally, the canonical re-baseline command is:

```bash
.venv/bin/python benchmarks/per_target/runner.py \
    benchmarks/per_target/fixtures/web/juiceshop \
    --scan-mode standard --strix-arg=--no-preflight \
    --output benchmarks/per_target/baseline/juiceshop_post_244_$(date +%Y%m%d_%H%M).json
```

Comparison anchor: `benchmarks/per_target/baseline/juiceshop_native_20260509_2301.json`
- 784s / $0.036 / 3 matched / 9 expected → recall 0.333, precision 0.60.

Expected directionally-positive deltas after the uplift:
- **KG node count** > 0 after the run (validates PR #242 specialist adoption)
- **objectives.jsonl** present (validates §2)
- **verification.jsonl** with records past `SCANNED` (validates §4 wiring)
- **patches.jsonl** present iff specialists exercised propose/verify
- **recall** improvement driven by the skill-body operational sections + §1 fresh-context (less mid-run drift)

---

## Open follow-up tasks

| Priority | Task | Effort |
|---|---|---|
| 1 | Wire Patcher specialist registry entry — LLM-driven diff generation that writes to `propose_patch` | medium |
| 1 | Scanner-side `verify_patch` re-run hooks — when an auto-applied patch lands, automatically re-call the original detector + auto-emit the outcome | medium |
| 2 | Extend KG adoption to scan_ssrf, scan_idor, scan_misconfig, scan_csrf, scan_authz_matrix (mechanical — pattern is in PR #242) | small |
| 2 | Port operational runbook sections into remaining vuln skills (idor, csrf, ssrf-deeper, jwt, deserialization, rce, command-injection) | medium |
| 3 | Real specialist inner-LLM tool wiring (§1 v1) — give each specialist its full registered tool subset, not just `complete_objective` | medium |
| 3 | Live juiceshop baseline + write to `juiceshop_post_244_*.json` | small (when key available) |
| 4 | Investigate hanging `tests/agents/test_progress_watchdog.py` suite (passes individually, hangs in group — flagged 2026-05-15) | small |
| 4 | Bind-mount prior-run `kg.json` for CI delta-scan context-awareness | medium |

---

## Rollback posture

Every section is independently revertable via its env-var kill switch. A defective merge can be neutralised without re-deploying:

```bash
STRIX_OBJECTIVES_DISABLED=1 \
STRIX_KG_DISABLED=1 \
STRIX_VERIFICATION_DISABLED=1 \
STRIX_PATCHER_DISABLED=1 \
STRIX_SKILLS_MENU_DISABLED=1 \
STRIX_OUTPUT_TIERING_DISABLED=1 \
STRIX_FALLBACK_DISABLED=1 \
strix -t <target>
```

This effectively reverts to pre-§1–§8 behaviour without changing code. Use it for A/B comparison or when bisecting a regression.

---

*Generated 2026-05-16 against main @ `13e00e2`.*
