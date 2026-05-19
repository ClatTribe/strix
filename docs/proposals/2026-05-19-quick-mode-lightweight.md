# Quick mode v3 — actually lightweight

**Status:** Proposal · 2026-05-19 · **Owner:** ClatTribe/strix
**Tracking:** masterroadmap §11 (cost) · continuation of
[scan-mode-cost-optimization.md](2026-05-19-scan-mode-cost-optimization.md)

## Problem

After the v2 cost-optimization arc (Phase 1 dispatch cap + 8 steps,
PRs #334 through #344), `quick` mode is *not* lightweight in any
honest sense:

- `--scan-mode quick` sets the `dispatch_specialist` cap to 0
  (no fresh-context inner-LLM loops)
- `--scan-mode quick` swaps in the `quick.md` skill body
- `--scan-mode quick` sets `reasoning_effort=medium`

…but **the lead is still a full LLM agent** in its own loop. The
v2 steps capped what the lead *can dispatch*; they did not cap how
many calls the lead itself makes.

Auditing every v2 step against the quick-mode call path:

| v2 step | Helps quick? | Why |
|---|---|---|
| Phase 1 — dispatch cap | indirect | sets cap=0 but lead-side calls untouched |
| 1 — FP filter | no | deterministic at emit time |
| 2 — verdict cache | **no** | only fires inside `dispatch_specialist`; cap=0 in quick |
| 3 — batched dispatch | **no** | same |
| 4 — structured result + skip-lead-think | partial | only when a dispatch actually fires |
| 5 — recon cache | **yes** | helps re-scans of same target |
| 6 — pre-dispatch gate | **no** | gated to 0 in quick |
| 7 — CWE templates | no | post-emit deterministic fill |
| 8 — boot prompt persistence | no | disk-only, no LLM impact |

**Of 8 v2 steps, only #5 (recon cache) directly cuts quick-mode
LLM-call count, and only on re-scans.** Everything else targeted
the dispatch path that quick mode already disables.

## What quick mode actually costs today

Per the v2 doc's call-breakdown table, after Phase 1 + step 5
landed:

| Phase | Calls (quick mode, first scan) |
|---|---:|
| Boot / system-prompt | 1 |
| Recon (interpretation of pipeline output) | 5–15 |
| Surface mapping | 3–10 |
| Specialist dispatch | **0** (cap=0) |
| Lead-between-dispatches | 0 |
| Lead-direct-tool-calls (probing via `scan_sqli` etc.) | 5–15 |
| Verification (LLM-driven verifier) | 5–15 |
| Report synthesis | 3–8 |
| **Total** | **22-64 calls** (median ~35) |

On Gemini Flash (~$0.000075 / 1K input tokens, ~$0.0003 / 1K
output) with ~80K cached prompt + ~2K per call: median quick scan
costs ~$0.15-0.30. Gemini free-tier (20 requests/day) cannot
complete a single quick scan. The user's complaint — "quick is
not supposed to call llm much" — is correct intuition; the
current implementation does not match the name.

The v2 arc reduced *deep* mode dramatically. It did not move
quick mode meaningfully.

## Goal

**Quick mode at ≤10 LLM calls per scan, ≤$0.05 on Flash, with
zero recall regression on benchmark `must_find` findings that
deterministic tools can already catch.**

Quick mode is explicitly *not* a thorough scan — it's "the
deterministic stack with a thin LLM layer for planning and
synthesis." Any `must_find` finding that requires multi-step LLM
reasoning will be missed in quick mode, by design. That's already
the case today; this proposal just makes quick mode cost match
its capability honestly.

## Proposal — four steps

Listed lowest-risk first, same discipline as the v2 arc.

### V3-1 — Lead iteration cap (P0, smallest unit)

Mirror Phase 1's `_DISPATCH_COUNT` pattern at the lead-loop level.

```
mode      | lead iteration cap
initial   | 6
quick     | 12
standard  | 60
deep      | unbounded (current)
```

**Engine change:**
- `strix/agents/lead_agent/` adds a per-run `_LEAD_ITER_COUNT`
  counter incremented on every lead-LLM call
- New helper `get_scan_mode_lead_iter_cap()` reads
  `STRIX_SCAN_MODE` (same env as the dispatch cap)
- When the lead exceeds the cap, the lead's next decision is
  forced to `advance_workflow_phase` (or `finish_scan` if
  already in the report phase) — graceful termination
- Override env: `STRIX_LEAD_ITER_OVERRIDE=<int>`
- Kill switch: `STRIX_LEAD_ITER_CAP_DISABLED=1`

**Recall-safety:**
- Quick mode at iter=12 covers: boot (1) + 1-2 recon interpretation
  + 3-4 probe decisions + 2-3 finding-emission + 1 report. That
  leaves ~1-2 buffer iterations.
- If the cap forces termination before all probes ran, the
  partial-scan flag in `run_meta.json` marks the run as
  `incomplete_due_to_iter_cap` so the wrapper / operator knows
  to re-run with a higher cap or different mode.
- **Recall canary:** any benchmark `must_find` finding that
  *deterministic specialist tools alone catch* must still land
  on quick mode with iter_cap=12. If a canary breaks, the cap
  is too tight for quick mode and the cap is loosened (not the
  canary).

**Cost cut:** ~50% on quick (35 → ~12 calls). **Effort: S.**

### V3-2 — Skip the LLM verification phase in quick (P0)

Today the verification phase fires the LLM for every finding,
regardless of how the finding was discovered. But:

- Deterministic specialists (`scan_sqli`, `scan_xss`, etc.) emit
  findings that are *already verified* — they only emit when the
  oracle fires (payload reflected, time-based delta, etc.).
- The FP filter (step 1) already removes structurally-noisy
  findings before they reach the verifier.
- Quick mode's selling point is "the deterministic stack catches
  the easy wins"; the LLM verifier is overhead.

**Engine change:**
- In `strix/agents/verification_pipeline.py`, add a quick-mode
  policy: findings with `discovery_method.primary` in
  {`cve_pattern_match`, `sast_rule`, `sca_lookup`,
  `nuclei_template`, deterministic specialist} skip the LLM
  verifier and advance directly to `VERIFIED` with
  `evidence=[{method: "deterministic_specialist", outcome:
  "PASSED"}]`.
- LLM-discovered findings (`discovery_method.primary ==
  "ai_specialist"`) — which only exist in standard/deep — still
  flow through the verifier as today.
- Kill switch: `STRIX_QUICK_SKIP_VERIFIER_DISABLED=1`.

**Recall-safety:**
- The deterministic specialists' verification logic is already
  the source of truth for their findings — they don't emit
  uncertain results. Wrapping their output in an LLM verifier
  adds nothing for confidence; it only adds cost.
- Findings can still be downgraded by the FP filter (R6 / R7 /
  R8) — those rules already run BEFORE the verifier, so this
  change doesn't touch FP-filter behavior.
- **Recall canary:** every `must_find` finding emitted by
  deterministic specialists on the benchmark stays at severity
  ≥ verified after this change. If a canary breaks, the rule
  that demoted it reverts.

**Cost cut:** ~7% of total (the entire verification phase). On
quick mode with ~5-15 verifier calls saved, that's significant.
**Effort: S.**

### V3-3 — Templated report in quick mode (P1)

The report phase synthesizes the executive summary, finding table,
and remediation guidance. In quick mode where the threat model is
"deterministic findings only," this is mostly templated content:

- Finding rows: already structured in `findings.json`
- Per-finding remediation: already auto-filled from CWE templates
  (step 7 of v2)
- Per-finding impact: comes from `business_impact_plain` (also
  templated from step 7)
- Executive summary: a single short paragraph describing scope
  + counts

**Engine change:**
- New module `strix/tools/finish/quick_report_renderer.py` that
  produces a Markdown / JSON report from `findings.json` alone,
  with zero LLM calls.
- The lead's `finish_scan` tool, when `scan_mode == "quick"`,
  invokes the templated renderer instead of the LLM-synthesized
  one.
- Standard/deep modes are unchanged.
- Kill switch: `STRIX_QUICK_TEMPLATED_REPORT_DISABLED=1`.

**Recall-safety:**
- The findings themselves are unchanged — only the report-text
  rendering changes.
- Customer-facing report quality may be lower-fidelity in quick
  mode (no LLM-written narrative). That's an explicit tradeoff
  consistent with quick mode's positioning.
- **Recall canary:** every `must_find` finding still appears in
  the templated report with severity + endpoint + brief
  description, all sourced from `findings.json` fields the
  specialists already emit.

**Cost cut:** 3-8 calls saved (the entire report phase).
**Effort: M.**

### V3-4 — Batched recon interpretation (P1)

Today the lead invokes `webapp_recon_pipeline` (which is mostly
deterministic), then makes multiple sequential LLM calls to
interpret each section of the result (fingerprint, crawl,
well-known, TLS, headers). Most of this can be a single
structured-output call: "given this surface map, return the
prioritized probe list as JSON."

**Engine change:**
- New tool `interpret_recon_and_plan_probes(surface_map_path)`:
  one LLM call that consumes the entire `webapp_surface_map.json`
  and returns a structured probe plan
  (`[{endpoint, methods, suspected_categories, why}]`).
- Quick mode's prompt teaches the lead to call this once after
  `webapp_recon_pipeline` rather than walking the result piece
  by piece.
- Standard/deep modes can opt in but the existing flow is
  unchanged by default.
- Kill switch: `STRIX_BATCHED_RECON_INTERP_DISABLED=1`.

**Recall-safety:**
- One structured call sees the entire surface; the probe plan it
  emits cannot miss anything more than the sequential approach
  could (in fact it has *more* context, not less).
- The lead is still free to override the plan (it's a suggestion
  in the result, not an enforced sequence).
- **Recall canary:** the probe plan must include every endpoint
  flagged with `suspected_categories ≠ []` that contains a
  `must_find` from benchmark.

**Cost cut:** 5-10 calls → 1 call on the recon-interpretation
slice. **Effort: M.**

## Stacked cost projection

| Phase | Today (quick) | After V3-1 (lead cap) | After V3-1+2 (skip verifier) | After V3-1+2+3 (templated report) | After all four |
|---|---:|---:|---:|---:|---:|
| Boot | 1 | 1 | 1 | 1 | 1 |
| Recon interp | 5-15 | 3-5 | 3-5 | 3-5 | **1** |
| Surface mapping | 3-10 | 2-3 | 2-3 | 2-3 | folded into V3-4 |
| Lead-direct probes | 5-15 | 3-5 | 3-5 | 3-5 | 3-5 |
| Verification | 5-15 | 3-5 | **0** | 0 | 0 |
| Report | 3-8 | 2-3 | 2-3 | **0** | 0 |
| **Total** | **22-64** | **14-22** | **9-17** | **8-15** | **5-10** |
| Median | 35 | 18 | 13 | 11 | **8** |

**8 calls × ~80K cached prompt + ~2K each ≈ $0.02-0.05 per
quick scan on Flash.** Comfortably under Gemini free-tier's
20-RPD ceiling for the first scan of the day. Standard mode
unchanged.

## Suggested ordering

| Step | Risk | Effort | Cost cut | Recall safeguards |
|---|---|---|---:|---|
| **V3-1** lead iter cap | low | S | ~50% on quick | iter_cap=12 floors the recall-safe coverage; canary on benchmark must_finds |
| **V3-2** skip verifier in quick | low | S | ~25% of remaining | restricted to deterministic-discovery findings; LLM-discovered ones still verify |
| **V3-3** templated report | low | M | ~15% of remaining | finding contents unchanged; only narrative changes |
| **V3-4** batched recon interp | medium | M | ~30% of remaining | structured-output call sees more context, not less; canary on must_find endpoint coverage |

Same ordering doctrine as the v2 arc: every step ships with a
recall canary, a kill switch, and benchmark sweep gate. A step
that drops a `must_find` reverts.

## What this does NOT change

- **Standard / deep mode**: zero impact. All four changes are
  gated on `scan_mode == "quick"`.
- **Recall on reasoning-bound findings**: BOLA, BFLA, mass
  assignment, business logic, chained exploits — these were
  already missed in quick mode (cap=0 on dispatch). v3 doesn't
  make this worse.
- **Quick mode's *capability* envelope**: this proposal makes
  the cost match what quick mode actually delivers. If
  customers need reasoning-bound findings, they need standard
  or deep — that's already the case; v3 just makes the
  positioning honest.

## Validation plan

- **Per-step unit tests**: every step ships with a positive
  + negative test + a recall canary against benchmark fixtures.
- **Benchmark gate** (when an LLM key is available): run
  vampi/quick on every PR; recall_must_find must not drop;
  cost_usd must drop in step with the stacked-cost table.
- **Cost-floor canary**: if quick mode ever costs >$0.10 on
  Flash after all four steps land, something regressed —
  triggers an explicit alert in the benchmark workflow.
- **Override sanity**: every step's kill switch is exercised
  by a test so an operator can roll any step back individually.

## Non-goals

- **Replacing standard/deep**: this is quick-mode-specific.
- **Removing the LLM lead entirely**: the lead remains
  LLM-driven; we just cap how many calls it can make in quick
  mode and avoid round-tripping for templated work.
- **Adding new finding classes to quick mode**: the v3 changes
  are about *cost*, not *coverage*. The set of vulnerability
  classes quick mode catches today is the set it catches after
  v3. Coverage expansion is a separate proposal.

## Relationship to other work

- **v2 arc** (#334-#344): complementary. v2 made deep+standard
  cheaper; v3 makes quick honestly lightweight.
- **MA-S2 alignment** (#338): orthogonal. v3's templated-report
  output still produces the per-finding `contextual_priority` +
  `attack_paths` references; MA-S2 attestation isn't affected.
- **Webappsec wrapper**: V3-3's templated report becomes the
  default the wrapper renders in the customer UI for
  quick-mode scans. No wrapper change required — same
  `findings.json` shape feeds in.

## Open questions

1. **Should V3-1's `STRIX_LEAD_ITER_OVERRIDE` allow a per-target
   override** (per the wrapper's `target_metadata`)? Or scan-wide
   only? Lean: scan-wide for now; per-target if a customer hits
   a corner case.
2. **Quick mode's verifier-skip policy** assumes deterministic
   specialists never emit a false positive. The FP filter (step
   1) already catches structural noise, but an FP that slips
   the filter would land as `VERIFIED` without LLM second-check.
   Mitigation: a follow-up step adds a "FP-skip-verifier"
   feedback metric the wrapper can flag to detect drift.
3. **Should V3-4 ship as a tool the lead chooses to call**, or
   as an *implicit* step in the workflow phase 3 (surface
   mapping) transition? Lean: explicit tool — the lead retains
   agency and can fall back to the per-section flow when needed.
