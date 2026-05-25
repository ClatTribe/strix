# Metrics roadmap — shipping list to align with `docs/metrics.md`

**Status**: **Wave 1-3 shipped** as of 2026-05-25. 11 of 19 metrics
now measurable; only Wave 4 (hypothesis explorer + cost curves)
remains, and it's strictly blocked on L2+ feature work.
**Last updated**: 2026-05-25.
**Source**: `docs/metrics.md` defines the 19 metrics + per-layer targets.
This doc is the execution plan to make them visible.

## Ship log (Wave 1 → Wave 3)

| iter | item | PR | tests | status |
|---|---|---|---|---|
| iter-31.1 | FP-suppression bench + L1.5 dismissal surfacing | #459 | 22 | ✓ merged |
| iter-31.2 | Chain detection bench + `chains_emitted` surface | #460 | 31 | ✓ merged |
| iter-31.3 | Severity calibration bench | #461 | 28 | ✓ merged |
| iter-31.5 | Corroboration rate bench + tracer rollup | #462 | 29 | ✓ merged |
| iter-31.6 | `phase_correlate_emissions` bench + tracer surface | #463 | 37 | ✓ merged |
| iter-31.7 | `reproducibility_rate` aggregator + bench | #464 | 32 | ✓ merged |
| iter-31.8 | `context_completeness` + `actionable_rate` bench | #465 | 40 | ✓ merged |
| iter-31.9 | `surface_discovery_breadth` bench | #466 | 20 | ✓ merged |
| iter-31.10 | `novel_finding_rate` bench | #467 | 26 | ✓ merged |
| iter-31.12 | `explanation_clarity` bench (heuristic + LLM-as-judge) | #468 | 22 | ✓ merged |
| iter-31.11 | `patch_correctness` bench + tracer rollup | #469 | 12 | ✓ merged |

**Net delivery**: 11 PRs, ~8.4K LOC of bench + scoring infrastructure,
~299 new tests, all merged to main behind a consistent anti-overfit
guard pattern (source-grep regression tests forbidding SUT-specific
tokens in every new bench source).

## Why this list

`docs/metrics.md` defined 19 metrics across 5 axes. Of those, **3 are
measured today**: `must_find_recall`, `juice_shop_full_recall`, and
`cost_per_matched_finding`. The other 16 are silent — including every
single metric that justifies L1.5 + L2's existence as architecture
layers.

This roadmap turns each silent metric into a measured one. Two
categories of work per metric:

1. **Signal creation** — make sure the LAYER emits the data point
   (often this already exists internally but is dropped before reaching
   the bench).
2. **Bench measurement** — build the scorer that reads the signal
   and compares to ground truth (often new fixture YAML fields).

---

## Per-metric implementation matrix

Status legend: ✓ done · 🚧 partially built (signal exists, bench missing) · ⬜ not started · ⛓ blocked on prerequisite

| # | Metric | Axis | Layer | Bench source | Status |
|---|---|---|---|---|---|
| 1 | `must_find_recall` | detection | L1 | `bench_l1_only.py` | ✓ DONE |
| 2 | `juice_shop_full_recall` | detection | L1+L2 | `bench_l2_juiceshop_full.py` | ✓ DONE |
| 3 | `chain_detection_rate` | detection | L1.5 | `bench_chains.py` (iter-31.2) | ✓ DONE |
| 4 | `novel_finding_rate` | detection | L2+ | `bench_novel.py` (iter-31.10) | ✓ DONE |
| 5 | `surface_discovery_breadth` | detection | L1 | `bench_surface.py` (iter-31.9) | ✓ DONE |
| 6 | `fp_rate` | quality | L1.5 | `bench_fp_suppression.py` (iter-31.1) | ✓ DONE |
| 7 | `severity_tier_accuracy` | quality | L1.5 | `bench_severity.py` (iter-31.3) | ✓ DONE |
| 8 | `reproducibility_rate` | quality | L2.5 | `bench_reproducibility.py` (iter-31.7) | ✓ DONE |
| 9 | `context_completeness` | quality | L1.5 | `bench_context.py` (iter-31.8) | ✓ DONE |
| 10 | `dismissal_accuracy` | quality | L1.5 | paired with #6 | ✓ DONE |
| 11 | `wall_seconds` | cost | all | both benches | ✓ DONE |
| 12 | `cost_per_scan_usd` | cost | L2+ | `bench_l2_juiceshop_full.py` | ✓ DONE |
| 13 | `cost_per_matched_finding_usd` | cost | L2+ | derived | ✓ DONE |
| 14 | `tokens_input/output/cached` | cost | L2+ | JSON output | ✓ DONE |
| 15 | `tools_invoked` | cost | all | bench breakdown | ✓ DONE |
| 16 | `hypothesis_generation_rate` | reasoning | L2+ | ⛓ feature not built (Wave 4) | ⛓ BLOCKED |
| 17 | `corroboration_rate` | reasoning | L1.5 | `bench_corroboration.py` (iter-31.5) | ✓ DONE |
| 18 | `chain_depth_p95` | reasoning | L1.5+L2 | paired with #3 | ✓ DONE |
| 19 | `phase_correlate_emissions` | reasoning | L2 | `bench_phase_correlate.py` (iter-31.6) | ✓ DONE |
| 20 | `patch_correctness` | output | L2+ | `bench_patcher_correctness.py` (iter-31.11) | ✓ DONE |
| 21 | `explanation_clarity` | output | L2 | `bench_explanation.py` (iter-31.12) | ✓ DONE |
| 22 | `actionable_rate` | output | L2 | `bench_context.py` (iter-31.8) | ✓ DONE |

**Scoreboard**: 21 / 22 metrics measurable (one is dependency-blocked
on L2+ features that don't exist yet). The 3/19 from session start
is now 21/22.

---

## Shipping waves

### Wave 1 — L1.5 moat metrics (3 items, ~1 week)

**Goal**: prove L1.5 reduces FPs by ≥30%, calibrates severity to ≥85%
accuracy, and detects ≥40% of chained attacks. These are the metrics
no competitor measures and the product's defensible moat.

| iter | Item | Effort | Signal | Bench |
|---|---|---|---|---|
| **iter-31.1** | `expected_dismissed[]` field schema + bench scorer for `fp_rate` + `dismissal_accuracy` | S (~250 LOC) | already-built FP filter starts surfacing its decisions in tracer + tool_results | new `bench_fp_suppression.py` |
| **iter-31.2** | `expected_chains[]` field schema + bench scorer for `chain_detection_rate` + `chain_depth_p95` | M (~400 LOC) | surface iter-27.2 `mid_scan_correlate` emissions as synthetic ToolResult entries (same pattern as iter-30.3) | new `bench_chains.py` |
| **iter-31.3** | `expected_severity_tier` per finding + bench scorer for `severity_tier_accuracy` | S (~200 LOC) | already-emitted but bench ignores | new `bench_severity.py` |
| **iter-31.4** | Add 3 fixture overlays: juice-shop, vampi, flask-vuln expected.yaml extended with `expected_dismissed[]` + `expected_chains[]` + `expected_severity_tier` | M (~150 LOC YAML + curation time) | n/a | enables 31.1-31.3 to actually score |

**Outcome**: L1.5's value becomes a number in the bench, not an architectural claim.

### Wave 2 — signal surfacing (5 items, ~1 week)

**Goal**: every layer's existing emissions reach the bench harness. Most
of this is "iter-30.3 patterns applied to the other emitters" — small
PRs each.

| iter | Item | Effort | What it surfaces |
|---|---|---|---|
| **iter-31.5** | Surface `corroborator_ledger` co-occurrence count per finding as synthetic ToolResult | S (~150 LOC) | `corroboration_rate` (#17) |
| **iter-31.6** | Surface `phase_correlate` emissions per phase as synthetic ToolResult | S (~150 LOC) | `phase_correlate_emissions` (#19) |
| **iter-31.7** | Aggregate `PocVerification.confidence` per scan as `reproducibility_rate` field in bench JSON | S (~120 LOC) | `reproducibility_rate` (#8) |
| **iter-31.8** | `bench_context.py` — for each finding, check field-presence of file+line / author / fix-hint / exploit-vector / next_probes; compute `context_completeness` + `actionable_rate` | M (~300 LOC) | `context_completeness` (#9) + `actionable_rate` (#22) |
| **iter-31.9** | `bench_surface.py` — aggregate `endpoints_discovered` across prepass tools; compare to `expected_endpoint_count` if present in YAML | S (~200 LOC) | `surface_discovery_breadth` (#5) |

**Outcome**: 7 more metrics visible (corroboration, phase correlate, reproducibility, context, actionable, surface, paired chain depth).

### Wave 3 — cost / novelty / output (3 items, ~1-2 weeks)

**Goal**: surface L2+'s differentiation evidence — novel-finding rate,
patcher correctness, explanation clarity. These are the metrics that
sell strix over Snyk/Aikido to dev-persona customers.

| iter | Item | Effort | What it shows |
|---|---|---|---|
| **iter-31.10** | `bench_novel.py` — load KEV + nuclei templates + sqlmap payload corpora; diff strix findings against; compute `novel_finding_rate` | M (~500 LOC + corpora load) | L2+ differentiation vs OSS toolchain |
| **iter-31.11** | `bench_patcher_correctness.py` — apply each patcher-emitted diff to a sandbox clone of the SUT source; run that repo's test suite; compute compile + pass rate | L (~800 LOC + per-fixture test-runner) | dev-persona "auto-PR works" pitch |
| **iter-31.12** | `bench_explanation.py` — LLM-as-judge (Claude/Gemini Pro) rates each finding's `description` field 1-5 against a rubric (clarity / actionability / reasoning) | M (~400 LOC) | dev-persona explainability pitch |

**Outcome**: 3 more metrics visible (novel, patch correctness, explanation clarity). Plus the dev-tier conversion narrative is now backed by numbers.

### Wave 4 — reasoning architecture (DEPENDS on L2+ features, ~3-4 weeks)

**Goal**: hypothesis-driven exploration measurement. ONLY worth building
once the L2+ feature itself ships.

| iter | Item | Effort | Notes |
|---|---|---|---|
| **iter-32.1** | Build hypothesis explorer (was iter-29 proposal — defer for measurement) | L (~600 LOC) | new module in `strix/agents/lead_agent/` |
| **iter-32.2** | `bench_hypothesis.py` — count per-L1-finding follow-up dispatches | S (~150 LOC) | requires 32.1 |
| **iter-32.3** | `bench_hypothesis_replay.py` — replay HackerOne disclosed reports; measure rediscovery rate | L (~1000 LOC + report curation, $$$ corpus work) | the "real-world" signal |
| **iter-32.4** | Build budget governor + per-mode model routing | M (~400 LOC) | required for `bench_cost_curves.py` |
| **iter-32.5** | `bench_cost_curves.py` — same fixture × quick/standard/deep modes, plot recall × cost | M (~300 LOC) | the dev-vs-engineer tier-positioning chart |

**Outcome**: full 19/19 metrics measurable.

---

## Critical-path ordering

```
   Wave 1 ──┐
            ├── enables Wave 2 (some)
   Wave 2 ──┤
            ├── enables L1.5 + L2 architectural-value narratives
   Wave 3 ──┘
            ↓
   (defer) Wave 4 — only when L2+ features themselves are shipped
```

**Strict prereqs:**
- 31.1 / 31.2 / 31.3 all depend on 31.4 (fixture YAML overlays). Can build the bench code in parallel, but need a fixture to score against.
- 31.5 / 31.6 / 31.7 are independent of Wave 1.
- 31.10 / 31.11 / 31.12 are independent of Wave 1 + 2 — can ship sooner if needed for tier-conversion pitches.
- Wave 4 strictly depends on the L2+ features (hypothesis explorer + budget governor) actually existing first.

**Recommended order:**

```
Day 1-3   :  31.4 (fixture overlays) + 31.1 (fp suppression bench)
Day 4-5   :  31.2 (chains bench) + 31.3 (severity bench)
Day 6-8   :  Wave 2 in parallel  — 31.5 / 31.6 / 31.7 / 31.8 / 31.9
Day 9-12  :  31.10 (novel)
Day 13-18 :  31.11 (patcher correctness)
Day 19-21 :  31.12 (explanation)
After:    :  Wave 4 only if and when L2+ features ship
```

**~3 weeks of bench-overhaul work makes all 19 metrics visible.** That's
the right next phase, before any more detection-lift iters (iter-30.5+).

---

## Signal-creation work — what each LAYER needs to ship to feed the benches

The bench is half the equation. The OTHER half is making sure each layer
actually emits the data point. Here's what already exists vs. what needs
to be added per layer:

### L0 (signature corpora)
- ✓ rule_id, severity, target — all emitted
- ⬜ `corpus_provenance` field (which corpus this came from — for `novel_finding_rate` denominator)
- ⬜ Surface skipped rules (template fired but didn't match) — for `dismissal_accuracy` baseline

### L1 (OSS specialist tools)
- ✓ findings with file+line+endpoint
- ✓ `partial` status with reason
- 🚧 `next_probes_suggested[]` field exists in SpecialistResult but not consistently populated — needed for `actionable_rate`
- ⬜ `discovered_endpoints[]` aggregate across all L1 specialists — needed for `surface_discovery_breadth`

### L1.5 (enrichment)
- 🚧 `pre_emission_fp_filter` decisions: dismissed findings get DROPPED before tracer; need to RECORD them so `fp_rate` is measurable
- 🚧 `corroborator_ledger` counts co-occurrences but doesn't add the count to the surviving finding — needed for `corroboration_rate`
- 🚧 `mid_scan_correlate` emits chain_summary blocks but they're attached to a chain.id with members[] — bench needs to read them
- ✓ `surface_priority`, `exploitability`, `git_blame` all annotate findings
- ✓ `hygiene` writes a per-finding score
- ⬜ Need: a single rollup function that emits an "L1.5 enrichment report" per scan with all of the above stats

### L2 / L2 deep (LLM-driven)
- ✓ tokens, cost, agents-count, tools-count via strix CLI summary panel
- ✓ findings with description + evidence
- 🚧 PoC verifier confidence (verified/likely/suspected/dismissed) attached to each finding — bench needs to aggregate
- ⬜ `reasoning_trace` field populated more consistently
- ⬜ Per-finding `cost_attributed_usd` (what tokens went toward producing this specific finding) — for `cost_per_matched_finding` per-finding rollup

### L2+ (hypothesis explorer, devil's advocate)
- ⬜ Doesn't exist yet — build before measuring

### L3 (portfolio)
- ⬜ Doesn't exist yet — build before measuring

---

## Concrete next PR (the kickoff)

**iter-31.1 — `bench_fp_suppression.py` + L1.5 fp_filter dismissal surfacing**

This single PR delivers the highest-leverage Wave 1 item:

1. **Signal**: modify `strix/l15/fp_filter.py` to APPEND dismissed-finding-shapes to a `dismissed_findings[]` list on the prepass summary (not just drop them). Each entry: `{rule_id, file, line, dismissal_reason}`.
2. **Schema**: add `expected_dismissed[]` field shape to expected.yaml (each entry: `{id, category, file, line, reason}` — describes a planted FP-decoy that L1.5 SHOULD dismiss).
3. **Bench**: new `bench_fp_suppression.py`:
   - Reads `expected_dismissed[]` from fixture
   - Reads `summary.dismissed_findings[]` from scan
   - Computes `dismissal_accuracy` = (correctly_dismissed / expected_dismissed_total)
   - Computes `fp_rate` = (emitted_FPs_NOT_in_expected / total_emissions)
4. **Fixture overlay**: extend juice-shop + vampi + flask-vuln expected.yaml with 3-5 planted decoys each (e.g., `csrf-token in /api/test/...` — a CSRF finding in a test-fixture endpoint that L1.5 should dismiss).
5. **Tests**: regression suite asserting the dismissed-findings list shape + scorer math.

Estimated effort: **~400 LOC across 6 files, ~2 days.**

**Outcome**: First number in the bench that proves L1.5 isn't just architecture — it's measurably reducing FPs. The conversation with a developer evaluating strix vs. Snyk gains a concrete data point on the L1.5 moat.

---

## Summary

| Bench surface today | Wave 1-3 baseline | Now (Wave 1-3 shipped) |
|---|---|---|
| 3/19 measured | 19/19 target | **21/22 measurable** (1 blocked on Wave 4 feature) |
| 0 L1.5 moat metrics | 5 L1.5 metrics | **5/5 shipped** (fp_rate, severity_tier_accuracy, chain_detection_rate, corroboration_rate, context_completeness) |
| 0 reasoning metrics | 4 reasoning metrics | **3/4 shipped** (corroboration_rate, chain_depth_p95, phase_correlate_emissions); hypothesis_generation_rate blocked |

**~3 weeks of focused bench-overhaul work** + ~12 small/medium iters
unlocks all 19. Most of the signal work is "surface what's already
being computed" — only `novel_finding_rate`, `patch_correctness`, and
`explanation_clarity` require fresh logic. The rest is plumbing.

After this work lands, the headline narrative shifts from "3/109" (a
single coverage axis we're underperforming on) to a multi-axis
scorecard where strix's actual differentiators — L1.5 enrichment + L2
reasoning + cost economics — become defensible numbers.
