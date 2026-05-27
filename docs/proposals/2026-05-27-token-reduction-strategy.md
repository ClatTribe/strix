# Token reduction strategy — without losing finding recall

**Status:** SUPERSEDED by
`2026-05-27-token-reduction-v2-stratified-compaction.md`.
This v1 had 6 static per-block compression rules. The v2 reframes
the same problem using Claude Code's stratified-by-recency
compaction model — recent turns verbatim, mid-range summarized,
old aggressively compacted; decisions preserved, deliberations
summarized. Strictly subsumes this v1.

Kept in-tree because the v1 → v2 evolution shows why the
naive per-block approach misses signal/noise stratification.

**Date:** 2026-05-27.
**Author:** Q2 thread, iter-Q1 follow-on.

## Constraint

**Token reduction must not reduce detection recall.** This proposal
is explicitly engineered around that constraint. Every technique
below ships behind an opt-out env flag and is validated against
`bench_owasp_benchmark.py` + `bench_l2_juiceshop_full.py` (multi-
trial median, post iter-Q1.4) **before** landing. Any technique
that drops the median Youden or completion rate by more than 1pp
relative to the iter-37.14 baseline is reverted.

## Problem statement

Last L2 Juice Shop bench (iter-37.12, single-trial, pre-fixes):
- **9.7M input tokens** across the run
- **8.7M cached** (90% cache hit rate — already saturated)
- **12 tool calls**
- **→ 810K tokens / turn**

Industry-standard agent benchmarks target **50-150K/turn**. We're
~5-10× over that. The cost ($3.78 for that run) and wall clock
(1212s for 12 tool calls = 100s/turn) both scale roughly linearly
with per-turn token volume.

But naive reduction risks dropping detection signal. The
`list_pending_findings` queue, `SecurityContext.AuthState`, tech-
stack fingerprint, and active tool catalog are all **load-bearing
for detection** — drop them and the LLM can't see what L1 found,
can't auth into post-auth surface, can't pick the right tool. Token
reduction must target **redundancy**, not signal.

## Signal vs redundancy in the system prompt

Per-turn system prompt rendering decomposes into:

| Block | Token cost | Carries detection signal? | Reduction safe? |
|---|---:|---|---|
| Tool catalog (XML schemas, 13 tools × ~5K each) | ~65K | Yes — LLM picks tools from here | **Partial.** Tool *names + arg schemas* are signal; verbose descriptions are redundant after turn 1. |
| `SecurityContext` render (endpoints + auth + tech + signals) | 5-30K (grows) | Yes — load-bearing for post-auth + chain | **Partial.** Auth-states + tech-stack must stay; verbose `raw_headers` + old `partial_signals` are redundant. |
| Anchor-prepass tool_results (33 web tools × ~2K each) | 50-200K (huge) | Mixed — finding summaries are signal; raw stdout is redundant. | **Yes.** Replace raw stdout with summary line; full output stays addressable via drill-down tool. |
| Conversation history (compounds turn-over-turn) | scales linearly | Mixed — reasoning is signal; tool-result raw output is redundant. | **Yes.** Compress old tool outputs to one-liners; keep `think()` content intact. |
| Workflow state snapshot | ~2-5K | Yes — phase + counters drive decisions | No — already small. |
| Boilerplate (role, format reinforcement) | ~10K | Reinforcement only | **Yes.** Drop after turn 3 (LLM has seen it; cached cost is real but processing time scales with context length). |

Net redundancy: ~100-300K tokens/turn that can be removed without
touching detection signal.

## Concrete proposals (ranked by ROI per detection risk)

### Proposal #1 — Tool-output drill-down pattern (~50-200K/turn saved, lowest risk)

**Today**: a sandbox tool returns a result dict; the entire dict
streams into the next LLM turn's prompt as part of the conversation
history. nuclei's output for one CVE template match can be 2-5K of
text (rule_id, matched_path, request, response, evidence). Multiplied
across 33 prepass tools, this is the largest single redundancy.

**Proposal**:
1. Sandbox tools register a `summary` field on their return:
   ```python
   return {
       "findings": [...],
       "summary": "nuclei matched 3 templates: cors-misconfig, "
                  "exposed-swagger, default-credentials-found",
       "_full_output_id": "nuclei_20260527_140502.jsonl",
   }
   ```
2. The tracer-side L1.5 propagation hook already captures the
   findings (iter-35.4). It also stores the `_full_output_id` →
   raw output mapping in `<run_dir>/tool_outputs/<id>.json`.
3. The conversation-history renderer replaces the full result with
   the `summary` field. Full output is accessible via a new tool:
   `read_tool_output(tool_output_id) → str`.

**Detection guarantee**: the FINDINGS dict (the signal) is untouched.
Only the raw stdout (the redundancy) is replaced with a summary.
LLM can still drill into raw output on demand via the new tool.

**Validation**: run OWASP Benchmark + Juice Shop multi-trial bench
(N=5 each) before/after; median Youden + median completion rate
must not regress.

**Implementation**: ~1 day. Touches:
- `strix/tools/registry.py` — add optional `summary_fn` to registration
- `strix/runtime/tool_server.py` — emit summary alongside raw findings
- `strix/agents/lead_agent/lead_agent.py` — conversation-history
  renderer swaps full output for summary
- New tool: `read_tool_output`

### Proposal #2 — SecurityContext compression after turn N (~10-30K/turn saved, low risk)

**Today**: `render_for_prompt()` in `security_context.py` emits the
full SECURITY CONTEXT block every turn — endpoints (up to 30), auth
states, tech_stack (with `raw_headers`), partial_signals (up to 20).

**Proposal**: after turn 5, render only the load-bearing subset:
- `auth_states` (always — LLM needs labels to call scan_idor)
- `tech_stack` core fields (server, framework, database, language —
  not `raw_headers`)
- Top 10 endpoints by `surface_priority` × `last_status`
- Top 5 `partial_signals` by recency

The full set stays queryable via a new tool: `get_security_context(
section: "endpoints" | "auth" | "tech" | "signals" | "all"
)`.

**Detection guarantee**: auth + tech stay in the prompt every turn;
the truncated endpoints/signals are still in memory + queryable.
The LLM can't miss a detection signal it had access to.

**Validation**: same as Proposal #1.

**Implementation**: ~0.5 day. Touches `security_context.py:render_for_prompt`.

### Proposal #3 — Tool schema description trimming for invoked tools (~5-15K/turn saved, low risk)

**Today**: every tool's full XML schema (param descriptions, examples,
edge cases) renders every turn. A 1-page description per tool ×
13 tools = ~65K every turn.

**Proposal**: after a tool is invoked at least once in the
conversation, drop its description and keep only the bare signature
(`tool_name(arg1: type, arg2: type)`). LLM has seen the description
already and the signature is sufficient for re-invocation.

**Detection guarantee**: never-invoked tools keep full descriptions
(LLM needs them to make first-time selection decisions). Once a
tool is "learned" (invoked once), the description is redundant.

**Validation**: same as Proposal #1.

**Implementation**: ~0.5 day. Touches the system-prompt assembly
in `lead_agent.py` — track invoked-tool set per conversation, swap
to short signature for repeats.

### Proposal #4 — Prepass tool_results sliding window (~30-150K/turn saved after turn 3, low risk)

**Today**: the anchor-prepass output (a 33-tool block for web/api)
is injected into the lead's FIRST system prompt as task context.
It persists in conversation history every turn after.

**Proposal**: after turn 3:
1. The full prepass block stays available via `read_prepass_summary()`
   tool.
2. The conversation history retains only the prepass's *top-line
   summary* (`"prepass ran 33 tools, 12 succeeded, 47 findings
   emitted, top-5 by surface_priority: ..."`).

**Detection guarantee**: `list_pending_findings` continues to surface
every L1.5-enriched finding regardless of where they appeared in
the conversation. The prepass tool_results are just the L1 raw
output; their semantic content is in the findings queue.

**Validation**: same as Proposal #1.

**Implementation**: ~0.5 day.

### Proposal #5 — Two-tier model routing (~30-50% cost cut, MEDIUM risk)

**Today**: every LLM turn uses one model (`STRIX_LLM=gemini-flash`
in current runs). Tool-selection turns (cheap, format-bound) cost
the same as chain-reasoning turns (expensive, semantic).

**Proposal**: classify each turn at compose-time:
- **Tool-selection turns** (the LLM picks a single tool from the
  catalog) → route to a small/fast model (Flash, Haiku)
- **Chain-reasoning turns** (the LLM ties multiple findings into a
  chain or writes a PoC) → route to a frontier model
  (Sonnet, Opus)

Classifier signal: when the previous turn surfaced a chain finding
OR the current `think()` content contains "chain" / "exploit" /
"poc" keywords, route to the frontier model. Otherwise, Flash.

**Detection risk**: HIGH if the classifier mis-routes. Tool-selection
on a frontier model is wasteful but safe. Chain-reasoning on Flash
is the case that breaks recall — the LLM might pick wrong tools or
fail to chain findings.

**Mitigation**: ship behind `STRIX_MULTI_MODEL_ROUTING=1` (opt-in),
NOT default-on. Validate against multi-trial Juice Shop with
explicit comparison: single-model Sonnet (baseline) vs multi-model
routing. Only enable when the multi-trial median COMPLETION RATE
(not just detection) is within 1pp.

**Implementation**: ~3 days. Touches `strix/llm/llm.py` (per-call
model routing) + classifier in `lead_agent.py`.

### Proposal #6 — Lossless conversation compression (post-turn-5, low risk)

**Today**: `MemoryCompressor` triggers at 90% context fill. By the
time it fires, we've already paid for 8.7M tokens of context.

**Proposal**: lower the threshold to 50% fill **for tool-output
content only**. Specifically:
1. Tool-output blocks older than the last 5 turns get compressed
   from full body → `[Tool X ran at turn T, summary: ...,
   full_output_id: <id>]`.
2. `think()` content, `create_vulnerability_report` calls, and
   user-facing messages are NEVER compressed.

**Detection guarantee**: only redundant tool output is compressed.
The LLM's own reasoning (`think`) and emitted findings stay intact.

**Validation**: same as Proposal #1.

**Implementation**: ~1 day. Refactor `MemoryCompressor` to apply
per-message-type rules.

## Combined expected impact

If all 6 ship and pass validation:

| Metric | Baseline (iter-37.12) | Target | Expected post-Q2 |
|---|---:|---:|---:|
| Tokens / turn | 810K | 100-200K | **~150K** (5×) |
| Cost / scan ($3.78) | $3.78 | $0.50-1.00 | **~$0.80** (5×) |
| Wall / turn | 100s | 30-50s | **~40s** (2.5×) |
| Detection recall | (current) | unchanged | unchanged ± 1pp |

The wall-clock factor is smaller than the token factor because
Flash's TTFT is mostly fixed; context-length impact on processing
time saturates around 200K input tokens.

## Validation methodology (mandatory)

Every proposal lands with this gate:

1. **Pre-baseline**: run `bench_multi_trial.py --bench
   owasp_benchmark --trials 5` AND `bench_multi_trial.py --bench
   l2_juiceshop_full --trials 5` on the CURRENT main branch. Record
   median Youden + median completion rate as the baseline.

2. **Implementation**: ship the proposal behind an opt-out env flag
   (default ON).

3. **Post-baseline**: re-run the same N=5 multi-trial benches with
   the proposal enabled.

4. **Gate**: PR merges only if BOTH benches' median (post) is within
   1pp of (pre). If completion rate drops 2+ pp, the proposal is
   REVERTED — no negotiation.

5. **Pager**: opt-out env flag (e.g. `STRIX_TOKEN_TRIM_DISABLED=1`)
   stays available for at least 2 release cycles so operators can
   bisect if a downstream regression appears.

## Iter sequence

| iter | scope | size |
|---|---|---|
| **iter-Q2.1** | Proposal #1 — tool-output drill-down. Foundation for others (introduces `read_tool_output`). | 1 PR, ~400 LOC, ~30 tests |
| **iter-Q2.2** | Proposal #2 — SecurityContext compression. | 1 PR, ~150 LOC, ~15 tests |
| **iter-Q2.3** | Proposal #3 — tool-schema description trimming. | 1 PR, ~200 LOC, ~15 tests |
| **iter-Q2.4** | Proposal #4 — prepass sliding window. | 1 PR, ~200 LOC, ~15 tests |
| **iter-Q2.5** | Proposal #6 — `MemoryCompressor` refactor (per-message-type rules). | 1 PR, ~300 LOC, ~20 tests |
| **iter-Q2.6** | Proposal #5 — multi-model routing. **Opt-in only.** | 1 PR, ~500 LOC, ~40 tests |
| **iter-Q2.7** | Combined bench: run all 6 enabled, validate against the iter-Q1 multi-trial baseline. Publish the cost/wall/recall delta in `docs/benchmark.md`. | bench only |

Total: 7 PRs, ~1750 LOC, 2-3 weeks of focused work.

## Risks + mitigations

- **Cache-hit rate regression**: shrinking the system prompt means
  the cached prefix is smaller, so cache savings shrink. The cost
  win is still real (fewer fresh tokens) but the absolute number
  is less than naive calculation. **Mitigated** by accounting for
  cache costs separately in the bench reports.

- **LLM relies on description more than we think**: Proposal #3
  assumes the LLM "remembers" tool descriptions after one
  invocation. If detection drops, revert by removing the
  per-conversation tool-set tracking.

- **Multi-model routing is high-variance**: Proposal #5 (the riskiest)
  ships opt-in only. Default users see no behavior change.

- **`read_tool_output` adds a tool call**: introducing a drill-down
  tool means the LLM might call it more often than expected, eating
  back the savings. **Mitigated** by capping drill-downs per turn
  (`STRIX_DRILL_DOWN_MAX_PER_TURN=3`) + measuring drill-down call
  frequency in bench output.

## What this changes about strix

Today's lead loop is "blast the LLM with full context every turn
and hope it picks the right tool." Post-Q2, it's "carefully curate
what the LLM sees, with everything else drill-downable on demand."
That's how real software engineering agents (Cursor, Aider) operate
— they don't put the whole codebase in every prompt; they put what's
relevant + an index.

The detection-preservation guarantee (multi-trial gate at <1pp
regression) is what makes this safe.

## Decision rule (proposed for CLAUDE.md §6)

> Every PR that touches the system-prompt assembly, tool catalog
> rendering, SecurityContext rendering, or conversation history
> compression MUST run `bench_multi_trial.py --bench owasp_benchmark
> --trials 5` AND `bench_multi_trial.py --bench l2_juiceshop_full
> --trials 5`. The PR description includes (pre, post) medians; PRs
> with completion-rate or Youden delta worse than −1pp are rejected
> without explicit justification.

This rule applies to every Q2 iter and to any future iter that
shrinks the per-turn context budget.

## See also

- Strategy doc: `docs/proposals/2026-05-27-benchmark-suite-strategy.md` (Q1)
- Multi-trial harness: `benchmarks/per_target/bench_multi_trial.py` (iter-Q1.4)
- L1 headline bench: `benchmarks/per_target/bench_owasp_benchmark.py` (iter-Q1.1)
- L2 chain-gap bench: `benchmarks/per_target/bench_webgoat_dual.py` (iter-Q1.2)
- Memory compressor: `strix/llm/memory_compressor.py`
- Prompt caching analysis: Anthropic's caching pricing (10% of fresh-token rate)
