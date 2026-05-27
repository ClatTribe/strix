# Token reduction v2 — stratified compaction (Claude Code style)

**Status:** proposal v2, supersedes
`2026-05-27-token-reduction-strategy.md`.
**Date:** 2026-05-27.

## Why a v2

The original Q2 proposal was 6 static compression rules keyed by
block type ("after turn N, do X to block Y"). It would work, but
it treats the context window as a flat thing to compress. **Claude
Code's compaction model is better**: the context window is a
stratified store where different content has different lifecycles
and value densities. Compress by recency tier × content type, not
by block.

This v2 leans into that. It also names the actual failure mode
the original proposal handwaved past: **the LLM's reasoning
(`think()` content) is mostly deliberation; the decisions are what
matter**. A compactor that preserves decisions and drops
deliberations gets most of the savings without losing signal.

## How Claude Code does it (the reference architecture)

Claude Code runs ~hour-long agent sessions on local code. Same
problem we have: context window fills up, finds + decisions + tool
outputs accumulate. Their answer:

1. **Stratified by recency**, not by block type. Recent turns:
   verbatim. Mid-range: summarized with tool outputs replaced.
   Old: aggressive compaction, just "X was decided / done."

2. **Auto-compact at ~90% fill** with progressive warning.
   `/compact <focus>` lets the user trigger explicit
   compaction with a focus instruction (e.g. `/compact prioritise
   the diagnosis findings`).

3. **A compaction transcript becomes a first-class artifact.**
   When compaction fires, the model produces a CompactSummary:
   high-level narrative + files touched + decisions made + open
   questions. That summary is what survives — the rest is dropped.

4. **Persistent breadcrumbs survive every cycle.** Memory files,
   TODO lists, files open in the workspace — these are anchored,
   not part of the recency stratum.

5. **Decisions, not deliberations.** The model's emit calls
   (`Edit`, `Write`, `Bash`) are the decisions. Tool outputs are
   the data the decisions were made on. The `text` blocks are the
   deliberation. Claude Code preserves the first two; the
   deliberation gets summarized.

Strix has all the same shapes:
- **Persistent breadcrumbs** = `workflow_state` snapshot,
  `SecurityContext`, `list_pending_findings` (the L1.5-ranked queue)
- **Decisions** = `create_vulnerability_report` calls, tool dispatch
- **Deliberation** = `think()` content, intermediate `text` blocks
- **Tool outputs** = the noisy bulk (nuclei stdout, sqlmap stdout, etc.)

The original Q2 proposal already protected breadcrumbs and decisions.
The miss was: it treated deliberation as preservable signal when
it's actually summarizable.

## The stratified model

Three recency tiers, with different rules per content type:

| Stratum | Turns | Tool outputs | think() | Tool calls | Findings emitted | Auth/SecCtx |
|---|---|---|---|---|---|---|
| **Hot** | Last 5 | Verbatim | Verbatim | Verbatim | Verbatim | Verbatim |
| **Warm** | Turn 5–N (N=20) | Summary line only; raw → `read_tool_output(id)` | First sentence + decision marker | Verbatim (the decision IS the call) | Verbatim | Verbatim |
| **Cold** | Older than turn N | "Tool X ran at turn T → {finding_count} findings" | Replaced with single-sentence summary from CompactSummary | Verbatim (tool name + key arg only) | Verbatim | Verbatim |

**Persistent anchors** (never touched by any stratum):
- `workflow_state` snapshot (current phase + counters + gates)
- `SecurityContext.AuthState` (auth labels + minimal fields — cookies/bearer captured)
- `SecurityContext.tech_stack` (server / framework / language)
- Top-N `list_pending_findings` (the L1.5-ranked queue)
- Active tool catalog signatures (name + args; descriptions only on
  first invocation per session)

**Compaction transcript** (a new first-class artifact):
- Emitted once per scan or every K turns (whichever first)
- Format: `## What we know so far` + `## What we've tried` + `##
  Open questions` + `## Findings emitted so far`
- Replaces the old conversation history when compaction fires
- Survives forever in the run output (`<run_dir>/compaction_
  transcript.md`)

## What the LLM sees on a steady-state turn (post v2)

```
SYSTEM PROMPT (~50-100K tokens, mostly cached)
├── Role + format reinforcement                  (~5K, dropped after turn 3)
├── Workflow state snapshot                      (~3K, full fidelity always)
├── SecurityContext compact render               (~5-15K, full auth + tech)
├── Tool catalog                                  (~30K turn 1 → ~10K steady-state via Q2.3)
├── Compaction transcript (if compacted)         (~10K, replaces cold turns)
└── Recent N=5 turns verbatim                    (~30-50K)
    + warm turns with summarized outputs        (~10-30K)
    + emit calls + decisions verbatim            (~5-10K)

LATEST USER + ASSISTANT TURNS (~10-50K, hot stratum)
```

Target: **100-200K tokens/turn at steady state** (vs current 810K).
Cost: drops ~5×. Wall: drops ~2.5×.

## Concrete techniques (revised, smaller surface than v1)

The v1 had 6 proposals. The v2 collapses several into one
architecture:

### Q2.1 — Stratified conversation compaction (replaces v1 #1, #4, #6)

A `ConversationCompactor` that runs every turn, classifies each
prior turn by recency stratum, applies per-stratum + per-content-
type rules. Produces a compacted conversation history for the next
LLM call.

**Key sub-behaviors:**
- Tool outputs go from verbatim → summary-line in the WARM stratum;
  fully replaced with `"<dropped, see compaction_transcript>"` in
  COLD.
- Old `think()` blocks get summarized to a single sentence in WARM,
  dropped entirely in COLD (the decision is in the tool call /
  emit call that followed, which IS preserved).
- Tool calls (the decisions) are preserved with full args at every
  stratum.
- `create_vulnerability_report` calls are preserved verbatim at
  every stratum (these are the canonical scan output).

**Detection guarantee**: every finding remains queryable via
`list_pending_findings` regardless of stratum. The HOT stratum
keeps the last 5 turns verbatim — enough for chain reasoning
across a multi-step exploit (most chains in iter-31.2 telemetry
fit in 3-7 turns).

**Validation**: same as v1 — multi-trial bench gate at <1pp
regression.

**~Impact**: 50-200K tokens/turn saved (compounds with turn count).

### Q2.2 — Compaction transcript artifact (NEW, Claude-Code-style)

A first-class scan artifact (`<run_dir>/compaction_transcript.md`)
that contains:
- The compacted summary of all COLD-stratum turns
- A running "what we know" + "what we've tried" + "open questions"
- The list of every emitted finding (with surface_priority,
  exploitability, corroborated_by)

Emitted on first compaction event, updated every K=10 turns.
The transcript REPLACES the dropped cold-stratum turns in the
system prompt — so the LLM still sees "what happened" without
the raw token cost.

**Why this matters**: in our last bench, the LLM made 12 tool
calls but burned 9.7M tokens. The cold stratum was bloated with
prepass tool outputs that were redundant by turn 5+. A
compaction transcript captures the SEMANTIC content of those
outputs in ~10K tokens instead of ~500K.

**Detection guarantee**: the compaction transcript is generated
by a deterministic summarizer (NOT another LLM call — that's
expensive AND adds variance). It pulls from `list_pending_
findings`, `SecurityContext`, `workflow_state.tool_results` —
all of which are L1.5-enriched + persisted regardless of
conversation state. The data the transcript represents is never
lost; only its raw representation is.

**~Impact**: 100-500K cold-stratum tokens replaced with ~10K
transcript.

### Q2.3 — Tool catalog progressive disclosure (kept from v1 #3)

Same as v1's Proposal #3. First invocation of a tool: full XML
schema. Subsequent invocations: just the signature.

LLM "learns" the tool on first call; doesn't need the verbose
description repeated.

**~Impact**: 5-15K/turn at steady state.

### Q2.4 — SecurityContext stratified rendering (kept from v1 #2)

Same as v1's Proposal #2. After turn 5, render only the
load-bearing subset (auth_states + core tech_stack + top-N
endpoints). Full set queryable via tool.

**~Impact**: 10-30K/turn.

### Q2.5 — Two-tier model routing (kept from v1 #5 — OPT-IN ONLY)

Same as v1's Proposal #5. Flash for tool-select turns, Sonnet for
chain reasoning turns. Riskier; ships opt-in.

**~Impact**: 30-50% cost cut when enabled.

### Dropped from v1

- **v1 #4 (prepass sliding window)** — subsumed by Q2.1 stratified
  compaction; prepass tool_results are just one content type that
  the stratified compactor handles.
- **v1 #6 (lossless conversation compression)** — same; the
  stratified compactor IS the conversation compression.

## What gets compacted vs preserved — the explicit decision tree

The compactor's per-message decision:

```
Is the message a USER message (the scan kickoff)?
  → KEEP VERBATIM forever.

Is the message in the HOT stratum (last 5 turns)?
  → KEEP VERBATIM.

Is the message a `create_vulnerability_report` call?
  → KEEP VERBATIM forever (canonical scan output).

Is the message a tool call (decision)?
  → KEEP the call name + args; drop verbose args after WARM.

Is the message a tool result?
  → WARM: replace body with summary + tool_output_id reference.
  → COLD: replace with one-line "<tool> ran at turn N → X findings".

Is the message a `think()` block?
  → WARM: keep first sentence + decision marker.
  → COLD: drop (decisions are captured in subsequent tool calls).

Is the message anything else (assistant text)?
  → WARM: summarize to one sentence.
  → COLD: drop (semantic content is in the compaction transcript).
```

This is auditable: every drop has a written-down reason. Every keep
is justified by either "user-visible" or "load-bearing for detection."

## How this maps to Claude Code's mental model

| Claude Code concept | Strix equivalent (post Q2 v2) |
|---|---|
| Auto-compact at 90% fill | Stratified compactor runs every turn; transcript fires at 50% fill |
| `/compact <focus>` user command | `compact_now(focus="...")` tool for the LLM to self-trigger |
| Compact summary (high-level narrative) | `compaction_transcript.md` |
| Memory files (persistent) | `workflow_state` + `SecurityContext` + `list_pending_findings` |
| Tool outputs replaceable by re-read | `read_tool_output(id)` drill-down |
| Recent turns verbatim, old turns summarized | HOT/WARM/COLD strata |
| Decisions preserved, deliberations summarized | Tool calls + emits preserved; `think()` summarized |
| Files-touched list persists | `tools_run` + `tools_succeeded` lists in workflow_state |

The 1:1 mapping is the proof we're not inventing something — we're
applying a battle-tested pattern.

## Combined expected impact (v2)

| Metric | Today | Target (post Q2 v2) | Mechanism |
|---|---:|---:|---|
| Tokens/turn | 810K | **100-200K** | Stratified compaction + transcript |
| Cold-stratum redundancy | ~500K/turn | ~10K | Compaction transcript replaces |
| Tool-output redundancy | ~200K/turn | ~30K | Drill-down + WARM-summary |
| Tool-catalog redundancy | ~50K/turn | ~10K | Q2.3 progressive disclosure |
| SecurityContext redundancy | ~20K/turn | ~5K | Q2.4 stratified render |
| Cost/scan | $3.78 | **~$0.80** (5×) | Linear with token cut |
| Wall/turn | 100s | **~40s** (2.5×) | Sub-linear with token cut |
| **Detection recall** | (current) | **unchanged ± 1pp** | Every drop is provably redundant |

## Hard constraint, re-stated

This is the requirement that supersedes everything else:

> **No technique in Q2 lands without proving via multi-trial
> `bench_owasp_benchmark.py` + `bench_l2_juiceshop_full.py`
> (N=5) that median Youden AND median completion rate are within
> 1pp of the pre-baseline.** Drops of 2+pp trigger immediate
> revert. The validation gate is non-negotiable.

## Iter sequence (revised, smaller than v1)

| iter | scope | size |
|---|---|---|
| **Q2.1** | Stratified `ConversationCompactor` — replaces v1's #1, #4, #6 | 1 PR, ~600 LOC, ~50 tests |
| **Q2.2** | Compaction transcript artifact | 1 PR, ~300 LOC, ~20 tests |
| **Q2.3** | Tool catalog progressive disclosure | 1 PR, ~200 LOC, ~15 tests |
| **Q2.4** | SecurityContext stratified rendering | 1 PR, ~150 LOC, ~15 tests |
| **Q2.5** | Two-tier model routing (OPT-IN) | 1 PR, ~500 LOC, ~40 tests |
| **Q2.6** | Combined bench + publish numbers | bench only |

Total: 5 PRs (down from v1's 7), ~1750 LOC, ~140 tests, 2 weeks.

## Two specific Claude-Code-inspired details

### The compaction transcript IS the conversation memory

When Claude Code compacts, the summary is what the model
"remembers." Strix's compaction transcript should be similarly
canonical: when a downstream turn asks "what tools have we tried?",
the answer comes from the transcript, not from a re-scan of cold
turns.

This makes the compactor's correctness EXTREMELY important — a
transcript that drops a critical finding is a real bug. Mitigation:
the transcript is deterministically generated from
`list_pending_findings` + `workflow_state.tool_results`, which are
themselves L1.5-enriched + persisted. The compactor never has to
"decide" what's important — the data structures upstream already
did.

### Decisions over deliberations

Claude Code preserves `Edit` / `Write` / `Bash` calls (the actions)
verbatim; the `text` blocks (the thinking-out-loud) get summarized.
For strix:

- **Decisions** (preserved verbatim):
  `create_vulnerability_report`, `scan_sqli_sqlmap`,
  `scan_idor`, `finish_scan` — the tool calls + their args.
- **Deliberations** (summarized in WARM, dropped in COLD):
  `think()` calls, intermediate assistant `text` blocks
  ("looking at the prepass output, I see a SQLi at /search...")

The first category IS the scan output. The second is the model
talking to itself. Treating them differently is the unlock.

## See also

- Original Q2 v1 proposal: `2026-05-27-token-reduction-strategy.md`
  (this v2 supersedes)
- Q1 measurement framework:
  `2026-05-27-benchmark-suite-strategy.md`
- Multi-trial harness:
  `benchmarks/per_target/bench_multi_trial.py`
- Existing memory compressor (the iter target):
  `strix/llm/memory_compressor.py`
- Claude Code reference: <https://docs.claude.com/en/docs/claude-code/>
  + the `/compact` slash command documentation
