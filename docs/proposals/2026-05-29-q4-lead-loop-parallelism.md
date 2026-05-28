# Q4 — Lead-loop parallelism

**Status:** proposal — pending review
**Owner:** ClatTribe/strix
**Created:** 2026-05-29
**Related:** Q1 (`docs/proposals/2026-05-27-benchmark-suite-strategy.md`), Q2 (`docs/proposals/2026-05-27-token-reduction-v2-stratified-compaction.md`), Q3 (`docs/proposals/2026-05-27-l1-parity-measurement.md`), Q5 (`docs/proposals/2026-05-27-l2-from-first-principles.md`), iter-33.2 (parallel specialist dispatch — shipped)

---

## 1. The question

> *"Why does a 5,000-URL crawl tree take 53 minutes when each per-URL specialist call is ~30s and we have hundreds of cores idle?"*

Translated into a measurable claim:

> **The L2 lead loop is sequential at the level of its highest-cost outer iteration: model → reason → emit one tool → wait → model → reason → emit one tool. Even with iter-33.2's parallel specialist dispatch inside `anchor_prepass`, the lead loop itself executes one model turn at a time. If the lead could fan out N exploration paths in parallel — each running its own loop against an independent target slice — wall-time at a given recall level drops to ~1/N.**

If the claim holds, the same scan that takes 53 minutes today completes in ~13 minutes at N=4 and ~7 minutes at N=8. If it doesn't hold — because tool dispatch is already the bottleneck, or because the model is throughput-limited, or because parallel paths produce redundant work — the gain is smaller and we keep the simpler sequential design.

Q1 measures detection recall. Q2 measures token economy. Q3 measures L1 parity vs. standalone OSS tools. **Q4 measures wall-time per recall point.** Without Q4, every other axis improves while the user still waits 53 minutes for the scan to land — and "best-in-class detection that takes an hour to produce" loses to "85% detection that takes 5 minutes" in every real procurement decision.

---

## 2. Current execution model (sequential lead, parallel L1)

```
┌─────────────────────────────────────────────────────────────────┐
│  HOST PROCESS (strix CLI)                                       │
│                                                                 │
│  1. anchor_prepass.run_oss_anchor_prepass(target)               │
│     ├── phase 1 : sequential _ANCHORS_WEB execution             │
│     │           (1 tool at a time, ~30 tools × 1-30s each)      │
│     ├── phase 2 : api / web dependent_api_tools                 │
│     ├── phase 2.5 : shape_aware_dispatcher                      │
│     │           ┌─ STRIX_DISPATCH_CONCURRENCY=4 ───┐            │
│     │           │  parallel per-endpoint probe    │            │
│     │           │  (iter-33.2 — within ONE phase) │            │
│     │           └────────────────────────────────┘             │
│     ├── phase 3 : anchor_fanout_across_endpoints                │
│     │           ┌─ STRIX_DISPATCH_CONCURRENCY=4 ───┐            │
│     │           │  parallel per-URL × per-tool    │            │
│     │           │  (iter-33.2 — within ONE phase) │            │
│     │           └────────────────────────────────┘             │
│     └── done — emit findings to tracer                          │
│                                                                 │
│  2. agent_loop(target, prepass_summary)        ← FULLY SEQUENTIAL│
│     while not finish_scan:                                      │
│         model.chat(prompt + history)   ← ~5-15s per turn        │
│         tool = parse(response)                                  │
│         result = execute_tool(tool)    ← ~0-30s per turn        │
│         history.append(result)                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

iter-33.2 closed the *intra*-phase parallelism gap — within `anchor_prepass`'s phase 3, N URLs × M tools fan out concurrently with `STRIX_DISPATCH_CONCURRENCY`. That's why the Q5.34l WAVSEP bench at limit=200 completed in 53 min instead of N×30s × 200 URLs = 8 hours.

The remaining gap is the **L2 lead loop**: after `anchor_prepass` returns, the agent loop runs sequentially — one model call, one tool call, repeat. The agent typically runs 30-200 turns per scan. At ~10s per turn (5s model + 5s tool average), that's 5-33 minutes of sequential time on top of the prepass.

Quick math for a representative scan:
- prepass: 10-15 min (already parallelised at the fan-out)
- lead loop: 5-30 min (sequential)
- **total: 15-45 min, with the lead-loop ratio rising as the agent explores more URLs**

Lead-loop parallelism doesn't eliminate either layer's wall-time — it overlaps them and adds capacity at the top of the loop.

---

## 3. What "parallel lead loop" actually means

Three distinct parallelism axes, each shippable independently:

### 3.1 Axis A — concurrent tool dispatch within one turn

Today the agent emits one tool call per turn. The Claude / Gemini API supports emitting multiple tool calls in a single response. The agent could be instructed:

> *"When the next-actions list contains independent items (different endpoints, different categories), emit all of them in one assistant turn as concurrent tool_use blocks. The executor will run them in parallel and return their results in one user turn."*

Mechanically: change the `agent_loop`'s tool-execution step from `await execute_tool(...)` to `await asyncio.gather(*[execute_tool(t) for t in response.tool_calls])`.

Cost: minimal — most modern LLM tool APIs already support multi-tool-call responses (Anthropic SDK exposes `content` as a list of `tool_use` blocks; Gemini's `tool_calls` array is the same shape). The agent just needs prompt-level guidance to actually emit multiple.

Gain: 2-4x within the current loop count for endpoint-traversal phases (where 4-8 next-actions are routinely independent). Saves no time on chain-construction or deep-exploit phases where actions are causally serial.

Risk: model emits tools that are NOT actually independent (e.g. needs result of `scan_idor` before calling `verify_finding` on the same endpoint). Solution: a dependency-classifier on the agent's tool_calls list that runs causally-serial items sequentially and parallelises the rest. The classifier reads from a small `TOOL_DEPENDENCIES: dict[str, set[str]]` table — keyed by tool name, valued by the set of tools whose output must precede it.

### 3.2 Axis B — multi-path scan tree (target-slice fan-out)

For multi-asset targets (`domain` with N subdomains, `api` with N OpenAPI tags, `local_code` with N language packs), the L2 lead could spawn N parallel sub-agents, each running its own loop against one slice. The sub-agents emit findings to a shared tracer (which already serialises L1.5 hooks); the parent coordinator waits for all to `finish_scan` then runs the cross-slice correlator (already exists as `mid_scan_correlate`).

Q5.44's child-asset pivot sidecar already produces the slice list. The wiring is:

```python
# Today (sequential, single lead)
sub = await run_oss_anchor_prepass(target_type, target_value, ...)
await agent_loop(target_value, sub)

# Q4 (parallel, fan-out)
children = sub.child_assets_discovered  # populated by Q5.44
if children and _multi_path_enabled():
    await asyncio.gather(*[
        agent_loop(c["host"], sub, slice_id=c["host"])
        for c in children
    ])
else:
    await agent_loop(target_value, sub)
```

Cost: per-child workflow_state isolation (each sub-agent needs its own `workflow_state` snapshot; the global singleton becomes per-slice). The tracer already supports multi-source emission so no change there.

Gain: linear with N children up to the model's parallel-call cap (Anthropic's tool-use API supports ~10 concurrent agent processes against the same key; Gemini Flash is higher). A domain scan with 12 subdomains drops from 12 × 15 min = 3 hours to ~20 min.

Risk: redundant work when children share infrastructure (same backend, same dependency CVEs). Solution: pre-loop dedup by inferred backend fingerprint — share the `query_threat_intel` cache and the `scan_container_image` results across slices that resolve to the same image.

### 3.3 Axis C — speculative pre-fetch (lead-loop tool prefetch)

The lead's next tool call is highly predictable from the current state (`workflow_status.next_actions` already lists 3-5 candidates with high accuracy). The executor could speculatively fire the top-K predicted next tools *while the model is thinking*, then return the matched result immediately when the model commits.

Mechanically:
```python
async def agent_loop_with_prefetch(...):
    while not finish_scan:
        prefetch_tasks = [
            asyncio.create_task(execute_tool(t))
            for t in workflow_status.predicted_next_actions[:K]
        ]
        response = await model.chat(prompt + history)
        actual_tool = parse(response)
        # Cancel un-matched prefetches; await the matched one
        result = await _match_or_run(actual_tool, prefetch_tasks)
```

Cost: K-1 cancelled tool calls per turn (waste). At K=2, ~50% waste; at K=4, ~75% waste. Only worth it when tool wall-time >> model wall-time, which is true for sqlmap (15-30s) and dalfox (10-20s) but not for `workflow_status` (instant).

Gain: hides model latency under tool latency, ~2-3x on the high-tool-cost phases of the scan. Stacks with Axis A.

Risk: tools emitting state-changing side effects (e.g. `create_vulnerability_report`) must NOT be prefetched. Easy gate: a per-tool `prefetch_safe: bool` flag on the registry.

---

## 4. Measurement plan

Q4 must answer three questions empirically before shipping any of A/B/C:

### Q4.1 — Where is wall-time actually spent today?

Instrument `agent_loop` to emit a JSONL trace of `(turn_id, model_wall_seconds, tool_wall_seconds, tool_name)` per turn. Aggregate across the Juice Shop + WAVSEP + OWASP Benchmark benches:

| Phase | Avg model time | Avg tool time | Avg turns | Total wall |
|---|---:|---:|---:|---:|
| anchor_prepass | n/a (no model) | ~600s | n/a | ~600s |
| recon (turns 1-5) | ? | ? | ? | ? |
| exploit (turns 6-30) | ? | ? | ? | ? |
| chain (turns 30+) | ? | ? | ? | ? |

If the model is the dominant cost (>60% of lead-loop wall), Axis A + Axis C are the wins. If tools dominate, Axis B is the win.

### Q4.2 — How much of the agent's tool emission is independent?

For each scan, classify per-turn tool calls as "could have been parallel with N previous turns" or "depends on previous-turn result". Manual labelling of 50 scans across the bench suite gives an empirical answer for the upper bound of Axis A.

Hypothesis: ~40% of turns are independent of the immediately-previous turn but depend on prepass output. Those collapse cleanly into Axis A multi-tool emissions. ~30% are causally serial (chain reasoning) and gain nothing. ~30% are mixed and benefit from a dependency classifier.

### Q4.3 — Does Axis B introduce correlation bugs?

Run the WAVSEP bench under `STRIX_LEAD_PARALLEL_PATHS=1` (sequential, control) and `STRIX_LEAD_PARALLEL_PATHS=4` (fan-out, treatment). Expected outcome on a 1133-case fixture: parallel mode at N=4 produces the same Youden ±2pp but completes in 1/4 wall-time.

If Youden drops more than 2pp in parallel mode, the L1.5 hook chain or `tracer.add_vulnerability_report`'s cross-tool merge logic is racing — that's a real bug to fix before shipping Axis B, not a reason to abandon it.

---

## 5. Iter sequence

| iter | scope | gates |
|---|---|---|
| **Q4.1** | trace instrumentation — per-turn wall-time JSONL in agent_loop | no bench change; gates on a clean trace artifact |
| **Q4.2** | dependency classifier — `TOOL_DEPENDENCIES` table + `_partition_independent_calls()` helper | unit tests on synthetic call lists |
| **Q4.3** | Axis A — multi-tool-call per turn in agent_loop | re-bench Juice Shop; require ≤2pp recall delta, expect ≥30% wall-time reduction |
| **Q4.4** | Axis B — multi-path fan-out coordinator on Q5.44's child_assets_discovered sidecar | re-bench WAVSEP at N=4; require ≤2pp Youden delta, expect ~3x wall-time reduction |
| **Q4.5** | Axis C — speculative prefetch with `prefetch_safe` registry flag | re-bench Juice Shop with K=2; require ≤2pp recall delta, expect ~30% extra wall-time reduction |
| **Q4.6** | combined Axis A+B+C bench — measure stacking efficiency | final scorecard alongside ZAP/Burp/Acunetix wall-time comparison |

Each axis is independently shippable and independently gated. Q4.3 alone may be enough — Q4.4 and Q4.5 are progressively higher-cost and may not be needed depending on what Q4.1 reveals.

---

## 6. Anti-claims

What Q4 explicitly does NOT propose:

1. **In-house tool parallelism.** Q4 adds parallelism at the orchestration layer — the LLM lead loop. Per CLAUDE.md §11.1, we still call community OSS tools for detection; we just call more of them concurrently.
2. **Lead-loop replacement.** Q4 keeps the existing single-agent design. It widens the loop, doesn't reshape it. The `workflow_state` / `tracer` singletons stay singletons (per-slice in Axis B). The L1.5 hook chain stays unchanged.
3. **Cost optimization.** Q4 trades token spend for wall-time. Axis C (prefetch) actively *increases* total token + tool spend by K-1× per turn. The user's wall-time at N customer-machine cores has higher ROI than the LLM-API spend at 30× that count.
4. **L1 detection coverage.** Q4 doesn't add a single detection capability. Every finding strix produces under Q4 was already produceable under sequential execution — just slower. Detection improvements live in Q3 / Q5.x / Q7.x.

---

## 7. Decision points the team needs to make

1. **Token budget tradeoff.** Axis C wastes K-1× tools per turn. At ~$0.001-0.01 per tool call this is small in absolute terms, but the L2 Lead's per-scan cost goes from ~$0.50 to ~$2.00 at K=4. Worth it? (Answer: yes per the wall-time framing, but the team should sign off.)

2. **Prefetch safety policy.** Which tools are `prefetch_safe=False`? Easy: all `COMMIT` bucket tools (`create_vulnerability_report`, `finish_scan` from CLAUDE.md §1.5.7). Harder: `dispatch_l2_probe` with state-mutating `kind` values. Need a small audit pass over the L2 catalog before shipping Axis C.

3. **Per-slice tracer isolation in Axis B.** Today's `tracer` is a process-singleton with global state. Two options: (a) per-slice tracer instances merged at finish, or (b) keep the singleton and serialise emit calls under a lock. Option (a) keeps the L1.5 chain's per-slice corroboration sane. Option (b) is simpler but loses some chain detection between slices.

4. **Anthropic API parallel-call cap.** Anthropic's tool-use API supports concurrent tool_use blocks within one response but limits the *number of agents* on one API key. Gemini Flash has a higher cap. Worth confirming both providers' cap empirically before betting Axis B on it.

---

## 8. Expected outcome

If Q4.1 instrumentation confirms today's lead loop is 40-60% of total scan wall-time (the hypothesis based on the WAVSEP Q5.34l data), shipping just Axis A drops the L2 portion by ~30% — meaning a 30-min scan becomes a 22-min scan. Shipping Axis B for multi-asset targets drops it further to ~10-15 min. Shipping Axis C is dessert.

At that point strix's wall-time-per-recall curve matches Burp Active Scan + Acunetix's published numbers (which are themselves heavily parallel internally). Combined with Q3-confirmed L1 parity and Q1's headline recall benches, the procurement story becomes: "comparable detection to Acunetix at comparable wall time, on the LLM-orchestration cost premise."

---

_Q4 is the wall-time axis of the four-corner framing (Q1 detection × Q2 tokens × Q3 parity × Q4 wall-time). It's the axis users actually feel._
