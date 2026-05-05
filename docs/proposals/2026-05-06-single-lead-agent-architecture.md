# Architectural proposal: replace parent-spawns-N-specialists with a single lead agent + specialist tools

**Author:** webappsec wrapper integration team
**Date:** 2026-05-06
**Status:** proposal
**Builds on:** [`docs/incidents/2026-05-05-tool-server-unreachable.md`](../incidents/2026-05-05-tool-server-unreachable.md), [`docs/incidents/2026-05-06-finding-emission-starvation.md`](../incidents/2026-05-06-finding-emission-starvation.md)

> Issues are disabled on this repo, so this proposal lives in `docs/proposals/`. Treat the file as an RFC entry — discuss in PR review, refine, accept/reject by merging or closing.

---

## TL;DR

The two prior incidents both trace to the same architectural choice: when a `standard`-mode scan starts, the parent agent spawns N specialist *sub-agents*, each with its own LLM conversation. This pays cache-miss pricing N times for context-loading and fragments the "evidence → emit" narrative across N independent contexts. Concretely, on `demo.testfire.net` we measured **8 sub-agents × ~700K input tokens of context-loading = $1.74 of pure overhead** before any probing happened. Findings emitted: 0.

This proposal replaces the multi-agent pattern with a **single lead agent + specialist *tools*** pattern. One conversation owns planning + emission + budget. Specialists become tools (`scan_xss(url, params) → XSSResult[]`) that internally call focused LLMs with **gemini cached-content** system prompts. Same specialist depth, ~4× lower cost, eager emission as a natural consequence.

This pattern has overtaken multi-agent in production agent systems over the last 12-18 months (Cline, Aider, Cursor Composer, Anthropic computer-use, OpenAI o1/o3 + tool use, Manus all use it). The multi-agent pattern (Devin, AutoGen, CrewAI, MetaGPT) had a moment in early 2024 but has been losing ground for exactly the cost/context-fragmentation reasons we hit.

---

## The diagnosis

### Today's flow (multi-agent)

```
[ User instruction ]
       │
       ▼
[ Parent agent ] ── reads test plan ──▶ creates 8 sub-agents:
       │
       ├──▶ [ Sub-agent 1: recon ]    fresh LLM convo, 700K context dump
       ├──▶ [ Sub-agent 2: SQLi ]     fresh LLM convo, 700K context dump
       ├──▶ [ Sub-agent 3: XSS ]      fresh LLM convo, 700K context dump
       ├──▶ [ Sub-agent 4: stored XSS ]  fresh LLM convo, 700K context dump
       ├──▶ [ Sub-agent 5: LFI ]      fresh LLM convo, 700K context dump
       ├──▶ [ Sub-agent 6: IDOR ]     fresh LLM convo, 700K context dump
       ├──▶ [ Sub-agent 7: CSRF ]     fresh LLM convo, 700K context dump
       └──▶ [ Sub-agent 8: misconfig ] fresh LLM convo, 700K context dump

8 × ~700K input tokens × $0.31/1M (cache miss) = $1.74 just to load context.
Each sub-agent then has $0.10 of budget left for actual probing.
Findings emitted: 0 (budget fires before emission).
```

### Why each sub-agent's context is so big

Reading strix source, the `create_agent` flow gives each sub-agent:

- Original user instruction (~2K tokens)
- Test plan (~5K tokens)
- Parent's accumulated context — recon results, prior tool outputs, screenshots, browser DOM (~50–200K tokens)
- Tool catalog — every available tool's schema (~100K tokens)
- Agent system prompt (~10K tokens)
- Often duplicated reasoning context the parent had been collecting (~300–500K tokens)

For 8 specialists × ~700K tokens × `$0.31/1M` = **$1.74 of pure context-loading**, every scan, before any actual work. That's 70% of the $2.50 budget cap we tested.

### Why findings don't emit

Each sub-agent finishes its conversation and returns to the parent. The parent then has to:
1. Read 8 separate result reports
2. Merge them into a coherent narrative
3. Decide which to emit as `finding.created` events

This adds latency and cost. Worse, the sub-agents themselves hesitate to emit because emission requires populating a heavy schema (`title`, `severity`, `category`, `description`, `impact`, `remediation_steps`, `poc_md`, `technical_analysis`, `cwe`, `cvss`, ...) and the LLM's training reward favours thoroughness over commitment. So sub-agents tend to gather more evidence rather than emit early.

### The hypothesis-tracker starvation is a separate symptom of the same root cause

`hypothesis.opened/confirmed/dismissed` events were 0 across all 8 sub-agents × 45 minutes. The hypothesis tracker (engine PR #138) was meant to write to a shared `active_hypotheses.jsonl`, but with conversations fragmented across 8 sub-agents and no shared-state coordination, no one writes to it. The wrapper's live-view `HypothesisPane` is empty for the entire run despite ~30 hypotheses' worth of reasoning happening across the sub-agents.

---

## The proposal

### One lead agent, N specialist tools

```
[ User instruction ]
       │
       ▼
[ Lead agent ]  ── one conversation, owns planning + budget + emission
       │
       │  Conversation accumulates ONE narrative.
       │  Cache hits work cleanly: the system prompt + test plan +
       │  early recon results are all cached, pay $0.078/1M, not $0.31/1M.
       │
       ├──▶ tool: scan_recon(target, scope)       ─▶ internal LLM call w/ cached system prompt
       ├──▶ tool: scan_xss(url, params, ctx)      ─▶ internal LLM call w/ cached system prompt
       ├──▶ tool: scan_sqli(url, params, raw_req) ─▶ internal LLM call w/ cached system prompt
       ├──▶ tool: scan_idor(endpoints, session)   ─▶ internal LLM call w/ cached system prompt
       ├──▶ tool: scan_csrf(state_changing_endpoints) ─▶ internal LLM call w/ cached system prompt
       ├──▶ tool: scan_misconfig(url)             ─▶ deterministic checks (no LLM!)
       ├──▶ tool: emit_finding(...)               ─▶ structured emission
       └──▶ tool: dismiss_finding(reason)         ─▶ explicit non-finding
```

### Three properties of specialist tools

Each specialist tool is:

1. **Bounded input.** The lead agent passes only what's needed: a URL, a list of params, an auth session. NOT the entire conversation context. This is the cache-pricing fix — tools see <50K tokens of fresh input, not 700K.

2. **Cached system prompt.** Each tool's system prompt is pre-registered via Gemini's cached content API (or Anthropic's prompt caching). The system prompt loads once per scan; subsequent invocations of the same tool pay $0.078/1M for the system portion. This is the second cache-pricing fix.

3. **Structured output.** Tools return JSON schemas (`{vulnerable: bool, evidence: str, reproduction: str, confidence: float, ...}`), not free-form prose. The lead agent consumes the structured result deterministically and decides whether to call `emit_finding` next turn.

### Why this fixes the emission gap

The lead agent's main loop is:

```python
while not terminated:
    next_action = lead_agent.think("based on findings so far, what next?")
    if next_action.type == "tool_call":
        result = invoke_tool(next_action.tool_name, next_action.args)
        lead_agent.observe(result)  # added to ONE growing conversation
    elif next_action.type == "emit_finding":
        emit(next_action.finding)   # structured emission — eager
    elif next_action.type == "finish_scan":
        break
```

Eager emission becomes natural: when `scan_xss(...)` returns `{vulnerable: true, evidence: "<script>alert('strix-abc')</script> reflected unescaped"}`, the next `lead_agent.think` turn just calls `emit_finding(severity=medium, category=xss, ...)`. No "wait until I have the full picture" hesitation — the structured tool output IS the picture.

### Why this fixes the hypothesis-tracker starvation

All hypothesis state lives in the lead agent's single conversation. There's no need for a separate `active_hypotheses.jsonl` shared-state file. The wrapper can render hypotheses by reading the lead agent's `think` events — which are all in one chronological stream.

### Why this fixes the cost-cap problem

| Phase | Today (8 sub-agents) | Proposed (1 lead + tools) |
|---|---|---|
| Context-loading | 8 × 700K × $0.31/1M = **$1.74** | 1 × ~50K × $0.31/1M (cache miss only on first turn) = **$0.02** |
| Subsequent turns (cached prefix) | minimal — each sub-agent only does ~3-5 follow-ups | many — but each hits cache at $0.078/1M |
| Specialist work | 8 × ~4 turns × 50K = ~$0.13 | 8 specialist tool calls × ~30K + cached system = **$0.10** |
| Tool output processing | $0.30 | ~$0.10 (structured outputs are smaller) |
| Output tokens | ~$0.30 (50K × $2.50/1M = $0.125 × 8) | ~$0.20 (one agent emitting more findings) |
| **Total** | **~$2.47** (cap fires) | **~$0.65** |

Same target, same coverage, **~4× cheaper** — and the budget headroom is what enables eager emission to actually fire.

### Why this fixes the tool-server reconnect issue (#146 secondary fix)

With 8 sub-agents each holding their own connection to the tool server, a tool-server hiccup affects 8 connections simultaneously. Reconnect logic has to coordinate across 8 contexts.

With one lead agent, there's one connection. Health-gate on lead-agent startup. If it drops mid-run, one circuit-breaker, one reconnect. Order-of-magnitude simpler.

---

## Where this approach is genuinely worse — and the mitigations

### 1. Wall-time parallelism

8 sub-agents can probe simultaneously: SQLi specialist hits `/search.aspx` while CSRF specialist tests `/transfer.aspx`. A serialised lead agent can't.

**Mitigation:** specialist tools themselves can be parallel. `scan_xss` accepts a list of URLs and fans out internally with a thread pool. The serialisation is at the *planning* layer (lead agent decides which tool to call next), not at the *execution* layer (each tool can be massively parallel).

### 2. Lead-agent context window bloat

Long scans accumulate tool outputs, screenshots, DOM dumps in the lead agent's context. Gemini-2.5-pro has 2M context but quality degrades past ~500K.

**Mitigations:**
- **Specialist tools return structured summaries**, not raw output. `sqlmap` dumping 50KB of stdout becomes `{vulnerable: true, evidence: "10-line excerpt...", commands_run: [...]}` — maybe 2KB. The lead agent only sees the summary.
- **Conversation compaction.** After every 20 turns, the lead agent calls `compact_context(retain=findings_so_far)` — summarises older turns into a brief, drops the verbose history.
- **Tier the context.** Recent 10 turns at full fidelity; older turns at 1-line summaries.

### 3. Specialist depth

A dedicated XSS sub-agent with a long system prompt focused on context-aware payload selection is genuinely better at XSS than a generalist.

**Mitigation:** the specialist *tool's* internal LLM call uses a focused, long system prompt. The lead agent doesn't see this — it only sees the structured result. Specialist depth is preserved at the tool level; coherent narrative is preserved at the agent level.

### 4. Failure isolation

If the lead agent gets stuck in a loop, the whole scan is stuck (vs. one sub-agent stuck = others continue).

**Mitigations:**
- **Per-tool-call timeout** (30s default) so a stuck tool can't hang the agent.
- **Watchdog turn counter** — if 5 turns pass without a finding emit OR a new endpoint touched, force `finish_scan` with what we have.
- **Sub-tool budget** — if a single specialist tool spends >10% of total budget without returning, abort it.

---

## Why this is the trend in production agent systems

Pattern observers will recognise this as the architectural shift that has happened across major agent platforms in 2025:

| System | 2024 architecture | 2025 architecture |
|---|---|---|
| **Cline** | already single-agent | unchanged |
| **Aider** | already single-agent | unchanged |
| **Cursor Composer** | mixed | converged on single-agent |
| **Anthropic computer-use** | n/a | single-agent + tools (launched this way) |
| **OpenAI o1/o3 native tool use** | n/a | single-agent + tools (launched this way) |
| **Devin (Cognition AI)** | multi-agent | now hybrid; lead agent dominant |
| **AutoGen / CrewAI / MetaGPT** | multi-agent | declining; mostly research code now |
| **Manus** | n/a | "one brain many tools" — explicit positioning |

The empirical evidence: single-agent + tools beats multi-agent on cost, coherence, and emission discipline. Multi-agent only wins when the parallel speedup outweighs the context-fragmentation cost — which is rare for budget-constrained agentic security testing where context-loading dominates.

---

## Migration path

This isn't a green-field rewrite. Strix already has all the building blocks. The migration is:

### Phase 1 — wrap existing sub-agents as tools (low-risk)

Today's `create_agent(name="xss_specialist", task="...")` call is internally:
1. Fork a sub-agent process
2. Pass the task + context
3. Wait for the sub-agent to finish_scan
4. Return its results to the parent

Replace step 1-3 with a thin wrapper that:
1. Compiles the sub-agent's system prompt (cache-keyed)
2. Calls a single LLM `dispatch_to_specialist(system_prompt_id, task, args)`
3. Returns structured result

The parent agent's tool catalog gains a new tool per specialist. The sub-agent abstraction is preserved internally; externally it's a tool. This is a 1-week refactor.

### Phase 2 — collapse the parent into a single lead agent (medium-risk)

The "parent" role becomes the lead agent. Today's parent reads the test plan and decides which sub-agents to spawn; tomorrow's lead reads the test plan and decides which specialist tools to call. Same logic, different invocation shape.

### Phase 3 — eager emission tooling (low-risk)

Add `emit_finding(verification_status="pattern_match", confidence=0.7, evidence=..., refine_later=true)` shorthand. The lead agent calls this on first credible evidence. Subsequent turns can emit `update_finding(finding_id, ...)` to refine.

### Phase 4 — gemini cached-content integration (medium-risk)

Each specialist tool's system prompt is registered once per scan via gemini's cached content API. The cached-content `name` is included in subsequent calls; gemini bills the cached portion at $0.078/1M instead of $0.31/1M. Anthropic prompt caching has the same shape. Single-line API change per tool, validated by a cost regression suite.

### Phase 5 — context compaction (medium-risk)

Lead agent's main loop checks `total_context_tokens > 500K` and calls a `compact_context` tool that summarises the older turns. The summary is appended to the conversation; older turn-by-turn detail is dropped from active context. Existing trajectory.jsonl preserves the full history for the audit trail.

---

## What this looks like for wrappers

Wrappers (like webappsec) currently consume 8 separate `agent.created` events + their associated tool calls. Under the new pattern, wrappers consume a single agent's tool-call stream — no merge logic across sub-agents.

Wrapper-side improvements that become possible:

- **`HypothesisPane`** populates from a single `think` stream — no "8 sub-agents are silent" scenario.
- **Coverage banner** is more accurate — `categories_covered` reflects actual specialist-tool calls, not "8 sub-agents started but emitted nothing."
- **Budget visualisation** shows one cost meter, not "8 specialists each tracked separately."
- **Cancel → SIGTERM** is one process, one cleanup. Today's coordination across N sub-agents goes away.

webappsec's existing fixes (PR #58 budget-exceeded UX, PR #64 coverage banner, PR #62 Slack notifier, PR #49 hypothesis pane) all work better under the proposed architecture without any wrapper changes.

---

## Acceptance criteria

If implemented, the new architecture should hit these on the same `demo.testfire.net` benchmark:

| Metric | Today | Target |
|---|---|---|
| Total cost (standard mode) | $2.50 (cap) | $0.50 - $0.80 |
| Wall time | 45 min | 15-20 min |
| `finding.created` events | 0 | 12 of 20 baseline |
| `hypothesis.opened` events | 0 | 8-15 |
| `coverage_percent` | 0% | 70%+ |
| Budget headroom at finish | -4% (cap exceeded) | +30-50% |

Anything close to those numbers makes strix competitive with Burp Suite Pro + ZAP on the same target — at lower cost than either, with auditor-grade artifacts that neither produces.

---

## Risks

1. **Backwards compatibility.** Wrappers consume `agent.created` events today. Removing them would break existing integrations. Mitigation: emit a synthetic `agent.created` for the lead agent at scan start so wrappers see a non-empty agent list; the multi-agent semantic just deflates to "1 agent ran."

2. **Specialist-tool design.** Defining the specialist-tool API (input schema, output schema, error model) is a few weeks of work and easy to get wrong. Mitigation: ship one specialist tool first (`scan_misconfig` is deterministic and easy), validate the pattern, then port the LLM-driven specialists.

3. **Loss of true parallel specialists.** For very-large-scope scans (hundreds of endpoints), the sequential lead-agent loop might be wall-time-slower than 8 parallel sub-agents. Mitigation: specialist tools fan out internally. Re-evaluate after Phase 1 metrics are in.

4. **Cache invalidation.** If the lead agent's accumulated context drifts, cached prefixes stop matching. Mitigation: a cache-key derivation that's stable across "small" context changes (e.g. hash the system prompt + the *summarised* prior turns, not the full turn-by-turn).

5. **Engine-team-time investment.** This is roughly a 4-6 week refactor. Worth it if the cost / emission targets above are believable.

---

## Cross-references

- [`docs/incidents/2026-05-05-tool-server-unreachable.md`](../incidents/2026-05-05-tool-server-unreachable.md) — fixed as a side-effect (one lead agent → one connection)
- [`docs/incidents/2026-05-06-finding-emission-starvation.md`](../incidents/2026-05-06-finding-emission-starvation.md) — fixed directly (eager emission natural in lead-agent loop)
- [`webappsec` PR #64](https://github.com/ClatTribe/webappsec/pull/64) — wrapper-side coverage banner; works under either architecture
- [Anthropic prompt caching docs](https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching) — the API that makes cached system prompts cost ~25% of standard rate
- [Gemini cached content API](https://ai.google.dev/gemini-api/docs/caching) — equivalent for gemini-2.5-pro
