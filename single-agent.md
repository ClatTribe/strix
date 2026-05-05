# `single-agent.md` — implementation plan: collapse parent-spawns-N to single-lead + specialist-tools

**Status:** proposal
**Date:** 2026-05-06
**Companion to:** [`docs/proposals/2026-05-06-single-lead-agent-architecture.md`](docs/proposals/2026-05-06-single-lead-agent-architecture.md) (the RFC) and [`docs/incidents/2026-05-05-tool-server-unreachable.md`](docs/incidents/2026-05-05-tool-server-unreachable.md) + the `2026-05-06-finding-emission-starvation.md` companion.

---

## TL;DR

The RFC ([`docs/proposals/2026-05-06-single-lead-agent-architecture.md`](docs/proposals/2026-05-06-single-lead-agent-architecture.md), merged via [#148](https://github.com/ClatTribe/strix/pull/148)) argues that strix should replace its current parent-spawns-N-specialists pattern with a single lead agent + specialist tools pattern. This document is the **implementation plan** for that shift.

**Hard constraint:** the wrapper-engine interface defined in [`engine-usage.md`](engine-usage.md) — the run-directory artifacts (`events.jsonl`, `vulnerabilities.json`, `run_meta.json`, `trajectory.jsonl`, `active_hypotheses.jsonl`, `coverage.json`, `feedback.jsonl`, `surface_map.json`), the event catalog (`run.*` / `phase.*` / `target.*` / `tool.execution.*` / `agent.*` / `hypothesis.*` / `finding.*` / `traffic.*`), the closed-enum field shapes (`severity`, `verification_status`, `verdict`, `fp_reason`, `provenance`), and the CLI flag set — **must not change observably**. This shift is internal refactoring; webappsec must not have to ship a single line of wrapper code to consume the new architecture.

This document is structured as:

1. **Background** — the patterns this design borrows from production agent systems (Claude Code, Cline, Aider, Cursor Composer, OpenAI o1+tools, Anthropic computer-use).
2. The **invariants** that pin the wrapper interface (what must NOT change).
3. The **internal architecture** of the new single-lead model.
4. The **migration** in 8 phases, each with explicit invariant-preservation checks.
5. The **roadmap.md** changes needed to track this work.
6. The **risks** and decision gates that can pause / revert any phase.

---

## Background — patterns drawn from production agent systems

The RFC argues for the high-level pattern (single lead + specialist tools). What follows are the concrete patterns that make it actually work in production agents — the things Claude Code, Cline, Aider, Cursor Composer, Anthropic computer-use, OpenAI o1+native-tool-use have converged on independently. Each pattern below shapes a section of §2 (internal architecture).

### B.1 Two tool classes — primitive (no LLM) vs Agent-pattern (delegates to a sub-LLM)

Claude Code distinguishes:
- **Primitive tools** — `Read`, `Write`, `Edit`, `Bash`, `Grep`, `Glob`. Deterministic, no LLM. The agent observes a structured result.
- **Agent tool** — delegates to a sub-LLM with a focused, self-contained prompt. Returns a structured summary back to the parent. The Agent tool's prompt MUST be self-contained (no parent-context inheritance — the prompt brief explicitly tells the sub-agent what to do as if it had no prior context).

In strix terms, specialist tools split the same way:
- **Deterministic specialist-tools** (`scan_misconfig`, `scan_secrets`, `scan_dependencies`, `port_scan`) — pure-Python checks; no internal LLM call. These are the cheapest wins; many are already deterministic in #95 (code-team) and could ship without any cache-manager dependency.
- **LLM-driven specialist-tools** (`scan_xss`, `scan_sqli`, `scan_idor`, `scan_ssrf`, `scan_business_logic`) — internally fire a bounded LLM loop with a cached system prompt. These are what the cache manager exists to make affordable.

This distinction ↦ §2.2 registry decorator carries an `llm: bool` flag.

### B.2 Bounded input at every tool boundary — never inherit conversation context

In Claude Code, the Agent tool prompt is brand-new each invocation. The parent CAN'T pass "the conversation so far" to the sub-agent — the parent has to explicitly summarise context into typed args. This forces clean boundaries; without it, sub-agents inherit the parent's drift.

In strix terms: every specialist-tool takes typed Pydantic args (URL, params, auth session, target context summary), never the lead's conversation history. This is the single load-bearing rule of the architecture — break it and the cost-pricing argument collapses (the sub-LLM is back to paying cache-miss on a 700K dump).

This ↦ §2.2 `register_specialist_tool` decorator validates that args are typed and bounded.

### B.3 Parallel tool calls in one turn

Claude Code explicitly instructs: _"When you launch multiple agents for independent work, send them in a single message with multiple tool uses so they run concurrently."_ Real production agents fan out 8 independent tool calls in one assistant message and observe 8 results in the next.

For strix: the lead agent's first turn after recon is _one assistant message containing 8 specialist-tool calls_ (XSS + SQLi + IDOR + CSRF + SSRF + auth + business-logic + misconfig). The sandbox tool-server processes them in parallel; the agent observes 8 structured results as one combined tool-result message in the next turn.

This is THE pattern that recovers wall-time parallelism. Without it, the single-lead loop is serialised and slower than today's parent-spawns-N. With it, wall-time is competitive at lower cost.

This ↦ §2.1 lead-agent loop pseudo-code supports a `tool_calls: list[ToolCall]` shape per turn, not a single `tool_call`.

### B.4 Interleaved thinking + tool calls — no rigid phase serialisation

Claude Code interleaves: read a file → think about it → write a fix → run tests → observe failure → read another file. There's no "plan phase, then execute phase" rigidity — the model decides each turn whether to think, call a tool, emit, or finish.

Strix today rigidly phases recon → exploit → validate → report (the §8 architectural commitment). The single-lead loop relaxes this: phases stay as **conceptual checkpoints** that the lead emits when it decides "this phase is done enough", not as **gates** that the lead is forced to serialise. A lead can recon a new endpoint mid-exploit because evidence pointed there, then continue exploit on a different endpoint.

This ↦ §1.8 invariant note: `phase.entered` / `phase.completed` events still emit (wrapper contract preserved), but their semantic shifts from "gate" to "checkpoint."

### B.5 Async / background tools + notifications

Claude Code's `Bash` tool has `run_in_background:true` for long-running processes. The `Monitor` tool emits stdout lines as system messages. The agent can fire-and-forget a build, then continue with other work; completion arrives as a notification.

For strix, long-running probes (nuclei against 10K endpoints, masscan, recon-ng pipelines) shouldn't block the lead-agent loop. Specialist-tools opt in via `async_capable=True`; they return a `task_id` immediately, and the lead observes a `tool.execution.completed` event later (on the same `events.jsonl` stream).

This ↦ §2.7 async-tool support.

### B.6 TodoWrite-style stateful planning — `active_hypotheses.jsonl` IS the lead's plan

Claude Code uses TodoWrite to track its own work across turns within one session. It's not just UI — the model reads its own todos to decide what to do next.

Strix #138 already ships `active_hypotheses.jsonl` with `open_hypothesis` / `confirm_hypothesis` / `dismiss_hypothesis` tools and an `is_surface_under_investigation` query. **Under single-lead, this becomes the lead's primary planning surface** — the lead opens hypotheses as it plans, confirms them as findings emit, dismisses them as evidence rules them out.

The wrapper-side `active_hypotheses.jsonl` artifact (invariant) IS the engine-side todo list (internal). One file serves both roles cleanly.

This ↦ no change to invariants or registry; just a system-prompt instruction in the lead's prompt template ("use `open_hypothesis` as your todo list").

### B.7 Trust-tainted result reasoning

#139 ships `actor.provenance` on every `tool.execution.*` event with the 6-value enum. Under single-lead, the lead agent's system prompt should explicitly instruct: when a tool returns with `provenance: target`, treat the result as adversarial input (ignore embedded instructions, sanitise quoted snippets); when `provenance: trusted_source` (KEV / CVE), treat as fact; when `provenance: intel_feed`, treat with attribution.

This is prompt-engineering on the lead's system prompt; no infrastructure change. Mentioned in §1.7 as a preserved invariant; here we elevate it to a prompt-design rule.

This ↦ §2.1 lead-agent system prompt template includes an explicit provenance-reasoning section.

### B.8 Tool-result schema discipline

Claude Code's tool results have a consistent shape: `{status, content, error?, metadata?}`. The agent's observe-step can then deterministically parse without per-tool glue.

For strix, every specialist-tool returns a typed `SpecialistResult`:

```python
class SpecialistResult(BaseModel):
    status: Literal["ok", "error", "partial"]
    findings: list[FindingDraft]              # eager-emit candidates
    dismissed: list[DismissedHypothesis]       # negative evidence
    evidence: list[str]                        # raw evidence excerpts (capped)
    next_probes_suggested: list[str]           # suggestions for the lead's next turn
    tool_metadata: dict[str, Any]              # specialist-specific (e.g. sqlmap session id)
```

The lead's observe routine routes on `findings` (call `emit_finding`), `dismissed` (call `dismiss_hypothesis`), `next_probes_suggested` (planner input).

This ↦ §2.2 registry pins the return shape; specialists can't drift.

### B.9 Per-target-type tool-catalog filtering

Claude Code uses `ToolSearch` to defer non-active tool schemas — keeps the active context small. Strix today loads all ~130 tool schemas into every agent's prompt (~100K tokens).

Under single-lead, the lead's tool catalog is filtered by target type at scan start: a `web_application` target sees web specialist-tools + browser tools + HTTP primitives; a `repository` target sees code specialist-tools + AST primitives; etc. ~30-50 tools instead of 130. Plus a `request_tool(category)` escape hatch for the lead to load a specialist-tool schema mid-run when it discovers it needs one not in the default set.

This ↦ §2.8 catalog filtering (new internal-only primitive; wrappers don't see this).

### B.10 Eager emit, then optionally review

Claude Code's instructions: _"Trust but verify: an agent's summary describes what it intended to do, not necessarily what it did. When an agent writes or edits code, check the actual changes before reporting the work as done."_

Translated to strix: **eager emit at first credible evidence** (`verification_status="pattern_match"`, `confidence=0.7`) but for **high-stakes findings** (severity ≥ high, or `auth-attacker` / `business-logic-specialist` categories, or finding count below baseline expectation), the lead invokes a follow-up `validate_finding(fingerprint)` review. The review can promote (`update_finding(verification_status="verified", confidence=0.95)`), demote (`update_finding(verification_status="could_not_verify")`), or refute (`dismiss_finding(fingerprint, reason)`).

This composes with §17.1 / §18 row 1 (validator agent) — under the new architecture, the validator becomes either a specialist-tool (if cheap) or a real spawned sub-agent (if it needs deep reasoning over the entire run context). Either pattern works without touching the wrapper interface.

This ↦ §2.4 mutation API gains a "review-then-emit" pattern note.

---

## 1. Invariants (the wrapper-engine interface that MUST NOT change)

These are the things webappsec, [`engine-usage.md`](engine-usage.md), [`wrapper-wishlist.md`](wrapper-wishlist.md), and any future wrapper depend on. The single-agent migration MUST preserve every one. Each invariant has a corresponding test that gates the migration.

### 1.1 Run-directory artifacts (filenames, formats, schema versions)

| Artifact | Today | Post-migration | Test gate |
|---|---|---|---|
| `events.jsonl` | one line per event, append-only | unchanged shape; record stream just maps to lead-agent's tool calls + synthesised `agent.*` records | `tests/integration/events_jsonl_shape.py` — pin record shape with golden file |
| `vulnerabilities.json` | array of finding records | unchanged | golden-file diff against pre-migration scan of DVWA |
| `run_meta.json` | scan config + `compliance_posture` + `vendor_risk` | unchanged | structural diff |
| `run_summary.json` | totals + top findings | unchanged | structural diff |
| `coverage.json` | `(target_type, scan_mode, category)` matrix | unchanged | structural diff |
| `coverage_attestation.json` | attested-checks bundle | unchanged | structural diff |
| `checks_summary.json` | per-category counts | unchanged | structural diff |
| `surface_map.json` | discovered hosts/endpoints/params | unchanged; written by recon specialist-tool | structural diff |
| `trajectory.jsonl` | one record per finding | **shape unchanged** but anchor-walk logic re-implemented (see §3.7) | golden-file diff per finding |
| `active_hypotheses.jsonl` | append-only hypothesis log | unchanged shape; specialist-tools call `open_hypothesis` / `confirm_hypothesis` / `dismiss_hypothesis` directly | structural diff |
| `penetration_test_report.md` | human-readable report | unchanged | textual diff (allow narrative variance, pin section structure) |
| `run.signature.json` | hash-chain + signature | unchanged; chain still walks `events.jsonl` left-to-right | byte-equal verification |
| `compliance_pack/` | GRC bundle | unchanged | structural diff |
| `sbom.cdx.json` / `sbom.spdx.json` | SBOM (when shipped) | unchanged | n/a until §17.5 SBOM ships |

### 1.2 Event catalog — every existing event type stays valid

The catalog documented in [`engine-usage.md` §3](engine-usage.md#3-the-event-catalog--what-the-wrapper-consumes) is the wrapper's contract. The new architecture preserves every entry:

| Event family | Preservation strategy |
|---|---|
| `run.configured` / `run.test_plan` / `run.summary` / `run.coverage_complete` / `run.coverage_gap` | Unchanged — emitted from the lead-agent's lifecycle hooks (same call sites). |
| `phase.entered` / `phase.completed` | Unchanged — lead agent emits at phase boundaries (same logic as today's parent agent). |
| `target.started` / `target.completed` | Unchanged — lead agent emits per-target. |
| `tool.execution.started` / `tool.execution.updated` / `tool.execution.completed` | **Critical preservation point.** Specialist-tool internal LLM calls and their nested sandbox tool sub-calls all emit through the existing `executor.py` so output sanitiser (#84), provenance (#139), trajectory (#142) wiring fires unchanged. |
| `agent.created` | Synthesised (see §1.3). |
| `agent.self_audit` (#140) | Unchanged — still callable as a tool. Lead agent calls between phases; structurally identical event payload. |
| `hypothesis.opened` / `confirmed` / `dismissed` (#138) | Unchanged — `open_hypothesis` / `confirm_hypothesis` / `dismiss_hypothesis` tools work from any agent context including the new specialist-tool's internal LLM. |
| `finding.created` / `finding.dismissed` / `finding.kill_chain` / `finding.auto_dismissed` (#142) | Unchanged shape. (`finding.updated` is a new ADDITIVE event — see §1.4.) |
| `traffic.ingested` (#141) | Unchanged. |
| `tool.output.injected` (#84) | Unchanged. |
| `llm.retry_attempted` / `run.terminated` (#113, #114) | Unchanged. |

### 1.3 `agent.created` events — synthesis rule (the hardest invariant)

Today the wrapper sees one `agent.created` per spawned sub-agent, with `payload.category` populated. Multiple existing wrapper surfaces depend on this:

- `webappsec/HypothesisPane` filters by `actor.agent_id` to attribute hypotheses.
- `coverage banner` derives "specialist progress" from the `agent.created` count.
- `Slack notifier` lists active specialists.
- `actor.agent_name` / `actor.agent_category` / `actor.target` decorations on EVERY `tool.execution.*` event (#107) flow from the agent registry.

**Synthesis rule (preserves these):**

1. **Lead agent emits ONE `agent.created` at scan start** with `payload.category="lead"`, `actor.agent_id="lead-<run_id>"`, `actor.agent_name="lead"`. This is the run's "real" agent.

2. **Each specialist-tool invocation emits a synthetic `agent.created` and a synthetic `agent.completed`** before / after the tool's internal LLM call. The synthetic agent's `agent_id` is derived deterministically from `(tool_name, invocation_seq)` so any two events emitted within one specialist-tool call carry the same `agent_id`. The `payload.category` matches the tool's specialist category (e.g. `xss-specialist`, `sqli-specialist`) — drawn from #89's `SPECIALIST_REGISTRY`.

3. **Tool calls emitted from inside a specialist-tool's internal LLM call carry the synthetic specialist `agent_id`** in `actor.agent_id` / `actor.agent_name` / `actor.agent_category`. This is what keeps `HypothesisPane` filtering by `agent_id` working — hypotheses opened by the XSS specialist tool show under the XSS specialist's synthetic agent.

4. **Tool calls emitted from the lead agent's outer loop** (e.g. `phase.entered`, `target.started`, top-level recon orchestration) carry the lead's `agent_id`.

The wrapper sees:
- One lead `agent.created` (vs today's parent `agent.created`).
- N synthetic specialist `agent.created` (vs today's N spawned-sub-agent `agent.created`).
- Per-tool-call `actor.agent_*` decorations preserved.

**Net effect for webappsec:** zero rendering change. The agent-graph view, the specialist activity pane, the per-agent budget meter, the live-pane filters all keep working.

**Test gate:** `tests/integration/agent_created_synthesis.py` — pin the count + payload shape against a golden DVWA scan recorded under both architectures.

### 1.4 Finding shape + mutation API

`finding.created` payload shape stays byte-identical. **Eager emission and refine-later** are layered as ADDITIVE primitives:

- New event type **`finding.updated`** (additive — old wrappers ignoring unknown events keep working) emitted by the new `update_finding` tool.
- `finding.updated` carries the same fingerprint + reproducibility_token; payload includes only the fields that changed plus `previous_values` for audit.
- The wrapper-side persistence layer in [`engine-usage.md §5.2.5`](engine-usage.md#525-surface-5--continuous-casefile-cross-scan-stable-identity) already keys on `fingerprint` for cross-scan dedup; receiving `finding.updated` is a strict subset of the already-supported "see same finding again" path.
- `vulnerabilities.json` post-update reflects the LATEST values per fingerprint; old wrappers reading the artifact at run-end see the merged shape regardless of how it was produced.

Closed-enum invariants preserved:
- `severity` ∈ `{info, low, medium, high, critical}`.
- `verification_status` ∈ `{verified, pattern_match, inconclusive, needs_review, could_not_verify}`.
- `verdict` ∈ `{tp, fp, partial_tp, needs_review, out_of_scope}`.
- `fp_reason` 13-value enum.
- `provenance` 6-value enum.

Eager emission specifically fires `verification_status="pattern_match"` + `confidence=0.7`; refine-later fires `update_finding(fingerprint, verification_status="verified", confidence=0.95)` after a validator confirms. Both endpoints already exist on the closed enums; no new enum values.

### 1.5 CLI flag surface

Every CLI flag stays — `--target`, `--scan-mode`, `--scope-mode`, `-n`, `--feedback-from`, `--max-cost`, `--max-input-tokens`, `--vendor-mode`, `--export-format`, `--compliance-pack`, `--instruction`, `--instruction-file`, `--diff-base`, `--quiet`, every existing flag. Migration adds at most:

- `STRIX_AGENT_ARCHITECTURE` env var = `legacy` (default during migration) | `single-lead` (new) — feature-gate so the rollout can be staged. After Phase 8 acceptance gate, default flips; the env var stays for one release cycle as an escape hatch then is removed.

### 1.6 Exit codes

Unchanged: `0` clean, `1` findings emitted, `2` CLI usage, `3` budget exceeded (#113), `≥10` engine internal. Exit-code mapping in [`engine-usage.md §1.4`](engine-usage.md#14-exit-codes) holds.

### 1.7 Schema versions

`features.schema_version`, `trajectory.jsonl[].schema_version`, `feedback.jsonl[].schema_version`, all bump only on **breaking** changes per [`engine-usage.md §6`](engine-usage.md#6-versioning--compatibility). The single-agent migration is non-breaking by construction (all changes are additive or implementation-internal). **No schema_version bumps in this migration.**

### 1.8 Phase events — checkpoints, not gates (semantic shift, no contract change)

Today strix rigidly serialises phases: recon → exploit → validate → report. The §8 commitment was "no phase blurring" with handoff artifacts (`surface_map.json` → `candidate_findings` → `verified_findings`).

Under single-lead the phases stay **conceptual** but stop being **gates**:

- `phase.entered` / `phase.completed` events still emit on every phase boundary (wrapper contract preserved).
- The lead agent decides when each phase is "done enough" rather than the framework enforcing serialisation.
- The lead can interleave: discover a new endpoint mid-exploit (treated as a recon checkpoint within the exploit phase), continue exploiting on a different endpoint, return to validate the original.
- `surface_map.json` still emitted at recon-phase completion (handoff artifact still exists; lead emits before declaring `phase.completed: recon`).
- `coverage.json` still tracks which categories were exercised across the whole run; per-phase attribution preserved.

**Wrapper-side impact: zero.** The wrapper consumes the same event sequence + the same artifacts. The shift is purely about which side decides "phase complete" — framework (today) vs lead-agent's own judgement (proposed).

**Roadmap.md §8 commitment update:** the architectural commitment ("phase gating") softens to "phase checkpoints with self-audit between." #140's `agent.self_audit` already runs between phases; this is the natural enforcement point. The commitment-text in §8 needs a footnote update during Phase 3 (see §4.2).

---

## 2. Internal architecture (what changes inside strix)

Everything below this line is internal — no observable wrapper-side change.

### 2.1 The lead-agent loop

Replaces today's `BaseAgent.agent_loop` semantics for the top-level run. Specialist sub-agents that are still spawned via raw `create_agent(...)` (legacy compatibility — see §3.4) keep using the existing loop.

```python
# strix/agents/lead_agent.py (NEW)

class LeadAgent(BaseAgent):
    """Single conversation that owns planning, specialist-tool dispatch,
    finding emission, and budget. Replaces the parent-spawns-N pattern.

    Internal use only. Wrappers see this as the "parent" agent — same
    `agent.created` payload shape (`category="lead"`).
    """

    def agent_loop(self) -> None:
        self._emit_synthetic_lead_created()  # invariant 1.3
        while not self._terminate():
            turn = self.think()  # one LLM call; may emit MANY tool calls
            if turn.has_tool_calls:
                # B.3 — parallel tool calls in one turn. The lead's
                # assistant message can contain N independent
                # tool_call blocks; we dispatch them concurrently and
                # observe N structured results in the next turn. This
                # is the pattern that recovers wall-time parallelism.
                results = self._invoke_tools_parallel(turn.tool_calls)
                self.observe_many(results)  # B.7 trust-tainted reasoning
                                            # routes here — annotate
                                            # each result with its
                                            # provenance class.
                if self._should_compact():           # §2.5
                    self._compact_context()
                if self._watchdog_should_force_exit():  # §2.6
                    self._force_finish_scan(reason="watchdog")
                    break
            elif turn.is_finish:
                break
            # Else: turn was thinking-only (no tool call); loop again.
            # Async tool completions land via observe_async (§2.7).
        self._emit_synthetic_lead_completed()

    def _invoke_tools_parallel(
        self, tool_calls: list[ToolCall],
    ) -> list[ToolResult]:
        """Dispatch N tool calls concurrently via thread-pool.
        Per-tool-call timeout (§2.6) enforced individually. Errors
        in one call don't fail siblings."""
        with ThreadPoolExecutor(max_workers=len(tool_calls)) as pool:
            futures = {
                pool.submit(self._invoke_tool_with_timeout, tc): tc
                for tc in tool_calls
            }
            return [f.result() for f in as_completed(futures)]
```

`_invoke_tool_with_timeout` routes through the existing `strix/tools/executor.py` pipeline — same #84 sanitiser, #139 provenance, #142 trajectory hooks fire. **No tool-side changes.**

The lead's system prompt template (`strix/agents/lead_agent/system_prompt.jinja`) explicitly instructs:

> **When you have multiple independent specialist-tool calls to make, emit them in a single assistant message with multiple tool_call blocks.** The framework will dispatch them concurrently. Examples: "scan_xss + scan_sqli + scan_idor on the same surface" → one assistant turn, three tool calls.

This is what makes single-lead competitive with multi-agent on wall-time.

### 2.2 The `specialist_tool` primitive

Specialists become tools via a registry decorator. Today's #89 `SpecialistProfile` reshapes from "agent profile" to "tool descriptor." **Two tool classes** are supported (per B.1 above):

#### 2.2.a Deterministic specialist-tools (`llm=False`) — the cheap class

Pure-Python checks; no internal LLM call. Cache manager not needed. Easiest migration target — many specialists today are already mostly-deterministic and just wrap shell tooling.

```python
@register_specialist_tool(
    category="misconfig-specialist",
    llm=False,                           # ← key distinction
    output_schema=SpecialistResult,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 30},
)
def scan_misconfig(
    *,
    url: str,
    auth_session: AuthSession | None = None,
) -> SpecialistResult:
    """Deterministic header / TLS / CSP checks. No LLM."""
    findings = []
    findings.extend(check_security_headers(url))
    findings.extend(check_csp(url))
    findings.extend(check_tls(url))
    return SpecialistResult(
        status="ok",
        findings=findings,
        dismissed=[],
        evidence=[...],
        next_probes_suggested=[],
    )
```

Candidates for `llm=False` migration: `scan_misconfig`, `scan_secrets` (regex-driven via #95), `scan_dependencies` (osv.dev / nvd_lookup), `port_scan` (naabu wrapper), `subdomain_takeover` (CNAME → 13-provider matrix). Most are already deterministic in their underlying tools (#95 / #8 / #16); the wrap-as-specialist-tool is mechanical.

#### 2.2.b LLM-driven specialist-tools (`llm=True`) — the Agent-pattern class

Internally fires a bounded LLM loop with a **cached system prompt** (per B.2). The lead invokes; the specialist's internal LLM observes the typed args + the cached system prompt + nested sandbox-tool sub-calls; emits a structured result.

```python
@register_specialist_tool(
    category="xss-specialist",
    llm=True,                                                    # ← key distinction
    system_prompt_path="strix/prompts/specialists/xss.jinja",
    output_schema=SpecialistResult,
    default_budget={"cost_usd": 0.30, "max_iterations": 8, "max_wall_seconds": 180},
    cache_ttl_seconds=3600,
    cached_tool_subset=[                # B.9 — bounded tool catalog for the inner LLM
        "send_request", "browser_action", "extract_dom",
    ],
)
def scan_xss(
    *,
    url: str,
    params: list[str],
    auth_session: AuthSession | None = None,
    target_summary: str,                # B.2 — bounded context, NOT inherited history
) -> SpecialistResult:
    """Internally invokes a focused LLM loop. Returns SpecialistResult."""
    ...
```

#### Properties enforced by the registry (both classes)

1. **Bounded input** (B.2). Args are typed Pydantic. The decorator validates that no `messages` / `conversation_history` / `parent_context` arg can be passed.
2. **Cached system prompt** (LLM class only — B.2). Registered via `cache_manager.register_cached_prompt(content, ttl)` (see §2.3). Subsequent invocations of the same tool reuse the cache.
3. **Structured output schema** (B.8). The `output_schema` defaults to `SpecialistResult`:
    ```python
    class SpecialistResult(BaseModel):
        status: Literal["ok", "error", "partial"]
        findings: list[FindingDraft]              # eager-emit candidates
        dismissed: list[DismissedHypothesis]       # negative evidence
        evidence: list[str]                        # raw evidence excerpts (capped)
        next_probes_suggested: list[str]           # planner input for the lead's next turn
        tool_metadata: dict[str, Any]              # specialist-specific (e.g. sqlmap session id)
    ```
    Parse failures fall back to `SpecialistResult(status="error", ...)` — never crashes the lead loop.
4. **Bounded tool catalog for LLM-driven specialists** (B.9). The `cached_tool_subset` arg pins which tools the specialist's internal LLM can see. The XSS specialist sees `send_request` / `browser_action` / `extract_dom`; not `port_scan` / `cve_lookup`. Smaller catalog = smaller cached prefix = lower per-call cost.
5. **Provenance preserved** (B.7). Internal LLM calls + nested sandbox-tool sub-calls all flow through the existing `executor.py` so #84 sanitiser, #139 provenance, #142 trajectory hooks fire. The LLM-driven specialist's prompt template includes the explicit provenance-reasoning section (B.7) so its internal reasoning respects the trust boundary.

Each existing #89 specialist becomes one `@register_specialist_tool`. Skills move from `LLMConfig.skills` into the tool's `cached_tool_subset`. Scope addendum becomes the leading section of the cached system prompt.

### 2.3 Cache manager (gemini cached-content + anthropic prompt caching)

Today: `strix/llm/llm.py:_add_cache_control` only handles anthropic via `cache_control: {type: ephemeral}`. Gemini cached-content is unbuilt.

```python
# strix/llm/cache_manager.py (NEW)

class CacheManager:
    def register_cached_prompt(
        self,
        *,
        content: str,
        model: str,
        ttl_seconds: int = 3600,
    ) -> CacheHandle:
        """Register a system-prompt for caching. Returns a handle the
        LLM call site uses to reference the cached portion. Provider-
        specific (anthropic / gemini / vertex) — handled internally."""
        ...

    def evict(self, handle: CacheHandle) -> None: ...
    def refresh(self, handle: CacheHandle, ttl_seconds: int) -> None: ...
```

Provider routing:
- **anthropic / claude**: extends current `_add_cache_control`. Per-tool cache key adds `cache_control: {type: ephemeral, key: "<tool_name>:<hash>"}`. Cost: $0.30/1M write + $0.03/1M read. Already-tested path; M-effort extension.
- **gemini / vertex_ai**: new integration via `google.genai.caching.CachedContent.create()`. Cost: $0.078/1M cached read. Cache-miss fallback re-creates transparently. **Net-new code; the largest unknown in the migration.**
- **openai / o1 / o3**: prompt caching is implicit — system prompts cached automatically when prefix matches. No-op handle returned.
- **other providers (ollama / lmstudio)**: no-op handle (cache is a perf optimisation, not a correctness primitive).

### 2.4 Eager emission + `update_finding` mutation

```python
# strix/tools/findings/update_finding.py (NEW)

@register_tool(sandbox_execution=False, provenance="framework")
def update_finding(
    *,
    fingerprint: str,
    verification_status: str | None = None,
    confidence: float | None = None,
    severity: str | None = None,
    poc_script_code: str | None = None,
    counter_proof: dict[str, Any] | None = None,
    additional_evidence: str | None = None,
) -> dict[str, Any]:
    """Mutate an already-emitted finding. Use after eager-emission +
    follow-up evidence (e.g. validator confirmed; severity needs bump)."""
    ...
```

Implementation:
- Looks up the existing finding by `fingerprint` in `tracer.vulnerability_reports`.
- Re-runs #86 canonical-finding contract validation on the merged payload.
- Re-runs #142 features extraction (the features block reflects latest values).
- Emits `finding.updated` event with `{fingerprint, fields_changed, previous_values}` payload.
- Re-runs cross-tool dedup (#98) + auto-dismiss (#142) so a now-verified finding correctly clears any stale auto-dismiss state.
- Updates `vulnerabilities.json` on next `save_run_data` so artifact reflects the merged shape.
- Closed-enum field changes validated (no new enum values; just transitions within the existing enum).

Eager emission shorthand:

```python
# In specialist-tool body:
if first_credible_evidence:
    emit_finding(
        title="Reflected XSS in /search",
        severity="medium",
        cwe="CWE-79",
        endpoint=f"{base_url}/search",
        verification_status="pattern_match",
        confidence=0.7,
        reasoning_trace=[ev1, ev2],
    )
    # later, after deeper probing:
    update_finding(
        fingerprint=<looked-up-from-emit>,
        verification_status="verified",
        confidence=0.95,
        poc_script_code=poc,
    )
```

### 2.5 Context compaction

Today: `strix/llm/memory_compressor.py` exists and runs in `_prepare_messages`. Compresses inline messages but does NOT summarise older turns.

Extension:
- New `compact_context(retain_findings=True, retain_hypotheses=True, summary_token_target=2000)` tool callable by the lead agent.
- Triggers automatically when `len(conversation_history) > 500K tokens`.
- Drops verbose tool outputs from older turns, replaces with `[Compacted: <one-line summary>]`.
- Always preserves: findings emitted so far, active hypotheses, the test plan, the most recent 10 turns at full fidelity.
- Existing `trajectory.jsonl` already captures the full pre-compaction history (events.jsonl is append-only and untouched), so the audit trail is complete regardless.

### 2.6 Watchdog + per-tool-call timeout

```python
class LeadAgent(BaseAgent):
    def __init__(self, ...):
        self._turns_since_progress = 0
        self._max_idle_turns = 5  # configurable

    def _watchdog_should_force_exit(self) -> bool:
        return self._turns_since_progress >= self._max_idle_turns

    def _record_progress(self, kind: Literal["finding", "endpoint", "phase"]):
        self._turns_since_progress = 0
```

"Progress" = a `finding.created` event OR a `target.completed` OR a `phase.completed`. If 5 turns pass without progress, force `finish_scan` with what's been collected. The lead emits a `run.terminated` event with `reason="watchdog_no_progress"` (re-uses #114 event shape, new reason value — additive).

Per-tool-call timeout: extend the existing #88 per-agent budget hook to also enforce a wall-time cap per `_invoke_tool` call. Default 60s; override per specialist-tool via the registry decorator.

### 2.7 Async / background specialist-tools (B.5)

Long-running specialist-tools (nuclei against 10K endpoints, masscan, recon-ng pipelines, browser_specialist's session-replay mode) shouldn't block the lead-agent loop. Today every tool call is synchronous and serialises wall-time.

Specialist-tools opt in via:

```python
@register_specialist_tool(
    category="bulk-recon-specialist",
    llm=False,
    async_capable=True,
    default_budget={"max_wall_seconds": 1800},  # 30-min cap
    ...
)
def bulk_subdomain_scan(*, domain: str, wordlists: list[str]) -> SpecialistResult:
    ...
```

Lifecycle:

1. **Lead calls** `bulk_subdomain_scan(domain="example.com", wordlists=[...])`. Tool returns `{status: "started", task_id: "task_abc123", eta_seconds: 600}` immediately. Same `tool.execution.started` event fires; `tool.execution.completed` does NOT fire yet.
2. **Lead continues** with other parallel tool calls (per B.3). It can call short-running specialists, emit findings on synchronous results, etc.
3. **Background task completes**. The framework emits the deferred `tool.execution.completed` event with the structured result. This becomes a notification message in the lead's next turn (similar to Claude Code's `Monitor` notifications).
4. **Lead observes** the late-arriving result + decides next probes. Findings + dismissals flow through the same `SpecialistResult` shape.

The lead's system prompt instructs:

> Long-running specialist-tools return `{status: "started", task_id, eta_seconds}` instead of `{status: "ok"}`. Continue with other work; the result will arrive as a system notification within `eta_seconds`. Do NOT poll — observe via natural turn progression.

**Wrapper-side impact:** zero. The `tool.execution.started` and `tool.execution.completed` events fire as today; just with potentially-large gaps between them on async tools. `events.jsonl` chain (#127) preserved.

**Implementation:** thread-pool worker per async task; framework-level task registry (`_async_task_registry`) tracks in-flight tasks; lead's `agent_loop` checks for completed async tasks at the top of each turn and observes their results before invoking `think()`.

**Cancellation:** lead can call `cancel_async_task(task_id)` if budget tightens. SIGTERM (#114) cancels all in-flight async tasks via the task registry.

### 2.8 Per-target-type tool-catalog filtering (B.9)

Today every agent's tool catalog includes ~130 tool schemas (~100K tokens). The lead agent's catalog is the union of every specialist-tool, every primitive tool, every threat-intel tool. That's the prompt-bloat risk #2 from the prior evaluation.

**Mitigation:** filter the lead's tool catalog at scan start by target type.

```python
# strix/agents/lead_agent/tool_catalog.py (NEW)

DEFAULT_CATALOG_BY_TARGET_TYPE = {
    "web_application": [
        # Specialist-tools
        "scan_xss", "scan_sqli", "scan_idor", "scan_csrf", "scan_ssrf",
        "scan_auth", "scan_business_logic", "scan_misconfig",
        # Primitives
        "send_request", "browser_action", "extract_dom",
        "ingest_har_file", "ingest_burp_file",
        # Coordination
        "open_hypothesis", "confirm_hypothesis", "dismiss_hypothesis",
        "emit_finding", "update_finding", "dismiss_finding",
        "agent_self_audit", "compact_context", "check_budget",
        # Threat intel (always-on)
        "cve_lookup", "kev_check",
    ],
    "repository": [
        "scan_secrets", "scan_dependencies", "scan_sast",
        "build_code_map", "taint_analysis", "score_reachability",
        "open_hypothesis", "confirm_hypothesis", "dismiss_hypothesis",
        "emit_finding", "update_finding", "dismiss_finding",
        "agent_self_audit", "compact_context", "check_budget",
        "cve_lookup", "kev_check",
    ],
    "domain": [...],
    "ip_address": [...],
    "local_code": [...],
}
```

~30-50 tools per catalog instead of 130. Saves 60-70K tokens of prompt per LLM call (compounds across the whole run).

**Escape hatch:** the lead can call `request_tool(category)` mid-run to load a specialist-tool schema not in the default set (mirroring Claude Code's `ToolSearch`). Useful when recon discovers an unexpected target shape (e.g. an `llm_app` endpoint inside a `web_application` target).

**Wrapper-side impact:** zero — the wrapper sees the same `tool.execution.*` events. Whether the lead's catalog had 30 tools or 130 isn't visible externally.

### 2.9 Budget introspection tool

The lead reasons over remaining budget when planning the next turn. New `check_budget()` tool exposes #113's run-level latch + #88's per-agent caps:

```python
@register_tool(sandbox_execution=False, provenance="framework")
def check_budget() -> dict[str, Any]:
    return {
        "cost_usd_consumed": 0.42,
        "cost_usd_cap": 1.50,
        "cost_usd_remaining": 1.08,
        "input_tokens_consumed": 85_000,
        "input_tokens_cap": 0,  # 0 = unlimited
        "wall_seconds_elapsed": 420,
        "wall_seconds_cap": 0,
        "cache_hit_ratio": 0.62,         # B.2 measurement
    }
```

Lead's system prompt:

> When `cost_usd_remaining` falls below `0.20` AND `findings_emitted` count is below baseline expectation, prioritise the highest-leverage remaining specialist-tool over breadth. Eager-emit on existing partial evidence rather than gathering more.

This is what makes "$2.50 cap exhausted with 0 findings" (incident #147) self-correctable.

---

## 3. Migration phases

Each phase ships as an independent PR. Phases are ordered so each builds on the prior; rollback is one-PR-revert.

| Phase | What ships | Effort | Invariant gate |
|---|---|---|---|
| **0.A** | Cost-bisection telemetry (`llm.token_breakdown` event) | S | Additive event; no invariant change. |
| **0.B** | Default-flip experiment (`inherit_context=False`) + opt-in flag | S | Cost falls from baseline; verify zero finding-output regression on DVWA. |
| **1** | `specialist_tool` registry + first specialist (`scan_misconfig` deterministic, no LLM) | M | Tool emits `tool.execution.*` per invariant 1.2. |
| **2** | Gemini cached-content integration + anthropic per-tool keys | M | No observable change (cost reduction is wrapper-invisible). |
| **3** | `LeadAgent` class + `specialist_tool` for 3 highest-leverage categories (XSS / SQLi / IDOR) | L | Synthetic `agent.created` rule (1.3) verified by golden-file diff. |
| **4** | Wrap remaining 9 specialists as tools | L | Same gate as Phase 3 for each. |
| **5** | `update_finding` mutation API + eager emission shorthand | S | `finding.updated` event added; old wrappers ignore unknowns; `vulnerabilities.json` post-update structurally identical. |
| **6** | Context compaction + watchdog + per-tool-call timeout | M | `events.jsonl` chain (#127) still verifies; `trajectory.jsonl` walk handles compacted segments. |
| **7** | Trajectory-capture re-anchoring | S | Per-finding trajectory still walks `tool.execution.*` upstream; new anchor logic produces equivalent records. Pin via golden-file diff. |
| **8** | Acceptance benchmark gate + flip `STRIX_AGENT_ARCHITECTURE` default to `single-lead` | M | `tests/benchmarks/{dvwa,juice-shop,demo.testfire.net}` all PASS at lower cost. Old wrappers (webappsec) pass full integration suite without code change. |

### 3.1 Phase 0.A — Cost-bisection telemetry

**Goal:** measure where the budget actually goes today, not infer.

- New event: `llm.token_breakdown` emitted on every LLM round-trip with `{system_tokens, tool_catalog_tokens, conversation_tokens, scope_addendum_tokens, output_tokens, cached_tokens, cost_usd}`.
- Aggregator: `tracer.token_breakdown_summary()` returns per-agent + per-call totals.
- New CLI `strix introspect tokens <run_dir>` prints a Pareto chart of cost-by-component.

**Invariant impact:** None. Pure telemetry addition. The new event is documented in [`engine-usage.md §3`](engine-usage.md) but optional for wrappers (additive).

**Test gate:** unit tests for the breakdown extraction; smoke test against a recorded LLM call.

### 3.2 Phase 0.B — Default-flip experiment

**Goal:** check whether 80% of the cost win comes from flipping `inherit_context=True` → `False` rather than full refactor.

- `create_agent` `inherit_context` default changes from `True` to `False`.
- Existing call sites in `spawn_webapp_specialist_team` etc. already pass `False` explicitly — they keep working.
- Call sites that depend on inheritance (notably the validator agent — currently a profile in #89 marked `inherit_context_default=False`, so unaffected) keep working.
- New `STRIX_INHERIT_CONTEXT_DEFAULT=true` env var lets ops re-enable inheritance run-by-run during transition.

**Invariant impact:** None — `inherit_context` is internal, never observed by wrappers.

**Test gate:** DVWA + juice-shop benchmark; total cost must not regress; finding count must match within ±1 of baseline.

**Decision gate:** If Phase 0.B closes ≥75% of the cost gap reported in incident #147 (target $0.65 from current $2.50; 0.B alone reaches < $1.00), the architectural shift becomes "deferred-nice-to-have" and Phases 1-8 sequence behind §18 unshipped rows. Otherwise — proceed.

### 3.3 Phase 1 — `specialist_tool` registry + deterministic-class first specialist

**Goal:** prove the registry pattern with a `llm=False` tool (per B.1) so cache + sub-LLM routing aren't on the critical path yet.

Pick `scan_misconfig` — deterministic checks (security headers, CSP / HSTS / X-Frame-Options, default-credentials, TLS posture). Today it's an LLM-driven specialist; replacing it with `llm=False` is a clean cost win regardless of whether subsequent phases ship.

- New `strix/tools/specialist/registry.py` with `@register_specialist_tool` decorator. Carries the full param surface from §2.2: `llm`, `system_prompt_path` (only when `llm=True`), `output_schema` (default `SpecialistResult`), `default_budget`, `cache_ttl_seconds`, `cached_tool_subset`, `async_capable`.
- New `strix/tools/specialist/scan_misconfig.py` — `llm=False` pure-Python implementation reading from existing `strix/tools/security_headers/` + `strix/tools/tls_audit/`.
- `SpecialistResult` model defined in `strix/tools/specialist/result.py` with the schema from §2.2.b.
- Lead-agent wiring deferred to Phase 3 — for now, the existing parent-agent treats `scan_misconfig` as just another callable tool. Backward-compat for the legacy mode.

**Invariant impact:** None observable. The tool emits standard `tool.execution.*` events.

**Test gate:** scan_misconfig findings on DVWA match the prior LLM-driven specialist's output set. Cost on this category drops to ~$0 (no LLM call). Registry decorator unit-tests cover param validation (rejects bare `messages` arg per B.2; rejects `system_prompt_path` when `llm=False`; rejects unknown `cached_tool_subset` entries).

### 3.4 Phase 2 — Cache manager

See §2.3 above.

**Invariant impact:** None observable. Cost reduction; same outputs.

**Test gate:** for anthropic models, cached-token-count > 0 on the second specialist-tool call within the same run; cost regression suite shows ≥30% reduction on long runs. For gemini, same — cached-content API reports cache hits.

### 3.5 Phase 3 — `LeadAgent` + first 3 specialist-tools (XSS / SQLi / IDOR)

The big architectural step. Lead agent runs the new loop with **parallel tool dispatch** (B.3); XSS / SQLi / IDOR specialists become `llm=True` tools.

- New `strix/agents/lead_agent.py` (`LeadAgent(BaseAgent)`) with the parallel-dispatch loop from §2.1.
- New `strix/agents/lead_agent/system_prompt.jinja` — explicitly instructs:
  - Parallel-tool-call dispatch when calls are independent (B.3)
  - `active_hypotheses.jsonl` as primary planning surface (B.6)
  - Provenance-tainted reasoning over tool results (B.7)
  - Eager-emit at first credible evidence; review on high-stakes (B.10)
- New `strix/agents/lead_agent/tool_catalog.py` — per-target-type catalog filtering (§2.8 / B.9).
- New `strix/tools/findings/check_budget.py` — budget introspection (§2.9).
- Existing `StrixAgent` stays — `LeadAgent` is selected via the new `STRIX_AGENT_ARCHITECTURE=single-lead` env var. Default stays `legacy` until Phase 8.
- `interface/main.py` reads the env var, instantiates `LeadAgent` or `StrixAgent` accordingly.
- `agent.created` synthesis (§1.3) implemented + tested with golden-file diff.

**Invariant impact:** Synthesised `agent.created` events MUST byte-match the old shape on every payload field except `agent_id` (which is intentionally derived from tool_name now). Golden file pinned per (target_type, scan_mode) tuple. **Phase events** (`phase.entered`/`phase.completed`) emit on lead-agent self-decided checkpoints rather than framework-enforced gates (§1.8 semantic shift) — wrapper sees same event sequence either way.

**Test gate:**
- `tests/integration/agent_created_synthesis.py` golden-file diff.
- `tests/integration/parallel_tool_calls.py` — verify N independent specialist-tool calls in one turn dispatch concurrently and observe N results in next turn.
- `tests/integration/wrapper_compat.py` — runs the legacy and new architectures against DVWA, diffs `events.jsonl` shape (allowing `agent_id` differences), pins `vulnerabilities.json` byte-equal.
- webappsec PR open (run via wrapper integration test) confirming HypothesisPane / coverage banner / Slack notifier all render correctly.

### 3.6 Phase 4 — Remaining 9 specialists

Wrap the rest of #89's `SPECIALIST_REGISTRY`:
- `auth-attacker`, `ssrf-scanner`, `csrf-specialist`, `business-logic-specialist`
- `secret-agent`, `dependency-agent`, `sast-agent`
- `subdomain-takeover-specialist`, `port-service-specialist`
- (validator-agent stays as a real sub-agent — see §3.7 risk).

Each migration is one PR. Test gate per-PR same as Phase 3.

**Existing scaffolding deflation:**
- `LeadTeam` class (#90) becomes a thin shim: `LeadTeam.spawn_many` → loops `specialist_tool(...)` calls. Existing tests pass unchanged via the shim.
- `spawn_webapp_specialist_team` (#92) → calls the new specialist-tools; legacy wrapper preserved for non-`single-lead` mode.
- `spawn_code_specialist_team` (#95) → same.
- `spawn_webapp_subteam` (#93) → same.

**Invariant impact:** Per-tool gate same as Phase 3.

### 3.7 Phase 5 — `update_finding` + eager emission

See §2.4.

**Invariant impact:**
- New event `finding.updated` is ADDITIVE — old wrappers ignore unknowns per [`engine-usage.md §6`](engine-usage.md#6-versioning--compatibility). `webappsec/usage.md §6` already supports this.
- `vulnerabilities.json` post-update reflects merged values; old wrappers reading the artifact see no schema change.
- `finding.created` shape unchanged; only the per-finding trajectory gets a longer event chain.

**Test gate:** mutation correctness + #86 contract revalidation + #142 features re-extraction + #98 cross-tool dedup composition.

### 3.8 Phase 6 — Context compaction + watchdog + async specialist-tools

See §2.5 + §2.6 + §2.7.

This phase combines the two mechanisms that handle long-running runs:
- **Context compaction** — keeps the lead's conversation under ~500K tokens.
- **Watchdog + per-tool-call timeout** — catches stuck-loop pathologies.
- **Async / background specialist-tools** (B.5 / §2.7) — long-running probes (nuclei against 10K endpoints, masscan, recon-ng pipelines) opt into `async_capable=True`, return a `task_id` immediately, and the lead observes their completion as a deferred `tool.execution.completed` event.

**Invariant impact:**
- `events.jsonl` hash-chain (#127) preserved — chain still walks left-to-right; compaction is in-memory only.
- `run.terminated.payload.reason` adds a new value `watchdog_no_progress` (additive within the closed-enum because [`engine-usage.md §6`](engine-usage.md) treats unknown reason values as informational).
- Async tool: `tool.execution.started` and `tool.execution.completed` events still fire as today; the gap between them just gets larger on async tools. Wrapper sees no schema change.

**Test gate:**
- Forced-stuck-agent test (mocked LLM returning `think` 6 turns in a row); watchdog fires; `run.terminated` emitted; exit code 0 (or 1 if findings); `vulnerabilities.json` reflects collected findings.
- Async-tool integration test: fire `bulk_subdomain_scan(...)` with mocked 60s wall-time; lead continues with parallel synchronous calls; deferred `tool.execution.completed` arrives; lead observes + emits findings from the async result.
- Long-run compaction test: 200-turn synthetic run; compaction triggers ≥3 times; final `vulnerabilities.json` count matches non-compacted baseline.

### 3.9 Phase 7 — Trajectory-capture re-anchoring

Today's `strix/telemetry/trajectory_capture.py` walks events backwards from `finding.created` to `agent.created`, collecting events sharing `actor.agent_id`. Under one lead agent, every event has the same agent_id, so the walk would over-collect.

**Re-anchor logic:**
1. Walk backwards from `finding.created`.
2. Stop at the **previous specialist-tool's `agent.completed`** (the synthetic one from §1.3 step 2) — not at the lead's `agent.created`.
3. Collect events with the same synthetic specialist `agent_id` (the one that emitted the finding).

This produces per-finding trajectories that are scoped to the specialist tool that emitted, not the entire lead-agent history.

**Invariant impact:** `trajectory.jsonl` schema unchanged. Per-finding event count smaller (just the specialist's invocation, not the whole run) — improves the labeler's grading signal.

**Test gate:** golden-file diff per finding on DVWA; trajectory length within reasonable bounds (5-50 events per finding).

### 3.10 Phase 8 — Benchmark gate + default flip

- `tests/benchmarks/` runs DVWA + juice-shop + demo.testfire.net under both architectures.
- PR sets `STRIX_AGENT_ARCHITECTURE=single-lead` as the default.
- `STRIX_AGENT_ARCHITECTURE=legacy` env var stays for one release cycle as escape hatch.

**Acceptance criteria** (from RFC):

| Metric | Baseline (legacy) | Target (single-lead) | Gate |
|---|---|---|---|
| Total cost on demo.testfire.net | $2.50 (cap) | $0.50-$0.80 | hard pass |
| Wall time | 45 min | 15-20 min | hard pass |
| `finding.created` events | 0 (incident #147) | ≥10 of 20 baseline | hard pass |
| `coverage_percent` | 0% | ≥70% | hard pass |
| webappsec integration suite | green | green (zero wrapper change) | hard pass |
| `events.jsonl` schema diff vs legacy | n/a | additive only | hard pass |
| `vulnerabilities.json` shape diff | n/a | byte-equal except finding count | hard pass |

**Test gate:** all of the above. Any miss → PR not merged; investigate; revert if needed.

---

## 4. Roadmap.md changes

The work above is currently untracked in `roadmap.md`. Add:

### 4.1 New section §8.5 — Single-lead-agent architecture migration

After §8.4 ("IP / network team"), before §9 ("Multi-tool orchestration"):

```markdown
## §8.5 Single-lead-agent architecture migration

The §8 specialist-team scaffolding (#89, #90, #92, #93, #95) ships as
parent-spawns-N-sub-agents. The RFC at [`docs/proposals/2026-05-06-
single-lead-agent-architecture.md`](docs/proposals/2026-05-06-single-
lead-agent-architecture.md) (PR #148) argues for replacing it with a
single lead agent + specialist-tools. Implementation plan in
[`single-agent.md`](single-agent.md).

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Phase 0.A — cost-bisection telemetry.** New `llm.token_breakdown` event on every LLM round-trip. Decision-gate input. | Without per-component cost data, the architectural decision is inference. | New: `strix/llm/llm.py` + new event. | S |
| ⬜ | **Phase 0.B — `inherit_context=False` default.** Flip the default; opt-in env var for the legacy behaviour. | If this captures the bulk of the cost win, full migration becomes optional. | `strix/tools/agents_graph/agents_graph_actions.py` line 388. | S |
| ⬜ | **Phase 1 — `specialist_tool` registry (with `llm=True/False` distinction) + `scan_misconfig` (`llm=False`) first migration + `SpecialistResult` schema.** | Proves the pattern with a deterministic tool (no LLM-routing on the critical path). Pins the `SpecialistResult` shape every subsequent specialist-tool returns. | New: `strix/tools/specialist/registry.py` + `result.py` + `scan_misconfig.py`. | M |
| ⬜ | **Phase 2 — gemini cached-content + anthropic per-tool keys.** | Cache-hit pricing is the load-bearing assumption for the architectural shift. Today only anthropic system-prompt caching is wired. | New: `strix/llm/cache_manager.py`. Provider-specific routing. | M |
| ⬜ | **Phase 3 — `LeadAgent` class + parallel-tool-dispatch loop (B.3) + 3 LLM-driven specialist-tools (XSS / SQLi / IDOR) + synthetic `agent.created` rule + per-target-type catalog filtering (§2.8) + `check_budget` (§2.9).** | Architectural step. Lead's system prompt explicitly instructs parallel-tool-calls, `active_hypotheses.jsonl` as todo list (B.6), provenance-reasoning (B.7), eager-emit-then-review (B.10). Behind `STRIX_AGENT_ARCHITECTURE=single-lead` env-gate. | New: `strix/agents/lead_agent.py` + `lead_agent/system_prompt.jinja` + `lead_agent/tool_catalog.py` + `strix/tools/findings/check_budget.py`. | L |
| ⬜ | **Phase 4 — wrap remaining 9 specialists as `llm=True` tools (and migrate any deterministic remainders to `llm=False`).** | One PR per specialist for reversibility. | `strix/tools/specialist/`. | L |
| ⬜ | **Phase 5 — `update_finding` mutation + eager-emission shorthand + review-then-emit pattern for high-stakes findings (B.10).** | Eager emission requires partial-finding write + later refinement. New `finding.updated` event (additive). Review path composes with §17.1 / §18 row 1 validator. | New: `strix/tools/findings/update_finding.py`. | S |
| ⬜ | **Phase 6 — context compaction + watchdog + per-tool-call timeout + async / background specialist-tools (B.5 / §2.7).** | Lead-agent context bloat past ~500K hurts attention quality; watchdog catches stuck-loop pathologies; async tools handle nuclei / masscan / recon-ng without blocking the lead loop. | Extend `strix/llm/memory_compressor.py` + `strix/agents/lead_agent.py` + new `strix/tools/specialist/async_dispatch.py`. | M |
| ⬜ | **Phase 7 — trajectory-capture re-anchoring.** | Per-finding trajectory anchors on specialist-tool boundaries instead of `agent.created` so #142 features stay meaningful. | `strix/telemetry/trajectory_capture.py`. | S |
| ⬜ | **Phase 8 — benchmark gate + default flip to `single-lead`.** | Acceptance gate on demo.testfire.net + DVWA + juice-shop. webappsec integration suite must pass with zero wrapper change. Cache-hit-ratio ≥60% gate (B.2 measurement). | `tests/benchmarks/`. | M |

**Total: 10 PRs, ~10-14 weeks for one engineer (depending on Phase 0
results).** Decision gate after Phase 0.B can de-prioritise Phases 1-8
to behind §18 unshipped rows if the default-flip captures most of the
win.

**Invariant:** the wrapper-engine interface defined in
[`engine-usage.md`](engine-usage.md) MUST NOT change observably across
this migration. webappsec ships zero wrapper code as part of this
work.
```

### 4.2 Annotate existing §8 rows that deflate

Add a footnote line under each of these existing rows:

- §8.0 row "Documented lead-team protocol" (#90):
  > _Note: under [§8.5 single-lead architecture](#85-single-lead-agent-architecture-migration), `LeadTeam` deflates to a thin shim over specialist-tool calls. The protocol document stays as the OODA-loop contract; the implementation moves from `lead_team.py` to `lead_agent.py`._

- §8.0 row "Specialist scope discipline" (#89):
  > _Note: under §8.5, the `SPECIALIST_REGISTRY` reshapes from "agent profile" to "tool descriptor." Skills + scope-addendum + budget caps move into the tool's internal LLM-call args. Wrapper-visible `agent_category` tags preserved by the synthetic-`agent.created` rule._

- §8.2 row "spawn_webapp_specialist_team" (#92), §8.1 row #95, §8.3 row #93:
  > _Note: under §8.5 these orchestrators become parallel-fan-out wrappers over `specialist_tool` calls. Public API unchanged for backward compatibility during migration._

### 4.3 Recently-shipped table — no change

The §8 PRs (#89, #90, #92, #93, #95) stay in "Recently shipped." They're not unshipped by this migration; they're re-shaped internally. Their externally-visible primitives (`spawn_webapp_specialist_team` tool, `LeadTeam` helper API) keep working.

### 4.4 §18 row references — no change

The §18 minimum-viable-AI-security-engineer table doesn't need new rows. The migration is enabling work for §18 (faster + cheaper specialist runs help every §18 row), not a §18 row itself.

---

## 5. Risks + decision gates

### 5.1 Phase 0 decision gate

**Gate question:** does flipping `inherit_context=False` as default (Phase 0.B) close ≥75% of the cost gap?

- **Pass** ($0.65-$1.00 on demo.testfire.net): proceed to Phase 1.
- **Marginal** ($1.00-$1.50): proceed to Phase 1 but re-evaluate after Phase 2 (cache integration) measurement.
- **Fail** (>$1.50 — most of the cost is NOT inheritance): proceed to Phase 1 with high confidence the full architectural shift is needed.

### 5.2 Phase 3 wrapper-compat gate

**Gate question:** does webappsec's full integration suite pass against the new architecture without any wrapper-side change?

If any wrapper test fails, the synthetic `agent.created` rule (§1.3) is wrong. Iterate until green; do NOT merge Phase 3 with wrapper-side breakage.

### 5.3 Phase 8 acceptance gate

**Gate question:** do the RFC's quantitative criteria all pass?

If any hard-pass criterion misses, do not flip the default. Investigate; iterate. The `STRIX_AGENT_ARCHITECTURE=legacy` escape hatch lets the migration ship with the new code in place but the old behaviour active until the criteria pass.

### 5.4 Validator agent (§17.1) interaction

The validator agent (§17.1, currently unshipped, listed in §18 row 1) was designed to spawn as a real sub-agent (not a tool) so it can reason fresh on candidate findings. Under §8.5 it could become a `validate_finding(fingerprint)` tool that internally re-runs exploitation, but this is a meaningful design change.

**Decision:** keep validator-agent as a real sub-agent for the foreseeable future. The single-lead architecture treats it as the one exception (the lead agent invokes `create_agent(category="validator-agent", ...)` directly, paying the spawn cost for ~1 specialist instead of N).

This is consistent with #89's existing `inherit_context_default=False` for the validator profile.

### 5.5 Schema-version bump risk

If during implementation any of the invariants in §1 turn out to require a schema_version bump, that's a hard stop. The migration must instead engineer around it (extend the additive event/field set, not break existing consumers).

If a bump is genuinely unavoidable, this becomes a **wrapper-coordinated migration** — webappsec ships a parallel PR; the strix migration waits on the wrapper deploy. This is the failure mode this whole document is structured to avoid.

### 5.6 Long-running scan + cache invalidation

Cache prefixes drift as the lead agent's conversation grows. If cache-hit ratio drops below ~40% mid-scan, Phase 2 cost benefits evaporate.

**Mitigation:**
- Cache TTL = max(1h, scan_duration * 1.5) so the cache lives long enough for the scan.
- Cache-key derivation uses the SUMMARISED prior turns (post-Phase-6 compaction), not the full turn-by-turn — so compaction stabilises the prefix.
- Phase 0.A telemetry includes per-turn cache-hit ratio; Phase 8 gate checks ratio ≥60% across the whole scan.

---

## 6. What webappsec needs to do

**Nothing.** That's the point.

If the migration ships correctly:
- Existing webappsec PRs (#49 HypothesisPane, #58 budget meter, #62 Slack notifier, #64 coverage banner) keep rendering correctly.
- The wrapper's persistence layer keyed on `fingerprint` already supports the new `finding.updated` semantics (it's the same path as "see same finding again across runs").
- The integration test suite in webappsec that runs strix on DVWA / juice-shop should pass byte-for-byte on `events.jsonl` schema, structurally on `vulnerabilities.json`, and matching-counts on findings.

If anything breaks on the wrapper side, it's a strix-side bug — file a strix-side PR to fix the synthesis logic, not a wrapper change. The whole point of treating the wrapper interface as an invariant is that internal refactors never become wrapper deploys.

---

## 7. Open questions

1. **Should the synthetic `agent.created` events emit a sentinel field** (e.g. `payload.synthetic: true`) so wrapper authors who care can distinguish "real spawn" from "specialist-tool synthetic"? — Strict interpretation of invariant 1.2 says no (additive risk). Pragmatic interpretation says yes for forward-compat. **Defer to Phase 3 PR review.**

2. **Should Phase 5's `finding.updated` carry the full merged payload or just the delta?** — Wrapper auditing benefits from a full payload (no need to reconstruct); cost benefits from a delta. **Recommendation:** delta + `previous_values`. Wrapper that wants the full merged payload reads the latest from the in-memory cache or `vulnerabilities.json` at run-end.

3. **Does `update_finding` apply to auto-dismissed findings?** — Per [`engine-usage.md §4.5`](engine-usage.md#45-force-show--re-promote-pattern), the wrapper writes a `verdict=tp` label to force-show. If the engine itself updates an auto-dismissed finding (e.g. validator confirms it's real), the auto-dismiss mutation should clear. **Implementation rule:** `update_finding` with `verification_status="verified"` clears `auto_dismissed=False`, records `re_promoted=True`, emits `finding.re_promoted` (new additive event).

4. **Phase 4 specialist ordering** — which 9 specialists to wrap, and in what order? **Recommendation:** by call frequency in production runs (highest-leverage first), measured during Phase 0.A.

5. **Backward-compat duration** — how many releases stays `STRIX_AGENT_ARCHITECTURE=legacy` valid? **Recommendation:** one full release after Phase 8 default-flip; remove in the release after that. Document the deprecation in [`engine-usage.md §6`](engine-usage.md#6-versioning--compatibility) the moment Phase 8 ships.

---

## 8. Reference

| File | Purpose |
|---|---|
| [`docs/proposals/2026-05-06-single-lead-agent-architecture.md`](docs/proposals/2026-05-06-single-lead-agent-architecture.md) | RFC (the why) |
| [`single-agent.md`](single-agent.md) (this doc) | Implementation plan (the how) |
| [`engine-usage.md`](engine-usage.md) | Wrapper-engine contract (the invariants) |
| [`roadmap.md`](roadmap.md) §8.5 | Tracked work items |
| [`docs/lead-team-protocol.md`](docs/lead-team-protocol.md) | OODA-loop contract — refresh after Phase 4 |
| [`docs/incidents/2026-05-05-tool-server-unreachable.md`](docs/incidents/2026-05-05-tool-server-unreachable.md) | Symptom #1 |
| [`docs/incidents/2026-05-06-finding-emission-starvation.md`](docs/incidents/2026-05-06-finding-emission-starvation.md) | Symptom #2 |
| [`wrapper-wishlist.md`](wrapper-wishlist.md) §15 + §16 | Operator-UX surfaces (no change required) |

The whole migration succeeds if and only if [`engine-usage.md`](engine-usage.md) is unchanged at the end of Phase 8 — and the wrapper authors never had to read this document.
