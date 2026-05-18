# Scan-mode cost optimization

**Status:** Phase 1 in flight (2026-05-19) · **Owner:** ClatTribe/strix
**Tracking:** masterroadmap §11 (cost) · engine-wishlist §4 (scan-mode gate)

## Problem

`--scan-mode quick|standard|deep` ships today as a *prompt-level* nudge: it
swaps which `strix/skills/scan_modes/*.md` body lands in the system prompt
and bumps `reasoning_effort` low/medium/high. Everything else — specialist
dispatch loops, recon depth, KG churn, verification rounds — is unchanged
across modes.

Result: a `quick` scan and a `deep` scan against the same target spend the
same order-of-magnitude in LLM calls. With Gemini 2.5 Flash today a single
standard run of a vulnerable web app routinely lands in the $0.40–$1.20
range; deep mode tips into $3+ for OWASP Juice Shop. That isn't
defensible for the "rapid triage" promise of `quick`, and it caps how
many scans a wrapper operator can pay for per day.

## Where the spend actually goes

Per-phase LLM-call breakdown for a representative `web_application`
standard scan (instrumented via tracer.cost_usd line-items):

| Phase                  | Calls       | Share of total cost |
|------------------------|------------:|--------------------:|
| Boot / system-prompt   |  1 (~80K ctx) | 5 % |
| Recon                  |   5–15      |  8 % |
| Surface mapping        |   3–10      |  5 % |
| **Specialist dispatch** | **N × (5–20)** | **60–70 %** |
| Lead-between-dispatches |   1–3 × N   | 10 % |
| Verification           |   5–15      |  7 % |
| Report                 |   3–8       |  5 % |

`N` = number of `dispatch_specialist(...)` calls the lead makes. On
juiceshop with current heuristics, `N` ranges 6 (clean run) → 28
(saturated lead, repeated dispatches against the same surface). Each
dispatch is its own fresh-context inner loop that re-pays the system
prompt + skill-body cost.

**Single highest-leverage knob: cap N.** Every other phase is bounded by
either the catalog or the workflow; specialist dispatch is the one
unbounded multiplier today.

## Proposal — five phases

### Phase 1 — engine-level scan-mode gate (this PR)

Convert `--scan-mode` from a prompt nudge into a hard engine gate at the
dispatch boundary.

| mode      | dispatch cap | behaviour |
|-----------|-------------:|-----------|
| `initial` | **0**        | newly-discovered-asset fast pass; deterministic-only |
| `quick`   | **0**        | deterministic scan + inner-LLM only on high-signal endpoints; no fresh-context loops |
| `standard`| **8**        | bounded multi-round; matches today's median good run |
| `deep`    | unbounded    | current behaviour, no change |

Wiring:

- `STRIX_SCAN_MODE` env is set at scan boot (`cli.py` / `tui.py`)
  from `scan_config["scan_mode"]`.
- `strix/agents/specialist_orchestrator.py` adds a module-level
  `_DISPATCH_COUNT` and `get_scan_mode_dispatch_cap()` helper.
- `dispatch_specialist(...)` checks the cap before building the
  fresh-context loop. Over-cap returns immediately with
  `status="DENIED_BY_SCAN_MODE"`, `reason="scan_mode=quick caps
  specialist dispatch at 0"`, and counts as a zero-cost no-op.
- `STRIX_DISPATCH_CAP_OVERRIDE=<int>` is an escape hatch for the
  wrapper to bypass the mode-derived cap when it has a budget reason.
- `--scan-mode initial` (engine-wishlist §2) shares the `quick` cap.

Effort: S. Surface: orchestrator + 2 boot sites + skill-body refresh.
**Expected impact: 60–80 % cost reduction on `standard`, 90 %+ on
`quick`, on workloads where the lead currently over-dispatches.** No
change to `deep`.

### Phase 2 — system-prompt + skill-body compression

The system prompt is ~80K tokens cached. That's fine for the lead (one
call per scan), but every `dispatch_specialist` invocation re-pays the
specialist's *own* system prompt (~25K) into a new conversation. Across
8 dispatches that's 200K of repeated prompt cost.

- Move the specialist skill bodies behind a Decepticon-style two-level
  menu — Level 1 (one-line per skill) lands in the prompt; Level 2
  (full body) loads on `get_skill_detail(name)` only when the
  specialist asks.
- Trim `scan_modes/*.md` from prose-heavy docs to terse decision
  tables. Today the `quick.md` body alone is 70 lines.
- Compress profile `system_prompt_addendum` blocks; the per-category
  addendums each duplicate 5–10 lines of "remember to be precise" boilerplate.

Effort: M. Expected impact: 30–50 % cut on specialist boot cost. No
behavioural change.

### Phase 3 — model routing per role

The lead does orchestration (planning, dispatch decisions, status
reads). The specialists do probing and exploit reasoning. They have
very different latency/accuracy profiles.

- Lead: Gemini Flash / Claude Haiku-tier — cheap, fast, good enough for
  routing decisions and dispatch choice.
- Specialists: Claude Sonnet or Gemini Pro for the exploit-reasoning
  step; the deterministic tool calls inside the specialist loop don't
  benefit from a strong model anyway.

Wire via `STRIX_LEAD_LLM` / `STRIX_SPECIALIST_LLM` overrides on top of
the existing `STRIX_LLM`. Backward-compatible default: both fall back
to `STRIX_LLM`.

Effort: M. Expected impact: 40–60 % cut on lead-side cost (which is
the bulk of the "between-dispatches" calls), no quality regression.

### Phase 4 — lazy specialist activation via KG signals

The lead today dispatches a recon specialist plus several
vulnerability-class specialists in a rough fixed rotation. Many of
those dispatches no-op because the KG never showed evidence for that
class (no SAML endpoint → no XSW dispatch).

- Gate dispatch on KG node-kind signals: only dispatch
  `saml-xsw-specialist` if the KG has an `auth` node with
  `subtype=saml`; only dispatch `idor` specialists if there's a
  `numeric_id_pattern` node, etc.
- Use the existing `get_skills_for_kg_node()` /
  `get_skills_for_discovered_asset()` mappings (Skills §6) as the
  signal source.

Effort: M. Expected impact: 20–30 % cut on `standard` mode by
suppressing dispatches that would have no-opped anyway.

### Phase 5 — pre-flight cost estimator

Surface the predicted cost band before the scan starts, so the operator
can choose mode + caps with intent:

```
$ strix --target https://juice.local --scan-mode standard --estimate
estimated cost: $0.35–$1.10  (standard, 8-dispatch cap)
estimated wall: 6–14 min
proceed? [y/N]
```

Effort: S. Builds on phases 1 + 3 — we have the cap from phase 1, the
per-call price from phase 3, and the historical mean from baseline
JSONs.

## Combined impact

| mode      | today      | after phases 1+2+3+4 | reduction |
|-----------|-----------:|---------------------:|----------:|
| `quick`   |   $0.40    |   $0.04              |    90 %   |
| `standard`|   $0.80    |   $0.20              |    75 %   |
| `deep`    |   $3.00    |   $1.80              |    40 %   |

`deep` improves least because the cap is uncapped by design — its
spend comes down only from phases 2 and 3 (compression + routing).

## Non-goals

- Reducing recall on the `must_find` set in `expected.yaml`. The CI
  benchmark gate enforces this — any phase that drops a `must_find`
  hit on `standard` mode reverts.
- Removing specialist dispatch entirely. The fresh-context loop is
  worth its cost on `deep` and on hard targets; this proposal makes
  it *opt-in* per mode, not gone.
- Reordering the existing seven workflow phases. The phase model
  itself is fine; this is about how much the lead spends inside each
  phase.

## Validation plan

1. **Unit** — `tests/agents/test_specialist_orchestrator_scan_mode.py`
   asserts the cap is enforced per mode, with an env override.
2. **Integration** — re-run the benchmark suite on `quick` and
   `standard` after phase 1 lands. Compare `cost_usd` and
   `recall_must_find` against the previous baseline.
3. **CI gate** — fail the benchmarks workflow if recall on
   `standard` drops more than 5 percentage points relative to the
   prior baseline.

## Phase 1 acceptance

- [ ] `STRIX_SCAN_MODE` set at scan boot in `cli.py` + `tui.py`.
- [ ] `get_scan_mode_dispatch_cap()` returns 0 / 0 / 8 / None for
      initial / quick / standard / deep.
- [ ] `dispatch_specialist` short-circuits over-cap with
      `DENIED_BY_SCAN_MODE` and increments no counters.
- [ ] `reset_for_testing()` resets the dispatch counter.
- [ ] Unit tests cover all four modes + the env override + reset.
- [ ] `scan_modes/{quick,standard}.md` mention the dispatch cap
      so the specialists' own prompt is honest about what's allowed.
