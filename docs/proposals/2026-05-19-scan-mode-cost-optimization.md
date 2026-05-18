# Scan-mode cost optimization

**Status:** Phase 1 merged (PR #334, 2026-05-19) · v2 amendment 2026-05-19
**Owner:** ClatTribe/strix
**Tracking:** masterroadmap §11 (cost) · engine-wishlist §4 (scan-mode gate)

## v2 amendment — recall-first reframe

The original v1 proposal stacked phases optimistically and claimed a 5x
cut on `standard` mode. Honest analysis showed (a) recall risk on
phases 2/3/4 as written, and (b) the actual deliverable post-phase-1
is ~2.5-3x on `standard` if every subsequent phase stays recall-safe.

This document is now **recall-first**: every optimization below is
gated on "if implementing this could cause a single `must_find`
finding to drop, it's off the list." We accept smaller cost cuts to
guarantee recall preservation, because the competitive defensibility
of Strix lives in the 40-60% of must_find findings that deterministic
scanners cannot reach (BOLA, BFLA, mass assignment, business logic,
chained exploits, novel patterns). Damaging recall to chase a cost
number erases the product's reason to exist.

The original phase 2 (compression), phase 3 (model routing), and
phase 4 (KG-gated dispatch) sections below are retained for
historical context, but **superseded** by the per-workflow-phase
recall-safe analysis that follows them.

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

### Phase 1 — engine-level scan-mode gate (MERGED — PR #334)

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

### Phase 2 (v1, SUPERSEDED) — system-prompt + skill-body compression

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

### Phase 3 (v1, SUPERSEDED) — model routing per role

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

### Phase 4 (v1, SUPERSEDED) — lazy specialist activation via KG signals

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

### Phase 5 (v1, KEPT) — pre-flight cost estimator

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

## Recall-first per-workflow-phase optimization (v2)

The v1 phases 2-4 above are superseded by this section. Instead of
re-shaping the architecture (compression / routing / KG gating), we
audit each of the seven workflow phases and pull only the wins that
*cannot* damage recall.

The gate for every item below: **if implementing this could cause a
single `must_find` finding to drop on the existing benchmark suite,
it's off the list.** We accept smaller cost cuts to guarantee that
the specialist edge (BOLA, BFLA, mass assignment, business logic,
chained exploits, novel patterns) stays intact.

### Workflow phase 1 — Boot (~5% cost, 1 call)

**Risk-free wins**

- **Persist rendered boot prompt across runs on the same target.**
  Anthropic ephemeral cache is 5min — a re-scan an hour later pays
  full freight. Serialize the rendered system prompt to disk under
  `strix_runs/<target_hash>/boot.txt`; replay on re-scan. ~70% cut
  on re-scans, 0 on first scan, **zero recall impact** (identical
  prompt).
- **Dedupe boilerplate across skill bodies.** Multiple skills repeat
  "stay in scope, emit `create_vulnerability_report`, call
  `complete_objective`" — factor into one shared preamble.
  ~5-10% byte reduction in the boot prompt.
- **Strip target-type-incompatible tool descriptions.** Audit
  whether `tool_catalog.py`'s filtering prunes the prompt or just
  hides tool names. If hidden-but-still-described, fix it. The lead
  cannot call them anyway, so no recall risk.

**Anti-pattern (do not do):** trimming skill body *substance* —
variant tables (SAML XSW's 8 variants), payload contexts (SQLi's
string/numeric/boolean/time-based axes), gotcha lists. That is
where the specialist edge lives.

### Workflow phase 2 — Recon (~8% cost, 5-15 calls)

**Risk-free wins**

- **Batch endpoint classification.** Today the lead makes N
  sequential "endpoint X, classify" calls. Replace with a single
  "here are N endpoints from httpx+gobuster+spider, return a JSON
  array of classifications" call. ~80% recon-LLM cost cut, same
  recall — same evidence, same reasoning, batched.
- **Cache recon output for same-target re-scans.** Persist
  `recon.json` keyed by `(target_url, target_content_hash)`.
  Re-scans diff against the cache; LLM only sees the *new* surface.
  Major win on iterative scans.
- **Push deterministic correlation OUT of LLM calls.** Joining
  `httpx` output with `subfinder` output with `nuclei`-discovered
  tech stack is a Python `dict.update`, not a reasoning task. Do
  the join in code; pass the LLM the *correlated* view.

**Anti-pattern:** skipping endpoint discovery for "obviously
low-value" paths. Recon misses cascade into missed surface, which
cascades into missed findings. Cheapen the *interpretation*, not
the *collection*.

### Workflow phase 3 — Surface mapping (~5% cost, 3-10 calls)

**Risk-free wins**

- **Memoize auth-pattern detection.** ~95% of apps fit one of:
  Bearer JWT, session cookie, OAuth bearer, SAML SP, API key,
  Basic. Detect via regex on observed `Authorization` / `Set-Cookie`
  / `WWW-Authenticate` headers. LLM only adjudicates ambiguous
  mixes.
- **Push trust-boundary mapping into a deterministic correlation
  step.** A trust boundary is structurally
  `{endpoint, required_auth_state, allowed_roles}`. Build it as a
  structured artifact from observed traffic, not an LLM narrative.
  LLM *consumes* the structured map; doesn't construct it.
- **Lazy tech-stack fingerprinting.** Don't fingerprint stack until
  the first dispatch that needs it. Pure ordering change; no recall
  impact.

**Anti-pattern:** skipping role-boundary mapping on apps that
appear single-user. Many SaaS apps have hidden admin roles —
always map the boundary even if only one role is observed.

### Workflow phase 4 — Specialist dispatch (~60-70% cost, N × 5-20 calls)

Already capped at 8 on `standard` (PR #334). Beyond the cap:

- **Verdict cache keyed on `(category, endpoint-shape, auth-state)`.**
  If `dispatch_specialist('sqli', /api/v1/users/{id})` returned
  BLOCKED with reason "no SQL backend, ORM only", skip the same
  category on `/api/v1/users/{id}/profile` and
  `/api/v1/users/{id}/settings` — same backend, same verdict. The
  shape canonicalization is: same prefix + same param pattern +
  same auth state. ~25-40% dispatch cut on CRUD-heavy APIs.
  **Recall-safe because we cache verdicts, not findings — every
  successful exploit still fires through.**
- **Batched per-category dispatch.** Instead of 8 dispatches (one
  per endpoint) for `sqli`, do 1 dispatch with all 8 endpoints in
  the objective. The fresh-context loop runs once, pays the 25K
  system prompt once, but probes all 8 endpoints sequentially.
  **Recall is preserved because each endpoint still gets full
  reasoning bandwidth** — we only stop re-paying the boot.
  ~50% cut on category-heavy targets.
- **Cross-dispatch KG context injection.** Each new specialist
  boots with a *digest* of prior-dispatch findings from the same
  run. Saves the specialist from re-probing known-safe surfaces;
  helps chaining. Net: faster termination per dispatch, same
  recall.
- **Pre-dispatch deterministic gate.** Before dispatching `sqli`,
  run `sqlmap --batch --level=1 --risk=1` as a fast probe. If
  sqlmap *finds* the bug → emit finding, skip the LLM dispatch
  entirely. If sqlmap is *uncertain* → dispatch as today.
  **Recall-safe because uncertainty always escalates to LLM.**

**Anti-pattern:** gating dispatch on KG signals alone (the
original v1 phase 4). BOLA, BFLA, mass assignment, business
logic — none tie to a single KG node kind. Gating these
silently destroys recall. The default-allowlist mitigation is in
the appendix.

### Workflow phase 5 — Lead-between-dispatches (~10% cost, 1-3 × N calls)

**Risk-free wins**

- **Structured specialist result.** Today specialists return prose;
  the lead parses + decides. Add a JSON field to the result:
  `{findings_count, next_suggested_dispatch: {category, objective,
  target}, blocks: [...]}`. The `next_suggested` is the
  specialist's own opinion — collapses the lead's between-dispatch
  reasoning to a structured triage. ~50% cut on lead-between
  calls.
- **Skip lead-think for PASSED-no-finding / BLOCKED-clean
  results.** If a specialist returned PASSED with 0 findings, no
  thinking is needed — log + advance. The "what's next?" call only
  fires on *interesting* dispatch results. Saves 1-2 calls per
  uninteresting dispatch.
- **Persist hypothesis state structurally.** Today the lead
  re-derives "what hypotheses are still open" by reading
  conversation. Store as a structured `open_hypotheses.json`;
  lead reads + writes structurally. Removes recurring "let me
  re-check what I've already tried" calls.

**Anti-pattern:** cutting the lead's *chaining* reasoning.
Cross-finding chains (info-leak → token → privesc → data) are the
highest-severity findings and they live in the between-dispatch
calls. Cheapen the routine triage; preserve the chain reasoning.

### Workflow phase 6 — Verification (~7% cost, 5-15 calls)

**Risk-free wins**

- **Deterministic FP filter BEFORE the LLM verifier.** Drop
  findings where:
  - The "vulnerable endpoint" returns the same response on a
    baseline (no-payload) request → reflected pattern was static
    content.
  - The payload also fires on a known-safe endpoint with identical
    response → not endpoint-specific.
  - The endpoint returned 404 in the cleanup phase → race
    condition, not a real finding.
  - The same finding was emitted twice with identical request →
    dedupe before verify.

  These catch 50-70% of FPs with zero LLM cost. **Recall-safe
  because the rules drop only structurally-noise findings, not
  unconfirmed reals.**

- **Cache PoC payload per `(vuln-class, endpoint-shape)`.** A
  working SQLi payload on `/api/users/{id}` is the starting payload
  for `/api/products/{id}`. The specialist may still adapt; doesn't
  re-derive from scratch.

- **Parallel verification.** Verify N findings concurrently rather
  than serially. Pure wall-clock win; LLM cost unchanged.

**Anti-pattern:** trusting the specialist's own self-verification
claim. The whole point of a separate verification phase is
independent confirmation. Don't collapse them.

### Workflow phase 7 — Report (~5% cost, 3-8 calls)

**Risk-free wins**

- **Template the report skeleton.** Executive summary structure,
  finding table, remediation table — all templatable. LLM fills
  only: (a) the per-finding "impact" paragraph and (b) the
  top-level narrative. Cuts ~60% of report calls.
- **Reuse the specialist's `summary` field for finding
  descriptions.** Specialists already write a one-paragraph summary
  at exit. Pipe that directly into the report's per-finding
  description; skip the LLM rewrite. 1-2 calls saved per finding.
- **Skip remediation generation for findings with a canonical
  CWE.** CWE-89 (SQLi), CWE-79 (XSS), CWE-78 (cmd injection), and
  the OWASP-Top-10 set have well-known remediation templates. Use
  the template; LLM fills only novel-CWE cases.

**Anti-pattern:** cutting the per-finding impact paragraph. That's
what makes the report useful to the human reading it. Cost there
is well-spent.

## Aggregate, recall-safe (v2 target)

Stacked across all seven workflow phases on `standard` mode,
post-PR-#334. Baseline `$0.55` = post-phase-1 typical run.

| workflow phase   | current share | recall-safe target | cut |
|------------------|--------------:|-------------------:|----:|
| Boot (re-scan only) |    5 %     |       1-2 %        | -70 % |
| Recon             |    8 %     |       3-4 %        | -50 % |
| Surface mapping   |    5 %     |       2-3 %        | -50 % |
| Specialist dispatch | 60-70 %  |      30-35 %       | -50 % |
| Lead-between      |   10 %     |       4-5 %        | -55 % |
| Verification      |    7 %     |       3-4 %        | -50 % |
| Report            |    5 %     |        2 %         | -60 % |
| **Total**         | **$0.55**  |     **~$0.25**     | **~55 %** |

So `standard` lands at **~2.2x cheaper than today's standard, and
~4x cheaper than pre-PR-#334 standard, with zero recall loss.**

The remaining gap to "5x" sits entirely in trims that *would*
affect recall (aggressive prompt compression, KG-only gating,
substantive skill-body trims). Those stay off the list.

| mode       | pre-PR-#334 | post-PR-#334 | post-v2 (target) |
|------------|------------:|-------------:|-----------------:|
| `quick`    |     $0.40   |    $0.05     |       $0.03      |
| `standard` |     $0.80   |    $0.55     |       $0.25      |
| `deep`     |     $3.00   |    $3.00     |       $1.50      |

`deep` improves from the workflow-phase wins (recon caching,
verification FP rules, report templating); the dispatch cap
doesn't apply.

## Suggested ordering (lowest recall-risk first)

Each step below is independently reversible and lands behind its
own kill switch + benchmark gate. **A step that drops a `must_find`
on any fixture reverts.**

1. **Verification FP rules** (deterministic pre-filter) — lowest
   risk, immediate win. Doesn't touch reasoning paths.
2. **Specialist verdict cache** — highest leverage; cache key is
   conservative (exact-prefix + exact-param-pattern + exact
   auth-state); cache misses fall through to dispatch.
3. **Batched per-category dispatch** — high leverage; preserves
   per-endpoint reasoning bandwidth.
4. **Structured specialist result + skip-lead-think rule** —
   touches the orchestration loop; rolled back via env flag.
5. **Recon/surface batching + cache** — touches early phases;
   benchmark gate before merge.
6. **Pre-dispatch deterministic gate** — needs careful "uncertain
   → dispatch" wiring; benchmark gate before merge.
7. **Report templating** — cosmetic; lowest priority, lowest risk.
8. **Boot prompt persistence** — only helps re-scans; lowest
   priority overall.

## Non-goals (v2)

- **Reducing recall on `must_find`.** Any change that drops a
  must_find on benchmark reverts. The CI gate enforces this.
- **Removing specialists.** The fresh-context loop is the
  competitive moat — it covers the 40-60% of findings that
  deterministic scanners cannot reach. We make it *cheaper per
  invocation*, not gone.
- **Aggressive prompt or skill-body compression.** Variant tables,
  payload contexts, and gotcha lists stay full-length.
- **KG-only dispatch gating.** BOLA, BFLA, mass assignment, and
  business logic do not map to single KG node kinds; gating on
  them silently destroys recall. Suppress at most by category
  default-allowlist (see appendix).
- **Reordering the seven workflow phases.** The phase model is
  fine; this is about how much we spend inside each phase.

## Validation plan (v2)

1. **Per-step unit tests** — each step ships with tests covering
   the new gate logic and a "fall-through on uncertain" path.
2. **Benchmark gate per step** — before merge, re-run the full
   per_target suite (`./benchmarks/run_all.sh --suite per_target
   --scan-mode standard`). The PR cannot merge if any fixture
   loses a `must_find` finding relative to the prior baseline.
3. **Absolute recall floor** — fail the benchmark workflow if any
   fixture drops below `recall_must_find=0.80`. The 5pp delta gate
   from v1 is replaced because it's too tight on small fixtures
   (e.g., vampi's 8 must_find → 5pp = 1 finding = noise).
4. **Cost regression report** — every step's PR description
   includes the cost delta on each fixture so we can see the
   stacked saving land.
5. **Override sanity** — every step's behavior must remain
   bypassable via env (`STRIX_*_DISABLED=1`) so an operator can
   roll back without a redeploy.

## Phase 1 acceptance (delivered in PR #334)

- [x] `STRIX_SCAN_MODE` set at scan boot in `cli.py` + `tui.py`.
- [x] `get_scan_mode_dispatch_cap()` returns 0 / 0 / 8 / None for
      initial / quick / standard / deep.
- [x] `dispatch_specialist` short-circuits over-cap with
      `DENIED_BY_SCAN_MODE` and increments no counters.
- [x] `reset_for_testing()` resets the dispatch counter.
- [x] Unit tests cover all four modes + the env override + reset.
- [x] `scan_modes/{quick,standard,deep,initial}.md` mention the
      dispatch cap so the lead's prompt is honest about what's
      allowed.

## Appendix — superseded v1 mitigations retained for reference

These were the mitigations proposed in the audit of the original
v1 doc. They are retained because if anyone ever revisits the
compression / model-routing / KG-gating approach, the same
guardrails apply.

- **Phase 4 (KG-gated dispatch) default-allowlist.** Categories
  that should *never* be gated on KG signal because their evidence
  is intrinsically weak in the graph: `auth`, `idor`,
  `mass_assignment`, `business_logic`, `bfla`. These dispatch
  unconditionally. Gating applies only to categories with strong
  graph signal (`saml_xsw` needs a SAML endpoint node;
  `aws_iam_chains` needs a CloudIdentity node; etc.).
- **CI recall gate threshold.** The original v1 gate was "fail if
  recall drops more than 5pp." On small fixtures (vampi: 8
  must_find) that's 1 missed finding = noise. The v2 plan uses an
  absolute floor (`recall_must_find ≥ 0.80`) plus a per-fixture
  delta gate (no fixture may lose any must_find).
- **`--max-cost` interaction.** Scan-mode cap is a *coarse*
  floor; `--max-cost` is the *fine* ceiling. Both enforce;
  whichever hits first wins. The dispatch counter is independent
  of cost spent — they are separate budgets.
- **CLI surface for the dispatch cap.** `STRIX_DISPATCH_CAP_OVERRIDE`
  is env-only today. A first-class `--max-dispatches N` flag
  should ship with the next round of CLI work for wrapper
  ergonomics.
