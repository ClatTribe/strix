# Strix Red-Team Uplift — Architectural Changes from Decepticon

**Goal**: bring Strix's pentesting depth closer to a real red-team agent (Decepticon) while staying true to the developer / AppSec audience.

**Hypothesis on current under-performance**: Strix is a wide-toolbelt single-agent loop. It runs an excellent **Observe** phase, but Decide/Act collapses into one context window where reasoning degrades, deep chains aren't pursued, and verification quality drifts as iterations pile up. The fix is structural, not more tools.

---

## TL;DR — what to copy, what to skip

**Copy from Decepticon** (relevant to apps):
1. Fresh-context-per-specialist orchestration (biggest single lever)
2. OPPLAN-style objective state machine
3. Persistent typed knowledge graph (replace `chaining_graph` in-memory walk)
4. Five-stage vulnresearch pipeline as a verification spine
5. Skills middleware with progressive disclosure at agent boot
6. Tiered output management for tool results
7. Lightweight engagement-scope doc
8. Model fallback chain from a credentials inventory

**Skip** (out-of-scope for AppSec / dev workflow):
- Sliver C2 server, AD Operator, Cloud Hunter*, Contract Auditor, Reverser specialists
- Two-network Docker isolation (overkill for CI; one sandbox is fine)
- Formal RoE / ConOps / Deconfliction paperwork (replace with a 20-line scope file)
- Sub-agent kill-chain phases like `c2` / `exfiltration`
- Soundwave-style interactive engagement interview as the default entry point

\* Cloud asset discovery already lives in Strix Observe; the *exploit-side* Cloud Hunter — IAM escalation, K8s RBAC escapes — is outside the AppSec wheelhouse.

---

## 1. Fresh-context specialist orchestration *(highest impact)*

### Problem
[`StrixAgent`](strix/agents/StrixAgent/strix_agent.py) runs with `max_iterations = 300` inside a single context window. After ~50 tool calls the conversation is saturated with stale tool output; planning quality degrades; the agent forgets what it already tried; verification gets sloppier the longer the run goes.

[`lead_team.py`](strix/agents/lead_team.py) and [`specialists.py`](strix/agents/specialists.py) introduce spawn primitives, but the lead still drives most of the loop in its own context.

### What Decepticon does
Orchestrator has `tools=[]`. Every objective is dispatched via `task()` to a sub-agent that boots with **a clean context window**. Findings persist to disk + KG; the sub-agent reads what it needs and returns `PASSED | BLOCKED`. The orchestrator never carries 80K tokens of nmap output forward.

### Strix changes
- `StrixAgent` becomes a **pure orchestrator** with no direct probing tools — only `spawn_specialist`, `query_kg`, `update_objective`, `read_finding`. Drop or gate the broad tool surface from the lead.
- Every specialist spawn is a **fresh `LLMConfig` + new conversation** seeded only with: (a) the objective, (b) the scope file, (c) relevant prior findings pulled from the KG, (d) its skill bundle. **No inherited chat history by default.** Flip `inherit_context_default` to `False` in `SpecialistProfile`.
- Cap each specialist at 50–80 iterations max. The orchestrator absorbs the long-running concern; specialists are sprints.
- Replace `max_iterations=300` on `StrixAgent` with an objective-budget cap (e.g. 200 objectives, ~20 iters each).

### Concrete code touchpoints
- [`strix/agents/specialists.py`](strix/agents/specialists.py) — flip default `inherit_context_default = False`, tighten per-category budgets.
- [`strix/agents/StrixAgent/strix_agent.py`](strix/agents/StrixAgent/strix_agent.py) — strip act-tools from the lead; reduce to orchestration tools only.
- [`strix/agents/lead_team.py`](strix/agents/lead_team.py) — make this the *only* path for executing checks. Re-architect `wait_for_all → collect_findings` so the lead's context never sees raw tool output.

---

## 2. OPPLAN-style objective state machine

### Problem
Strix has phase events (`recon → exploit → validate → report`) and a coverage matrix, but no first-class **objective** with status / dependencies / acceptance criteria. The agent can't reliably answer "what's left to do?" or "what blocked us?" without re-reading the events log.

### What Decepticon does
`OPPLANMiddleware` injects the current OPPLAN progress table into every LLM call and exposes 5 CRUD tools (create / add_child / get / list / update). Each objective carries `phase`, `opsec_level`, `mitre`, `depends_on`, `acceptance_criteria`, `status` ∈ {pending, in-progress, completed, blocked, cancelled}.

### Strix changes
Add an `ObjectiveTracker` middleware/tool family. For AppSec, simplify the schema:

```yaml
OBJ-007:
  title: "Verify IDOR on /api/users/{id}"
  phase: exploit
  category: idor-specialist        # maps to existing specialist registry
  surface: https://app/api/users
  depends_on: [OBJ-002]            # OBJ-002 = auth-mapping
  acceptance: "Cross-tenant read with role=user creds"
  status: pending
  evidence_required: 2             # multi-method floor (see §4)
```

- Store objectives in the run's existing state dir (`strix_runs/<run>/objectives.jsonl`) — no DB needed.
- Inject the progress table into every system prompt (orchestrator + specialists) the same way Decepticon does.
- Use it as the natural extension of the existing coverage matrix: each (target_type × scan_mode) coverage entry becomes a generated set of objectives at scan start.

### Why this matters for AppSec
- CI/CD runs become **diffable**: PR scan vs main scan = objective-status delta, not a fuzzy events.jsonl comparison.
- The "you intended X but didn't test it" coverage-gap event becomes deterministic (a `pending` objective at end of run).
- Re-runs can resume from `blocked`/`pending` objectives instead of re-doing the whole scan.

---

## 3. Persistent typed knowledge graph

### Problem
[`chaining_graph.py`](strix/agents/chaining_graph.py) walks the live finding list looking for known edge patterns (`xss → cookie_theft → csrf`, `ssrf → metadata_creds → cloud_compromise`). It's pattern-matching after the fact, not a planning substrate the agent can query forward.

### What Decepticon does
Neo4j graph with typed nodes (`Host`, `Service`, `Vulnerability`, `Credential`, `Account`) and typed edges (`RUNS_ON`, `AFFECTS`, `EXPLOITS`, `REQUIRES`, `LEADS_TO`, `USES`, `OWNS`). Tools: `kg_create_node`, `kg_create_edge`, `kg_query_nodes(type, filters)`, `kg_query_paths(start_id, end_id)`. Agents query the graph **before** acting to find unexplored chains.

### Strix changes
You don't need Neo4j — a single-file embedded graph (`networkx` over a JSON-backed store, or SQLite with a 2-table schema `nodes` + `edges`) is sufficient for one-target runs. Keep it inside `strix_runs/<run>/kg.json` and bind-mount into the sandbox.

Node types tuned for AppSec:

| Node | Properties |
|---|---|
| `Surface` | url, method, params, auth_state |
| `Asset` | type (repo/domain/url/ip), value |
| `Vuln` | cwe, owasp, severity, confidence, verification_status, finding_id |
| `Credential` | username, source, scope |
| `Secret` | type (api-key, jwt, db), source_finding |
| `Dependency` | name, version, ecosystem, cve_ids |
| `Role` | name, capabilities |

Edges:
| Edge | Meaning |
|---|---|
| `AFFECTS` | Vuln → Surface / Dependency |
| `REACHABLE_FROM` | Surface → Surface (auth chain) |
| `LEAKS` | Vuln → Secret / Credential |
| `GRANTS_ACCESS_TO` | Credential → Surface |
| `CHAINS_TO` | Vuln → Vuln (replaces in-memory chain edges) |

The existing `chaining_graph` pattern set becomes **edge-construction rules**, not after-the-fact reporting. The agent calls `kg_query_paths(surface=A, goal=cloud_compromise)` and gets a planned sequence.

### Why this matters for AppSec
- Powers the "kill-chain narrative finding" that's already in `chaining_graph.py` — but proactively, not retroactively.
- Multi-hop chains (XSS → cookie theft → CSRF on admin endpoint) require state across specialist spawns. The KG is the substrate that lets fresh-context specialists hand off (§1).
- Survives across CI runs (mount the previous run's `kg.json` for context-aware delta scanning).

---

## 4. Five-stage vulnresearch pipeline as a verification spine

### Problem
Strix has `verification_status` ∈ {verified, pattern_match, inconclusive, needs_review} but it's set heuristically per tool. Findings reach the report without a deterministic confirmation discipline. Reviewers see "needs_review" without a clear protocol for how it got there.

### What Decepticon does
Vulnresearch runs a strict pipeline where state flows **only through the KG**:

```
Scanner          → Detector             → Verifier         → Exploiter     → Patcher
(candidates)     (confidence-rated)     (multi-method)     (working PoC)   (autofix)
```

**Critical rule**: CRITICAL / HIGH findings require **2+ independent verification methods** before being marked `verified`.

### Strix changes
Make the pipeline an explicit objective subgraph for every Scanner-emitted candidate:

```
For each Detector-confidence-rated candidate (severity ≥ HIGH):
  spawn Verifier(method=A)   # e.g. payload-response oracle
  spawn Verifier(method=B)   # e.g. timing oracle / DOM oracle / oob
  if both PASSED → spawn Exploiter(generate PoC)
  if Exploiter PASSED → spawn Patcher(generate autofix PR)
```

- Each stage = its own specialist category (already partially exists: `sqli-validator`, `xss-specialist`).
- Add **`Patcher`** as a first-class category producing autofix branches/PRs (the Strix Platform already has this; bring it into the OSS Act stage).
- Re-emit `phase events` with the stage label so the events.jsonl audit trail shows the verification chain per finding.

### Why this matters for AppSec
- Directly attacks false-positive rate — the #1 complaint about appsec scanners.
- "Two independent methods" is the deterministic floor that bug-bounty triagers want to see.
- Patcher → PR turns Strix into the rare scanner that closes the loop, not just reports.

---

## 5. Skills middleware with progressive disclosure at boot

### Problem
Strix skills load via the `load_skill` tool — the agent has to *decide* to load a skill, then make a tool call, then read the file. This is two extra round trips before the skill is in context. For unfamiliar attack classes the agent doesn't know which skill to ask for.

### What Decepticon does
`SkillsMiddleware` reads SKILL.md frontmatter at agent boot, filters by agent role, and **injects descriptions** for every relevant skill into the system prompt. The agent sees the menu without paying for the bodies; bodies load on demand via `read_file`.

```
Available Skills:
- **passive-recon**: Use when gathering intelligence WITHOUT touching
  the target: WHOIS, DNS, subdomain enumeration. Triggers on: 'WHOIS',
  'subdomain', 'amass'.
  -> Read `/skills/recon/passive-recon/SKILL.md` for full instructions
```

### Strix changes
- Add a startup middleware that walks [`strix/skills/`](strix/skills/) and emits the frontmatter menu into each specialist's system prompt, filtered by category (the specialist registry already encodes the mapping).
- Keep `load_skill` as the Level-2 fetch.
- Adopt Decepticon's `description` convention: `"Use when {condition}: {tools/actions}. Triggers on: '{kw1}', '{kw2}'."` Concrete trigger keywords measurably improve agent skill-selection.

### Why this matters for AppSec
- Smaller context, lower cost — only the menu is loaded, not bodies.
- Better skill discovery — the agent sees "you have a `cache-deception` skill" even if it didn't know to ask for one.
- Mechanical to implement; the skills already exist with the right shape in [`strix/skills/`](strix/skills/).

---

## 6. Tiered output management

### Problem
Strix has truncation, but tool output volume is still the single biggest context killer in long sessions (Decepticon's own context-engineering doc identifies this as the dominant cost).

### What Decepticon does

| Output size | Handling |
|---|---|
| ≤ 15K chars | Returned inline |
| 15K – 100K chars | Saved to `/workspace/.scratch/`, agent gets a summary + path |
| > 5M chars | Watchdog kills the command |

Plus ANSI stripping and repeat-line compression before the LLM sees it.

### Strix changes
Implement the same tiering in [`strix/runtime/docker_runtime.py`](strix/runtime/docker_runtime.py) (or wherever the tool executor lives). Critically, **3-turn-old + >5K-char tool outputs should auto-mask to a preview + path**, the same way Decepticon's StreamingEngine does — see Decepticon's [`docs/architecture/context-engineering.md`](../Decepticon/docs/architecture/context-engineering.md) §2.1.

The preview-and-path pattern means the agent can always go re-read the raw output if needed, but it's not eating context budget on every subsequent call.

### Why this matters for AppSec
Strix already runs against large repos / web crawls / bulk threat-intel; output bloat is the hidden cost of `--scan-mode standard` runs. This is invisible cost reduction with no behavior change.

---

## 7. Lightweight engagement-scope doc

### Problem
`--instruction-file` is free-form text. It carries scope information but isn't structured, isn't validated, and the agent has to re-parse it on every spawn.

### What Decepticon does
Soundwave produces a formal RoE + OPPLAN before any probe. Heavyweight for AppSec — but the *structure* is what matters.

### Strix changes
Define a minimal `strix.scope.yml` (auto-generated from CLI flags + optional `--instruction-file`):

```yaml
targets:
  - type: web_application
    value: https://app.example.com
exclusions:
  paths: [/admin/destructive-export]
  hosts: [prod-payments.example.com]
opsec_level: standard               # quiet | standard | loud
rate_limit_rps: 10
auth:
  method: bearer
  inject_from: env:STRIX_BEARER
acceptance_criteria:
  - "All OWASP A0X covered"
  - "Authz matrix on all role pairs"
escalation_contact: secops@example.com
```

- Inject this as a structured object into every specialist's system prompt (one block, ~200 tokens).
- Add the existing **cluster-A safety** filters as derivations of this file (`--exclude-path`, `--rate-limit`, `--auth-*` flags become `scope.yml` fields).
- Validate at scan start; refuse to spawn specialists if scope.yml is malformed.

This is **not** a Soundwave-style interactive interview. It's a YAML the user writes once (or the CLI generates from flags) and the agent enforces every spawn.

### Why this matters for AppSec
- CI: scope.yml lives next to `.github/workflows/strix.yml`, version-controlled.
- Reproducibility: a finding always has the exact scope it was generated under.
- Onboarding: a single doc to point a new team member at, vs. CLI flag spelunking.

---

## 8. Model fallback chain from a credentials inventory

### Problem
`STRIX_LLM` is one model. Provider outage / rate limit / context overflow = the run fails or stalls.

### What Decepticon does
`ModelFallbackMiddleware` walks a primary→fallback chain built dynamically from the user's declared credentials in priority order. Per-agent tier (HIGH/MID/LOW) chosen by profile.

### Strix changes
- `STRIX_AUTH_PRIORITY=anthropic,openai,google` declares preference.
- Per-specialist tier: `sqli-validator` MID, `taint` HIGH, `recon` LOW. Match Decepticon's `eco` profile defaults — verifier/exploiter on HIGH, recon on LOW.
- Auto-fallback on `429 / 5xx / context_length_exceeded`.
- Especially valuable in CI where a rate-limited Anthropic call shouldn't fail the whole PR check.

You don't need Decepticon's full 17-auth-method matrix or subscription OAuth — three to four providers is enough for the AppSec use case.

---

## 9. Suggested sequencing

Roll out as independent PRs; each lands isolated value:

| Order | Change | Why first |
|---|---|---|
| 1 | §6 Tiered output management | Pure cost reduction, no behavior change, ~1 day work |
| 2 | §5 Skills middleware at boot | Improves baseline reasoning on every run, low risk |
| 3 | §8 Model fallback chain | CI reliability win |
| 4 | §7 `strix.scope.yml` | Foundation for §2 + §1 |
| 5 | §2 OPPLAN objective state machine | Reframes phase events into structured state |
| 6 | §1 Fresh-context specialists | The big lever — depends on §2 for objective dispatch |
| 7 | §3 Typed KG (replace `chaining_graph`) | Powers §1 specialist handoff |
| 8 | §4 Vulnresearch verification pipeline | Final quality jump — depends on §1, §3 |

Items 1–4 are tactical and can ship within 2–3 weeks. Items 5–8 are the structural lift; budget 4–6 weeks if done sequentially.

---

## 10. Wrapper integration — webappsec calls Strix only

**Decision**: webappsec should call **only Strix**. Strix should **not** internally call Decepticon.

### Why not "Strix calls Decepticon for hard targets"
- Decepticon's engagement model is fundamentally synchronous and slow (Soundwave interview → RoE → OPPLAN → execution). Embedding it under Strix drags the dev-facing tool into the engagement workflow.
- Decepticon's unique capabilities relevant to apps (objective tracking, fresh-context specialists, KG-driven chaining) are **architectural patterns**, not invocations. Porting them into Strix as §1–§4 above gives you the benefit without the integration tax.
- Decepticon's truly-unique capabilities (Sliver C2, AD Operator, Smart Contract Auditor, Binary Reverser) are out of scope for AppSec — invoking Decepticon to get them would mean exposing irrelevant features to dev users.
- Two child processes from one wrapper = duplicated sandboxes, conflicting finding schemas, double the LLM cost, and a merge problem at report time.

### Why not "webappsec calls both separately"
- Two product surfaces in the dev wrapper creates a UX trap ("which button do I press?").
- Findings from two engines need to be deduplicated by fingerprint — that's a real engineering project, not free.
- Billing / quota / rate-limit accounting gets messy when one user run spans two agent products.

### Recommended architecture

```
┌────────────────────────────────────────────────────────────┐
│                    webappsec (wrapper)                     │
│                                                            │
│   Single API surface:                                      │
│     POST /scan { target, scope, mode: quick|standard|deep }│
└──────────────────────────┬─────────────────────────────────┘
                           │
                  ┌────────▼────────┐
                  │      Strix      │
                  │ (uplifted per   │
                  │  §1–§8 above)   │
                  └─────────────────┘
                           │
                  ┌────────▼────────┐
                  │  Docker sandbox │
                  │  + KG + tools   │
                  └─────────────────┘

Decepticon lives separately as a red-team product for red-team users
(its own CLI, its own dashboard, its own engagement workflow). Not
reachable from webappsec.
```

### When a user genuinely needs red-team capability
That user does not belong in the AppSec wrapper. Direct them to Decepticon as a separate product, with its own onboarding, RoE, and engagement docs. This keeps each product honest about what it is — appsec doesn't pretend to be red team; red team doesn't pretend to fit in CI.

### One-way knowledge flow
The reverse direction *is* useful: ideas that worked for Decepticon flow into Strix (this document). And findings exported by Strix in a Decepticon-compatible format (KG JSON, MITRE-tagged finding files) could be picked up by Decepticon if a customer escalates from AppSec to red team. But that's a data interchange concern, not a runtime invocation concern.

---

## 11. Out-of-scope explicitly

Things from Decepticon that you should consciously **not** copy:

| Decepticon feature | Why skip |
|---|---|
| Sliver C2 server / `sandbox-net` separate network | Dev tool doesn't need C2; one sandbox is fine |
| Soundwave interactive interview | Replace with declarative `strix.scope.yml` |
| RoE / ConOps / Deconfliction Plan documents | Way too heavy for CI; the scope.yml + events.jsonl is enough |
| AD Operator, Cloud Hunter (exploit-side), Contract Auditor, Reverser specialists | Outside AppSec wheelhouse; if a user needs these, they need Decepticon |
| Subscription OAuth handlers (Claude Code, ChatGPT Pro, Copilot, Grok, Perplexity) | Nice-to-have, not load-bearing for the use case |
| `c2` / `exfiltration` kill-chain phases | Strix already maps to PTES discovery/attack/reporting — the right model for AppSec |
| Engagement-spanning persistent state with PostgreSQL + Neo4j servers | Per-run `strix_runs/<run>/kg.json` is sufficient |

---

## 12. Success metrics

How to know the uplift is working:

| Metric | Baseline | Target |
|---|---|---|
| False-positive rate on HIGH/CRIT findings | current | ↓ 40% (driven by §4 two-method floor) |
| Multi-hop chain findings per run | current | ↑ 3× (driven by §3 typed KG) |
| Tokens per finding | current | ↓ 30% (driven by §1 fresh context + §6 tiered output) |
| Median run completion time | current | ↑ slightly OK (more verification work) but max-run-time ↓ (no context-bloat stalls) |
| Coverage-gap rate (objectives left pending at run end) | current | ↓ 50% (driven by §2 explicit state machine) |
| CI re-runs that exit early on cached objectives | 0 | ≥ 60% on PR-diff scans |

The first two are the quality story; the rest are the cost / DX story. Both matter for the developer audience.
