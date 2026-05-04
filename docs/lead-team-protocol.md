# Lead-team protocol

> Roadmap §8.0. The documented contract for how a lead agent
> spawns specialists, hands off context, collects findings, and
> adjudicates conflicts. Operationalises the **Decide → Act → Orient**
> stages of the OODA loop for multi-agent scans.

This doc captures the protocol that already exists in code after
PRs #86–#89. It makes the contract explicit so every sub-agent team
(§8.1 code, §8.2 web, §8.3 domain, §8.4 IP) reuses the same
primitives instead of re-implementing coordination ad-hoc.

---

## OODA framing

The protocol maps each phase of the lead-team interaction to an OODA stage:

| Phase | Lead action | OODA stage |
|---|---|---|
| 1. Plan | Lead reads `surface_map.json` (Observe artifact), decides which specialists to spawn | Decide |
| 2. Spawn | Lead calls `create_agent(category="...", task="...", budget={...})` per specialist | Decide |
| 3. Specialist run | Each specialist runs its scoped Act loop | Act |
| 4. Specialist finish | Each emits findings via `tracer.add_vulnerability_report` (canonical contract validates) | Orient |
| 5. Lead collect | Lead reads `tracer.get_existing_vulnerabilities()` after specialists finish | Orient |
| 6. Adjudicate | Lead deduplicates by `fingerprint`, ranks by severity × KEV × verification_status | Orient |
| 7. Report | Lead calls `finish_scan` with the consolidated finding set | (handoff to report renderer) |

---

## 1. Spawn contract

The lead spawns specialists via `create_agent` (in
[`agents_graph_actions.py`](../strix/tools/agents_graph/agents_graph_actions.py)).
The minimum invocation is:

```python
result = create_agent(
    agent_state=self.state,
    task="Probe /api/login for SQLi.",
    name="SQL-Specialist-1",
    category="sqli-specialist",   # registered in strix.agents.specialists
)
```

When `category` matches a registered specialist profile (see
[`strix/agents/specialists.py`](../strix/agents/specialists.py)),
the spawn system applies defaults for any unset field:

- **`skills`**: profile's `recommended_skills` (e.g. `sql_injection,sqlmap` for `sqli-specialist`).
- **`budget`**: profile's `default_budget` (e.g. `{"max_cost_usd": 0.50, "max_input_tokens": 80_000}`).
- **`task`**: profile's `scope_addendum` is prepended ("You are the SQLi specialist. Your scope is STRICTLY ... Do NOT probe other classes — defer.").
- **`inherit_context`**: profile's `inherit_context_default` (defaults to True; Validator agent uses False so it reasons fresh).

**Caller always wins.** If you pass `skills="xss"` to a `category="sqli-specialist"`, the SQLi profile's skills are NOT applied; only the addendum + budget defaults still come from the profile.

### Per-key budget merging

The `budget` parameter merges with the profile's `default_budget` per-key. Caller-supplied keys win:

```python
create_agent(
    ...,
    category="ssrf-scanner",  # default_budget = {max_cost_usd: 0.50, max_input_tokens: 80_000, max_output_tokens: 20_000}
    budget={"max_cost_usd": 5.00},  # override the cost cap
)
# Result: max_cost_usd=5.00 (caller), max_input_tokens=80_000 (profile),
# max_output_tokens=20_000 (profile)
```

### Registered specialists

See [`strix/agents/specialists.py`](../strix/agents/specialists.py)'s `SPECIALIST_REGISTRY`:

| Team | Categories |
|---|---|
| Web (§8.2) | `sqli-specialist`, `xss-specialist`, `ssrf-scanner`, `auth-attacker`, `idor-specialist`, `csrf-specialist` |
| Code (§8.1) | `secret-agent`, `dependency-agent`, `sast-agent` |
| Domain (§8.3) | `subdomain-takeover-specialist` |
| IP / Network (§8.4) | `port-service-specialist` |
| Validator | `validator-agent` |

Register a new specialist by appending a `SpecialistProfile` to the `_SPECIALISTS` tuple. No spawn-side change required.

---

## 2. Handoff artifacts

Three documented JSON artifacts flow between OODA stages:

| Artifact | Producer | Consumer | OODA edge | Schema |
|---|---|---|---|---|
| `surface_map.json` | `domain_recon_pipeline` | exploit specialists, `cross_target_correlate` | Observe → Decide | [`strix/agents/handoffs/surface_map.py`](../strix/agents/handoffs/surface_map.py) (#87) |
| `candidate_findings.json` | exploit specialists | Validator agent | Decide → Validator | TBD (waits on Validator agent §17.1) |
| `verified_findings.json` | Validator agent | Report renderer | Validator → Report | TBD (waits on Validator agent §17.1) |

### Validation contract

Producers write whatever they want; the validator at the boundary records contract violations (never blocks). Each handoff emits `handoff.shape_violation` events on canonical-contract errors so wrappers can flag drift.

```python
from strix.agents.handoffs.surface_map import validate_surface_map

violations = validate_surface_map(data)
errors = [v for v in violations if v.severity == "error"]
warns = [v for v in violations if v.severity == "warn"]
```

Stable violation codes are part of the public contract — see each schema module's docstring.

---

## 3. Finding-shape contract

Every specialist emits findings through `tracer.add_vulnerability_report`. The canonical-finding contract (#86) validates AFTER the tracer's existing coercions:

- **Required**: `title`, `severity`, `category`, `verification_status`, at least one of `endpoint` / `target` / `code_locations`.
- **Allow-listed**: `severity ∈ {info, low, medium, high, critical}`, `verification_status ∈ {verified, pattern_match, inconclusive, needs_review, could_not_verify}`.
- **Format**: `cwe ∈ /CWE-\d+/`, `cve ∈ /CVE-YYYY-N+/`.
- **§11 UX (warn)**: `description_plain` + `recommended_action` recommended on severity ≥ low.
- **Coherence (warn)**: high severity on `category=informational` etc.

Violations are attached to the finding (`shape_violations` field, `is_canonical` boolean) AND emitted as a `finding.shape_violation` event. Non-canonical findings are NEVER dropped — data loss is worse than ugly data.

See [`strix/telemetry/finding_contract.py`](../strix/telemetry/finding_contract.py) for the 13 stable violation codes.

---

## 4. Budget enforcement

Each spawned agent has its own per-iteration budget tracking. After each iteration, `BaseAgent._sync_budget_from_llm` pulls the LLM's cumulative `input_tokens`/`output_tokens`/`cost`, computes deltas vs. last-pushed, and records onto `state.record_token_usage(...)`.

Budget dimensions:

- `max_input_tokens` (0 = unlimited)
- `max_output_tokens` (0 = unlimited)
- `max_cost_usd` (0.0 = unlimited)
- `time_budget_seconds` (0 = unlimited)

When the FIRST budget breach is detected, an `agent.budget_exceeded` event is emitted (latched — fires once per agent), and `state.should_stop()` returns True so the iteration loop terminates the specialist.

Lead agents pass per-specialist budgets explicitly:

```python
create_agent(
    ...,
    category="sqli-specialist",
    budget={
        "max_cost_usd": 0.50,    # $0.50 cap on this specialist
        "max_input_tokens": 80_000,
        "time_budget_seconds": 300,
    },
)
```

If budget is unset, the specialist profile's `default_budget` applies. If both are unset, the specialist is unbounded (only the iteration cap applies).

See [`strix/agents/state.py`](../strix/agents/state.py) for `set_budget` / `has_exceeded_budget` / `record_token_usage`.

---

## 5. Lead waits + collects

After spawning specialists asynchronously, the lead has three options:

### Option A — wait-for-completion (synchronous)

```python
import time

agent_ids = [a["agent_id"] for a in spawn_results]
while True:
    states = view_agent_graph(self.state)
    pending = [a for a in states["nodes"] if a["id"] in agent_ids and a["status"] == "running"]
    if not pending:
        break
    time.sleep(2)
```

### Option B — interactive coordination

```python
send_message_to_agent(target_agent_id=specialist_id, content="Update on findings?")
```

### Option C — fire-and-forget (let specialists finish via `agent_finish`)

The simplest pattern: spawn, do other work, read `tracer.get_existing_vulnerabilities()` at the end. Each specialist finishes by calling `agent_finish` which the agent loop uses as the completion signal.

The reference helper [`strix/agents/lead_team.py`](../strix/agents/lead_team.py) provides Option A with sensible defaults.

---

## 6. Conflict adjudication

When two specialists report overlapping findings (e.g. the SQLi specialist flags the same endpoint as the IDOR specialist), the lead deduplicates by `fingerprint`:

```python
findings = tracer.get_existing_vulnerabilities()
by_fingerprint: dict[str, dict] = {}
for f in findings:
    fp = f.get("fingerprint")
    if not fp:
        continue
    existing = by_fingerprint.get(fp)
    if existing is None or _severity_rank(f) > _severity_rank(existing):
        by_fingerprint[fp] = f
canonical = list(by_fingerprint.values())
```

The `fingerprint` is computed at finding-write time over normalised
(cwe, endpoint|file, first-80-chars-of-title) — see
[`strix/telemetry/tracer.py`](../strix/telemetry/tracer.py)'s
`compute_finding_fingerprint`. Two specialists reporting the same
underlying issue produce the same fingerprint, so dedup is
deterministic.

Severity-rank tie-breakers: prefer findings with `verification_status=verified`, prefer findings with `is_kev=True`, prefer the higher-confidence specialist (judged by category vs. the finding's class).

---

## 7. Reference impl: `LeadTeam` helper

A thin orchestrator wrapping the existing primitives. Use it OR call `create_agent` directly — both are supported.

```python
from strix.agents.lead_team import LeadTeam

team = LeadTeam(self.state)

# Spawn 4 specialists in parallel.
team.spawn(category="sqli-specialist", task="Probe /api/login.", name="SQL-1")
team.spawn(category="xss-specialist", task="Probe /api/login.", name="XSS-1")
team.spawn(category="ssrf-scanner", task="Probe /api/proxy.", name="SSRF-1")
team.spawn(category="csrf-specialist", task="Probe forms.", name="CSRF-1")

# Wait for all specialists to finish (or hit budget).
team.wait_for_all(timeout=600)

# Adjudicate findings — dedup by fingerprint, rank.
findings = team.collect_findings()

# Surface team metrics.
report = team.summary()  # spawn_count, completion_rate, total cost, ...
```

See [`strix/agents/lead_team.py`](../strix/agents/lead_team.py).

---

## 8. Stop conditions

Each specialist stops when ANY of:

1. `state.completed = True` (specialist called `agent_finish`)
2. `state.stop_requested = True` (lead called `stop_agent`)
3. `state.has_reached_max_iterations()` (iteration cap)
4. `state.has_exceeded_budget()` returns `(True, reason)` (budget cap — emits `agent.budget_exceeded` once)

The lead's `wait_for_all` returns when every spawned specialist is in any of those terminal states.

---

## 9. Events emitted by the protocol

The protocol surfaces its activity via the tracer's events.jsonl stream so wrappers / GRC platforms / cost dashboards can render it:

| Event | Phase | Source |
|---|---|---|
| `agent.created` | Spawn | `create_agent` |
| `tool.execution.started` (with `actor.mitre_techniques`) | Specialist Act loop | `_execute_single_tool` |
| `finding.created` | Specialist emits finding | `add_vulnerability_report` |
| `finding.shape_violation` | Canonical-contract violation | finding-contract validator |
| `handoff.shape_violation` | Surface-map / candidate-findings violation | handoff schema validator |
| `tool.output.injected` | Indirect-prompt-injection detected in tool output | output sanitiser (#84) |
| `agent.budget_exceeded` | Per-sub-agent budget cap hit | `_sync_budget_from_llm` |
| `agent.completed` / `agent.failed` | Specialist termination | agent-loop completion |
| `check.completed` | Per-(category × surface) test verdict | `complete_check` |
| `phase.entered` / `phase.completed` | Lead-driven phase transitions | `enter_phase` / `complete_phase` |

---

## See also

- [`roadmap.md`](../roadmap.md) §8 — sub-agent teams roadmap
- [`overall.md`](../overall.md) §1 — OODA-loop categorisation of the architecture
- [`strix/telemetry/finding_contract.py`](../strix/telemetry/finding_contract.py) — finding-shape contract (PR #86)
- [`strix/agents/handoffs/surface_map.py`](../strix/agents/handoffs/surface_map.py) — surface_map handoff schema (PR #87)
- [`strix/agents/state.py`](../strix/agents/state.py) — `AgentState` budget primitives (PR #88)
- [`strix/agents/specialists.py`](../strix/agents/specialists.py) — specialist registry (PR #89)
- [`strix/agents/lead_team.py`](../strix/agents/lead_team.py) — reference orchestrator helper (this PR)
