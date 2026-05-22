# iter-26 — L2 consumption of L1.5 signals

> Companion to `docs/L2-optimization.md`. iter-25 built the L1.5 layer
> (deterministic enrichment / join / amplify between L1 emission and L2
> LLM consumption). Every finding now carries:
>
> - `exploitability: {code × route × auth × data, composite, action}`
> - `surface_priority: {label, depth_multiplier, rationale}`
> - `git_blame: {author, commit_date, days_since_change, commit_subject}`
> - `corroborated_by: [vuln_id, ...]` / `role: "corroborator"`
> - `noise: true` (when demoted by exploitability)
> - `occurrences: [{file, line, ...}]` (root-cause collapsed)
> - `pending_confirmations: [{tool, target_url, param, ...}]`
> - `triggered_probes: [{tool, args, stealth, ...}]`
> - `SecurityPosture` keyed by target URL (process-local cache)
> - `HygieneLedger` (process-local accumulator)
>
> **None of this is read by L2 today.** The Lead Orchestrator still
> dispatches specialists in catalog order; the patcher still doesn't
> see `git_blame`; the active specialists still fire full-throttle
> payloads regardless of WAF posture; `pending_confirmations[]` sits
> on findings unread.
>
> iter-26 closes that gap.

---

## 1. What "L2 consumption of L1.5" actually means

A finding lands in `vulnerabilities.json` with an `exploitability.composite
= 0.92` and `surface_priority.label = "critical"`. Today the Lead reads
the title + severity + cwe and dispatches a specialist with the standard
iter-cap. Tomorrow (post-iter-26):

  * Lead reads the L1.5 fields and dispatches **first** because the
    finding's composite exploitability is highest.
  * Specialist gets `iter_cap × 3.0` because the surface label is
    `critical`.
  * Specialist's payload set is `stealth_mode` because the target's
    `SecurityPosture.waf_detected = True`.
  * Specialist sees `corroborated_by` already has 2 entries and skips
    its own verification step → goes straight to PoC capture.
  * Patcher generates the fix; the commit message tags the original
    author from `git_blame.author` for review routing.
  * The `pending_confirmations[]` SAST→DAST plan gets fired
    automatically via the amplify orchestrator — no LLM round-trip.
  * `triggered_probes[]` bundles fire concurrently (admin-burst /
    sqli-burst / verified-secret-burst) gated by `posture.stealth_required`.

Same evidence, dramatically less L2 reasoning required.

---

## 2. Twelve concrete L2 changes

Each one is **either prompt engineering, catalog wiring, or specialist
code**. None of them require new LLM reasoning capability — they all
make the LLM act on signals that are already there.

### 26.1 — Lead system prompt: L1.5 field glossary + prioritization rules

The Lead Orchestrator system prompt currently has no awareness of the
L1.5 fields. Add a section that:

  * Explains what each field means (`exploitability.composite`,
    `surface_priority.label`, `corroborated_by`, etc.).
  * States the ordering rule: **"Dispatch by composite exploitability
    descending. Skip findings with `noise=True` or `role=corroborator`
    unless asked. Surface_priority `critical` always beats `low`
    regardless of severity."**
  * Tells the LLM about the new `execute_adaptive_probe` escape hatch
    (added in 26.11) and when it's appropriate.

LOC: ~300 prompt tokens added; no code change.

### 26.2 — `dispatch_specialist` ranks pending findings by exploitability

Currently `dispatch_specialist` is called by the LLM one finding at a
time. The catalog presentation should rank findings by:

```
primary key = surface_priority.label  (critical > high > normal > low)
secondary  = exploitability.composite (descending)
tertiary   = severity                 (existing tiebreaker)
```

When the LLM asks "what's left to dispatch?", the answer should be
this sorted list, with explicit annotations:

```
[1] vuln-0042 — SQLi confirmed (CWE-89)
     surface: critical (/api/v1/admin/users)
     exploitability: 0.92 (code=1.0 route=1.0 auth=1.0 data=0.92)
     ⚠ KEV match, corroborated by 2 sources
[2] vuln-0017 — Path traversal potential (CWE-22)
     surface: high (/api/v1/files)
     exploitability: 0.75
     pending_confirmation queued: scan_path_traversal
```

LOC: ~250 (table builder + prompt formatting).

### 26.3 — `dispatch_specialist` scales `iter_cap` by `surface_priority.depth_multiplier`

Today every specialist gets the same iter-cap (set by scan mode). The
multiplier is already on the finding; just apply it:

```python
effective_iter_cap = scan_mode.iter_cap * finding.surface_priority.depth_multiplier
```

Critical surface → 3× iter-cap (LLM gets more loops on auth/payment).
Low surface → 0.3× iter-cap (cap at maybe 3 loops for a marketing page).

LOC: ~200, contained in `dispatch_specialist`.

### 26.4 — Global hygiene multiplier on dispatch budgets

At scan start, the Lead reads `hygiene_ledger.compute()` once and bakes
the result into every subsequent specialist dispatch:

```python
global_depth_mult = hygiene_ledger.compute().depth_multiplier
final_iter_cap = scan_mode.iter_cap
              * finding.surface_priority.depth_multiplier
              * global_depth_mult
```

Sloppy target (Werkzeug in prod, no headers, gitleaks density > 1/kloc)
→ 2× across the board. Tidy target → 0.6×.

LOC: ~150.

### 26.5 — L2 reads `pending_confirmations[]` and fires them

L1.5 plans the SAST→DAST confirmation (e.g. semgrep flagged SQLi sink →
`pending_confirmations: [{tool: "scan_sqli_sqlmap", target_url:
"https://...", param: "id", ...}]`). Today these requests sit on the
finding unread.

The Lead orchestrator should auto-route them: when a finding lands with
a non-empty `pending_confirmations[]`, dispatch the named tool with the
specified args **without** asking the LLM. Drop the result back into
the finding as `confirmed_by_dast: bool`. If confirmed, promote
severity one tier; if not, demote to `info`.

LOC: ~350 (a new "auto-confirm" middleware in the lead's finding-receipt
path, plus result merging logic).

### 26.6 — Amplify orchestrator fires `triggered_probes[]` bundles

L1.5's `plan_probe_bundle` already drops bundle plans on findings. Wave
4 wired the `execute_adaptive_probe` escape hatch but the auto-fire
side was deliberately left to iter-26.

Build a small amplify orchestrator:

  * On each finding emission, read `triggered_probes[]`.
  * Group steps by tool to batch (avoid 5 sequential
    `discover_paths_feroxbuster` calls for 5 admin panels — batch the
    target URLs).
  * For each step, check `posture.stealth_required(target)` once more
    (the L1.5 cache may have been updated since the plan was made).
  * Dispatch via existing sandbox tool runner. Cap concurrency at
    `posture.rate_limit_cap(target)`.
  * Record results back into the source finding under
    `bundle_results[]`.

This is the **single highest-leverage L2 change** — it turns ~70% of
what's currently LLM-driven follow-up into deterministic fan-out.

LOC: ~400.

### 26.7 — Catalog presentation hides demoted findings

When the Lead asks "what's left", findings with `noise=True` or
`role=corroborator` should NOT appear by default. They can be revealed
via an explicit `list_demoted_findings` tool call for audit.

Today every finding shows up regardless of how L1.5 ranked it. The
LLM has to read the `noise=True` flag and decide to skip — burns
tokens.

LOC: ~150 in the catalog formatter.

### 26.8 — Active specialists honour `SecurityPosture.stealth_required`

When `posture.stealth_required(target) == True`, active specialists
must:

  * Sqli specialist: pass `--tamper=space2comment,between` to sqlmap;
    prefer time-based-blind over error-based payloads.
  * Xss specialist: ratchet down payload variety, prefer `<svg/onload>`
    over `<script>` (more likely to bypass keyword WAFs).
  * Path-traversal specialist: encode `../` as `%2e%2e%2f` /
    `..%252f` (double-encoded).
  * SSRF specialist: skip cloud-metadata payloads on Cloudflare-fronted
    targets (would 403 cleanly anyway).
  * All specialists: rotate `User-Agent` per request; cap concurrency
    at `posture.rate_limit_cap(target)`.

This is **per-specialist** code, not a single hook — ~50 LOC per
specialist × 6 specialists ≈ 300 LOC + 100 LOC shared helpers.

LOC: ~400.

### 26.9 — `correlate_findings` runs mid-scan, not just post-scan

`correlate_findings` exists but is invoked once at scan end. Its
attack-chain synthesis is most useful when fed back into the Lead's
planning, e.g.:

  * `[reflected XSS on /api/v1/login]` + `[CORS Allow-Credentials: *]`
    → chain "credential theft via XSS+CORS" — Lead should pivot to
    auth-bypass dispatch.
  * `[SSRF on /api/proxy]` + `[Spring Boot actuator at /actuator]` →
    chain "SSRF → internal-only endpoint enumeration."

Fix: re-invoke `correlate_findings` at each phase boundary
(`workflow.advance_workflow_phase`). Newly-formed chains get attached
to the next phase's specialist dispatch queue with severity bumped.

LOC: ~300.

### 26.10 — Patcher reads `git_blame` for commit-message routing

The patcher specialist generates unified diffs and commits them. Today
the commit message is `fix: <finding title>`. Post-iter-26:

```
fix: <finding title>

The vulnerable code at <file>:<line> was introduced by <author> on
<commit_date> ("<commit_subject>"). Patcher's suggested fix preserves
the original code's intent; please review @<author>'s context before
merging.
```

This routes the PR review to the dev who wrote the code — critical
for large teams.

LOC: ~150 in patcher prompt + commit message template.

### 26.11 — Register `execute_adaptive_probe` in Lead catalog

The tool exists (iter-25.10) but isn't in the Lead's tool catalog yet.
Add it with a clear docstring:

> Fire any L1 tool with custom args. Use when `triggered_probes[]`
> didn't cover the follow-up you want (the unforeseen 30%).
> Per-scan call cap of 10; respects WAF posture.

Plus add a hint in the system prompt: *"Before calling
`execute_adaptive_probe`, check whether the finding already has a
`triggered_probes[]` bundle. If yes, those are firing automatically —
don't duplicate."*

LOC: ~200 (catalog entry + prompt addition).

### 26.12 — iter-25.11 follow-up: remove `webapp_recon_pipeline`

Replace with explicit `katana_crawl` → `probe_hosts_httpx` →
`fingerprint_services_nmap` sequencing in the Lead system prompt.
The composite pipeline tool hid execution details from the LLM and
duplicated work (Lead ran the composite, then re-ran discrete tools
when it wanted more detail). 40 call-sites; mostly in
`lead_agent.py` system prompt + a few specialist tool-catalog
references.

LOC: ~400.

---

## 3. The shape of the iter-26 change

| Phase | What | Where it lives | LOC |
|------|------|---------------|-----:|
| 26.1 | Lead system prompt updated for L1.5 vocab + rules | `strix/agents/lead_agent/lead_agent.py` (prompt strings) | ~300 |
| 26.2 | Catalog presentation ranks pending findings | `strix/tools/findings/list_findings.py` + Lead prompt | ~250 |
| 26.3 | `dispatch_specialist` scales iter-cap by surface label | `strix/tools/workflow/specialist_dispatch.py` | ~200 |
| 26.4 | Global hygiene depth multiplier | same file | ~150 |
| 26.5 | Auto-confirm middleware fires `pending_confirmations[]` | new `strix/agents/lead_agent/auto_confirm.py` | ~350 |
| 26.6 | Amplify orchestrator fires `triggered_probes[]` | new `strix/agents/lead_agent/amplify_orchestrator.py` | ~400 |
| 26.7 | Hide `noise=True` / `corroborator` from default catalog | `strix/tools/findings/list_findings.py` | ~150 |
| 26.8 | Posture-aware payload selection in 6 active specialists | each specialist module under `strix/tools/specialist/` | ~400 |
| 26.9 | Mid-scan `correlate_findings` re-invocation | `strix/tools/workflow/advance_phase.py` | ~300 |
| 26.10 | Patcher commit-message includes git_blame author | `strix/tools/patcher/` | ~150 |
| 26.11 | Register `execute_adaptive_probe` in Lead catalog | `strix/tools/workflow/__init__.py` + prompt | ~200 |
| 26.12 | Remove `webapp_recon_pipeline`; promote discrete trio | `strix/agents/lead_agent/lead_agent.py` + 40 callers | ~400 |

Total: ~3,250 LOC across ~15 files.

---

## 4. Phased rollout — same waves pattern as iter-25

**Wave 1 — Cheap presentation wins (prompt + catalog):** 26.1 + 26.2 +
26.7. Zero new code paths; pure prompt + formatter work. Expected
effect: L2 token consumption drops ~30 % on noisy targets because the
LLM stops seeing demoted noise + sees explicit ordering.

**Wave 2 — Budget scaling:** 26.3 + 26.4 + 26.11. Specialist depth
scales by surface priority + hygiene. Expected effect: longer auth-flow
runs on critical surfaces; shorter / skipped runs on static assets.
`execute_adaptive_probe` exposed to LLM with usage hint.

**Wave 3 — Auto-fire amplify:** 26.5 + 26.6. The deterministic
follow-ups L1.5 planned actually fire. **Biggest single bench impact
expected here** — this is where the recall lifts from auto-confirmed
DAST hits land. juiceshop / vibe-app targets should show measurable
recall improvement.

**Wave 4 — Polish:** 26.8 + 26.9 + 26.10 + 26.12. Stealth payloads,
mid-scan correlation, patcher author routing, recon-pipeline cleanup.

---

## 5. Bench targets

Set go/no-go thresholds against the **post-iter-25 bench**
(re-run needed once Wave 1 of iter-26 lands; iter-25 alone didn't
move the bench needle because the L1.5 fields exist but L2 doesn't
read them yet).

| Fixture | Today (recall / precision) | After Wave 1+2 | After Wave 3+4 |
| :--- | :--- | :--- | :--- |
| flask-vuln | 0.900 / 0.47 | 0.900 / 0.70 | 1.000 / 0.80 |
| api/vampi | 0.875 / 0.17 | 0.875 / 0.35 | 1.000 / 0.50 |
| vibe-app | 0.600 / 0.05 | 0.600 / 0.20 | 0.800 / 0.35 |
| juiceshop | 0.222 / 0.03 | 0.333 / 0.15 | 0.555 / 0.30 |
| nginx-vuln | 0.000 / 0.00 | (sandbox unblock first) | 0.500 / 0.50 |
| **mean** | **0.600** | **0.625** | **0.770+** |

Recall lift comes from auto-fired confirmations (Wave 3) hitting
findings that the LLM previously dropped between phases. Precision
lift comes from hiding `noise=True` and ranking by exploitability
(Waves 1+2).

---

## 6. Risks / open questions

- **Prompt regression.** Rewriting the Lead system prompt (26.1, 26.12)
  is the highest-risk change. The current prompt has hundreds of
  hours of tuning baked in. Mitigate with: (a) keep the existing
  prompt as a fallback under `STRIX_LEAD_PROMPT=legacy`; (b) bench
  every Wave 1 PR against the post-iter-25 baseline before merging.

- **Amplify orchestrator concurrency.** Wave 3 introduces concurrent
  tool fan-out. Need to confirm the sandbox tool runner is
  thread-safe for parallel invocations of the same tool — historically
  some specialists carry process-local state (jwt_audit cookie cache,
  etc.). Solution: a per-tool max-concurrency setting in the
  amplify orchestrator; default to 1 for any tool not on a known-safe
  list.

- **Patcher git-blame leakage.** Including author name in commit
  messages could leak personal info into public commit history.
  Make it opt-in via `scope.yml: patcher.include_blame_in_commits:
  false` default.

- **Adaptive probe abuse.** If the LLM hits the per-scan cap of 10
  adaptive probes and still wants to fire more, what should it do?
  Recommend: fail explicitly with a clear error message
  ("`execute_adaptive_probe` cap reached for this scan; recommend
  capturing the planned probe in `triggered_probes[]` instead.")

- **Phase-boundary correlation cost.** `correlate_findings` is O(n²)
  in finding count. Mid-scan invocation × 4 phases on a 200-finding
  vibe-app run = ~160k pair comparisons. Probably fine but should
  profile.

---

## 7. What iter-26 is NOT

- **Not new L1 tools.** The OSS-tool surface (iter-22/23/24) is done.
- **Not new L1.5 enrichment.** Posture / exploitability / git-blame /
  bundles all exist already.
- **Not a rewrite of the specialist dispatch architecture.** The
  changes are surgical: each Wave is small enough to merge in a single
  PR.
- **Not LLM-side work.** No new tool reasoning capability. The LLM
  already knows what `severity: critical` means; iter-26 just gives
  it more structured signal alongside.

---

## 8. Summary

| Layer | Status after iter-25 | After proposed iter-26 |
| :--- | :--- | :--- |
| **L0** signature corpora | Done (iter-24) | Unchanged |
| **L1** OSS + deterministic specialists | Done (iter-22/23/24) | Unchanged |
| **L1.5** enrichment / join / amplify | Done (iter-25) | Unchanged |
| **L2** LLM orchestration | Exists but reads nothing from L1.5 | Reads, prioritises, auto-fires, scales depth, posture-aware |

iter-22 → iter-24 gave strix the tool surface. iter-25 gave it the
enrichment layer that makes findings engineer-grade. iter-26 closes
the loop: makes the LLM actually act on what L1.5 produced.
