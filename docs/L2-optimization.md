# L2 Optimization — Thinking Like a Security Engineer

> Companion to `docs/L1-optimization.md`. The L1 doc closed the **tool surface** gap
> (every dynamic OSS specialist a security team would want at L1 is now wrapped — see
> iter-22 / iter-23 / iter-24). This doc covers the **decision-layer** gap: what L2
> currently does versus what a real security engineer does when handed the same L1
> evidence.

---

## 1. Where we ended up after iter-22 → iter-24

The prior `docs/l2-architecture-evaluation.md` listed concrete L1 → L2 gaps. They are
now closed or nearly so:

| Prior doc section | What was proposed | Status |
| :--- | :--- | :--- |
| §2 Dynamic L1 OSS tools (sqlmap, feroxbuster, subfinder, httpx, nmap, trufflehog `--live`, dockle, grype) | wrap each as `@register_tool` | **DONE** (iter-22.4 / 23.1-3) |
| §4 `kg_query_*` promotion to Lead Orchestrator | move from patcher-only to global | **DONE** (iter-22.10) |
| §5.1 4 CVE-lookup tools → `query_threat_intel` | consolidate | **DONE** (iter-22.9) |
| §5.2 3 `replay_mutation_*` → unified | consolidate | **DONE** (iter-22.9) |
| §5.4 SAST/SCA leakage in `web_application` catalog | remove | **DONE** (iter-22.9) |
| §5.3 Remove `webapp_recon_pipeline` | replace with discrete `katana` + `httpx` + `nmap` sequencing | **OPEN** (40 call-sites; iter-25.10) |
| §4 `generate_remediation_plan` | new tool | **OPEN** (deferred — iter-26+) |

What's left from the prior doc is mostly the leftovers — important but additive.
**The harder gap was never written down**, and it dominates everything else.

---

## 2. The real gap — L2 today is a tool router, not an engineer

A real security engineer doesn't process L1 output in tool-emission order. They run
a tight inner loop:

```
observe → suspect → probe → narrow → confirm or move on
                ↑___________________|
```

Every signal **triggers more focused signals**. Most of the work is **pruning** —
deciding what doesn't matter — not exhaustively listing findings. The L1 output is
*evidence*; L2's job is to **weigh it, join it, amplify it, and act on it**.

Strix's current L2 is **reactive**:

```
L1 emits → L2 dispatches matching specialists → reports
```

That is "tool router", not "engineer". A router cannot decide *what to chase next*,
cannot tell *that's interesting* from *that's noise*, cannot stop because *I have
enough already*. It just runs every specialist the catalog says is applicable.

The result on noisy targets (vibe-app, juiceshop, sast-vibe): L2 receives 60-100 raw
findings, has to read each in-context, dispatches dozens of specialists, and emits
attack chains. Token spend is high; recall is bottlenecked by what the LLM can
remember across the conversation. Findings with `severity: medium` and
`reachability_score: 0.0` get treated the same as `severity: critical` with three
corroborating signals — because nothing has differentiated them at the structural
layer.

### Why the existing primitives don't fix this

We have most of the *primitives* a real engineer uses:

- `score_reachability` (code-graph BFS — file-level only)
- `correlate_findings` (post-scan attack-chain synthesis)
- `dispatch_specialist` (router)
- `dismiss_finding` (manual demotion)
- `agent_self_audit` / `check_budget` (cost guardrails)

But none of them are wired into a layer that **runs between L1 emission and L2 LLM
consumption**. That missing layer — call it **L1.5** — is where the engineer's
mental model lives.

---

## 3. The L1.5 layer — what it should do

L1.5 is a deterministic, no-LLM enrichment / join / amplify layer sitting between
L1 finding emission and L2 dispatch. It does what a security engineer does in the
first 60 seconds of looking at a scan:

```
┌─────────────────────────────────────────────────────────────┐
│ L1: OSS scanners + deterministic specialists                │
│ • gitleaks, semgrep, trivy, dockle, nuclei, dalfox, sqlmap, │
│   katana, httpx, subfinder, nmap, testssl, hibp, ...        │
└──────────────────────────┬──────────────────────────────────┘
                           │ raw findings
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ L1.5: deterministic enrichment / join / amplify (NEW)       │
│                                                             │
│  ENRICH  per-finding context                                │
│  ├─ git blame (author, commit_date, days_since_change)      │
│  ├─ FP filters (tests/, examples/, getenv-default, comments)│
│  ├─ surface priority label (admin / auth / payment / other) │
│  └─ hygiene prior (header absences, dev-banner, stale deps) │
│                                                             │
│  JOIN  cross-tool / cross-finding                           │
│  ├─ root-cause collapse (same rule × file → one finding)    │
│  ├─ mid-scan corroborator (≥2 signals on same CWE/surface)  │
│  └─ exploitability score (code × route × auth × data)       │
│                                                             │
│  AMPLIFY  trigger more focused L1                           │
│  ├─ finding-triggered probe bundles                         │
│  │   (admin-burst, sqli-burst, secret-burst, subdomain-burst│
│  └─ SAST-sink → DAST-confirm auto-promotion                 │
└──────────────────────────┬──────────────────────────────────┘
                           │ enriched, joined, amplified findings
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ L2: cognitive orchestration (LLM)                           │
│ • hypothesis formation, attack-chain reasoning,             │
│   patch generation, compliance synthesis                    │
└─────────────────────────────────────────────────────────────┘
```

After L1.5:

- L2 sees ~½ to ⅓ the input tokens (FP filter + root-cause collapse).
- L2's first decision is *which high-confidence chain to act on*, not *which of
  these 100 findings matter*.
- Specialists fire less often (deterministic confirmation already happened).

---

## 4. The nine concrete gaps, by engineer decision-point

### Gap 1 — Adaptive L1 re-invocation (the "go deeper" reflex)

An engineer who finds `/admin` returning 200 immediately does five things, none of
them conversational:

1. Try default creds (`admin/admin`, `admin/password`, ...).
2. Probe `/admin.bak`, `/admin.zip`, `/admin/.git/config`.
3. Run RBAC matrix with two test sessions.
4. Fuzz IDOR on the listed resources.
5. Check the same path on every discovered subdomain.

None of that needs new tools. All of it is **L1 re-invoked with parameters drawn
from the previous finding**.

**Today:** L1 anchor prepass runs once with fixed params. After that, follow-ups
require the LLM to think them up.

**Fix:** `finding_triggered_probes.py` — a finding-type → probe-bundle dispatch
table. Examples:

| Finding kind | Auto-bundle (L1, no LLM) |
| :--- | :--- |
| `unauth_debug_endpoint` (e.g. `/admin`) | default-creds, backup-paths, RBAC matrix, IDOR scan, repeat across subdomains |
| `sqli_potential_sast` | sqlmap `--batch --level 3 --risk 2` on every reachable route touching the sink |
| `secret_found_gitleaks` | trufflehog `--only-verified` on the artifact, then enumerate other repos in the org for the same regex |
| `subdomain_takeover_candidate` | httpx active probe + DNS CNAME chain walk + cloud-provider claim check |
| `tech_fingerprint=jenkins` | nuclei `-tags jenkins`, common Jenkins paths, Groovy script-console probe |

This is the highest-leverage single change in the whole doc: it converts ~70 % of
what L2 spends LLM cycles on into deterministic L1 calls.

### Gap 2 — Cross-tool corroboration (the "wait, that's interesting" moment)

Three weak signals individually = noise. Together = critical:

- nuclei flags `CVE-2017-5638` template hit (low confidence — banner match)
- SBOM extract shows `struts-core-2.5.13.jar` (vulnerable version)
- feroxbuster finds `/struts2-rest-showcase/orders/3` (the actual exposed endpoint)

Today these are **three separate findings**. The engineer reads them and stacks
them mentally for ~100 % confidence and one critical report.

`correlate_findings` exists but runs **post-scan** as attack-chain synthesis. Too
late: by then L2 has already dispatched specialists against each finding
individually.

**Fix:** `mid_scan_corroborator.py` — runs every time a finding is emitted.
Algorithm:

```
for new_finding f:
    cwe = f.cwe
    surface = (f.url or f.file)
    related = [g for g in emitted_findings
               if g.cwe == cwe and same_surface(g.surface, surface)]
    if len(related) >= 2 and any(g.source != f.source for g in related):
        promote(f, severity="critical", confidence=1.0,
                corroborated_by=related)
        demote(related, severity="info", role="corroborator")
```

Effect: 3 weak findings → 1 critical with attached evidence trail. L2 sees one
clear thing, not three muddled things.

### Gap 3 — Reachability-aware exploitability (the "but is it actually exploitable?" question)

`score_reachability` today returns file-level import-graph BFS reachability. Useful,
but the engineer's real question is layered:

| Factor | Today | Should-have |
| :--- | :--- | :--- |
| Code reachable from any callsite | `score_reachability` (have) | reuse |
| Route reachable from internet | not joined | join `katana_crawl` + `feroxbuster` paths against SAST sink files |
| Reachable unauthenticated | not joined | join `scan_multi_role_auth` or `auth_flow` result |
| Touches sensitive data | not modeled | small semgrep rule: sink writes to `users` / `payments` / `secrets` / `pii_*` |

**Fix:** `composite_exploitability.py` computes:

```
exploitability = code_reachable × route_reachable × auth_bypassable × data_sensitivity
```

All four factors are 0-1 floats. Multiply, then:

- `< 0.1` → demote to `info`, mark `noise=True`
- `> 0.8` → promote one tier (medium → high, high → critical)
- in between → leave alone

This is the **single highest-leverage filter** in the whole pipeline. Most "high"
findings in vibe-app / juiceshop have `exploitability < 0.1` (dead code, gated
routes, internal-only endpoints) and currently still consume L2 attention.

### Gap 4 — Negative-space reasoning (the "smell" detector)

Engineers notice **absences** as much as presences:

- `Server: Werkzeug/2.2.3` in production → dev server → assume everything else is
  also lax; raise the prior probability of finding more issues.
- No CSP + no X-Frame-Options + no HSTS → vibe-coded or framework-defaulted; go
  look at auth flow harder.
- Login endpoint exists + no rate-limit → password reset OTP almost certainly also
  unlimited; probe it specifically.

Today: each missing header is a separate low-severity finding. No mechanism
aggregates them into a **hygiene prior** that influences subsequent scan depth.

**Fix:** `hygiene_prior.py` runs at end of prepass; computes 0-1 score across:

- security-header completeness
- dev-server banners (Werkzeug, Express dev, webpack-dev-server)
- dependency staleness (mean age of vulnerable deps)
- secret-management hygiene (any `.env` checked in, gitleaks density)
- error-handling hygiene (stack traces in 500 responses)

Low hygiene → **bump depth** of subsequent specialists (more nuclei templates,
higher sqlmap risk level, more brute-force iterations). High hygiene → **shorten**
the same scans. This is exactly how engineers triage time.

### Gap 5 — Stop-condition / root-cause collapse

Engineer sees 30 findings of `strix-hardcoded-credential-literal-python` across one
repo → root cause is one bad practice. They file **one** finding with
`occurrences: [30 locations]`. Not 30.

Today: vibe-app returns 60 SAST findings; many are the same rule across files. L2
then reads each in-context. Token bill scales linearly with N.

**Fix:** `root_cause_collapse.py` runs on every finding emission. Coalesce by
`(rule_id, file, function)` → one finding with `occurrences[]`. Same `(rule_id,
repo)` with `count > N` → "systemic issue" meta-finding.

Drops L2 input tokens 3-5× on vibe-coded targets without losing recall.

### Gap 6 — Time-axis context (git blame for the dev who wrote this)

Engineer asks: "Who wrote this, when, and what was the commit message?" Three
reasons:

1. **New code** = higher attention (production drift, missed review)
2. **PR context** sometimes reveals "this was a quick hack, will fix later"
3. **Authorship** helps with remediation routing (assign to the right human)

Today: zero git context on any finding.

**Fix:** `git_blame_enrich.py` — 50-line tool called once at finding-emission. Adds
`{author, commit_date, days_since_last_change, commit_subject}`. Feeds the prior
in Gap 4 and the remediation routing in `generate_remediation_plan` (Gap 11).

### Gap 7 — Anti-FP via local context (the "is this a test file" check)

Engineer dismisses instantly:

- Hardcoded creds in `tests/fixtures/*` → test data, not a leak.
- `MD5(file_contents)` in `cache_key.py` → idempotency key, not security.
- "Open redirect" if the route allowlists the host → we just missed it.
- "AWS key" in `examples/README.md` → docs example.

Today: SAST emits these. L2 can dismiss them via `dismiss_finding` but only
conversationally — that's a per-FP token cost. Engineer dismisses in 2 seconds; L2
burns 2000 tokens on the same call.

**Fix:** `pre_emission_fp_filters.py` — small rule pack run at finding-emission:

| Heuristic | Action |
| :--- | :--- |
| File path matches `tests/` / `__tests__/` / `*_test.py` / `*.test.ts` | demote to `info` unless severity is `critical` |
| File path matches `examples/` / `docs/` / `samples/` | drop |
| Assignment is `os.getenv(KEY, default)` with `default ∈ {test, placeholder, ...}` | drop |
| Match is inside a docstring / `//` line comment / `<!-- -->` | drop |
| Severity `low` AND file is `.md` / `.rst` / `.txt` | drop |

Maybe 250 LOC. Cuts FP volume ~30 % before L2 ever sees them.

### Gap 8 — Verification chain (turn "potential" into "confirmed" without the LLM)

Today: SAST flags "SQL string concat" with severity `medium` (it's a potential).
Engineer's next move: fire **one** payload. DB exception in response → critical
confirmed. Parameterized at runtime → drop.

Currently that confirmation requires the `scan_sqli` conversational specialist
(LLM in the loop). We shipped `scan_sqli_sqlmap` (iter-23.2) but **it's not
auto-chained** to SAST hits.

**Fix:** `sast_to_dast_promoter.py` — for each high-confidence SAST sink
(SQLi / XSS / SSRF / path-traversal / cmd-injection):

1. Find the live HTTP route touching the same file/function (join with
   `katana_crawl` + `feroxbuster` output).
2. Fire the matching deterministic active specialist:
   - SQLi sink → `scan_sqli_sqlmap`
   - XSS sink → `scan_xss_dalfox`
   - SSRF sink → `scan_ssrf` (deterministic specialist)
   - Path-traversal sink → `scan_path_traversal`
   - Cmd-injection sink → `scan_cmd_injection`
3. Merge the result back as a single elevated finding (severity bumped,
   `confirmed_by_dast=True`, `evidence=...`).

This is what `correlate_findings` *should* be doing mid-scan, not post-scan.

### Gap 9 — Investigation depth heuristics (the time-box reflex)

Engineer time-boxes: "30 min on auth, 10 min on the rest." Strix has no equivalent
— every surface gets the same depth.

**Fix:** `surface_priority.py` labels each surface at the start of L2:

| Label | Match rule | Depth multiplier |
| :--- | :--- | ---: |
| `critical` | `/admin`, `/api/*/auth*`, `/api/*/payment*`, paths tagged `internal_only` in OpenAPI, paths whose SAST taint touches sensitive models | **3×** |
| `high` | authenticated routes, OAuth callbacks, password-reset endpoints | **2×** |
| `normal` | other authenticated user routes | **1×** |
| `low` | static marketing pages, public docs, healthcheck endpoints, OG image generators | **0.3×** |

`dispatch_specialist` reads the label and adjusts its `max_iterations` /
`payload_variety` knobs accordingly. Today every specialist gets the same iter-cap
regardless of which route it's hitting.

---

## 5. What this collapses into — the L1.5 architectural layer

Every gap above is the same architectural absence in a different costume:

> Strix has L1 primitives + L2 cognitive tools, but the **enrichment / join /
> amplify layer** that turns primitives into "engineer-grade evidence" doesn't
> exist.

Build it as **L1.5** — a deterministic, no-LLM stage between L1 finding emission
and L2 LLM consumption. Three sub-functions:

| L1.5 sub-function | Gaps it closes |
| :--- | :--- |
| **Enrich** — per-finding context | 4 (hygiene prior), 6 (git blame), 7 (FP filter), 9 (surface priority) |
| **Join** — cross-tool / cross-finding | 2 (corroborator), 3 (exploitability), 5 (root-cause collapse) |
| **Amplify** — trigger more L1 | 1 (probe bundles), 8 (SAST→DAST confirm) |

Each one is small, deterministic, testable. None requires the LLM. All run in the
existing tracer-emit hook path so they layer on without rewriting L2.

---

## 6. Proposed phased rollout — iter-25 roadmap

Eleven phases, sized to match the iter-22 / iter-23 / iter-24 pattern (each PR
mergeable in a single sitting with ≥6 tests).

| Iteration | Title | Engineer instinct | LOC est | Tests | Effort |
| :--- | :--- | :--- | ---: | ---: | :--- |
| **25.1** | Pre-emission FP filters (test-file / docstring / getenv-default heuristics) | "is this even real?" | ~250 | 10+ | Small |
| **25.2** | Auto root-cause collapse (rule × file × function → single finding with occurrences[]) | "stop counting; one bug" | ~200 | 8+ | Small |
| **25.3** | Mid-scan corroborator (cross-tool ≥2-signal promotion + singleton demotion) | "three signals = take it seriously" | ~350 | 12+ | Medium |
| **25.4** | Composite exploitability score (code × route × auth × data) | "but is it actually exploitable?" | ~400 | 12+ | Medium |
| **25.5** | Hygiene prior + investigation-depth multipliers | "this place is sloppy — look harder" | ~300 | 10+ | Medium |
| **25.6** | Surface priority labels + per-surface depth budget in `dispatch_specialist` | "30 min on auth, 10 on the rest" | ~250 | 8+ | Small |
| **25.7** | Git-blame enrichment on every code-anchored finding | "who wrote this and when" | ~150 | 6+ | Small |
| **25.8** | SAST-sink → DAST-confirm auto-promotion (sqlmap / dalfox / specialists) | "fire one payload and check" | ~350 | 10+ | Medium |
| **25.9** | Finding-triggered probe bundles (admin-burst, sqli-burst, secret-burst, subdomain-burst, tech-burst) | "the obvious follow-ups" | ~500 | 14+ | Medium |
| **25.10** | Remove `webapp_recon_pipeline`; promote katana + httpx + nmap as the discrete trio | "stop hiding tools behind composites" | ~400 | 10+ | Medium |
| **25.11** | `generate_remediation_plan` tool (narrative remediation for non-patchable findings) | "write it up for the dev / CISO / auditor" | ~600 | 10+ | Medium |

### Sequencing rationale

**First wave (recall × precision wins, lowest risk):** 25.1 + 25.2 + 25.3.
Together these probably halve L2 input token count on noisy targets and visibly
improve the bench precision column (today: vibe-app 0.05, juiceshop 0.03; target
≥ 0.15 on both). Each is < 350 LOC and the changes are localised to a single
post-emit hook.

**Second wave (accuracy multipliers):** 25.4 + 25.8. Reachability-aware severity
and auto SAST → DAST confirm. These turn "potential" findings into either
"confirmed exploitable" or "demoted to info" without burning L2 LLM cycles.
Expected effect: bench juiceshop recall lifts from 0.222 toward the high-recall
ceiling because confirmed-DAST findings stop getting buried in noise.

**Third wave (depth / context):** 25.5 + 25.6 + 25.7 + 25.9. Hygiene prior,
surface priority, git blame, probe bundles. These are the "engineer's reflexes"
— make the scanner *behave* like one even on targets it has never seen before.

**Fourth wave (architectural cleanup + reporting):** 25.10 + 25.11. Catalog
consolidation leftover from iter-22, and the human-readable remediation narrative
called out in the prior L2-architecture doc.

### Bench targets

Set explicit go/no-go thresholds. Compare against the **post-iter-24 baseline**
(`benchmarks/per_target/baseline/l1_only_20260522_223932.md`):

| Fixture | Today (recall / precision) | After 25.1-25.3 target | After 25.1-25.8 target |
| :--- | :--- | :--- | :--- |
| flask-vuln | 0.900 / 0.47 | 0.900 / 0.65 | 0.900 / 0.75 |
| api/vampi | 0.875 / 0.17 | 0.875 / 0.30 | 1.000 / 0.40 |
| vibe-app | 0.600 / 0.05 | 0.600 / 0.15 | 0.800 / 0.25 |
| juiceshop | 0.222 / 0.03 | 0.222 / 0.10 | 0.444 / 0.20 |
| nginx-vuln | 0.000 / 0.00 | (unblock sandbox timeout first) | 0.500 / 0.50 |
| **mean** | **0.600** | **0.602** (precision↑) | **0.700+** |

Recall holds or rises; precision is where most of the lift lives because L1.5's
job is precisely to prune noise.

---

## 7. What L1.5 explicitly is NOT

To prevent scope creep on this layer:

- **Not an LLM** — every L1.5 step is deterministic. No GPT call. No tool-call
  cycle. The whole point is to take the work off L2.
- **Not a new specialist** — L1.5 invokes existing L1 specialists; it doesn't
  re-implement detection logic.
- **Not a finding generator** — it transforms, joins, and routes. The set of
  findings after L1.5 is a strict re-shaping of the set before (with severity /
  confidence / occurrences[] possibly updated and some findings collapsed or
  dropped).
- **Not in the critical path for crashes** — every L1.5 hook must be wrapped in a
  `try/except` that falls back to "passthrough" semantics. L1.5 failure must
  never make L2 worse off than no-L1.5.

---

## 8. Open questions / known unknowns

- **Sensitive-data taint detection (Gap 3 part 4):** the cheapest implementation
  is a semgrep rule pack matching `db.session.add(<User|Payment|Secret>)`-shaped
  AST nodes. Will it generalize beyond Flask-SQLAlchemy / Django ORM? Need to
  prototype on the existing fixtures.

- **Probe-bundle blast radius (Gap 1):** auto-firing follow-ups risks tripping
  WAFs or hitting customer rate limits. Need to expose a `--probe-burst-limit`
  CLI flag and respect `scope.yml`'s `rate_limit_rps`.

- **Surface priority label leakage (Gap 9):** if the priority labels are
  attacker-controllable (e.g. via host header), an attacker could downgrade a
  scan to `low_priority` to avoid detection. Labels must be derived from
  immutable signal (URL prefix, OpenAPI `x-internal: true`, SAST taint), never
  from response headers.

- **Cost of git blame on monorepos (Gap 6):** `git blame -L line,line` is O(file
  history). On large repos it's the dominant cost. Probably needs a per-scan
  blame cache keyed by `(repo_sha, file)`.

---

## 9. Summary

| Layer | Status after iter-22 → iter-24 | After proposed iter-25 |
| :--- | :--- | :--- |
| **L0** signature corpora (gitleaks/wappalyzer/hadolint rule refresh) | DONE (iter-24) | unchanged |
| **L1** deterministic OSS + in-house specialists | DONE — surface is complete | unchanged |
| **L1.5** enrichment / join / amplify | **MISSING** | **BUILT** |
| **L2** LLM orchestration + specialist dispatch + patcher + compliance | exists but works alone — burns tokens routing noise | **freed to act on triaged, joined, high-confidence evidence** |

iter-22 / 23 / 24 gave strix every OSS tool an engineer reaches for. iter-25 makes
strix *use* them like an engineer would.
