# AI Security Engineer — Engine Roadmap

This document is the strategic roadmap for **strix as the engine** powering the
[webappsec](../webappsec/) wrapper that vibe-coded-app companies log into. The
wrapper's UX is documented separately in [`AISecurityEngineerUX.md`](./AISecurityEngineerUX.md).

> **Audience**: contributors to `strix/`. The phases below are technical
> capabilities. Customer-visible product surfaces (PR-comment bots,
> compliance dashboards, trust pages, etc.) are deliberately scoped out of
> this doc — they live in the wrapper.

---

## 1. Vision

> **An AI security engineer for companies building vibe-coded apps** — apps
> shipped fast by AI assistants (Cursor, v0, Bolt, Replit, Lovable), built
> on heavy npm trees, deployed to edge runtimes, often with LLM features
> baked in.

The engine should:

1. **Detect** — bugs the customer wouldn't have found themselves: dependency
   CVEs, OWASP Top 10, AI-feature attacks, business-logic flaws, configuration
   drift.
2. **Reason** — like a senior engineer, not a regex: hypothesis → probe →
   confirm → chain → exploit-story.
3. **Stay current** — real-time threat intel, daily community-corpus refresh,
   continuous learning from every customer's misses.
4. **Compose** — primitives into novel exploits when no public signature
   exists yet.
5. **Remember** — across engagements; build per-customer experience.

Each phase below moves us a measurable step closer.

---

## 2. Current state (post Phases 1–5)

**Shipped (24 PRs merged into main, #193–#215, plus #216, #217, #218):**

| Layer | What's there |
|---|---|
| **Foundation** | Decision log, OOB-DNS service, OpenAPI parser, tech-stack KB, parallel dispatch, provider failover |
| **17 deterministic specialists** | OWASP Top 10 + CWE Top 25 coverage (sqli, xss, xxe, ssrf, idor, oauth, deserialization, path traversal, ssti, nosqli, xpath, ldap, secrets, request smuggling, blind variants, business logic) |
| **Multi-role auth** | Anon + default-creds + admin + user-a + user-b session capture |
| **Reasoning layer** | Hypothesis-EV scoring, chaining graph, telemetry, counter-example logging, replay-mutation orchestrator |
| **Real-time intel** (PR #217) | CISA KEV + FIRST EPSS + NIST NVD local cache + 4 LLM tools |
| **Community corpus** (PR #218) | 13,123 nuclei templates, daily-updated, `scan_nuclei_templates` tool |

**Validated**: 88% recall on the Juice Shop benchmark (8/9 must-find findings).

---

## 3. Strategic frame

Three constraints shape every phase below:

### 3.1. Engine ≠ product
Strix produces structured findings + telemetry. The wrapper builds the
product (UX, billing, compliance dashboards, customer trust pages). Engine
phases must produce **machine-readable artifacts** the wrapper consumes:

- `vulnerabilities.json` (existing tracer output)
- `decision_log.jsonl` (Phase 1.6)
- `specialist_telemetry.jsonl` (Phase 5.4)
- `specialist_misses.jsonl` (Phase 5.3)
- New: `sca_inventory.json`, `sast_findings.json`, `compliance_evidence.json`,
  `iac_posture.json`, `ai_feature_findings.json` (this roadmap)

### 3.2. Vibe-coded apps shape priorities
Top vuln sources empirically:
1. **Dependency CVEs** (~70% of disclosed bugs in modern web apps)
2. **Inlined secrets** (AI assistants love hardcoding API keys)
3. **AI-generated auth flaws** (mass-assignment, missing authz checks)
4. **LLM-feature attacks** (prompt injection, jailbreak, tool-call abuse)
5. **Configuration drift** (Vercel/Cloudflare/Netlify settings)

DAST is one piece. SCA + SAST + secrets + LLM-feature security are the rest.

### 3.3. Continuous, not one-shot
Vibe coders ship 10–50 PRs/day. The engine must support:
- Diff-aware mode (scan only what changed)
- Daemon mode (run continuously, alert on regression)
- Per-PR context (correlate findings with commit/author)

---

## 4. Core principles

These apply across every phase:

1. **Deterministic + LLM-augmented**, not LLM-everywhere. Static fast paths
   first; LLM-driven specialists as fallback when static returns 0 findings on
   strong-signal endpoints.
2. **Bounded inner-LLM calls**. Cached system prompts, capped tool subsets,
   wall-time budgets. Cost-predictable; no token-runaway.
3. **External corpus over hand-written**. Community-maintained payload
   libraries (nuclei, Semgrep rules, exploit-DB, Snyk DB) update for free.
4. **Best-effort throughout**. Failures swallowed; cache stays at last-known-
   good; never raise into the agent loop.
5. **Telemetry-driven improvement**. Every miss recorded; nightly active-
   learning consumes the corpus.
6. **Composable artifacts**. Each capability emits a typed JSONL the wrapper
   can consume independently. No coupling between SCA and DAST emit paths.

---

## 4a. Cross-cutting: single-lead asset-aware planning

> **Why this is its own section, not a phase.** Every phase below adds a
> *capability* (SCA, SAST, AI-feature security, IaC, ...). What turns a
> capability bundle into an "AI security engineer" is how the single lead
> agent **plans across assets** with them. That planning layer cuts across
> every phase and gets revisited as each new capability lands. Treating it
> as a phase would imply "we ship it once and move on"; it isn't.
>
> This section was retro-added in PR #219 alongside Phase 6 because that
> was the first phase where the cross-asset story became concrete (SCA on
> the repo + DAST on the URL = paired scan of the same vibe-coded SaaS).
> Future phases extend the same machinery rather than rebuild it.

**The architectural commitment** (since roadmap §8.5 Phase 3): one lead
agent, one conversation, one LLM client. No sub-agents. The lead's tool
catalog is filtered per `target_type` so it never sees irrelevant tools.
The deprecated multi-agent "specialist hands findings up to coordinator"
pattern is gone.

**The two questions that single-lead has to answer well**:

1. *Given the asset(s) in scope, where do I start?* — **asset-aware routing**
2. *Given a finding on asset A, what does it imply for asset B?* — **cross-asset correlation**

### 4a.1. Asset-aware routing

For each registered target type, the lead's system prompt names the
**anchor tool(s)** it should start with — the highest-EV first probe for
that asset class. The mapping (per `strix/agents/lead_agent/lead_agent.py`
`_PER_ASSET_GUIDANCE`):

| Target type        | Anchor                                                  | Why                                                       |
|--------------------|---------------------------------------------------------|-----------------------------------------------------------|
| `web_application`  | `webapp_recon_pipeline` → `fingerprint_tech_stack` → specialists | Recon-first; tech stack picks the relevant specialists    |
| `repository`       | `scan_sca_lockfiles` first                              | Cheapest, deterministic, surfaces the #1 vuln class       |
| `local_code`       | `scan_sca_lockfiles` then SAST                          | Same as above; SCA precedes SAST in expected impact       |
| `domain`           | `domain_recon_pipeline` → `subdomain_takeover_check`    | Network footprint before any web probing                  |
| `ip_address`       | port scan → `tls_audit` → pivot to web-app              | Network-first, then HTTP if a web service is found        |

This is intentionally **prescriptive guidance, not enforcement**. The
catalog filter is the enforcement (the lead literally cannot call
`browser_action` on a `repository` target — the tool isn't in scope).
The prompt block tells the lead *which of the in-scope tools is the
right first probe*.

### 4a.2. Cross-asset correlation

When the run has more than one target type in scope (the typical
vibe-coded SaaS case: deployed URL + co-located source repo), the
prompt appends an explicit cross-asset block with concrete chains:

- **SCA → DAST**. SCA flags `lodash<4.17.21` → prototype pollution →
  probe the live URL for unsafe object merge endpoints / client-side
  template injection.
- **SAST → DAST**. `taint_analysis` flags an `eval` sink reachable from
  `/api/exec` → confirm it's reachable in the live deployment with
  `scan_cmd_injection`.
- **DAST → SCA/SAST**. Live SQL error in a response → grep the repo for
  the offending query → emit a code-level follow-up finding so the
  wrapper has both the runtime evidence and the fix location.
- **Convergent evidence bumps severity**. A package shows up in *both*
  the SCA inventory AND a DAST behavioural probe → it's a real exploit
  path, not just an advisory match → escalate.

This is the single-lead *replacement* for the deprecated multi-agent
"specialist publishes finding to a shared bus and other specialists
subscribe" pattern. One agent, one conversation, the chain happens
inside the lead's reasoning rather than across agents.

### 4a.3. How each new phase plugs in

Every phase ahead adds at least one new tool to the catalog. Each one
must answer:

1. **Which `target_type` catalog(s) does the tool belong to?** — defined
   in `strix/agents/lead_agent/tool_catalog.py`.
2. **Should it be the anchor for that type, or a follow-up?** — if
   anchor, named in `_PER_ASSET_GUIDANCE`.
3. **What cross-asset chain does it enable?** — added to the
   `_CROSS_ASSET_BLOCK` examples when material.

Concretely for the phases below:
- **Phase 7 (SAST)** — anchor for `repository`/`local_code` after SCA;
  cross-asset link: SAST sink + SCA package version → DAST probe target.
- **Phase 8 (AI-feature security)** — sub-anchor for `web_application`
  when LLM endpoints are detected; cross-asset link: AI prompt-injection
  attack chains into business-logic abuse.
- **Phase 11 (IaC / cloud posture)** — new target type `iac_repository`
  or shares `repository`; cross-asset link: misconfigured Vercel env
  variable exposure → DAST probe for that endpoint.

### 4a.4. Validation: paired-asset benchmark

Per-phase recall has always been measured on single-target fixtures
(`benchmarks/per_target/fixtures/code/flask-vuln/`,
`web/juiceshop/`). Phase 6 added `code/sca-vuln-deps/` for SCA-specific
recall. The deliberate gap: there's no fixture today that exercises
*paired* scans (a repo + the URL it deploys to) — that's where the
cross-asset chains actually fire.

**Open follow-up**: build a `web+code/vibe-app/` fixture that's both a
checked-in repo AND a docker-compose deployment of the app, with
`expected.yaml` entries that require BOTH a DAST emit and a matching
SCA emit (e.g. `lodash@4.17.20` in lockfile + reachable
prototype-pollution behaviour on the URL). Without this, "single-lead
correlates across assets" stays an architectural assertion — measurable
only in production telemetry.

### 4a.5. What this is NOT

- Not a separate planning agent. The cross-asset block is a prompt
  augmentation; the lead's reasoning loop is unchanged.
- Not a workflow engine. There's no DAG, no scheduler, no retry policy.
  The lead picks the order; the prompt suggests good defaults.
- Not a static rule set. The chains in `_CROSS_ASSET_BLOCK` are seeds.
  The lead can (and should) generate novel chains in-context once it
  has evidence — that's the §1.4 "Compose primitives" capability.

---

## 5. Phase 6 — SCA + Supply Chain (highest customer-value next phase)

**Status:** 6.1 / 6.2 / 6.3 / 6.4 / 6.5 landed in **PR #219**
(2026-05-10). Malicious-package detection (6.6) and license
compliance (6.7) are scoped as follow-up PRs.

**Phase 6.4 (reachability) shipped as v1**: import-level only.
`scan_sca_lockfiles` now classifies every vulnerable package as
`direct_import` / `transitive_only` / `unused` / `unknown` based
on whether app source files reference the package by name.
Severity demotes -1 tier for `transitive_only`, -2 for `unused`;
`direct_import` and `unknown` are no-ops. KEV / EPSS≥0.5 override
demotion (the threat is real even if the local import graph
doesn't reflect it). The headline efficiency claim — "30-60% noise
reduction on the high tier for real repos" — is measured by the
new `benchmarks/per_target/fixtures/code/sca-reachability/`
fixture, which plants a 3-direct/3-unused split and asserts the
filtered high-count drops from 4 → 1. Function-level reachability
(call-graph from the specific vulnerable function to a real entry
point) is **6.4 v2**, deferred to a future PR.

**Goal**: detect dependency-CVE risk in `package-lock.json` / `requirements.txt`
/ `Cargo.lock` / `Gemfile.lock` / `composer.lock`.

### Why first
- ~70% of disclosed CVEs in modern web apps are dependency-driven.
- Vibe-coded apps have 600+ transitive deps on average.
- We have the threat-intel daemon (PR #217) — SCA is the natural next step
  that closes the loop ("we know about CVE-X, you're using vulnerable-pkg-Y").
- Competitors (Snyk, Socket.dev, Endor Labs) make this their flagship feature.

### Items

#### 6.1. Lockfile parsers (`strix/sca/parsers/`) — **shipped in #219**
- `parse_package_lock(path)` — npm v1/v2/v3 + yarn.lock + pnpm-lock.yaml
- `parse_requirements(path)` — `requirements*.txt` + `Pipfile.lock` + `poetry.lock` + `uv.lock`
- `parse_cargo_lock(path)` — `Cargo.lock`
- `parse_gemfile_lock(path)` — `Gemfile.lock`
- `parse_composer_lock(path)` — `composer.lock`
- `parse_go_sum(path)` — `go.sum`

Each returns `[(ecosystem, name, version, dev_only_bool), ...]`. ~600 LOC each;
12 ecosystems = ~3,500 LOC total over the phase.

#### 6.2. Vulnerability matching pipeline (`strix/sca/match.py`) — **shipped in #219**
- Takes `(ecosystem, name, version)` from a parser
- Queries the threat-intel cache (PR #217) for matching CVEs
- Adds GitHub Security Advisories DB (Phase 6.5) for ecosystem-specific data
  the NVD doesn't have
- Returns `[CVERecord with version-pattern matched, source]`

#### 6.3. SCA specialist (`scan_sca_lockfiles`) — **shipped in #219**
LLM-facing tool:
```
scan_sca_lockfiles(
    repo_path,
    only_kev=False,
    min_epss=0.0,
    only_runtime_deps=True,
    auto_emit_findings=True,
)
```
Walks `repo_path` for lockfiles, parses, matches, emits one finding per
matching CVE.

#### 6.4. Reachability analysis (Endor Labs differentiator) — **v1 shipped in #219**
Use existing `taint_analysis` + `build_code_map` to filter SCA findings:
"you have CVE-2024-X in package P, but your code never calls the vulnerable
function." Drops CVSS by ~2 for unreachable, raises severity for reachable.
~1,200 LOC.

#### 6.5. GitHub Security Advisories ingester — **shipped in #219**
GHSA's GraphQL API has per-ecosystem advisory data NVD lacks. Daily polling
into the threat-intel cache. ~600 LOC.

#### 6.6. Malicious package detection (Socket.dev angle) — **deferred follow-up**
Heuristic + LLM-driven:
- Postinstall scripts that fetch external resources
- Packages with no GitHub repo / no maintainer history
- Recently-published packages with high download counts
- Typosquat candidates (Levenshtein distance 1–2 from popular packages)
- Network-call patterns ("does this package exfil to a non-listed domain?")
~900 LOC.

#### 6.7. License compliance — **deferred follow-up**
Parse package metadata, flag GPL/AGPL/copyleft/commercial-restricted licenses
in proprietary code. Maps to OPS-3 for SOC 2. ~400 LOC.

### Deliverables
- 12 ecosystem lockfile parsers
- `sca_inventory.json` artifact
- `scan_sca_lockfiles` LLM tool
- Reachability filter integration
- GHSA ingester
- Malicious package heuristics
- License compliance check

### Phase effort
~8,000 LOC across ~10 PRs over 4–6 weeks.

### Success criteria
- 90%+ recall on a curated test fixture of known-vulnerable lockfiles
- Reachability filter reduces false positives by ≥40% on real customer repos
- Same-day awareness of new GHSA advisories

### Wrapper dependency
- Wrapper's onboarding flow needs to ingest a repo path or git URL → triggers
  this phase's pipeline. See `AISecurityEngineerUX.md` Phase A.

---

## 6. Phase 7 — Real SAST (semantic code review)

**Goal**: pre-PR code-review-grade analysis of source files.

### Why
- Snyk Code, Semgrep, GitHub CodeQL all do this. Customer expectation.
- Vibe-coded apps especially benefit because AI-generated auth/crypto/injection
  patterns are the top vuln source after deps.

### Items

#### 7.1. Semgrep wrapper (`strix/sast/semgrep_runner.py`)
- Shell out to `semgrep` (preferred) OR pure-Python rule interpreter
- Use Semgrep's official rule registry (1000+ rules) + `p/owasp-top-ten` pack
- Per-language coverage: JS/TS/Python/Go/Java/PHP/Ruby/C#/Kotlin/Swift
- Daily rule-pack refresh via `semgrep --update`

#### 7.2. Custom rule library for vibe-coded patterns
Rules specific to AI-generated code:
- Mass-assignment in Express handlers (`req.body` → DB without allowlist)
- Missing authz check on Next.js Server Actions
- Hardcoded JWT secrets in `next.config.js`
- React `dangerouslySetInnerHTML` from user input
- Vercel function with overly-permissive CORS
- AI-prompt-injection in LLM endpoint code

~50–100 custom rules = ~3,000 LOC.

#### 7.3. Diff-aware mode
For PR-time scanning, only run rules on files changed in the diff:
```
sast_scan(repo_path, since_commit="main", until_commit="HEAD")
```
~400 LOC.

#### 7.4. Severity calibration
Cross-reference SAST findings with reachability + entry-point analysis:
- A SQLi sink in a private helper called only by tests → low
- A SQLi sink reachable from a public HTTP route → critical
~600 LOC.

#### 7.5. SARIF output
Industry-standard format. Required for GitHub Code Scanning integration.
~300 LOC.

### Deliverables
- Semgrep runner specialist
- 50+ custom Semgrep rules for vibe-coded patterns
- Diff-aware execution
- SARIF output
- Severity calibration via reachability

### Phase effort
~5,000 LOC across ~6 PRs.

### Success criteria
- Detection on a curated repo of intentionally-bad AI-generated patterns
- <10% false-positive rate (calibrated against customer feedback in wrapper)

### Wrapper dependency
- PR-comment bot (Phase A) uses `sast_findings.json` artifact for inline
  comments

---

## 7. Phase 8 — AI / LLM feature security

**Goal**: probe LLM-backed endpoints for prompt injection, jailbreak,
indirect injection via uploads, tool-call abuse.

### Why
- Vibe-coded apps frequently ship LLM features (chat, search, agents).
- Lakera / Protect AI / HiddenLayer dominate this niche but charge enterprise prices.
- Zero current coverage in strix.
- This is genuinely novel; differentiates us.

### Items

#### 8.1. LLM-feature detection
Heuristic to identify endpoints backed by an LLM:
- Streaming SSE responses with token-by-token output
- Response shape: `{"completion": "..."}` / `{"choices": [...]}`
- Headers: `X-Anthropic-*`, `OpenAI-*`, `cf-ray`-with-AI-flag
- Latency profile: variable per request (model inference) vs static (cache)
~500 LOC.

#### 8.2. Direct prompt injection (`scan_prompt_injection`)
- Probe with payloads from `garak` corpus (NVIDIA's open LLM-attack library)
- Detect when system-prompt content leaks into response
- Detect jailbreak success markers ("DAN", "Sure, here's how to...")
- Detect tool-call leakage ("```python\nimport requests\n...```")
~1,200 LOC + integration with `garak`.

#### 8.3. Indirect prompt injection
- Upload poisoned doc / image / SVG with hidden instructions
- Probe RAG-backed search endpoints with adversarial doc URLs
- Detect when assistant follows attacker-uploaded instruction
~800 LOC.

#### 8.4. Tool-call / agent abuse
- When the LLM has tool-calling, probe for unauthorized tool invocation
- Detect when assistant calls `delete_user(id=victim_id)` from chat input
- Test for confused-deputy attacks (assistant runs commands on behalf of attacker)
~700 LOC.

#### 8.5. Training-data extraction
- Probe with prompts known to extract memorized training data
- Detect PII / customer-data leakage through inversion attacks
- Coordinate with the customer's compliance posture
~600 LOC.

#### 8.6. Output validation testing
- When LLM output is fed back into the app (DOM, DB, shell), check for
  XSS / SQLi / RCE via crafted prompts
- This is "prompt → output → second-stage exploit" chain
~500 LOC.

### Deliverables
- 5 new specialists (`scan_prompt_injection`, `scan_indirect_injection`,
  `scan_llm_tool_abuse`, `scan_training_data_extraction`,
  `scan_llm_output_validation`)
- LLM-feature auto-detection
- `garak` integration for the prompt corpus

### Phase effort
~5,500 LOC across ~6 PRs.

### Success criteria
- Detection on intentionally-vulnerable LLM testbeds (Gandalf, PortSwigger
  AI labs)
- Coverage of OWASP LLM Top 10 (2024) categories LLM01–LLM10

### Wrapper dependency
- Compliance dashboard needs LLM-feature findings tagged for AI-act / GDPR /
  EU AI Regulation evidence (Phase C).

---

## 8. Phase 9 — Real-time intelligence + behavioural detection

**Goal**: same-hour awareness of new CVEs/exploits + drift detection on
deployed apps.

### Why
- Daily cron isn't real-time. KEV updates can take hours to surface.
- Behavioural detection catches novel bugs no signature has yet.

### Items

#### 9.1. Push-feed daemon (`strix/threat_intel/streaming/`)
Replaces the daily cron with:
- Webhook subscriber for GHSA (push notifications via GitHub App)
- 5-minute polling of CISA KEV (lightweight JSON feed)
- RSS subscriptions: HackerOne Hacktivity, exploit-db, vendor advisories
- Bluesky firehose for `#infosec` keyword + curated researcher allow-list
- `event_stream.jsonl` ring buffer the agent subscribes to mid-scan
~1,500 LOC.

#### 9.2. Per-endpoint behavioural baselines (`strix/baselines/`)
- For every recon-discovered endpoint, capture:
  - 5-sample latency distribution (p50, p99)
  - Response status, headers, content-type
  - Body length distribution + JSON shape (key set)
  - Auth-state delta (anon vs authenticated)
- Persist to `behavioural_baselines.jsonl`
~800 LOC.

#### 9.3. Anomaly-diff specialist (`scan_response_anomaly`)
- Diffs probe response against baseline
- Anomaly classes: status-flip, length-outlier, latency-outlier (>3σ),
  new-keys-in-json, error-string-presence, header-set-change
- Used by every other specialist as a complementary signal
~600 LOC.

#### 9.4. State-machine workflow discovery
- Crawl auth + state-change endpoints, infer state machine
- Probe transitions: skip-step, backward, cross-tenant
- Persist to `workflow_graph.json`
~1,500 LOC.

#### 9.5. Timing oracle specialist (`scan_timing_oracle`)
- 50-sample timing-sensitive probes per param
- Statistical fit (boxplot, KDE)
- Detects blind injection / padding oracles / TOCTOU
~700 LOC.

#### 9.6. Response-shape clustering
- Group probe responses by shape (status × length-bucket × content-type ×
  body-fingerprint)
- Outliers signal novel behaviour
- Pairs with mutation fuzzer (Phase 13.5)
~400 LOC.

### Deliverables
- Streaming threat-intel daemon
- 4 new specialists (anomaly-diff, workflow-discovery, timing-oracle, shape-clustering)
- `event_stream.jsonl` + `behavioural_baselines.jsonl` artifacts

### Phase effort
~5,500 LOC across ~7 PRs.

### Success criteria
- Time-from-CVE-disclosure-to-detection < 1h (currently ~24h)
- Anomaly diff catches at least 3 manifest items without static-payload help
- Workflow discovery generates ≥10 transition probes per typical multi-page app

---

## 9. Phase 10 — AI-native specialist class (LLM-fallback)

**Goal**: when static specialists return 0 findings on strong-signal endpoints,
escalate to bounded LLM-driven probe generation.

### Why
- Application-specific bypasses (Juice Shop's `/redirect` allowlist trick)
  aren't in any static corpus
- Senior pentesters reason about response shape and adapt; we can too
- This is the wedge that distinguishes an AI security engineer from a scanner

### Items

#### 10.1. LLM-fallback infrastructure
- Cached system-prompt registry (Phase 2 in workitem.md, never built)
- Bounded inner-LLM tool subset (Phase 1 B.9 in workitem.md)
- Cost cap per fallback call ($0.05 default)
- Output coercion to SpecialistResult schema
~1,000 LOC.

#### 10.2. `scan_xss_llm` (the proof point)
- Triggered when `scan_xss` returns 0 findings on a clearly-reflective endpoint
- Inner LLM:
  1. Reads baseline_response, identifies reflection points
  2. Generates 5 context-aware payloads (HTML attribute / JS string / URL / template)
  3. Sends + observes via the bounded tool subset
  4. Returns `SpecialistResult` with novel-payload findings
- Cost target: $0.02–0.05 per fallback call
~800 LOC + system prompt template.

#### 10.3. `scan_sqli_llm`
- Same pattern, DB-aware: reasons about Postgres/MySQL/MSSQL/SQLite
  fingerprints, generates DB-specific payloads (xp_cmdshell, COPY FROM
  PROGRAM, INTO OUTFILE)
~700 LOC.

#### 10.4. `scan_authz_logic_llm`
- When scan_idor + scan_business_logic both miss
- Inner LLM models likely auth invariants from the endpoint's behaviour,
  designs probes that violate them
- Highest-leverage on novel/business-logic bugs
~900 LOC.

#### 10.5. `scan_oauth_advanced_llm`
- jku-spoof / kid-traversal / alg-confusion / mix-up attacks
- All require reasoning over a captured JWT
~700 LOC.

#### 10.6. `scan_business_flow_llm`
- Models multi-step workflows (cart → checkout → payment)
- Probes invariant violations (negative price after coupon, double-spend
  via parallel requests)
~800 LOC.

#### 10.7. `scan_code_review_llm` (when source available)
- Reads auth middleware, crypto, deserialization sites with intent
- Specifically: "find bug class X in this code, give me concrete file:line"
- Pairs with Phase 7 SAST findings for false-positive triage
~1,000 LOC.

### Deliverables
- 6 new LLM-driven specialists
- Cached prompt registry (cost / cache-hit infrastructure)
- Per-specialist cost telemetry

### Phase effort
~6,000 LOC across ~7 PRs.

### Success criteria
- Recall on Juice Shop ≥95% (vs current 88%)
- Median fallback cost < $0.05/call
- ≥20% of misses on real customer scans get a finding from LLM-fallback

---

## 10. Phase 11 — IaC / cloud posture

**Goal**: scan Terraform / CloudFormation / Pulumi / K8s manifests; audit
Vercel / Cloudflare / Netlify configs.

### Why
- Vibe-coded apps deploy to edge platforms; misconfig is a top vuln source
- Wiz/Snyk IaC dominate this market — but mostly enterprise-priced

### Items

#### 11.1. IaC parsers
- Terraform (HCL2 parser via `python-hcl2`)
- CloudFormation (YAML/JSON)
- Pulumi (Python/TypeScript AST)
- Kubernetes manifests (YAML)
- Docker Compose / Dockerfile
~2,000 LOC.

#### 11.2. Checkov rule integration
- Shell out to `checkov` (1,500+ rules) OR pure-Python equivalents
- SOC 2 / CIS / NIST / HIPAA mapping built into Checkov rules
- Auto-fix suggestions when present
~1,000 LOC.

#### 11.3. Edge-platform config audit
- Vercel: parse `vercel.json` + project settings via API
- Cloudflare Workers: `wrangler.toml` + KV bindings + service bindings
- Netlify: `netlify.toml` + Edge Functions config
- Specific to vibe-coded apps' deployment surface
~1,500 LOC.

#### 11.4. Cloud API integration (read-only)
- AWS: IAM policy review, S3 bucket policies, Security Group analysis
- GCP: project IAM, GCS bucket ACL, Compute firewall
- Azure: RBAC, storage account access policies
- Authenticated via customer-supplied read-only credentials
~3,000 LOC.

#### 11.5. Container image scanning
- Wrap `trivy` or `grype` for image-CVE scanning
- Map detected base-image OSes to threat-intel cache
~800 LOC.

### Deliverables
- 5 IaC parsers
- Checkov runner specialist
- 3 edge-platform auditors (Vercel/Cloudflare/Netlify)
- AWS/GCP/Azure read-only auditors
- Trivy wrapper

### Phase effort
~8,000 LOC across ~9 PRs.

### Success criteria
- Coverage of CIS benchmarks for the 3 edge platforms
- Detection on a curated misconfig fixture set
- AWS IAM finding parity with Snyk IaC's reports

---

## 11. Phase 12 — Auto-fix / remediation

**Goal**: generate actual code patches, not just remediation paragraphs.

### Why
- Pixee built a $25M ARR business on this premise
- "Apply Fix" buttons in PR-comment workflows close the loop on
  detect → fix → ship
- Differentiator vs Snyk/Aikido (who recommend, don't always fix)

### Items

#### 12.1. Codemod library
- Per bug class: a parameterized codemod template
  - SQLi → parameterized query rewrite
  - XSS → output encoding insertion
  - Hardcoded secret → env-var migration
  - Missing authz → middleware insertion
  - Open redirect → allowlist check insertion
- Initial coverage: ~30 codemods
~3,500 LOC.

#### 12.2. AST-aware patch generation
- Per language: parse, transform, re-emit
- JS/TS via `tree-sitter` or `babel-parser`
- Python via `libcst` or `ast`
- Go via `go/ast`
~2,500 LOC.

#### 12.3. LLM-augmented patch fallback
- When no codemod template matches, LLM generates a candidate patch
- Confidence scoring (does the patch compile? does the test pass? does it
  remove the SAST finding without introducing a new one?)
- Bounded LLM call ($0.10 per patch)
~1,500 LOC.

#### 12.4. Patch validation pipeline
- Each generated patch goes through:
  1. Syntax check
  2. Type-check (where applicable)
  3. Re-run the SAST/SCA finding (must no longer fire)
  4. Run existing test suite (must still pass)
- Only patches passing all 4 gates surface to the customer
~1,200 LOC.

#### 12.5. Patch artifact format
- `auto_fix_patches.json`: list of `{finding_id, patch_diff, confidence, validation_results}`
- Wrapper consumes this to render "Apply Fix" PR-comment buttons
~300 LOC.

### Deliverables
- 30+ codemods covering top OWASP categories
- AST-aware generation for 5 languages
- Patch validation pipeline
- LLM-fallback for novel bug shapes

### Phase effort
~9,000 LOC across ~10 PRs.

### Success criteria
- 70% auto-fix rate on the canonical OWASP Top 10 test corpus
- 95% of validated patches don't introduce regressions

---

## 12. Phase 13 — Continuous monitoring + long-term memory

**Goal**: the engine gets better with every customer engagement.

### Why
- Senior engineer behaviour: remember what's worked, recognize patterns
- Continuous monitoring catches regressions vs annual pentest
- Phase 5.4 telemetry foundation is unused

### Items

#### 13.1. Per-customer engagement memory
- `~/.strix/customers/<customer-id>/decision_log_archive.jsonl`
- On scan start, lead seeds context from:
  - Prior decision log (avoid re-discovery)
  - Confirmed findings from last engagement
  - Customer's threat-model preferences
~800 LOC.

#### 13.2. Cross-customer attack-pattern library (privacy-preserving)
- Anonymized: "this auth-shape correlates with kid-traversal"
- Features hashed, customer-identifying data stripped
- Continuous learning: every scan contributes
~1,200 LOC.

#### 13.3. Active-learning consumer
- Nightly job reads `specialist_telemetry.jsonl` + `specialist_misses.jsonl`
- Identifies common-miss patterns
- Generates new payload candidates via LLM
- A/B tests on synthetic + benchmark targets
- Persists winners into per-specialist `learned_payloads.json`
~900 LOC.

#### 13.4. Continuous scanning daemon
- `strix watch <target> --schedule="*/30 * * * *"`
- Re-runs specialists on schedule
- Emits findings only on **delta** (regression detection)
- Hooks into wrapper's alerting
~700 LOC.

#### 13.5. Mutation fuzzer with anomaly detection
- AFL-style random mutations + response-shape clustering
- Detects novel input handling bugs
- Generic fallback when neither static nor LLM-driven probing fits
~1,500 LOC.

#### 13.6. Researcher-feed ingester
- RSS / Bluesky firehose of curated security researchers
- LLM summarization → indexed by attack-class keyword
- Lead can search ("recent attack patterns affecting Express + JWT") to
  pull historical analogs into its hypothesis-EV scoring
~1,000 LOC.

### Deliverables
- Per-customer memory archive
- Anonymized cross-customer pattern library
- Active-learning nightly job
- Continuous scanning daemon mode
- Mutation fuzzer
- Researcher-feed ingester

### Phase effort
~6,000 LOC across ~7 PRs.

### Success criteria
- Demonstrable improvement on benchmark recall after 30 days of telemetry
  consumption
- Continuous mode catches ≥80% of intentionally-introduced regressions in
  staging-vs-production diff testing

---

## 13. Cross-cutting concerns

### Testing & quality
Every phase ships with:
- Unit tests pinning detection + suppressions + wiring (~10–20 per specialist)
- Integration test against a curated benchmark fixture
- Performance regression tests (each new specialist adds <10% to scan time)
- False-positive rate measurement on a known-clean corpus

### Performance
- Diff-aware mode for SAST + SCA + Secrets (Phase 6, 7, 12)
- Parallel specialist dispatch (Phase 1.7, already shipped)
- Specialist timeout budgets (per-tool `default_budget.max_wall_seconds`)
- Cache warm-up on engine boot (threat-intel + nuclei corpus)

### Telemetry
Every artifact produced (`*.jsonl`, `*.json`) goes through the existing
provenance log + Phase 5.4 telemetry stream so the wrapper can:
- Show real-time scan progress
- Render the engine's decision trace
- Surface counter-examples for triage tuning

### Security of the engine itself
- No raw customer source code persisted outside `<run_dir>` (configurable)
- Anonymized cross-customer pattern library (Phase 13.2) hashes features
- All third-party feeds verified by signature where available
- LLM calls scrubbed for customer-identifiable content before logging

---

## 14. Wrapper dependencies

The wrapper consumes engine outputs. New artifacts the wrapper needs (cross-
referenced in [`AISecurityEngineerUX.md`](./AISecurityEngineerUX.md)):

| Phase | Artifact | Wrapper consumer |
|---|---|---|
| 6 | `sca_inventory.json` | Findings inbox + dependency graph view |
| 6 | `auto_fix_patches.json` | "Apply Fix" PR-comment button |
| 7 | `sast_findings.json` (SARIF) | PR-comment annotations + GitHub Code Scanning |
| 8 | `ai_feature_findings.json` | LLM-security tab in dashboard |
| 9 | `event_stream.jsonl` | Real-time threat alerts in customer dashboard |
| 10 | `llm_fallback_invocations.jsonl` | Cost-monitoring + customer billing |
| 11 | `iac_posture.json` | Cloud-posture dashboard tile |
| 12 | `auto_fix_patches.json` | Auto-fix PR opener |
| 13 | `continuous_scan_deltas.jsonl` | Regression-alerting daemon |

The wrapper's onboarding flow assumes:
- Repo URL + GitHub App token → triggers Phase 6 lockfile parser + Phase 7 SAST
- Customer's deployed URL → triggers Phase 9 baseline + recurring DAST
- AWS/GCP/Azure read-only creds → triggers Phase 11 cloud posture

---

## 15. Out of scope

Things this engine deliberately won't do:

| Category | Why excluded |
|---|---|
| Mobile / firmware / IoT | Different target type; new infra; not relevant to vibe-coded SaaS apps |
| Memory-corruption (CWE-787, etc.) | Binary-class; not a fit for the Python-based engine |
| Compliance dashboard / customer trust pages / billing | These live in the wrapper |
| Bug bounty triage UX / customer-facing findings views | Wrapper |
| Auditor-handover PDF generation | Wrapper |
| Multi-tenant isolation / SSO | Wrapper |
| Symbolic execution / formal verification | Different research direction; consider after Phase 13 |
| AI/ML model adversarial testing (FGSM, etc.) | Out of scope vs Lakera/Protect AI; we focus on application-level LLM features |

---

## 16. Suggested phase order + timeline

| Sequence | Phase | Customer-value priority | Engineering risk |
|---|---|---|---|
| 1 | Phase 6 — SCA + Supply Chain | **highest** (dep CVEs are #1 vuln source) | low |
| 2 | Phase 7 — Real SAST | high (table stakes) | low (Semgrep wrapper) |
| 3 | Phase 8 — AI/LLM feature security | high (vibe-coded differentiator) | medium (novel area) |
| 4 | Phase 11 — IaC / Cloud Posture | high (deploy-stage risk) | medium |
| 5 | Phase 9 — Real-time intel + behavioural | medium (incremental) | medium |
| 6 | Phase 12 — Auto-fix / remediation | high (closes the loop) | high (codemod quality) |
| 7 | Phase 10 — AI-native LLM-fallback | medium (recall ceiling) | medium |
| 8 | Phase 13 — Continuous + memory | medium (long-term moat) | low |

**Total scope**: ~50,000 LOC across ~60 PRs.

**Calendar estimate**: 6–9 months at current pace (1–2 PRs/week with full
test coverage). Could be compressed to 3–4 months with multiple engineers.

---

## 17. Open questions

1. **Build vs buy on SAST**: shipping our own rule engine vs vendoring Semgrep.
   Latter is faster (Phase 7 ships in days not weeks) but creates a dep.
2. **Auto-fix safety**: how much do we trust LLM-generated patches? Phase 12's
   validation pipeline matters here; loosening it for speed would be a mistake.
3. **Customer code privacy**: Phase 13.2 cross-customer pattern library needs
   formal privacy review before any shared feature ingestion.
4. **Real-time feeds vs reliability**: push feeds add reliability concerns
   (webhook delivery failure, RSS rate limits). Daily fallback always.
5. **LLM cost ceiling**: Phase 10's LLM-fallback specialists need a hard
   per-customer cap to prevent runaway costs.
6. **Engine ↔ wrapper API stability**: every artifact format above is a public
   contract once the wrapper consumes it. Schema versioning matters.

---

## 18. Tracking

- This doc is the strategic plan; the tactical sequence lives in `workitem.md`
  (which should be updated after this is reviewed).
- Each phase opens a tracking issue in the GitHub repo.
- Engine releases should align with wrapper-side feature releases — the
  wrapper PRs gate on engine artifacts being available.
