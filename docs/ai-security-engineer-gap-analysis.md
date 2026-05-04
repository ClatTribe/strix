# AI security engineer — gap analysis

**Status:** Living document. Drives [`roadmap.md`](../roadmap.md) §17.6 + §18 row additions.
**Owner:** ClatTribe security-engineering.
**Companion:** [`docs/rlhf-design.md`](rlhf-design.md) (the closed FP-loop architecture this analysis recommends as Priority #2).

## What this is

A senior-AI-security-engineer-lens audit of [`roadmap.md`](../roadmap.md) along two dimensions:

1. **Target-analysis completeness** — what tools / coverage are still missing that an AI security engineer would notice on first engagement?
2. **AI-native OODA loop with reasoning + action agents** — how complete is the agentic architecture? Pieces exist; do they *compose*?

99 ⬜ + 6 🚧 items remained at audit time, with strong coverage of compliance/§16 (just closed) and §4 resilience. The two dimensions have very different shapes:

- **Dimension 1** — roadmap is ~80% complete by item count but has specific *kinds* of blind spots that show up immediately on real engagements.
- **Dimension 2** — pieces exist; they don't yet *compose* into a tight loop. This is the bigger gap.

## Dimension 1 — Target-analysis completeness

### A. Critical items already in roadmap as ⬜

Tracked, just unshipped. Execution work.

| # | Item | Roadmap row | Why it's critical |
|---|---|---|---|
| **A.1** | Validator agent / spin-up-app dynamic exploit | §7.1 + §17.1 | Single biggest finding-quality lever. Today ~70% of findings ship as `needs_review`. Without spin-up-app exploitation, "verified" is impossible for most categories. |
| **A.2** | Multi-language taint (JS/TS, Go, Java, Ruby, PHP, C#) | §7.1 / §17.1 | Python AST taint shipped (#96). Modern codebases are polyglot. Without JS/TS specifically, web-app SAST coverage is incomplete. Tree-sitter or LSP-based extraction is the lift. |
| **A.3** | Service-specialist skill packs (SMB / SSH / RDP / SNMP / LDAP / DBs) | §7.4 | Internal pen-tests are dominantly service-specialist work. IP-target findings depend on agent improvisation today. |
| **A.4** | `nuclei_scan` first-class tool | §9 | Nuclei templates ship daily; ad-hoc nuclei use means deterministic CVE coverage is missed run-to-run. First-class wrapping with template-by-tech selection is high-leverage. |
| **A.5** | `semgrep_scan` first-class tool | §9 | Semgrep covers high-confidence patterns in seconds. LLM-only static analysis is wasteful when the `r/security-audit` pack is sitting unused. |
| **A.6** | Deep cloud-IAM probe (per-cloud) | §17.3 | Cloud-IAM mis-config is the dominant breach class in modern public-cloud incidents. Strix's cloud coverage today is recon-only. Pacu-style edge enumeration is the credibility bar. |
| **A.7** | `llm_app` target type | §17.3 | Fastest-growing security-budget line item in 2025-26. The product-marketing inverse of the OWASP LLM Top 10 mention. |
| **A.8** | Network-protocol coverage: LDAP / AD / SMB / gRPC / IoT | §17.3 | Standard pen-test surfaces commercial scanners cover and Strix doesn't. AD especially — Kerberoasting and AS-REP roasting are on every internal-pentest checklist. |

### B. Blind spots NOT tracked in roadmap (true gaps)

These would all show up in the first hour of a real engagement. **Now added as new ⬜ rows in §7.0 / §7.1 / §7.2 / §17.3 of [`roadmap.md`](../roadmap.md).**

| # | Item | Roadmap location | Effort |
|---|---|---|---|
| **B.1** | HAR / Burp project ingestion | §7.0 (added) | M |
| **B.2** | First-class browser-automation specialist | §7.0 (added) | L |
| **B.3** | OAuth 2.0 / OIDC flow probe | folded into B.2 (browser specialist) | M |
| **B.4** | SAML / SSO testing (XSW, comment-injection) | folded into B.2 | M |
| **B.5** | CI/CD pipeline analysis (GitHub Actions / GitLab CI / Circle) | §7.1 (added) | M |
| **B.6** | First-class Dockerfile audit | §7.1 (added) | S |
| **B.7** | Build-graph analysis (npm lifecycle / Makefile / bazel) | §7.1 (added) | M |
| **B.8** | Deserialization gadget probe (ysoserial-style) | §7.1 (added) | M |
| **B.9** | Server-side template injection (SSTI) deterministic probe | §7.2 (added) | S |
| **B.10** | Real fuzzing (mutational + dictionary + coverage-guided) | not yet added — research-tier; defer to §15 | L |
| **B.11** | Server-Sent Events (SSE) testing | §7.2 (added) | S |
| **B.12** | Lambda / Function URL exposure probe | §17.3 (added) | S |
| **B.13** | Cloud-storage policy depth (S3 / GCS / Azure ACL+Policy+CORS+...) | §17.3 (added) | M |
| **B.14** | Browser-extension targets (Manifest V3 audit) | not yet added — niche; defer | M |
| **B.15** | Differential / record-replay scanning | §15 research (already partial) | M |
| **B.16** | Notification-abuse / signup-enumeration probe | §7.2 (added) | S |
| **B.17** | DDoS surface / amplification estimation | not yet added — niche; defer | M |
| **B.18** | Apollo / GraphQL persisted-query enumeration | not yet added — niche; defer | S |

## Dimension 2 — AI-native OODA loop

The roadmap has the *components*: lead-team protocol (#90), specialist registry (#89), budget enforcement (#88), handoff schemas, finding contract (#86), cross-target correlation (#83), validator subset (#93), output sanitiser (#84). They don't yet *compose* into a tight loop. Each new specialist is currently a one-off rather than a building block.

### C. Critical items already in roadmap as ⬜

| # | Item | Roadmap row | OODA stage |
|---|---|---|---|
| **C.1** | Closed FP feedback loop (RLHF pipeline) | designed in [`rlhf-design.md`](rlhf-design.md), unshipped | Decide / Orient (long-term) |
| **C.2** | Reasoning-trace per finding | §12 #687 | Orient + auditability |
| **C.3** | Continuous confidence score (0.0–1.0) | §12 #686 | Orient (substrate for FP classifier) |
| **C.4** | Counter-proof artifact alongside PoC | §12 #691 | Orient (negative examples for RL) |
| **C.5** | Reproducibility token per finding | §12 #692 | Orient (dedup reasoning attempts, distinct from fingerprint) |
| **C.6** | Severity-tiered self-verification depth | §12 #690 | Decide (action selection by severity) |
| **C.7** | Cost-aware planner at the lead | §14 #722 | Decide (pre-commit budget plan) |
| **C.8** | Adversary-model selector | §14 #721 | Orient (different threat actor → different checks) |
| **C.9** | Structured threat-model input | §14 #720 | Orient (business-logic findings need a spec) |
| **C.10** | Multi-target dependency graph | §14 #719 | Orient (cross-target reasoning needs a graph) |
| **C.11** | Stop-and-resume scan semantics (`--checkpoint`) | §17.4 #821 | Loop (operator review break) |
| **C.12** | Public benchmark / regression suite | §17.5 #829 | Loop (no way to grade agent improvements without it) |
| **C.13** | `agent.uncertain` event + human-in-the-loop window | §17.4 #820 | Decide / Loop |
| **C.14** | LLM-judgment severity tuning with provenance | §17.5 #828 | Orient (rule-based severity is blind to context) |
| **C.15** | Finding-cluster narrative emission | §17.5 #830 | Report (47 findings unreadable; 5 narratives is) |

### D. Architectural blind spots — NOT tracked anywhere

**Now added as new ⬜ rows in §17.6 of [`roadmap.md`](../roadmap.md).** These are the items that an AI security engineer would notice as "the OODA loop has pieces but they don't talk to each other."

| # | Item | OODA stage | What's missing |
|---|---|---|---|
| **D.1** | Active-hypothesis state shared across sub-agents | Decide / Act | Today specialists work from `surface_map.json` but don't see "things sister specialists are currently investigating." Two parallel specialists can spend tokens on the same hypothesis. Need a shared `active_hypotheses.jsonl` that updates near-real-time. |
| **D.2** | Tool-output provenance / trust-taint | Observe / Orient | #84 sanitises prompt-injection. But the agent doesn't structurally distinguish "this came from KEV catalog (trusted)" vs "this came from the target (potentially adversarial)." Every tool output should carry `provenance: {trusted_source\|target\|intel_feed}` the agent reasons over. |
| **D.3** | Reviewer-LLM on agent's chain-of-thought | Orient (verification) | A second LLM reviewing the first's reasoning steps before a finding is finalised. §17.5 has "LLM-judgment severity tuning" but only for severity. Full chain review catches "the chain ran but the conclusion was wrong" — the dominant FP failure mode. |
| **D.4** | Per-tool effectiveness telemetry | Loop (across runs) | Per-tool: how often does it fire? How often does it produce a confirmed-TP finding? Per-(tool × category): is the tool actually useful or noise? Without this metric, the maintainer can't prune dead tools or tune low-precision ones. |
| **D.5** | Active-learning specialist-spawn policy | Decide | When the lead has spawned 3 specialists and has budget for 5 more, which categories to spawn next? Today it's hand-coded heuristics. An active-learning policy would pick based on observed signal density. |
| **D.6** | `phase.completed` self-audit step | Orient | Between recon → exploit, exploit → validate, validate → report — the lead should run a structured self-audit ("Did I cover what's in the surface_map? Which categories did I skip? Which sub-agents are stuck?"). Today implicit; make it explicit. |
| **D.7** | Cross-run memory / strategic continuity | Loop (across runs) | Today every scan is from-scratch. Real engagements: "last week's scan found X; this week it's gone — was it remediated?" `--prior-findings` (§12 #676) is partial. Need `~/.strix/memory/<target>/` that survives runs. |
| **D.8** | Drift detection on agent's own behavior post-model-upgrade | Loop | When a model upgrade lands (Sonnet 4.5 → 5), how do we know the agent's still behaving? Need a baseline scan against a known-target + diff. (Pairs with §17.5 #829.) |
| **D.9** | Specialist-team cross-pollination | Act / Orient | §15 research mentions it. A finding by the IDOR specialist sometimes hints at a related Code-team check ("this endpoint missed `@require_role`"). Today specialists are siloed; cross-pollination would let one team's finding spawn a targeted check in another. |
| **D.10** | Trajectory-replay debugging tool | Loop (offline) | When a scan went wrong, the operator should be able to replay just the agent's trajectory (LLM calls + tool calls + state) without re-running tools. The events.jsonl + chain-hash (#127) are inputs; a replay tool isn't built. |
| **D.11** | Specialist coordination via blackboard | Orient | More architectural than D.1: a true blackboard (shared structured memory) that specialists POST findings/hypotheses/dismissals to and READ from. Today the closest analog is `tracer.get_existing_vulnerabilities()` (read-only, after-the-fact). |
| **D.12** | Operator-corrigibility hooks beyond cancel | Decide | The wrapper can SIGTERM (#114). It can't currently say "skip this category" or "spend more tokens on auth-flaws specifically" mid-scan. Need an inbox the agent polls for operator nudges. |

## Top 10 — minimum-viable-AI-security-engineer credibility

If we had to ship 10 things this year for Strix to be unimpeachable as an AI-native security engineer:

| Rank | Item | Tracked? | Dimension |
|---|---|---|---|
| **1** | Validator agent — spin-up-app dynamic exploit (the white-box → black-box bridge) | ⬜ §17.1 | 1 + 2 |
| **2** | Closed FP feedback loop (Phase 1 of the RLHF pipeline) | designed not shipped | 2 |
| **3** | HAR / Burp ingestion | §7.0 (added by this audit) | 1 |
| **4** | Reasoning-trace + continuous-confidence + counter-proof per finding | ⬜ §12 #686 / #687 / #691 | 2 |
| **5** | Multi-language taint (JS/TS first, then Go/Java) | ⬜ §17.1 | 1 |
| **6** | `llm_app` target type — OWASP LLM Top 10 probe | ⬜ §17.3 | 1 |
| **7** | Public benchmark + regression suite (CI on every PR) | ⬜ §17.5 #829 | 2 (loop) |
| **8** | Browser-automation specialist (DOM-XSS verify, CSP, postMessage, OAuth/OIDC, SAML) | §7.0 (added by this audit) | 1 |
| **9** | Active-hypothesis shared state + per-phase agent-self-audit | §17.6 (added by this audit) | 2 (architectural) |
| **10** | Tool-output provenance / trust-taint | §17.6 (added by this audit) | 2 (security of the agent itself) |

Five of those ten are partially or fully tracked but not yet shipped. **Five are blind spots** — concentrated on:

- *Inputs the agent should accept* (HAR/Burp, threat model)
- *Browser-shaped probes* (SAML/OAuth/CSP/postMessage all want a real browser)
- *Architectural OODA glue* (active-hypothesis sharing, provenance, self-audit)

This list now lives at [`roadmap.md` §18](../roadmap.md#18-minimum-viable-ai-security-engineer-credibility) as a strategic-priority section.

## What changed in roadmap.md

This audit produced concrete row additions. Diff at a glance:

**§7.0 (target-class-agnostic):**
- HAR / Burp project ingestion
- First-class browser-automation specialist

**§7.1 Code targets:**
- CI/CD pipeline analysis tool
- First-class Dockerfile audit
- Build-graph analysis (npm lifecycle / Makefile / bazel)
- Deserialization gadget probe

**§7.2 Web application:**
- SSTI deterministic probe
- Server-Sent Events (SSE) first-class testing
- Notification-abuse / signup-enumeration probe

**§17.3 New target classes (cloud):**
- Cloud-storage policy depth
- Lambda / Cloud Functions / Azure Functions URL exposure

**§17.6 (new subsection): AI-native OODA architecture**
- All 12 D.* items above

**§18 (new section): Minimum-viable-AI-security-engineer credibility**
- Top-10 strategic-priority list

## Why three new structural pieces

1. **§17.6 (AI-native OODA architecture)** — collects the architectural-glue items that don't fit cleanly under any single per-target subsection. The OODA loop is cross-cutting infrastructure.

2. **§18 (Minimum-viable credibility)** — strategic priority list that picks across the whole roadmap. Different from §17 (which is "gaps surfaced by a different audit"); §18 is "if I had to ship 10 items this year, these are the 10."

3. **This document (`docs/ai-security-engineer-gap-analysis.md`)** — the source-of-truth audit so the roadmap-row decisions are traceable. Future re-audits will diff against this doc and update the §17.6 / §18 rows.

## Re-audit trigger

Re-run the audit when:

- A model upgrade lands and findings-quality posture changes (Sonnet 4.5 → 5, or any major Claude generation).
- A wrapper integration ships that surfaces new operator-feedback signals (e.g., the RLHF Phase-1 work).
- A competitor ships a feature that becomes table-stakes (e.g., DARPA AIxCC binary-analysis raises the binary-target bar).
- Six months elapse without a re-audit.

The audit lives in this doc; updates ship as PRs to `docs/ai-security-engineer-gap-analysis.md` plus the corresponding §17.6 / §18 row updates.

## References

- [`roadmap.md`](../roadmap.md) — the engine roadmap this audit shaped.
- [`docs/rlhf-design.md`](rlhf-design.md) — the closed FP-loop architecture cited as Priority #2.
- [`overall.md`](../overall.md) — the strategic overview that shaped §17.
- [`wrapper-wishlist.md`](../wrapper-wishlist.md) §12-§14 — wrapper-side companions for the engine work.
- [`docs/lead-team-protocol.md`](lead-team-protocol.md) — the multi-agent OODA-loop protocol the §17.6 items extend.
