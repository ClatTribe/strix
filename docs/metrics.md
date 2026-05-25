# Strix metrics framework

**Status**: proposal — measure what matters, not just what's easy.
**Last updated**: 2026-05-25.

## Why we need this doc

Strix is currently measured on a single dimension: **must_find recall** on
Juice Shop / vampi / flask-vuln. Today that number is 2/9 on Juice Shop
must_find (3/109 on Juice Shop full) — which looks bad in isolation but
hides everything else the product does. Worse, the metrics that justify
strix's *architectural moat* (L1.5 enrichment, L2 reasoning) **are not
measured at all** by the current bench.

A pentester evaluating ANY DAST tool asks five different questions, not
one:

1. **Did it find the bug?** — coverage
2. **Was the finding real?** — precision / FP rate
3. **Did it tell me the right priority?** — severity calibration
4. **What did it cost me?** — wall time + $
5. **Did it explain HOW to exploit / fix?** — actionability

This doc defines those five axes formally, sets per-layer targets,
catalogs the benchmarks that should measure each, and shows where we
stand today.

---

## 1. The metric framework

### 1.1 Detection metrics (coverage)

| Metric | Definition | Why it matters |
|---|---|---|
| `must_find_recall` | matched / must_find_total | Current headline. Coverage of curated vulns. |
| `juice_shop_full_recall` | solved / 109 challenges via /api/Challenges/ | Broader coverage; SUT is the grader. |
| `chain_detection_rate` | (chains_found / chains_expected) when ≥2 findings compose | Multi-step attack discovery. **No competitor measures this.** |
| `novel_finding_rate` | findings_emitted / findings_in_corpora (KEV+nuclei+sqlmap templates) — fraction NOT already in any public corpus | LLM differentiation — humans find things scanners can't. |
| `surface_discovery_breadth` | unique_endpoints_probed / unique_endpoints_actually_present | Did we even SEE the surface? |

### 1.2 Quality metrics (precision)

| Metric | Definition | Why it matters |
|---|---|---|
| `fp_rate` | false_positives / total_emissions | Lower = less triage burden. **L1.5's primary purpose.** |
| `severity_tier_accuracy` | % of HIGH-severity findings that are actually exploitable critical | Wrong severity = wasted attention. **L1.5 surface_priority + exploitability.** |
| `reproducibility_rate` | % of findings where PoC re-fires same signal (verifier path) | Eliminates flake / transient state FPs. **L1.5 + L2.5 PoC verifier.** |
| `context_completeness` | % of findings with file+line + author + fix-hint + exploit-vector populated | Actionability vs. "here's a vuln, good luck." |
| `dismissal_accuracy` | % of correctly-dismissed FPs from the FP-filter pre-emission layer | Negative-space testing — did we correctly NOT report? |

### 1.3 Cost metrics

| Metric | Definition | Why it matters |
|---|---|---|
| `wall_seconds` | scan start → final report | Bench iteration speed; user-facing latency. |
| `cost_per_scan_usd` | total LLM + compute spend per scan | Tier pricing input. |
| `cost_per_matched_finding_usd` | cost / matched_count — the headline economics number | The L2 dev-persona pitch: "$0.10 per real bug." |
| `tokens_input` / `tokens_output` / `tokens_cached` | parsed from strix CLI summary panel | Diagnoses where the cost lives. |
| `tools_invoked` | unique tool calls during scan | Activity proxy; surfaces stuck-on-one-tool failures. |

### 1.4 Reasoning metrics

| Metric | Definition | Why it matters |
|---|---|---|
| `hypothesis_generation_rate` | % of L1 findings that triggered follow-up specialist dispatches | L2 reflex — "if SQLi here, check there too." |
| `corroboration_rate` | % of findings backed by ≥2 independent tool signals | L1.5 corroborator — promote signals seen by multiple tools. |
| `chain_depth_p50` / `chain_depth_p95` | distribution of finding-counts within detected chains | Did L2 reason 3 steps deep or 1? |
| `phase_correlate_emissions` | # of chain_summaries emitted at phase boundaries | iter-27.2 mid-scan correlate — direct activity measure. |

### 1.5 Output / patcher metrics

| Metric | Definition | Why it matters |
|---|---|---|
| `patch_correctness` | % of auto-PRs that compile + pass tests | L2 patcher chain quality (iter-27.3). |
| `explanation_clarity` | developer survey, 1-5 scale | Subjective but THE conversion lever for dev-persona. |
| `actionable_rate` | % of findings with a concrete next step (probe, fix, dismiss) | Triage UX. |

### 1.6 Enterprise / compliance metrics (L3 only)

| Metric | Definition |
|---|---|
| `soc2_controls_covered` | CC6.1 / CC6.6 / CC7.x rule coverage % |
| `portfolio_drift_detection` | % of new findings flagged as "new since last scan" |
| `audit_log_completeness` | % of dispatch decisions logged for SOC2 evidence |
| `evidence_export_format` | PDF / SARIF / CSV / JIRA-ready availability |

---

## 2. Per-layer targets

Numbers are realistic targets anchored against competitor data
(ZAP automated 14% on Juice Shop full, Burp Pro 23%, pentester 60-80%).

| Metric | L0 (rules) | L1 (OSS specialists) | L1.5 (enrichment) | L2 std | L2 deep | L2+ (hypothesis) | L3 (portfolio) |
|---|---|---|---|---|---|---|---|
| **must_find_recall** (curated) | 10% | 60-75% | unchanged | 80-90% | 90-95% | 95% | n/a |
| **juice_shop_full** | 1-2/109 | **15-25/109** | unchanged | **25-40/109** | **40-55/109** | **55-75/109** | n/a |
| **chain_detection_rate** | 0% | 0% | **40-60%** ⭐ | 70% | 80% | 90% | 95% |
| **novel_finding_rate** | 0% | 5% | 5% | 15-25% | 30% | **40-60%** ⭐ | 60% |
| **surface_discovery_breadth** | n/a | 70-85% | 85-90% | 90% | 95% | 98% | 98% |
| **fp_rate** | 30-50% | 20-30% | **≤10%** ⭐ | ≤8% | ≤5% | ≤3% | ≤3% |
| **severity_tier_accuracy** | 50% | 60% | **≥85%** ⭐ | 90% | 92% | 95% | 95% |
| **reproducibility_rate** | 100% | 70% | 90% | **95%** ⭐ | 98% | 99% | 99% |
| **context_completeness** | 30% | 60% | **100%** ⭐ | 100% | 100% | 100% | 100% |
| **dismissal_accuracy** | n/a | n/a | **≥80%** ⭐ | 85% | 90% | 92% | 92% |
| **wall_seconds** (median) | <30 | 300-900 | <5 | 300-900 | 1800-3600 | 3600-14400 | n/a |
| **cost_per_scan_usd** | ~$0 | $0.01-0.10 | $0 | $1-5 | $5-20 | $10-50 | $50+/target/mo |
| **cost_per_matched_finding_usd** | $0 | <$0.05 | $0 | **<$0.50** ⭐ | <$2 | <$5 | <$10 |
| **hypothesis_generation_rate** | n/a | n/a | n/a | 20% | 40% | **60-80%** ⭐ | 80% |
| **corroboration_rate** | n/a | 10% | **30-50%** ⭐ | 60% | 70% | 80% | 85% |
| **chain_depth_p95** | n/a | 1 | 2-3 | 3 | 4 | **5+** ⭐ | 5+ |
| **patch_correctness** | n/a | n/a | n/a | 40% | 60% | **75%+** ⭐ | 80% |
| **explanation_clarity** (1-5) | 1 | 2 | 3 | **4+** ⭐ | 4.3 | 4.5 | 4.5 |
| **actionable_rate** | 30% | 60% | 85% | **95%+** ⭐ | 97% | 98% | 98% |

⭐ = **PRIMARY metric for that layer** — what the layer is most directly responsible for.

---

## 3. Benchmark catalog

A single benchmark can only measure a subset of the framework above.
Different benchmarks emphasize different axes.

### 3.1 Current benchmarks

| Bench | Where | Measures | Doesn't measure |
|---|---|---|---|
| `bench_l1_only.py` | strix repo | must_find recall, wall time, found_count, partial precision | FP rate, severity, chains, dismissals, cost |
| `bench_l2_juiceshop_full.py` | strix repo | juice_shop_full_recall, weighted_score, tier breakdown, cost, tools used | FP rate, chains, severity, dismissals, explanation |
| `bench_validate_change.py` | strix repo | per-fixture delta (anti-overfit gate) | per-metric improvement |
| `runner.py` | strix repo | per-target full L2 scan + score against expected.yaml | same gaps as L1 bench |
| `benchmarks/run_all.sh` | strix repo | wrapper over runner.py + L1 + L2 | aggregator only |

### 3.2 Proposed benchmarks (not built — gaps in the framework)

| Bench (proposed) | What it adds | Effort |
|---|---|---|
| **`bench_fp_suppression.py`** | New `expected_dismissed[]` field in expected.yaml + scoring for fp_rate, dismissal_accuracy | S (~150 LOC + per-fixture YAML edits) |
| **`bench_chains.py`** | New `expected_chains[]` field — list of multi-finding chains with kind + members. Scores chain_detection_rate + chain_depth_p95. | M (~300 LOC) |
| **`bench_severity_calibration.py`** | New `expected_severity_tier` per finding. Scores severity_tier_accuracy. | S (~150 LOC + YAML edits) |
| **`bench_novel.py`** | Diff strix's findings against KEV + nuclei + sqlmap template corpora to compute novel_finding_rate. | M (~400 LOC) |
| **`bench_cost_per_finding.py`** | Aggregate cost_per_matched_finding across full bench suite. Headline economics number. | S (~100 LOC, mostly aggregation) |
| **`bench_patcher_correctness.py`** | Auto-PR each finding's diff into a sandbox repo; run that repo's tests; count compile + pass rate. | L (~800 LOC) |
| **`bench_explanation_eval.py`** | Sample N findings, route through Claude/Gemini to rate explanation clarity 1-5 vs reference. | M (~400 LOC) |
| **`bench_hypothesis_replay.py`** | Replay strix scans against HackerOne disclosed bug-bounty reports; measure rediscovery rate. | L (~1000 LOC + report curation) |
| **`bench_drift.py`** | Run strix weekly against same target; measure new + regressed + fixed findings over time. | M (~500 LOC + scheduling). L3-only. |
| **`bench_portfolio.py`** | Run strix against N targets; aggregate cross-target chain detection. | L (~600 LOC). L3-only. |

---

## 4. Current performance — actual measurements

These are the numbers from the last bench run (2026-05-25, post iter-30.4).

### 4.1 must_find_recall (the metric we DO measure)

| Fixture | L0 | L1 | L1+L1.5 | L2 std (Gemini Flash) | L2 deep | Target (L1) |
|---|---:|---:|---:|---:|---:|---:|
| code/flask-vuln (10) | n/a | **9/10 (90%)** | 9/10 | not measured | not measured | 7-8/10 ✓ exceeds |
| api/vampi (8) | n/a | **7/8 (87%)** | 7/8 | not measured | not measured | 6-7/8 ✓ on target |
| web+code/vibe-app (5) | n/a | **3/5 (60%)** | 3/5 | not measured | not measured | 4-5/5 ✗ below |
| ip/vulnerable-services (3) | n/a | **3/3 (100%)** | 3/3 | not measured | not measured | 3/3 ✓ |
| web/juiceshop must_find (9) | n/a | **2/9 (22%)** | 2/9 | not measured | not measured | 5-7/9 ✗ **way below** |
| web/juiceshop FULL (109) | n/a | **3/109 (3%)** | 3/109 | 3/109 ($0.30) | not run | 15-25/109 ✗ **5-8× below** |
| container/nginx-vuln (4) | n/a | **4/4 (100%)** | 4/4 | not measured | not measured | 4/4 ✓ |

### 4.2 fp_rate, severity_accuracy, chain_detection — current state

| Metric | Layer | Current measurement | Target | Gap |
|---|---|---|---|---|
| fp_rate | L1 | **not measured** | n/a (no target) | bench missing |
| fp_rate | L1.5 | **not measured** | ≤10% | bench missing — `expected_dismissed[]` not in any fixture |
| severity_tier_accuracy | L1.5 | **not measured** | ≥85% | bench missing — `expected_severity_tier` not in any fixture |
| chain_detection_rate | L1.5 | **not measured** | 40-60% | bench missing — `expected_chains[]` not in any fixture |
| corroboration_rate | L1.5 | **not measured** | 30-50% | unobserved (L1.5 corroborator logs but no fixture scores it) |
| reproducibility_rate | L2 | **not measured** | 95% | iter-29.5 PoC verifier built but bench doesn't read its output |

### 4.3 Cost metrics (we DO measure these now)

| Run | Cost ($) | Matched | $/finding | Wall (s) |
|---|---|---|---|---|
| L2 Juice Shop full (Gemini Flash, 2026-05-25 01:20) | 0.30 | 3 | **0.10** ✓ beats <0.50 target | 567 |
| L2 Juice Shop full (planned: Pro/Sonnet) | est 3-8 | est 25-40 | est 0.10-0.30 ✓ | est 1800-3600 |

cost_per_matched_finding is the ONE metric we hit our target on, by accident.

### 4.4 Reasoning metrics — current state

| Metric | Layer | Current state | Gap |
|---|---|---|---|
| hypothesis_generation_rate | L2+ | 0% — feature not built (proposed iter-29) | architectural |
| chain_depth_p95 | L1.5 + L2 | **1** (no chains detected in any bench run so far) | both bench + L1 detection floor too low |
| phase_correlate_emissions | L2 | not surfaced to bench | iter-27.2 fires but invisible to scorer |
| patch_correctness | L2 | not measured | bench missing |
| explanation_clarity | L2 | not measured | bench missing |

### 4.5 Output metrics — current state

| Metric | State |
|---|---|
| context_completeness | unmeasured (L1.5 git_blame + finding context exists; bench doesn't read it) |
| actionable_rate | unmeasured |
| dismissal_accuracy | unmeasured |
| novel_finding_rate | unmeasured |

---

## 5. Honest position summary

Of the **19 metrics** we should measure across layers, we currently measure **3**:
- must_find_recall ✓
- juice_shop_full_recall ✓
- cost / cost_per_matched_finding ✓ (only in the L2 bench)

The other **16 are invisible** to current benches. Which means:

* **We can't prove L1.5's value.** All of L1.5's primary metrics (fp_rate, severity_accuracy, chain_detection_rate, dismissal_accuracy, corroboration_rate) are unmeasured. The architectural moat is real but unprovable to a skeptic.
* **We can't prove L2's value.** Beyond cost economics, every L2 differentiation metric (hypothesis_generation_rate, novel_finding_rate, explanation_clarity, patch_correctness) is unmeasured.
* **3/109 looks bad in isolation, but it's the wrong measurement.** Juice Shop full's `solved` count is a pure coverage metric — it doesn't reward chain detection, FP suppression, severity calibration, explanation quality, or novel-finding generation. These are where the product wins.

---

## 6. What to ship next (priority-ordered)

| # | Item | Effort | Unlocks |
|---|---|---|---|
| 1 | `bench_fp_suppression.py` + `expected_dismissed[]` in 3+ fixtures | S | L1.5 fp_rate + dismissal_accuracy visible |
| 2 | `bench_chains.py` + `expected_chains[]` in juice-shop + vampi | M | L1.5 chain_detection_rate + L2 chain_depth_p95 |
| 3 | `expected_severity_tier` per finding + bench scoring | S | L1.5 severity_tier_accuracy visible |
| 4 | iter-30.5 (proper control payloads in fire_and_diff) | M | Lift L1 juice_shop_full from 3 → 8-15 (then L1.5 can demonstrate ≥10% FP suppression on a bigger sample) |
| 5 | `bench_novel.py` against KEV + nuclei templates | M | L2+ novel_finding_rate visible |
| 6 | `bench_patcher_correctness.py` with sandbox-repo PR replay | L | L2+ patch_correctness visible |
| 7 | `bench_explanation_eval.py` with LLM-as-judge | M | L2 explanation_clarity visible |
| 8 | `bench_hypothesis_replay.py` against HackerOne reports | L | Real-world signal; tier-conversion proof |

**#1-3 are the bench overhaul** — they make L1.5's architectural moat measurable. Without them, every conversation about strix's value is anchored to one metric (must_find recall) that doesn't reflect what strix actually does better than competitors.

**#4 is the L1 detection lift** that makes the existing bench number look less bad.

**#5-8 are the L2+ differentiation evidence** — proof points for the dev-persona tier conversion.

---

## 7. What "performing well" actually means — per-metric value to each persona

A metric target is just a number until it's tied to the user's daily
work. Below, each metric is restated as: *what the target unlocks for
the security engineer (Pro/Enterprise persona) and for the developer
(Pro persona) in concrete terms.*

### Detection axis

| Metric | Target | What it means for the **security engineer** | What it means for the **developer** |
|---|---|---|---|
| **must_find_recall** | 80%+ at L1+L2 | "I can trust strix to catch OWASP top-10 on my routine scans, so I spend manual Burp time on the 20% edge cases instead of the 80% well-known patterns." | "CI gate will catch the obvious bugs before a human reviewer has to flag them. I won't ship a textbook SQLi." |
| **juice_shop_full_recall** | 40/109 at L2 std | "On a known-vulnerable demo I can validate the tool's coverage breadth before recommending it to my org — passes the smoke test for OWASP-classic surface." | "Confidence the scanner generalizes beyond cherry-picked cases — works on a real (if intentional) buggy app." |
| **chain_detection_rate** | 60% at L1.5 | "The multi-step attacks that take me 4 hours in Burp — auth-bypass → IDOR → admin → data exfil — get surfaced as ONE chain finding with the kill-chain laid out. I review the chain, not 4 isolated mediums." | "The tool shows me `your SQLi + your IDOR + this admin endpoint = critical data-breach scenario`, not 3 yellow warnings I'll ignore." |
| **novel_finding_rate** | 30%+ at L2+ | "Tool finds things outside the standard sigfile/template corpus — proves it does more than what I could `grep -r CVE-` for. Justifies the budget." | "Catches bugs in MY custom business logic, not just CVEs already in nuclei templates. Generic SAST can't do this." |
| **surface_discovery_breadth** | 90% at L1 | "Audit signoff: 'we tested every endpoint your app exposes.' Comprehensive enumeration = no audit findings about missed surface." | "SPA hash routes, JS-bundled API endpoints, hidden /api/v2/ paths — all discovered automatically. I don't have to maintain a list of paths to scan." |

### Quality axis (where L1.5's moat lives)

| Metric | Target | Security engineer | Developer |
|---|---|---|---|
| **fp_rate** | ≤10% at L1.5 | "Triage budget: I investigate 10 findings, ~9 are real. With most tools I waste 4 hrs/week chasing alarms. With this, 30 min." | "PR comment fatigue dies. I stop dismissing the tool after the first 5 false alarms. Tool keeps being useful month 6." |
| **severity_tier_accuracy** | ≥85% at L1.5 | "When tool says CRITICAL, on-call wakes up — and there's a real reason. No 'cried wolf' burnout on the team." | "When tool says BLOCK MERGE, the PR is genuinely unsafe. Trust builds. No 'just override the tool' culture." |
| **reproducibility_rate** | 95% at L2.5 | "Every finding I hand to a dev comes with a working PoC — the exact curl/request that triggers it. No 'works on my scanner' arguments." | "Clear repro = fast fix. I copy the curl, run it, see the bug, apply the fix, re-run, verify. 5 minutes vs 50." |
| **context_completeness** | 100% at L1.5 | "Every finding: file+line+author+fix-hint+exploit-vector. I don't dig into the codebase to understand — I review the finding's metadata, ack or push back to dev." | "Bug location, who wrote the code, what to change. Sometimes the patcher PR is already drafted. Fix in 5 minutes." |
| **dismissal_accuracy** | ≥80% at L1.5 | "Tool correctly NOT-reports test-file vulns + framework-defaults + docstring patterns. Team doesn't get desensitized to a noise machine." | "No 'we already checked, the scanner is wrong about this test fixture' conversations. The tool *knows* it's a test file." |

### Cost axis (the dev-persona economics)

| Metric | Target | Security engineer | Developer |
|---|---|---|---|
| **wall_seconds** (median) | <15 min L2 | "Run after every fix attempt during a pentest engagement — fast feedback loop, not a 6-hour batch." | "Fits inside a CI gate. PRs merge in 20 min, not blocked for an hour." |
| **cost_per_scan_usd** | <$5 L2 std | "Scan every staging deploy without quarterly budget conversation. Procurement-friendly." | "Scan every PR without finance flagging the AWS bill." |
| **cost_per_matched_finding_usd** | <$0.50 L2 std | "$-per-real-bug is auditable + defensible to CFO. Cheaper than the engineer's hourly rate to find the bug manually." | "The line item on the invoice ($X for Y bugs found) doesn't get questioned. Compared to a single security-engineer salary, this is rounding error." |
| **tokens_input/output** | track | Diagnostic: cost root-cause when bills go up. | Same. |
| **tools_invoked** | track | "Audit trail — I can prove which tools ran against which surface for compliance reporting." | Debug: why didn't tool X scan endpoint Y? |

### Reasoning axis (the L2 differentiation)

| Metric | Target | Security engineer | Developer |
|---|---|---|---|
| **hypothesis_generation_rate** | 60%+ at L2+ | "Tool extrapolates from finding A to test endpoint B — like a junior pentester does on instinct. I get a senior pentester's coverage from a one-engineer team." | "The tool 'thinks' — catches stuff a sigfile can't. It sees SQLi on /search and goes 'wait, /admin might have the same parser'. Finds bugs I'd never have caught with rule-based tools." |
| **corroboration_rate** | 30-50% at L1.5 | "Every reported finding is backed by ≥2 independent tool signals. High-confidence triage starts here — no '1-signal heuristic' false starts." | "Two scanners agree → don't argue with the finding, just fix. Removes the 'is this real?' meeting." |
| **chain_depth_p95** | 4+ at L2+ | "4-step chain detection matches what I'd manually construct in Burp Suite over an afternoon. Tool does my baseline chain-analysis for me." | "Executive summary `auth bypass → IDOR → privesc = data breach scenario` is written for me. I forward it to my manager — no translation needed." |
| **phase_correlate_emissions** | >0 per scan | "Signal that the tool is doing cross-phase analysis, not isolated scans. Visible in the audit trail." | Implicit — they just see better chain reports. |

### Output axis (the patcher + explainability win)

| Metric | Target | Security engineer | Developer |
|---|---|---|---|
| **patch_correctness** | 75%+ at L2+ | "75% of generated PRs I can review-and-approve directly without edits. Frees up half a sprint per quarter on routine fixes." | "Tool fixed it for me, I just merge the PR. Eliminates the fix-cycle entirely. The bug never enters my todo list." |
| **explanation_clarity** | 4+/5 at L2 | "Can hand the finding to the dev without translating + a security tutorial. The finding describes the impact and the fix in language the dev understands." | "I don't need a security background to understand what the bug is + what to change. Plain English + example exploit + suggested code change." |
| **actionable_rate** | 95%+ at L2 | "Every finding has a next step (probe deeper / fix this way / safely dismiss). No 'what do I do with this?' findings polluting my queue." | "Each PR comment is a TODO I can act on, not a question. 'Change this line, here's why, here's the test.'" |

### Enterprise / compliance axis (the L3 differentiation)

| Metric | Target | Security engineer (Enterprise) |
|---|---|---|
| **soc2_controls_covered** | CC6.1/CC6.6/CC7.x | "Auditor asks 'how do you know you covered access control + change management?' — I show the strix portfolio report with per-control coverage. SOC2 prep drops from 3 months to 3 weeks." |
| **portfolio_drift_detection** | week-over-week diff | "Show the board: 'this quarter we eliminated 23 highs, 2 new ones landed in the auth service this week.' Quantified posture, not vibes." |
| **audit_log_completeness** | 100% of dispatch decisions | "Every probe, every dismissal, every patch suggestion logged. Compliance officer reviews the audit trail without bothering engineering." |
| **evidence_export_format** | PDF/SARIF/CSV/JIRA | "Push findings directly into JIRA/Linear; export PDF for the auditor; SARIF for our SAST aggregator. No copy-paste." |

---

## 8. Per-axis "good day" narratives

Translating the metric targets into what a *good day* using strix
looks like for each persona.

### A security engineer at a 50-person SaaS startup

> Monday morning: I get a strix weekly digest. 7 new findings since
> last week, 2 critical. Strix's chain detector grouped them — both
> criticals are actually 1 chain (a new admin endpoint deployed last
> Friday + the existing IDOR primitive). I review the chain in 5
> minutes (vs the 2 hours I'd spend manually correlating).
>
> The patcher already drafted a PR for the admin endpoint. It's
> good — adds a permission check that matches the pattern of every
> other admin endpoint we have. I approve, the dev merges, strix
> reruns and confirms the chain is broken.
>
> Total time spent this week on strix-found bugs: 90 minutes.
> Before strix: 6-8 hours, plus weekend pages.

**Metrics doing the work**:
- chain_detection_rate (60% — bundled the 2 criticals into 1 chain)
- patch_correctness (75% — PR was good enough to merge)
- explanation_clarity (4+ — I understood without digging)
- portfolio_drift_detection (week-over-week diff surfaced what's new)

### A developer at a 5-person seed-stage team

> Tuesday I push a PR. CI runs strix. Comment appears on my PR:
>
> > ❌ Blocking: SQL injection in /api/users/search (line 42)
> > Your `q` param flows into `db.query("SELECT ... WHERE name LIKE %"+q+"%")`.
> > An attacker can `q='; DROP TABLE users; --`.
> > **Fix**: use parameterized query (template patch in the diff below).
>
> The diff is correct. I apply it (one keystroke). Push. CI passes.
> PR merges 5 minutes later.
>
> Without strix: that SQLi would have shipped to staging, our (one
> overworked) backend engineer would have caught it in code review
> eventually maybe, or — more likely — a bounty hunter would have
> found it in 3 weeks and we'd be writing a postmortem.

**Metrics doing the work**:
- must_find_recall (90%+ — caught the bug)
- explanation_clarity (4+ — plain English + working PoC)
- patch_correctness (75%+ — fix was applicable)
- actionable_rate (95%+ — the comment had a concrete next step)
- wall_seconds (<15 min — didn't slow my PR)

### What "bad performance" looks like for both personas

| If the metric is BAD... | Security engineer experience | Developer experience |
|---|---|---|
| **fp_rate ≥ 30%** | "I spend 4 hours every Monday triaging junk. By month 3 I dismiss strix findings without reading. By month 6 I've turned the tool off." | "I dismiss the tool's PR comments within 2 weeks. CI gate becomes noise. We rip it out of the pipeline." |
| **chain_detection_rate ≤ 10%** | "Tool gives me 3 isolated findings instead of 1 chain. I have to mentally correlate them. Same work as without the tool." | "I see 3 separate yellow warnings. They look minor. None are blocking. I merge. Two months later we have a breach." |
| **patch_correctness ≤ 30%** | "Generated PRs are wrong half the time. I stop reviewing them, just delete." | "Auto-PRs are wrong. I don't trust them. I write the fix myself. Tool's biggest pitch (auto-fix) fails." |
| **explanation_clarity ≤ 2.5/5** | "I have to translate every finding to plain English for the dev. Adds 30 minutes per finding." | "I don't understand the finding. Ask the security engineer. They're busy. PR sits open for 3 weeks." |
| **cost_per_matched_finding ≥ $5** | "Quarterly bill is $1000 for 200 bugs. Manager asks 'why?' Hard to justify vs hiring 1/4 of a security engineer." | "Bill keeps growing. Finance flags. We downgrade the plan. Now we only scan 1 in 5 PRs. Bugs slip through." |

The bad-day stories aren't hypothetical — they're what Snyk-adopters
say in churn surveys after 12-18 months. Strix's positioning is
explicitly to **not be that.**

---

## 9. The pitch — how this framework reframes the 3/109 number

Without this framework:

> "Strix scores 3/109 on Juice Shop full. ZAP scores 15/109. We're way behind."

With this framework:

> "On the must_find detection axis, we're at L1 floor (3/109) because our deterministic dispatcher's signal model needs the iter-30.5 control-payload fix. We're competitive on cost economics ($0.10/finding) and architectural moat (L1.5 enrichment, no competitor has this layer). The detection number rises after iter-30.5; the moat metrics are real today but currently unmeasured by the bench. The next bench iter measures all 19 metrics, not just 1."

That's the conversation we want with a developer evaluating strix vs. Aikido or Snyk.
