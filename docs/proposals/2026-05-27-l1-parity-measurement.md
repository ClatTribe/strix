# Q3 — Measuring L1 / L1.5 parity vs. standalone OSS tools

**Status:** proposal — pending review (revised post product-goal framing in CLAUDE.md §1.5)
**Owner:** ClatTribe/strix
**Created:** 2026-05-27
**Related:** Q1 (`docs/proposals/2026-05-27-benchmark-suite-strategy.md`), Q2 (`docs/proposals/2026-05-27-token-reduction-v2-stratified-compaction.md`)

---

## 1. The question

> *"Finding the vuln at L1/L1.5 should match best-in-class at that level. Is that happening?"*

Translated into a measurable claim:

> **For every OSS tool we wrap (nuclei, sqlmap, dalfox, semgrep, trufflehog, …), strix's wrapper achieves the same per-fixture detection recall as running the OSS tool directly with its default "find everything" flags.**

If the claim holds, strix's L1 layer is **as good as the leading OSS tool of record** — anything better would require a new OSS scanner or our own in-house engine (the latter is forbidden per CLAUDE.md §11.1). If the claim *does not* hold, the gap is a wrapper bug, not a model-class limitation, and is fixable in days.

Q1 measures strix-vs-competitors externally (OWASP Benchmark, WebGoat, Vulhub). Q3 measures **strix-wrapper-vs-the-tool-it-wraps**, which is the upstream causal layer Q1's numbers depend on. Without Q3, a regression in strix's OWASP Benchmark Youden index could be a nuclei-flag bug, a result-parsing bug, an L1.5 over-suppression bug, or a model regression — and we have no way to tell which.

### 1.1 Why this is THE load-bearing measurement (per CLAUDE.md §1.5)

Per the product framing codified in CLAUDE.md §1.5, strix produces two artifacts:

| Artifact | Audience | Source data |
|---|---|---|
| **Security dashboard** | Security team — knows how to read raw scanner output | L1 (pre-L1.5) findings, verbatim from the OSS tool |
| **Developer Action List** | Non-security team (devs, PMs) | L2 narrative — prioritized + chained + remediation-mapped + compliance-tagged |

The security-team-facing artifact **is the OSS tool's output, surfaced through strix**. If strix drops findings that the OSS tool would have surfaced, the security team has a strictly worse dashboard than running the tool directly — and the value proposition collapses. **L1 parity is therefore not a nice-to-have benchmark; it is the precondition for the entire product.**

The L2 audience (devs, PMs) is downstream: L2 cannot translate, prioritize, or chain findings that L1 didn't surface. So Q3's parity bench is also the prerequisite for L2's value. Both audiences depend on it.

This is why Q3 is the **causal-attribution layer** for every other Q-track:
* Q1 regressions get attributed to specific Q3-named wrappers.
* Q2's `<1pp regression gate` is implemented by re-running Q3 with stratified compaction on/off.
* Q4's parallelism gate is the same.

Without Q3, every PR that touches L1 / L1.5 / Q2 / Q4 is shipping on a guess.

---

## 2. Why Q1 doesn't already answer this

Q1's per-layer recall matrix is the right *external* gauge:

| Q1 bench | Compares strix against | Layer attribution |
|---|---|---|
| `bench_owasp_benchmark.py` | Veracode / Checkmarx / Fortify / ZAP | L1 (with `STRIX_L2_DISABLED=1`) |
| `bench_webgoat_dual.py` | Internal — detection vs. lesson-completion gap | L2 chain gap |
| `bench_vulhub_cve_corpus.py` | Internal — KEV hit rate | L0 corpus freshness |

What none of these answer:

* When strix's OWASP Benchmark Youden index moves, **which wrapper changed**?
* When `scan_nuclei_templates` finds 12 vulnerabilities and standalone nuclei finds 17 against the same fixture, where did the 5 go?
* When the L1.5 FP filter drops 8 findings, are those 8 actual FPs or are we silently regressing recall on a vuln category?

These are wrapper-internal questions. The OWASP / WebGoat / Vulhub benches treat strix as a black box; they cannot localize the loss.

---

## 3. Failure modes we expect to find

Each wrapper is ~50–150 LOC of CLI orchestration around a battle-tested OSS binary. The places we leak detection are predictable:

| Failure class | Example | Detection mechanism |
|---|---|---|
| **Wrong CLI flags** | `scan_nuclei_templates` defaults to `-tags exposed-panels,cve` but standalone nuclei runs all 9k+ templates by default | Diff `cmd[]` array against canonical "find everything" recipe |
| **Stale flag surface** | Tool added `-include-cve` last release; our wrapper still uses the deprecated `-cve` | Snapshot tool `--help` output per release |
| **Aggressive timeout** | Wrapper sets `-timeout 30s` (LLM-cost-driven); standalone defaults to 300s. Slow targets time out before tool finds the deep vulns | Multi-timeout bench (30s / 120s / 300s) |
| **Output parsing drops** | Wrapper splits `nuclei -jsonl` by line but mangles multi-line stack traces | Diff `finding_count` parser-input vs. parser-output |
| **Target subsetting** | Wrapper feeds only `target_url` while standalone nuclei would crawl from it | Bench with `--explicit-endpoints` vs. `--root-only` |
| **L1.5 FP filter over-eager** | `pre_emission_fp_filter` drops findings that look like the planted-decoy shape but are real | Bench with `STRIX_L15_DISABLED=1` (already shipped in Q1.4) |
| **Result-shape munging** | Wrapper coerces `severity: "info"` → severity: "low" so it gets demoted out of the report | Per-finding field-level diff |
| **Stale tool binary** | Sandbox image pins nuclei v3.1; latest is v3.4 with new templates | `tool --version` snapshot per bench run |

The first 7 are detectable from inside strix; the 8th requires a separate corpus-freshness pager (Vulhub CVE bench from Q1.3 covers part of it for nuclei templates).

---

## 4. Inventory of wrappers in scope

Per `ls strix/tools/*_runner/` (PR #494 + iter-37.4), the in-scope L1 OSS wrappers are:

### High-value detection wrappers (P0 — bench first)

| Wrapper | OSS tool | Detection category |
|---|---|---|
| `nuclei_runner/scan_nuclei_templates` | nuclei | CVE + misconfig signatures |
| `sqlmap_runner/scan_sqli_sqlmap` | sqlmap | SQL injection |
| `dalfox_runner/scan_xss_dalfox` | dalfox | XSS |
| `trufflehog_runner/verify_credentials_trufflehog` | trufflehog | secrets |
| `taint/taint_analysis` | semgrep | SAST taint flows |
| `ffuf_runner/scan_fuzz_ffuf` | ffuf | content discovery + parameter fuzz |

### Discovery / surface wrappers (P1 — bench second)

| Wrapper | OSS tool | Purpose |
|---|---|---|
| `katana_runner/crawl_with_katana` | katana | JS-aware crawl |
| `subfinder_runner/enumerate_subdomains_subfinder` | subfinder | subdomain enum |
| `httpx_runner/probe_hosts_httpx` | httpx | live-host probing |
| `nmap_runner/fingerprint_services_nmap` | nmap | port + service fingerprint |
| `inql_runner/map_graphql_inql` | inql | GraphQL introspection |

### Hygiene / compliance wrappers (P2 — bench third)

| Wrapper | OSS tool | Purpose |
|---|---|---|
| `dockle_runner/scan_image_dockle` | dockle | container linting |
| `checkdmarc_runner/scan_dns_hygiene_checkdmarc` | checkdmarc | DNS hygiene |
| `dnstwist_runner` | dnstwist | typo-squat detection |
| `testssl_runner/tls_audit_testssl` | testssl.sh | TLS misconfig |
| `mobsf_runner/scan_mobile_mobsfscan` | mobsfscan | mobile SAST |
| `hadolint_runner` | hadolint | Dockerfile linting |
| `hydra_runner/probe_default_creds_hydra` | hydra | default-cred bruteforce |
| `smuggler_runner/scan_smuggling_smuggler` | smuggler | HTTP request smuggling |
| `schemathesis_runner/scan_api_schemathesis` | schemathesis | API spec fuzzing |
| `feroxbuster_runner` | feroxbuster | directory bruteforce |
| `bbot_runner` | bbot | recursive recon |

**22 wrappers total.** P0 + P1 = 11 — the load-bearing ones. P2 can defer to a follow-up iter.

---

## 5. Proposed measurement framework

### 5.1 The bench shape

For each wrapper, one bench file at `benchmarks/per_target/parity/bench_<tool>_parity.py`:

```python
def run_parity_bench(*, fixture_path: Path, tool: str) -> ParityReport:
    """For one wrapper + one fixture, return:
       - findings_via_strix:   list of (rule_id, endpoint, severity)
       - findings_via_standalone: list of (rule_id, endpoint, severity)
       - missing_in_strix:     standalone ∖ strix
       - missing_in_standalone: strix ∖ standalone   (low priority — strix
                                 may add value via L1.5 enrichment)
       - delta_pp:             |missing_in_strix| / |findings_via_standalone| * 100
       - layer_attribution:    where the loss happens
    """
```

Layer attribution decomposes the loss:

```
findings_standalone → (subprocess.run)
                    → tool_output
                    → wrapper_parser
                    → raw_findings_pre_l15        ← measure here
                    → tracer.add_vulnerability_report
                    → L1.5 hook chain
                    → vulnerability_reports       ← measure here too
```

By snapshotting at both points we localize loss to **wrapper parsing** or **L1.5 over-suppression**.

### 5.2 Standalone-baseline definition

For each tool, define a canonical "find everything mode" recipe:

```yaml
# benchmarks/per_target/parity/baselines.yaml
nuclei:
  cmd: ["nuclei", "-u", "{target}", "-silent", "-jsonl",
        "-severity", "info,low,medium,high,critical",
        "-timeout", "300"]
  comment: "no -tags filter, all severities, generous timeout"

sqlmap:
  cmd: ["sqlmap", "-u", "{target}", "--batch", "--level=3", "--risk=2",
        "--smart", "--output-format=JSON"]
  comment: "level 3 risk 2 covers most production-realistic vectors"

dalfox:
  cmd: ["dalfox", "url", "{target}", "--silence", "--format=json",
        "--mining-dom", "--mining-dict"]
  comment: "DOM mining + dict mining are dalfox's default deep mode"
```

The baseline cmd is **pinned per tool-version**. When we bump a tool version we re-snapshot the baseline; otherwise it's frozen.

### 5.3 Fixtures

Three classes of fixture per wrapper:

| Fixture class | Source | Why |
|---|---|---|
| **Known-positives** | OWASP Benchmark (Q1.1) / Juice Shop / DVWA — vulnerable apps with labeled vulns | Lower bound on recall — every labeled vuln **must** be found by both strix and standalone |
| **Live-CVE corpus** | Vulhub (Q1.3) — 25 curated CVEs | Real-world signal, not synthetic |
| **Known-clean** | A static-HTML fixture with no vulnerabilities | Both strix and standalone must report 0 — catches false-positive regressions |

Fixtures live under `benchmarks/per_target/fixtures/parity/<tool>/` and are versioned with the bench (so a bench-fixture refresh is an explicit PR).

### 5.4 The parity report — three views

Each bench emits ONE report with three sections, one per consumer:

```
# nuclei parity report — fixture: juice-shop-snapshot-2026-05
# tool version: nuclei v3.4.1 (pinned in strix-sandbox image)

================================================================
Section A — L1 dashboard view (security-team audience, CLAUDE.md §1.5)
================================================================
Δ between strix's pre-L1.5 emissions and standalone nuclei:

| Severity | Standalone | Via strix (pre-L1.5) | Δ | Verdict |
|---|---|---|---|---|
| critical | 2 | 2 | 0 | GREEN |
| high | 8 | 8 | 0 | GREEN |
| medium | 7 | 5 | -2 | YELLOW |
| low | 4 | 2 | -2 | YELLOW |
| info | 2 | 2 | 0 | GREEN |
| **TOTAL** | **23** | **19** | **-4 (-17.4%)** | **YELLOW** |

Loss attribution (wrapper layer):
* 2 lost: template_id={exposed-config, exposed-git}
  → wrapper's -tags filter excludes "exposures" category
* 2 lost: template_id={security-headers, cache-control}
  → wrapper's -severity filter defaults to high+critical only

This is the L1-dashboard regression. The security team would see
4 fewer findings via strix vs. running nuclei standalone.

================================================================
Section B — L1.5 hook chain attribution
================================================================
Δ between strix pre-L1.5 and strix post-L1.5 emissions:

| Hook | Findings dropped | Reason | Audit log |
|---|---|---|---|
| pre_emission_fp_filter | 1 | "planted-decoy-shape" | run_summary.l15_dismissals[0] |
| corroborator_ledger | 0 | (no demotions) | — |
| post_emit_verifier | 0 | (all verified) | — |
| _maybe_merge_into_existing_finding | 2 | duplicate of #4 (CWE-200) | merged into #4.corroborated_by[] |

Net: 19 pre-L1.5 → 16 post-L1.5.
* The 2 merges are not losses (count drops, but information preserved
  via corroborated_by[]).
* The 1 FP drop is a real loss IF the planted-decoy shape false-positives
  on a real finding. Manual review of run_summary.l15_dismissals[0]
  required.

================================================================
Section C — L2 developer-facing view (non-security audience, CLAUDE.md §1.5)
================================================================

Of the 16 post-L1.5 findings:
* 8 surfaced into the prioritized chain narrative (chain_summary != null)
* 4 have file/line/author/fix_hint (bench_context complete)
* 2 have plain-English remediation (bench_explanation pass)
* 1 has compliance mapping (bench_patcher_correctness or compliance hook)

The L2-audience metrics are tracked in their own benches (per CLAUDE.md
§6) — Q3 only surfaces the per-wrapper L1 -> L1.5 -> L2 pipeline shape
so we can see whether L2's developer-facing output is bottlenecked by
L1 misses, L1.5 over-suppression, or L2 narrative gaps.

================================================================
Verdict — P0/P1/P2 (drives release-gate decision)
================================================================

P0: wrapper -tags filter is over-restrictive → blocks security-team
    dashboard. Fix path: expose `tags=None` invocation mode (4 lines).
P1: wrapper -severity default trims low/medium → consider opt-in
    `full_severity=True` flag for the standalone-equivalent mode.
P2: post_emit_verifier hook chain — 1 dismissal — manual audit needed.
```

### 5.5 Decision rule (codified — audience-aware)

The decision rule splits by audience per CLAUDE.md §1.5:

#### Security-team view (L1 dashboard, Section A above)

> * **Δ ≤ 0pp** on high+critical (every finding nuclei would surface, strix also surfaces): **GREEN**. The L1 dashboard is at parity.
> * **0pp < Δ ≤ 5pp** on high+critical: **YELLOW**. Open issue, document missing finding, schedule fix. The security team loses information but no critical signal.
> * **Δ > 5pp on high+critical** OR **any miss of a critical-severity finding**: **RED / P0**. Block strix release. The L1 dashboard is strictly worse than running the tool standalone, and the product value collapses (CLAUDE.md §1.5).
> * **Δ > 15pp on low/medium**: **YELLOW**. Lower priority but track.

#### Developer audience (L2 narrative, Section C above)

> * The L2-audience metrics live in their own benches (`bench_context`, `bench_explanation`, `bench_chains`, `bench_patcher_correctness`, `bench_severity`). Q3 does NOT gate on those numbers — that's Q1's job.
> * What Q3 does gate: **L2 cannot translate findings L1 didn't surface**. If Section A is RED, Section C metrics are moot until Section A is GREEN.

#### Surprise outcomes

> * **Δ < 0** (strix finds MORE than standalone): investigate but do not block. Most likely L2-orchestrated retry / multi-pass; could also be the L1.5 chain's `_maybe_merge_into_existing_finding` reducing dedup loss. Document the source.
> * **L1.5 drops a finding the standalone tool emitted as high/critical**: P0. The L1.5 chain exists to add context for L2, NOT to filter what the L1 audience sees. Severity demotions are allowed; outright drops on high/critical are not.

The threshold applies primarily to **high + critical** because info / low findings have too much noise for the threshold to be meaningful, and the L1 audience can tolerate noise at those tiers. Critical findings have zero tolerance — every miss blocks release.

### 5.6 Anti-overfit guards

Same as Q1 §6.4:

1. **Per-tool source-grep test**: the bench module must not contain wrapper-internal identifiers (e.g. `scan_nuclei_templates`) so a wrapper rename doesn't silently break the bench.
2. **Tool version pinning**: every bench run snapshots `<tool> --version` into the report. A version bump is a separate explicit PR.
3. **Fixture version pinning**: fixtures are committed to the repo; refresh requires a PR.
4. **Multi-trial median**: `bench_multi_trial.py` (already shipped in Q1.4) wraps the parity benches. Single-trial parity delta is noise for tools with concurrent randomness (sqlmap, dalfox).
5. **Per-layer ablation**: every parity report runs twice — once with `STRIX_L15_DISABLED=1`, once with the chain on. The delta between the two attributes the L1.5 contribution.

---

## 6. Iter sequence

| iter | scope | size |
|---|---|---|
| **Q3.1** | Parity-bench framework (`benchmarks/per_target/parity/bench_runner.py` + `baselines.yaml` + `ParityReport` dataclass + CLI) | 1 PR, ~500 LOC, ~30 tests |
| **Q3.2** | `bench_nuclei_parity.py` + fixture set + first run report | 1 PR, ~200 LOC + fixture, ~15 tests |
| **Q3.3** | `bench_sqlmap_parity.py` + fixture set | 1 PR, similar |
| **Q3.4** | `bench_dalfox_parity.py` + fixture set | 1 PR, similar |
| **Q3.5** | `bench_semgrep_parity.py` + fixture set | 1 PR, similar |
| **Q3.6** | `bench_trufflehog_parity.py` + fixture set | 1 PR, similar |
| **Q3.7** | `bench_ffuf_parity.py` + fixture set | 1 PR, similar |
| **Q3.8** | P0 wrapper-bug fixes from Q3.2-Q3.7 findings | N PRs, scoped per bug |
| **Q3.9** | Promote parity dashboard to CLAUDE.md §6 (alongside Q1 per-layer matrix) | docs PR |
| **Q3.10** | P1 wrappers (katana, subfinder, httpx, nmap, inql) | 5 PRs, condensed |
| **Q3.11** | P2 wrappers (dockle, checkdmarc, dnstwist, testssl, mobsfscan, hadolint, hydra, smuggler, schemathesis, feroxbuster, bbot) | 11 PRs, condensed — or one "P2 mega" PR |

**Hard gate before merging Q3.8+**: every P0 wrapper must have a parity report committed to `benchmarks/per_target/parity/reports/` so we have a baseline to regress against.

---

## 7. Expected outcomes (priors)

Based on inspection of the wrappers in §4:

### Likely-GREEN wrappers (Δ ≤ 5pp)

* **trufflehog** — wraps a single command (`trufflehog filesystem --json`) with no flag-surface trimming. The wrapper's primary work is JSON parsing, which is shape-stable. Predicted Δ ≈ 0pp.
* **dalfox** — wrapper calls `dalfox url --format=json` and parses the structured output. Flag surface is minimal. Predicted Δ ≈ 0-5pp.
* **httpx**, **subfinder** — discovery tools; the wrappers are thin shells. Predicted Δ ≈ 0pp.

### Likely-YELLOW wrappers (5-15pp)

* **nuclei** — the wrapper currently exposes `-tags` and `-severity` filters as kwargs. The minimal-catalog (iter-37.11) usage from the L2 lead defaults to a targeted subset, which is fine for the L2 use case but means parity vs. standalone "find everything" needs an explicit `tags=None, severity=None` invocation path. Predicted Δ ≈ 10-15pp until we add a `scan_nuclei_templates_full()` companion.
* **sqlmap** — wrapper sets `--batch --level=2 --risk=1` by default (LLM-cost-driven). Standalone "find everything" is `--level=5 --risk=3`. Predicted Δ ≈ 15-30pp; we may need a slow-mode variant.

### Likely-RED wrappers (Δ > 15pp)

* **semgrep** (taint_analysis) — the wrapper currently runs a curated ruleset, not `--config auto` (which includes Semgrep Registry's full rule set). Predicted Δ ≈ 20-40pp. Fix path: opt-in `full_rules=True` flag.
* **mobsfscan**, **schemathesis** — iter-37.4 wrappers; we haven't yet validated they expose the full tool surface.

These priors are deliberately documented so the bench results either confirm them (predictable issues we know how to fix) or surprise us (which would be more interesting).

---

## 8. Connection to Q1, Q2, Q4 — audience-aware

The Q3 parity bench is the **load-bearing measurement for the security-team-facing artifact** (CLAUDE.md §1.5). Every other Q-track depends on it:

* **Q1** measures strix vs. competitors externally on the developer-facing artifact (Youden index, lesson completion, KEV hit rate). Q3 explains *why* strix is at/below the Q1 numbers by attributing loss to specific wrappers. Q1 is the L2-audience scorecard; Q3 is the L1-audience scorecard. Both ship together.
* **Q2** reduces tokens but **must not reduce findings the L1 audience sees**. Q3's per-wrapper baseline is the regression gate. The `<1pp regression gate` Q2.6 mentions is implemented by re-running Q3.2-Q3.7 parity benches with the Q2-stratified compactor on vs. off. If Section A (the L1 dashboard) regresses by >0pp on high+critical, the Q2 PR is rejected even if it improves Q1's L2-facing numbers.
* **Q4** parallelizes the lead's tool dispatch. Same regression gate as Q2 — parallelism changes the per-tool recall via race conditions / port-reuse / shared state, all of which only Q3 catches.

Q3 is the **causal-attribution layer** that makes Q1/Q2/Q4 iter PRs auditable: every regression's root cause is one of a small set of named wrappers. Without Q3, every PR that ships into the L1-audience path is shipping on a guess.

### 8.1 The two-scorecard release gate

Going forward, **every L1 / L1.5 / L2 / Q2 / Q4 iter PR carries two scorecards** in its body:

1. **Q3 parity scorecard** (Sections A+B of the parity report) — does this PR change the L1-dashboard / L1.5-attribution numbers? Gates the security-team-facing artifact.
2. **Q1 per-layer-recall scorecard** (Youden / detection_rate / KEV hit-rate, per CLAUDE.md §6) — does this PR change the developer-facing artifact?

A PR that regresses (1) but improves (2) is rejected without explicit justification. A PR that improves (1) but regresses (2) is allowed but flagged for L2-iter follow-up.

---

## 9. Open questions for review

1. **Threshold tuning** — is 5pp the right GREEN bar? Some tools (sqlmap, dalfox) have legitimate run-to-run variance > 5pp on the same fixture due to concurrent payload mutation. The multi-trial median should smooth this, but we may need per-tool thresholds.
2. **Parity dashboard frequency** — run on every PR (slow but bisectable) or nightly cron (fast PRs, regression-finds-via-cron-page)?
3. **Fixture lifetime** — Juice Shop / VAMPI / Vulhub fixtures get refreshed. Do we lock to a specific snapshot per release, or chase head? Locking is safer; chasing exercises corpus-freshness too. Suggest: lock per-release, separate cron pager (Vulhub already has one via Q1.3) catches the chase-head regressions.
4. **L1.5-FP-filter calibration** — if Q3 reveals the FP filter is dropping real findings on multiple wrappers, that's a deeper bug than per-wrapper. Should the FP-filter calibration be a separate iter under Q3 or its own QX?

---

## 10. Success criterion

> By the end of Q3.7, the strix repo has a per-wrapper parity baseline committed for all 6 P0 OSS detection wrappers. Every subsequent PR that touches L1 / L1.5 / Q2-compaction-related / Q4-parallelism code re-runs the parity benches in CI and **any wrapper showing Δ > 0pp on critical or Δ > 5pp on high vs. its committed baseline blocks the PR**, regardless of L2-audience metric improvements.

This codifies the CLAUDE.md §1.5 product gate: the security-team-facing artifact is non-negotiable. Without Q3, every PR is a guess about whether we just lost detection recall on the L1-dashboard. With it, every PR is a measurable claim about whether we did, and the security-team audience gets a strictly-monotonic dashboard quality (it never silently regresses).

The L2-facing developer-action-list metrics (`bench_context`, `bench_explanation`, `bench_patcher_correctness`, etc.) are tracked separately under Q1's per-layer recall matrix and have their own iter sequences. Q3 is the load-bearing gate for the L1 audience; Q1 is the load-bearing gate for the L2 audience. Both must be green for a release.
