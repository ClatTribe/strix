# Benchmark suite strategy — beyond Juice-Shop binary scoring

**Status:** proposal (this PR opens the design conversation).
**Date:** 2026-05-27.
**Author:** Q1 thread, iter-37 follow-on.

## Problem statement

The L2 bench harness (`benchmarks/per_target/bench_l2_juiceshop_full.py`)
polls Juice Shop's `/api/Challenges` endpoint and scores per challenge
on **binary completion** (`solved: true` ⇔ the specific exploit sequence
fired, otherwise `solved: false`). This has three consequences:

1. **Finding ≠ exploit completion.** Strix can correctly identify the
   SQLi at `/rest/products/search?q=` (and emit a high-confidence
   verified finding for it), but unless the lead's follow-up call
   actually uses the SQLi to read the `admin` user's row, the
   `unionSqlInjectionChallenge` stays at `solved: false`. The bench
   reports 0/1 for what is actually a 1/1 detection outcome.

2. **Single-fixture overfit risk.** Optimising against one bench
   ([Juice Shop](https://github.com/juice-shop/juice-shop) v17.2.0)
   pushes the codebase toward Juice-Shop-specific shapes. The
   anti-overfit guards in
   `benchmarks/per_target/bench_*.py` (source-grep tests forbidding
   `juice-shop` / `bkimminich` / `vampi` / `erev0s` in
   non-fixture code) catch the worst cases but not subtler bias —
   e.g. tuning a heuristic for `juice-shop`-style 401 → 200 transitions
   that don't generalise.

3. **No per-layer attribution.** When L2 recall drops, we can't tell
   whether L1 missed the finding entirely, L1.5 dismissed it as an
   FP, or L2 found it but failed to exploit-chain it. The `bench_l1_
   only.py` harness exists but isn't measured against a known-good
   external baseline, so its absolute number is ambiguous.

The current state (`docs/benchmark.md`) lists per-fixture must-find
targets + top-competitor recall numbers but treats those competitor
numbers as folklore. We haven't measured strix against a benchmark
**designed by a neutral party for tool comparison**.

## What "best in class" actually means at each layer

Different layers have different ceilings + different benchmarks
that exist to measure them:

| Layer | What it does | Measurement question | Closest neutral benchmark |
|---|---|---|---|
| L0 | Signature corpus (nuclei templates, semgrep rules, sqlmap payloads, KEV) | Coverage of known CVEs / CWE classes | **Vulhub** (300+ CVE-replication containers); **NIST CVE-Bench** |
| L1 | Deterministic OSS detection (sqlmap, dalfox, nuclei, semgrep, trivy, ...) | Recall vs OSS-tool ceiling; FP rate | **OWASP Benchmark Project v1.2** (~3K test cases, per-CWE TP/FP/TN/FN); **NIST SARD / Juliet** for SAST |
| L1.5 | FP filter / surface_priority / corroborator / threat_intel enrichment | Does the chain *improve* L1's output? | **OWASP Benchmark** before/after L1.5 hooks (delta = L1.5 value) |
| L2 | LLM-driven chain exploitation + business logic | Multi-step exploit completion rate | **Juice Shop** (current); **WebGoat lessons**; **HTB / THM machines** (manual flag check) |
| L3 | Portfolio-level / cross-scan dedup | Cross-target correlation rate | Not yet built; no public bench either |

## Survey of available benchmarks

### OWASP Benchmark Project v1.2 (purpose-built for tool eval)

- **~3000 test cases**, half intentionally vulnerable, half intentionally safe (each pair tests the SAST tool's TP + FP independently)
- Categories: `cmdi`, `crypto`, `hash`, `ldapi`, `pathtraver`, `securecookie`, `sqli`, `trustbound`, `weakrand`, `xpathi`, `xss`
- **Per-CWE scoring**: tools report `<test_id, finding_or_no>`; the bench scores precision + recall + F1 + Youden index per CWE
- **Published competitor scores**: Veracode 51%, Checkmarx 47%, Fortify 35%, SonarQube 6% (Youden index, 2024)
- **Strix fit**: best L1 measurement target. Could ship as `bench_owasp_benchmark.py` reading `expected.yaml` from BenchmarkJava/expectedresults-1.2.csv

### NIST SARD / Juliet Test Suite (SAST ground truth)

- **~80K test cases** across C, C++, Java, C# with hand-labelled CWE positives + safe variants
- **Strix fit**: best SAST-only measurement (`scan_sast` / `scan_sca_lockfiles` / `mobsfscan`). Heavier — would need a separate `bench_nist_sard.py` and a corpus-download step

### Vulhub CVE labs (CVE replication)

- **300+ docker-compose fixtures** for specific CVEs (CVE-2017-5638 Struts, CVE-2021-44228 Log4j, ...)
- **Strix fit**: measures **L0/L1 CVE corpus freshness** — does `nuclei -t cves/` actually fire on the vulnerable version? Catches stale-template drift
- Could ship as `bench_vulhub_subset.py` running ~20-30 representative CVE labs

### CVE-Bench (academic, 2024)

- **Recent CVEs (2023-2024) with vulnerable-by-design containers**
- Specifically tests whether security tools are **current** on the latest CVE corpus
- **Strix fit**: complement to Vulhub — tests the freshness end of the spectrum

### OWASP WebGoat (lesson-based + exploitable)

- 30+ lessons; each lesson has a backend solution-checker
- **Two scoring modes**: vulnerability-found (DAST mode) OR lesson-completed (exploit mode)
- **Strix fit**: bridges the L1/L2 gap. Same bench can score on detection rate OR exploit rate; the difference is exactly the L2 chain-execution measurement

### DVWA / NodeGoat / Vulnado

- Smaller smoke-test fixtures
- **Strix fit**: regression fixtures, not headline benchmarks. Already partially used as bench_l1_only inputs

### HackTheBox / TryHackMe machines

- Real CTF-style chains; no automated scoring (flag-text-match only)
- **Strix fit**: out-of-band testing for L2 chain reasoning. Can't be a bench harness because no neutral scorer exists, but useful for qualitative
  capability check

### XBOW / proprietary benchmarks

- XBOW's internal eval set (not public)
- Replicate the published methodology where described, but treat
  results as folklore until we can run our own measurement

## Proposed bench-suite mix by layer

The proposal is to **stop treating L2 Juice Shop as the headline number** and instead publish a per-layer recall matrix:

| Bench harness | Measures | Cadence | Headline number |
|---|---|---|---|
| `bench_owasp_benchmark.py` (NEW) | L1 detection precision + recall + F1 per CWE | Every PR touching L1 / wrappers | F1 per CWE bucket; expect parity with the underlying OSS tool's standalone score |
| `bench_l1_parity.py` (NEW — Q3) | Strix-L1 finding count vs same OSS tool standalone | Every PR touching prepass / executor | per-tool delta — should be 0 (parity) |
| `bench_vulhub_subset.py` (NEW) | L0 CVE-template freshness | Weekly cron | hit-rate on 25 curated CVE labs |
| `bench_l1_only.py` (existing) | End-to-end L1 detection on strix's fixture set | Every PR | aggregate finding count, FP rate |
| `bench_webgoat_dual.py` (NEW) | L1 detection + L2 lesson-completion on the same fixture | Per-iter for L2 changes | (detection_rate, lesson_completion_rate) tuple — gap measures L2 value |
| `bench_l2_juiceshop_full.py` (existing) | L2 chain-exploit completion | Per-iter for L2 changes | challenge-completion rate (current Juice Shop metric) |

The shift: **OWASP Benchmark v1.2 becomes the headline L1 number** (because it has a neutral published-competitor table). Juice Shop stays for L2 (because nothing else measures multi-step chain exploitation as well). The two together let us attribute regressions to a specific layer.

## Anti-overfit + comparability guards

Each new bench harness must include:

1. **Source-grep test**: forbid SUT-specific identifiers (`OWASP_BENCHMARK`, `WebGoat`, `Vulhub`, fixture IDs) in `strix/` source. Catches the case where a heuristic tunes to one fixture's response shape.

2. **Multi-fixture rotation**: each bench runs across ≥3 fixtures of the same shape (e.g. OWASP Benchmark has 11 CWE categories — score per-category + aggregate). Catches single-shape overfit.

3. **Per-layer ablation**: each headline number is reported with two
   ablations:
   - With L1.5 hooks disabled (`STRIX_L15_DISABLED=1`)
   - With L2 LLM disabled (`STRIX_L2_DISABLED=1`)
   The deltas attribute value to each layer cleanly.

4. **Median + p10/p90 over N=5 trials** (per iter-36 candidate): single-trial bench numbers are noise. The harness reports the 5-trial median; per-iter PRs must show *both* mean and p10 not regressing.

5. **Published-competitor citation**: every headline number is reported with the latest published score for a named competitor on the same fixture (Burp Pro, Veracode, Semgrep, etc.). Forces honest comparison.

## Acceptance criteria

After this proposal ships (4 iter sequence below), the team should be
able to answer:

| Question | Today | After |
|---|---|---|
| "How does strix's L1 SQLi recall compare to Veracode's?" | Folklore / handwave | Number from OWASP Benchmark v1.2 cmdi/sqli buckets |
| "Did iter-X regress L1 coverage on CVE-2017-5638?" | Manual one-off run | bench_vulhub_subset.py PR-blocking signal |
| "Is the L1.5 chain (FP filter + surface_priority + corroborator) actually adding value, or is L1 doing the work?" | No data | OWASP Benchmark delta with hooks on/off |
| "How much of the L2 Juice Shop gap is detection vs exploit-chain execution?" | Couldn't separate them | WebGoat dual mode — detection_rate − completion_rate = L2 chain gap |
| "Are we current on latest CVEs?" | Periodic manual checks | Vulhub cron + alert on regression |

## Iter sequence

| iter | scope | size |
|---|---|---|
| **iter-Q1.1** | Add OWASP Benchmark v1.2 fixture: download script, fixture pinning, expected.csv loader, `bench_owasp_benchmark.py` harness scoring per-CWE TP/FP/TN/FN + F1 + Youden index. Headline competitor table cited. | 1 PR, ~500 LOC, ~30 tests |
| **iter-Q1.2** | Add WebGoat dual-mode fixture + harness. Two columns: detection_rate (DAST scan of vulnerable lessons) + completion_rate (lesson-checker poll). | 1 PR, ~400 LOC |
| **iter-Q1.3** | Add Vulhub subset (25 curated recent + high-EPSS CVEs): one docker-compose per CVE, `bench_vulhub_subset.py` runs nuclei against each, expects positive hit. Weekly cron. | 1 PR + ops setup |
| **iter-Q1.4** | Per-bench ablation harness (L1.5/L2-disabled env flags) + multi-trial-median reporter. Update existing bench harnesses to emit median + p10/p90. | 1 PR, refactor |
| **iter-Q1.5** | docs/benchmark.md rewritten as the per-layer recall matrix. Each headline number cites competitor + multi-trial median + published source. | 1 PR, docs |

Total scope: 5 PRs, ~2000 LOC, 2-3 weeks of focused work.

## Risks + mitigations

- **OWASP Benchmark is Java-shaped**: it's designed for SAST tools scanning the BenchmarkJava codebase. Strix's L1 doesn't ship a Java SAST natively. We'd need to wire semgrep with the Java rules pack OR (lighter) use only the categories where strix has existing detection (cmdi via nuclei templates, pathtraver via nuclei, sqli via sqlmap, xss via dalfox, weakrand via secrets/semgrep). The remaining 4 categories report 0 with a documented gap.

- **CVE labs need network egress to vuln-version registries**: Vulhub labs sometimes need to pull EOL container images. Mitigate by pinning images + caching layers in the bench harness image.

- **Cost**: WebGoat + Vulhub each take 5-15 min per run. 5-trial × 5 fixtures = 2-6 hr per PR if run synchronously. Mitigate by parallel benches in CI + scheduling only OWASP Benchmark + L1-only on every PR; WebGoat + Vulhub on iter-major-version-bump.

- **Maintenance**: external benchmarks drift (OWASP releases v1.3, WebGoat refactors). Mitigate via pinned fixture versions + a quarterly bench-suite update iter.

## Decision rule going forward

Add to CLAUDE.md §6 (bench framework):

> **Every new L1/L1.5 iter PR must run `bench_owasp_benchmark.py` and report the delta on the affected CWE categories.** Every new L2 iter PR must run both `bench_l2_juiceshop_full.py` AND `bench_webgoat_dual.py`, with the detection_rate − completion_rate gap reported. PR descriptions must cite the relevant external competitor's score for the same fixture.

> A PR that improves L2 numbers but regresses L1 numbers is REJECTED unless the regression is explicitly justified.

This pins strix to a **multi-benchmark, layer-attributed, competitor-cited measurement framework** — closing the gap between "Juice Shop says we did poorly" and "here's exactly which layer fell short, by how much, and how that compares to industry."

## See also

- `docs/benchmark.md` — current per-fixture state + must-find counts
- `docs/metrics.md` §2 — per-layer measurement targets
- `docs/metrics-roadmap.md` — iter-31 bench infrastructure
- `benchmarks/per_target/bench_l2_juiceshop_full.py` — current L2 harness
- OWASP Benchmark Project: <https://owasp.org/www-project-benchmark/>
- NIST SARD: <https://samate.nist.gov/SARD/>
- Vulhub: <https://github.com/vulhub/vulhub>
- WebGoat: <https://github.com/WebGoat/WebGoat>
