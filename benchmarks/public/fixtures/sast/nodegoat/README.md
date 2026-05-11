# NodeGoat — public SAST benchmark

[OWASP NodeGoat](https://github.com/OWASP/NodeGoat) — re-used as a
SAST target (the same clone backs the SCA fixture at
`../../sca/nodegoat/`). NodeGoat embeds documented OWASP Top 10
bugs across `app/routes/*`, `server.js`, and `app/views/*`, so it
exercises real SAST patterns rather than synthetic test cases.

## What we measure

Recall on a hand-picked set of 5 well-known NodeGoat SAST bugs.
Match criterion: **(category, file)** — line number is
informational only because the same logical bug can flow through
multiple Semgrep rules at slightly different lines.

| ID | Bug | File | Severity | must_find |
|---|---|---|---|---|
| nodegoat-sast-eval-injection | eval() with user input | `app/routes/contributions.js` | high | ✅ |
| nodegoat-sast-open-redirect | unvalidated res.redirect | `app/routes/index.js` | medium | ✅ |
| nodegoat-sast-helmet-missing | no helmet() middleware | `server.js` | medium | ✅ |
| nodegoat-sast-insecure-cookie | session cookie missing secure/httpOnly | `server.js` | medium | ✅ |
| nodegoat-sast-plaintext-http | plaintext HTTP link in tutorial pages | `app/views/tutorial/a2.html` | low | ❌ |

## Setup

The clone is shared with the SCA fixture. If you haven't run that
first:

```bash
bash ../../sca/nodegoat/setup.sh   # idempotent
```

Install Semgrep — strix's SAST tool returns `engine_available:
false` and 0 findings without it:

```bash
pip install semgrep
```

## Run

```bash
python benchmarks/public/run_sast_benchmark.py \
  benchmarks/public/fixtures/sast/nodegoat \
  -o benchmarks/public/fixtures/sast/nodegoat/baseline/run_$(date +%Y%m%d_%H%M).json
```

Takes ~6–7 s on an M2 laptop (Semgrep over 75 files).

## FLOOR vs CEILING

- **FLOOR** (no Semgrep): `engine_available: false`, 0 findings.
  Captured as a regression-detection floor — if a future change
  silently breaks the Semgrep wrapper, this run shifts from
  CEILING back to FLOOR.
- **CEILING** (Semgrep installed): real findings, scored against
  `expected.yaml`.

The first captured baseline is a CEILING run (Semgrep 1.162.0):

| Metric | Value |
|---|---|
| recall_must_find | 100% (4/4) |
| recall_all | 100% (5/5) |
| total findings | 23 |
| duration | 6.5 s |
| files scanned | 75 |
| rule packs | strix's `vibe_coded` (39 rules) + `p/owasp-top-ten` |

## Comparing to commercial SAST

| Tool | NodeGoat A1 (eval) | A10 (open redirect) | A5 (misconfig) | Published per-fixture number? |
|---|---|---|---|---|
| Snyk Code | ✅ | ✅ | partial | No per-fixture; OWASP Top 10 claim only |
| GitHub CodeQL | ✅ | ✅ | partial | No per-fixture |
| SonarQube | ✅ | ✅ | partial | No per-fixture |
| Semgrep `p/owasp-top-ten` | ✅ | ✅ | ✅ | Per-rule pass/fail in their CI; aggregate ~OWASP Top 10 |
| **strix** | ✅ | ✅ | ✅ | This benchmark (recall_must_find=100%) |

Commercial SAST vendors don't publish per-fixture recall numbers —
their marketing leans on "we catch the OWASP Top 10" claims. This
benchmark is the strix equivalent of that claim: explicit per-bug
recall on a public fixture, reproducible from this repo.

For the **academic** comparable number (F-score against
ground-truth set of 2,740 cases), the next benchmark to wire is
**OWASP Benchmark v1.2** (Java). Snyk Code / Semgrep / Checkmarx /
Veracode all publish official F-scores against it.
