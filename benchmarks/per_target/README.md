# Per-target-type benchmarks

A baseline benchmark suite for measuring Strix's coverage and quality on
each target type (code, web app, domain, IP). Designed to be re-run after
every roadmap milestone — drift in precision/recall tells us whether a
change actually improved coverage or just rearranged it.

This complements (does **not** replace) the upstream
[usestrix/benchmarks](https://github.com/usestrix/benchmarks) suite (XBEN,
web CTF). XBEN measures black-box web exploitation. This suite measures
**per-target-type comprehensiveness** — including categories XBEN doesn't
cover (white-box, domain recon, network services).

---

## Goals

1. **Baseline current behavior.** Before any roadmap §7 / §8 changes land, capture today's precision, recall, time, and cost on each fixture. Without a baseline, "we improved coverage" is unfalsifiable.
2. **Regression-detect new gaps.** Each fixture has an `expected.yaml` manifest of planted vulnerabilities. A finding-that-disappears between runs is a regression.
3. **Compare scan modes / models.** Same fixture, different `--scan-mode` or `STRIX_LLM`, scored against the same manifest.
4. **Scope per target type.** Fixtures are organized so we can answer "did our domain-target work in §7.3 actually improve domain coverage?" — not "did the average across mixed targets improve?".

---

## Layout

```
benchmarks/per_target/
├── README.md                    this file
├── runner.py                    runs strix against a fixture, scores against expected.yaml
├── scoring.py                   precision / recall / coverage helpers
├── fixtures/
│   ├── code/
│   │   └── flask-vuln/          minimal Flask app with 10 planted vulnerabilities
│   ├── web/
│   │   └── juiceshop/           OWASP Juice Shop (docker-compose)
│   ├── ip/
│   │   └── vulnerable-services/ Redis + nginx + vsftpd in docker-compose
│   └── domain/
│       └── README.md            methodology — domain fixtures need a real test domain
└── baseline/
    ├── README.md                how to interpret baseline files
    └── *.json                   baseline result files (one per fixture × scan_mode × model)
```

---

## How to run

```bash
# 1. Install runner deps
pip install pyyaml

# 2. Make sure strix is installed and STRIX_LLM is set
which strix && echo "STRIX_LLM=$STRIX_LLM"

# 3. Run a fixture
python benchmarks/per_target/runner.py benchmarks/per_target/fixtures/code/flask-vuln

# 4. With a specific scan mode
python benchmarks/per_target/runner.py benchmarks/per_target/fixtures/code/flask-vuln --scan-mode quick

# 5. Save the result as a baseline
python benchmarks/per_target/runner.py \
    benchmarks/per_target/fixtures/code/flask-vuln \
    --scan-mode standard \
    --output benchmarks/per_target/baseline/flask-vuln_standard_$(date +%Y%m%d).json
```

For docker-based fixtures (`web/juiceshop`, `ip/vulnerable-services`), the
runner will `docker compose up -d` the fixture, wait for health, run the
scan, then `docker compose down`. Make sure Docker is available.

For the `domain` fixture, see [fixtures/domain/README.md](fixtures/domain/README.md) — domain testing requires a real test domain you control.

### L2-specific: Juice Shop full challenge.json bench

`runner.py` scores against a curated 9 must-find list. For L2 we want
to measure **chain reasoning + reasoning depth**, not L1-friendly OSS
recall. `bench_l2_juiceshop_full.py` scores against Juice Shop's
internal `/api/Challenges/` endpoint (109 challenges, 6 difficulty
tiers, 17 categories) — the SUT auto-marks a challenge as solved when
its exploit pattern fires, so the score is purely a function of what
L2 naturally tripped while probing.

```bash
# Standard L2 scan against juice-shop, score against all 109 challenges
python -m benchmarks.per_target.bench_l2_juiceshop_full --scan-mode standard

# Deep mode (more LLM iterations, costlier)
python -m benchmarks.per_target.bench_l2_juiceshop_full --scan-mode deep

# Compare against a prior run
python -m benchmarks.per_target.bench_l2_juiceshop_full --scan-mode standard \
    --compare-to benchmarks/per_target/baseline/l2_juiceshop_full_20260524_154933_standard.json

# Smoke-test the scoring path without paying LLM cost (manual scan in
# another shell or none at all)
python -m benchmarks.per_target.bench_l2_juiceshop_full --skip-strix --keep-up
```

Output (markdown + JSON in `baseline/`) breaks down:
- solved per difficulty tier (1★–6★)
- solved per category (XSS, Injection, Broken Auth, ...)
- weighted score (Σ difficulty × solved / Σ difficulty × total) — rewards harder tiers
- LLM cost / tokens / agents / tools used
- cost per challenge solved (the L2-economics headline)
- vs prior-run deltas (`--compare-to`)

Why this metric beats the 9-must_find list:

| Aspect | 9-must_find scoring | full challenge.json scoring |
|---|---|---|
| Coverage | 9 hand-picked vulns | 109 with rich tier/category breakdown |
| L1 vs L2 separation | none — L1 already nails most | Tier 1-2 = L1 floor, Tier 4-6 = L2 reasoning |
| Bias | curator picked easy DAST wins | SUT is source of truth, no human curation |
| Comparability | drift if we curate differently | stable across model/scan-mode changes |
| Maps to L2+ readiness | no | yes — Tier 5-6 gaps are exactly where L2+ hypothesis explorer + chain reasoning would land |

---

## Scoring

For each scan, the runner emits:

| Metric | Meaning |
|---|---|
| `expected_count` | Findings the manifest says should be detected (`must_find: true`). |
| `found_count` | Total findings Strix wrote. |
| `matched_count` | Findings that match an expected entry (by category + location). |
| `precision` | `matched_count / found_count` — fraction of findings that were real. |
| `recall` | `matched_count / expected_count` — fraction of planted bugs that were caught. |
| `missed` | List of expected IDs Strix did not find. |
| `false_positives` | List of found findings that didn't match any expected entry. May include real bugs we didn't plant — review before treating as noise. |
| `duration_seconds` | Wall-clock from invocation to exit. |
| `cost_usd` | Sum of `cost` from `events.jsonl` (or `null` if not available). |
| `iterations` | Total agent iterations. |

A "match" is conservative: same category (or CWE), same file (for code targets)
or same endpoint (for web targets), and (for code) line within ±20 of expected.
Strix can describe a finding many ways; the matcher only counts a finding if
it identifies the same root issue at the same location.

---

## Interpreting results

- **Recall < 0.7 on any fixture** → Strix isn't finding things we know are there. Check the `missed` list to see whether it's a category gap (entire class missing) or a location-fuzz issue (found at line N when expected at N+30).
- **Precision < 0.4** → Strix is generating noise. Check `false_positives` — are they real bugs we didn't plant, or hallucinations? Real-bug FPs are good signal that the fixture's manifest is incomplete; hallucinations are a quality problem.
- **Cost increases > 2× recall increase** → A roadmap change is paying too much for marginal coverage. Reconsider.

---

## Adding a new fixture

A fixture is a directory with at least:

- `expected.yaml` — manifest of planted bugs (see schema in `scoring.py`).
- `README.md` — what's planted and why.
- For code targets: the source files.
- For docker-based targets: `docker-compose.yml`, plus optionally a `setup.sh` for one-time data seeding.

The runner detects the target type from `expected.yaml` (`target_type:` field).
Supported types: `local_code`, `repository`, `web_application`, `ip_address`,
`domain`. The runner spins up dockerized fixtures automatically.

For a new fixture to be useful as a baseline, it should:

1. Cover a class of vulnerabilities that's specifically tested by Strix's expected behaviour (e.g. SSRF for web app, supply-chain CVE for code).
2. Be deterministic — running it twice should produce the same `expected_count`.
3. Be small enough that scans complete within the default budget on `quick` mode.

---

## Limitations

- This suite measures **what Strix finds**, not **whether it found the right thing for the right reason**. A finding that says "SQL injection" at the right file:line with a wrong PoC still counts as matched. Quality of explanation / PoC has to be reviewed manually until §12 ships `verification_status`.
- The matcher is structural (category + location). A subtle finding strix describes correctly but at a different line — e.g. it flagged the route handler instead of the vulnerable line — is currently a miss. The matcher window (±20 lines) is generous to compensate.
- Docker-based fixtures depend on the image staying available. If `bkimminich/juice-shop` updates its vuln set, baselines drift.
- No `domain` fixture ships runnable; see the methodology in `fixtures/domain/README.md`.
