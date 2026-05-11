# NodeGoat — public SCA benchmark

[OWASP NodeGoat](https://github.com/OWASP/NodeGoat) is a deliberately
vulnerable Node.js / Express demo app maintained by OWASP. It is one
of the most widely-cited public benchmarks for npm SCA tools because:

1. It is a **real-shaped** Express application — not a synthetic
   lockfile of hand-picked CVEs.
2. Snyk uses it as a reference target in its product demos and
   publishes detection numbers against it.
3. The full transitive closure is ~1,500 packages — exercises real
   reachability questions, not just "does the matcher see the
   pinned-vuln line".

## What we measure

Direct-dependency CVE recall, scored by package-name presence in
`category=vulnerable_dependency` findings. See `expected.yaml` for
the 8 advisories we expect strix to surface (5 high-confidence
`must_find=true`, 3 lower-confidence).

We deliberately **do not** score on transitive vulns. The transitive
closure has ~30 advisories per Snyk's published number; that's a
useful headline figure but a noisy one (each finding's "match" is
ambiguous when a transitive shows up under multiple paths). The
direct-dep list isolates "did we catch the developer-introduced
vulnerable dep" — the single signal a developer actually acts on.

## Setup

```bash
bash setup.sh            # clones NodeGoat at pinned commit c5cb68a → ./src
```

The pinned commit is from 2023-06; NodeGoat has been stable since.
`setup.sh` is idempotent.

## Run

```bash
# from repo root
python benchmarks/public/run_sca_benchmark.py \
  benchmarks/public/fixtures/sca/nodegoat \
  -o benchmarks/public/fixtures/sca/nodegoat/baseline/run_$(date +%Y%m%d_%H%M).json
```

Takes ~1.5 s on an M2 laptop.

## Threat-intel pre-condition

`scan_sca_lockfiles` reads from the local threat-intel SQLite cache
(`~/.cache/strix/threat_intel.db` by default). With an **empty
cache**, the runner reports a **FLOOR baseline** — `vulnerable_
dependency` recall = 0% because there's no CVE data to match
against. Only the heuristic categories (`malicious_dependency` for
typosquats / install-scripts / known-malicious, and
`license_violation`) will fire.

To get the **CEILING** — comparable to Snyk's published numbers —
seed the cache first:

```bash
export GITHUB_TOKEN=<your-pat>   # GHSA requires auth (60 req/h unauth)
python -m strix.threat_intel.refresh \
  --only ghsa,popular,ossf-malicious \
  --ghsa-days 365 \
  --popular-top-n 1000
```

GHSA refresh takes ~10–15 min for a 365-day window. Popular-packages
+ OSSF malicious are a couple of minutes each. After seeding, re-run
the benchmark — `recall_must_find` should land at ≥ 80%
(individual CVE coverage depends on the GHSA window).

> **Known issue (2026-05-11):** the popular-packages npm parser
> currently crashes on some response shapes
> (`'list' object has no attribute 'strip'` at
> `strix/threat_intel/feeds/popular_packages.py:112`). Track:
> see spawned task. The benchmark will still produce a CEILING run
> if GHSA is seeded — popular-packages only affects the typosquat
> false-positive count.

## Comparing to Snyk

Snyk publishes detection numbers on NodeGoat in its product
demos / blog posts. **As of mid-2025**:

| Tool                     | Direct-dep vulns surfaced | Tree vulns surfaced |
|--------------------------|---------------------------|---------------------|
| Snyk `snyk test`         | ~12–15                    | ~30 (varies)        |
| GitHub Dependabot        | ~10–12                    | ~25                 |
| npm audit                | ~8–10                     | ~22                 |
| strix (CEILING, seeded)  | _TBD — first run pending_ | _TBD_               |
| strix (FLOOR, empty cache) | 0                       | 0                   |

The strix CEILING row will land in a follow-up commit once the
GHSA seed completes against an authenticated token. Until then the
benchmark serves as a regression-detection harness: a change that
moves the FLOOR meaningfully (more heuristic noise, fewer
malicious-dep findings, license-family coverage drop) is a
regression we want to catch.

## What's in `baseline/`

One JSON per run. Filename convention:
`<floor|ceiling>_<YYYYMMDD_HHMM>_<note>.json`. The `cache_state`
block in each baseline records which feeds were seeded at run time
— compare apples-to-apples.

Current files:

- `floor_20260511_empty_cache.json` — first FLOOR baseline.
  `vulnerable_dependency=0`, `malicious_dependency=322` (mostly
  typosquat false positives — popular-package corpus missing),
  `license_violation=307`. 1.3 s runtime.

## Why a separate harness from `benchmarks/per_target/`

`per_target/runner.py` invokes the full strix CLI as a subprocess,
parses markdown findings, and is set up for agentic-scan benchmarks
(precision/recall on a full LLM-driven scan). For pure SCA, that's
unnecessary expense — `scan_sca_lockfiles` is a deterministic
direct-tool call that returns structured findings in ~1 s. The
runner here invokes it directly and emits a comparable number to
Snyk's `snyk test` (also direct-tool, no agent).

The per-target harness is the right tool for DAST / agent-driven
benchmarks. This harness is the right tool for SCA / SAST / IaC
benchmarks where deterministic direct-tool invocation is the
honest comparison surface.
