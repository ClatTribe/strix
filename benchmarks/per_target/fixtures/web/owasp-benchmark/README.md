# OWASP Benchmark Project v1.2 — strix bench fixture

## What this fixture is

[OWASP Benchmark Project v1.2](https://owasp.org/www-project-benchmark/) is a ~3000-test-case Java web application designed for neutral AppSec tool comparison. Each test case is a JSP file that either contains a real vulnerability in a specific CWE class OR is a safe-variant of the same shape. Tools run against the deployed app; findings are scored per-CWE for TP/FP/TN/FN → precision / recall / F1 / Youden index.

This fixture deploys BenchmarkJava as a local docker container so the strix bench harness (`bench_owasp_benchmark.py`) can measure strix's L1 detection against the published competitor leaderboard (Veracode 51%, Checkmarx 47%, Fortify 35%, SonarQube 6%, ZAP 13%).

## Why this matters (vs Juice Shop)

| Aspect | Juice Shop | OWASP Benchmark v1.2 |
|---|---|---|
| Scoring | Binary per challenge (exploit-completion) | Per-test-case TP/FP (detection-only) |
| Ground truth shape | 109 hand-coded challenges | ~3000 systematic test cases per CWE class |
| Published competitor scores | None | Veracode, Checkmarx, Fortify, SonarQube, ZAP |
| What it measures | L2 chain reasoning + exploit execution | L1 detection precision + recall |

Per `docs/proposals/2026-05-27-benchmark-suite-strategy.md`, this is the **L1 headline benchmark** going forward; Juice Shop stays as the L2 chain-exploit canonical.

## Setup

### First run (builds the docker image from source — ~10 min)

```bash
cd benchmarks/per_target/fixtures/web/owasp-benchmark
docker compose build
```

This clones BenchmarkJava from the upstream repo, runs `mvn package`, and bakes the resulting WAR into a Tomcat 9 image (`strix-bench/owasp-benchmark:v1.2`).

### Fetching the full expectedresults CSV

The fixture ships a 20-row subset (`expectedresults-1.2.csv`) for CI smoke tests. For real bench runs, download the full ~3000-row file:

```bash
curl -O https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master/expectedresults-1.2.csv
mv expectedresults-1.2.csv ~/expectedresults-1.2.csv
export OWASP_BENCH_EXPECTED_CSV=$HOME/expectedresults-1.2.csv
```

### Running the bench

```bash
# Bring up the fixture, run strix, score, tear down
python -m benchmarks.per_target.bench_owasp_benchmark --scan-mode standard
```

Output: per-CWE scorecard markdown + JSON in `benchmarks/per_target/baseline/owasp_bench_<timestamp>.{json,md}`.

### Scoring an existing strix run (no docker required)

```bash
python -m benchmarks.per_target.bench_owasp_benchmark \
    --no-compose --no-strix \
    --existing-findings /path/to/strix_runs/<run_id>/vulnerabilities.json
```

## Why Tomcat 9 (not 10)

BenchmarkJava uses `javax.servlet.*` imports. Tomcat 10 migrated to `jakarta.servlet.*` and no longer runs servlets compiled against javax. Tomcat 9 (released 2017, EOL 2027) is the last release compatible with BenchmarkJava's source as-shipped.

## See also

- Strategy doc: `docs/proposals/2026-05-27-benchmark-suite-strategy.md`
- Scoring module: `benchmarks/per_target/owasp_benchmark_scoring.py`
- Harness: `benchmarks/per_target/bench_owasp_benchmark.py`
- Upstream: <https://github.com/OWASP-Benchmark/BenchmarkJava>
- Project leaderboard: <https://owasp.org/www-project-benchmark/>
