# Public benchmarks

Reproducible benchmarks for strix against well-known **public**
intentionally-vulnerable datasets — the kind of targets where
commercial tools (Snyk, Aikido, Semgrep, Checkmarx, Veracode,
Burp/ZAP) have already published detection numbers, so a strix
score is directly comparable.

This complements **but does not replace**:

| Suite | What it measures | When to use |
|---|---|---|
| `benchmarks/per_target/` | Per-target-type recall on hand-built fixtures (synthetic Flask app, planted SAST/SCA fixtures, etc.) using the **full agentic scan** (`strix -t ...`) | Regression-detect after roadmap changes; same suite captures cost + LLM iteration count |
| **`benchmarks/public/`** _(this dir)_ | Direct-tool detection rate on **public** vulnerable datasets, **no agent** | Externally-defensible comparison vs commercial tools; honest single-number score per asset class |
| Upstream [`usestrix/benchmarks`](https://github.com/usestrix/benchmarks) | XBEN black-box web CTF — 104 challenges, ~96% solve rate for v0.4.0 | The headline external claim |

## Why a separate harness

The `per_target` runner spawns the full `strix` CLI, lets the lead
agent drive a scan, and parses markdown findings. That's the right
shape for DAST and agentic-workflow benchmarks — cost / iterations
/ recall all roll up to a single number.

For SCA / SAST / IaC, the agentic layer is noise. Snyk's `snyk test`,
Semgrep's `semgrep --config=p/owasp-top-ten`, and Checkmarx's CLI
are all direct-tool invocations — fast, deterministic, no LLM in
the loop. To produce a comparable number, this harness invokes
strix's tools directly:

| Asset | Tool invoked | Comparable to |
|---|---|---|
| SCA | `scan_sca_lockfiles()` | `snyk test`, `npm audit`, Dependabot |
| SAST _(planned)_ | `scan_sast()` | `semgrep ci`, `snyk code test`, Checkmarx CLI |
| IaC _(planned)_ | `scan_iac()` | `checkov`, `tfsec`, `kics` |

DAST stays in `per_target/` — the agentic loop **is** the product
there, and a direct-tool DAST benchmark wouldn't represent how
strix actually runs.

## Per-category coverage

| Category | Public asset | Runner | Status | First captured baseline |
|---|---|---|---|---|
| **SAST**  | OWASP NodeGoat source (shared clone) | `run_sast_benchmark.py` | ✅ wired | CEILING — 100% recall_must_find (4/4), 23 findings, 6.5 s |
| **SCA**   | OWASP NodeGoat lockfile (`package-lock.json`) | `run_sca_benchmark.py` | ✅ wired | FLOOR — 0% recall (cache empty), 629 findings, 1.3 s |
| **IaC**   | Synthetic Dockerfile + docker-compose (`dockerfile-bad-patterns/`) | `run_iac_benchmark.py` | ✅ wired (synthetic placeholder; TerraGoat / KICS deferred to Phase 11.2/11.3) | CEILING — 100% recall_must_find (9/9), 0.96 s |
| **DAST**  | OWASP Juice Shop (agentic, via `per_target/`) | `per_target/runner.py` | ✅ exists | see `per_target/baseline/juiceshop_*.json` |
| Network / IP recon | — | — | not planned (no public comparable score) | — |
| Domain recon       | — | — | not planned (needs controlled domain) | — |
| LLM endpoints      | — | — | Phase 8 not shipped | — |

## Layout

```
benchmarks/public/
├── README.md                       this file
├── run_sca_benchmark.py            SCA runner    → scan_sca_lockfiles()
├── run_sast_benchmark.py           SAST runner   → scan_sast()
├── run_iac_benchmark.py            IaC runner    → scan_iac()
└── fixtures/
    ├── dast/
    │   └── README.md               pointer → per_target/juiceshop
    ├── sast/
    │   └── nodegoat/               OWASP NodeGoat source (re-uses sca/nodegoat/src)
    │       ├── README.md
    │       ├── expected.yaml       5 ground-truth SAST findings
    │       └── baseline/
    │           └── ceiling_*.json
    ├── sca/
    │   └── nodegoat/               OWASP NodeGoat, pinned @ c5cb68a
    │       ├── README.md
    │       ├── setup.sh            clone NodeGoat (idempotent)
    │       ├── expected.yaml       8 direct-dep CVE expectations
    │       ├── .gitignore
    │       └── baseline/
    │           └── floor_*.json
    └── iac/
        └── dockerfile-bad-patterns/   synthetic recall fixture
            ├── README.md
            ├── expected.yaml       9 IaC misconfig expectations
            ├── src/
            │   ├── Dockerfile      planted bad patterns
            │   └── docker-compose.yml
            └── baseline/
                └── ceiling_*.json
```

## Quick start

```bash
# 1. Fetch the fixture source
bash benchmarks/public/fixtures/sca/nodegoat/setup.sh

# 2. (Optional) Seed the threat-intel cache for a CEILING run.
#    Without this, vulnerable_dependency recall = 0 (FLOOR run).
export GITHUB_TOKEN=<your-pat>
python -m strix.threat_intel.refresh \
  --only ghsa,popular,ossf-malicious \
  --ghsa-days 365

# 3. Run + capture
python benchmarks/public/run_sca_benchmark.py \
  benchmarks/public/fixtures/sca/nodegoat \
  -o benchmarks/public/fixtures/sca/nodegoat/baseline/run.json
```

## FLOOR vs CEILING

Each benchmark records `cache_state` so you can tell whether a run
is a FLOOR (no threat-intel) or CEILING (fully seeded) measurement:

- **FLOOR** = `ghsa_seeded: false`. Only heuristic categories fire
  (typosquat, install-script, license policy). `vulnerable_
  dependency` recall is 0. Use FLOOR runs for regression-detection
  on the heuristic surface.

- **CEILING** = `ghsa_seeded: true`. Real CVE detection.
  `vulnerable_dependency` recall is the comparable number against
  Snyk-class tools.

The included `floor_20260511_empty_cache.json` is the first FLOOR
baseline for NodeGoat — 0/5 must-find CVEs (cache empty), 322
typosquat heuristic findings (popular-package corpus also empty),
307 license-policy findings (real signal — NodeGoat's transitives
include 307 packages with no SPDX field).

## Roadmap

| Lane | Fixture | Status |
|---|---|---|
| SCA  | OWASP NodeGoat | ✅ Wired (FLOOR captured; CEILING gated on `GITHUB_TOKEN` for GHSA seed) |
| SAST | OWASP NodeGoat source | ✅ Wired (CEILING captured — 100% recall_must_find) |
| IaC  | dockerfile-bad-patterns (synthetic) | ✅ Wired (CEILING — 100% recall_must_find) |
| DAST | OWASP Juice Shop | ✅ Existing via `per_target/` |
| SCA  | Snyk's `goof`  | Planned — denser direct-dep target |
| SAST | OWASP Benchmark v1.2 (Java) | Planned — has official F-score table from Snyk / Checkmarx / Veracode / Semgrep; the **externally-defensible** academic number |
| SAST | NIST SARD Juliet (subset) | Planned — multi-language, broader than OWASP Benchmark |
| IaC  | TerraGoat / KICS test-repo | Gated on Phase 11.2 (Checkov) + 11.3 (Terraform parser) |

Each row above represents a separate PR.

## Reproducibility

- Fixture sources are **never committed**. `setup.sh` clones at a
  pinned commit (`.gitignore` excludes `src/`).
- The `cache_state` block in each baseline JSON records exactly
  which feeds were seeded — apples-to-apples comparisons require
  the same `cache_state`.
- A baseline filename convention encodes the cache state:
  `floor_*` = empty cache, `ceiling_*` = seeded.
