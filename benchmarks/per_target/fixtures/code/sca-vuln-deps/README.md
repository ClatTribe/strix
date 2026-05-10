# sca-vuln-deps

Tiny "repo" pinned to widely-known-vulnerable package versions. Used to
benchmark Phase 6 (`scan_sca_lockfiles`) recall the same way `flask-vuln`
benchmarks code-target DAST recall.

## Layout

```
sca-vuln-deps/
├── README.md          this file
├── expected.yaml      manifest — per-package CVE expectations
└── src/
    ├── package-lock.json   npm v3 lockfile, 4 vulnerable + 1 dev-only
    └── requirements.txt    pip pinned, 4 vulnerable
```

The runner walks `src/` (the same convention `flask-vuln` uses to keep
`expected.yaml` out of Strix's view).

## Running

```bash
# 1. Refresh the threat-intel cache so GHSA / NVD have these CVEs.
python -m strix.threat_intel.refresh --feeds kev,epss,nvd,ghsa

# 2. Run the benchmark.
python benchmarks/per_target/runner.py \
    benchmarks/per_target/fixtures/code/sca-vuln-deps \
    --scan-mode standard
```

## Why these versions

Each package was selected from public advisory databases as a recognised
"unmistakable hit" so SCA failure means the matcher / parser is broken,
not that the data was ambiguous:

| Package           | CVE                     | Class                       |
|-------------------|-------------------------|-----------------------------|
| lodash@4.17.20    | CVE-2020-8203           | Prototype pollution         |
| minimist@1.2.5    | CVE-2021-44906          | Prototype pollution         |
| express@4.16.0    | CVE-2024-29041          | Open redirect               |
| ws@5.2.2          | CVE-2024-37890          | ReDoS                       |
| django@2.2.0      | CVE-2019-19844 (+more)  | SQLi / disclosure           |
| requests@2.19.0   | CVE-2018-18074          | Header leak on redirect     |
| pyyaml@5.1        | CVE-2020-14343          | RCE via yaml.load           |
| flask@0.12.2      | multiple                | Werkzeug debug-PIN          |

## What "must_find: true" means

Recall is measured against `must_find: true` only. The optional
entries (`must_find: false`) are tracked but don't fail the benchmark
— they're flaky depending on which feeds the threat-intel cache has
synced. Eight expected findings, four must-find.
