# sca-reachability — Phase 6.4 efficiency benchmark

Measures the **noise-reduction ratio** that import-level reachability
analysis (Phase 6.4, PR #219 follow-up) achieves over raw SCA
matching.

## What's planted

`package-lock.json` pins 6 vulnerable packages. `app.js` imports 3
of them. The other 3 sit in the dep tree but no source file
references them. That gives a deterministic 50/50 split:

| Package           | reachability    | severity (raw)  | severity (filtered) |
|-------------------|-----------------|-----------------|---------------------|
| lodash@4.17.20    | direct_import   | high            | high (unchanged)    |
| ejs@3.1.6         | direct_import   | critical        | critical (unchanged)|
| express@4.16.0    | direct_import   | medium          | medium (unchanged)  |
| ws@5.2.2          | unused          | high            | **low** (-2 tiers)  |
| minimist@1.2.5    | unused          | high            | **low** (-2 tiers)  |
| yargs@16.0.0      | unused          | high            | **low** (-2 tiers)  |

## Running

```bash
# Refresh threat-intel cache so the headline CVEs are present.
python -m strix.threat_intel.refresh --feeds kev,epss,nvd,ghsa

# Run with reachability ON (default — Phase 6.4 behaviour).
python benchmarks/per_target/runner.py \
    benchmarks/per_target/fixtures/code/sca-reachability \
    --scan-mode standard

# Compare against reachability OFF (raw matching) to see the
# demotion effect:
python benchmarks/per_target/runner.py \
    benchmarks/per_target/fixtures/code/sca-reachability \
    --scan-mode standard \
    --strix-arg "--instruction" \
    --strix-arg "Run scan_sca_lockfiles with with_reachability=False"
```

## What "passing" looks like

* Reachable findings (lodash, ejs, express) keep their original
  severity from the threat-intel cache.
* Unused findings (ws, minimist, yargs) demote from high → low
  AND carry `[reachability=unused]` in the title so reviewers see
  why they're below the fold.
* `tool_metadata.reachability.by_status` reports
  `{direct_import: 3, unused: 3}` exactly.
* Recall is full (all 5 must-find entries surface), but the count
  of `severity=high` findings drops from 4 (raw) → 1 (filtered).

## What this isn't

Not a measurement of *true* reachability. v1 is import-level: a
package is reachable if any source file `import`s or `require()`s
it by name. Function-level reachability (call-graph from the
specific vulnerable function to a real entry point) is Phase 6.4
v2 — the next iteration of this same module.

Real-world reduction ratios on customer repos are 30–60% on the
high-severity tier (per the §6.4 plan in `AISecurityEngineer.md`).
50% here is a deliberate, contrived ratio for testability — the
fixture is small enough that 3-of-6 unused is achievable
without bloating the corpus.
