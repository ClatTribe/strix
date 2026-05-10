# sca-supply-chain — Phase 6.6 + 6.7 benchmark

Pattern-recognition benchmark for malicious-package heuristics and
license compliance. Pairs with:

* `code/sca-vuln-deps/` — known-CVE matching (Phase 6.3)
* `code/sca-reachability/` — import-level reachability (Phase 6.4)
* `web+code/vibe-app/` — paired-asset cross-correlation (§4a)

## What's planted

```
package-lock.json:
├── lodash@4.17.21       MIT, no CVE          → no finding
├── express@4.18.2       MIT, no CVE          → no finding
├── lodahs@1.0.0         typosquat of lodash  → malicious_dependency / typosquat
├── reqests@1.0.0        soft typosquat       → may or may not flag
├── agpl-utility@2.0.0   AGPL-3.0             → license_violation / copyleft (high)
├── busl-cache@1.5.0     BUSL-1.1             → license_violation / commercial (high)
├── no-license-pkg@1.0.0 license=null         → license_violation / unknown (medium)
└── sharp@0.32.0         hasInstallScript     → malicious_dependency / install_script
```

## Running

```bash
python benchmarks/per_target/runner.py \
    benchmarks/per_target/fixtures/code/sca-supply-chain \
    --scan-mode standard
```

No threat-intel cache refresh needed — these heuristics don't
query the cache. Pure pattern match.

## What "passing" looks like

Five `must_find: true` entries:

| id                         | category              | severity |
|----------------------------|-----------------------|----------|
| malicious-typosquat-lodahs | malicious_dependency  | medium   |
| malicious-install-script-sharp | malicious_dependency | medium |
| license-agpl-utility       | license_violation     | high     |
| license-busl-cache         | license_violation     | high     |
| license-no-license-pkg     | license_violation     | medium   |

`tool_metadata.malicious.by_indicator` should report at least
`{typosquat: 1, install_script: 1}`. `tool_metadata.licenses.by_family`
should report `{permissive: 2, copyleft: 1, commercial_restricted:
1, unknown: 1}` (all 8 packages classified).

## What this isn't

Not a measure of true / false positive rates against a
representative corpus. Real-world maliciousness scoring needs a
much larger curated benchmark (Backstabber's Knife, MalRegistry,
etc.) — that's a separate threat-intel feed, not a per-fixture
benchmark.
