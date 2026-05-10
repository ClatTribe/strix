# sast-vibe — Phase 7 SAST benchmark

Anchors the `scan_sast` recall measurement. `handler.js` plants 8
vulnerable patterns, one per bundled `strix-*` rule. The benchmark
asserts each rule fires at least once on its planted line.

## Layout

```
sast-vibe/
├── README.md
├── expected.yaml     8 must-find rule matches
└── src/
    └── handler.js    8 planted vulnerable blocks
```

## Running

```bash
# Phase 7.1 prerequisite — semgrep CLI on PATH.
pip install semgrep

python benchmarks/per_target/runner.py \
    benchmarks/per_target/fixtures/code/sast-vibe \
    --scan-mode standard
```

When `semgrep` isn't installed the runner exits early with
`status=partial` — recall reads as 0/8 and the test signals "install
the engine" rather than failing in some confusing way.

## What's planted

| Line | CWE      | Rule                          | Pattern              |
|------|----------|-------------------------------|----------------------|
| 12   | CWE-798  | strix-hardcoded-jwt-secret    | JWT_SECRET literal   |
| 16   | CWE-1004 | strix-express-permissive-cors | `*` + credentials    |
| 21   | CWE-89   | strix-sql-string-concat       | template literal SQL |
| 27   | CWE-22   | strix-path-traversal          | fs.readFile(req.params) |
| 35   | CWE-94   | strix-eval-user-input         | eval(req.body)       |
| 41   | CWE-918  | strix-ssrf-from-user-url      | fetch(req.body.url)  |
| 48   | CWE-915  | strix-express-mass-assignment | User.create(req.body) |
| 54   | CWE-338  | strix-insecure-random         | Math.random for token |

The `react-dangerously-set-innerhtml` and
`nextjs-server-action-no-auth` rules need JSX / Server-Action
contexts respectively; future iterations of the benchmark will
add a JSX file + a Next.js app dir to cover those.

## Severity calibration

`code_map.json` is NOT shipped with the fixture, so the
route-reachable bump doesn't fire — severities reflect raw rule
verdicts. Future iteration: add a generated `code_map.json` with
the right routes so we can pin the calibrated severities (line 21
+ 27 + 35 + 41 + 48 should bump high → critical).
