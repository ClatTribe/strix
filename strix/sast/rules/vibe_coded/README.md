# strix vibe-coded SAST rules

YAML rules targeting AI-generated code patterns that commonly
introduce security bugs in vibe-coded apps. Loaded by
`strix.sast.semgrep_runner.run_semgrep` via Semgrep's
`--config <dir>` mechanism.

## Rule index (v1 — 9 rules)

| File                                       | CWE      | Pattern                                              |
|--------------------------------------------|----------|------------------------------------------------------|
| `express-mass-assignment.yml`              | CWE-915  | `Model.create(req.body)` without allowlist           |
| `express-permissive-cors.yml`              | CWE-1004 | `cors({origin:'*', credentials:true})`               |
| `react-dangerously-set-innerhtml.yml`      | CWE-79   | `dangerouslySetInnerHTML` from user input            |
| `nextjs-server-action-no-auth.yml`         | CWE-862  | `'use server'` mutating DB without `await auth()`    |
| `hardcoded-jwt-secret.yml`                 | CWE-798  | `jwt.sign(data, "literal-secret")`                   |
| `sql-string-concat.yml`                    | CWE-89   | SQL via template literal / string concat             |
| `path-traversal-from-params.yml`           | CWE-22   | `fs.readFile(req.params.x)` w/o `path.basename`      |
| `eval-with-user-input.yml`                 | CWE-94   | `eval(req.body.x)` / `new Function(req.body.x)`      |
| `insecure-random-for-crypto.yml`           | CWE-338  | `Math.random()` for tokens / secrets / OTPs          |
| `ssrf-from-user-url.yml`                   | CWE-918  | `fetch(req.body.url)` w/o allowlist                  |

## Adding rules

1. Create `<short-name>.yml` in this dir.
2. Use `strix-<short-name>` as the rule `id` (id collision check
   runs via `tests/sast/test_rules.py::test_rule_ids_are_unique`).
3. Set `metadata.vibe_pattern: true` so the rules can be filtered
   from non-AI-generated patterns at scoring time.
4. Map to a CWE that's in `_CWE_TO_CATEGORY` in
   `strix/sast/semgrep_runner.py` so findings get the right
   semantic category for cross-asset routing.

## Validation

Rules don't compile-check until Semgrep parses them. The unit
tests in `tests/sast/test_rules.py` verify YAML structure and
rule-id uniqueness; run-time errors surface in `SemgrepResult.
status="partial"`.

## Why so few

The roadmap plans 50+ rules. v1 ships 9 anchors covering the
highest-impact AI-generated patterns. Expanding to 50+ is its
own follow-up PR — adds rule files only, no engine changes.
