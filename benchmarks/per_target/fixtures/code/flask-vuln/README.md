# flask-vuln — code-target benchmark fixture

A single-file Flask app with **10 deliberately-planted vulnerabilities**,
one per classic OWASP category. Used to baseline Strix's white-box
coverage on code targets.

> Don't run this app on a network you care about. It is intentionally
> exploitable. The runner targets it as `local_code` (file scan), not as
> a running web app.

## What's planted

| # | Category | CWE | Where |
|---|---|---|---|
| 1 | Hardcoded secret | CWE-798 | `src/app.py:22` |
| 2 | SQL injection | CWE-89 | `src/app.py:51` |
| 3 | OS command injection | CWE-78 | `src/app.py:63` |
| 4 | SSRF | CWE-918 | `src/app.py:73` |
| 5 | IDOR | CWE-639 | `src/app.py:81` |
| 6 | Reflected XSS | CWE-79 | `src/app.py:92` |
| 7 | Insecure deserialization | CWE-502 | `src/app.py:99` |
| 8 | Path traversal | CWE-22 | `src/app.py:107` |
| 9 | Open redirect | CWE-601 | `src/app.py:116` |
| 10 | Weak crypto | CWE-327 | `src/app.py:124` |

## Layout

Source files live in `src/`. The manifest (`expected.yaml`) and this
README sit at the fixture root, **outside** the scanned directory — so
the agent doesn't read the answers when it scans `src/`.

The exact line numbers are pinned in `expected.yaml`. The matcher in
`scoring.py` tolerates ±20 lines, so small editorial changes to the file
won't break the manifest — but big rewrites should also update the lines.

## Running

```bash
# from repo root
python benchmarks/per_target/runner.py benchmarks/per_target/fixtures/code/flask-vuln \
    --scan-mode standard \
    --output benchmarks/per_target/baseline/flask-vuln_standard.json
```

Strix will scan `app.py` as a `local_code` target. The runner parses
`strix_runs/<run-name>/vulnerabilities/*.md`, scores against the manifest,
and writes the result JSON.

## What "good" looks like

Today's Strix should hit:
- **Easy wins (recall ≥ 0.9):** SQL injection, command injection, hardcoded secret, path traversal — all are pattern-match-friendly and well-covered by skills.
- **Medium (recall ≥ 0.6):** SSRF, IDOR, deserialization, open redirect — the agent has to reason about flow, not just match a pattern.
- **Harder (varies):** Reflected XSS in a Python f-string template requires the agent to reason about HTML rendering context; weak-crypto MD5 is obvious but easily missed if the agent doesn't load a crypto skill.

A run that misses the easy wins is a regression worth investigating.
A run that hits all 10 with low precision (lots of FPs) suggests the agent
is over-reporting — the FP list in the result file should be reviewed
manually before treating it as noise; some FPs are real bugs we didn't
plant (Flask's `debug=False` default is one hardening; weak `secret_key`
hardcoding on `app.secret_key` is another).

## Editing this fixture

If you change `src/app.py`:

1. Run `grep -n "Planted bug" src/app.py` to get the new line numbers.
2. Update `line:` fields in `expected.yaml`.
3. Re-baseline before merging.

If you add a new planted bug:

1. Add a "Planted bug N (CWE-XXX): ..." comment line at the bug location.
2. Add a corresponding entry in `expected_findings` with a stable `id:`.
3. Note the addition in this README's table.
