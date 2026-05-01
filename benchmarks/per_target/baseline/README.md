# baseline/

Baseline result files from `runner.py`, one per `(fixture, scan_mode, model, date)`
tuple. Used to compare runs over time: when a roadmap item lands, re-run the
relevant fixtures and diff against the most recent baseline.

## Naming convention

```
<fixture-slug>_<scan-mode>_<YYYYMMDD>[_<model-slug>].json
```

Examples:
```
flask-vuln_standard_20260429.json
juiceshop_quick_20260429.json
vulnerable-services_deep_20260430_anthropic-sonnet.json
```

Including the model slug is optional but recommended when comparing
across providers.

## File schema

Output of `runner.py` is a flat JSON object:

```json
{
  "fixture": "benchmarks/per_target/fixtures/code/flask-vuln",
  "target": "/abs/path/to/app.py",
  "target_type": "local_code",
  "scan_mode": "standard",
  "model": "anthropic/claude-sonnet-4-6",
  "strix_exit_code": 2,
  "duration_seconds": 423.4,
  "cost_usd": 0.84,
  "iterations": 87,
  "run_dir": "/.../strix_runs/flask-vuln_a1b2",
  "expected_count": 10,
  "found_count": 12,
  "matched_count": 8,
  "precision": 0.667,
  "recall": 0.8,
  "missed": ["weak-crypto-md5", "open-redirect-login"],
  "false_positives": ["Spurious CSRF on static asset"],
  "matches": [
    ["sqli-search", "SQL Injection in /search"],
    ["cmd-injection-ping", "Command injection via shell=True"]
  ]
}
```

## Comparing two baselines

A useful one-liner for a quick diff:

```bash
jq -r '"\(.fixture) recall=\(.recall) precision=\(.precision) cost=\(.cost_usd)"' \
   benchmarks/per_target/baseline/flask-vuln_standard_*.json | sort
```

For a per-finding diff (what changed in `missed`):

```bash
diff <(jq -r '.missed[]' a.json | sort) <(jq -r '.missed[]' b.json | sort)
```

## Don't commit baselines

Baselines are **operational output of running the test suite**, not test
infrastructure. They're tied to a specific model, scan mode, run timestamp,
and (for live-target runs) the security state of a real production
asset at a moment in time. None of that belongs in version control.

Running `runner.py` is a **read-only execution of the repo** — it should
not modify repo content. Treat the directory like `/var/log/`: the
runner writes here, you read here, you compare here, but you don't push
results back.

Concretely:

- This directory is the right place to write baselines locally with `--output`.
- Don't `git add` the resulting JSON. The directory itself is committed
  (this README explains the convention) but its contents are gitignored
  by virtue of project policy, not by `.gitignore` (so a commit that
  includes a baseline by mistake is visible at `git status`, not silent).
- For sharing a baseline: paste the relevant numbers into a PR
  description or attach the JSON to an issue. Don't merge it.
- For tracking drift over time: keep a personal `baseline/` archive
  outside the repo, or use an external store (gist, S3, internal wiki).

## When to ignore a recall regression

Sometimes a change makes recall *drop* on a previous run because it
tightened false-positive detection. That's a precision↑ recall↓ tradeoff
and may be the right call. Call it out explicitly when it happens — in
the PR description, with the numbers — instead of silently re-running
to a new baseline.
