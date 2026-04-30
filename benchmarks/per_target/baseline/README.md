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

## When to commit baselines

Yes, commit them. They're small, they're how the team agrees on what
"current behavior" means, and they let PRs include "baseline shifted by
X" in the description.

When adding a baseline file:

1. Run the fixture on a clean checkout of `main`.
2. Use a stable model + scan_mode (commit the same combo each time so
   diffs are interpretable).
3. Add a one-line note in the PR description: "ran on
   `anthropic/claude-sonnet-4-6` with `--scan-mode standard`."

## When to ignore a recall regression

Sometimes a roadmap change makes recall *drop* on an old baseline because
it tightened false-positive detection. That's a precision↑ recall↓
tradeoff and may be the right call. The PR should explicitly call it
out — not silently land a regression in the baselines.
