"""iter-Q1.4 — multi-trial bench runner with median + p10/p90.

Per docs/proposals/2026-05-27-benchmark-suite-strategy.md: single-
trial bench numbers are noise. This wrapper invokes any other bench
harness N times, parses the per-trial JSON, and emits a summary
with the median + p10/p90 over the trials.

The bench harness being wrapped is expected to:
  * Accept --output <path> and write JSON there
  * The JSON contains the headline metric(s) under a top-level
    `scorecard` block

Headline metrics supported (one per bench harness):
  * OWASP Benchmark v1.2:    `scorecard.overall.youden`
  * WebGoat dual-mode:        `scorecard.detection_rate`,
                              `scorecard.completion_rate`,
                              `scorecard.chain_gap`
  * Vulhub CVE corpus:        `scorecard.hit_rate`,
                              `scorecard.kev_hit_rate`
  * L2 Juice Shop full:       legacy bench writes its own
                              `recall` field (no `scorecard`
                              nesting); we handle that too.

Usage:

    # Run OWASP Benchmark 5 times, get median + p10/p90
    python -m benchmarks.per_target.bench_multi_trial \\
        --bench owasp_benchmark --trials 5 \\
        -- --no-strix --existing-findings /path/to/vulns.json

    # Same with the L2 Juice Shop bench (each trial is ~10 min)
    python -m benchmarks.per_target.bench_multi_trial \\
        --bench l2_juiceshop_full --trials 5

    # Ablation: run the OWASP bench with + without L1.5, compute delta
    STRIX_L15_DISABLED=1 python -m benchmarks.per_target.bench_multi_trial \\
        --bench owasp_benchmark --trials 5 --output /tmp/no_l15.json
    python -m benchmarks.per_target.bench_multi_trial \\
        --bench owasp_benchmark --trials 5 --output /tmp/with_l15.json
    # Then compare /tmp/no_l15.json's median Youden vs /tmp/with_l15.json's
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess  # noqa: S404
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Bench harness registry — maps `--bench <name>` to its module path
# and the JSON-path to the headline metric(s).
# ---------------------------------------------------------------------------


# Maps bench name → (module, default_metric_paths_in_json).
# Metric paths use dotted notation, e.g. `scorecard.overall.youden`.
_BENCH_REGISTRY: dict[str, dict[str, Any]] = {
    "owasp_benchmark": {
        "module": "benchmarks.per_target.bench_owasp_benchmark",
        "metrics": [
            "scorecard.overall.youden",
            "scorecard.overall.tpr",
            "scorecard.overall.fpr",
            "scorecard.overall.f1",
        ],
    },
    "webgoat_dual": {
        "module": "benchmarks.per_target.bench_webgoat_dual",
        "metrics": [
            "scorecard.detection_rate",
            "scorecard.completion_rate",
            "scorecard.chain_gap",
        ],
    },
    "vulhub_cve_corpus": {
        "module": "benchmarks.per_target.bench_vulhub_cve_corpus",
        "metrics": [
            "scorecard.hit_rate",
            "scorecard.kev_hit_rate",
            "scorecard.epss_weighted_score",
        ],
    },
    "l2_juiceshop_full": {
        "module": "benchmarks.per_target.bench_l2_juiceshop_full",
        # Legacy bench writes recall + weighted_score at top level,
        # not under `scorecard`.
        "metrics": [
            "recall_pct",
            "weighted_score_pct",
            "total_solved",
        ],
    },
    "l2_juiceshop_quick": {
        "module": "benchmarks.per_target.bench_l2_juiceshop_full",
        "metrics": ["recall_pct", "weighted_score_pct", "total_solved"],
        "extra_args": ["--scan-mode", "quick"],
    },
}


# ---------------------------------------------------------------------------
# Per-trial driver
# ---------------------------------------------------------------------------


def _run_one_trial(
    module: str, output_path: Path, passthrough_args: list[str],
) -> tuple[int, float]:
    """Invoke `python -m <module> --output <output_path> <passthrough>`.

    Returns (exit_code, wall_seconds)."""
    cmd = [
        sys.executable, "-m", module,
        "--output", str(output_path),
        *passthrough_args,
    ]
    start = time.monotonic()
    proc = subprocess.run(cmd, check=False)  # noqa: S603
    wall = time.monotonic() - start
    return (proc.returncode, wall)


def _extract_metric(data: dict, dotted_path: str) -> float | int | None:
    """Walk a dotted-path expression (e.g. `scorecard.overall.youden`)
    against a parsed JSON dict. Return None when the path doesn't
    resolve."""
    cur: Any = data
    for key in dotted_path.split("."):
        if not isinstance(cur, dict):
            return None
        if key not in cur:
            return None
        cur = cur[key]
    if isinstance(cur, (int, float)):
        return cur
    return None


# ---------------------------------------------------------------------------
# Statistics — median + p10 + p90 over the trials
# ---------------------------------------------------------------------------


def _percentile(values: list[float], pct: float) -> float:
    """Linear-interpolation percentile (matches numpy's default)."""
    if not values:
        return 0.0
    sorted_v = sorted(values)
    if len(sorted_v) == 1:
        return sorted_v[0]
    k = (len(sorted_v) - 1) * pct / 100.0
    lo = int(k)
    hi = lo + 1
    if hi >= len(sorted_v):
        return sorted_v[-1]
    return sorted_v[lo] + (k - lo) * (sorted_v[hi] - sorted_v[lo])


def _summarise(
    metric_name: str, values: list[float | int | None],
) -> dict[str, float | int]:
    """Summarise per-trial values for one metric."""
    valid = [float(v) for v in values if isinstance(v, (int, float))]
    if not valid:
        return {
            "metric": metric_name, "n_valid": 0,
            "median": 0.0, "p10": 0.0, "p90": 0.0,
            "min": 0.0, "max": 0.0, "mean": 0.0,
            "stdev": 0.0,
        }
    return {
        "metric": metric_name,
        "n_valid": len(valid),
        "median": round(statistics.median(valid), 4),
        "mean": round(statistics.mean(valid), 4),
        "stdev": round(statistics.stdev(valid), 4) if len(valid) >= 2 else 0.0,
        "p10": round(_percentile(valid, 10), 4),
        "p90": round(_percentile(valid, 90), 4),
        "min": round(min(valid), 4),
        "max": round(max(valid), 4),
    }


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def _render_report(
    *, bench_name: str, trials: int,
    per_trial_results: list[dict],
    summaries: list[dict],
    total_wall_seconds: float,
) -> str:
    lines: list[str] = []
    lines.append(f"# Multi-trial bench — {bench_name}")
    lines.append("")
    lines.append(f"- **Trials**: {trials}")
    lines.append(f"- **Total wall time**: {total_wall_seconds:.1f}s")
    lines.append("")

    lines.append("## Per-metric summary (median + p10/p90 over trials)")
    lines.append("")
    lines.append(
        "| Metric | N | Median | p10 | p90 | Min | Max | Mean | Stdev |"
    )
    lines.append(
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|"
    )
    for s in summaries:
        lines.append(
            f"| `{s['metric']}` | {s['n_valid']} | "
            f"{s['median']} | {s['p10']} | {s['p90']} | "
            f"{s['min']} | {s['max']} | {s['mean']} | {s['stdev']} |"
        )
    lines.append("")

    lines.append("## Per-trial raw values")
    lines.append("")
    metric_names = [s["metric"] for s in summaries]
    headers = ["trial", "exit", "wall_s"] + [
        f"`{m.split('.')[-1]}`" for m in metric_names
    ]
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join(["---:"] * len(headers)) + "|")
    for r in per_trial_results:
        row = [
            str(r["trial"]),
            str(r["exit_code"]),
            f"{r['wall_seconds']:.1f}",
        ]
        for m in metric_names:
            v = r["metrics"].get(m)
            row.append(f"{v:.4f}" if isinstance(v, (int, float)) else "—")
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        epilog=(
            "Pass arguments to the wrapped bench after `--`. "
            "Example: bench_multi_trial --bench owasp_benchmark "
            "--trials 5 -- --no-strix --existing-findings vulns.json"
        ),
    )
    parser.add_argument(
        "--bench", required=True,
        choices=sorted(_BENCH_REGISTRY.keys()),
        help="Bench harness name (see _BENCH_REGISTRY)",
    )
    parser.add_argument(
        "--trials", type=int, default=5,
        help="Number of trials (default: 5)",
    )
    parser.add_argument(
        "--output",
        help=(
            "Multi-trial summary JSON path "
            "(default: baseline/multi_trial_<bench>_<ts>.json)"
        ),
    )
    parser.add_argument(
        "--metric", action="append", default=[],
        help=(
            "Override metric dotted-paths to extract (repeatable). "
            "When unset, uses the registry's defaults for the bench."
        ),
    )
    parser.add_argument(
        "passthrough_args", nargs="*",
        help="Args to pass through to the wrapped bench (after `--`)",
    )
    # argparse doesn't natively split on `--`; do it ourselves.
    if "--" in sys.argv:
        idx = sys.argv.index("--")
        argv_pre = sys.argv[1:idx]
        passthrough = sys.argv[idx + 1:]
        args = parser.parse_args(argv_pre)
        args.passthrough_args = passthrough
    else:
        args = parser.parse_args()

    bench_cfg = _BENCH_REGISTRY[args.bench]
    metrics = args.metric or bench_cfg["metrics"]
    extra_args = list(bench_cfg.get("extra_args") or [])
    passthrough = extra_args + list(args.passthrough_args)

    baseline_dir = Path(__file__).parent / "baseline"
    baseline_dir.mkdir(exist_ok=True)

    print(
        f"[multi-trial] running {args.bench} × {args.trials} "
        f"(metrics: {', '.join(metrics)})",
    )

    per_trial_results: list[dict[str, Any]] = []
    metric_values: dict[str, list[float | int | None]] = {
        m: [] for m in metrics
    }
    start = time.monotonic()

    with tempfile.TemporaryDirectory() as tmpdir:
        for trial in range(1, args.trials + 1):
            trial_json = Path(tmpdir) / f"trial_{trial}.json"
            print(f"[multi-trial] trial {trial}/{args.trials} ...")
            exit_code, wall = _run_one_trial(
                bench_cfg["module"], trial_json, passthrough,
            )
            if not trial_json.is_file():
                print(
                    f"[multi-trial]   trial {trial} produced no JSON "
                    f"(exit={exit_code}); recording empty metrics.",
                )
                trial_metrics: dict[str, float | int | None] = {
                    m: None for m in metrics
                }
            else:
                try:
                    data = json.loads(trial_json.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as e:
                    print(f"[multi-trial]   trial {trial} bad JSON: {e}")
                    trial_metrics = {m: None for m in metrics}
                else:
                    trial_metrics = {
                        m: _extract_metric(data, m) for m in metrics
                    }
            for m in metrics:
                metric_values[m].append(trial_metrics.get(m))
            per_trial_results.append({
                "trial": trial,
                "exit_code": exit_code,
                "wall_seconds": round(wall, 1),
                "metrics": trial_metrics,
            })

    total_wall = time.monotonic() - start
    summaries = [_summarise(m, metric_values[m]) for m in metrics]

    ts = time.strftime("%Y%m%d_%H%M%S")
    output_json = (
        Path(args.output) if args.output
        else baseline_dir / f"multi_trial_{args.bench}_{ts}.json"
    )
    output_md = output_json.with_suffix(".md")

    payload = {
        "schema_version": 1,
        "bench": args.bench,
        "trials": args.trials,
        "metrics_extracted": metrics,
        "total_wall_seconds": round(total_wall, 1),
        "summaries": summaries,
        "per_trial": per_trial_results,
    }
    output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md = _render_report(
        bench_name=args.bench, trials=args.trials,
        per_trial_results=per_trial_results,
        summaries=summaries,
        total_wall_seconds=total_wall,
    )
    output_md.write_text(md, encoding="utf-8")

    print(f"[multi-trial] wrote {output_json}")
    print(f"[multi-trial] wrote {output_md}")
    print()
    print(md)

    return 0


if __name__ == "__main__":
    sys.exit(main())
