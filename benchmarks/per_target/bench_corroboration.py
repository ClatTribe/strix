"""iter-31.5 — Corroboration rate bench.

Reads the `corroborations[]` + `corroboration_rate` rollup that
`Tracer.build_run_summary()` surfaces (iter-31.5), and reports the
aggregate `corroboration_rate` metric (#17 in docs/metrics.md §1.4).

Why this metric matters
-----------------------
A real security engineer sees three findings of the same CWE on the
same surface from three different tools (SAST + DAST + SBOM) and
mentally stacks them into ONE critical, very-high-confidence finding.
L1.5's `corroborator_ledger` (iter-25.3) does that stacking
automatically. The metric measures how often it happens — and
therefore how much "free signal" L1.5 is extracting from L0/L1's
overlapping detections.

Per docs/metrics.md target: ≥30% of findings should be corroborated
by ≥2 distinct sources at L1.5.

Per-fixture, the bench:
  * Reads `summary.corroborations[]` from the run output JSON.
  * Reports the per-fixture rate + the source-count distribution
    (how many parents have 2 sources vs 3+ sources).
  * Aggregates across all fixtures into an overall rate.

There's no fixture YAML overlay required — corroboration is a pure
runtime signal. The bench just makes the existing signal visible.

Anti-overfit
------------
The scorer reads only the canonical rollup shape (`corroborations[]`
with `parent_id`/`source_count` keys). It never references SUT-
specific values; source-grep guard test enforces this.

Usage:

    python -m benchmarks.per_target.bench_corroboration
    python -m benchmarks.per_target.bench_corroboration --fixture web/juiceshop
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_ROOT = REPO_ROOT / "benchmarks" / "per_target" / "fixtures"


_DEFAULT_FIXTURES = [
    "code/flask-vuln",
    "api/vampi",
    "web/juiceshop",
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FixtureCorroborationResult:
    fixture: str
    total_findings: int = 0
    corroborated_count: int = 0
    corroboration_rate: float = 0.0
    source_count_p50: float = 0.0
    source_count_max: int = 0
    distribution: dict[int, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AggregateCorroborationReport:
    fixtures: list[FixtureCorroborationResult] = field(default_factory=list)
    total_findings: int = 0
    total_corroborated: int = 0
    overall_corroboration_rate: float = 0.0
    overall_source_count_p50: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixtures": [f.to_dict() for f in self.fixtures],
            "total_findings": self.total_findings,
            "total_corroborated": self.total_corroborated,
            "overall_corroboration_rate": self.overall_corroboration_rate,
            "overall_source_count_p50": self.overall_source_count_p50,
        }


# ---------------------------------------------------------------------------
# Score logic
# ---------------------------------------------------------------------------

def score_corroboration_summary(
    fixture: str,
    run_summary: dict[str, Any],
) -> FixtureCorroborationResult:
    """Per-fixture corroboration scorer.

    `run_summary` is the dict produced by `Tracer.build_run_summary()`.
    Tolerant of missing keys — older runs (pre-iter-31.5) won't have
    `corroborations[]` and we report a zero-rate result with a note.
    """
    result = FixtureCorroborationResult(fixture=fixture)

    if not isinstance(run_summary, dict):
        result.notes.append("run_summary not a dict — bench skipped")
        return result

    # findings_summary.total is the canonical post-L1.5 finding count.
    # Falls back to len(top_findings) when total isn't present.
    findings_summary = run_summary.get("findings_summary") or {}
    result.total_findings = int(findings_summary.get("total") or 0)

    corroborations = run_summary.get("corroborations")
    if not isinstance(corroborations, list):
        result.notes.append(
            "no `corroborations[]` in run_summary — pre-iter-31.5 run?"
        )
        return result

    result.corroborated_count = len(corroborations)
    if result.total_findings:
        result.corroboration_rate = round(
            result.corroborated_count / result.total_findings, 3,
        )

    # Source-count distribution: how many parents have 2 sources vs
    # 3 vs 4+ vs etc.
    source_counts: list[int] = []
    for c in corroborations:
        if not isinstance(c, dict):
            continue
        n = int(c.get("source_count") or 0)
        if n >= 2:
            source_counts.append(n)
            result.distribution[n] = result.distribution.get(n, 0) + 1
            result.source_count_max = max(result.source_count_max, n)

    if source_counts:
        try:
            result.source_count_p50 = float(statistics.median(source_counts))
        except statistics.StatisticsError:
            pass

    return result


# ---------------------------------------------------------------------------
# Scan harness
# ---------------------------------------------------------------------------

async def _scan_fixture_collect_summary(
    fixture_dir: Path, sandbox_image: str | None,
) -> dict[str, Any]:
    """Run L1-only bench, return tracer.build_run_summary()."""
    from strix.telemetry.tracer import Tracer, set_global_tracer
    from benchmarks.per_target import bench_l1_only as bench_mod

    tr = Tracer(run_name="corroboration_bench")
    set_global_tracer(tr)

    agent_state = None
    sandbox_runtime = None
    sandbox_info = None
    if sandbox_image:
        sandbox_runtime, sandbox_info = await bench_mod._provision_sandbox(
            image=sandbox_image,
        )
        agent_state = bench_mod._SandboxAgentState(
            sandbox_id=sandbox_info["workspace_id"],
            sandbox_token=sandbox_info["auth_token"],
            sandbox_info=sandbox_info,
        )

    try:
        await bench_mod.run_one_fixture(
            fixture_dir, agent_state=agent_state,
        )
    finally:
        if sandbox_runtime and sandbox_info:
            try:
                await sandbox_runtime.destroy_sandbox(sandbox_info["workspace_id"])
            except Exception:  # noqa: BLE001
                pass

    return tr.build_run_summary()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def amain(args: argparse.Namespace) -> int:
    fixtures = args.fixtures or _DEFAULT_FIXTURES
    report = AggregateCorroborationReport()
    all_source_counts: list[int] = []

    for relpath in fixtures:
        fixture_dir = FIXTURES_ROOT / relpath
        if not fixture_dir.is_dir():
            print(f"[skip] {relpath} not found", file=sys.stderr)
            continue

        print(f"\n=== {relpath} ===")
        try:
            summary = await _scan_fixture_collect_summary(
                fixture_dir, args.sandbox_image,
            )
        except Exception as e:  # noqa: BLE001
            print(f"  SCAN FAILED: {type(e).__name__}: {e}", file=sys.stderr)
            continue

        r = score_corroboration_summary(relpath, summary)
        print(
            f"  findings={r.total_findings} "
            f"corroborated={r.corroborated_count} "
            f"rate={r.corroboration_rate*100:.1f}%  "
            f"(dist={dict(sorted(r.distribution.items()))} "
            f"p50_source_count={r.source_count_p50:.1f})"
        )
        if r.notes:
            for n in r.notes:
                print(f"  note: {n}")

        report.fixtures.append(r)
        report.total_findings += r.total_findings
        report.total_corroborated += r.corroborated_count
        for n, k in r.distribution.items():
            all_source_counts.extend([n] * k)

    if report.total_findings:
        report.overall_corroboration_rate = round(
            report.total_corroborated / report.total_findings, 3,
        )
    if all_source_counts:
        try:
            report.overall_source_count_p50 = float(
                statistics.median(all_source_counts)
            )
        except statistics.StatisticsError:
            pass

    print("\n=== overall ===")
    print(
        f"corroboration_rate={report.overall_corroboration_rate*100:.1f}%  "
        f"target ≥ 30% (L1.5)  "
        f"(corroborated={report.total_corroborated} / "
        f"findings={report.total_findings})"
    )
    print(f"source_count p50={report.overall_source_count_p50:.1f}")

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2))
        print(f"[bench] wrote {out}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--fixtures", nargs="+", default=None)
    parser.add_argument("--sandbox-image", default="strix-sandbox:local")
    parser.add_argument("--output")
    args = parser.parse_args()
    import asyncio
    return asyncio.run(amain(args))


if __name__ == "__main__":
    sys.exit(main())
