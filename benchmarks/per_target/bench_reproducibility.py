"""iter-31.7 — Reproducibility-rate bench.

Reads `reproducibility_rate` + `reproducibility_by_tier` from
`Tracer.build_run_summary()` (iter-31.7) and produces a per-fixture +
aggregate scorecard for the `reproducibility_rate` metric (#8 in
docs/metrics.md §1.2).

Why this metric matters
-----------------------
A finding that the agent claims as "verified" needs to actually
reproduce on re-fire. If `reproducibility_rate` is low, the
`verification_status=verified` badge on the dashboard is meaningless.
Per docs/metrics.md target: ≥80% at L2.5 (the layer that owns the
diff-verifier + variant payloads).

Strong tiers (count toward the rate):
  * `verified` — both original + variant payloads reproduced
  * `exploited` — agent demonstrated impact (cookie, data read, etc.)

Weak tier (only counts toward `_within_likely`):
  * `likely` — original re-fired, variant didn't

Other (denominator-only):
  * `suspected`, `dismissed`, `pattern_match`, `inconclusive`

Anti-overfit
------------
Scorer reads only canonical tier labels; source-grep guard forbids
SUT-specific tokens.

Usage:

    python -m benchmarks.per_target.bench_reproducibility
"""

from __future__ import annotations

import argparse
import json
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
class FixtureReproducibilityResult:
    fixture: str
    findings_total: int = 0
    strong_count: int = 0  # verified + exploited
    weak_count: int = 0    # likely
    reproducibility_rate: float = 0.0
    reproducibility_rate_within_likely: float = 0.0
    by_tier: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AggregateReproducibilityReport:
    fixtures: list[FixtureReproducibilityResult] = field(default_factory=list)
    total_findings: int = 0
    total_strong: int = 0
    total_weak: int = 0
    overall_reproducibility_rate: float = 0.0
    overall_reproducibility_rate_within_likely: float = 0.0
    aggregate_by_tier: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixtures": [f.to_dict() for f in self.fixtures],
            "total_findings": self.total_findings,
            "total_strong": self.total_strong,
            "total_weak": self.total_weak,
            "overall_reproducibility_rate": self.overall_reproducibility_rate,
            "overall_reproducibility_rate_within_likely":
                self.overall_reproducibility_rate_within_likely,
            "aggregate_by_tier": self.aggregate_by_tier,
        }


_STRONG_TIERS = {"verified", "exploited"}
_WEAK_TIERS = {"likely"}


# ---------------------------------------------------------------------------
# Score logic
# ---------------------------------------------------------------------------

def score_reproducibility(
    fixture: str, run_summary: dict[str, Any],
) -> FixtureReproducibilityResult:
    """Per-fixture reproducibility scorer.

    `run_summary` is `Tracer.build_run_summary()`. Tolerant of missing
    fields (pre-iter-31.7 runs) and of being computed from the raw
    `by_tier` block when the top-level `reproducibility_rate` key
    happens not to be present.
    """
    result = FixtureReproducibilityResult(fixture=fixture)

    if not isinstance(run_summary, dict):
        result.notes.append("run_summary not a dict — bench skipped")
        return result

    by_tier = run_summary.get("reproducibility_by_tier")
    if not isinstance(by_tier, dict):
        result.notes.append(
            "no `reproducibility_by_tier` in run_summary — pre-iter-31.7 run?"
        )
        return result

    # Recompute aggregates from the tier histogram (instead of trusting
    # the top-level rate fields blindly) so the bench is robust to
    # future tier-label additions on the tracer side.
    total = 0
    strong = 0
    weak = 0
    for label, count in by_tier.items():
        try:
            c = int(count)
        except (TypeError, ValueError):
            continue
        if c <= 0:
            continue
        total += c
        label_norm = str(label).strip().lower()
        result.by_tier[label_norm] = result.by_tier.get(label_norm, 0) + c
        if label_norm in _STRONG_TIERS:
            strong += c
        elif label_norm in _WEAK_TIERS:
            weak += c

    result.findings_total = total
    result.strong_count = strong
    result.weak_count = weak
    if total:
        result.reproducibility_rate = round(strong / total, 3)
        result.reproducibility_rate_within_likely = round(
            (strong + weak) / total, 3,
        )

    return result


# ---------------------------------------------------------------------------
# Scan harness
# ---------------------------------------------------------------------------

async def _scan_fixture_collect_summary(
    fixture_dir: Path, sandbox_image: str | None,
) -> dict[str, Any]:
    from strix.telemetry.tracer import Tracer, set_global_tracer
    from benchmarks.per_target import bench_l1_only as bench_mod

    tr = Tracer(run_name="reproducibility_bench")
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
    report = AggregateReproducibilityReport()

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

        r = score_reproducibility(relpath, summary)
        print(
            f"  findings={r.findings_total} "
            f"strong={r.strong_count} weak={r.weak_count}  "
            f"rate={r.reproducibility_rate*100:.1f}% "
            f"(within_likely={r.reproducibility_rate_within_likely*100:.1f}%)"
        )
        if r.by_tier:
            print(f"  by_tier: {dict(sorted(r.by_tier.items()))}")
        if r.notes:
            for n in r.notes:
                print(f"  note: {n}")

        report.fixtures.append(r)
        report.total_findings += r.findings_total
        report.total_strong += r.strong_count
        report.total_weak += r.weak_count
        for tier, c in r.by_tier.items():
            report.aggregate_by_tier[tier] = (
                report.aggregate_by_tier.get(tier, 0) + c
            )

    if report.total_findings:
        report.overall_reproducibility_rate = round(
            report.total_strong / report.total_findings, 3,
        )
        report.overall_reproducibility_rate_within_likely = round(
            (report.total_strong + report.total_weak) / report.total_findings, 3,
        )

    print("\n=== overall ===")
    print(
        f"reproducibility_rate="
        f"{report.overall_reproducibility_rate*100:.1f}%  "
        f"target ≥ 80% (L2.5)  "
        f"(strong={report.total_strong} / "
        f"findings={report.total_findings})"
    )
    print(
        f"rate_within_likely="
        f"{report.overall_reproducibility_rate_within_likely*100:.1f}%"
    )

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
