"""iter-31.6 — phase_correlate emissions bench.

Reads the `phase_correlations[]` list that `Tracer.build_run_summary()`
surfaces (iter-31.6) and reports two aggregate metrics for
`phase_correlate_emissions` (#19 in docs/metrics.md §1.4):

  * `phase_correlations_count` — how many phase boundaries the
    mid_scan_correlate hook actually fired at. Target ≥ 3 at L2 (the
    workflow has roughly recon → discovery → exploitation → impact →
    report boundaries; firing at ≥3 of them means the chains are
    showing up mid-scan, not just at the end).
  * `new_chains_per_invocation_p50` — typical chain output per
    invocation. Higher = the correlator is finding new chains as the
    scan progresses (the iter-27.2 design intent).

Why this metric matters
-----------------------
The original `correlate_findings` only ran at scan-end, so newly
discovered attack chains couldn't influence the Lead's planning during
the scan. iter-27.2 added phase-boundary invocations to fix this. Until
this bench landed, the value of that fix was invisible to scoring.

No fixture YAML overlay required — phase_correlations are pure runtime
signals. The bench just makes the existing signal visible.

Anti-overfit
------------
Scorer reads only canonical PhaseCorrelationResult fields (`from_phase`,
`to_phase`, `new_chains`, `findings_promoted`). Source-grep guard
forbids SUT-specific tokens.

Usage:

    python -m benchmarks.per_target.bench_phase_correlate
    python -m benchmarks.per_target.bench_phase_correlate --fixture web/juiceshop
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
class FixturePhaseCorrelateResult:
    fixture: str
    invocations: int = 0
    invocations_with_new_chains: int = 0
    total_new_chains: int = 0
    total_findings_promoted: int = 0
    new_chains_per_invocation_p50: float = 0.0
    new_chains_per_invocation_max: int = 0
    per_phase_invocations: dict[str, int] = field(default_factory=dict)
    errors: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AggregatePhaseCorrelateReport:
    fixtures: list[FixturePhaseCorrelateResult] = field(default_factory=list)
    total_invocations: int = 0
    total_new_chains: int = 0
    overall_new_chains_per_invocation_p50: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixtures": [f.to_dict() for f in self.fixtures],
            "total_invocations": self.total_invocations,
            "total_new_chains": self.total_new_chains,
            "overall_new_chains_per_invocation_p50":
                self.overall_new_chains_per_invocation_p50,
        }


# ---------------------------------------------------------------------------
# Score logic
# ---------------------------------------------------------------------------

def score_phase_correlations(
    fixture: str, run_summary: dict[str, Any],
) -> FixturePhaseCorrelateResult:
    """Per-fixture scorer.

    `run_summary` is the dict from `Tracer.build_run_summary()`.
    Tolerant of missing keys — pre-iter-31.6 runs report a zero result
    with a note.
    """
    result = FixturePhaseCorrelateResult(fixture=fixture)

    if not isinstance(run_summary, dict):
        result.notes.append("run_summary not a dict — bench skipped")
        return result

    pc = run_summary.get("phase_correlations")
    if not isinstance(pc, list):
        result.notes.append(
            "no `phase_correlations[]` in run_summary — pre-iter-31.6 run?"
        )
        return result

    new_chain_counts: list[int] = []
    for entry in pc:
        if not isinstance(entry, dict):
            continue
        result.invocations += 1
        new = int(entry.get("new_chains") or 0)
        result.total_new_chains += new
        result.total_findings_promoted += int(entry.get("findings_promoted") or 0)
        if new > 0:
            result.invocations_with_new_chains += 1
        if entry.get("error"):
            result.errors += 1
        new_chain_counts.append(new)
        # Phase-boundary fan-out: which "to_phase" did the correlator
        # most actively fire at? Useful to spot the workflow stage
        # where chains land.
        to_phase = str(entry.get("to_phase") or "unknown")
        result.per_phase_invocations[to_phase] = (
            result.per_phase_invocations.get(to_phase, 0) + 1
        )

    if new_chain_counts:
        try:
            result.new_chains_per_invocation_p50 = float(
                statistics.median(new_chain_counts)
            )
        except statistics.StatisticsError:
            pass
        result.new_chains_per_invocation_max = max(new_chain_counts)

    return result


# ---------------------------------------------------------------------------
# Scan harness
# ---------------------------------------------------------------------------

async def _scan_fixture_collect_summary(
    fixture_dir: Path, sandbox_image: str | None,
) -> dict[str, Any]:
    from strix.telemetry.tracer import Tracer, set_global_tracer
    from benchmarks.per_target import bench_l1_only as bench_mod

    tr = Tracer(run_name="phase_correlate_bench")
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
    report = AggregatePhaseCorrelateReport()
    all_new_chain_counts: list[int] = []

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

        r = score_phase_correlations(relpath, summary)
        print(
            f"  invocations={r.invocations} "
            f"(non-empty={r.invocations_with_new_chains}) "
            f"new_chains_total={r.total_new_chains} "
            f"findings_promoted={r.total_findings_promoted} "
            f"p50_new_chains={r.new_chains_per_invocation_p50:.1f} "
            f"max={r.new_chains_per_invocation_max} "
            f"errors={r.errors}"
        )
        if r.per_phase_invocations:
            print(f"  per_phase: {dict(sorted(r.per_phase_invocations.items()))}")
        if r.notes:
            for n in r.notes:
                print(f"  note: {n}")

        report.fixtures.append(r)
        report.total_invocations += r.invocations
        report.total_new_chains += r.total_new_chains
        # Re-derive raw new-chain counts for aggregate p50
        for _phase, k in r.per_phase_invocations.items():
            pass  # placeholder — actual counts aggregated below
        # Actually: build a list of new_chains values across all
        # invocations to compute aggregate p50. We track these
        # internally via the score loop, but didn't expose them on the
        # dataclass to keep it small. Read-derive instead:
        pc = summary.get("phase_correlations") or []
        all_new_chain_counts.extend(
            int(e.get("new_chains") or 0)
            for e in pc if isinstance(e, dict)
        )

    if all_new_chain_counts:
        try:
            report.overall_new_chains_per_invocation_p50 = float(
                statistics.median(all_new_chain_counts)
            )
        except statistics.StatisticsError:
            pass

    print("\n=== overall ===")
    print(
        f"phase_correlations_count={report.total_invocations}  "
        f"target ≥ 3 (L2)  "
        f"(new_chains_total={report.total_new_chains})"
    )
    print(
        f"new_chains_per_invocation_p50="
        f"{report.overall_new_chains_per_invocation_p50:.1f}"
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
