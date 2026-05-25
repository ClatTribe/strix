"""iter-31.11 — Patcher-correctness bench.

Scores `patch_correctness` (#20 in docs/metrics.md §1.5) — the
fraction of patcher-emitted diffs that successfully verify (i.e. the
original PoC no longer fires against the patched code).

Two scoring layers:

  * **Strict** (default): reads patcher registry status counts from
    `Tracer.build_run_summary()` (iter-31.11). A patch is "correct"
    when `verify_patch` ran and saw no regression. Rate =
    verified / (verified + regressed). Doesn't compile-and-test
    against the SUT's test suite — that's L3 patcher work.

  * **Apply-and-test** (opt-in via `--apply-and-test`): for each
    proposed patch, applies the diff to a sandbox clone of the SUT
    source and runs the SUT's test suite. Rate = (compiled + tests
    passed) / total_patches.
    Status: **stub** for now; per-fixture test-runner integration is
    a follow-up iter (the sandbox-clone + test-execution machinery
    needs its own design). The flag exists so the CLI accepts it
    but currently logs that mode is unimplemented.

Why this matters
----------------
Auto-PR quality is the dev-persona conversion lever. "Tool fixed it
for me, I just merge the PR" only sells if 75%+ of the diffs are
actually mergeable. Without `patch_correctness`, the patcher chain
(iter-27.3) is invisible to scoring.

Anti-overfit
------------
- Scorer reads only canonical patcher fields (status, finding_id);
  never SUT identifiers or diff content
- Source-grep guard forbids SUT tokens

Usage:

    # Strict mode (default, reads from tracer summary)
    python -m benchmarks.per_target.bench_patcher_correctness

    # Read from a saved run_summary.json
    python -m benchmarks.per_target.bench_patcher_correctness \\
        --input strix_runs/<run>/run_summary.json
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
class FixturePatcherResult:
    fixture: str
    patches_total: int = 0
    patches_verified: int = 0
    patches_regressed: int = 0
    patches_applied: int = 0
    patch_correctness: float = 0.0
    by_status: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AggregatePatcherReport:
    fixtures: list[FixturePatcherResult] = field(default_factory=list)
    total_patches: int = 0
    total_verified: int = 0
    total_regressed: int = 0
    overall_patch_correctness: float = 0.0
    aggregate_by_status: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixtures": [f.to_dict() for f in self.fixtures],
            "total_patches": self.total_patches,
            "total_verified": self.total_verified,
            "total_regressed": self.total_regressed,
            "overall_patch_correctness": self.overall_patch_correctness,
            "aggregate_by_status": self.aggregate_by_status,
        }


# ---------------------------------------------------------------------------
# Score logic
# ---------------------------------------------------------------------------

def score_fixture_patcher(
    fixture: str, run_summary: dict[str, Any],
) -> FixturePatcherResult:
    """Per-fixture patcher-correctness scorer.

    `run_summary` is `Tracer.build_run_summary()`. Tolerant of:
      - Missing patcher keys (pre-iter-31.11 runs)
      - `patches_total=0` (run had no patcher emissions)
    """
    result = FixturePatcherResult(fixture=fixture)

    if not isinstance(run_summary, dict):
        result.notes.append("run_summary not a dict — bench skipped")
        return result

    by_status_raw = run_summary.get("patches_by_status")
    if not isinstance(by_status_raw, dict):
        result.notes.append(
            "no `patches_by_status` in run_summary — pre-iter-31.11 run?"
        )
        return result

    result.by_status = dict(by_status_raw)
    result.patches_total = int(run_summary.get("patches_total") or 0)
    result.patches_verified = int(run_summary.get("patches_verified_count") or 0)
    result.patches_regressed = int(
        run_summary.get("patches_regressed_count") or 0
    )
    result.patches_applied = int(run_summary.get("patches_applied_count") or 0)

    denom = result.patches_verified + result.patches_regressed
    if denom:
        result.patch_correctness = round(
            result.patches_verified / denom, 3,
        )
    else:
        result.notes.append(
            "no verify_patch cycles ran — patch_correctness=0 "
            "(no signal yet)"
        )

    return result


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

def _load_run_summary(path: Path) -> dict[str, Any]:
    """Read a saved run_summary.json file. Returns empty dict on error."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


# ---------------------------------------------------------------------------
# Scan harness (live mode)
# ---------------------------------------------------------------------------

async def _scan_fixture_collect_summary(
    fixture_dir: Path, sandbox_image: str | None,
) -> dict[str, Any]:
    from strix.telemetry.tracer import Tracer, set_global_tracer
    from benchmarks.per_target import bench_l1_only as bench_mod

    tr = Tracer(run_name="patcher_bench")
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
    report = AggregatePatcherReport()

    if args.apply_and_test:
        print(
            "[bench] note: --apply-and-test mode is a stub. "
            "Per-fixture sandbox-clone + test-runner integration is a "
            "follow-up iter (see roadmap).",
            file=sys.stderr,
        )

    if args.input:
        # Single-run mode — read a saved run_summary.json
        summary = _load_run_summary(Path(args.input))
        if not summary:
            print(f"error: no run_summary at {args.input}", file=sys.stderr)
            return 1
        r = score_fixture_patcher(args.fixture, summary)
        _print_fixture_result(r)
        report.fixtures.append(r)
        report.total_patches += r.patches_total
        report.total_verified += r.patches_verified
        report.total_regressed += r.patches_regressed
        for s, c in r.by_status.items():
            report.aggregate_by_status[s] = (
                report.aggregate_by_status.get(s, 0) + c
            )
    else:
        # Live mode — run L1 bench per fixture, read from tracer
        fixtures = args.fixtures or _DEFAULT_FIXTURES
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
                print(
                    f"  SCAN FAILED: {type(e).__name__}: {e}", file=sys.stderr,
                )
                continue
            r = score_fixture_patcher(relpath, summary)
            _print_fixture_result(r)
            report.fixtures.append(r)
            report.total_patches += r.patches_total
            report.total_verified += r.patches_verified
            report.total_regressed += r.patches_regressed
            for s, c in r.by_status.items():
                report.aggregate_by_status[s] = (
                    report.aggregate_by_status.get(s, 0) + c
                )

    denom = report.total_verified + report.total_regressed
    if denom:
        report.overall_patch_correctness = round(
            report.total_verified / denom, 3,
        )

    print("\n=== overall ===")
    print(
        f"patch_correctness="
        f"{report.overall_patch_correctness*100:.1f}%  "
        f"target ≥ 75% (L2+)  "
        f"(verified={report.total_verified} / "
        f"verified+regressed={denom})"
    )
    if report.aggregate_by_status:
        print(f"by_status: {dict(sorted(report.aggregate_by_status.items()))}")

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2))
        print(f"[bench] wrote {out}")
    return 0


def _print_fixture_result(r: FixturePatcherResult) -> None:
    print(
        f"  patches_total={r.patches_total}  "
        f"verified={r.patches_verified} regressed={r.patches_regressed} "
        f"applied={r.patches_applied}  "
        f"correctness={r.patch_correctness*100:.1f}%"
    )
    if r.by_status:
        print(f"  by_status: {dict(sorted(r.by_status.items()))}")
    if r.notes:
        for n in r.notes:
            print(f"  note: {n}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--input", default=None,
        help="Path to a saved run_summary.json. When set, "
             "skips live scans and grades the saved run.",
    )
    parser.add_argument(
        "--fixture", default="from-input",
        help="Fixture label to use when --input is set.",
    )
    parser.add_argument("--fixtures", nargs="+", default=None)
    parser.add_argument("--sandbox-image", default="strix-sandbox:local")
    parser.add_argument("--output")
    parser.add_argument(
        "--apply-and-test", action="store_true",
        help="Apply each diff to a sandbox clone + run tests. "
             "STUB — implementation pending.",
    )
    args = parser.parse_args()
    import asyncio
    return asyncio.run(amain(args))


if __name__ == "__main__":
    sys.exit(main())
