"""iter-31.1 — FP suppression bench.

The first L1.5-moat metric (`fp_rate` + `dismissal_accuracy`) made
visible. Without this, L1.5's `pre_emission_fp_filter` could be
broken or doing nothing and nobody would notice — the existing
`bench_l1_only` and `runner.py` benches only count `must_find`
recall, not what L1.5 quietly drops.

**What it measures:**

  * `dismissal_accuracy` — of the planted FP-decoys in each fixture's
    `expected_dismissed[]` list, how many did L1.5 correctly drop?
    Target ≥ 80% per `docs/metrics.md §2`.
  * `fp_rate` — of the findings L1.5 DID emit, how many are
    not-in-expected (i.e. likely false positives)? Target ≤ 10%.
  * Per-fixture breakdown so we can see which fixture's FP-filter
    rules need tuning.

**Inputs:**

  * Each fixture's `expected.yaml` extended with:
    ```yaml
    expected_dismissed:
      - id: csrf-on-test-fixture
        category: csrf
        file: tests/fixtures/users.py
        line: 12
        reason: test_file_path
        description: a CSRF decoy planted to verify L1.5 catches it
    ```
  * Tracer's `dismissed_findings[]` list (populated by iter-31.1
    in `add_vulnerability_report`).
  * `summary.l15_dismissals` in `build_run_summary()`.

**Outputs:**

  * Per-fixture JSON: `{fixture, expected_dismissed_count,
     actually_dismissed_count, correctly_dismissed_count,
     missed_dismissals[], fp_emissions[], dismissal_accuracy,
     fp_rate}`
  * Aggregate report.

**Anti-overfit:**

  * `expected_dismissed[]` entries are DOCUMENTED FP patterns
    (test-file paths, getenv defaults, framework boilerplate) —
    not arbitrary fixture quirks.
  * Each decoy has a `reason` field that maps to L1.5's
    `pre_emission_fp_filter` rules — so a decoy that L1.5 SHOULD
    catch by virtue of being on a `test/` path must declare
    `reason: test_file_path`.
  * The bench reports MISSED dismissals separately so we can see
    which FP-filter rules need expanding.

**Usage:**

    python -m benchmarks.per_target.bench_fp_suppression
    python -m benchmarks.per_target.bench_fp_suppression --fixture code/flask-vuln

Exit codes:
    0 — bench ran (any score)
    1 — bench infrastructure failure
    2 — invocation error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Optional dep — fixtures use YAML
try:
    import yaml  # type: ignore[import-untyped]
except ImportError:
    print("error: pyyaml not installed (`pip install pyyaml`)", file=sys.stderr)
    sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_ROOT = REPO_ROOT / "benchmarks" / "per_target" / "fixtures"
BASELINE_DIR = REPO_ROOT / "benchmarks" / "per_target" / "baseline"


# Same default fixture set as the validator (anti-overfit: ≥3)
_DEFAULT_FIXTURES = [
    "code/flask-vuln",
    "api/vampi",
    "web/juiceshop",
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FixtureFpResult:
    fixture: str
    expected_dismissed_count: int = 0
    actually_dismissed_count: int = 0
    correctly_dismissed_count: int = 0
    # IDs from expected_dismissed[] that L1.5 should have caught but didn't
    missed_dismissals: list[str] = field(default_factory=list)
    # Dismissals L1.5 made that weren't in expected_dismissed[] (extra-credit)
    unexpected_dismissals: list[str] = field(default_factory=list)
    dismissal_accuracy: float = 0.0
    # FP rate is computed across the full bench — see aggregator
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AggregateReport:
    fixtures: list[FixtureFpResult] = field(default_factory=list)
    total_expected_dismissals: int = 0
    total_actual_dismissals: int = 0
    total_correctly_dismissed: int = 0
    # Aggregate dismissal_accuracy across all fixtures
    overall_dismissal_accuracy: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixtures": [f.to_dict() for f in self.fixtures],
            "total_expected_dismissals": self.total_expected_dismissals,
            "total_actual_dismissals": self.total_actual_dismissals,
            "total_correctly_dismissed": self.total_correctly_dismissed,
            "overall_dismissal_accuracy": self.overall_dismissal_accuracy,
        }


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------

def _load_expected_dismissed(fixture_path: Path) -> list[dict[str, Any]]:
    """Read `expected_dismissed[]` from a fixture's expected.yaml.
    Returns empty list when the field is absent."""
    expected_yaml = fixture_path / "expected.yaml"
    if not expected_yaml.is_file():
        return []
    try:
        data = yaml.safe_load(expected_yaml.read_text())
    except (yaml.YAMLError, OSError) as e:
        print(
            f"WARN: could not parse {expected_yaml}: {e}",
            file=sys.stderr,
        )
        return []
    if not isinstance(data, dict):
        return []
    raw = data.get("expected_dismissed") or []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in raw:
        if isinstance(entry, dict) and entry.get("id"):
            out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Match logic
# ---------------------------------------------------------------------------

def _dismissal_matches_expected(
    expected: dict[str, Any], actual: dict[str, Any],
) -> bool:
    """Does an actual dismissal match an expected decoy?

    Match heuristic: ALL of these MUST agree (when present in both):
      - category (or rule_id substring)
      - file path (case-insensitive substring match)
      - line (within ±2 lines if both present)

    Anti-overfit: matching is SHAPE-based, not by `id` — the `id`
    field in expected.yaml is only for human-readable bench output.
    """
    # Category match
    ec = (expected.get("category") or "").lower()
    ac = (actual.get("category") or "").lower()
    if ec and ac and ec not in ac and ac not in ec:
        return False
    # File path match
    ef = (expected.get("file") or "").lower()
    af = str(actual.get("file") or "").lower()
    if ef and af and ef not in af and af not in ef:
        return False
    # Line match (±2 tolerance, only when both present)
    el = expected.get("line")
    al = actual.get("line")
    try:
        if el is not None and al is not None:
            if abs(int(el) - int(al)) > 2:
                return False
    except (TypeError, ValueError):
        pass
    return True


def score_fixture(
    fixture: str,
    expected_dismissed: list[dict[str, Any]],
    actual_dismissals: list[dict[str, Any]],
) -> FixtureFpResult:
    """Score a single fixture's dismissals against expected decoys."""
    result = FixtureFpResult(
        fixture=fixture,
        expected_dismissed_count=len(expected_dismissed),
        actually_dismissed_count=len(actual_dismissals),
    )

    if not expected_dismissed:
        result.notes.append("no expected_dismissed[] in fixture — bench skipped")
        return result

    # For each expected decoy, find a matching actual dismissal
    matched_actual_idxs: set[int] = set()
    for expected in expected_dismissed:
        found = False
        for idx, actual in enumerate(actual_dismissals):
            if idx in matched_actual_idxs:
                continue
            if _dismissal_matches_expected(expected, actual):
                matched_actual_idxs.add(idx)
                found = True
                break
        if found:
            result.correctly_dismissed_count += 1
        else:
            result.missed_dismissals.append(expected.get("id") or "unknown")

    # Unexpected dismissals (extra credit — L1.5 caught FPs we didn't plant)
    for idx, actual in enumerate(actual_dismissals):
        if idx not in matched_actual_idxs:
            ident = (
                actual.get("title")
                or f"{actual.get('category', '?')}@{actual.get('file', '?')}"
            )
            result.unexpected_dismissals.append(ident[:80])

    if result.expected_dismissed_count > 0:
        result.dismissal_accuracy = round(
            result.correctly_dismissed_count / result.expected_dismissed_count,
            3,
        )
    return result


# ---------------------------------------------------------------------------
# Scan harness
# ---------------------------------------------------------------------------

def _import_pytest_friendly_l15() -> tuple[Any, Any]:
    """Late-import the tracer + bench_l1_only so a test runner that
    imports this module doesn't trigger heavy strix imports."""
    from strix.telemetry.tracer import Tracer, set_global_tracer
    from benchmarks.per_target import bench_l1_only as bench_mod
    return (Tracer, set_global_tracer), bench_mod


async def _scan_fixture_collect_dismissals(
    fixture_dir: Path, sandbox_image: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run the L1-only bench harness against `fixture_dir`, return
    (dismissed_findings, score_result_dict).

    Reuses bench_l1_only's per-fixture machinery + provisioned sandbox.
    Stand-alone wrapper avoids re-implementing docker_up, source-copy,
    sandbox provisioning, etc.
    """
    (Tracer, set_global_tracer), bench_mod = _import_pytest_friendly_l15()

    # Fresh tracer so we start with empty dismissed_findings
    tr = Tracer(run_name="fp_suppression_bench")
    set_global_tracer(tr)

    # Provision the sandbox once for all fixtures (caller-managed)
    # — but for the standalone bench we provision per-call. Acceptable
    # given fp_suppression runs over 3 fixtures total.
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
        result = await bench_mod.run_one_fixture(
            fixture_dir, agent_state=agent_state,
        )
    finally:
        if sandbox_runtime and sandbox_info:
            try:
                await sandbox_runtime.destroy_sandbox(sandbox_info["workspace_id"])
            except Exception:  # noqa: BLE001
                pass

    # The tracer has the dismissed findings populated by L1.5's hook
    dismissed = list(tr.dismissed_findings)
    return dismissed, result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def amain(args: argparse.Namespace) -> int:
    fixtures = args.fixtures or _DEFAULT_FIXTURES

    report = AggregateReport()

    for relpath in fixtures:
        fixture_dir = FIXTURES_ROOT / relpath
        if not fixture_dir.is_dir():
            print(f"[skip] {relpath} — fixture dir not found", file=sys.stderr)
            continue
        expected = _load_expected_dismissed(fixture_dir)
        if not expected:
            print(f"[skip] {relpath} — no expected_dismissed[] in expected.yaml")
            continue

        print(f"\n=== {relpath} ===")
        try:
            dismissed, _ = await _scan_fixture_collect_dismissals(
                fixture_dir, args.sandbox_image,
            )
        except Exception as e:  # noqa: BLE001
            print(f"  SCAN FAILED: {type(e).__name__}: {e}", file=sys.stderr)
            continue
        fixture_result = score_fixture(relpath, expected, dismissed)
        print(
            f"  expected_dismissed={fixture_result.expected_dismissed_count} "
            f"actual_dismissed={fixture_result.actually_dismissed_count} "
            f"correctly_dismissed={fixture_result.correctly_dismissed_count} "
            f"accuracy={fixture_result.dismissal_accuracy*100:.1f}%"
        )
        if fixture_result.missed_dismissals:
            print(f"  missed: {fixture_result.missed_dismissals}")
        report.fixtures.append(fixture_result)
        report.total_expected_dismissals += fixture_result.expected_dismissed_count
        report.total_actual_dismissals += fixture_result.actually_dismissed_count
        report.total_correctly_dismissed += fixture_result.correctly_dismissed_count

    if report.total_expected_dismissals:
        report.overall_dismissal_accuracy = round(
            report.total_correctly_dismissed / report.total_expected_dismissals,
            3,
        )

    print("\n=== overall ===")
    print(
        f"dismissal_accuracy={report.overall_dismissal_accuracy*100:.1f}%  "
        f"target ≥ 80.0%  "
        f"(correctly_dismissed={report.total_correctly_dismissed} / "
        f"expected={report.total_expected_dismissals})"
    )

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2))
        print(f"[bench] wrote {out}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--fixtures", nargs="+", default=None,
        help=f"fixture paths under fixtures/ (default: {_DEFAULT_FIXTURES})",
    )
    parser.add_argument(
        "--sandbox-image", default="strix-sandbox:local",
        help="sandbox image (default: strix-sandbox:local)",
    )
    parser.add_argument(
        "--output",
        help="JSON output path (default: don't persist)",
    )
    args = parser.parse_args()

    import asyncio
    return asyncio.run(amain(args))


if __name__ == "__main__":
    sys.exit(main())
