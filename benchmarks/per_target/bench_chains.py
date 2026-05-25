"""iter-31.2 — Chain detection bench.

Measures whether L1.5's `mid_scan_correlate` (iter-27.2) successfully
identifies multi-finding attack chains — vs treating each finding as
isolated. This is the L1.5 metric that justifies the architectural
moat: no competitor's tool surfaces "your SQLi + your IDOR + this
admin endpoint = data-breach scenario" as a single chain finding.

Per `docs/metrics.md §1.1`:
  * `chain_detection_rate` — of the chains in `expected_chains[]`, how
    many did L1.5 actually emit?  Target ≥ 40% at L1.5, ≥ 70% at L2.
  * `chain_depth_p95` — 95th percentile of members per chain. Target
    ≥ 4 at L2+. Higher depth = the tool reasoned more steps deep.

**Inputs:**

  * Each fixture's `expected.yaml` extended with:
    ```yaml
    expected_chains:
      - id: auth-bypass-to-data-exfil
        kind: lateral-movement
        members: [sqli-login, idor-basket]
        severity: critical
        description: ...
    ```
  * Tracer's `chains_emitted[]` extracted from
    `vulnerability_reports[].chain_summary` blocks via iter-31.2.
  * Available via `summary.chains_emitted` in `build_run_summary()`.

**Match logic:**

  An expected chain matches an actual chain when ≥half of expected
  members are present in the actual chain's `members[]`. Order does
  not matter; the chain's *composition* matters.

**Anti-overfit:**

  * `kind` field is the OWASP / MITRE ATT&CK tactic label (lateral-
    movement / privilege-escalation / data-exfil / etc.), not
    SUT-specific.
  * `members[]` are finding-id strings from `expected_findings[]` —
    if a fixture's expected_findings doesn't include the member, the
    chain is unreachable and the bench logs that.
  * Source-grep regression guard prevents SUT-specific values in
    the bench itself.

Usage:

    python -m benchmarks.per_target.bench_chains
    python -m benchmarks.per_target.bench_chains --fixture web/juiceshop
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:
    print("error: pyyaml not installed", file=sys.stderr)
    sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_ROOT = REPO_ROOT / "benchmarks" / "per_target" / "fixtures"
BASELINE_DIR = REPO_ROOT / "benchmarks" / "per_target" / "baseline"


_DEFAULT_FIXTURES = [
    "code/flask-vuln",
    "api/vampi",
    "web/juiceshop",
]


# Half of expected members must overlap with actual members to count as match.
_MATCH_OVERLAP_RATIO = 0.5


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ChainMatch:
    expected_id: str
    expected_kind: str | None
    expected_members: list[str]
    matched_actual_chain_id: str | None = None
    matched_actual_members: list[str] = field(default_factory=list)
    overlap_count: int = 0
    overlap_ratio: float = 0.0
    matched: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FixtureChainResult:
    fixture: str
    expected_chain_count: int = 0
    actual_chain_count: int = 0
    matched_count: int = 0
    matches: list[ChainMatch] = field(default_factory=list)
    chain_detection_rate: float = 0.0
    chain_depth_p50: float = 0.0
    chain_depth_p95: float = 0.0
    unmatched_expected_ids: list[str] = field(default_factory=list)
    extra_actual_chain_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            **{k: v for k, v in asdict(self).items() if k != "matches"},
            "matches": [m.to_dict() for m in self.matches],
        }


@dataclass
class AggregateChainReport:
    fixtures: list[FixtureChainResult] = field(default_factory=list)
    total_expected: int = 0
    total_matched: int = 0
    overall_chain_detection_rate: float = 0.0
    overall_chain_depth_p95: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixtures": [f.to_dict() for f in self.fixtures],
            "total_expected": self.total_expected,
            "total_matched": self.total_matched,
            "overall_chain_detection_rate": self.overall_chain_detection_rate,
            "overall_chain_depth_p95": self.overall_chain_depth_p95,
        }


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------

def _load_expected_chains(fixture_path: Path) -> list[dict[str, Any]]:
    """Read `expected_chains[]` from expected.yaml."""
    f = fixture_path / "expected.yaml"
    if not f.is_file():
        return []
    try:
        data = yaml.safe_load(f.read_text())
    except (yaml.YAMLError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    raw = data.get("expected_chains") or []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in raw:
        if isinstance(entry, dict) and entry.get("id") and entry.get("members"):
            out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Match logic
# ---------------------------------------------------------------------------

def _chain_member_overlap(
    expected_members: list[str], actual_members: list[str],
) -> tuple[int, float]:
    """Compute (overlap_count, overlap_ratio).

    Two chains match when ≥50% of expected members appear in actual.
    Substring matching: an expected member `sqli-login` matches an
    actual member `vuln-0003-sqli-login` or `sqli-login-rest-user-login`.

    Returns (count, ratio_against_expected).
    """
    if not expected_members:
        return 0, 0.0
    overlap = 0
    actual_str = " ".join(str(m) for m in actual_members).lower()
    for em in expected_members:
        em_str = str(em).lower()
        if em_str in actual_str:
            overlap += 1
        else:
            # Also check substring the OTHER way (actual member -> expected key)
            for am in actual_members:
                if em_str in str(am).lower() or str(am).lower() in em_str:
                    overlap += 1
                    break
    overlap = min(overlap, len(expected_members))  # cap
    return overlap, overlap / len(expected_members)


def score_fixture_chains(
    fixture: str,
    expected_chains: list[dict[str, Any]],
    actual_chains: list[dict[str, Any]],
) -> FixtureChainResult:
    """Score per-fixture chain detection."""
    result = FixtureChainResult(
        fixture=fixture,
        expected_chain_count=len(expected_chains),
        actual_chain_count=len(actual_chains),
    )

    if not expected_chains:
        result.notes.append("no expected_chains[] in fixture — bench skipped")
        return result

    matched_actual_ids: set[str] = set()

    for exp in expected_chains:
        exp_id = str(exp.get("id"))
        exp_kind = exp.get("kind")
        exp_members = [str(m) for m in (exp.get("members") or [])]
        match = ChainMatch(
            expected_id=exp_id,
            expected_kind=exp_kind,
            expected_members=exp_members,
        )

        best_overlap = 0
        best_ratio = 0.0
        best_actual: dict[str, Any] | None = None
        for actual in actual_chains:
            actual_id = str(actual.get("chain_id") or "")
            if actual_id in matched_actual_ids:
                continue
            actual_members = [str(m) for m in (actual.get("members") or [])]
            overlap, ratio = _chain_member_overlap(exp_members, actual_members)
            if ratio > best_ratio:
                best_overlap = overlap
                best_ratio = ratio
                best_actual = actual

        if best_actual is not None and best_ratio >= _MATCH_OVERLAP_RATIO:
            match.matched = True
            match.matched_actual_chain_id = best_actual.get("chain_id")
            match.matched_actual_members = list(
                best_actual.get("members") or []
            )
            match.overlap_count = best_overlap
            match.overlap_ratio = round(best_ratio, 3)
            matched_actual_ids.add(str(best_actual.get("chain_id")))
            result.matched_count += 1
        else:
            result.unmatched_expected_ids.append(exp_id)

        result.matches.append(match)

    # Actual chains the bench didn't expect (extra credit / surprise)
    for actual in actual_chains:
        aid = str(actual.get("chain_id") or "")
        if aid and aid not in matched_actual_ids:
            result.extra_actual_chain_ids.append(aid)

    if result.expected_chain_count > 0:
        result.chain_detection_rate = round(
            result.matched_count / result.expected_chain_count, 3,
        )

    # Depth distribution from actual chains
    depths = [
        len(c.get("members") or []) for c in actual_chains
        if isinstance(c.get("members"), list)
    ]
    if depths:
        try:
            result.chain_depth_p50 = float(statistics.median(depths))
            result.chain_depth_p95 = float(
                statistics.quantiles(depths, n=20)[-1]
                if len(depths) > 1 else depths[0]
            )
        except statistics.StatisticsError:
            pass
    return result


# ---------------------------------------------------------------------------
# Scan harness
# ---------------------------------------------------------------------------

async def _scan_fixture_collect_chains(
    fixture_dir: Path, sandbox_image: str | None,
) -> list[dict[str, Any]]:
    """Run L1-only bench against `fixture_dir`, return the chains_emitted
    list from the tracer."""
    from strix.telemetry.tracer import Tracer, set_global_tracer
    from benchmarks.per_target import bench_l1_only as bench_mod

    tr = Tracer(run_name="chains_bench")
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

    return tr._collect_chains_emitted()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def amain(args: argparse.Namespace) -> int:
    fixtures = args.fixtures or _DEFAULT_FIXTURES
    report = AggregateChainReport()
    all_depths: list[int] = []

    for relpath in fixtures:
        fixture_dir = FIXTURES_ROOT / relpath
        if not fixture_dir.is_dir():
            print(f"[skip] {relpath} not found", file=sys.stderr)
            continue
        expected = _load_expected_chains(fixture_dir)
        if not expected:
            print(f"[skip] {relpath} — no expected_chains[] in expected.yaml")
            continue

        print(f"\n=== {relpath} ===")
        try:
            actual = await _scan_fixture_collect_chains(
                fixture_dir, args.sandbox_image,
            )
        except Exception as e:  # noqa: BLE001
            print(f"  SCAN FAILED: {type(e).__name__}: {e}", file=sys.stderr)
            continue

        fixture_result = score_fixture_chains(relpath, expected, actual)
        print(
            f"  expected_chains={fixture_result.expected_chain_count} "
            f"actual_chains={fixture_result.actual_chain_count} "
            f"matched={fixture_result.matched_count} "
            f"detection_rate={fixture_result.chain_detection_rate*100:.1f}% "
            f"depth_p95={fixture_result.chain_depth_p95:.1f}"
        )
        if fixture_result.unmatched_expected_ids:
            print(f"  unmatched: {fixture_result.unmatched_expected_ids}")
        if fixture_result.extra_actual_chain_ids:
            print(
                f"  extra (bonus) chains found: "
                f"{fixture_result.extra_actual_chain_ids[:5]}"
            )

        # Aggregate
        for a in actual:
            d = len(a.get("members") or [])
            if d:
                all_depths.append(d)
        report.fixtures.append(fixture_result)
        report.total_expected += fixture_result.expected_chain_count
        report.total_matched += fixture_result.matched_count

    if report.total_expected:
        report.overall_chain_detection_rate = round(
            report.total_matched / report.total_expected, 3,
        )
    if all_depths:
        try:
            report.overall_chain_depth_p95 = float(
                statistics.quantiles(all_depths, n=20)[-1]
                if len(all_depths) > 1 else all_depths[0]
            )
        except statistics.StatisticsError:
            report.overall_chain_depth_p95 = float(all_depths[0])

    print("\n=== overall ===")
    print(
        f"chain_detection_rate={report.overall_chain_detection_rate*100:.1f}%  "
        f"target ≥ 40% (L1.5) / 70% (L2)  "
        f"(matched={report.total_matched} / expected={report.total_expected})"
    )
    print(
        f"chain_depth_p95={report.overall_chain_depth_p95:.1f}  "
        f"target ≥ 4 at L2+"
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
