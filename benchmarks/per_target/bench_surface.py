"""iter-31.9 — Surface-discovery-breadth bench.

Reads `endpoints_discovered_total` from `Tracer.build_run_summary()`
(surfaced via iter-31.9 hook on workflow_state) and divides against
the fixture's `expected_endpoint_count` to score
`surface_discovery_breadth` (#5 in docs/metrics.md §1.1).

Why this metric matters
-----------------------
Recall on a vuln scanner is bounded by recall on surface enumeration —
you can't find SQLi on a route you never visited. Target ≥85% at L1.5
(katana crawl + openapi spec ingest + JS bundle parsing should
collectively discover ≥85% of an app's HTTP routes).

Fixture YAML overlay
--------------------

    expected_endpoint_count: <int>   # curated floor

When the overlay is absent, the bench reports the absolute count
without computing a rate.

Anti-overfit
------------
- Bench reads only the canonical count, never URL paths
- Per-fixture `expected_endpoint_count` is a curated LOWER bound,
  not a list of paths — fixture authors can't accidentally couple
  recall to one fixture's specific routes
- Source-grep guard forbids SUT tokens

Usage:

    python -m benchmarks.per_target.bench_surface
"""

from __future__ import annotations

import argparse
import json
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


_DEFAULT_FIXTURES = [
    "code/flask-vuln",
    "api/vampi",
    "web/juiceshop",
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FixtureSurfaceResult:
    fixture: str
    expected_endpoint_count: int | None = None
    actual_endpoint_count: int = 0
    actual_endpoints_pre_auth: int = 0
    actual_endpoints_post_auth: int = 0
    surface_discovery_breadth: float = 0.0  # 0.0–1.0+ (capped at 1.0)
    over_discovery: bool = False  # true when actual > expected
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AggregateSurfaceReport:
    fixtures: list[FixtureSurfaceResult] = field(default_factory=list)
    total_expected: int = 0
    total_actual: int = 0
    overall_surface_discovery_breadth: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixtures": [f.to_dict() for f in self.fixtures],
            "total_expected": self.total_expected,
            "total_actual": self.total_actual,
            "overall_surface_discovery_breadth":
                self.overall_surface_discovery_breadth,
        }


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _load_expected_endpoint_count(fixture_path: Path) -> int | None:
    """Read `expected_endpoint_count` from expected.yaml. Returns None
    when missing or malformed — the bench reports absolute count
    without a rate in that case."""
    f = fixture_path / "expected.yaml"
    if not f.is_file():
        return None
    try:
        data = yaml.safe_load(f.read_text())
    except (yaml.YAMLError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    raw = data.get("expected_endpoint_count")
    try:
        n = int(raw)
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Score logic
# ---------------------------------------------------------------------------

def score_fixture_surface(
    fixture: str,
    expected_count: int | None,
    run_summary: dict[str, Any],
) -> FixtureSurfaceResult:
    """Per-fixture surface-discovery-breadth scorer.

    `run_summary` is `Tracer.build_run_summary()`. Reads
    `endpoints_discovered_*` keys surfaced by iter-31.9.

    When `expected_count` is None, the bench can't compute a rate; it
    reports the absolute count with a note so the operator knows the
    fixture is missing the YAML overlay.
    """
    result = FixtureSurfaceResult(
        fixture=fixture,
        expected_endpoint_count=expected_count,
    )

    if not isinstance(run_summary, dict):
        result.notes.append("run_summary not a dict — bench skipped")
        return result

    total = int(run_summary.get("endpoints_discovered_total") or 0)
    pre = int(run_summary.get("endpoints_discovered_pre_auth") or 0)
    post = int(run_summary.get("endpoints_discovered_post_auth") or 0)
    result.actual_endpoint_count = total
    result.actual_endpoints_pre_auth = pre
    result.actual_endpoints_post_auth = post

    if expected_count is None:
        result.notes.append(
            "no `expected_endpoint_count` in expected.yaml — "
            "rate cannot be computed (reporting absolute count only)"
        )
        return result

    # Cap rate at 1.0 — discovering MORE endpoints than expected is a
    # win but it shouldn't inflate the metric beyond 100%. We track
    # the over-discovery as a separate flag so it's visible.
    raw_rate = total / expected_count if expected_count else 0.0
    result.over_discovery = raw_rate > 1.0
    result.surface_discovery_breadth = round(min(raw_rate, 1.0), 3)

    return result


# ---------------------------------------------------------------------------
# Scan harness
# ---------------------------------------------------------------------------

async def _scan_fixture_collect_summary(
    fixture_dir: Path, sandbox_image: str | None,
) -> dict[str, Any]:
    from strix.telemetry.tracer import Tracer, set_global_tracer
    from benchmarks.per_target import bench_l1_only as bench_mod

    tr = Tracer(run_name="surface_bench")
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
    report = AggregateSurfaceReport()

    for relpath in fixtures:
        fixture_dir = FIXTURES_ROOT / relpath
        if not fixture_dir.is_dir():
            print(f"[skip] {relpath} not found", file=sys.stderr)
            continue
        expected_count = _load_expected_endpoint_count(fixture_dir)
        if expected_count is None:
            print(
                f"[skip] {relpath} — no `expected_endpoint_count` "
                f"in expected.yaml"
            )
            continue

        print(f"\n=== {relpath} ===")
        try:
            summary = await _scan_fixture_collect_summary(
                fixture_dir, args.sandbox_image,
            )
        except Exception as e:  # noqa: BLE001
            print(f"  SCAN FAILED: {type(e).__name__}: {e}", file=sys.stderr)
            continue

        r = score_fixture_surface(relpath, expected_count, summary)
        print(
            f"  expected={r.expected_endpoint_count}  "
            f"actual={r.actual_endpoint_count} "
            f"(pre_auth={r.actual_endpoints_pre_auth}, "
            f"post_auth={r.actual_endpoints_post_auth})  "
            f"breadth={r.surface_discovery_breadth*100:.1f}% "
            f"(target ≥85% L1.5)"
        )
        if r.over_discovery:
            print(
                f"  note: over-discovered "
                f"(found {r.actual_endpoint_count} > expected "
                f"{r.expected_endpoint_count})"
            )
        if r.notes:
            for n in r.notes:
                print(f"  note: {n}")

        report.fixtures.append(r)
        if r.expected_endpoint_count is not None:
            report.total_expected += r.expected_endpoint_count
        report.total_actual += r.actual_endpoint_count

    if report.total_expected:
        report.overall_surface_discovery_breadth = round(
            min(report.total_actual / report.total_expected, 1.0), 3,
        )

    print("\n=== overall ===")
    print(
        f"surface_discovery_breadth="
        f"{report.overall_surface_discovery_breadth*100:.1f}%  "
        f"target ≥ 85% (L1.5)  "
        f"(actual={report.total_actual} / expected={report.total_expected})"
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
