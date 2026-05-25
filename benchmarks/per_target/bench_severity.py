"""iter-31.3 — Severity calibration bench.

Measures whether the severity tier emitted on each finding matches the
ground-truth tier declared in `expected.yaml`. Per docs/metrics.md §1.2,
`severity_tier_accuracy` is the L1.5 metric that determines whether the
"this is CRITICAL" badge on the dashboard is trustworthy or noise.

When L1.5's `surface_priority` + `exploitability` adjusters fire, they
mutate `finding.severity` (and write a reasoning_trace line). This bench
scores the FINAL severity (post-L1.5) against the fixture's ground-truth
tier.

**Inputs:**

  * Each fixture's `expected.yaml` already carries `severity:` per
    `expected_findings[]` entry. No new schema field required — we
    simply consume what's already there. Fixtures MAY override with
    `expected_severity_tier:` if the technical severity differs from
    the calibrated tier (e.g., a CVSS-9.8 SSRF that L1.5 should
    nonetheless rate `high` because the target is non-prod).

  * Actual findings are read from
    `summary.tool_results[].raw_result.findings` (the same harness
    bench_l1_only uses). Severity is taken AFTER L1.5 mutation —
    that's the agent-visible tier.

**Match logic:**

  An expected finding matches an actual finding by `category` +
  one of `file` / `endpoint` (substring match either direction).
  Defensive: don't credit "right severity, wrong finding."

**Tiers:**

  Severity tiers compared in canonical order:
  `info < low < medium < high < critical`. Unknown / missing tiers
  count as `info`. The bench reports both:
    * `severity_tier_accuracy` — strict equality
    * `severity_tier_accuracy_within_1` — off-by-one (medium-vs-high
      is OK but medium-vs-critical is not)

**Anti-overfit:**

  * The scorer never references SUT-specific values (no juice-shop /
    vampi identifiers in the source — guard test enforces).
  * Match logic uses `category` taxonomy (sqli/xss/idor/…) +
    file/endpoint substring — generic, applies to any fixture.

Usage:

    python -m benchmarks.per_target.bench_severity
    python -m benchmarks.per_target.bench_severity --fixture web/juiceshop
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


# Canonical severity ordering. info=0 … critical=4. Anything else maps
# to "info" so we don't crash on garbage; the per-finding match record
# carries the raw value so the noise is visible in output.
_TIER_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _normalize_tier(s: Any) -> str:
    if not isinstance(s, str):
        return "info"
    v = s.strip().lower()
    return v if v in _TIER_RANK else "info"


def _tier_distance(a: str, b: str) -> int:
    return abs(_TIER_RANK[_normalize_tier(a)] - _TIER_RANK[_normalize_tier(b)])


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SeverityMatch:
    expected_id: str
    expected_category: str | None
    expected_severity: str
    actual_severity: str | None = None
    actual_title: str | None = None
    matched: bool = False  # found a corresponding actual finding
    severity_exact_match: bool = False
    severity_within_1_match: bool = False
    distance: int | None = None  # tier-distance when matched

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FixtureSeverityResult:
    fixture: str
    expected_count: int = 0
    matched_count: int = 0  # how many expected findings had a corresponding actual
    exact_count: int = 0  # strict tier equality among matched
    within_1_count: int = 0  # off-by-one or better among matched
    severity_tier_accuracy: float = 0.0
    severity_tier_accuracy_within_1: float = 0.0
    matches: list[SeverityMatch] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            **{k: v for k, v in asdict(self).items() if k != "matches"},
            "matches": [m.to_dict() for m in self.matches],
        }


@dataclass
class AggregateSeverityReport:
    fixtures: list[FixtureSeverityResult] = field(default_factory=list)
    total_expected: int = 0
    total_matched: int = 0
    total_exact: int = 0
    total_within_1: int = 0
    overall_severity_tier_accuracy: float = 0.0
    overall_severity_tier_accuracy_within_1: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixtures": [f.to_dict() for f in self.fixtures],
            "total_expected": self.total_expected,
            "total_matched": self.total_matched,
            "total_exact": self.total_exact,
            "total_within_1": self.total_within_1,
            "overall_severity_tier_accuracy": self.overall_severity_tier_accuracy,
            "overall_severity_tier_accuracy_within_1":
                self.overall_severity_tier_accuracy_within_1,
        }


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _load_expected_findings(fixture_path: Path) -> list[dict[str, Any]]:
    """Read `expected_findings[]` from expected.yaml; preserves all keys.
    Returns empty list on missing / malformed file."""
    f = fixture_path / "expected.yaml"
    if not f.is_file():
        return []
    try:
        data = yaml.safe_load(f.read_text())
    except (yaml.YAMLError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    raw = data.get("expected_findings") or []
    if not isinstance(raw, list):
        return []
    return [e for e in raw if isinstance(e, dict) and e.get("id")]


# ---------------------------------------------------------------------------
# Match logic
# ---------------------------------------------------------------------------

def _finding_matches_expected(
    expected: dict[str, Any], actual: dict[str, Any],
) -> bool:
    """Whether `actual` finding describes the same vuln as `expected`.

    Match conditions (ALL must hold):
      1. `category` matches (substring, case-insensitive). Missing
         category on either side is tolerated when the location matches.
      2. `file` OR `endpoint` substring matches (either direction).

    This is the same shape-matching philosophy used by
    `bench_fp_suppression` — robust to formatting drift between agent
    output and YAML.
    """
    exp_cat = (expected.get("category") or "").strip().lower()
    act_cat = (actual.get("category") or "").strip().lower()
    if exp_cat and act_cat:
        if exp_cat not in act_cat and act_cat not in exp_cat:
            return False

    # Location: file (for code targets) or endpoint (for web/api targets).
    exp_loc = (expected.get("file") or expected.get("endpoint") or "").strip().lower()
    act_loc = (
        actual.get("file")
        or actual.get("endpoint")
        or actual.get("target")
        or ""
    ).strip().lower()
    if exp_loc and act_loc:
        if exp_loc not in act_loc and act_loc not in exp_loc:
            return False
        return True
    # No usable location on one side — fall back to category-only match
    # when both categories were present + matched (already returned above
    # on mismatch). Avoid crediting blindly: require at least category.
    return bool(exp_cat) and bool(act_cat)


def score_fixture_severity(
    fixture: str,
    expected_findings: list[dict[str, Any]],
    actual_findings: list[dict[str, Any]],
) -> FixtureSeverityResult:
    """Per-fixture severity calibration scorer."""
    result = FixtureSeverityResult(
        fixture=fixture,
        expected_count=len(expected_findings),
    )

    if not expected_findings:
        result.notes.append("no expected_findings[] in fixture — bench skipped")
        return result

    used_actual_indices: set[int] = set()

    for exp in expected_findings:
        # Prefer explicit override; otherwise the existing `severity` key.
        exp_sev = _normalize_tier(
            exp.get("expected_severity_tier") or exp.get("severity")
        )
        match = SeverityMatch(
            expected_id=str(exp.get("id")),
            expected_category=exp.get("category"),
            expected_severity=exp_sev,
        )

        # Find the first un-used actual finding that matches.
        for i, actual in enumerate(actual_findings):
            if i in used_actual_indices:
                continue
            if _finding_matches_expected(exp, actual):
                used_actual_indices.add(i)
                match.matched = True
                match.actual_severity = _normalize_tier(actual.get("severity"))
                match.actual_title = actual.get("title")
                d = _tier_distance(exp_sev, match.actual_severity)
                match.distance = d
                match.severity_exact_match = (d == 0)
                match.severity_within_1_match = (d <= 1)
                break

        if match.matched:
            result.matched_count += 1
            if match.severity_exact_match:
                result.exact_count += 1
            if match.severity_within_1_match:
                result.within_1_count += 1

        result.matches.append(match)

    # Accuracy is computed against MATCHED findings (the bench can't
    # grade severity on findings the scanner missed entirely — that's
    # `must_find_recall`'s job, not this metric's).
    if result.matched_count:
        result.severity_tier_accuracy = round(
            result.exact_count / result.matched_count, 3,
        )
        result.severity_tier_accuracy_within_1 = round(
            result.within_1_count / result.matched_count, 3,
        )
    else:
        result.notes.append(
            "no expected findings matched any actual finding — "
            "severity cannot be graded (recall failure upstream)"
        )

    return result


# ---------------------------------------------------------------------------
# Scan harness
# ---------------------------------------------------------------------------

async def _scan_fixture_collect_findings(
    fixture_dir: Path, sandbox_image: str | None,
) -> list[dict[str, Any]]:
    """Run L1-only bench against `fixture_dir`, return the flat list of
    findings from tracer.vulnerability_reports (post-L1.5 mutation)."""
    from strix.telemetry.tracer import Tracer, set_global_tracer
    from benchmarks.per_target import bench_l1_only as bench_mod

    tr = Tracer(run_name="severity_bench")
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

    return list(tr.vulnerability_reports)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def amain(args: argparse.Namespace) -> int:
    fixtures = args.fixtures or _DEFAULT_FIXTURES
    report = AggregateSeverityReport()

    for relpath in fixtures:
        fixture_dir = FIXTURES_ROOT / relpath
        if not fixture_dir.is_dir():
            print(f"[skip] {relpath} not found", file=sys.stderr)
            continue
        expected = _load_expected_findings(fixture_dir)
        if not expected:
            print(f"[skip] {relpath} — no expected_findings[] in expected.yaml")
            continue

        print(f"\n=== {relpath} ===")
        try:
            actual = await _scan_fixture_collect_findings(
                fixture_dir, args.sandbox_image,
            )
        except Exception as e:  # noqa: BLE001
            print(f"  SCAN FAILED: {type(e).__name__}: {e}", file=sys.stderr)
            continue

        fixture_result = score_fixture_severity(relpath, expected, actual)
        print(
            f"  expected={fixture_result.expected_count} "
            f"matched={fixture_result.matched_count} "
            f"exact={fixture_result.exact_count} "
            f"within_1={fixture_result.within_1_count} "
            f"accuracy={fixture_result.severity_tier_accuracy*100:.1f}% "
            f"(within_1={fixture_result.severity_tier_accuracy_within_1*100:.1f}%)"
        )
        if fixture_result.notes:
            for n in fixture_result.notes:
                print(f"  note: {n}")

        report.fixtures.append(fixture_result)
        report.total_expected += fixture_result.expected_count
        report.total_matched += fixture_result.matched_count
        report.total_exact += fixture_result.exact_count
        report.total_within_1 += fixture_result.within_1_count

    if report.total_matched:
        report.overall_severity_tier_accuracy = round(
            report.total_exact / report.total_matched, 3,
        )
        report.overall_severity_tier_accuracy_within_1 = round(
            report.total_within_1 / report.total_matched, 3,
        )

    print("\n=== overall ===")
    print(
        f"severity_tier_accuracy={report.overall_severity_tier_accuracy*100:.1f}%  "
        f"target ≥ 85% (L1.5)  "
        f"(exact={report.total_exact} / matched={report.total_matched})"
    )
    print(
        f"severity_tier_accuracy_within_1="
        f"{report.overall_severity_tier_accuracy_within_1*100:.1f}%"
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
