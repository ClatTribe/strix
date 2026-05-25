"""iter-31.8 — Context-completeness + actionable-rate bench.

Two metrics in one bench (both per-finding field-presence checks):

  * `context_completeness` (#9) — % of findings that carry ALL of:
      file+line / author / fix-hint / exploit-vector / business_impact.
      Target 100% at L1.5 per docs/metrics.md.
  * `actionable_rate` (#22) — % of findings that carry AT LEAST ONE
      concrete next-step field: next_probes_suggested[] /
      remediation_steps / recommended_action / poc_script_code /
      poc_description. Target ≥95% at L2.

The two metrics differ in semantics:
  - context_completeness asks "did the agent populate the rich
    context that lets a security engineer triage in seconds?"
  - actionable_rate asks the weaker "did the agent give me at least
    one thing to DO with this finding?"

Why these matter
----------------
Without these, the L1.5 enrichment work (git_blame, surface_priority,
exploitability) and the L2 agent prompts (recommended_action,
next_probes) are invisible to scoring. A scanner that emits the same
20 findings as ZAP but with full context wins on every dimension
that's visible to the security engineer — but only if the bench can
prove it.

Anti-overfit
------------
- Field-presence checks reference canonical finding keys (file,
  line, author, recommended_action) — not SUT-specific values
- Source-grep guard forbids SUT tokens
- Per-finding match shape is generic (no fixture-specific overrides)

Usage:

    python -m benchmarks.per_target.bench_context
    python -m benchmarks.per_target.bench_context --fixture web/juiceshop
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


# The five context dimensions. A finding scores 1 point per dimension
# present; max=5 → full context. Each is a TUPLE of accepted field
# paths so the bench doesn't crater when a producer uses one of
# several legitimate field names for the same concept.
_CONTEXT_DIMENSIONS: dict[str, tuple[str, ...]] = {
    # Where in the codebase / URL space the finding lives.
    # Either file+line OR endpoint counts. Two paths are tried:
    # explicit `file`/`line`, or `code_locations[0].file/line_number`.
    "location": ("file", "line", "endpoint", "code_locations"),
    # Git-blame author (L1.5 enrichment per iter-25.4).
    "author": ("blame_author", "git_blame", "author"),
    # Concrete remediation guidance.
    "fix_hint": (
        "recommended_action",
        "remediation_steps",
        "fix_hint",
    ),
    # How to exploit it (PoC script, technical_analysis with curl,
    # explicit exploit_vector field, attack_recipe).
    "exploit_vector": (
        "poc_script_code",
        "poc_description",
        "exploit_vector",
        "attack_recipe",
        "technical_analysis",
    ),
    # Business / blast-radius framing (the non-technical priority).
    "business_impact": (
        "business_impact_plain",
        "impact",
        "contextual_priority",
    ),
}


# Concrete next-step fields. ANY ONE of these populated counts the
# finding as actionable.
_ACTIONABLE_FIELDS: tuple[str, ...] = (
    "next_probes_suggested",
    "recommended_action",
    "remediation_steps",
    "poc_script_code",
    "poc_description",
    "fix_hint",
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FindingContextScore:
    finding_id: str | None = None
    title: str | None = None
    severity: str | None = None
    dimensions_present: list[str] = field(default_factory=list)
    dimensions_missing: list[str] = field(default_factory=list)
    # iter-32.3 — dimensions that don't apply to this finding's target
    # type (e.g. `author` for a web/api finding with no file path —
    # git_blame is meaningless on a remote URL). Excluded from the
    # denominator so context_completeness measures "what the agent
    # could populate" rather than penalizing structurally-N/A signals.
    dimensions_not_applicable: list[str] = field(default_factory=list)
    actionable: bool = False
    actionable_field: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FixtureContextResult:
    fixture: str
    findings_total: int = 0
    findings_with_full_context: int = 0  # all 5 dimensions present
    findings_actionable: int = 0          # ≥1 next-step field populated
    context_completeness: float = 0.0
    actionable_rate: float = 0.0
    per_dimension_presence: dict[str, int] = field(default_factory=dict)
    per_finding: list[FindingContextScore] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            **{k: v for k, v in asdict(self).items() if k != "per_finding"},
            "per_finding": [f.to_dict() for f in self.per_finding],
        }


@dataclass
class AggregateContextReport:
    fixtures: list[FixtureContextResult] = field(default_factory=list)
    total_findings: int = 0
    total_with_full_context: int = 0
    total_actionable: int = 0
    overall_context_completeness: float = 0.0
    overall_actionable_rate: float = 0.0
    aggregate_dimension_presence: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixtures": [f.to_dict() for f in self.fixtures],
            "total_findings": self.total_findings,
            "total_with_full_context": self.total_with_full_context,
            "total_actionable": self.total_actionable,
            "overall_context_completeness": self.overall_context_completeness,
            "overall_actionable_rate": self.overall_actionable_rate,
            "aggregate_dimension_presence": self.aggregate_dimension_presence,
        }


# ---------------------------------------------------------------------------
# Per-finding presence check
# ---------------------------------------------------------------------------

def _field_populated(finding: dict[str, Any], path: str) -> bool:
    """Check whether `finding[path]` is meaningfully populated.

    Accepts non-empty strings, non-empty lists, non-empty dicts.
    `False` / `0` / `None` / `""` / `[]` / `{}` count as missing
    so the bench doesn't credit placeholder values.
    """
    v = finding.get(path)
    if v is None:
        return False
    if isinstance(v, str):
        return bool(v.strip())
    if isinstance(v, (list, tuple, dict, set)):
        return len(v) > 0
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return True


def _has_file_location(finding: dict[str, Any]) -> bool:
    """Is this finding tied to a file in source code (i.e. a target the
    `author` / git_blame dimension can meaningfully apply to)?

    iter-32.3 — true when the finding carries a `file` field OR a
    `code_locations[].file` entry. False when the only locator is an
    `endpoint` URL (= web/api target — no source to git-blame).
    """
    if _field_populated(finding, "file"):
        return True
    cl = finding.get("code_locations")
    if isinstance(cl, list):
        for entry in cl:
            if isinstance(entry, dict) and entry.get("file"):
                return True
    return False


def _dimension_applicable(finding: dict[str, Any], dim: str) -> bool:
    """iter-32.3 — whether the dimension can be populated at all for
    this finding's target shape.

    Currently the only structurally-N/A dimension is `author` on
    findings that have NO file location (only an endpoint). git_blame
    requires source code; a remote DAST finding against a Docker
    image can't produce one.

    Other dimensions are always applicable — the agent could in
    principle populate impact / fix_hint / exploit / location on any
    finding regardless of target type.
    """
    if dim == "author":
        return _has_file_location(finding)
    return True


def _dimension_satisfied(finding: dict[str, Any], dim: str) -> bool:
    """For the LOCATION dimension specifically, require BOTH file+line OR
    code_locations OR endpoint; for the others, any single field path
    being populated counts."""
    if dim == "location":
        # file+line counts
        has_filel = (
            _field_populated(finding, "file")
            and _field_populated(finding, "line")
        )
        if has_filel:
            return True
        # code_locations[0].{file, line_number} counts
        cl = finding.get("code_locations")
        if isinstance(cl, list) and cl:
            first = cl[0] if isinstance(cl[0], dict) else None
            if first and first.get("file") and (
                first.get("line") or first.get("line_number")
            ):
                return True
        # bare endpoint counts (web/api targets)
        if _field_populated(finding, "endpoint"):
            return True
        return False

    # Default: any of the accepted paths populated
    paths = _CONTEXT_DIMENSIONS.get(dim, ())
    return any(_field_populated(finding, p) for p in paths)


def _actionable_field(finding: dict[str, Any]) -> str | None:
    """First populated next-step field path; None if none."""
    for path in _ACTIONABLE_FIELDS:
        if _field_populated(finding, path):
            return path
    return None


def score_finding_context(finding: dict[str, Any]) -> FindingContextScore:
    """Per-finding context + actionable scorer.

    iter-32.3 — dimensions are categorised in this order:
      1. POPULATED → `present` (always counts, even on a target type
         where the dimension is structurally N/A — if the agent
         supplied the data, credit the agent).
      2. EMPTY + applicable → `missing` (the agent could and should
         have populated it).
      3. EMPTY + not applicable → `not_applicable` (structurally
         impossible for this target shape — e.g. git_blame for an
         endpoint-only DAST finding with no source file).
    Only `missing` reflects an agent failure; `not_applicable` is
    excluded from the context_completeness denominator.
    """
    score = FindingContextScore(
        finding_id=finding.get("id"),
        title=finding.get("title"),
        severity=finding.get("severity"),
    )
    for dim in _CONTEXT_DIMENSIONS:
        if _dimension_satisfied(finding, dim):
            score.dimensions_present.append(dim)
        elif _dimension_applicable(finding, dim):
            score.dimensions_missing.append(dim)
        else:
            score.dimensions_not_applicable.append(dim)
    af = _actionable_field(finding)
    if af:
        score.actionable = True
        score.actionable_field = af
    return score


def score_fixture_context(
    fixture: str, findings: list[dict[str, Any]],
) -> FixtureContextResult:
    """Per-fixture context + actionable scorer.

    Excludes corroborator-role siblings (their context is the
    parent's; double-counting would conflate).
    """
    result = FixtureContextResult(fixture=fixture)

    if not findings:
        result.notes.append("no findings to score")
        return result

    eligible_findings = [
        f for f in findings if f.get("role") != "corroborator"
    ]
    result.findings_total = len(eligible_findings)
    if not result.findings_total:
        result.notes.append(
            "all findings were corroborator-role siblings — nothing to score"
        )
        return result

    # Per-dimension presence counters
    dim_counts: dict[str, int] = {dim: 0 for dim in _CONTEXT_DIMENSIONS}

    for f in eligible_findings:
        s = score_finding_context(f)
        result.per_finding.append(s)
        # iter-32.3 — "full context" means every APPLICABLE dimension
        # is present. Findings on web/api targets won't have `author`
        # (no source to git-blame); penalising them for that
        # structurally-N/A dimension produced 0% on the v1/v2/v3 L2
        # Juice Shop runs even though impact/fix/exploit/location/PoC
        # were all populated.
        applicable_count = (
            len(_CONTEXT_DIMENSIONS) - len(s.dimensions_not_applicable)
        )
        if applicable_count > 0 and len(s.dimensions_present) == applicable_count:
            result.findings_with_full_context += 1
        if s.actionable:
            result.findings_actionable += 1
        for dim in s.dimensions_present:
            dim_counts[dim] = dim_counts.get(dim, 0) + 1

    result.per_dimension_presence = dim_counts
    result.context_completeness = round(
        result.findings_with_full_context / result.findings_total, 3,
    )
    result.actionable_rate = round(
        result.findings_actionable / result.findings_total, 3,
    )

    return result


# ---------------------------------------------------------------------------
# Scan harness
# ---------------------------------------------------------------------------

async def _scan_fixture_collect_findings(
    fixture_dir: Path, sandbox_image: str | None,
) -> list[dict[str, Any]]:
    from strix.telemetry.tracer import Tracer, set_global_tracer
    from benchmarks.per_target import bench_l1_only as bench_mod

    tr = Tracer(run_name="context_bench")
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
    report = AggregateContextReport()

    for relpath in fixtures:
        fixture_dir = FIXTURES_ROOT / relpath
        if not fixture_dir.is_dir():
            print(f"[skip] {relpath} not found", file=sys.stderr)
            continue

        print(f"\n=== {relpath} ===")
        try:
            findings = await _scan_fixture_collect_findings(
                fixture_dir, args.sandbox_image,
            )
        except Exception as e:  # noqa: BLE001
            print(f"  SCAN FAILED: {type(e).__name__}: {e}", file=sys.stderr)
            continue

        r = score_fixture_context(relpath, findings)
        print(
            f"  findings={r.findings_total}  "
            f"full_context={r.findings_with_full_context}  "
            f"actionable={r.findings_actionable}  "
            f"context_completeness={r.context_completeness*100:.1f}% "
            f"(target 100%) "
            f"actionable_rate={r.actionable_rate*100:.1f}% (target ≥95%)"
        )
        if r.per_dimension_presence:
            print(
                f"  per_dimension: "
                f"{dict(sorted(r.per_dimension_presence.items()))}"
            )
        if r.notes:
            for n in r.notes:
                print(f"  note: {n}")

        report.fixtures.append(r)
        report.total_findings += r.findings_total
        report.total_with_full_context += r.findings_with_full_context
        report.total_actionable += r.findings_actionable
        for dim, c in r.per_dimension_presence.items():
            report.aggregate_dimension_presence[dim] = (
                report.aggregate_dimension_presence.get(dim, 0) + c
            )

    if report.total_findings:
        report.overall_context_completeness = round(
            report.total_with_full_context / report.total_findings, 3,
        )
        report.overall_actionable_rate = round(
            report.total_actionable / report.total_findings, 3,
        )

    print("\n=== overall ===")
    print(
        f"context_completeness="
        f"{report.overall_context_completeness*100:.1f}%  "
        f"target 100% (L1.5)  "
        f"(full_context={report.total_with_full_context} / "
        f"findings={report.total_findings})"
    )
    print(
        f"actionable_rate={report.overall_actionable_rate*100:.1f}%  "
        f"target ≥ 95% (L2)  "
        f"(actionable={report.total_actionable})"
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
