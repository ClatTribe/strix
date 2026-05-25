"""iter-31.10 — Novel-finding-rate bench.

Scores `novel_finding_rate` (#4 in docs/metrics.md §1.1) — the
fraction of findings that came from L2's AI-specialist pipeline and
do NOT match any known public-corpus signature (KEV / nuclei
templates / semgrep rules / trivy SBOM signatures / SCA lookups).

Why this metric matters
-----------------------
"strix finds the same things nuclei finds" is a fair criticism if
strix's L2 layer just re-implements existing toolchains. Novel-
finding rate is the only metric that proves L2's LLM specialists
discover bugs the open-source corpus doesn't already know about.

Target ≥30% at L2+ per docs/metrics.md — the "humans find things
nuclei can't" axis.

Classification logic (shape-based, not literal value match)
-----------------------------------------------------------
For each finding, derive corpus membership from the finding's own
metadata — never from SUT-specific values:

  * `kev` if a CVE is attached AND the KEV block is listed
    OR `kev_block.listed=True` OR `discovery_method.primary=
    cve_pattern_match`
  * `nuclei` if `rule_id` starts with `nuclei-` OR the
    `discovery_method.primary=nuclei_template`
  * `semgrep` if `rule_id` starts with `semgrep-` / `semgrep:`
  * `trivy` if `rule_id` starts with `trivy-`
  * `bandit` if `rule_id` starts with `bandit-` or `B<digits>`
  * `sca` if `discovery_method.primary=sca_lookup`
  * `sast_rule` if `discovery_method.primary=sast_rule`
  * `nuclei_template` if discovery_method points there
  * `cve_pattern_match` if discovery_method points there
  * `novel` otherwise — AND the finding is L2-emitted
    (`discovery_method.primary=ai_specialist` OR the field is unset).

A finding without ANY corpus membership IS novel — but excluding
the corroborator-role siblings (they're tied to a parent, never
their own novel discovery).

Anti-overfit
------------
- Classification reads only rule_id prefixes + discovery_method
  fields; never SUT identifiers
- Source-grep guard forbids SUT tokens

Usage:

    python -m benchmarks.per_target.bench_novel
"""

from __future__ import annotations

import argparse
import json
import re
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


# Prefix → bucket map. Order matters for "first match wins".
_RULE_PREFIXES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^nuclei[-_:]", re.I), "nuclei"),
    (re.compile(r"^semgrep[-_:]", re.I), "semgrep"),
    (re.compile(r"^trivy[-_:]", re.I), "trivy"),
    (re.compile(r"^bandit[-_:]", re.I), "bandit"),
    (re.compile(r"^B\d{3,}$", re.I), "bandit"),
    (re.compile(r"^safety[-_:]", re.I), "safety"),
    (re.compile(r"^retire[-_:]", re.I), "retire"),
]

# `discovery_method.primary` → bucket map (used when rule_id misses
# a prefix or the corpus origin is encoded on discovery_method).
_PRIMARY_BUCKETS = {
    "cve_pattern_match": "kev",
    "sca_lookup": "sca",
    "sast_rule": "sast_rule",
    "nuclei_template": "nuclei",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FindingNoveltyVerdict:
    finding_id: str | None = None
    title: str | None = None
    severity: str | None = None
    bucket: str = "novel"  # one of the corpus buckets or "novel"
    is_novel: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FixtureNovelResult:
    fixture: str
    findings_total: int = 0
    novel_count: int = 0
    by_bucket: dict[str, int] = field(default_factory=dict)
    novel_finding_rate: float = 0.0
    per_finding: list[FindingNoveltyVerdict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            **{k: v for k, v in asdict(self).items() if k != "per_finding"},
            "per_finding": [f.to_dict() for f in self.per_finding],
        }


@dataclass
class AggregateNovelReport:
    fixtures: list[FixtureNovelResult] = field(default_factory=list)
    total_findings: int = 0
    total_novel: int = 0
    overall_novel_finding_rate: float = 0.0
    aggregate_by_bucket: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixtures": [f.to_dict() for f in self.fixtures],
            "total_findings": self.total_findings,
            "total_novel": self.total_novel,
            "overall_novel_finding_rate": self.overall_novel_finding_rate,
            "aggregate_by_bucket": self.aggregate_by_bucket,
        }


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _classify_finding_novelty(finding: dict[str, Any]) -> str:
    """Return the bucket label for the given finding.

    Buckets: novel / kev / nuclei / semgrep / trivy / bandit /
    safety / retire / sca / sast_rule
    """
    # KEV check first — even an ai_specialist-emitted CVE that lands
    # in KEV isn't novel (the corpus knows about that CVE).
    kev_block = finding.get("kev_block") or {}
    if isinstance(kev_block, dict) and kev_block.get("listed") is True:
        return "kev"
    if finding.get("kev") is True:
        return "kev"

    # rule_id prefix match
    rule_id = finding.get("rule_id")
    if isinstance(rule_id, str):
        for pattern, bucket in _RULE_PREFIXES:
            if pattern.search(rule_id):
                return bucket

    # discovery_method.primary mapping
    dm = finding.get("discovery_method") or {}
    if isinstance(dm, dict):
        primary = str(dm.get("primary") or "").strip().lower()
        if primary in _PRIMARY_BUCKETS:
            return _PRIMARY_BUCKETS[primary]
        # ai_specialist + no CVE = canonical novel
        if primary == "ai_specialist" and not finding.get("cve"):
            return "novel"

    # Fallback: ai_specialist-default path. A finding without any
    # corpus signal lands as novel.
    if not finding.get("cve") and not finding.get("rule_id"):
        return "novel"

    # CVE present but no KEV listing — still "in_corpus" because the
    # CVE itself is a public identifier. Bucket it under `cve` to
    # surface visibility.
    if finding.get("cve"):
        return "cve"

    return "novel"


def score_finding_novelty(finding: dict[str, Any]) -> FindingNoveltyVerdict:
    bucket = _classify_finding_novelty(finding)
    return FindingNoveltyVerdict(
        finding_id=finding.get("id"),
        title=finding.get("title"),
        severity=finding.get("severity"),
        bucket=bucket,
        is_novel=(bucket == "novel"),
    )


def score_fixture_novelty(
    fixture: str, findings: list[dict[str, Any]],
) -> FixtureNovelResult:
    """Per-fixture novelty scorer.

    Excludes corroborator-role siblings (their "novel" status is the
    parent's; double-counting would inflate the rate).
    """
    result = FixtureNovelResult(fixture=fixture)
    if not findings:
        result.notes.append("no findings to score")
        return result

    eligible = [f for f in findings if f.get("role") != "corroborator"]
    result.findings_total = len(eligible)
    if not result.findings_total:
        result.notes.append("all findings were corroborator siblings")
        return result

    for f in eligible:
        v = score_finding_novelty(f)
        result.per_finding.append(v)
        result.by_bucket[v.bucket] = result.by_bucket.get(v.bucket, 0) + 1
        if v.is_novel:
            result.novel_count += 1

    result.novel_finding_rate = round(
        result.novel_count / result.findings_total, 3,
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

    tr = Tracer(run_name="novel_bench")
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
    report = AggregateNovelReport()

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

        r = score_fixture_novelty(relpath, findings)
        print(
            f"  findings={r.findings_total}  novel={r.novel_count}  "
            f"novel_finding_rate={r.novel_finding_rate*100:.1f}%  "
            f"(target ≥ 30% L2+)"
        )
        if r.by_bucket:
            print(f"  by_bucket: {dict(sorted(r.by_bucket.items()))}")
        if r.notes:
            for n in r.notes:
                print(f"  note: {n}")

        report.fixtures.append(r)
        report.total_findings += r.findings_total
        report.total_novel += r.novel_count
        for bucket, c in r.by_bucket.items():
            report.aggregate_by_bucket[bucket] = (
                report.aggregate_by_bucket.get(bucket, 0) + c
            )

    if report.total_findings:
        report.overall_novel_finding_rate = round(
            report.total_novel / report.total_findings, 3,
        )

    print("\n=== overall ===")
    print(
        f"novel_finding_rate={report.overall_novel_finding_rate*100:.1f}%  "
        f"target ≥ 30% (L2+)  "
        f"(novel={report.total_novel} / findings={report.total_findings})"
    )
    if report.aggregate_by_bucket:
        print(f"by_bucket: {dict(sorted(report.aggregate_by_bucket.items()))}")

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
