"""iter-31.12 — Explanation-clarity bench (LLM-as-judge + heuristic).

Scores `explanation_clarity` (#21 in docs/metrics.md §1.5) — how
clear, actionable, and reasoned each finding's `description` field is.
Target ≥4.0 / 5.0 at L2 per docs/metrics.md.

Two modes for the per-finding 1-5 score:

  1. **Heuristic (default)** — deterministic, no LLM call. Scores
     based on field presence + structure (does the description
     mention impact? exploit? remediation? line numbers?). Catches
     "obviously bad" explanations (one-liners, jargon-only) without
     LLM cost — good signal for CI without burning tokens.

  2. **LLM-as-judge (opt-in via `--llm <model>`)** — routes each
     finding's explanation through Claude/Gemini, scoring against a
     rubric (clarity / actionability / reasoning). Slower + costs
     tokens but more accurate. Falls back to heuristic when the LLM
     call fails or no API key is configured.

Rubric (both modes target the same 1-5 scale):

  5 = "I understood the bug + fix in 30 seconds. Plain English + a
      concrete next step + clear exploit description."
  4 = "I understood after one read. Could explain to dev."
  3 = "I had to re-read. Some jargon. Fix step is implicit."
  2 = "Required external research to understand. Vague."
  1 = "Useless. One-line + acronyms. Or just a CVE ID."

Anti-overfit
------------
- Heuristic reads canonical field names only (description,
  description_plain, business_impact_plain, recommended_action,
  remediation_steps) — never SUT identifiers
- LLM prompt mentions no SUT-specific values; the prompt template
  is in this file and source-grep guard tests forbid SUT tokens
- Per-finding token-budget cap (~600 input tokens) keeps the
  per-PR cost bounded even on large scans

Usage:

    # Offline / heuristic mode (default, no LLM)
    python -m benchmarks.per_target.bench_explanation \\
        --input strix_runs/<run>/run_summary.json

    # LLM-as-judge mode
    python -m benchmarks.per_target.bench_explanation \\
        --input strix_runs/<run>/run_summary.json \\
        --llm anthropic/claude-sonnet-4-5
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Heuristic scoring rubric
# ---------------------------------------------------------------------------

# Each criterion contributes 0-1 to a raw 0-7 score that gets mapped
# to the 1-5 bench scale. Designed to land most _bad_ explanations at
# 1-2 and most _good_ ones at 4-5, with the inevitable noise in 2-4.
_HEURISTIC_CRITERIA = {
    "has_description":          1.0,   # finding has a description field at all
    "description_minlen":       1.0,   # >= 60 chars
    "description_maxlen_ok":    0.5,   # <= 2000 chars (penalize wall-of-text)
    "has_impact":               1.0,   # business_impact_plain populated
    "has_remediation":          1.0,   # recommended_action / remediation_steps
    "has_exploit_demo":         1.0,   # poc_script_code or poc_description
    "no_unexplained_acronym":   0.5,   # at most 2 bare acronyms in description
    "mentions_location":        1.0,   # file:line OR endpoint mentioned in description
}

_MAX_RAW = sum(_HEURISTIC_CRITERIA.values())  # 7.0
# Map: 0-7 raw → 1-5 scale (linear, then clamp). 0 raw → 1.0, 7 raw → 5.0
# So scale = 1 + (raw / 7) * 4
_BARE_ACRONYM = re.compile(r"\b[A-Z]{3,8}\b")


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ExplanationVerdict:
    finding_id: str | None = None
    title: str | None = None
    severity: str | None = None
    score: float = 0.0  # 1-5 scale
    rubric_breakdown: dict[str, float] = field(default_factory=dict)
    judge: str = "heuristic"  # "heuristic" or "<model>"
    rationale: str | None = None  # one-line explanation

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FixtureExplanationResult:
    fixture: str
    findings_total: int = 0
    average_score: float = 0.0
    p50_score: float = 0.0
    p10_score: float = 0.0  # worst-decile score — catches "any really bad ones"
    per_finding: list[ExplanationVerdict] = field(default_factory=list)
    by_score_band: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            **{k: v for k, v in asdict(self).items() if k != "per_finding"},
            "per_finding": [f.to_dict() for f in self.per_finding],
        }


@dataclass
class AggregateExplanationReport:
    fixtures: list[FixtureExplanationResult] = field(default_factory=list)
    total_findings: int = 0
    overall_average_score: float = 0.0
    overall_p50_score: float = 0.0
    overall_p10_score: float = 0.0
    overall_by_score_band: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixtures": [f.to_dict() for f in self.fixtures],
            "total_findings": self.total_findings,
            "overall_average_score": self.overall_average_score,
            "overall_p50_score": self.overall_p50_score,
            "overall_p10_score": self.overall_p10_score,
            "overall_by_score_band": self.overall_by_score_band,
        }


# ---------------------------------------------------------------------------
# Heuristic scorer
# ---------------------------------------------------------------------------

def _location_mentioned_in_description(
    description: str, finding: dict[str, Any],
) -> bool:
    """Does the description mention the location (file/line/endpoint)?
    Substring match — checks each of the finding's location fields
    against the description text."""
    d = (description or "").lower()
    if not d:
        return False
    for key in ("file", "endpoint", "method", "target"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip().lower() in d:
            return True
    # Mention of a line number (`line 22` / `line:22` / `:22`)
    if re.search(r"\bline[\s:=]+\d+\b", d):
        return True
    # Mention of code_locations.line_number
    cl = finding.get("code_locations") or []
    if isinstance(cl, list):
        for entry in cl:
            if isinstance(entry, dict):
                ln = entry.get("line") or entry.get("line_number")
                if ln and str(ln) in d:
                    return True
    return False


def score_finding_heuristic(finding: dict[str, Any]) -> ExplanationVerdict:
    """Per-finding heuristic 1-5 score."""
    description = finding.get("description") or finding.get("description_plain") or ""
    if not isinstance(description, str):
        description = ""

    breakdown: dict[str, float] = {}

    breakdown["has_description"] = (
        _HEURISTIC_CRITERIA["has_description"] if description.strip() else 0.0
    )
    breakdown["description_minlen"] = (
        _HEURISTIC_CRITERIA["description_minlen"]
        if len(description) >= 60 else 0.0
    )
    breakdown["description_maxlen_ok"] = (
        _HEURISTIC_CRITERIA["description_maxlen_ok"]
        if 0 < len(description) <= 2000 else 0.0
    )
    breakdown["has_impact"] = (
        _HEURISTIC_CRITERIA["has_impact"]
        if (finding.get("business_impact_plain") or finding.get("impact"))
        else 0.0
    )
    breakdown["has_remediation"] = (
        _HEURISTIC_CRITERIA["has_remediation"]
        if (finding.get("recommended_action") or finding.get("remediation_steps"))
        else 0.0
    )
    breakdown["has_exploit_demo"] = (
        _HEURISTIC_CRITERIA["has_exploit_demo"]
        if (finding.get("poc_script_code") or finding.get("poc_description"))
        else 0.0
    )
    breakdown["no_unexplained_acronym"] = (
        _HEURISTIC_CRITERIA["no_unexplained_acronym"]
        if len(_BARE_ACRONYM.findall(description)) <= 2 else 0.0
    )
    breakdown["mentions_location"] = (
        _HEURISTIC_CRITERIA["mentions_location"]
        if _location_mentioned_in_description(description, finding) else 0.0
    )

    raw = sum(breakdown.values())
    # Map 0-7 → 1-5 with clamp
    score = 1.0 + (raw / _MAX_RAW) * 4.0
    score = max(1.0, min(5.0, round(score, 2)))

    return ExplanationVerdict(
        finding_id=finding.get("id"),
        title=finding.get("title"),
        severity=finding.get("severity"),
        score=score,
        rubric_breakdown=breakdown,
        judge="heuristic",
        rationale=(
            f"raw={raw:.1f}/{_MAX_RAW:.1f}  "
            f"len={len(description)} "
            f"impact={'y' if breakdown['has_impact'] else 'n'} "
            f"remediation={'y' if breakdown['has_remediation'] else 'n'} "
            f"poc={'y' if breakdown['has_exploit_demo'] else 'n'}"
        ),
    )


# ---------------------------------------------------------------------------
# LLM-as-judge scorer (opt-in via --llm <model>)
# ---------------------------------------------------------------------------

_LLM_PROMPT_TEMPLATE = """\
You are evaluating the quality of a security finding's explanation
on a 1-5 scale. The finding will be handed to a developer for triage
+ remediation.

Rate the finding's `description` field (and adjacent metadata if
present) against this rubric:

  5 = "I understood the bug + fix in 30 seconds. Plain English +
       a concrete next step + clear exploit description."
  4 = "I understood after one read. Could explain to a developer."
  3 = "I had to re-read. Some jargon. Fix step is implicit."
  2 = "Required external research to understand. Vague."
  1 = "Useless. One-line + acronyms. Or just a CVE ID."

Reply with ONE JSON object:
  {{"score": <int 1-5>, "rationale": "<≤25 words>"}}

Do not include any prose outside the JSON. Do not include keys other
than `score` and `rationale`.

Finding:
{finding_json}
"""


def _summarize_finding_for_judge(finding: dict[str, Any]) -> str:
    """Build a compact JSON dump of just the explanation-relevant
    fields. Caps each text field at ~400 chars so the per-finding
    judge prompt stays under ~600 input tokens."""
    keys = (
        "title", "severity", "category", "cwe", "endpoint", "file",
        "description", "description_plain",
        "business_impact_plain", "impact",
        "recommended_action", "remediation_steps",
        "poc_description", "technical_analysis",
    )
    out: dict[str, Any] = {}
    for k in keys:
        v = finding.get(k)
        if isinstance(v, str) and v.strip():
            out[k] = v.strip()[:400]
    return json.dumps(out, indent=2, ensure_ascii=False)


def score_finding_llm(
    finding: dict[str, Any], *, model: str,
) -> ExplanationVerdict | None:
    """Per-finding LLM-as-judge 1-5 score.

    Returns None when the call fails — caller falls back to heuristic.
    Errors are intentionally swallowed; this metric is best-effort.
    """
    try:
        # Lazy import — only fail when actually called
        from strix.llm.client import LLMClient  # type: ignore[import-not-found]
    except ImportError:
        return None

    finding_json = _summarize_finding_for_judge(finding)
    prompt = _LLM_PROMPT_TEMPLATE.format(finding_json=finding_json)

    try:
        client = LLMClient(model=model)
        response = client.complete_sync(
            prompt=prompt,
            max_tokens=128,
            temperature=0.0,
        )
        # Best-effort JSON extraction
        match = re.search(r"\{[^{}]*\}", response)
        if not match:
            return None
        parsed = json.loads(match.group(0))
        score = float(parsed.get("score", 0))
        if not (1.0 <= score <= 5.0):
            return None
        return ExplanationVerdict(
            finding_id=finding.get("id"),
            title=finding.get("title"),
            severity=finding.get("severity"),
            score=round(score, 2),
            rubric_breakdown={"llm_score": score},
            judge=model,
            rationale=str(parsed.get("rationale", "") or "")[:200],
        )
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _band(score: float) -> str:
    """1-5 score → band label for the histogram."""
    if score >= 4.5:
        return "5"
    if score >= 3.5:
        return "4"
    if score >= 2.5:
        return "3"
    if score >= 1.5:
        return "2"
    return "1"


def score_fixture_explanation(
    fixture: str,
    findings: list[dict[str, Any]],
    *,
    llm_model: str | None = None,
) -> FixtureExplanationResult:
    """Per-fixture explanation-clarity scorer.

    Excludes corroborator-role siblings (their explanation is the
    parent's). When `llm_model` is set, tries LLM-as-judge first per
    finding; falls back to heuristic on any failure.
    """
    result = FixtureExplanationResult(fixture=fixture)
    if not findings:
        result.notes.append("no findings to score")
        return result

    eligible = [f for f in findings if f.get("role") != "corroborator"]
    result.findings_total = len(eligible)
    if not result.findings_total:
        result.notes.append("all findings were corroborator siblings")
        return result

    scores: list[float] = []
    for f in eligible:
        v: ExplanationVerdict | None = None
        if llm_model:
            v = score_finding_llm(f, model=llm_model)
        if v is None:
            v = score_finding_heuristic(f)
        result.per_finding.append(v)
        scores.append(v.score)
        result.by_score_band[_band(v.score)] = (
            result.by_score_band.get(_band(v.score), 0) + 1
        )

    if scores:
        result.average_score = round(statistics.mean(scores), 2)
        result.p50_score = round(statistics.median(scores), 2)
        # P10 — bottom-decile finding's score. Catches "any really
        # bad ones in the pile" that the average glosses over.
        # Clamped to [1.0, 5.0] because statistics.quantiles
        # extrapolates beyond the data range on small samples.
        try:
            if len(scores) > 1:
                raw_p10 = statistics.quantiles(scores, n=10)[0]
            else:
                raw_p10 = scores[0]
            result.p10_score = round(max(1.0, min(5.0, raw_p10)), 2)
        except statistics.StatisticsError:
            result.p10_score = scores[0]

    return result


# ---------------------------------------------------------------------------
# I/O — read findings from a run_summary.json or live scan
# ---------------------------------------------------------------------------

def _load_findings_from_run_summary(path: Path) -> list[dict[str, Any]]:
    """Read findings from a saved run JSON. Supports two formats:

      1. `vulnerability_reports[]` (tracer's `to_dict()` output —
         what's persisted to `strix_runs/<id>/run.json`).
      2. `findings[]` flat array (some bench outputs use this shape).

    Returns empty list on any error.
    """
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, dict):
        return []
    raw = data.get("vulnerability_reports") or data.get("findings") or []
    return [r for r in raw if isinstance(r, dict)]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--input", required=True,
        help="Path to run_summary.json or run.json containing "
             "vulnerability_reports[].",
    )
    parser.add_argument(
        "--llm", default=None,
        help="Optional LLM model identifier (e.g. anthropic/claude-sonnet-4-5). "
             "When unset, uses heuristic scorer.",
    )
    parser.add_argument(
        "--fixture", default="from-input",
        help="Label to use for the fixture in the report.",
    )
    parser.add_argument("--output")
    args = parser.parse_args()

    findings = _load_findings_from_run_summary(Path(args.input))
    if not findings:
        print(f"error: no findings in {args.input}", file=sys.stderr)
        return 1

    r = score_fixture_explanation(
        args.fixture, findings, llm_model=args.llm,
    )
    print(f"\n=== {args.fixture} ===")
    print(
        f"  findings={r.findings_total}  "
        f"avg={r.average_score:.2f} "
        f"p50={r.p50_score:.2f} "
        f"p10={r.p10_score:.2f}  "
        f"target ≥ 4.0 (L2)  "
        f"(judge={args.llm or 'heuristic'})"
    )
    if r.by_score_band:
        print(f"  by_score_band: {dict(sorted(r.by_score_band.items()))}")
    if r.notes:
        for n in r.notes:
            print(f"  note: {n}")

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(r.to_dict(), indent=2))
        print(f"[bench] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
