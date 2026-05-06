"""§8.5 Phase 8 acceptance-gate validator.

Reads a run_dir (events.jsonl + vulnerabilities.json + run_meta.json)
and evaluates the acceptance criteria from `single-agent.md §3.10`.
The engine default flip from `legacy` → `single-lead` is gated on
this validator returning `passes=True` against demo.testfire.net /
DVWA / juice-shop benchmark runs.

Schema-versioned. Wrapper-side impact: zero — the validator is a
pure-Python read-only consumer of existing artifacts.

Acceptance criteria (single-agent.md §3.10):

| Metric                                     | Gate     | Threshold     |
|--------------------------------------------|----------|---------------|
| Total cost on demo.testfire.net            | hard     | $0.50–$0.80   |
| Wall time                                  | hard     | 15–20 min     |
| `finding.created` events                   | hard     | ≥ 10 of 20    |
| `coverage_percent`                         | hard     | ≥ 70%         |
| Cache-hit ratio across whole scan          | hard     | ≥ 60%         |
| Peak context-window utilisation            | hard     | ≤ 60%         |
| Compactions per 60-turn scan               | soft     | ≤ 2 (warn>3)  |
| Reflections written                        | soft     | ≥ 1 per phase |

Hard-pass = required for default flip. Soft-pass = warning, not
blocking.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


ACCEPTANCE_GATE_SCHEMA_VERSION: int = 1


@dataclass
class GateResult:
    """One row in the acceptance table."""

    name: str
    severity: str  # "hard" | "soft"
    measured: float | int | None
    threshold_min: float | None = None
    threshold_max: float | None = None
    passes: bool = False
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "measured": self.measured,
            "threshold_min": self.threshold_min,
            "threshold_max": self.threshold_max,
            "passes": self.passes,
            "detail": self.detail,
        }


@dataclass
class AcceptanceReport:
    """Full validator output. Suitable for JSON serialization."""

    schema_version: int = ACCEPTANCE_GATE_SCHEMA_VERSION
    passes: bool = False
    hard_passes: int = 0
    hard_fails: int = 0
    soft_passes: int = 0
    soft_fails: int = 0
    results: list[GateResult] = field(default_factory=list)
    run_id: str | None = None
    target: str | None = None
    architecture: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "passes": self.passes,
            "hard_passes": self.hard_passes,
            "hard_fails": self.hard_fails,
            "soft_passes": self.soft_passes,
            "soft_fails": self.soft_fails,
            "results": [r.to_dict() for r in self.results],
            "run_id": self.run_id,
            "target": self.target,
            "architecture": self.architecture,
            "error": self.error,
        }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    except OSError:
        logger.debug("acceptance_gate: jsonl read failed for %s", path, exc_info=True)
    return out


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.debug("acceptance_gate: json read failed for %s", path, exc_info=True)
        return {}


def _check_range(
    name: str,
    severity: str,
    measured: float | int | None,
    *,
    min_value: float | None = None,
    max_value: float | None = None,
    detail: str | None = None,
) -> GateResult:
    """Helper: pass when min_value ≤ measured ≤ max_value (either
    bound optional). Missing measurement → fail."""
    if measured is None:
        return GateResult(
            name=name, severity=severity, measured=None,
            threshold_min=min_value, threshold_max=max_value,
            passes=False, detail=(detail or "no measurement"),
        )
    passes = True
    if min_value is not None and measured < min_value:
        passes = False
    if max_value is not None and measured > max_value:
        passes = False
    return GateResult(
        name=name, severity=severity, measured=measured,
        threshold_min=min_value, threshold_max=max_value,
        passes=passes, detail=detail,
    )


def evaluate_acceptance_gates(  # noqa: PLR0915
    *,
    run_dir: Path,
    expected_baseline_findings: int = 20,
) -> AcceptanceReport:
    """Evaluate the §3.10 acceptance criteria against a finished run.

    Args:
        run_dir: directory with events.jsonl + vulnerabilities.json
            + run_meta.json + (optionally) trajectory.jsonl,
            run_summary.json.
        expected_baseline_findings: total findings the benchmark
            target is expected to expose. demo.testfire.net = 20
            (per incident #147).

    Returns:
        `AcceptanceReport` with per-gate results + overall pass/fail.
        Hard-fail in any row → overall `passes=False`. Soft-fail
        does not block; warns only.
    """
    report = AcceptanceReport()

    if not run_dir.exists() or not run_dir.is_dir():
        report.error = f"run_dir does not exist: {run_dir}"
        return report

    # Load artifacts.
    events = _read_jsonl(run_dir / "events.jsonl")
    vuln_file = _read_json(run_dir / "vulnerabilities.json")
    findings_list = (
        vuln_file.get("findings")
        or vuln_file.get("vulnerabilities")
        or []
    )
    run_meta = _read_json(run_dir / "run_meta.json")

    report.run_id = run_meta.get("run_id") or run_meta.get("run_name")
    targets = run_meta.get("targets") or []
    if isinstance(targets, list) and targets:
        first = targets[0]
        if isinstance(first, dict):
            report.target = first.get("original") or first.get("details", {}).get(
                "target_url", "unknown",
            )
    report.architecture = run_meta.get("agent_architecture") or "unknown"

    # ------------------------------------------------------------------
    # Cost
    # ------------------------------------------------------------------
    cost_consumed: float | None = None
    for ev in events:
        if ev.get("event_type") == "run.terminated":
            payload = ev.get("payload") or {}
            consumed = payload.get("consumed") or {}
            v = consumed.get("cost_usd") or consumed.get("cost")
            if isinstance(v, int | float):
                cost_consumed = float(v)
                break
    if cost_consumed is None:
        # Fallback: walk llm.token_breakdown events.
        total = 0.0
        any_seen = False
        for ev in events:
            if ev.get("event_type") == "llm.token_breakdown":
                payload = ev.get("payload") or {}
                v = payload.get("measured_cost_usd")
                if isinstance(v, int | float):
                    total += float(v)
                    any_seen = True
        if any_seen:
            cost_consumed = round(total, 6)
    report.results.append(_check_range(
        "cost_usd",
        "hard",
        cost_consumed,
        min_value=0.50,
        max_value=0.80,
        detail="single-agent.md §3.10 acceptance: $0.50-$0.80 on demo.testfire.net",
    ))

    # ------------------------------------------------------------------
    # Wall time (minutes)
    # ------------------------------------------------------------------
    wall_minutes: float | None = None
    start = run_meta.get("start_time")
    end = run_meta.get("end_time")
    if isinstance(start, str) and isinstance(end, str):
        try:
            from datetime import datetime
            ds = datetime.fromisoformat(start.replace("Z", "+00:00"))
            de = datetime.fromisoformat(end.replace("Z", "+00:00"))
            wall_minutes = round((de - ds).total_seconds() / 60.0, 2)
        except (ValueError, TypeError):
            wall_minutes = None
    report.results.append(_check_range(
        "wall_time_minutes",
        "hard",
        wall_minutes,
        min_value=15.0,
        max_value=20.0,
        detail="single-agent.md §3.10 acceptance: 15-20 min on demo.testfire.net",
    ))

    # ------------------------------------------------------------------
    # Findings emitted
    # ------------------------------------------------------------------
    findings_count = len(findings_list) if isinstance(findings_list, list) else 0
    findings_threshold = max(1, int(expected_baseline_findings * 0.5))
    report.results.append(_check_range(
        "findings_emitted",
        "hard",
        findings_count,
        min_value=findings_threshold,
        detail=f"≥ {findings_threshold} of {expected_baseline_findings} baseline findings",
    ))

    # ------------------------------------------------------------------
    # Coverage percent
    # ------------------------------------------------------------------
    coverage = _read_json(run_dir / "coverage.json")
    coverage_pct = coverage.get("coverage_percent")
    if not isinstance(coverage_pct, int | float):
        coverage_pct = None
    report.results.append(_check_range(
        "coverage_percent",
        "hard",
        coverage_pct,
        min_value=70.0,
        detail="≥ 70% category coverage",
    ))

    # ------------------------------------------------------------------
    # Cache-hit ratio (Phase 2 / Phase 0.A)
    # ------------------------------------------------------------------
    total_input = 0
    total_cached = 0
    for ev in events:
        if ev.get("event_type") == "llm.token_breakdown":
            payload = ev.get("payload") or {}
            ti = payload.get("measured_input_tokens")
            tc = payload.get("measured_cached_tokens")
            if isinstance(ti, int | float):
                total_input += int(ti)
            if isinstance(tc, int | float):
                total_cached += int(tc)
    cache_hit_ratio: float | None = None
    if total_input > 0:
        cache_hit_ratio = round(total_cached / total_input, 4)
    report.results.append(_check_range(
        "cache_hit_ratio",
        "hard",
        cache_hit_ratio,
        min_value=0.60,
        detail="cache-stability rule (single-agent.md §2.5.4)",
    ))

    # ------------------------------------------------------------------
    # Peak context-window utilisation
    # ------------------------------------------------------------------
    peak_util: float | None = None
    for ev in events:
        if ev.get("event_type") in ("llm.token_breakdown", "check_budget.snapshot"):
            payload = ev.get("payload") or {}
            v = payload.get("context_window_utilisation")
            if isinstance(v, int | float):
                if peak_util is None or v > peak_util:
                    peak_util = float(v)
    report.results.append(_check_range(
        "peak_context_window_utilisation",
        "hard",
        peak_util,
        max_value=0.60,
        detail="quality-knee compaction trigger (single-agent.md §2.5.2)",
    ))

    # ------------------------------------------------------------------
    # Soft: compactions per 60-turn scan
    # ------------------------------------------------------------------
    compactions = sum(
        1 for ev in events if ev.get("event_type") == "context.compacted"
    )
    total_turns = sum(
        1 for ev in events if ev.get("event_type") == "tool.execution.started"
    )
    compactions_per_60 = (
        round(compactions / max(1, total_turns) * 60, 2)
        if total_turns > 0 else 0
    )
    report.results.append(_check_range(
        "compactions_per_60_turns",
        "soft",
        compactions_per_60,
        max_value=2.0,
        detail="cache-stability rule §2.5.4 — sparse-but-deep",
    ))

    # ------------------------------------------------------------------
    # Soft: reflections per phase
    # ------------------------------------------------------------------
    reflection_count = sum(
        1 for ev in events if ev.get("event_type") == "reflection.recorded"
    )
    phase_completed_count = max(1, sum(
        1 for ev in events if ev.get("event_type") == "phase.completed"
    ))
    reflections_per_phase = round(reflection_count / phase_completed_count, 2)
    report.results.append(_check_range(
        "reflections_per_phase",
        "soft",
        reflections_per_phase,
        min_value=1.0,
        detail="memory-stream synthesis (single-agent.md §2.5.5)",
    ))

    # Aggregate.
    for r in report.results:
        if r.severity == "hard":
            if r.passes:
                report.hard_passes += 1
            else:
                report.hard_fails += 1
        else:
            if r.passes:
                report.soft_passes += 1
            else:
                report.soft_fails += 1
    report.passes = report.hard_fails == 0

    return report
