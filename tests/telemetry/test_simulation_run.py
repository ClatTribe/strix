"""Tests for MA-S2 P0-APM-C — `simulation_run.json` attestation.

Recall-safety contract pinned by tests:
  * Output ALWAYS has the canonical schema shape — every key
    present, even when source data is unavailable.
  * Schema version stamp present.
  * Builder NEVER raises — failures fall through to a minimal
    summary that still passes schema validation.
  * File lands on disk when `save_run_data(mark_complete=True)`
    fires; absent when mark_complete=False (intermediate saves).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.telemetry.simulation_run import (
    _build_minimal_summary,
    _gather_findings_counts,
    _gather_kg_counts,
    _gather_mitre_techniques,
    _gather_models_used,
    _gather_specialist_counts,
    _gather_tool_call_counts,
    build_simulation_run,
)
from strix.telemetry.tracer import Tracer, set_global_tracer


# ---------------------------------------------------------------------------
# Stub tracer for the gatherer unit tests
# ---------------------------------------------------------------------------


class _StubTracer:
    """Minimal duck-type matching what build_simulation_run reads
    from a real Tracer."""

    def __init__(
        self,
        *,
        run_metadata: dict | None = None,
        tool_executions: dict | None = None,
        vulnerability_reports: list | None = None,
        kg_node_deltas: list | None = None,
        kg_edge_deltas: list | None = None,
    ) -> None:
        self.run_metadata = run_metadata or {}
        self.tool_executions = tool_executions or {}
        self.vulnerability_reports = vulnerability_reports or []
        self.kg_node_deltas = kg_node_deltas or []
        self.kg_edge_deltas = kg_edge_deltas or []


# ---------------------------------------------------------------------------
# Schema invariant — every key present, every type stable
# ---------------------------------------------------------------------------


_EXPECTED_KEYS = {
    "schema", "run_id", "scan_mode", "started_at", "ended_at",
    "duration_s", "models_used", "specialists_dispatched",
    "specialist_categories_exercised", "mitre_techniques_exercised",
    "kg_node_count", "kg_edge_count", "ai_reasoning_calls",
    "deterministic_tool_calls", "novel_findings_count", "findings_count",
}


def test_schema_keys_always_present_on_empty_tracer() -> None:
    out = build_simulation_run(_StubTracer())
    assert set(out.keys()) == _EXPECTED_KEYS
    assert out["schema"] == "strix.simulation_run/v1"


def test_schema_keys_present_on_populated_tracer() -> None:
    tracer = _StubTracer(
        run_metadata={
            "run_id": "test-run-1",
            "scan_mode": "deep",
            "model": "anthropic/claude-sonnet-4-6",
            "start_time": "2026-05-19T10:00:00+00:00",
            "end_time": "2026-05-19T10:30:00+00:00",
        },
        tool_executions={
            1: {"tool_name": "scan_sqli", "mitre_techniques": ["T1190"]},
            2: {"tool_name": "scan_xss", "mitre_techniques": ["T1059"]},
            3: {"tool_name": "think"},
            4: {"tool_name": "send_request"},
        },
        vulnerability_reports=[
            {"severity": "high", "title": "SQLi",
             "discovery_method": {"is_novel": True}},
            {"severity": "low", "title": "Banner"},
        ],
        kg_node_deltas=[{"id": "n1"}, {"id": "n2"}],
        kg_edge_deltas=[{"id": "e1"}],
    )
    out = build_simulation_run(tracer)
    assert set(out.keys()) == _EXPECTED_KEYS


# ---------------------------------------------------------------------------
# Per-field gatherers
# ---------------------------------------------------------------------------


def test_models_used_emits_lead_and_specialist_rows() -> None:
    models = _gather_models_used({"model": "anthropic/claude-sonnet-4-6"})
    roles = {m["role"] for m in models}
    assert roles == {"lead", "specialist"}


def test_models_used_empty_on_missing_model_metadata() -> None:
    assert _gather_models_used({}) == []


def test_specialist_categories_extracted_from_tool_names() -> None:
    tracer = _StubTracer(tool_executions={
        1: {"tool_name": "scan_sqli"},
        2: {"tool_name": "scan_xss"},
        3: {"tool_name": "send_request"},  # not a specialist
        4: {"tool_name": "scan_idor"},
    })
    out = _gather_specialist_counts(tracer)
    assert set(out["specialist_categories_exercised"]) == {"sqli", "xss", "idor"}


def test_mitre_techniques_aggregated_across_tools() -> None:
    tracer = _StubTracer(tool_executions={
        1: {"tool_name": "x", "mitre_techniques": ["T1190", "T1078"]},
        2: {"tool_name": "y", "mitre_techniques": ["T1078", "T1530"]},
    })
    assert _gather_mitre_techniques(tracer) == ["T1078", "T1190", "T1530"]


def test_kg_counts_from_deltas() -> None:
    tracer = _StubTracer(
        kg_node_deltas=[{"id": str(i)} for i in range(5)],
        kg_edge_deltas=[{"id": str(i)} for i in range(3)],
    )
    out = _gather_kg_counts(tracer)
    assert out["kg_node_count"] == 5
    assert out["kg_edge_count"] == 3


def test_tool_call_counts_split_ai_vs_deterministic() -> None:
    tracer = _StubTracer(tool_executions={
        1: {"tool_name": "think"},
        2: {"tool_name": "dispatch_specialist"},
        3: {"tool_name": "send_request"},
        4: {"tool_name": "scan_sqli"},
        5: {"tool_name": "browser_action"},
    })
    out = _gather_tool_call_counts(tracer)
    # think + dispatch_specialist = 2 AI calls
    assert out["ai_reasoning_calls"] == 2
    # send_request + scan_sqli + browser_action = 3 deterministic
    assert out["deterministic_tool_calls"] == 3


def test_findings_counts_total_and_novel() -> None:
    tracer = _StubTracer(vulnerability_reports=[
        {"id": "1", "discovery_method": {"is_novel": True}},
        {"id": "2", "discovery_method": {"is_novel": False}},
        {"id": "3"},  # no discovery_method
        {"id": "4", "discovery_method": {"is_novel": True}},
    ])
    out = _gather_findings_counts(tracer)
    assert out["findings_count"] == 4
    assert out["novel_findings_count"] == 2


# ---------------------------------------------------------------------------
# Duration parsing
# ---------------------------------------------------------------------------


def test_duration_computed_from_iso_timestamps() -> None:
    tracer = _StubTracer(run_metadata={
        "start_time": "2026-05-19T10:00:00+00:00",
        "end_time": "2026-05-19T10:30:00+00:00",
    })
    out = build_simulation_run(tracer)
    assert out["duration_s"] == 1800.0


def test_duration_null_on_missing_timestamps() -> None:
    tracer = _StubTracer(run_metadata={"start_time": "2026-05-19T10:00:00Z"})
    out = build_simulation_run(tracer)
    assert out["duration_s"] is None


def test_duration_null_on_garbage_timestamps() -> None:
    tracer = _StubTracer(run_metadata={
        "start_time": "not a date", "end_time": "also not a date",
    })
    out = build_simulation_run(tracer)
    assert out["duration_s"] is None


# ---------------------------------------------------------------------------
# Minimal fallback
# ---------------------------------------------------------------------------


def test_minimal_summary_has_canonical_shape() -> None:
    out = _build_minimal_summary(_StubTracer())
    assert set(out.keys()) == _EXPECTED_KEYS
    assert out["models_used"] == []
    assert out["specialists_dispatched"] == 0


# ---------------------------------------------------------------------------
# Recall safety — builder never raises
# ---------------------------------------------------------------------------


def test_builder_does_not_raise_on_broken_tracer() -> None:
    """A tracer that raises on every attribute access (e.g. half-
    initialized) still produces a canonical-shape result."""
    class _BrokenTracer:
        run_metadata = {"run_id": "x"}
        @property
        def tool_executions(self):
            raise RuntimeError("simulated explosion")
        @property
        def vulnerability_reports(self):
            raise RuntimeError("simulated explosion")
        @property
        def kg_node_deltas(self):
            raise RuntimeError("simulated explosion")
        @property
        def kg_edge_deltas(self):
            raise RuntimeError("simulated explosion")

    out = build_simulation_run(_BrokenTracer())
    # Schema present + every key intact
    assert out["schema"] == "strix.simulation_run/v1"
    assert set(out.keys()) == _EXPECTED_KEYS


# ---------------------------------------------------------------------------
# Integration — file lands on disk at scan completion
# ---------------------------------------------------------------------------


def test_simulation_run_json_written_on_mark_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.chdir(tmp_path)
    tracer = Tracer("ma-s2-apm-c-integration")
    set_global_tracer(tracer)
    tracer.save_run_data(mark_complete=True)

    sim_path = tmp_path / "strix_runs" / "ma-s2-apm-c-integration" / "simulation_run.json"
    assert sim_path.exists()
    with sim_path.open() as f:
        data = json.load(f)
    assert data["schema"] == "strix.simulation_run/v1"
    assert set(data.keys()) == _EXPECTED_KEYS


def test_simulation_run_json_not_written_on_intermediate_save(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """save_run_data() without mark_complete=True is an intermediate
    save (called after every finding emit). simulation_run.json
    should NOT be written then — only at scan completion."""
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.chdir(tmp_path)
    tracer = Tracer("ma-s2-apm-c-no-mid-write")
    set_global_tracer(tracer)
    tracer.save_run_data(mark_complete=False)

    sim_path = tmp_path / "strix_runs" / "ma-s2-apm-c-no-mid-write" / "simulation_run.json"
    assert not sim_path.exists(), (
        "simulation_run.json must only be written at mark_complete=True; "
        "writing on every intermediate save would thrash the file."
    )
