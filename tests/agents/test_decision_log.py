"""Tests for Phase 1.6 — decision provenance log.

Pins:
  * `record_decision` returns a stable id; appends to in-memory list
  * `link_decisions` adds predecessor links retroactively
  * `list_decisions(kind=...)` filters
  * `reasoning_trace_for_finding` walks the predecessor graph
  * Persistence to `<run_dir>/decision_log.jsonl` when env var set
  * Bounded memory (max 5000 entries)
"""

from __future__ import annotations

import json

import pytest

from strix.agents.decision_log import (
    link_decisions,
    list_decisions,
    reasoning_trace_for_finding,
    record_decision,
    reset_decision_log,
)


@pytest.fixture(autouse=True)
def _isolate_log() -> None:
    reset_decision_log()
    yield
    reset_decision_log()


# ---------------------------------------------------------------------------
# Basic recording
# ---------------------------------------------------------------------------


def test_record_returns_stable_id() -> None:
    did = record_decision(kind="probe", target="/x", input={"payload": "'"})
    assert isinstance(did, str)
    assert did.startswith("d_")
    decisions = list_decisions()
    assert len(decisions) == 1
    assert decisions[0].decision_id == did


def test_decision_kinds_are_filterable() -> None:
    record_decision(kind="probe", target="/x")
    record_decision(kind="probe", target="/y")
    record_decision(kind="finding", target="/z", output={"title": "Test"})

    probes = list_decisions(kind="probe")
    findings = list_decisions(kind="finding")
    assert len(probes) == 2
    assert len(findings) == 1


def test_actor_input_output_links_recorded() -> None:
    did = record_decision(
        kind="specialist_invocation",
        target="http://x/login",
        actor={"tool_name": "scan_sqli"},
        input={"params": ["email"], "method": "POST"},
        output={"findings_emitted": 1},
        links={"hypothesis_id": "hyp_abc"},
    )
    d = list_decisions()[0]
    assert d.actor == {"tool_name": "scan_sqli"}
    assert d.input["params"] == ["email"]
    assert d.output["findings_emitted"] == 1
    assert d.links["hypothesis_id"] == "hyp_abc"


# ---------------------------------------------------------------------------
# Linking
# ---------------------------------------------------------------------------


def test_link_decisions_adds_predecessors() -> None:
    p1 = record_decision(kind="probe", target="/x")
    p2 = record_decision(kind="probe", target="/y")
    finding = record_decision(kind="finding", output={"title": "f"})
    link_decisions(child_id=finding, predecessor_ids=[p1, p2])

    d = next(d for d in list_decisions() if d.decision_id == finding)
    assert d.links["predecessors"] == [p1, p2]


def test_link_decisions_dedupes() -> None:
    p1 = record_decision(kind="probe", target="/x")
    finding = record_decision(kind="finding")
    link_decisions(child_id=finding, predecessor_ids=[p1])
    link_decisions(child_id=finding, predecessor_ids=[p1])  # dup

    d = next(d for d in list_decisions() if d.decision_id == finding)
    assert d.links["predecessors"] == [p1]


def test_link_decisions_no_op_for_unknown_child() -> None:
    # Doesn't crash even if child_id doesn't exist
    link_decisions(child_id="d_nonexistent", predecessor_ids=["p1"])


# ---------------------------------------------------------------------------
# Reasoning trace
# ---------------------------------------------------------------------------


def test_reasoning_trace_walks_predecessors() -> None:
    """A finding linked back through 2 probes + 1 hypothesis should
    produce a 4-line trace (the finding itself + the predecessors)."""
    h = record_decision(
        kind="hypothesis",
        input={"hypothesis": "Login is SQLi-vulnerable via email param"},
    )
    p1 = record_decision(
        kind="probe",
        target="/login",
        input={"payload": "'"},
    )
    p2 = record_decision(
        kind="probe",
        target="/login",
        input={"payload": "' OR 1=1--"},
    )
    finding = record_decision(
        kind="finding",
        target="/login",
        output={"title": "SQL injection auth bypass"},
        links={"finding_id": "vuln-001", "predecessors": [h, p1, p2]},
    )

    trace = reasoning_trace_for_finding("vuln-001")
    # 4 entries: finding + h + p1 + p2 (in BFS order)
    assert len(trace) >= 3
    assert any("Finding emitted" in t for t in trace)
    assert any("Hypothesis" in t for t in trace)
    assert any("Probed" in t for t in trace)


def test_reasoning_trace_returns_empty_for_unknown_finding() -> None:
    record_decision(kind="finding", links={"finding_id": "vuln-known"})
    trace = reasoning_trace_for_finding("vuln-unknown")
    assert trace == []


def test_reasoning_trace_bounded_to_10_entries() -> None:
    # Build a chain of 20 probes → 1 finding
    probe_ids = [
        record_decision(kind="probe", target=f"/p{i}", input={"payload_label": f"p{i}"})
        for i in range(20)
    ]
    record_decision(
        kind="finding",
        output={"title": "f"},
        links={"finding_id": "v1", "predecessors": probe_ids},
    )
    trace = reasoning_trace_for_finding("v1")
    assert len(trace) <= 10


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_persistence_writes_jsonl(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    record_decision(kind="probe", target="/x", input={"a": 1})
    record_decision(kind="finding", output={"title": "t"})

    log_file = tmp_path / "decision_log.jsonl"
    assert log_file.exists()
    lines = log_file.read_text().strip().split("\n")
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["kind"] == "probe"
    assert parsed[1]["kind"] == "finding"


def test_persistence_silent_when_no_run_dir(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_RUN_DIR", raising=False)
    # Should not raise
    record_decision(kind="probe", target="/x")


# ---------------------------------------------------------------------------
# Memory bounds
# ---------------------------------------------------------------------------


def test_in_memory_log_bounded() -> None:
    """Long-running scan: don't OOM. Cap at 5000 most recent."""
    for i in range(5500):
        record_decision(kind="probe", target=f"/p{i}")
    decisions = list_decisions()
    assert len(decisions) == 5000
    # Most recent kept
    assert decisions[-1].target == "/p5499"
    assert decisions[0].target == "/p500"  # oldest 500 evicted
