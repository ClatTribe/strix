"""Tests for §8.5 Phase 6 — `reflect` + `list_reflections`.

Pins the reflection record schema (additive within
active_hypotheses.jsonl), the closed-enum scope set, the cap on
summary length, and the read API.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.agents.lead_agent.reflection import (
    REFLECTION_SCHEMA_VERSION,
    list_reflections,
    reflect,
)


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    """Set up a fresh tracer + run-dir so each test has its own
    active_hypotheses.jsonl."""
    from strix.telemetry import tracer as tracer_module
    from strix.telemetry import utils as telemetry_utils
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("reflection-test")
    set_global_tracer(tracer)
    yield


def test_schema_version_pinned() -> None:
    assert REFLECTION_SCHEMA_VERSION == 1


def test_reflect_writes_record_to_active_hypotheses_jsonl() -> None:
    out = reflect(
        scope="last_n_turns",
        n=30,
        summary="Recon phase produced 14 endpoints; 8 auth-protected.",
    )
    assert out["success"] is True
    assert out["reflection_id"].startswith("refl_")
    assert out["scope"] == "last_n_turns"

    # Verify on disk.
    from strix.telemetry.tracer import get_global_tracer

    path = get_global_tracer().get_run_dir() / "active_hypotheses.jsonl"
    assert path.exists()
    records = [
        json.loads(line) for line in path.read_text().splitlines() if line.strip()
    ]
    refl = [r for r in records if r.get("record_type") == "reflection"]
    assert len(refl) == 1
    assert refl[0]["scope"] == "last_n_turns"
    assert refl[0]["n"] == 30
    assert "Recon phase" in refl[0]["summary"]


@pytest.mark.parametrize(
    "scope",
    ["last_n_turns", "current_phase", "current_target"],
)
def test_reflect_accepts_canonical_scopes(scope: str) -> None:
    out = reflect(scope=scope, summary="test")
    assert out["success"] is True


def test_reflect_rejects_unknown_scope() -> None:
    out = reflect(scope="weird_scope", summary="test")  # type: ignore[arg-type]
    assert out["success"] is False
    assert "scope" in (out["error"] or "")


def test_reflect_rejects_empty_summary() -> None:
    out = reflect(scope="last_n_turns", summary="")
    assert out["success"] is False
    assert "summary" in (out["error"] or "")


def test_reflect_rejects_whitespace_only_summary() -> None:
    out = reflect(scope="last_n_turns", summary="   \n\t  ")
    assert out["success"] is False


def test_reflect_caps_summary_at_4096_chars() -> None:
    out = reflect(scope="last_n_turns", summary="x" * 5000)
    assert out["success"] is True

    from strix.telemetry.tracer import get_global_tracer

    path = get_global_tracer().get_run_dir() / "active_hypotheses.jsonl"
    rec = next(
        json.loads(l) for l in path.read_text().splitlines()
        if l.strip() and json.loads(l).get("record_type") == "reflection"
    )
    assert len(rec["summary"]) == 4096


def test_reflect_clamps_negative_n() -> None:
    out = reflect(scope="last_n_turns", n=-10, summary="test")
    assert out["success"] is True

    from strix.telemetry.tracer import get_global_tracer

    path = get_global_tracer().get_run_dir() / "active_hypotheses.jsonl"
    rec = next(
        json.loads(l) for l in path.read_text().splitlines()
        if l.strip() and json.loads(l).get("record_type") == "reflection"
    )
    assert rec["n"] == 0


def test_list_reflections_returns_only_reflection_records() -> None:
    """Hypothesis records share the same file. `list_reflections`
    must filter to record_type='reflection' only."""
    from strix.agents.active_hypotheses import open_hypothesis

    open_hypothesis(hypothesis="test hyp", surface="/x")
    reflect(scope="last_n_turns", summary="reflection 1")
    open_hypothesis(hypothesis="test hyp 2", surface="/y")
    reflect(scope="current_phase", summary="reflection 2")

    out = list_reflections()
    assert out["success"] is True
    assert out["count"] == 2
    assert all(r.get("record_type") == "reflection" for r in out["reflections"])


def test_list_reflections_filters_by_scope() -> None:
    reflect(scope="last_n_turns", summary="r1")
    reflect(scope="current_phase", summary="r2")
    reflect(scope="last_n_turns", summary="r3")

    out = list_reflections(scope="last_n_turns")
    assert out["count"] == 2
    out2 = list_reflections(scope="current_phase")
    assert out2["count"] == 1


def test_list_reflections_rejects_unknown_scope() -> None:
    out = list_reflections(scope="weird")
    assert out["success"] is False


def test_list_reflections_returns_empty_when_no_records() -> None:
    out = list_reflections()
    assert out["success"] is True
    assert out["count"] == 0
    assert out["reflections"] == []


def test_reflection_emits_event() -> None:
    """`reflection.recorded` event lets wrappers render reflections
    in real-time."""
    reflect(scope="last_n_turns", summary="test reflection")

    from strix.telemetry.tracer import get_global_tracer

    events_path = get_global_tracer().get_run_dir() / "events.jsonl"
    events = [
        json.loads(line)
        for line in events_path.read_text().splitlines()
        if line.strip()
    ]
    refl_events = [e for e in events if e.get("event_type") == "reflection.recorded"]
    assert len(refl_events) == 1


def test_reflect_returns_unique_reflection_ids() -> None:
    a = reflect(scope="last_n_turns", summary="a")
    b = reflect(scope="last_n_turns", summary="b")
    assert a["reflection_id"] != b["reflection_id"]
