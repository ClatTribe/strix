"""Tests for `agent_self_audit` (roadmap §17.6 / §18 row 9 second-half)."""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


import strix.tools.self_audit.self_audit_tool  # noqa: F401

sa_module = sys.modules["strix.tools.self_audit.self_audit_tool"]
agent_self_audit = sa_module.agent_self_audit


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("self-audit-test")
    set_global_tracer(tracer)
    yield


def _events(tmp_path) -> list[dict[str, Any]]:
    p = tmp_path / "strix_runs" / "self-audit-test" / "events.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# Phase validation
# ---------------------------------------------------------------------------


def test_empty_phase_completed_rejected() -> None:
    out = agent_self_audit(phase_completed="")
    assert out["success"] is False
    assert "phase_completed" in out["message"]


def test_invalid_phase_completed_rejected() -> None:
    out = agent_self_audit(phase_completed="not-a-real-phase")
    assert out["success"] is False
    assert "canonical set" in out["message"]


@pytest.mark.parametrize("phase", ["recon", "exploit", "validate", "report"])
def test_each_canonical_phase_accepted(phase: str) -> None:
    out = agent_self_audit(phase_completed=phase)
    assert out["success"] is True
    assert out["phase_completed"] == phase


def test_phase_lowercased_on_normalisation() -> None:
    out = agent_self_audit(phase_completed="RECON")
    assert out["success"] is True
    assert out["phase_completed"] == "recon"


def test_invalid_phase_starting_rejected() -> None:
    out = agent_self_audit(phase_completed="recon", phase_starting="nonsense")
    assert out["success"] is False


def test_phase_starting_optional() -> None:
    """The final 'report' boundary has no next phase."""
    out = agent_self_audit(phase_completed="report")
    assert out["success"] is True
    assert out["phase_starting"] is None


# ---------------------------------------------------------------------------
# Event emission + payload schema
# ---------------------------------------------------------------------------


def test_event_emitted(tmp_path) -> None:
    agent_self_audit(
        phase_completed="recon",
        phase_starting="exploit",
        categories_covered=["sql_injection", "xss", "ssrf"],
    )
    events = _events(tmp_path)
    audits = [e for e in events if e.get("event_type") == "agent.self_audit"]
    assert len(audits) == 1
    payload = audits[0]["payload"]
    assert payload["phase_completed"] == "recon"
    assert payload["phase_starting"] == "exploit"
    assert "sql_injection" in payload["categories_covered"]


def test_event_carries_all_audit_fields(tmp_path) -> None:
    agent_self_audit(
        phase_completed="exploit",
        phase_starting="validate",
        categories_covered=["xss", "sql_injection"],
        categories_skipped=[
            {"category": "ssrf", "reason": "no internal-network surface"},
        ],
        stuck_sub_agents=[
            {"agent_id": "agent-x", "category": "auth", "reason": "rate-limited"},
        ],
        open_hypotheses_count=3,
        concern="Auth specialist hit rate-limit; coverage may be partial.",
        next_phase_plan="Run validator on top-3 candidate findings.",
    )
    events = _events(tmp_path)
    payload = next(e for e in events if e.get("event_type") == "agent.self_audit")["payload"]

    assert payload["phase_completed"] == "exploit"
    assert payload["phase_starting"] == "validate"
    assert payload["categories_covered"] == ["xss", "sql_injection"]
    assert payload["categories_skipped"][0]["category"] == "ssrf"
    assert payload["stuck_sub_agents"][0]["agent_id"] == "agent-x"
    assert payload["open_hypotheses_count"] == 3
    assert "rate-limit" in payload["concern"]
    assert "validator" in payload["next_phase_plan"]


# ---------------------------------------------------------------------------
# categories_covered normalisation
# ---------------------------------------------------------------------------


def test_categories_lowercase_dedup() -> None:
    out = agent_self_audit(
        phase_completed="recon",
        categories_covered=["XSS", "xss", "  Sql_Injection  ", "SQL_INJECTION"],
    )
    assert out["categories_covered_count"] == 2  # xss + sql_injection


def test_categories_capped_at_50() -> None:
    out = agent_self_audit(
        phase_completed="recon",
        categories_covered=[f"category-{i}" for i in range(100)],
    )
    assert out["categories_covered_count"] == 50


def test_categories_non_string_skipped() -> None:
    out = agent_self_audit(
        phase_completed="recon",
        categories_covered=["xss", 42, None, "ssrf"],  # type: ignore[list-item]
    )
    assert out["categories_covered_count"] == 2


# ---------------------------------------------------------------------------
# categories_skipped normalisation
# ---------------------------------------------------------------------------


def test_skipped_requires_both_category_and_reason(tmp_path) -> None:
    agent_self_audit(
        phase_completed="recon",
        categories_skipped=[
            {"category": "ssrf", "reason": "out of scope"},
            {"category": "xss"},  # missing reason — drop
            {"reason": "stub"},  # missing category — drop
            {"category": "sqli", "reason": "no input forms"},
        ],
    )
    events = _events(tmp_path)
    payload = next(e for e in events if e.get("event_type") == "agent.self_audit")["payload"]
    assert len(payload["categories_skipped"]) == 2


def test_skipped_dedup_by_category(tmp_path) -> None:
    agent_self_audit(
        phase_completed="recon",
        categories_skipped=[
            {"category": "ssrf", "reason": "first"},
            {"category": "ssrf", "reason": "second"},  # dup — drop
        ],
    )
    events = _events(tmp_path)
    payload = next(e for e in events if e.get("event_type") == "agent.self_audit")["payload"]
    assert len(payload["categories_skipped"]) == 1
    assert payload["categories_skipped"][0]["reason"] == "first"


# ---------------------------------------------------------------------------
# stuck_sub_agents normalisation
# ---------------------------------------------------------------------------


def test_stuck_requires_agent_id_or_category(tmp_path) -> None:
    agent_self_audit(
        phase_completed="exploit",
        stuck_sub_agents=[
            {"agent_id": "agent-x", "category": "auth", "reason": "rate"},
            {"reason": "orphan"},  # no agent_id, no category — drop
            {"agent_id": "agent-y"},  # category missing — keep
        ],
    )
    events = _events(tmp_path)
    payload = next(e for e in events if e.get("event_type") == "agent.self_audit")["payload"]
    assert len(payload["stuck_sub_agents"]) == 2


# ---------------------------------------------------------------------------
# open_hypotheses_count
# ---------------------------------------------------------------------------


def test_open_hypotheses_count_clamped_non_negative(tmp_path) -> None:
    agent_self_audit(
        phase_completed="recon",
        open_hypotheses_count=-5,
    )
    events = _events(tmp_path)
    payload = next(e for e in events if e.get("event_type") == "agent.self_audit")["payload"]
    assert payload["open_hypotheses_count"] == 0


def test_open_hypotheses_count_garbage_falls_to_none(tmp_path) -> None:
    agent_self_audit(
        phase_completed="recon",
        open_hypotheses_count="not-a-number",  # type: ignore[arg-type]
    )
    events = _events(tmp_path)
    payload = next(e for e in events if e.get("event_type") == "agent.self_audit")["payload"]
    assert payload["open_hypotheses_count"] is None


# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------


def test_concern_capped(tmp_path) -> None:
    agent_self_audit(
        phase_completed="recon",
        concern="X" * 5000,
    )
    events = _events(tmp_path)
    payload = next(e for e in events if e.get("event_type") == "agent.self_audit")["payload"]
    assert len(payload["concern"]) <= 2048


def test_next_phase_plan_capped(tmp_path) -> None:
    agent_self_audit(
        phase_completed="recon",
        next_phase_plan="Y" * 5000,
    )
    events = _events(tmp_path)
    payload = next(e for e in events if e.get("event_type") == "agent.self_audit")["payload"]
    assert len(payload["next_phase_plan"]) <= 2048


# ---------------------------------------------------------------------------
# Tracer-absent fallback
# ---------------------------------------------------------------------------


def test_works_without_tracer(monkeypatch) -> None:
    monkeypatch.setattr(tracer_module, "get_global_tracer", lambda: None)
    out = agent_self_audit(
        phase_completed="recon", phase_starting="exploit"
    )
    # Tool returns success regardless — emit is best-effort.
    assert out["success"] is True


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_agent_self_audit_tool_registered() -> None:
    from strix.tools.registry import get_tool_by_name

    assert get_tool_by_name("agent_self_audit") is not None


def test_agent_self_audit_provenance_is_framework() -> None:
    from strix.tools.registry import get_tool_provenance

    assert get_tool_provenance("agent_self_audit") == "framework"


# ---------------------------------------------------------------------------
# Integration: the audit naturally complements active_hypotheses
# ---------------------------------------------------------------------------


def test_audit_with_hypothesis_count_correlates(tmp_path) -> None:
    """A typical phase boundary call: query active_hypotheses for the
    investigating count, then pass it into self_audit."""
    import strix.agents.active_hypotheses as ah

    ah.reset_for_testing()
    h1 = ah.open_hypothesis(hypothesis="h1", surface="/a")
    ah.open_hypothesis(hypothesis="h2", surface="/b")
    investigating = ah.list_active_hypotheses(only_status="investigating")
    assert len(investigating) == 2

    agent_self_audit(
        phase_completed="recon",
        phase_starting="exploit",
        open_hypotheses_count=len(investigating),
    )

    events = _events(tmp_path)
    payload = next(e for e in events if e.get("event_type") == "agent.self_audit")["payload"]
    assert payload["open_hypotheses_count"] == 2
