"""Tests for the LeadTeam reference orchestrator (roadmap §8.0).

Tests cover:

- LeadTeam constructor requires a lead state
- spawn() records success / failure
- spawn_many() handles a list of dicts
- collect_findings() deduplicates by fingerprint, picks higher-rank
- collect_findings() preserves unfingerprinted findings
- collect_findings() ranking: severity × verification × KEV
- _finding_rank: severity dominates, KEV/verification add bonus
- summary() aggregates spawn / completion / finding metrics
- summary() handles missing graph helper gracefully
- wait_for_all() polls until terminal status
- wait_for_all() respects timeout
- wait_for_all() returns empty when no spawns
- All methods swallow exceptions so the lead loop is never broken
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from strix.agents.lead_team import (
    LeadTeam,
    LeadTeamSummary,
    _finding_rank,
)
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


def _make_lead_state(agent_id: str = "lead_001") -> Any:
    class _State:
        def __init__(self) -> None:
            self.agent_id = agent_id

        def get_conversation_history(self) -> list:
            return []

    return _State()


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_constructor_requires_lead_state() -> None:
    with pytest.raises(ValueError):
        LeadTeam(None)


def test_constructor_accepts_state() -> None:
    team = LeadTeam(_make_lead_state())
    assert team is not None


# ---------------------------------------------------------------------------
# spawn() — record success + failure
# ---------------------------------------------------------------------------


def test_spawn_success(monkeypatch) -> None:
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.create_agent",
        lambda **kwargs: {"success": True, "agent_id": "agent_42"},
    )
    team = LeadTeam(_make_lead_state())
    record = team.spawn(task="probe", name="X", category="sqli-specialist")
    assert record.success is True
    assert record.agent_id == "agent_42"
    assert record.category == "sqli-specialist"


def test_spawn_failure_recorded(monkeypatch) -> None:
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.create_agent",
        lambda **kwargs: {"success": False, "error": "Invalid skills"},
    )
    team = LeadTeam(_make_lead_state())
    record = team.spawn(task="probe", name="X", category="bogus")
    assert record.success is False
    assert record.error is not None
    assert "Invalid skills" in record.error


def test_spawn_exception_recorded(monkeypatch) -> None:
    """Exceptions in create_agent are swallowed; the team records
    a failure record so the lead can continue."""
    def boom(**kwargs):
        raise RuntimeError("network blip")

    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.create_agent", boom,
    )
    team = LeadTeam(_make_lead_state())
    record = team.spawn(task="probe", name="X", category="sqli-specialist")
    assert record.success is False
    assert "network blip" in (record.error or "")


def test_spawn_many(monkeypatch) -> None:
    counter = {"i": 0}
    def fake_create(**kwargs):
        counter["i"] += 1
        return {"success": True, "agent_id": f"agent_{counter['i']}"}

    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.create_agent", fake_create,
    )
    team = LeadTeam(_make_lead_state())
    out = team.spawn_many([
        {"task": "1", "name": "X1", "category": "sqli-specialist"},
        {"task": "2", "name": "X2", "category": "xss-specialist"},
        "skip-me",  # not a dict, should be skipped silently
        {"task": "3", "name": "X3", "category": "ssrf-scanner"},
    ])
    assert len(out) == 3
    assert {r.agent_id for r in out} == {"agent_1", "agent_2", "agent_3"}


# ---------------------------------------------------------------------------
# collect_findings — dedup + rank
# ---------------------------------------------------------------------------


def _emit_finding(tracer, **kwargs) -> str:
    """Helper to emit a finding via the tracer with sensible
    defaults so the canonical-contract validator passes."""
    base = {
        "title": kwargs.get("title", "Test"),
        "severity": kwargs.get("severity", "medium"),
        "category": kwargs.get("category", "csrf"),
        "endpoint": kwargs.get("endpoint", "https://app.example.com"),
        "verification_status": kwargs.get("verification_status", "needs_review"),
        "description_plain": "p",
        "recommended_action": "a",
        "cwe": kwargs.get("cwe", "CWE-352"),
    }
    if "cve" in kwargs:
        base["cve"] = kwargs["cve"]
    return tracer.add_vulnerability_report(**base)


def test_collect_findings_no_tracer_returns_empty() -> None:
    team = LeadTeam(_make_lead_state())
    # No tracer set → empty.
    out = team.collect_findings()
    assert out == []


def test_collect_findings_basic() -> None:
    tracer = Tracer("collect-basic")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})

    _emit_finding(tracer, title="A", severity="medium", endpoint="https://x/a")
    _emit_finding(tracer, title="B", severity="high", endpoint="https://x/b")

    team = LeadTeam(_make_lead_state())
    findings = team.collect_findings()
    titles = [f["title"] for f in findings]
    # Ranked by severity desc → high before medium.
    assert titles[0] == "B"
    assert titles[1] == "A"


def test_collect_findings_dedup_by_fingerprint() -> None:
    """Two specialists report the same finding (same CWE, endpoint,
    title) — fingerprint is identical → dedup."""
    tracer = Tracer("collect-dedup")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})

    # Identical title/endpoint/cwe → identical fingerprint.
    _emit_finding(tracer, title="Same", endpoint="https://x/y", severity="low")
    _emit_finding(tracer, title="Same", endpoint="https://x/y", severity="high")
    _emit_finding(tracer, title="Same", endpoint="https://x/y", severity="medium")

    team = LeadTeam(_make_lead_state())
    findings = team.collect_findings(dedup_by_fingerprint=True)
    assert len(findings) == 1
    # Higher-severity wins.
    assert findings[0]["severity"] == "high"


def test_collect_findings_dedup_disabled() -> None:
    """After PR #98, cross-tool dedup happens at write time so the
    tracer never holds two records with the same fingerprint.
    `collect_findings(dedup_by_fingerprint=False)` returns whatever
    is in the tracer — which is one record per fingerprint by
    construction. To exercise the consumer-side dedup-disable
    branch we now need to inject two distinct findings (different
    endpoints → different fingerprints)."""
    tracer = Tracer("collect-no-dedup")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})

    _emit_finding(tracer, title="Same", endpoint="https://x/y")
    _emit_finding(tracer, title="Same", endpoint="https://x/z")

    team = LeadTeam(_make_lead_state())
    findings = team.collect_findings(dedup_by_fingerprint=False)
    assert len(findings) == 2


def test_collect_findings_unfingerprinted_kept() -> None:
    """Findings without a fingerprint pass through (defensive
    against future schema changes)."""
    tracer = Tracer("collect-unfp")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})

    _emit_finding(tracer, title="Has-fp", endpoint="https://x/a")

    # Manually inject a finding with no fingerprint to simulate
    # legacy / hand-crafted entries.
    tracer.vulnerability_reports.append({
        "id": "vuln-9999",
        "title": "No fp",
        "severity": "medium",
        "verification_status": "needs_review",
    })

    team = LeadTeam(_make_lead_state())
    findings = team.collect_findings()
    titles = {f["title"] for f in findings}
    assert "Has-fp" in titles
    assert "No fp" in titles


# ---------------------------------------------------------------------------
# _finding_rank
# ---------------------------------------------------------------------------


def test_rank_severity_dominates() -> None:
    a = {"severity": "critical"}
    b = {"severity": "high", "is_kev": True, "verification_status": "verified"}
    # Even with KEV + verified, 'high' < 'critical'.
    assert _finding_rank(a) > _finding_rank(b)


def test_rank_kev_bonus() -> None:
    a = {"severity": "high", "is_kev": True}
    b = {"severity": "high"}
    assert _finding_rank(a) > _finding_rank(b)


def test_rank_ransomware_extra_bonus() -> None:
    a = {"severity": "high", "is_kev": True, "kev_ransomware_use": True}
    b = {"severity": "high", "is_kev": True}
    assert _finding_rank(a) > _finding_rank(b)


def test_rank_verification_bonus() -> None:
    a = {"severity": "medium", "verification_status": "verified"}
    b = {"severity": "medium", "verification_status": "needs_review"}
    assert _finding_rank(a) > _finding_rank(b)


def test_rank_unknown_severity_zero() -> None:
    a = {"severity": "bogus"}
    assert _finding_rank(a) >= 0  # doesn't crash


# ---------------------------------------------------------------------------
# summary()
# ---------------------------------------------------------------------------


def test_summary_no_spawns() -> None:
    team = LeadTeam(_make_lead_state())
    s = team.summary()
    assert s.spawn_count == 0
    assert s.spawn_success_count == 0
    assert s.findings_count == 0


def test_summary_aggregates_spawns(monkeypatch) -> None:
    counter = {"i": 0}
    def fake_create(**kwargs):
        counter["i"] += 1
        return {"success": True, "agent_id": f"agent_{counter['i']}"}

    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.create_agent", fake_create,
    )
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.view_agent_graph",
        lambda _state: {"nodes": [
            {"id": "agent_1", "status": "completed"},
            {"id": "agent_2", "status": "running"},
            {"id": "agent_3", "status": "failed"},
        ]},
    )

    team = LeadTeam(_make_lead_state())
    team.spawn(task="t", name="X1", category="sqli-specialist")
    team.spawn(task="t", name="X2", category="sqli-specialist")
    team.spawn(task="t", name="X3", category="xss-specialist")

    s = team.summary()
    assert s.spawn_count == 3
    assert s.spawn_success_count == 3
    assert s.completed_count == 1
    assert s.running_count == 1
    assert s.failed_count == 1
    assert s.by_category == {"sqli-specialist": 2, "xss-specialist": 1}


def test_summary_handles_view_failure(monkeypatch) -> None:
    """When view_agent_graph fails, summary returns 0 status counts
    but the spawn metadata is still surfaced."""
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.create_agent",
        lambda **kw: {"success": True, "agent_id": "agent_x"},
    )
    def boom(_state):
        raise RuntimeError("graph unavailable")

    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.view_agent_graph", boom,
    )

    team = LeadTeam(_make_lead_state())
    team.spawn(task="t", name="X1", category="sqli-specialist")
    s = team.summary()
    assert s.spawn_count == 1
    assert s.completed_count == 0
    assert s.running_count == 0


def test_summary_to_dict_serialisable() -> None:
    team = LeadTeam(_make_lead_state())
    s = team.summary()
    d = s.to_dict()
    assert "spawn_count" in d
    assert "spawn_records" in d
    # Should be JSON-serialisable (no exotic types).
    import json
    json.dumps(d)


# ---------------------------------------------------------------------------
# wait_for_all
# ---------------------------------------------------------------------------


def test_wait_for_all_no_spawns_returns_empty() -> None:
    team = LeadTeam(_make_lead_state())
    out = team.wait_for_all(timeout=0.1)
    assert out == {}


def test_wait_for_all_returns_terminal_states(monkeypatch) -> None:
    """All specialists are already terminal → returns immediately."""
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.create_agent",
        lambda **kw: {"success": True, "agent_id": kw.get("name", "agent_x")},
    )
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.view_agent_graph",
        lambda _state: {"nodes": [
            {"id": "X1", "status": "completed"},
            {"id": "X2", "status": "failed"},
        ]},
    )

    team = LeadTeam(_make_lead_state())
    team.spawn(task="t", name="X1", category="sqli-specialist")
    team.spawn(task="t", name="X2", category="xss-specialist")

    out = team.wait_for_all(timeout=2.0, poll_interval=0.1)
    assert out["X1"] == "completed"
    assert out["X2"] == "failed"


def test_wait_for_all_timed_out(monkeypatch) -> None:
    """Specialist still running past timeout → status='timed_out'."""
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.create_agent",
        lambda **kw: {"success": True, "agent_id": "agent_running"},
    )
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.view_agent_graph",
        lambda _state: {"nodes": [{"id": "agent_running", "status": "running"}]},
    )

    team = LeadTeam(_make_lead_state())
    team.spawn(task="t", name="agent_running", category="sqli-specialist")

    out = team.wait_for_all(timeout=0.3, poll_interval=0.1)
    assert out.get("agent_running") == "timed_out"


def test_wait_for_all_view_unavailable(monkeypatch) -> None:
    """When view_agent_graph throws, wait returns immediately."""
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.create_agent",
        lambda **kw: {"success": True, "agent_id": "agent_x"},
    )
    def boom(_state):
        raise RuntimeError("graph unavailable")

    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions.view_agent_graph", boom,
    )

    team = LeadTeam(_make_lead_state())
    team.spawn(task="t", name="agent_x", category="sqli-specialist")
    out = team.wait_for_all(timeout=2.0, poll_interval=0.1)
    # Function returns; doesn't raise.
    assert isinstance(out, dict)


# ---------------------------------------------------------------------------
# Composability with the rest of §8.0
# ---------------------------------------------------------------------------


def test_summary_records_canonical_finding_count() -> None:
    """Findings emitted via the canonical-contract path have
    is_canonical=True; LeadTeam summary surfaces the count."""
    tracer = Tracer("collect-canonical")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})

    _emit_finding(tracer, title="Canonical", endpoint="https://x")
    # Manually inject a non-canonical finding.
    tracer.vulnerability_reports.append({
        "id": "vuln-bad",
        "title": "Non-canon",
        "severity": "medium",
        "is_canonical": False,
    })

    team = LeadTeam(_make_lead_state())
    s = team.summary()
    assert s.findings_count == 2
    assert s.canonical_finding_count == 1
