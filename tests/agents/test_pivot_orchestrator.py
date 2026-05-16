"""Tests for `strix.agents.pivot_orchestrator` — depth gap #2.

The orchestrator is the forward-attack-chain layer: once a finding
lands with `verification_status='exploited'` AND
`proof_artifact_path` set, it dispatches pivot specialists keyed by
the impact-type extracted from the proof filename.

Tests cover:

  * Impact-type extraction from proof_artifact_path
  * Entry guards (verification_status != exploited; missing proof;
    kill switch; depth cap; budget cap)
  * Dispatch ordering matches registration order
  * Specialist exceptions logged + recorded, never raise
  * Outcome shapes: pivoted (with emitted_finding_id),
    dead_end, error, skipped
  * KG PIVOTED_FROM edge fires on pivoted outcome
  * `to_dict` shape for wrapper consumption
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from strix.agents import pivot_orchestrator
from strix.agents.pivot_orchestrator import (
    DEFAULT_MAX_DEPTH,
    PivotChainOutcome,
    PivotResult,
    register_pivot,
    run_pivot_chain,
)


# ---------------------------------------------------------------------------
# Fixtures — fresh registry per test + tmp run dir for KG persistence
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_registry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    pivot_orchestrator.reset_for_testing()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_PIVOT_ORCHESTRATOR_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)
    # Reset the KG too so PIVOTED_FROM edge counts are clean.
    from strix.agents import knowledge_graph as kg
    kg.reset_for_testing()
    yield
    pivot_orchestrator.reset_for_testing()


def _exploited_finding(
    *,
    finding_id: str = "vuln-0001",
    impact_type: str = "cookie_theft",
    fingerprint: str = "fp-source",
) -> dict[str, Any]:
    """Build a canonical exploited-tier finding for orchestrator
    input. Path shape mirrors `proof_of_impact.capture_proof_of_impact`."""
    return {
        "id": finding_id,
        "title": "Reflected XSS captured admin cookie",
        "severity": "high",
        "verification_status": "exploited",
        "proof_artifact_path": (
            f"proof_of_impact/{fingerprint}.{impact_type}.bin"
        ),
        "target": "https://app.test",
        "category": "xss",
    }


# ---------------------------------------------------------------------------
# Impact-type extraction
# ---------------------------------------------------------------------------


def test_impact_type_extracted_from_proof_filename() -> None:
    outcome = run_pivot_chain(source_finding=_exploited_finding(
        impact_type="metadata_exfil", fingerprint="fp-x",
    ))
    assert outcome.impact_type == "metadata_exfil"


def test_impact_type_none_when_proof_path_malformed() -> None:
    finding = _exploited_finding()
    finding["proof_artifact_path"] = "broken"   # no `.<impact>.bin`
    outcome = run_pivot_chain(source_finding=finding)
    assert outcome.impact_type is None
    assert "impact_type" in outcome.chain_terminated_reason


# ---------------------------------------------------------------------------
# Entry guards
# ---------------------------------------------------------------------------


def test_only_exploited_status_triggers_orchestrator() -> None:
    finding = _exploited_finding()
    finding["verification_status"] = "verified"
    outcome = run_pivot_chain(source_finding=finding)
    assert outcome.specialists_attempted == []
    assert "exploited" in outcome.chain_terminated_reason


def test_missing_proof_path_terminates_chain() -> None:
    finding = _exploited_finding()
    finding.pop("proof_artifact_path")
    outcome = run_pivot_chain(source_finding=finding)
    assert outcome.specialists_attempted == []


def test_kill_switch_short_circuits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_PIVOT_ORCHESTRATOR_DISABLED", "1")

    @register_pivot(name="should_not_fire", impact_types=["cookie_theft"])
    def _should_not_fire(**_kwargs) -> PivotResult:
        pytest.fail("kill switch should have prevented dispatch")
        return PivotResult(outcome="dead_end")

    outcome = run_pivot_chain(source_finding=_exploited_finding())
    assert outcome.specialists_attempted == []
    assert outcome.chain_terminated_reason == "kill_switch"


def test_no_specialists_for_impact_type_terminates() -> None:
    # No specialist registered for cookie_theft.
    outcome = run_pivot_chain(source_finding=_exploited_finding(
        impact_type="cookie_theft",
    ))
    assert outcome.specialists_attempted == []
    assert "no pivot specialists registered" in outcome.chain_terminated_reason


def test_max_depth_exceeded_terminates_chain() -> None:
    @register_pivot(name="depth_sentinel", impact_types=["cookie_theft"])
    def _depth_sentinel(**_kwargs) -> PivotResult:
        pytest.fail("max_depth should have prevented dispatch")
        return PivotResult(outcome="dead_end")

    outcome = run_pivot_chain(
        source_finding=_exploited_finding(),
        _depth=DEFAULT_MAX_DEPTH + 1,
    )
    assert outcome.specialists_attempted == []
    assert "max_depth" in outcome.chain_terminated_reason


# ---------------------------------------------------------------------------
# Dispatch ordering + budget
# ---------------------------------------------------------------------------


def test_specialists_dispatched_in_registration_order() -> None:
    call_log: list[str] = []

    @register_pivot(name="first", impact_types=["cookie_theft"])
    def _first(**_kwargs) -> PivotResult:
        call_log.append("first")
        return PivotResult(outcome="dead_end")

    @register_pivot(name="second", impact_types=["cookie_theft"])
    def _second(**_kwargs) -> PivotResult:
        call_log.append("second")
        return PivotResult(outcome="dead_end")

    run_pivot_chain(source_finding=_exploited_finding())
    assert call_log == ["first", "second"]


def test_pivot_budget_caps_dispatched_count() -> None:
    call_log: list[str] = []

    for i in range(5):
        @register_pivot(name=f"spec_{i}", impact_types=["cookie_theft"])
        def _spec(**_kwargs) -> PivotResult:
            call_log.append("hit")
            return PivotResult(outcome="dead_end")

    outcome = run_pivot_chain(
        source_finding=_exploited_finding(),
        pivot_budget=2,
    )
    assert len(call_log) == 2
    assert "pivot_budget=2 exhausted" in outcome.chain_terminated_reason


# ---------------------------------------------------------------------------
# Specialist exceptions
# ---------------------------------------------------------------------------


def test_specialist_exception_recorded_not_raised() -> None:
    @register_pivot(name="broken", impact_types=["cookie_theft"])
    def _broken(**_kwargs) -> PivotResult:
        raise RuntimeError("intentional test failure")

    outcome = run_pivot_chain(source_finding=_exploited_finding())
    assert len(outcome.specialists_attempted) == 1
    result = outcome.specialists_attempted[0]
    assert result.outcome == "error"
    assert "RuntimeError" in result.detail
    assert "intentional test failure" in result.detail


def test_specialist_can_return_pivoted_outcome() -> None:
    @register_pivot(name="real_pivot", impact_types=["cookie_theft"])
    def _real(**_kwargs) -> PivotResult:
        return PivotResult(
            outcome="pivoted",
            emitted_finding_id="vuln-0002",
            detail="captured admin session via cookie replay",
        )

    outcome = run_pivot_chain(source_finding=_exploited_finding())
    assert outcome.emitted_finding_ids == ["vuln-0002"]
    assert outcome.specialists_attempted[0].outcome == "pivoted"


# ---------------------------------------------------------------------------
# KG PIVOTED_FROM edge
# ---------------------------------------------------------------------------


def test_pivot_edge_recorded_on_successful_pivot() -> None:
    """When a specialist returns `pivoted` with an emitted finding
    id, the orchestrator drops a PIVOTED_FROM edge in the KG.
    The edge runs target → source (the new finding pivoted FROM
    the original)."""
    from strix.agents import knowledge_graph as kg

    graph = kg.get_kg()
    source_node = graph.add_node(
        type="Vuln", props={"finding_id": "vuln-0001", "category": "xss"},
    )
    target_node = graph.add_node(
        type="Vuln",
        props={"finding_id": "vuln-0002", "category": "account_takeover"},
    )

    @register_pivot(name="pivots", impact_types=["cookie_theft"])
    def _pivots(**_kwargs) -> PivotResult:
        return PivotResult(
            outcome="pivoted", emitted_finding_id="vuln-0002",
        )

    run_pivot_chain(source_finding=_exploited_finding(
        finding_id="vuln-0001",
    ))

    edges = graph.query_edges(
        type="PIVOTED_FROM", source=target_node.id, target=source_node.id,
    )
    assert len(edges) == 1


def test_pivot_edge_skipped_when_target_vuln_node_missing() -> None:
    """Defensive: if the new finding hasn't been added to the KG
    yet, the orchestrator should log + continue, not raise."""
    from strix.agents import knowledge_graph as kg

    graph = kg.get_kg()
    graph.add_node(type="Vuln", props={"finding_id": "vuln-0001"})

    @register_pivot(name="emit_missing", impact_types=["cookie_theft"])
    def _emit(**_kwargs) -> PivotResult:
        return PivotResult(
            outcome="pivoted",
            emitted_finding_id="vuln-NOT-IN-KG",
        )

    outcome = run_pivot_chain(source_finding=_exploited_finding(
        finding_id="vuln-0001",
    ))
    # Specialist still recorded as pivoted — only the edge fails.
    assert outcome.specialists_attempted[0].outcome == "pivoted"
    assert graph.stats()["edge_types"].get("PIVOTED_FROM", 0) == 0


# ---------------------------------------------------------------------------
# to_dict shape — wrapper contract
# ---------------------------------------------------------------------------


def test_to_dict_shape_for_wrapper() -> None:
    @register_pivot(name="ok", impact_types=["cookie_theft"])
    def _ok(**_kwargs) -> PivotResult:
        return PivotResult(
            outcome="pivoted",
            emitted_finding_id="vuln-0002",
            detail="captured admin session",
            elapsed_seconds=0.42,
        )

    outcome = run_pivot_chain(source_finding=_exploited_finding())
    d = outcome.to_dict()
    assert d["source_finding_id"] == "vuln-0001"
    assert d["impact_type"] == "cookie_theft"
    assert d["emitted_finding_ids"] == ["vuln-0002"]
    assert len(d["specialists_attempted"]) == 1
    spec = d["specialists_attempted"][0]
    assert spec["specialist_name"] == "ok"
    assert spec["outcome"] == "pivoted"
    assert spec["emitted_finding_id"] == "vuln-0002"


# ---------------------------------------------------------------------------
# Built-in specialists (stubs from pivot_specialists.py)
# ---------------------------------------------------------------------------


def test_builtin_specialists_register_on_import() -> None:
    """Importing `pivot_specialists` populates the playbook with
    the built-in stubs — cookie_theft, metadata_exfil, rce_output,
    idor_record routes are all wired."""
    # The autouse fixture clears the registry before each test, so
    # we re-import to repopulate.
    import importlib

    from strix.agents import pivot_specialists
    importlib.reload(pivot_specialists)

    assert "cookie_replay_admin_probe" in pivot_orchestrator.lookup_playbook(
        "cookie_theft",
    )
    assert "cookie_replay_admin_probe" in pivot_orchestrator.lookup_playbook(
        "auth_bypass_session",
    )
    assert "imds_iam_credential_extract" in pivot_orchestrator.lookup_playbook(
        "metadata_exfil",
    )
    assert "rce_secrets_scrape" in pivot_orchestrator.lookup_playbook(
        "rce_output",
    )
    assert "idor_bulk_enumeration" in pivot_orchestrator.lookup_playbook(
        "idor_record",
    )


def test_builtin_stubs_return_dead_end_without_target_context() -> None:
    """Stubs are wiring-only: missing context → dead_end (not
    error). Replacing the stub bodies is a follow-up PR."""
    import importlib

    from strix.agents import pivot_specialists
    importlib.reload(pivot_specialists)

    outcome = run_pivot_chain(
        source_finding=_exploited_finding(impact_type="cookie_theft"),
        target_context={},
    )
    assert len(outcome.specialists_attempted) == 1
    assert outcome.specialists_attempted[0].outcome == "dead_end"
