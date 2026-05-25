"""Tests for iter-33.4 — chain re-prompting on chain promotion."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from strix.agents.lead_agent.mid_scan_correlate import (
    _CHAIN_KIND_TO_NEXT_STEPS,
    _DEFAULT_NEXT_STEP,
    _next_step_for_kind,
    _promote_chain_parent,
)


# ---------------------------------------------------------------------------
# _next_step_for_kind — mapping
# ---------------------------------------------------------------------------

def test_returns_specific_step_for_priv_escalation():
    out = _next_step_for_kind("heuristic_privilege_escalation_chain")
    assert "auth-bypass" in out.lower()
    assert "admin" in out.lower() or "escalation" in out.lower()


def test_returns_specific_step_for_credential_extraction():
    out = _next_step_for_kind("heuristic_credential_extraction_chain")
    assert "credential" in out.lower()


def test_returns_specific_step_for_data_exfil():
    out = _next_step_for_kind("heuristic_data_exfil_chain")
    assert "exfil" in out.lower() or "dump" in out.lower() or "enumerate" in out.lower()


def test_returns_specific_step_for_bola_at_scale():
    out = _next_step_for_kind("heuristic_bola_at_scale_chain")
    assert "bola" in out.lower() or "idor" in out.lower() or "sweep" in out.lower()


def test_returns_specific_step_for_strict_sca_sast_dast():
    out = _next_step_for_kind("sca_sast_dast")
    assert "regression" in out.lower() or "patched" in out.lower()


def test_returns_default_for_unknown_kind():
    out = _next_step_for_kind("totally_invented_chain_kind")
    assert out == _DEFAULT_NEXT_STEP


def test_returns_default_for_none():
    out = _next_step_for_kind(None)
    assert out == _DEFAULT_NEXT_STEP


def test_returns_default_for_non_string():
    out = _next_step_for_kind(42)  # type: ignore[arg-type]
    assert out == _DEFAULT_NEXT_STEP


# ---------------------------------------------------------------------------
# _promote_chain_parent — attaches next_exploit_step + reasoning_trace
# ---------------------------------------------------------------------------

def _make_tracer(reports):
    tr = MagicMock()
    tr.vulnerability_reports = reports
    return tr


def _make_chain(*, chain_id, members, kind=None, chain_type=None):
    chain = MagicMock()
    chain.id = chain_id
    chain.chain_id = chain_id
    if kind:
        chain.kind = kind
    if chain_type:
        chain.chain_type = chain_type
    chain.members = members
    return chain


def test_promote_attaches_next_exploit_step_to_chain_summary():
    """When a chain is promoted, the parent's chain_summary must
    carry the iter-33.4 next_exploit_step field."""
    parent = {"id": "v1", "severity": "medium"}
    tracer = _make_tracer([parent])
    chain = _make_chain(
        chain_id="c1", members=["v1", "v2"],
        kind="heuristic_privilege_escalation_chain",
    )
    n = _promote_chain_parent(tracer, chain, to_phase="exploit")
    assert n == 1
    assert "chain_summary" in parent
    cs = parent["chain_summary"]
    assert "next_exploit_step" in cs
    assert "auth-bypass" in cs["next_exploit_step"].lower()


def test_promote_appends_next_step_to_reasoning_trace():
    """The next-step text must also land in reasoning_trace so the
    LLM sees it via list_pending_findings."""
    parent = {"id": "v1", "severity": "low"}
    tracer = _make_tracer([parent])
    chain = _make_chain(
        chain_id="c1", members=["v1", "v2"],
        kind="heuristic_credential_extraction_chain",
    )
    _promote_chain_parent(tracer, chain, to_phase="report")
    trace = parent["reasoning_trace"]
    assert any("iter-33.4 next-step" in line for line in trace)
    assert any("credential" in line.lower() for line in trace)


def test_promote_uses_chain_type_when_kind_missing():
    """When the chain object exposes `chain_type` instead of `kind`,
    fall back to that for the next-step lookup."""
    parent = {"id": "v1", "severity": "medium"}
    tracer = _make_tracer([parent])
    chain = MagicMock()
    chain.id = "c1"
    chain.chain_id = "c1"
    chain.members = ["v1", "v2"]
    # No `kind` attr — only chain_type
    chain.kind = None
    chain.label = None
    chain.chain_type = "sca_sast_dast"
    n = _promote_chain_parent(tracer, chain, to_phase="exploit")
    assert n == 1
    assert "regression" in parent["chain_summary"]["next_exploit_step"].lower()


def test_promote_uses_default_step_for_unknown_kind():
    parent = {"id": "v1", "severity": "medium"}
    tracer = _make_tracer([parent])
    chain = _make_chain(chain_id="c1", members=["v1", "v2"], kind="unknown_x")
    _promote_chain_parent(tracer, chain, to_phase="exploit")
    assert parent["chain_summary"]["next_exploit_step"] == _DEFAULT_NEXT_STEP


def test_promote_preserves_existing_reasoning_trace():
    """An existing reasoning_trace list should be extended, not
    replaced."""
    parent = {
        "id": "v1", "severity": "medium",
        "reasoning_trace": ["prior line 1", "prior line 2"],
    }
    tracer = _make_tracer([parent])
    chain = _make_chain(
        chain_id="c1", members=["v1", "v2"],
        kind="heuristic_privilege_escalation_chain",
    )
    _promote_chain_parent(tracer, chain, to_phase="exploit")
    trace = parent["reasoning_trace"]
    assert "prior line 1" in trace
    assert "prior line 2" in trace
    assert any("iter-33.4" in line for line in trace)


def test_promote_bumps_severity_and_attaches_next_step_together():
    """Severity bump + next_exploit_step happen in the same
    promotion."""
    parent = {"id": "v1", "severity": "low"}
    tracer = _make_tracer([parent])
    chain = _make_chain(
        chain_id="c1", members=["v1", "v2"],
        kind="heuristic_data_exfil_chain",
    )
    _promote_chain_parent(tracer, chain, to_phase="impact")
    assert parent["severity"] == "medium"  # low → medium
    assert "next_exploit_step" in parent["chain_summary"]


def test_promote_returns_0_when_parent_not_in_tracer():
    """No matching finding in tracer.vulnerability_reports → no-op."""
    tracer = _make_tracer([])  # empty
    chain = _make_chain(
        chain_id="c1", members=["v1", "v2"], kind="heuristic_data_exfil_chain",
    )
    assert _promote_chain_parent(tracer, chain, to_phase="exploit") == 0


# ---------------------------------------------------------------------------
# All 4 heuristic chain kinds have a specific (non-default) next step
# ---------------------------------------------------------------------------

def test_all_four_heuristic_chains_have_specific_next_steps():
    """The iter-33.3 heuristic linkers' link_type values must each
    have a non-default iter-33.4 prompt registered. Catches the
    common bug where a new linker ships but the prompt mapping
    forgets to extend."""
    for kind in (
        "heuristic_privilege_escalation_chain",
        "heuristic_credential_extraction_chain",
        "heuristic_data_exfil_chain",
        "heuristic_bola_at_scale_chain",
    ):
        out = _next_step_for_kind(kind)
        assert out != _DEFAULT_NEXT_STEP, (
            f"iter-33.4 missing specific prompt for chain kind: {kind!r}"
        )
        # And it should be a non-trivial paragraph
        assert len(out) > 80, (
            f"iter-33.4 prompt for {kind!r} too short to be useful: {out!r}"
        )


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_next_step_prompts_have_no_sut_specific_strings():
    """Chain prompts must give shape-based guidance, not SUT-specific
    URLs / credentials / identifiers."""
    for kind, prompt in _CHAIN_KIND_TO_NEXT_STEPS.items():
        text = prompt.lower()
        forbidden = (
            "bkimminich", "juice-sh.op", "/rest/user/login",
            "/users/v1/_debug", "vampi", "erev0s", "juice-shop",
            "jsmith", "demo1234",
        )
        for tok in forbidden:
            assert tok not in text, (
                f"chain-kind {kind!r} prompt contains SUT token {tok!r}"
            )


def test_source_has_no_sut_specific_strings():
    """The iter-33.4 source section must not reference SUT tokens."""
    import strix.agents.lead_agent.mid_scan_correlate as mod
    src = open(mod.__file__).read()
    start = src.find("iter-33.4")
    assert start > 0, "iter-33.4 marker missing from source"
    iter_section = src[start:].lower()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "/users/v1/_debug", "vampi", "erev0s", "juice-shop",
    )
    for tok in forbidden:
        assert tok not in iter_section, (
            f"SUT-specific token {tok!r} in iter-33.4 source"
        )
