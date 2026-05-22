"""End-to-end: L1.5 hooks wired into tracer.add_vulnerability_report."""

from __future__ import annotations

import pytest

from strix.l15 import corroborator_ledger, root_cause_ledger
from strix.telemetry.tracer import Tracer


@pytest.fixture
def tracer(tmp_path, monkeypatch):
    """Fresh real Tracer + clean ledgers per test."""
    root_cause_ledger.clear()
    corroborator_ledger.clear()
    # Point the run dir at a tmpdir so artefacts go nowhere we care.
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    t = Tracer(run_name="l15-int-test")
    # Stub the side-effects we don't want firing.
    t._emit_event = lambda *a, **k: None
    t._maybe_merge_into_existing_finding = lambda r: None
    yield t
    root_cause_ledger.clear()
    corroborator_ledger.clear()


def test_fp_filter_drops_obvious_fp(tracer, monkeypatch):
    """A high finding inside examples/ should NEVER be persisted."""
    # Strip out posthog + KG side-effects that the constructor normally
    # wires up but our skeleton tracer doesn't have.
    monkeypatch.setattr(
        "strix.telemetry.tracer.posthog.finding",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.telemetry.tracer._emit_kg_auto_for_finding",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.llm.kev_enrichment.resolve_kev_block",
        lambda **_k: {},
    )
    monkeypatch.setattr(
        "strix.llm.campaign_enrichment.resolve_campaign_block",
        lambda **_k: {"matched_pulse_count": 0, "matched_pulses": []},
    )
    rid = tracer.add_vulnerability_report(
        title="Hardcoded creds",
        severity="high",
        code_locations=[{"file": "examples/quickstart.py", "line": 1}],
        cwe="CWE-798",
    )
    # Returned id is the same string format but nothing got persisted.
    assert isinstance(rid, str)
    assert len(tracer.vulnerability_reports) == 0


def test_root_cause_collapse_e2e(tracer, monkeypatch):
    """Two SAST findings for the same rule×file×func → one row with
    occurrences[]."""
    monkeypatch.setattr(
        "strix.telemetry.tracer.posthog.finding",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.telemetry.tracer._emit_kg_auto_for_finding",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.llm.kev_enrichment.resolve_kev_block",
        lambda **_k: {},
    )
    monkeypatch.setattr(
        "strix.llm.campaign_enrichment.resolve_campaign_block",
        lambda **_k: {"matched_pulse_count": 0, "matched_pulses": []},
    )
    id1 = tracer.add_vulnerability_report(
        title="Hardcoded credential",
        severity="medium",
        rule_id="strix-hardcoded-cred",
        code_locations=[{"file": "src/auth.py", "function": "login", "line": 5}],
        cwe="CWE-798",
    )
    id2 = tracer.add_vulnerability_report(
        title="Hardcoded credential",
        severity="medium",
        rule_id="strix-hardcoded-cred",
        code_locations=[{"file": "src/auth.py", "function": "login", "line": 17}],
        cwe="CWE-798",
    )
    # Second call returns the SAME id (collapsed) and there's still
    # only one row persisted, with two occurrences.
    assert id1 == id2
    assert len(tracer.vulnerability_reports) == 1
    occs = tracer.vulnerability_reports[0].get("occurrences", [])
    assert len(occs) == 1  # the duplicate (parent itself isn't in occurrences[])
    assert occs[0]["line"] == 17


def test_dropped_finding_does_not_collide_id(tracer, monkeypatch):
    """iter-25-fix regression: when L1.5's FP filter drops a finding,
    the next real finding must NOT inherit the dropped ID.

    Original bug: report_id was computed from
    len(vulnerability_reports)+1, but dropped findings never get
    appended → counter doesn't advance → next call generates the
    same ID. Anything keyed on report_id (update_finding,
    dismiss_finding, patcher chain) would now operate on the wrong
    record.
    """
    monkeypatch.setattr(
        "strix.telemetry.tracer.posthog.finding", lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.telemetry.tracer._emit_kg_auto_for_finding",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.llm.kev_enrichment.resolve_kev_block", lambda **_k: {},
    )
    monkeypatch.setattr(
        "strix.llm.campaign_enrichment.resolve_campaign_block",
        lambda **_k: {"matched_pulse_count": 0, "matched_pulses": []},
    )

    # First call — L1.5 will DROP this (file under examples/, severity
    # not critical)
    id1 = tracer.add_vulnerability_report(
        title="Drop me",
        severity="high",
        code_locations=[{"file": "examples/demo.py", "line": 1}],
        cwe="CWE-798",
    )
    # Second call — real finding, must persist with DIFFERENT id
    id2 = tracer.add_vulnerability_report(
        title="Real finding",
        severity="high",
        code_locations=[{"file": "src/auth.py", "line": 1}],
        cwe="CWE-89",
        endpoint="https://e.com/login",
    )
    assert id1 != id2, "FP-dropped finding must not collide with next"
    assert len(tracer.vulnerability_reports) == 1
    assert tracer.vulnerability_reports[0]["id"] == id2


def test_corroborator_boost_e2e(tracer, monkeypatch):
    """SAST + DAST hit on same CWE+surface → parent severity bumps to
    critical, second finding becomes corroborator."""
    monkeypatch.setattr(
        "strix.telemetry.tracer.posthog.finding",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.telemetry.tracer._emit_kg_auto_for_finding",
        lambda *_a, **_k: None,
    )
    monkeypatch.setattr(
        "strix.llm.kev_enrichment.resolve_kev_block",
        lambda **_k: {},
    )
    monkeypatch.setattr(
        "strix.llm.campaign_enrichment.resolve_campaign_block",
        lambda **_k: {"matched_pulse_count": 0, "matched_pulses": []},
    )
    sast_id = tracer.add_vulnerability_report(
        title="SAST: SQL string concat",
        severity="medium",
        cwe="CWE-89",
        endpoint="https://example.com/login",
        discovery_source_tool="semgrep",
    )
    dast_id = tracer.add_vulnerability_report(
        title="DAST: SQLi confirmed",
        severity="medium",
        cwe="CWE-89",
        endpoint="https://example.com/login",
        discovery_source_tool="sqlmap",
    )
    # Both rows persist (corroborator dedup is on identity, not
    # presence — the LLM may still want to read both).
    assert len(tracer.vulnerability_reports) == 2
    sast_row = next(
        r for r in tracer.vulnerability_reports if r["id"] == sast_id
    )
    dast_row = next(
        r for r in tracer.vulnerability_reports if r["id"] == dast_id
    )
    # Parent (sast) bumped one tier: medium → high
    assert sast_row["severity"] == "high"
    # Corroborator (dast) demoted to info with role flag
    assert dast_row["severity"] == "info"
    assert dast_row["role"] == "corroborator"
    assert dast_row["corroborates"] == sast_id
    # Parent has corroborated_by attached
    assert dast_id in sast_row.get("corroborated_by", [])
