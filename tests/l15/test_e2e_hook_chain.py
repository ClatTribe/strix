"""E2E Phase B — full L1.5 hook chain on real tracer.

Per `docs/E2E-test-proposal.md` §3.3. These exercise the COMPLETE
ordered chain (FP filter → root_cause → hygiene → surface_priority →
git_blame → exploitability → SAST→DAST planner → corroborator) against
real `Tracer.add_vulnerability_report` so cross-hook interactions are
caught.

Phase A regressions (Bug 1-4) already shipped in #428/#429; this phase
catches the next class of cross-hook interaction bugs.

Anti-patterns these tests AVOID (per E2E-test-proposal.md §5):
  * No `Tracer.__new__(Tracer)` skeleton — real constructor.
  * No `execute_tool` mock — we don't invoke specialists, only the
    tracer emission path.
  * Assert on persisted record (`tracer.vulnerability_reports[i]`),
    not in-memory dicts.
"""

from __future__ import annotations

import pytest

from strix.l15 import corroborator_ledger, hygiene_ledger, root_cause_ledger
from strix.l15.git_blame import clear_cache as _clear_blame_cache
from strix.l15.posture import clear_cache as _clear_posture_cache
from strix.telemetry.tracer import Tracer


@pytest.fixture
def tracer(tmp_path, monkeypatch):
    """Real Tracer + clean ledgers + stubbed side effects."""
    root_cause_ledger.clear()
    corroborator_ledger.clear()
    hygiene_ledger.clear()
    _clear_blame_cache()
    _clear_posture_cache()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
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
    t = Tracer(run_name="e2e-phase-b")
    # Bypass fingerprint dedup so it doesn't interfere with corroborator
    t._maybe_merge_into_existing_finding = lambda _r: None
    yield t
    root_cause_ledger.clear()
    corroborator_ledger.clear()
    hygiene_ledger.clear()
    _clear_blame_cache()
    _clear_posture_cache()


# =========================================================================
# E2E-L15-1 — full promotion chain
# =========================================================================

def test_full_hook_chain_promotion_path(tracer):
    """SAST + DAST findings on same CWE+surface → root_cause emits both
    (different rule_ids), then corroborator boosts parent severity,
    exploitability scores the post-boost record, all L1.5 fields land
    on the persisted dict.

    This is the canonical "happy path" exercising every hook.
    """
    # NB: deliberately use a user-data endpoint (not /auth/login) so
    # exploitability's auth_bypassable heuristic doesn't demote both
    # findings to info BEFORE the corroborator runs. The hook order is:
    #   FP → root_cause → hygiene → surface_priority → git_blame →
    #   exploitability → SAST→DAST → corroborator
    # Hooks 6 and 8 both touch severity. Filed separately as a known
    # ordering issue for the docs/L2-optimization.md follow-up:
    # exploitability demote can pre-empt corroborator boost when the
    # endpoint matches an auth-gated path heuristic. We test the
    # corroborator path here against a non-auth endpoint so the
    # exploitability score lands at neutral 0.5 (composite=0.25 → leave).
    sast_id = tracer.add_vulnerability_report(
        title="Potential SQLi (SAST)",
        severity="medium",
        cwe="CWE-89",
        rule_id="semgrep-sqli-string-concat",
        endpoint="https://app.example.com/api/v1/products/42",
        code_locations=[{
            "file": "src/products/view.py",
            "line": 42,
            "snippet": "query = f\"... id = {request.args.get('id')}\"",
        }],
        discovery_source_tool="semgrep",
    )
    dast_id = tracer.add_vulnerability_report(
        title="SQLi confirmed (DAST)",
        severity="medium",
        cwe="CWE-89",
        endpoint="https://app.example.com/api/v1/products/42",
        discovery_source_tool="sqlmap",
    )

    # Both persisted; sast is the parent.
    assert len(tracer.vulnerability_reports) == 2
    parent = next(
        r for r in tracer.vulnerability_reports if r["id"] == sast_id
    )
    child = next(
        r for r in tracer.vulnerability_reports if r["id"] == dast_id
    )

    # Wave 1 — corroborator: parent boosted, child demoted to corroborator
    assert parent["severity"] == "high", (
        f"parent severity should be bumped one tier (medium → high); "
        f"got {parent['severity']} — likely exploitability hook ordering "
        f"interaction (KNOWN ISSUE if path matches an auth-gated heuristic)"
    )
    assert dast_id in (parent.get("corroborated_by") or []), (
        "parent must record the corroborator id"
    )
    assert child["severity"] == "info"
    assert child.get("role") == "corroborator"
    assert child.get("corroborates") == sast_id

    # Wave 3 — surface_priority on parent (/products/* is "normal")
    assert parent.get("surface_priority", {}).get("label") in (
        "normal", "high", "critical",
    )

    # Wave 2 — exploitability block exists on parent
    expl = parent.get("exploitability")
    assert isinstance(expl, dict)
    assert "composite" in expl
    assert "code_reachable" in expl
    assert 0.0 <= expl["composite"] <= 1.0

    # Wave 2 — SAST→DAST planner attached pending_confirmations on parent
    pending = parent.get("pending_confirmations") or []
    assert any(
        p.get("tool") == "scan_sqli_sqlmap" for p in pending
    ), "SAST-shape finding must queue a sqlmap confirmation"

    # Wave 4 — probe-bundle plan reflects /api/v1/auth being a critical
    # surface (auth burst). Bundle may be empty if classifier doesn't
    # match — but reasoning_trace should reflect corroborator + any
    # severity bumps.
    trace = parent.get("reasoning_trace") or []
    if isinstance(trace, str):
        trace = [trace]
    assert any("corroborated" in line.lower() for line in trace), (
        "reasoning_trace should explain the corroborator boost"
    )


# =========================================================================
# E2E-L15-4 — hook exception passthrough
# =========================================================================

def test_hook_exception_does_not_block_emission(tracer, monkeypatch):
    """Inject a fault into the exploitability scorer. The emission
    must still complete (other hooks run, finding persists).

    Recall-safety: per docs/L2-optimization.md §7, L1.5 failure
    must NEVER make L2 worse off than no-L1.5. The try/except
    wrappers around each hook must hold under fault injection.
    """
    def _boom(_finding):
        raise RuntimeError("simulated scorer crash")

    monkeypatch.setattr(
        "strix.l15.score_exploitability", _boom,
    )
    # Direct import paths might be cached — also patch via the
    # explicit module
    monkeypatch.setattr(
        "strix.l15.exploitability.score_exploitability", _boom,
    )

    finding_id = tracer.add_vulnerability_report(
        title="Test finding",
        severity="high",
        cwe="CWE-89",
        endpoint="https://app.example.com/api/v1/users/42",
        discovery_source_tool="semgrep",
    )

    # Finding still persisted despite the crash in one hook
    assert len(tracer.vulnerability_reports) == 1
    row = tracer.vulnerability_reports[0]
    assert row["id"] == finding_id

    # Other hooks still ran:
    # - surface_priority: /api/v1/users/* is "high" (user routes)
    assert row.get("surface_priority", {}).get("label") in (
        "critical", "high", "normal",
    )
    # - exploitability hook was the one that crashed; field absent or
    #   defaulted is fine, as long as it didn't poison anything else
    # - severity must not be downgraded by the crash
    assert row["severity"] == "high"


# =========================================================================
# E2E-L15-5 — root-cause systemic promotion
# =========================================================================

def test_systemic_promotion_collapses_repeat_findings(tracer):
    """Emit 12 findings with the same (rule_id, file, function) tuple.
    Only ONE finding persists; the rest become occurrences[] on the
    parent. At some point in the sequence, the systemic threshold (8
    per docs/L2-optimization.md §4 Gap 5) trips and the parent's
    severity bumps one tier with a `systemic` reasoning_trace line.

    This is the "drop L2 input tokens 3-5x on vibe-coded targets"
    behavior in §4 Gap 5.
    """
    finding_ids = []
    for i in range(12):
        fid = tracer.add_vulnerability_report(
            title="Hardcoded credential literal",
            severity="medium",
            rule_id="strix-hardcoded-credential-literal-python",
            code_locations=[{
                "file": "src/auth.py",
                "function": "login",
                "line": 10 + i,
            }],
            cwe="CWE-798",
        )
        finding_ids.append(fid)

    # Only ONE record persisted (parent + 11 collapsed occurrences)
    assert len(tracer.vulnerability_reports) == 1
    parent = tracer.vulnerability_reports[0]

    # Occurrences[] populated with the duplicates
    occurrences = parent.get("occurrences") or []
    assert len(occurrences) == 11, (
        f"expected 11 occurrences (12 emissions - 1 parent), got "
        f"{len(occurrences)}"
    )

    # All but the first ID share the parent id — caller's API contract
    # promises "next call returns the parent id when collapsed".
    assert finding_ids[0] == parent["id"]
    assert all(fid == parent["id"] for fid in finding_ids[1:])

    # Systemic promotion: at some point severity bumped (medium → high)
    # AND a `systemic` line is in reasoning_trace
    trace = parent.get("reasoning_trace") or []
    if isinstance(trace, str):
        trace = [trace]
    systemic_lines = [
        line for line in trace if "systemic" in str(line).lower()
    ]
    assert len(systemic_lines) >= 1, (
        f"expected at least one 'systemic' line in reasoning_trace, "
        f"got: {trace}"
    )
    assert parent["severity"] == "high", (
        f"severity should be promoted medium→high by systemic threshold; "
        f"got {parent['severity']}"
    )


# =========================================================================
# E2E-L15-1b — sanity: token-cost reduction claim from the docs
# =========================================================================

def test_l15_chain_reduces_persisted_record_count(tracer):
    """L1.5's whole point is that 30 raw SAST hits don't all reach L2.
    Emit 30 findings hitting various collapse / dedup paths; assert
    the persisted count is dramatically lower.

    Concrete shape: 20 hits of the same SAST rule × file (collapse to
    1); 10 hits with different rule_ids on a single endpoint (one
    parent + 9 corroborators OR independent emits). Cap: under 12
    persisted (a 60% drop from raw 30).
    """
    # 20 collapsing SAST hits
    for i in range(20):
        tracer.add_vulnerability_report(
            title="Hardcoded credential literal",
            severity="medium",
            rule_id="strix-hardcoded-cred",
            code_locations=[{
                "file": "src/secrets.py",
                "function": "load_keys",
                "line": 5 + i,
            }],
            cwe="CWE-798",
        )

    # 10 mixed hits on the same endpoint (DAST corroborates SAST)
    for i in range(10):
        tracer.add_vulnerability_report(
            title=f"Finding {i}",
            severity="medium",
            cwe="CWE-89",
            rule_id=f"rule-{i}",
            endpoint="https://e.com/api/v1/search",
            discovery_source_tool="semgrep" if i < 5 else "sqlmap",
        )

    persisted = len(tracer.vulnerability_reports)
    assert persisted <= 12, (
        f"L1.5 chain should compress 30 raw emissions to ≤12 persisted, "
        f"got {persisted}"
    )
