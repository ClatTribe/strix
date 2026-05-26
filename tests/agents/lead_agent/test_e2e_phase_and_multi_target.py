"""E2E Phase F.5 + F.6 — workflow phase transitions + multi-target union.

F.5 — Phase transitions
  When a scan moves recon → probe → report, the catalog visible to
  the Lead changes (phase filter intersects with target-type set).
  L1.5 enrichment on findings emitted during recon must SURVIVE the
  phase transition — the persisted record's exploitability /
  surface_priority / corroborated_by fields must still be readable
  after the workflow advances.

F.6 — Multi-target union
  Vibe-coded SaaS targets typically pair `web_application` with
  `repository` (frontend deployed + repo source available). The
  catalog union must include tools from BOTH target_types, and L1.5
  enrichment must fire on findings regardless of which target type
  they were emitted against.
"""

from __future__ import annotations

import pytest

from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog
from strix.l15 import corroborator_ledger, hygiene_ledger, root_cause_ledger
from strix.l15.git_blame import clear_cache as _clear_blame_cache
from strix.l15.posture import clear_cache as _clear_posture_cache
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture
def tracer(tmp_path, monkeypatch):
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
    t = Tracer(run_name="e2e-phase-f56")
    t._maybe_merge_into_existing_finding = lambda _r: None
    set_global_tracer(t)
    yield t
    root_cause_ledger.clear()
    corroborator_ledger.clear()
    hygiene_ledger.clear()
    _clear_blame_cache()
    _clear_posture_cache()
    set_global_tracer(None)


# =========================================================================
# F.5 — workflow phase transitions preserve L1.5 enrichment
# =========================================================================

def test_l15_enrichment_survives_phase_transition(tracer):
    """Emit findings during the recon phase; advance to probe; assert
    the L1.5 fields on those findings are still present + readable
    via list_pending_findings.

    Catches "phase filter drops L1.5 fields" bug class — if the
    catalog filter ever started stripping fields off findings, this
    test would catch it.
    """
    # Recon-phase emission with all L1.5 fields
    recon_id = tracer.add_vulnerability_report(
        title="SAST hit during recon",
        severity="medium",
        cwe="CWE-89",
        rule_id="semgrep-sqli",
        endpoint="https://app.example.com/admin/users",
        code_locations=[{"file": "src/admin.py", "line": 5}],
        discovery_source_tool="semgrep",
        verification_status="exploited",  # forces exploitability promote
    )
    row = tracer.vulnerability_reports[0]
    # Confirm enrichment landed on emission (Phase B coverage)
    assert "exploitability" in row
    assert "surface_priority" in row

    # Simulate the workflow advancing from recon to probe by querying
    # the catalog with phase="probe". The PERSISTED finding row must
    # be untouched.
    catalog_probe = get_lead_tool_catalog(
        target_types={"web_application"}, phase="probe",
    )
    # In probe phase, recon-only tools are hidden but core stays.
    # iter-37.8 dropped drain_amplify_queue from minimal core;
    # iter-37.10 trimmed core to 5 tools. The L1.5-aware ranked-
    # catalog accessor (list_pending_findings) is still core.
    assert "list_pending_findings" in catalog_probe
    assert "create_vulnerability_report" in catalog_probe

    # Re-read the finding via list_pending_findings — fields should
    # be intact
    from strix.tools.findings.list_findings import list_pending_findings
    out = list_pending_findings()
    matched = next(
        (r for r in out["findings"] if r["id"] == recon_id), None,
    )
    assert matched is not None, (
        "recon-phase finding disappeared from catalog after phase advance"
    )
    # surface_priority + exploitability annotations preserved
    assert matched.get("surface_priority") == "critical"
    assert "exploitability" in matched


# =========================================================================
# F.6 — multi-target catalog union (web_application + repository)
# =========================================================================

def test_multi_target_union_catalog_includes_both_asset_types():
    """The vibe-coded SaaS pattern (web target + paired repo) must
    yield a catalog union with tools from BOTH target types.
    """
    catalog = get_lead_tool_catalog(
        target_types={"web_application", "repository"},
    )
    # Web-only tools
    assert "crawl_with_katana" in catalog
    assert "scan_xss_dalfox" in catalog
    # Repo-only tools
    assert "scan_sast" in catalog
    assert "scan_sca_lockfiles" in catalog
    assert "secrets_scan" in catalog
    # Core tools in both (iter-37.10 minimal core: list_pending_findings
    # is the L1.5-aware ranked-catalog accessor; create_vulnerability_report
    # is the universal emission tool).
    assert "list_pending_findings" in catalog
    assert "create_vulnerability_report" in catalog


def test_multi_target_findings_get_l15_enrichment_regardless_of_origin(tracer):
    """A scan that targets both web_application AND repository must
    enrich findings emitted from EITHER asset type with full L1.5.
    Catches the bug class "L1.5 hooks gated by target_type" — they
    must be target-type-agnostic.
    """
    # Emit a web-style finding
    web_id = tracer.add_vulnerability_report(
        title="DAST XSS",
        severity="medium",
        cwe="CWE-79",
        endpoint="https://app.example.com/search?q=test",
        discovery_source_tool="dalfox",
    )
    # Emit a repo-style finding
    repo_id = tracer.add_vulnerability_report(
        title="SAST hardcoded credential",
        severity="medium",
        cwe="CWE-798",
        rule_id="strix-hardcoded-cred",
        code_locations=[{"file": "src/db.py", "line": 12}],
        discovery_source_tool="semgrep",
    )
    web_row = next(
        r for r in tracer.vulnerability_reports if r["id"] == web_id
    )
    repo_row = next(
        r for r in tracer.vulnerability_reports if r["id"] == repo_id
    )

    # Both got exploitability (one of the universal hooks)
    assert "exploitability" in web_row
    assert "exploitability" in repo_row

    # Web-style finding got surface_priority (endpoint hook)
    assert web_row.get("surface_priority") is not None
    # Repo-style finding has no surface_priority (no endpoint), but
    # WOULD have got git_blame if the file existed in a real git repo

    # Both reachable via list_pending_findings (ranking handles mixed
    # surface types — web has surface_priority, repo doesn't)
    from strix.tools.findings.list_findings import list_pending_findings
    out = list_pending_findings()
    visible_ids = {r["id"] for r in out["findings"]}
    assert web_id in visible_ids
    assert repo_id in visible_ids
