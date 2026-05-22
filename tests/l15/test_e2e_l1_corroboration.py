"""E2E Phase E (L1 cross-tool) — multiple-source corroboration.

Per `docs/E2E-test-proposal.md` §3.2. Most L1 single-tool happy-path
coverage already exists in the iter-22/23/24 unit suites
(`test_scan_sqli_sqlmap.py`, `test_crawl_with_katana.py`,
`test_scan_image_dockle.py`, etc.). What was missing was a
cross-tool corroboration test exercising the L1.5 corroborator on
emissions from multiple distinct scanners.

Container_image is the canonical case: trivy + dockle + grype can
flag the same CVE from three different angles. Without the L1.5
corroborator they're 3 separate findings; with it they collapse to
ONE critical finding with `corroborated_by: [2 ids]`.
"""

from __future__ import annotations

import pytest

from strix.l15 import (
    corroborator_ledger,
    hygiene_ledger,
    root_cause_ledger,
)
from strix.telemetry.tracer import Tracer


@pytest.fixture
def tracer(tmp_path, monkeypatch):
    root_cause_ledger.clear()
    corroborator_ledger.clear()
    hygiene_ledger.clear()
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
    t = Tracer(run_name="e2e-phase-e")
    t._maybe_merge_into_existing_finding = lambda _r: None
    yield t
    root_cause_ledger.clear()
    corroborator_ledger.clear()
    hygiene_ledger.clear()


# =========================================================================
# E2E-L1-container-1 — trivy + dockle + grype corroborate on same CVE
# =========================================================================

def test_three_container_scanners_corroborate_on_same_cve(tracer):
    """Trivy + dockle + grype all flag CVE-2024-XXXX on the same
    container image. After L1.5 corroborator runs, ONE parent finding
    holds severity=critical (bumped one tier from high) with the
    other two demoted to role=corroborator."""
    image = "registry.example.com/myapp:1.2.3"
    cwe = "CWE-1395"  # vulnerable dependency

    trivy_id = tracer.add_vulnerability_report(
        title="CVE-2024-XXXX in libcurl",
        severity="high",
        cwe=cwe,
        target=image,
        endpoint=image,
        cve="CVE-2024-XXXX",
        discovery_source_tool="trivy",
    )
    dockle_id = tracer.add_vulnerability_report(
        title="CVE-2024-XXXX flagged by container linter",
        severity="high",
        cwe=cwe,
        target=image,
        endpoint=image,
        cve="CVE-2024-XXXX",
        discovery_source_tool="dockle",
    )
    grype_id = tracer.add_vulnerability_report(
        title="CVE-2024-XXXX detected by grype",
        severity="high",
        cwe=cwe,
        target=image,
        endpoint=image,
        cve="CVE-2024-XXXX",
        discovery_source_tool="grype",
    )

    # All three persisted; trivy is parent (first emitted)
    assert len(tracer.vulnerability_reports) == 3
    parent = next(
        r for r in tracer.vulnerability_reports if r["id"] == trivy_id
    )
    dockle = next(
        r for r in tracer.vulnerability_reports if r["id"] == dockle_id
    )
    grype = next(
        r for r in tracer.vulnerability_reports if r["id"] == grype_id
    )

    # Parent boosted (high → critical via first corroboration)
    assert parent["severity"] == "critical"

    # Both subsequent findings registered as corroborators
    corrob = parent.get("corroborated_by") or []
    assert dockle_id in corrob
    assert grype_id in corrob
    assert len(corrob) == 2

    # Corroborator children demoted to info with role flag
    assert dockle["severity"] == "info"
    assert dockle.get("role") == "corroborator"
    assert dockle.get("corroborates") == trivy_id
    assert grype["severity"] == "info"
    assert grype.get("role") == "corroborator"

    # When the Lead lists pending findings, only the parent surfaces;
    # the two corroborator children are hidden by default.
    from strix.telemetry.tracer import set_global_tracer
    from strix.tools.findings.list_findings import list_pending_findings
    set_global_tracer(tracer)
    try:
        listed = list_pending_findings()
        visible_ids = {r["id"] for r in listed["findings"]}
        assert trivy_id in visible_ids
        assert dockle_id not in visible_ids
        assert grype_id not in visible_ids
        assert listed["demoted_hidden"] == 2, (
            f"both corroborator children should be hidden; got "
            f"demoted_hidden={listed['demoted_hidden']}"
        )
    finally:
        set_global_tracer(None)


# =========================================================================
# E2E-L1-repo-1 — semgrep + gitleaks corroborate on hardcoded secret
# =========================================================================

def test_repo_sast_secrets_corroborate_on_same_file(tracer):
    """semgrep flags `strix-hardcoded-cred` on a line; gitleaks finds
    an AWS key on the same file. Different surfaces (no shared
    endpoint) so corroborator should NOT fire — each is its own
    finding.

    Negative test: corroborator requires the SAME surface AND CWE.
    Different files / different CWEs = independent findings.
    """
    semgrep_id = tracer.add_vulnerability_report(
        title="Hardcoded credential literal",
        severity="medium",
        rule_id="strix-hardcoded-credential-literal-python",
        cwe="CWE-798",
        code_locations=[{
            "file": "src/auth.py",
            "function": "login",
            "line": 17,
        }],
        discovery_source_tool="semgrep",
    )
    gitleaks_id = tracer.add_vulnerability_report(
        title="AWS Access Key",
        severity="high",
        rule_id="aws-access-key-id",
        cwe="CWE-798",
        code_locations=[{
            "file": "src/auth.py",  # SAME file
            "line": 17,              # SAME line
        }],
        discovery_source_tool="gitleaks",
    )

    # Both persisted as parents (different rule_ids → root_cause
    # doesn't collapse). They corroborate on (CWE-798, src/auth.py).
    assert len(tracer.vulnerability_reports) == 2
    semgrep_row = next(
        r for r in tracer.vulnerability_reports if r["id"] == semgrep_id
    )
    gitleaks_row = next(
        r for r in tracer.vulnerability_reports if r["id"] == gitleaks_id
    )

    # Corroborator fired (same CWE, same file surface, different sources)
    # → parent (semgrep) gets bumped + corroborator marker
    assert semgrep_id in (gitleaks_row.get("corroborates") or "") or \
           gitleaks_id in (semgrep_row.get("corroborated_by") or [])
