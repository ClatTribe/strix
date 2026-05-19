"""Tests for MA-S2 P0-APM-B — R9 + R10 contextual triage rules.

Recall-safety contract pinned by tests:
  * R9 NEVER downgrades on `verdict='unknown'` — absence of
    reachability evidence MUST NOT trigger downgrade.
  * R10 NEVER drops — UPGRADE only (chain context can promote
    a finding's priority but never demote).
  * When R9 + R10 both want to fire on the same finding, R10
    wins (chain context overrides per-finding unreachability).
  * Kill switch returns zero applications.
  * Per-finding failures don't poison the batch.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.llm import contextual_triage_rules as ctr


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_CONTEXTUAL_TRIAGE_DISABLED", raising=False)


def _cp(
    *,
    severity: str = "high",
    verdict: str = "unknown",
    membership: list[str] | None = None,
    tier: str = "p2_standard",
    max_chained: str | None = None,
) -> dict:
    return {
        "raw_cvss": 7.5,
        "raw_severity": severity,
        "epss_score": None,
        "kev_listed": False,
        "reachability": {
            "source_level": "unknown",
            "dependency_level": "unknown",
            "runtime_level": "unknown",
            "verdict": verdict,
        },
        "asset_context": {
            "criticality": "unknown",
            "data_sensitivity": "unknown",
            "blast_radius": "unknown",
        },
        "attack_path_membership": membership or [],
        "max_chained_severity": max_chained or severity,
        "priority_tier": tier,
    }


# ---------------------------------------------------------------------------
# R9 — unreachable_high_downgrade
# ---------------------------------------------------------------------------


def test_r9_fires_on_unreachable_high() -> None:
    tier = ctr.rule_r9_unreachable_high_downgrade(
        contextual_priority=_cp(severity="high", verdict="unreachable"),
    )
    assert tier == "p4_suppressible"


def test_r9_fires_on_unreachable_critical() -> None:
    tier = ctr.rule_r9_unreachable_high_downgrade(
        contextual_priority=_cp(severity="critical", verdict="unreachable"),
    )
    assert tier == "p4_suppressible"


def test_r9_does_not_fire_on_unknown_verdict() -> None:
    """Recall canary — absence of evidence (verdict='unknown')
    MUST NOT trigger downgrade. R9 only fires when reachability
    is explicitly 'unreachable'."""
    tier = ctr.rule_r9_unreachable_high_downgrade(
        contextual_priority=_cp(severity="critical", verdict="unknown"),
    )
    assert tier is None


def test_r9_does_not_fire_on_medium() -> None:
    tier = ctr.rule_r9_unreachable_high_downgrade(
        contextual_priority=_cp(severity="medium", verdict="unreachable"),
    )
    assert tier is None


def test_r9_does_not_fire_when_in_attack_path() -> None:
    """If the finding is part of any attack path, R9 yields to
    R10 — chain context overrides the per-finding unreachability
    heuristic."""
    tier = ctr.rule_r9_unreachable_high_downgrade(
        contextual_priority=_cp(
            severity="critical", verdict="unreachable",
            membership=["ap-001"],
        ),
    )
    assert tier is None


# ---------------------------------------------------------------------------
# R10 — chain_first_link_upgrade
# ---------------------------------------------------------------------------


def _path(*, max_severity: str, first_finding: str, others: list[str] | None = None) -> dict:
    stages = [{"step": 1, "finding_id": first_finding}]
    for i, fid in enumerate(others or [], start=2):
        stages.append({"step": i, "finding_id": fid})
    return {
        "id": "ap-001", "name": "test path",
        "max_severity": max_severity, "stages": stages,
        "preconditions": [], "impact_summary": "x",
        "confidence": 1.0,
    }


def test_r10_fires_when_finding_is_first_stage_of_critical_chain() -> None:
    tier = ctr.rule_r10_chain_first_link_upgrade(
        contextual_priority=_cp(severity="medium", membership=["ap-001"]),
        finding_id="vuln-001",
        attack_paths=[_path(
            max_severity="critical", first_finding="vuln-001",
            others=["vuln-002"],
        )],
    )
    assert tier == "p0_emergency"


def test_r10_does_not_fire_when_finding_is_not_first_stage() -> None:
    """The finding is in a chain but NOT step=1 — R10 doesn't
    fire. (The first-link is what's externally reachable; step-2+
    findings are only reachable through the chain.)"""
    tier = ctr.rule_r10_chain_first_link_upgrade(
        contextual_priority=_cp(severity="critical", membership=["ap-001"]),
        finding_id="vuln-002",
        attack_paths=[_path(
            max_severity="critical", first_finding="vuln-001",
            others=["vuln-002"],
        )],
    )
    assert tier is None


def test_r10_does_not_fire_when_chain_not_critical() -> None:
    """Chain's max_severity is high (not critical) → R10 doesn't
    upgrade. The conservative threshold limits noise."""
    tier = ctr.rule_r10_chain_first_link_upgrade(
        contextual_priority=_cp(severity="medium", membership=["ap-001"]),
        finding_id="vuln-001",
        attack_paths=[_path(
            max_severity="high", first_finding="vuln-001",
            others=["vuln-002"],
        )],
    )
    assert tier is None


def test_r10_does_not_fire_when_no_attack_paths() -> None:
    tier = ctr.rule_r10_chain_first_link_upgrade(
        contextual_priority=_cp(severity="critical"),
        finding_id="vuln-001",
        attack_paths=[],
    )
    assert tier is None


def test_r10_recall_canary_upgrade_only_never_drop() -> None:
    """Recall canary — R10 is UPGRADE-only. It never returns
    a tier below the input's tier. If this canary breaks, R10
    has been corrupted into a downgrade rule and reverts."""
    cp = _cp(
        severity="critical", membership=["ap-001"],
        tier="p1_urgent",
    )
    tier = ctr.rule_r10_chain_first_link_upgrade(
        contextual_priority=cp,
        finding_id="vuln-001",
        attack_paths=[_path(
            max_severity="critical", first_finding="vuln-001",
            others=["vuln-002"],
        )],
    )
    # Tier is p0_emergency (the only upgrade outcome).
    # It is NEVER p3 / p4 (downgrade outcomes).
    assert tier == "p0_emergency"


# ---------------------------------------------------------------------------
# apply_contextual_triage_rules — end-to-end on a findings list
# ---------------------------------------------------------------------------


def test_apply_backfills_membership_from_paths() -> None:
    """attack_path_membership wasn't available at emit time;
    apply_contextual_triage_rules backfills it from the loaded
    paths file."""
    findings = [{
        "id": "vuln-001",
        "contextual_priority": _cp(severity="medium"),
    }]
    paths = [_path(
        max_severity="critical", first_finding="vuln-001",
        others=["vuln-002"],
    )]
    ctr.apply_contextual_triage_rules(findings=findings, attack_paths=paths)
    assert findings[0]["contextual_priority"]["attack_path_membership"] == ["ap-001"]
    assert findings[0]["contextual_priority"]["max_chained_severity"] == "critical"


def test_apply_r10_upgrade_wins_over_r9_downgrade() -> None:
    """When R10 wants p0_emergency and R9 wants p4_suppressible
    on the same finding, R10 wins."""
    findings = [{
        "id": "vuln-001",
        "contextual_priority": _cp(
            severity="critical", verdict="unreachable",
        ),
    }]
    paths = [_path(
        max_severity="critical", first_finding="vuln-001",
        others=["vuln-002"],
    )]
    stats = ctr.apply_contextual_triage_rules(
        findings=findings, attack_paths=paths,
    )
    assert findings[0]["contextual_priority"]["priority_tier"] == "p0_emergency"
    assert stats["r10_upgrades"] == 1
    assert stats["r9_downgrades"] == 0


def test_apply_r9_fires_when_no_chain() -> None:
    findings = [{
        "id": "vuln-001",
        "contextual_priority": _cp(severity="high", verdict="unreachable"),
    }]
    stats = ctr.apply_contextual_triage_rules(
        findings=findings, attack_paths=[],
    )
    assert findings[0]["contextual_priority"]["priority_tier"] == "p4_suppressible"
    assert stats["r9_downgrades"] == 1


def test_apply_no_op_when_neither_rule_fires() -> None:
    findings = [{
        "id": "vuln-001",
        "contextual_priority": _cp(severity="high", verdict="unknown"),
    }]
    ctr.apply_contextual_triage_rules(findings=findings, attack_paths=[])
    # Priority tier untouched
    assert findings[0]["contextual_priority"]["priority_tier"] == "p2_standard"


def test_apply_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_CONTEXTUAL_TRIAGE_DISABLED", "1")
    findings = [{
        "id": "vuln-001",
        "contextual_priority": _cp(severity="critical", verdict="unreachable"),
    }]
    stats = ctr.apply_contextual_triage_rules(
        findings=findings, attack_paths=[],
    )
    assert stats == {"r9_downgrades": 0, "r10_upgrades": 0}
    # No mutation
    assert findings[0]["contextual_priority"]["priority_tier"] == "p2_standard"


def test_apply_skips_malformed_findings_without_crashing() -> None:
    findings = [
        "not a dict",  # malformed
        {"id": "ok", "contextual_priority": _cp(
            severity="critical", verdict="unreachable",
        )},
        None,  # malformed
    ]
    stats = ctr.apply_contextual_triage_rules(
        findings=findings, attack_paths=[],
    )
    # The well-formed finding still processes
    assert stats["r9_downgrades"] == 1


# ---------------------------------------------------------------------------
# load_attack_paths
# ---------------------------------------------------------------------------


def test_load_returns_empty_when_file_missing(tmp_path: Path) -> None:
    assert ctr.load_attack_paths(tmp_path) == []


def test_load_reads_jsonl(tmp_path: Path) -> None:
    f = tmp_path / "attack_paths.jsonl"
    f.write_text(
        json.dumps({"id": "ap-001", "stages": []}) + "\n"
        + json.dumps({"id": "ap-002", "stages": []}) + "\n",
        encoding="utf-8",
    )
    paths = ctr.load_attack_paths(tmp_path)
    assert len(paths) == 2
    assert paths[0]["id"] == "ap-001"


def test_load_skips_malformed_lines(tmp_path: Path) -> None:
    f = tmp_path / "attack_paths.jsonl"
    f.write_text(
        json.dumps({"id": "ap-001", "stages": []}) + "\n"
        + "this is not json\n"
        + json.dumps({"id": "ap-002", "stages": []}) + "\n",
        encoding="utf-8",
    )
    paths = ctr.load_attack_paths(tmp_path)
    assert len(paths) == 2  # malformed line skipped


# ---------------------------------------------------------------------------
# End-to-end via tracer
# ---------------------------------------------------------------------------


def test_triage_rules_applied_on_mark_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """End-to-end — emit a finding with unreachable evidence,
    then save the tracer; the priority_tier should be downgraded
    to p4_suppressible by R9."""
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.chdir(tmp_path)
    from strix.telemetry.tracer import Tracer, set_global_tracer
    t = Tracer("apm-b-int")
    set_global_tracer(t)
    fid = t.add_vulnerability_report(
        title="x", severity="high",
        endpoint="/x", target="https://x.com/x", category="sqli",
        description="...reachability=unused...",  # SCA tag = unreachable
        impact="x", technical_analysis="x",
        poc_description="x", poc_script_code="curl x",
        remediation_steps="x",
    )
    # Manually force reachability to 'unreachable' to test R9
    # (the SCA-tag heuristic only sets dependency_level today; we
    # need verdict='unreachable' for R9 to fire — set it before
    # save_run_data).
    for r in t.vulnerability_reports:
        if r["id"] == fid:
            r["contextual_priority"]["reachability"]["verdict"] = "unreachable"
            r["contextual_priority"]["raw_severity"] = "high"
    t.save_run_data(mark_complete=True)
    report = next(r for r in t.vulnerability_reports if r["id"] == fid)
    assert report["contextual_priority"]["priority_tier"] == "p4_suppressible"
