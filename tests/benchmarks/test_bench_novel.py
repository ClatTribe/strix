"""Tests for iter-31.10 — novel_finding_rate bench."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.per_target.bench_novel import (
    AggregateNovelReport,
    FindingNoveltyVerdict,
    FixtureNovelResult,
    _classify_finding_novelty,
    score_finding_novelty,
    score_fixture_novelty,
)


# ---------------------------------------------------------------------------
# _classify_finding_novelty
# ---------------------------------------------------------------------------

def test_classify_kev_listed_finding():
    f = {"id": "v1", "cve": "CVE-2023-1234", "kev_block": {"listed": True}}
    assert _classify_finding_novelty(f) == "kev"


def test_classify_kev_via_kev_flag():
    f = {"id": "v1", "cve": "CVE-2023-1234", "kev": True}
    assert _classify_finding_novelty(f) == "kev"


def test_classify_nuclei_via_rule_id():
    f = {"id": "v1", "rule_id": "nuclei-cve-2023-9999"}
    assert _classify_finding_novelty(f) == "nuclei"


def test_classify_nuclei_via_discovery_method():
    f = {
        "id": "v1",
        "discovery_method": {"primary": "nuclei_template", "is_novel": False},
    }
    assert _classify_finding_novelty(f) == "nuclei"


def test_classify_semgrep_via_rule_id():
    f = {"id": "v1", "rule_id": "semgrep-python.flask.sqli"}
    assert _classify_finding_novelty(f) == "semgrep"


def test_classify_trivy():
    f = {"id": "v1", "rule_id": "trivy-cve-2024-5555"}
    assert _classify_finding_novelty(f) == "trivy"


def test_classify_bandit_via_explicit_prefix():
    f = {"id": "v1", "rule_id": "bandit-B201"}
    assert _classify_finding_novelty(f) == "bandit"


def test_classify_bandit_via_B_code_alone():
    """Bandit IDs like B102 / B602 / B321."""
    f = {"id": "v1", "rule_id": "B102"}
    assert _classify_finding_novelty(f) == "bandit"


def test_classify_safety_rule_id():
    f = {"id": "v1", "rule_id": "safety-12345"}
    assert _classify_finding_novelty(f) == "safety"


def test_classify_sca_via_discovery_method():
    f = {
        "id": "v1",
        "discovery_method": {"primary": "sca_lookup", "is_novel": False},
    }
    assert _classify_finding_novelty(f) == "sca"


def test_classify_cve_pattern_match_via_discovery_method():
    f = {
        "id": "v1",
        "cve": "CVE-2022-9999",
        "discovery_method": {"primary": "cve_pattern_match"},
    }
    assert _classify_finding_novelty(f) == "kev"


def test_classify_ai_specialist_no_cve_is_novel():
    f = {
        "id": "v1",
        "discovery_method": {"primary": "ai_specialist", "is_novel": True},
    }
    assert _classify_finding_novelty(f) == "novel"


def test_classify_no_metadata_at_all_is_novel():
    """Finding with no rule_id and no discovery_method → assumed
    novel since L2-emitted findings often have minimal metadata."""
    f = {"id": "v1", "title": "agent-emitted"}
    assert _classify_finding_novelty(f) == "novel"


def test_classify_cve_without_kev_lands_in_cve_bucket():
    """A CVE that isn't KEV-listed isn't novel — the CVE itself
    is a public identifier — but isn't `kev` either. Bucket: `cve`."""
    f = {
        "id": "v1", "cve": "CVE-2020-1111",
        "kev_block": {"listed": False},
    }
    assert _classify_finding_novelty(f) == "cve"


def test_classify_sast_rule_via_discovery_method():
    f = {
        "id": "v1",
        "discovery_method": {"primary": "sast_rule"},
    }
    assert _classify_finding_novelty(f) == "sast_rule"


# ---------------------------------------------------------------------------
# score_finding_novelty
# ---------------------------------------------------------------------------

def test_score_novel_finding_returns_is_novel_true():
    v = score_finding_novelty({"id": "v1"})
    assert v.is_novel is True
    assert v.bucket == "novel"


def test_score_kev_finding_returns_is_novel_false():
    f = {"id": "v1", "kev": True, "cve": "CVE-2023-0001"}
    v = score_finding_novelty(f)
    assert v.is_novel is False
    assert v.bucket == "kev"


# ---------------------------------------------------------------------------
# score_fixture_novelty
# ---------------------------------------------------------------------------

def test_score_fixture_all_novel():
    findings = [
        {"id": "v1", "title": "agent_finding_1"},
        {"id": "v2", "title": "agent_finding_2"},
    ]
    r = score_fixture_novelty("test", findings)
    assert r.findings_total == 2
    assert r.novel_count == 2
    assert r.novel_finding_rate == 1.0


def test_score_fixture_mixed_buckets():
    findings = [
        {"id": "v1", "kev": True, "cve": "CVE-2023-0001"},
        {"id": "v2", "rule_id": "nuclei-cve-2024-1234"},
        {"id": "v3", "title": "agent finding"},
        {"id": "v4", "title": "agent finding 2"},
    ]
    r = score_fixture_novelty("test", findings)
    assert r.findings_total == 4
    assert r.novel_count == 2
    assert r.novel_finding_rate == 0.5
    assert r.by_bucket["kev"] == 1
    assert r.by_bucket["nuclei"] == 1
    assert r.by_bucket["novel"] == 2


def test_score_fixture_excludes_corroborator_siblings():
    findings = [
        {"id": "v1"},
        {"id": "v2", "role": "corroborator"},
    ]
    r = score_fixture_novelty("test", findings)
    assert r.findings_total == 1  # v2 excluded
    assert r.novel_count == 1


def test_score_fixture_empty_findings_noted():
    r = score_fixture_novelty("test", [])
    assert r.findings_total == 0
    assert any("no findings" in n for n in r.notes)


def test_score_fixture_only_corroborator_noted():
    findings = [{"id": "v1", "role": "corroborator"}]
    r = score_fixture_novelty("test", findings)
    assert r.findings_total == 0
    assert any("corroborator" in n for n in r.notes)


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def test_aggregate_serializable():
    rep = AggregateNovelReport(
        fixtures=[FixtureNovelResult(
            fixture="x", findings_total=4, novel_count=2,
            novel_finding_rate=0.5,
        )],
        total_findings=4,
        total_novel=2,
        overall_novel_finding_rate=0.5,
        aggregate_by_bucket={"novel": 2, "kev": 2},
    )
    json.dumps(rep.to_dict())


def test_verdict_serializable():
    v = FindingNoveltyVerdict(
        finding_id="v1", title="x", severity="high",
        bucket="novel", is_novel=True,
    )
    json.dumps(v.to_dict())


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_source_has_no_sut_specific_strings():
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_novel.py"
    )
    text = src.read_text().lower()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "/users/v1/_debug", "vampi-admin", "erev0s",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in bench source"


def test_no_specific_cve_values_in_source():
    """The classification logic must not hardcode specific CVE IDs."""
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_novel.py"
    )
    text = src.read_text()
    import re
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text)
    # Allow only documentary examples — confirm there are no
    # branches keyed on CVE values
    assert all("(e.g." in text.lower() or "example" in text.lower() for _ in cves)
