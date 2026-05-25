"""Tests for iter-31.2 — chain detection bench scorer + tracer
`chains_emitted[]` surfacing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.per_target.bench_chains import (
    AggregateChainReport,
    ChainMatch,
    FixtureChainResult,
    _chain_member_overlap,
    _load_expected_chains,
    score_fixture_chains,
)


# ---------------------------------------------------------------------------
# _chain_member_overlap — shape-based matching
# ---------------------------------------------------------------------------


def test_overlap_exact_match_full_ratio():
    overlap, ratio = _chain_member_overlap(
        ["sqli-login", "missing-auth-admin"],
        ["sqli-login", "missing-auth-admin"],
    )
    assert overlap == 2
    assert ratio == 1.0


def test_overlap_partial_match():
    overlap, ratio = _chain_member_overlap(
        ["sqli-login", "missing-auth-admin", "weak-jwt"],
        ["sqli-login", "missing-auth-admin"],
    )
    assert overlap == 2
    assert pytest.approx(ratio, 0.01) == 2 / 3


def test_overlap_substring_in_actual():
    """Expected member found as substring of an actual member's id."""
    overlap, ratio = _chain_member_overlap(
        ["sqli-login"],
        ["vuln-0003-sqli-login-via-rest-user"],
    )
    assert overlap == 1
    assert ratio == 1.0


def test_overlap_substring_other_direction():
    """Actual member id substring-included in expected."""
    overlap, ratio = _chain_member_overlap(
        ["sqli-login-via-rest-user-endpoint"],
        ["sqli-login"],
    )
    assert overlap == 1
    assert ratio == 1.0


def test_overlap_no_match_returns_zero():
    overlap, ratio = _chain_member_overlap(
        ["sqli-login", "missing-auth-admin"],
        ["xss-search", "idor-basket"],
    )
    assert overlap == 0
    assert ratio == 0.0


def test_overlap_empty_expected_handled():
    overlap, ratio = _chain_member_overlap([], ["sqli-login"])
    assert overlap == 0
    assert ratio == 0.0


def test_overlap_case_insensitive():
    overlap, ratio = _chain_member_overlap(
        ["SQLi-Login"], ["sqli-LOGIN"],
    )
    assert overlap == 1
    assert ratio == 1.0


def test_overlap_cap_prevents_exceeding_expected_count():
    """Even if one actual member matches MANY expected substrings,
    overlap is capped at len(expected_members)."""
    overlap, ratio = _chain_member_overlap(
        ["sqli", "sqli-login"],
        ["sqli-login-and-other-sqli-bits"],
    )
    # Both expected match the same actual — count, but capped at 2 (= expected)
    assert overlap <= 2
    assert ratio <= 1.0


# ---------------------------------------------------------------------------
# score_fixture_chains
# ---------------------------------------------------------------------------


def test_score_perfect_chain_detection():
    expected = [
        {"id": "auth-bypass-to-admin",
         "kind": "privilege-escalation",
         "members": ["sqli-login", "missing-auth-admin"]},
    ]
    actual = [
        {"chain_id": "c1",
         "kind": "privilege-escalation",
         "members": ["sqli-login", "missing-auth-admin"],
         "promoted_at_phase": "exploit"},
    ]
    result = score_fixture_chains("test", expected, actual)
    assert result.matched_count == 1
    assert result.chain_detection_rate == 1.0
    assert result.unmatched_expected_ids == []
    assert result.matches[0].matched is True
    assert result.matches[0].matched_actual_chain_id == "c1"


def test_score_partial_chain_detection():
    expected = [
        {"id": "c1", "members": ["a", "b"]},
        {"id": "c2", "members": ["c", "d"]},
    ]
    actual = [{"chain_id": "x1", "members": ["a", "b"]}]
    result = score_fixture_chains("test", expected, actual)
    assert result.matched_count == 1
    assert result.chain_detection_rate == 0.5
    assert result.unmatched_expected_ids == ["c2"]


def test_score_no_expected_skipped_with_note():
    result = score_fixture_chains("test", [], [])
    assert result.matched_count == 0
    assert result.chain_detection_rate == 0.0
    assert any("no expected_chains" in n for n in result.notes)


def test_score_no_actual_all_unmatched():
    expected = [{"id": "c1", "members": ["a", "b"]}]
    result = score_fixture_chains("test", expected, [])
    assert result.matched_count == 0
    assert result.chain_detection_rate == 0.0
    assert result.unmatched_expected_ids == ["c1"]


def test_score_below_50pct_overlap_does_not_match():
    """≥50% overlap is the threshold."""
    expected = [{"id": "c1", "members": ["a", "b", "c", "d"]}]
    # Only 1/4 overlap → 25%, below threshold
    actual = [{"chain_id": "x", "members": ["a", "z", "y", "q"]}]
    result = score_fixture_chains("test", expected, actual)
    assert result.matched_count == 0


def test_score_at_50pct_overlap_does_match():
    expected = [{"id": "c1", "members": ["a", "b", "c", "d"]}]
    # 2/4 → 50%
    actual = [{"chain_id": "x", "members": ["a", "b", "z", "y"]}]
    result = score_fixture_chains("test", expected, actual)
    assert result.matched_count == 1


def test_score_extra_actual_chains_logged_as_bonus():
    expected = [{"id": "c1", "members": ["a", "b"]}]
    actual = [
        {"chain_id": "x1", "members": ["a", "b"]},
        {"chain_id": "x2-extra", "members": ["p", "q", "r"]},
    ]
    result = score_fixture_chains("test", expected, actual)
    assert "x2-extra" in result.extra_actual_chain_ids


def test_score_one_actual_chain_only_credited_once():
    """A single actual chain can't satisfy multiple expecteds — prevents
    double-counting."""
    expected = [
        {"id": "c1", "members": ["a", "b"]},
        {"id": "c2", "members": ["a", "b"]},  # identical shape, distinct id
    ]
    actual = [{"chain_id": "x", "members": ["a", "b"]}]
    result = score_fixture_chains("test", expected, actual)
    # Only one credited
    assert result.matched_count == 1
    assert len(result.unmatched_expected_ids) == 1


def test_score_chain_depth_p95_computed():
    expected = [{"id": "c1", "members": ["a", "b"]}]
    actual = [
        {"chain_id": "x", "members": ["a", "b"]},
        {"chain_id": "y", "members": ["c", "d", "e"]},
        {"chain_id": "z", "members": ["f", "g", "h", "i", "j"]},
    ]
    result = score_fixture_chains("test", expected, actual)
    # depths = [2, 3, 5] — p95 ≈ max-tier
    assert result.chain_depth_p95 >= 3.0


def test_score_actual_chains_without_members_handled():
    """Don't crash on actual chains missing the members field."""
    expected = [{"id": "c1", "members": ["a", "b"]}]
    actual = [{"chain_id": "x"}]  # missing members
    result = score_fixture_chains("test", expected, actual)
    # Should treat as zero-overlap, not crash
    assert result.matched_count == 0


# ---------------------------------------------------------------------------
# _load_expected_chains — YAML loader
# ---------------------------------------------------------------------------


def test_load_expected_chains_from_yaml(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        "expected_chains:\n"
        "  - id: c1\n"
        "    kind: privilege-escalation\n"
        "    members: [a, b]\n"
        "  - id: c2\n"
        "    members: [c, d]\n"
    )
    out = _load_expected_chains(fixture)
    assert len(out) == 2
    assert out[0]["id"] == "c1"
    assert out[0]["kind"] == "privilege-escalation"


def test_load_missing_yaml_returns_empty(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    assert _load_expected_chains(fixture) == []


def test_load_yaml_without_expected_chains_key(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        "target: http://app\nexpected_findings:\n  - id: f1\n"
    )
    assert _load_expected_chains(fixture) == []


def test_load_skips_entries_without_id_or_members(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text(
        "expected_chains:\n"
        "  - id: valid\n    members: [a, b]\n"
        "  - members: [orphan-no-id]\n"
        "  - id: orphan-no-members\n"
    )
    out = _load_expected_chains(fixture)
    assert len(out) == 1
    assert out[0]["id"] == "valid"


def test_load_yaml_with_malformed_content(tmp_path):
    fixture = tmp_path / "f"
    fixture.mkdir()
    (fixture / "expected.yaml").write_text("not-a-dict-but-a-list\n- a\n- b\n")
    # Either no chains parsed (treated as not-a-dict) — must not crash
    assert _load_expected_chains(fixture) == []


# ---------------------------------------------------------------------------
# Aggregate report dataclass
# ---------------------------------------------------------------------------


def test_aggregate_chain_report_serializable():
    rep = AggregateChainReport(
        fixtures=[FixtureChainResult(fixture="x", chain_detection_rate=0.5)],
        total_expected=4,
        total_matched=2,
        overall_chain_detection_rate=0.5,
        overall_chain_depth_p95=3.0,
    )
    json.dumps(rep.to_dict())


def test_chain_match_serializable():
    m = ChainMatch(
        expected_id="c1",
        expected_kind="privilege-escalation",
        expected_members=["a", "b"],
        matched=True,
        matched_actual_chain_id="x1",
        matched_actual_members=["a", "b"],
        overlap_count=2,
        overlap_ratio=1.0,
    )
    d = m.to_dict()
    json.dumps(d)
    assert d["matched"] is True


# ---------------------------------------------------------------------------
# Anti-overfit guard — the bench source itself
# ---------------------------------------------------------------------------


def test_source_has_no_sut_specific_matching_strings():
    """The bench scorer must use shape-based matching, not SUT-specific
    string literals. Path references in `_DEFAULT_FIXTURES`
    (`api/vampi`, `web/juiceshop`) are allowed since those are file-
    path constants; what we forbid are SUT-specific MATCHING values
    that couple the scorer to one fixture's content."""
    src = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "bench_chains.py"
    )
    text = src.read_text().lower()
    forbidden = (
        "bkimminich",            # Juice Shop author handle
        "juice-sh.op",           # Juice Shop public domain
        "/rest/user/login",      # Juice Shop specific path
        "/api/baskets",          # Juice Shop specific path
        "vampi-admin",           # vampi hardcoded admin
        "erev0s",                # vampi author handle
        "/users/v1/_debug",      # vampi specific path
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in bench source"


# ---------------------------------------------------------------------------
# Tracer chains_emitted surfacing — iter-31.2 signal
# ---------------------------------------------------------------------------


def test_tracer_collects_chain_summary_from_findings():
    """When mid_scan_correlate has attached chain_summary to a finding,
    `_collect_chains_emitted()` surfaces it with the canonical shape."""
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="test_chains_collect")
    # Synthesize what mid_scan_correlate would attach.
    tr.vulnerability_reports.append({
        "id": "vuln-0001",
        "severity": "critical",
        "chain_summary": {
            "chain_id": "chain-abc",
            "kind": "privilege-escalation",
            "members": ["vuln-0001", "vuln-0002"],
            "promoted_at_phase": "exploit",
        },
    })
    chains = tr._collect_chains_emitted()
    assert len(chains) == 1
    c = chains[0]
    assert c["chain_id"] == "chain-abc"
    assert c["kind"] == "privilege-escalation"
    assert c["members"] == ["vuln-0001", "vuln-0002"]
    assert c["depth"] == 2
    assert c["parent_finding_id"] == "vuln-0001"
    assert c["parent_severity"] == "critical"


def test_tracer_dedups_chain_summary_by_chain_id():
    """Two findings sharing one chain_id only produce one chain entry."""
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="test_dedup")
    cs = {
        "chain_id": "chain-xyz",
        "kind": "data-exfil",
        "members": ["v1", "v2"],
    }
    tr.vulnerability_reports.extend([
        {"id": "v1", "severity": "high", "chain_summary": cs},
        {"id": "v2", "severity": "high", "chain_summary": cs},
    ])
    chains = tr._collect_chains_emitted()
    assert len(chains) == 1


def test_tracer_ignores_invalid_chain_summary():
    """Findings without `chain_summary` (or malformed) are skipped."""
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="test_ignore")
    tr.vulnerability_reports.extend([
        {"id": "v1", "severity": "high"},  # no chain_summary
        {"id": "v2", "severity": "high", "chain_summary": "not-a-dict"},
        {"id": "v3", "severity": "high", "chain_summary": {}},  # no chain_id
    ])
    assert tr._collect_chains_emitted() == []


def test_tracer_build_run_summary_includes_chains():
    """`build_run_summary()` surfaces chains_emitted + chains_emitted_count."""
    from strix.telemetry.tracer import Tracer

    tr = Tracer(run_name="test_summary_chains")
    tr.vulnerability_reports.append({
        "id": "v1",
        "severity": "critical",
        "chain_summary": {
            "chain_id": "c1",
            "kind": "privilege-escalation",
            "members": ["v1", "v2"],
        },
    })
    summary = tr.build_run_summary()
    assert summary["chains_emitted_count"] == 1
    assert len(summary["chains_emitted"]) == 1
    assert summary["chains_emitted"][0]["chain_id"] == "c1"


# ---------------------------------------------------------------------------
# Fixture overlay acceptance — iter-31.2 acceptance criterion
# ---------------------------------------------------------------------------


def test_default_fixtures_have_expected_chains_overlays():
    """Acceptance criterion for iter-31.2: juiceshop + vampi each have
    ≥1 expected_chains[] entry. flask-vuln (code target) is exempt
    since mid_scan_correlate is DAST-shaped."""
    fixtures_root = (
        Path(__file__).resolve().parents[2]
        / "benchmarks" / "per_target" / "fixtures"
    )
    for t in ("api/vampi", "web/juiceshop"):
        out = _load_expected_chains(fixtures_root / t)
        assert len(out) >= 1, (
            f"fixture {t} must have ≥1 expected_chains entry "
            f"(iter-31.2 acceptance criterion). Got {len(out)}."
        )
