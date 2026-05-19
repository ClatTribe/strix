"""Tests for MA-S2 P0-CVS-B — contextual_priority rollup.

Recall-safety contract pinned by tests:
  * Block ALWAYS present with the canonical 9 top-level keys.
  * raw_cvss + raw_severity + priority_tier MUST be preserved
    verbatim from the source report (doctrine §4 — two-signal
    layering — wrapper may store its override separately but
    engine signals are immutable).
  * is_novel + KEV listing + EPSS score never drive the
    priority_tier higher than the data supports (recall
    canary on KEV → p0).
  * Builder NEVER raises; failure falls through to minimal
    block with priority_tier='unknown'.
  * Kill switch returns the minimal block.
"""

from __future__ import annotations

import pytest

from strix.llm import contextual_priority as cp


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_CONTEXTUAL_PRIORITY_DISABLED", raising=False)


_EXPECTED_KEYS = {
    "raw_cvss", "raw_severity", "epss_score", "kev_listed",
    "reachability", "asset_context", "attack_path_membership",
    "max_chained_severity", "priority_tier",
}


# ---------------------------------------------------------------------------
# Schema invariant
# ---------------------------------------------------------------------------


def test_block_has_canonical_keys_on_minimal_report() -> None:
    out = cp.build_contextual_priority(report={}, scan_config=None)
    assert set(out.keys()) == _EXPECTED_KEYS
    assert set(out["reachability"].keys()) == {
        "source_level", "dependency_level", "runtime_level", "verdict",
    }
    assert set(out["asset_context"].keys()) == {
        "criticality", "data_sensitivity", "blast_radius",
    }


def test_kill_switch_returns_minimal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_CONTEXTUAL_PRIORITY_DISABLED", "1")
    out = cp.build_contextual_priority(
        report={"cvss": 9.8, "severity": "critical"},
        scan_config=None,
    )
    assert out["priority_tier"] == "unknown"
    assert set(out.keys()) == _EXPECTED_KEYS


# ---------------------------------------------------------------------------
# raw_cvss + raw_severity preserved (two-signal layering doctrine)
# ---------------------------------------------------------------------------


def test_raw_cvss_preserved_verbatim() -> None:
    """The engine's raw_cvss MUST be preserved exactly. Future
    PRs that downgrade or overwrite this break the boundary
    invariant — this canary catches it."""
    out = cp.build_contextual_priority(
        report={"cvss": 7.5, "severity": "high"},
        scan_config=None,
    )
    assert out["raw_cvss"] == 7.5
    assert out["raw_severity"] == "high"


def test_raw_severity_string_case_preserved() -> None:
    """raw_severity preserved as emitted (case-sensitive). Should
    not be normalized — the wrapper sees what the agent emitted."""
    out = cp.build_contextual_priority(
        report={"cvss": 9.0, "severity": "Critical"},  # capital C
        scan_config=None,
    )
    assert out["raw_severity"] == "Critical"


# ---------------------------------------------------------------------------
# EPSS surfacing from epss block
# ---------------------------------------------------------------------------


def test_epss_score_pulled_from_epss_block() -> None:
    out = cp.build_contextual_priority(
        report={
            "cvss": 7.5, "severity": "high",
            "epss": {"score": 0.85, "reason": "ok"},
        },
        scan_config=None,
    )
    assert out["epss_score"] == 0.85


def test_epss_score_null_when_no_block() -> None:
    out = cp.build_contextual_priority(
        report={"cvss": 5.0, "severity": "medium"},
        scan_config=None,
    )
    assert out["epss_score"] is None


def test_epss_score_null_on_null_score_in_block() -> None:
    out = cp.build_contextual_priority(
        report={
            "cvss": 5.0, "severity": "medium",
            "epss": {"score": None, "reason": "no_cve"},
        },
        scan_config=None,
    )
    assert out["epss_score"] is None


# ---------------------------------------------------------------------------
# KEV lookup
# ---------------------------------------------------------------------------


def test_kev_listed_true_when_threat_intel_says_yes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StubCVE:
        kev = True
    monkeypatch.setattr(
        "strix.threat_intel.lookup.get_cve", lambda cve_id: _StubCVE()
    )
    out = cp.build_contextual_priority(
        report={"cvss": 7.5, "severity": "high", "cve": "CVE-2024-1234"},
        scan_config=None,
    )
    assert out["kev_listed"] is True


def test_kev_listed_false_when_no_cve() -> None:
    out = cp.build_contextual_priority(
        report={"cvss": 7.5, "severity": "high"},  # no CVE
        scan_config=None,
    )
    assert out["kev_listed"] is False


def test_kev_listed_false_when_threat_intel_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If get_cve raises, fall through to kev_listed=False."""
    def boom(cve_id):
        raise RuntimeError("DB locked")
    monkeypatch.setattr("strix.threat_intel.lookup.get_cve", boom)
    out = cp.build_contextual_priority(
        report={"cvss": 7.5, "severity": "high", "cve": "CVE-2024-1234"},
        scan_config=None,
    )
    assert out["kev_listed"] is False


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------


def test_reachability_source_reachable_when_code_locations_present() -> None:
    """Findings with `code_locations` carry SAST taint evidence —
    they're definitively reachable at source."""
    out = cp.build_contextual_priority(
        report={
            "cvss": 7.5, "severity": "high",
            "code_locations": [{"file": "app.py", "line": 42}],
        },
        scan_config=None,
    )
    assert out["reachability"]["source_level"] == "reachable"
    assert out["reachability"]["verdict"] == "reachable"


def test_reachability_dependency_called_when_tag_present() -> None:
    """SCA reachability tags (`reachability=direct_import`/`called`)
    surface in description."""
    out = cp.build_contextual_priority(
        report={
            "cvss": 7.5, "severity": "high",
            "description": "Vulnerable dep `requests` (reachability=called)",
        },
        scan_config=None,
    )
    assert out["reachability"]["dependency_level"] == "called"


def test_reachability_unknown_default() -> None:
    """No reachability evidence → verdict=unknown (safe default;
    recall protected — never falsely 'unreachable')."""
    out = cp.build_contextual_priority(
        report={"cvss": 7.5, "severity": "high"},
        scan_config=None,
    )
    assert out["reachability"]["verdict"] == "unknown"


# ---------------------------------------------------------------------------
# Asset context
# ---------------------------------------------------------------------------


def test_asset_context_pulled_from_target_metadata() -> None:
    out = cp.build_contextual_priority(
        report={"cvss": 7.5, "severity": "high"},
        scan_config={
            "target_metadata": {
                "criticality": "high",
                "data_sensitivity": "pii",
                "blast_radius": "tenant",
            },
        },
    )
    assert out["asset_context"] == {
        "criticality": "high",
        "data_sensitivity": "pii",
        "blast_radius": "tenant",
    }


def test_asset_context_unknown_when_target_metadata_missing() -> None:
    out = cp.build_contextual_priority(
        report={"cvss": 7.5, "severity": "high"},
        scan_config={},
    )
    assert out["asset_context"]["criticality"] == "unknown"
    assert out["asset_context"]["data_sensitivity"] == "unknown"
    assert out["asset_context"]["blast_radius"] == "unknown"


# ---------------------------------------------------------------------------
# priority_tier derivation
# ---------------------------------------------------------------------------


def test_priority_kev_listed_goes_p0_emergency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recall canary — KEV-listed findings ALWAYS reach
    p0_emergency regardless of CVSS. CISA KEV is the highest-
    confidence "actively exploited" signal."""
    class _Kev:
        kev = True
    monkeypatch.setattr("strix.threat_intel.lookup.get_cve", lambda c: _Kev())
    out = cp.build_contextual_priority(
        report={
            "cvss": 4.0, "severity": "medium",  # would normally be p3
            "cve": "CVE-2024-1234",
        },
        scan_config=None,
    )
    assert out["priority_tier"] == "p0_emergency"


def test_priority_high_epss_goes_p0(monkeypatch: pytest.MonkeyPatch) -> None:
    """EPSS ≥ 0.7 → p0_emergency."""
    out = cp.build_contextual_priority(
        report={
            "cvss": 5.0, "severity": "medium",
            "epss": {"score": 0.8, "reason": "ok"},
        },
        scan_config=None,
    )
    assert out["priority_tier"] == "p0_emergency"


def test_priority_critical_no_signals_is_p1_urgent() -> None:
    out = cp.build_contextual_priority(
        report={"cvss": 9.5, "severity": "critical"},
        scan_config=None,
    )
    assert out["priority_tier"] == "p1_urgent"


def test_priority_high_with_moderate_epss_is_p1_urgent() -> None:
    """High severity + EPSS ≥ 0.5 → p1_urgent (bumped from p2)."""
    out = cp.build_contextual_priority(
        report={
            "cvss": 8.0, "severity": "high",
            "epss": {"score": 0.55, "reason": "ok"},
        },
        scan_config=None,
    )
    assert out["priority_tier"] == "p1_urgent"


def test_priority_high_no_epss_is_p2_standard() -> None:
    out = cp.build_contextual_priority(
        report={"cvss": 7.5, "severity": "high"},
        scan_config=None,
    )
    assert out["priority_tier"] == "p2_standard"


def test_priority_medium_is_p3_deferrable() -> None:
    out = cp.build_contextual_priority(
        report={"cvss": 5.0, "severity": "medium"},
        scan_config=None,
    )
    assert out["priority_tier"] == "p3_deferrable"


def test_priority_low_is_p4_suppressible() -> None:
    out = cp.build_contextual_priority(
        report={"cvss": 2.0, "severity": "low"},
        scan_config=None,
    )
    assert out["priority_tier"] == "p4_suppressible"


def test_priority_unknown_severity_unknown_tier() -> None:
    out = cp.build_contextual_priority(
        report={"cvss": None, "severity": ""},
        scan_config=None,
    )
    assert out["priority_tier"] == "unknown"


# ---------------------------------------------------------------------------
# Recall safety — builder never raises
# ---------------------------------------------------------------------------


def test_builder_never_raises_on_malformed_report() -> None:
    """A broken report (epss block is a list instead of a dict)
    shouldn't crash the builder."""
    out = cp.build_contextual_priority(
        report={"cvss": 7.5, "severity": "high", "epss": ["not a dict"]},
        scan_config=None,
    )
    assert "priority_tier" in out


def test_builder_never_raises_on_malformed_scan_config() -> None:
    """scan_config with wrong-typed target_metadata."""
    out = cp.build_contextual_priority(
        report={"cvss": 5.0, "severity": "medium"},
        scan_config={"target_metadata": "not a dict"},
    )
    assert out["asset_context"]["criticality"] == "unknown"


# ---------------------------------------------------------------------------
# attack_path_membership stays empty until P0-APM-A ships
# ---------------------------------------------------------------------------


def test_attack_path_membership_empty_until_apm_a() -> None:
    """P0-APM-A will populate this from attack_paths.jsonl.
    Until then, every finding has an empty list."""
    out = cp.build_contextual_priority(
        report={"cvss": 7.5, "severity": "high"},
        scan_config=None,
    )
    assert out["attack_path_membership"] == []


# ---------------------------------------------------------------------------
# Integration via tracer
# ---------------------------------------------------------------------------


def test_block_lands_on_finding_via_tracer(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    """End-to-end: emit a finding through tracer and verify the
    contextual_priority block lands on the persisted report."""
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.chdir(tmp_path)
    from strix.telemetry.tracer import Tracer, set_global_tracer
    t = Tracer("cp-int")
    t.set_scan_config({
        "targets": [{"original": "https://x.com"}],
        "target_metadata": {
            "criticality": "high",
            "data_sensitivity": "pii",
            "blast_radius": "tenant",
        },
    })
    set_global_tracer(t)
    fid = t.add_vulnerability_report(
        title="x", severity="high",
        endpoint="/x", target="https://x.com/x", category="sqli",
        description="x", impact="x", technical_analysis="x",
        poc_description="x", poc_script_code="curl x",
        remediation_steps="x",
    )
    r = next(r for r in t.vulnerability_reports if r["id"] == fid)
    assert "contextual_priority" in r
    cp_block = r["contextual_priority"]
    assert set(cp_block.keys()) == _EXPECTED_KEYS
    assert cp_block["asset_context"]["criticality"] == "high"
    # raw_severity preserved from the emit
    assert cp_block["raw_severity"] == "high"
    assert cp_block["priority_tier"] in {"p1_urgent", "p2_standard"}
