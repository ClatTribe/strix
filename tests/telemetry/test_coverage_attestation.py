"""Tests for the promoted coverage-attestation artifact (roadmap §17.1).

Promotes the §11 check-events stack into a per-(category × surface)
structured attestation. The artifact lives in `coverage_attestation.json`
next to the existing `checks_summary.json`, and the markdown report
gains explicit "Tested and not vulnerable" / "Tested and vulnerable" /
"Tested but inconclusive" subsections.

Tests cover:

- build_coverage_attestation: structured shape (schema_version, run_id,
  attestations[], negative_coverage[], inconclusive_coverage[],
  vulnerable_coverage[])
- attestations record per-check atomic data (category, surface, tool,
  result, confidence, evidence, finding_id, duration_seconds)
- negative_coverage groups not_vulnerable checks per category with
  unique surfaces
- inconclusive_coverage groups inconclusive checks
- vulnerable_coverage groups vulnerable checks with finding_ids
- save_run_data writes coverage_attestation.json when checks ran
- save_run_data does NOT write the file when no checks ran
- _format_coverage_assertions includes "Tested and not vulnerable",
  "Tested and vulnerable", and "Tested but inconclusive" subsections
- backward compatibility: get_check_summary still works, the existing
  checks_summary.json is still written
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


def _populate_checks(tracer: Tracer) -> None:
    """Populate a representative mix of checks across categories."""
    # not_vulnerable
    cid_a = tracer.start_check(category="csrf", surface="https://app.example.com/login", tool="csrf_check")
    tracer.complete_check(cid_a, "not_vulnerable", evidence="all bypasses rejected")

    cid_b = tracer.start_check(category="csrf", surface="https://app.example.com/profile", tool="csrf_check")
    tracer.complete_check(cid_b, "not_vulnerable", evidence="all bypasses rejected")

    # vulnerable
    cid_c = tracer.start_check(category="cors_deep", surface="https://api.example.com/v1", tool="cors_deep_check")
    tracer.complete_check(
        cid_c, "vulnerable",
        evidence="Origin reflected with credentials",
        finding_id="vuln-0001",
    )

    # inconclusive
    cid_d = tracer.start_check(category="session_entropy", surface="https://app.example.com/login", tool="session_entropy_check")
    tracer.complete_check(cid_d, "inconclusive", evidence="cookie not minted by endpoint")


# ---------------------------------------------------------------------------
# Structured shape
# ---------------------------------------------------------------------------


def test_build_attestation_top_level_keys() -> None:
    tracer = Tracer("attestation-shape")
    set_global_tracer(tracer)
    _populate_checks(tracer)

    out = tracer.build_coverage_attestation()
    assert set(out.keys()) >= {
        "schema_version", "run_id", "run_name", "generated_at",
        "targets", "summary", "attestations",
        "negative_coverage", "inconclusive_coverage", "vulnerable_coverage",
    }
    assert out["schema_version"] == 1
    assert out["run_id"] == tracer.run_id


def test_build_attestation_zero_checks_empty_buckets() -> None:
    tracer = Tracer("attestation-empty")
    set_global_tracer(tracer)

    out = tracer.build_coverage_attestation()
    assert out["summary"]["total"] == 0
    assert out["attestations"] == []
    assert out["negative_coverage"] == []
    assert out["inconclusive_coverage"] == []
    assert out["vulnerable_coverage"] == []


def test_attestation_record_per_check() -> None:
    tracer = Tracer("attestation-records")
    set_global_tracer(tracer)
    _populate_checks(tracer)

    out = tracer.build_coverage_attestation()
    assert len(out["attestations"]) == 4
    sample = out["attestations"][0]
    assert {"check_id", "category", "result", "confidence", "duration_seconds"} <= set(sample.keys())


def test_attestation_records_evidence_and_finding_id() -> None:
    tracer = Tracer("attestation-evidence")
    set_global_tracer(tracer)
    _populate_checks(tracer)

    out = tracer.build_coverage_attestation()
    vuln = [a for a in out["attestations"] if a["result"] == "vulnerable"]
    assert len(vuln) == 1
    assert vuln[0].get("finding_id") == "vuln-0001"
    assert "evidence" in vuln[0]


# ---------------------------------------------------------------------------
# Bucketed views
# ---------------------------------------------------------------------------


def test_negative_coverage_groups_per_category() -> None:
    tracer = Tracer("attestation-negative")
    set_global_tracer(tracer)
    _populate_checks(tracer)

    out = tracer.build_coverage_attestation()
    neg = out["negative_coverage"]
    csrf_entries = [e for e in neg if e["category"] == "csrf"]
    assert len(csrf_entries) == 1
    assert "https://app.example.com/login" in csrf_entries[0]["surfaces"]
    assert "https://app.example.com/profile" in csrf_entries[0]["surfaces"]
    assert csrf_entries[0]["surface_count"] == 2


def test_inconclusive_coverage_listed() -> None:
    tracer = Tracer("attestation-incon")
    set_global_tracer(tracer)
    _populate_checks(tracer)

    out = tracer.build_coverage_attestation()
    incon = out["inconclusive_coverage"]
    session_entries = [e for e in incon if e["category"] == "session_entropy"]
    assert len(session_entries) == 1
    assert "https://app.example.com/login" in session_entries[0]["surfaces"]


def test_vulnerable_coverage_includes_finding_ids() -> None:
    tracer = Tracer("attestation-vuln")
    set_global_tracer(tracer)
    _populate_checks(tracer)

    out = tracer.build_coverage_attestation()
    vuln = out["vulnerable_coverage"]
    cors_entries = [e for e in vuln if e["category"] == "cors_deep"]
    assert len(cors_entries) == 1
    assert "vuln-0001" in cors_entries[0]["finding_ids"]


def test_dedup_surfaces_across_repeat_checks() -> None:
    """Same (category, surface) pair re-tested → surfaces list dedups."""
    tracer = Tracer("attestation-dedup")
    set_global_tracer(tracer)

    cid1 = tracer.start_check(category="csrf", surface="https://x", tool="csrf_check")
    tracer.complete_check(cid1, "not_vulnerable")
    cid2 = tracer.start_check(category="csrf", surface="https://x", tool="csrf_check")
    tracer.complete_check(cid2, "not_vulnerable")

    out = tracer.build_coverage_attestation()
    csrf = [e for e in out["negative_coverage"] if e["category"] == "csrf"]
    assert len(csrf) == 1
    assert csrf[0]["surfaces"] == ["https://x"]
    assert csrf[0]["surface_count"] == 1


# ---------------------------------------------------------------------------
# File persistence
# ---------------------------------------------------------------------------


def test_save_run_data_writes_attestation_json(tmp_path) -> None:
    tracer = Tracer("attestation-saved")
    set_global_tracer(tracer)
    _populate_checks(tracer)
    tracer.final_scan_result = "Scan complete."

    tracer.save_run_data(mark_complete=True)

    run_dir = tracer.get_run_dir()
    artifact = run_dir / "coverage_attestation.json"
    assert artifact.exists()

    data = json.loads(artifact.read_text())
    assert data["schema_version"] == 1
    assert data["summary"]["total"] == 4
    assert any(e["category"] == "csrf" for e in data["negative_coverage"])
    assert any(e["category"] == "cors_deep" for e in data["vulnerable_coverage"])
    assert any(e["category"] == "session_entropy" for e in data["inconclusive_coverage"])


def test_save_run_data_no_checks_no_artifact(tmp_path) -> None:
    """Empty checks → no coverage_attestation.json written."""
    tracer = Tracer("attestation-skip")
    set_global_tracer(tracer)
    tracer.final_scan_result = "Scan complete."

    tracer.save_run_data(mark_complete=True)

    run_dir = tracer.get_run_dir()
    assert not (run_dir / "coverage_attestation.json").exists()


def test_save_run_data_still_writes_checks_summary_for_backcompat(tmp_path) -> None:
    """The existing checks_summary.json keeps being written (back-compat)."""
    tracer = Tracer("attestation-backcompat")
    set_global_tracer(tracer)
    _populate_checks(tracer)
    tracer.final_scan_result = "Scan complete."

    tracer.save_run_data(mark_complete=True)

    run_dir = tracer.get_run_dir()
    # Both files exist.
    assert (run_dir / "checks_summary.json").exists()
    assert (run_dir / "coverage_attestation.json").exists()


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def test_format_coverage_assertions_includes_three_subsections() -> None:
    tracer = Tracer("attestation-md")
    set_global_tracer(tracer)
    _populate_checks(tracer)

    md = tracer._format_coverage_assertions()
    assert md is not None
    assert "## Tested and not vulnerable" in md
    assert "## Tested and vulnerable" in md
    assert "## Tested but inconclusive" in md


def test_format_coverage_assertions_lists_finding_ids() -> None:
    tracer = Tracer("attestation-md-vuln")
    set_global_tracer(tracer)
    _populate_checks(tracer)

    md = tracer._format_coverage_assertions()
    assert md is not None
    assert "vuln-0001" in md


def test_format_coverage_assertions_links_to_json() -> None:
    tracer = Tracer("attestation-md-link")
    set_global_tracer(tracer)
    _populate_checks(tracer)

    md = tracer._format_coverage_assertions()
    assert md is not None
    assert "coverage_attestation.json" in md


def test_format_coverage_assertions_empty_returns_none() -> None:
    tracer = Tracer("attestation-md-empty")
    set_global_tracer(tracer)

    md = tracer._format_coverage_assertions()
    assert md is None


def test_format_coverage_assertions_only_neg_no_vuln_section() -> None:
    """When no vulnerable checks ran, the 'Tested and vulnerable' section
    is omitted (we don't render empty subsections)."""
    tracer = Tracer("attestation-md-no-vuln")
    set_global_tracer(tracer)
    cid = tracer.start_check(category="csrf", surface="https://x", tool="csrf_check")
    tracer.complete_check(cid, "not_vulnerable")

    md = tracer._format_coverage_assertions()
    assert md is not None
    assert "## Tested and not vulnerable" in md
    assert "## Tested and vulnerable" not in md
    assert "## Tested but inconclusive" not in md


# ---------------------------------------------------------------------------
# End-to-end: report file contains the section
# ---------------------------------------------------------------------------


def test_penetration_test_report_includes_attestation(tmp_path) -> None:
    tracer = Tracer("attestation-report-md")
    set_global_tracer(tracer)
    _populate_checks(tracer)
    tracer.final_scan_result = "## Findings\n\nSee vulnerabilities/ for full list."

    tracer.save_run_data(mark_complete=True)

    run_dir = tracer.get_run_dir()
    report = (run_dir / "penetration_test_report.md").read_text()
    assert "# Coverage Assertions" in report
    assert "## Tested and not vulnerable" in report
    assert "## Tested and vulnerable" in report
    assert "## Tested but inconclusive" in report
    assert "coverage_attestation.json" in report
