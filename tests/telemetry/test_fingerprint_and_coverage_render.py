"""Tests for the §11 wrap-ups: stable finding fingerprint + coverage-assertions
rendering in penetration_test_report.md."""

from __future__ import annotations

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import (
    Tracer,
    compute_finding_fingerprint,
    set_global_tracer,
)


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


# ---------------------------------------------------------------------------
# compute_finding_fingerprint — pure function tests
# ---------------------------------------------------------------------------


def test_fingerprint_is_deterministic() -> None:
    a = compute_finding_fingerprint(
        title="SQL Injection in /search",
        cwe="CWE-89",
        endpoint="/search",
    )
    b = compute_finding_fingerprint(
        title="SQL Injection in /search",
        cwe="CWE-89",
        endpoint="/search",
    )
    assert a == b
    assert len(a) == 16


def test_fingerprint_differs_on_different_cwe() -> None:
    a = compute_finding_fingerprint(title="Injection", cwe="CWE-89", endpoint="/x")
    b = compute_finding_fingerprint(title="Injection", cwe="CWE-78", endpoint="/x")
    assert a != b


def test_fingerprint_differs_on_different_endpoint() -> None:
    a = compute_finding_fingerprint(title="X", cwe="CWE-89", endpoint="/a")
    b = compute_finding_fingerprint(title="X", cwe="CWE-89", endpoint="/b")
    assert a != b


def test_fingerprint_normalizes_whitespace_and_case() -> None:
    a = compute_finding_fingerprint(
        title="  SQL  Injection in /SEARCH  ",
        cwe="CWE-89",
        endpoint="/search",
    )
    b = compute_finding_fingerprint(
        title="sql injection in /search",
        cwe="cwe-89",
        endpoint="/search",
    )
    assert a == b


def test_fingerprint_uses_file_when_no_endpoint() -> None:
    a = compute_finding_fingerprint(title="SQLi", cwe="CWE-89", file="app.py")
    b = compute_finding_fingerprint(title="SQLi", cwe="CWE-89", file="other.py")
    assert a != b


def test_fingerprint_endpoint_takes_precedence_over_file() -> None:
    """When both endpoint and file are present, endpoint wins (web targets are
    the dominant case for fingerprinting; file fallback is for code targets)."""
    a = compute_finding_fingerprint(
        title="SQLi", cwe="CWE-89", endpoint="/search", file="app.py"
    )
    b = compute_finding_fingerprint(
        title="SQLi", cwe="CWE-89", endpoint="/search", file="other.py"
    )
    assert a == b


def test_fingerprint_handles_missing_inputs() -> None:
    # Empty everything still produces a valid (deterministic) hash.
    a = compute_finding_fingerprint(title=None, cwe=None)
    b = compute_finding_fingerprint(title="", cwe="")
    assert a == b
    assert len(a) == 16


def test_fingerprint_truncates_long_titles_at_80_chars() -> None:
    long_title = "X" * 200
    same_first_80 = "X" * 80 + "Y" * 50
    a = compute_finding_fingerprint(title=long_title, cwe="CWE-89", endpoint="/x")
    b = compute_finding_fingerprint(title=same_first_80, cwe="CWE-89", endpoint="/x")
    assert a == b


# ---------------------------------------------------------------------------
# add_vulnerability_report attaches the fingerprint
# ---------------------------------------------------------------------------


def test_finding_carries_fingerprint_and_version(tmp_path) -> None:
    tracer = Tracer("fp-finding")
    set_global_tracer(tracer)
    tracer.add_vulnerability_report(
        title="SQL Injection in /search",
        severity="high",
        cwe="CWE-89",
        endpoint="/search",
    )
    report = tracer.get_existing_vulnerabilities()[0]
    assert "fingerprint" in report
    assert len(report["fingerprint"]) == 16
    assert report["fingerprint_version"] == 1


def test_two_findings_with_same_inputs_share_fingerprint(tmp_path) -> None:
    tracer = Tracer("fp-dup")
    set_global_tracer(tracer)
    tracer.add_vulnerability_report(
        title="SQLi", severity="high", cwe="CWE-89", endpoint="/x"
    )
    tracer.add_vulnerability_report(
        title="sqli   ", severity="high", cwe="cwe-89", endpoint="/x"
    )
    reports = tracer.get_existing_vulnerabilities()
    assert reports[0]["fingerprint"] == reports[1]["fingerprint"]


def test_fingerprint_uses_first_code_location_for_code_targets(tmp_path) -> None:
    tracer = Tracer("fp-code")
    set_global_tracer(tracer)
    tracer.add_vulnerability_report(
        title="SQLi",
        severity="high",
        cwe="CWE-89",
        code_locations=[{"file": "app.py", "start_line": 50}],
    )
    report = tracer.get_existing_vulnerabilities()[0]
    expected = compute_finding_fingerprint(
        title="SQLi", cwe="CWE-89", file="app.py"
    )
    assert report["fingerprint"] == expected


def test_fingerprint_appears_in_markdown_metadata(tmp_path) -> None:
    tracer = Tracer("fp-md")
    set_global_tracer(tracer)
    tracer.add_vulnerability_report(
        title="SQLi", severity="high", cwe="CWE-89", endpoint="/x"
    )
    md = (tmp_path / "strix_runs" / "fp-md" / "vulnerabilities" / "vuln-0001.md").read_text()
    assert "**Fingerprint:**" in md
    # 16 hex chars + " (v1)"
    assert "(v1)" in md


# ---------------------------------------------------------------------------
# Coverage assertions in penetration_test_report.md
# ---------------------------------------------------------------------------


def test_report_appends_coverage_section_when_checks_present(tmp_path) -> None:
    tracer = Tracer("cov-report")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "domain", "value": "example.com"}], "scan_mode": "standard"}
    )

    cid = tracer.start_check(category="email_security", surface="example.com")
    tracer.complete_check(cid, "not_vulnerable", evidence="SPF + DMARC present")
    cid = tracer.start_check(category="dns_security", surface="example.com")
    tracer.complete_check(cid, "not_vulnerable", evidence="DNSSEC signed")

    tracer.update_scan_final_fields(
        executive_summary="OK",
        methodology="Passive recon",
        technical_analysis="Nothing noteworthy",
        recommendations="Maintain posture",
    )
    tracer.save_run_data(mark_complete=True)

    report = (tmp_path / "strix_runs" / "cov-report" / "penetration_test_report.md").read_text()
    assert "# Coverage Assertions" in report
    assert "Tested and not vulnerable" in report
    # Categories rendered in alphabetical order.
    assert "**dns_security**" in report
    assert "**email_security**" in report
    # Surface listed.
    assert "`example.com`" in report
    # Header summary line counts both checks.
    assert "ran **2** checks" in report


def test_report_omits_coverage_section_when_no_checks(tmp_path) -> None:
    tracer = Tracer("cov-report-empty")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    tracer.update_scan_final_fields(
        executive_summary="OK",
        methodology="",
        technical_analysis="",
        recommendations="",
    )
    tracer.save_run_data(mark_complete=True)

    report = (tmp_path / "strix_runs" / "cov-report-empty" / "penetration_test_report.md").read_text()
    assert "# Coverage Assertions" not in report


def test_coverage_section_groups_multiple_surfaces(tmp_path) -> None:
    tracer = Tracer("cov-multi-surface")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})
    for surface in ("/api/users", "/api/orders", "/api/billing"):
        cid = tracer.start_check(category="sqli", surface=surface)
        tracer.complete_check(cid, "not_vulnerable")
    tracer.update_scan_final_fields(
        executive_summary="OK", methodology="", technical_analysis="", recommendations=""
    )
    tracer.save_run_data(mark_complete=True)

    report = (tmp_path / "strix_runs" / "cov-multi-surface" / "penetration_test_report.md").read_text()
    assert "**sqli**" in report
    # All three surfaces should appear.
    assert "/api/users" in report
    assert "/api/orders" in report
    assert "/api/billing" in report


def test_coverage_section_flags_inconclusive_checks(tmp_path) -> None:
    tracer = Tracer("cov-inconclusive")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})

    cid = tracer.start_check(category="email_security", surface="example.com")
    tracer.complete_check(cid, "inconclusive")

    tracer.update_scan_final_fields(
        executive_summary="OK", methodology="", technical_analysis="", recommendations=""
    )
    tracer.save_run_data(mark_complete=True)

    report = (tmp_path / "strix_runs" / "cov-inconclusive" / "penetration_test_report.md").read_text()
    # §17.1 promoted format: a structured "Tested but inconclusive" subsection
    # replaces the old single-line summary. The semantic (1 inconclusive
    # check, surface listed, "needs review" framing) is still asserted.
    assert "## Tested but inconclusive" in report
    assert "1 inconclusive" in report  # from the summary header
    assert "email_security" in report
    assert "needs review" in report
