"""Tests for the canonical-finding contract (roadmap §8.0).

The contract validates every finding written via
`tracer.add_vulnerability_report` against a canonical shape:

- Required fields: title, severity, category, verification_status,
  + at least one of {endpoint, target, code_locations}
- Severity ∈ {info, low, medium, high, critical}
- verification_status ∈ {verified, pattern_match, inconclusive,
  needs_review, could_not_verify}
- CWE: `CWE-<digits>`
- CVE: `CVE-YYYY-N+`
- §11 UX presence (warn): description_plain + recommended_action
  on findings with severity ≥ low
- Severity-category coherence (warn): high severity on
  informational categories

The contract NEVER drops a finding. Violations are attached to the
finding (`shape_violations`) AND emitted as a
`finding.shape_violation` event.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.finding_contract import (
    Violation,
    has_canonical_errors,
    validate_canonical_finding,
)
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


def _events_for(tmp_path, run_name: str) -> list[dict[str, Any]]:
    events_file = tmp_path / "strix_runs" / run_name / "events.jsonl"
    if not events_file.exists():
        return []
    return [
        json.loads(line) for line in events_file.read_text().splitlines() if line.strip()
    ]


def _canonical_finding(**overrides: Any) -> dict[str, Any]:
    """A finding that satisfies the contract; tests can mutate one
    field at a time."""
    base = {
        "title": "Test finding",
        "severity": "high",
        "description": "Plain description",
        "endpoint": "https://app.example.com/api",
        "target": "https://app.example.com",
        "category": "csrf",
        "cwe": "CWE-352",
        "verification_status": "needs_review",
        "description_plain": "Plain English description.",
        "recommended_action": "Plain English recommended action.",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Pure-function unit tests
# ---------------------------------------------------------------------------


def test_canonical_finding_no_violations() -> None:
    report = _canonical_finding()
    violations = validate_canonical_finding(report)
    assert violations == []


def test_missing_title_error() -> None:
    report = _canonical_finding(title="")
    violations = validate_canonical_finding(report)
    assert any(v.code == "finding.missing.title" for v in violations)
    assert has_canonical_errors(violations)


def test_missing_severity_error() -> None:
    report = _canonical_finding()
    del report["severity"]
    violations = validate_canonical_finding(report)
    assert any(v.code == "finding.missing.severity" for v in violations)


def test_invalid_severity_error() -> None:
    report = _canonical_finding(severity="kinda-bad")
    violations = validate_canonical_finding(report)
    assert any(v.code == "finding.severity.invalid" for v in violations)


def test_invalid_verification_status_error() -> None:
    report = _canonical_finding(verification_status="bogus")
    violations = validate_canonical_finding(report)
    assert any(v.code == "finding.verification_status.invalid" for v in violations)


def test_missing_verification_status_error() -> None:
    report = _canonical_finding()
    del report["verification_status"]
    violations = validate_canonical_finding(report)
    assert any(v.code == "finding.missing.verification_status" for v in violations)


def test_exploited_status_accepted_with_proof() -> None:
    """The new `exploited` tier (depth #1) is canonical when the
    finding also carries `proof_artifact_path`."""
    report = _canonical_finding(
        verification_status="exploited",
        proof_artifact_path="proof_of_impact/abcd.cookie_theft.bin",
    )
    violations = validate_canonical_finding(report)
    assert not any(
        v.code.startswith("finding.exploited.")
        or v.code == "finding.verification_status.invalid"
        for v in violations
    ), violations


def test_exploited_without_proof_path_errors() -> None:
    """`verification_status='exploited'` without `proof_artifact_path`
    is a contract violation — the whole point of the tier is the
    captured artifact."""
    report = _canonical_finding(verification_status="exploited")
    report.pop("proof_artifact_path", None)
    violations = validate_canonical_finding(report)
    codes = {v.code for v in violations}
    assert "finding.exploited.missing_proof" in codes


def test_exploited_with_blank_proof_path_errors() -> None:
    """Empty / whitespace-only `proof_artifact_path` is a violation
    too — same intent."""
    report = _canonical_finding(
        verification_status="exploited",
        proof_artifact_path="   ",
    )
    violations = validate_canonical_finding(report)
    codes = {v.code for v in violations}
    assert "finding.exploited.missing_proof" in codes


def test_non_exploited_status_does_not_require_proof() -> None:
    """`verified` findings don't need `proof_artifact_path` — only
    the `exploited` tier carries the artifact contract."""
    report = _canonical_finding(verification_status="verified")
    violations = validate_canonical_finding(report)
    assert not any(v.code == "finding.exploited.missing_proof" for v in violations)


def test_missing_category_error() -> None:
    report = _canonical_finding()
    del report["category"]
    violations = validate_canonical_finding(report)
    assert any(v.code == "finding.missing.category" for v in violations)


def test_no_locatable_surface_error() -> None:
    report = _canonical_finding()
    del report["endpoint"]
    del report["target"]
    violations = validate_canonical_finding(report)
    assert any(v.code == "finding.missing.location" for v in violations)


def test_locatable_via_code_locations_only() -> None:
    report = _canonical_finding()
    del report["endpoint"]
    del report["target"]
    report["code_locations"] = [{"file": "src/auth.py", "line": 42}]
    violations = validate_canonical_finding(report)
    assert not any(v.code == "finding.missing.location" for v in violations)


def test_invalid_cwe_format_error() -> None:
    report = _canonical_finding(cwe="352")  # missing CWE- prefix
    violations = validate_canonical_finding(report)
    assert any(v.code == "finding.cwe.invalid_format" for v in violations)


def test_valid_cwe_lowercase_accepted() -> None:
    report = _canonical_finding(cwe="cwe-352")
    violations = validate_canonical_finding(report)
    assert not any(v.code == "finding.cwe.invalid_format" for v in violations)


def test_invalid_cve_format_error() -> None:
    report = _canonical_finding(cve="2024-12345")  # missing CVE- prefix
    violations = validate_canonical_finding(report)
    assert any(v.code == "finding.cve.invalid_format" for v in violations)


def test_valid_cve_format_accepted() -> None:
    report = _canonical_finding(cve="CVE-2024-12345")
    violations = validate_canonical_finding(report)
    assert not any(v.code == "finding.cve.invalid_format" for v in violations)


def test_missing_description_plain_warns() -> None:
    """High-severity finding without description_plain → warn."""
    report = _canonical_finding(severity="high")
    del report["description_plain"]
    violations = validate_canonical_finding(report)
    ux_violations = [v for v in violations if v.code == "finding.ux.missing.description_plain"]
    assert len(ux_violations) == 1
    assert ux_violations[0].severity == "warn"


def test_missing_recommended_action_warns() -> None:
    report = _canonical_finding(severity="medium")
    del report["recommended_action"]
    violations = validate_canonical_finding(report)
    assert any(
        v.code == "finding.ux.missing.recommended_action" and v.severity == "warn"
        for v in violations
    )


def test_info_severity_skips_ux_check() -> None:
    """Info-severity findings don't require §11 UX fields."""
    report = _canonical_finding(severity="info")
    del report["description_plain"]
    del report["recommended_action"]
    violations = validate_canonical_finding(report)
    # No UX violations on info severity.
    assert not any(v.code.startswith("finding.ux.missing.") for v in violations)


def test_severity_category_coherence_warn() -> None:
    """High severity on informational category → warn."""
    report = _canonical_finding(severity="high", category="informational")
    violations = validate_canonical_finding(report)
    assert any(
        v.code == "finding.severity_category.incoherent" and v.severity == "warn"
        for v in violations
    )


def test_low_severity_on_informational_category_no_warn() -> None:
    report = _canonical_finding(severity="low", category="posture")
    violations = validate_canonical_finding(report)
    assert not any(v.code == "finding.severity_category.incoherent" for v in violations)


def test_has_canonical_errors_filters_warns() -> None:
    """Only error-severity violations make a finding 'non-canonical'.
    Warns are advisory."""
    warn_only = [Violation(code="x", field="x", message="x", severity="warn")]
    err_present = [
        Violation(code="x", field="x", message="x", severity="warn"),
        Violation(code="y", field="y", message="y", severity="error"),
    ]
    assert has_canonical_errors(warn_only) is False
    assert has_canonical_errors(err_present) is True


def test_validator_handles_non_dict() -> None:
    out = validate_canonical_finding("not a dict")  # type: ignore[arg-type]
    assert any(v.code == "finding.not_dict" for v in out)


# ---------------------------------------------------------------------------
# Integration: tracer.add_vulnerability_report
# ---------------------------------------------------------------------------


def test_canonical_finding_no_violations_attached() -> None:
    tracer = Tracer("contract-clean")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})

    tracer.add_vulnerability_report(
        title="X",
        severity="medium",
        category="csrf",
        cwe="CWE-352",
        endpoint="https://app.example.com",
        verification_status="needs_review",
        description="x",
        description_plain="plain",
        recommended_action="action",
    )
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["is_canonical"] is True
    assert "shape_violations" not in findings[0]


def test_non_canonical_finding_attaches_violations() -> None:
    tracer = Tracer("contract-broken")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})

    # Missing endpoint AND target AND code_locations + non-canonical
    # CWE.
    tracer.add_vulnerability_report(
        title="Broken finding",
        severity="high",
        category="weak_crypto",
        cwe="352",  # missing CWE- prefix
        verification_status="needs_review",
    )
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["is_canonical"] is False
    violations = findings[0]["shape_violations"]
    codes = {v["code"] for v in violations}
    assert "finding.cwe.invalid_format" in codes
    assert "finding.missing.location" in codes


def test_violation_event_emitted(tmp_path) -> None:
    tracer = Tracer("contract-event")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})

    tracer.add_vulnerability_report(
        title="Bad",
        severity="not-a-severity",  # invalid severity
        category="csrf",
        endpoint="https://x",
        verification_status="needs_review",
        description_plain="p",
        recommended_action="a",
    )
    events = _events_for(tmp_path, "contract-event")
    shape_events = [
        e for e in events if (e.get("event_type") or e.get("event")) == "finding.shape_violation"
    ]
    assert len(shape_events) == 1
    payload = shape_events[0].get("payload") or {}
    codes = {v["code"] for v in payload.get("violations") or []}
    assert "finding.severity.invalid" in codes
    assert payload.get("is_canonical") is False


def test_warn_only_violations_are_canonical() -> None:
    """A finding with ONLY warn-level violations is still canonical."""
    tracer = Tracer("contract-warn-only")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})

    # Missing description_plain → warn only.
    tracer.add_vulnerability_report(
        title="Warn-only",
        severity="medium",
        category="csrf",
        cwe="CWE-352",
        endpoint="https://app.example.com",
        verification_status="needs_review",
        # description_plain absent → warn
        # recommended_action absent → warn
    )
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["is_canonical"] is True  # warns don't break canonical
    # But violations are still recorded for visibility.
    assert "shape_violations" in findings[0]
    codes = {v["code"] for v in findings[0]["shape_violations"]}
    assert "finding.ux.missing.description_plain" in codes


def test_finding_never_dropped_even_with_errors() -> None:
    """Non-canonical findings still land in vulnerability_reports."""
    tracer = Tracer("contract-not-dropped")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})

    # Provide enough to actually create a finding (title + severity)
    # but be non-canonical on shape.
    tracer.add_vulnerability_report(
        title="Should not be dropped",
        severity="totally-invalid-severity",
        # missing endpoint/target/code_locations, missing category
    )
    assert len(tracer.get_existing_vulnerabilities()) == 1


def test_existing_recent_pr_findings_pass_contract() -> None:
    """A representative finding written via the recent-PR pattern
    (csrf_check / cors_deep_check / debug_endpoint_check) should pass
    the contract — regression guard against the contract becoming
    too strict for shipped tools."""
    tracer = Tracer("contract-existing")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://x"}]})

    # Mimic the cors_deep_check finding shape from #78.
    tracer.add_vulnerability_report(
        title="CORS misconfiguration (subdomain_prefix_with_credentials) on api.example.com — critical",
        severity="critical",
        category="cors_misconfiguration",
        cwe="CWE-942",
        target="api.example.com",
        endpoint="https://api.example.com/v1/profile",
        description="Probe `subdomain_prefix` sent `Origin: ...`",
        impact="CORS misconfiguration breaks the browser's same-origin policy",
        remediation_steps="Replace dynamic Origin reflection",
        description_plain="Your server reflects an attacker-controlled origin",
        recommended_action="Replace dynamic Origin reflection with allow-list",
        verification_status="needs_review",
    )
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["is_canonical"] is True
    # No shape_violations attached because zero violations occurred.
    assert "shape_violations" not in findings[0]


def test_violation_codes_stable_for_wrappers() -> None:
    """The violation codes are part of the public contract — the
    wrapper / GRC consumers key on them. This test pins the set of
    codes the validator can emit so a refactor doesn't accidentally
    rename them."""
    expected_codes = {
        "finding.not_dict",
        "finding.missing.title",
        "finding.missing.severity",
        "finding.severity.invalid",
        "finding.missing.verification_status",
        "finding.verification_status.invalid",
        "finding.missing.category",
        "finding.missing.location",
        "finding.cwe.invalid_format",
        "finding.cve.invalid_format",
        "finding.ux.missing.description_plain",
        "finding.ux.missing.recommended_action",
        "finding.severity_category.incoherent",
    }

    # Stress-test: a maximally-broken finding triggers most codes.
    broken = {
        "title": "",
        "severity": "kinda-bad",
        "verification_status": "bogus",
        "cwe": "352",
        "cve": "2024-1",
        # No endpoint / target / code_locations
        # No category
        # No description_plain / recommended_action
    }
    violations = validate_canonical_finding(broken)
    actual_codes = {v.code for v in violations}
    # Subset of what we expect to see; the test ensures no surprise codes appear.
    assert actual_codes <= expected_codes
    # And we should see most of them — at least 5 different categories.
    assert len(actual_codes) >= 5
