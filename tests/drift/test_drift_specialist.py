"""Tests for the `correlate_drift` specialist — engine dispatch +
tracer round-trip with classification metadata."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from strix.cspm.aws import CspmFinding
from strix.drift import tools as drift_tools
from strix.drift.tools import correlate_drift
from strix.iac.rules import IacFinding
from strix.iac.scanner import IacReport
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _tracer_reset(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("drift-test")
    set_global_tracer(tracer)
    yield tracer


def _stub_iac_report(*findings) -> IacReport:
    return IacReport(
        repo_path="/fake/repo",
        files_scanned=["main.tf"],
        files_by_platform={"terraform": 1},
        findings=list(findings),
    )


def _fake_repo(tmp_path: Path) -> Path:
    d = tmp_path / "repo"
    d.mkdir()
    return d


def _iac(rule_id: str, *, name: str, sev="high") -> IacFinding:
    return IacFinding(
        rule_id=rule_id,
        file="main.tf", line=10, severity=sev,
        message=f"{rule_id} on {name}",
        cwe="CWE-732", category="misconfig", platform="terraform",
        metadata={"resource_name": name},
    )


def _cspm(rule_id: str, *, arn: str, sev="high") -> CspmFinding:
    return CspmFinding(
        rule_id=rule_id, severity=sev,
        message=f"{rule_id} on {arn}",
        service="s3", region=None, resource_arn=arn,
        account_id="123456789012",
        cwe="CWE-732", category="misconfig",
    )


# ---------------------------------------------------------------------------
# Engine dispatch
# ---------------------------------------------------------------------------


def test_iac_repo_path_must_be_directory(tmp_path) -> None:
    result = correlate_drift(iac_repo_path="/no/such/dir")
    assert result["status"] == "error"
    assert "not a directory" in result["error"]


def test_empty_iac_repo_path_rejected() -> None:
    result = correlate_drift(iac_repo_path="")
    assert result["status"] == "error"


def test_drift_pipeline_ok_when_both_scanners_yield_findings(
    monkeypatch, tmp_path, _tracer_reset,
) -> None:
    repo = _fake_repo(tmp_path)
    monkeypatch.setattr(drift_tools, "scan_iac_repo", lambda *_a, **_kw: _stub_iac_report(
        _iac("TF_AWS_S3_PUBLIC_ACL", name="agreed"),
        _iac("TF_AWS_S3_PUBLIC_ACL", name="pending-apply"),
    ))
    monkeypatch.setattr(drift_tools, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        drift_tools, "scan_aws_account",
        lambda **_kw: _StubAwsReport([
            _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::agreed"),
            _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::orphan"),
        ]),
    )

    result = correlate_drift(iac_repo_path=str(repo))
    assert result["status"] == "ok"
    summary = result["tool_metadata"]["drift_summary"]
    assert summary["iac_root_cause"] == 1
    assert summary["drift"] == 1
    assert summary["iac_unfollowed"] == 1
    assert result["tool_metadata"]["total_drift_signal"] == 2
    assert result["tool_metadata"]["engine_cspm"] == "boto3"


def test_drift_pipeline_uses_prowler_when_available(
    monkeypatch, tmp_path, _tracer_reset,
) -> None:
    repo = _fake_repo(tmp_path)
    monkeypatch.setattr(drift_tools, "scan_iac_repo", lambda *_a, **_kw: _stub_iac_report(
        _iac("TF_AWS_S3_PUBLIC_ACL", name="agreed"),
    ))
    monkeypatch.setattr(drift_tools, "is_prowler_available", lambda: True)

    from strix.cspm.prowler import ProwlerScanResult
    fake_result = ProwlerScanResult(
        provider="aws",
        findings=[_cspm("prowler:s3_bucket_public_access",
                        arn="arn:aws:s3:::agreed")],
        metadata={"prowler_version": "4.5.0"},
    )
    monkeypatch.setattr(drift_tools, "run_prowler",
                        lambda **_kw: fake_result)
    # Make sure boto3 isn't used.
    monkeypatch.setattr(
        drift_tools, "scan_aws_account",
        lambda **_kw: (_ for _ in ()).throw(AssertionError("boto3 called")),
    )

    result = correlate_drift(iac_repo_path=str(repo))
    assert result["status"] == "ok"
    assert result["tool_metadata"]["engine_cspm"] == "prowler"


def test_drift_pipeline_fallback_to_boto3_when_prowler_errors(
    monkeypatch, tmp_path, _tracer_reset,
) -> None:
    repo = _fake_repo(tmp_path)
    monkeypatch.setattr(drift_tools, "scan_iac_repo", lambda *_a, **_kw: _stub_iac_report())
    monkeypatch.setattr(drift_tools, "is_prowler_available", lambda: True)

    from strix.cspm.prowler import ProwlerScanResult
    monkeypatch.setattr(
        drift_tools, "run_prowler",
        lambda **_kw: ProwlerScanResult(
            provider="aws", findings=[],
            errors=[{"source": "prowler", "error": "auth failed"}],
        ),
    )
    monkeypatch.setattr(
        drift_tools, "scan_aws_account",
        lambda **_kw: _StubAwsReport([]),
    )

    result = correlate_drift(iac_repo_path=str(repo))
    assert result["status"] == "ok"
    # Engine field reports boto3 since prowler failed.
    assert result["tool_metadata"]["engine_cspm"] == "boto3"


def test_non_aws_without_prowler_surfaces_error(
    monkeypatch, tmp_path, _tracer_reset,
) -> None:
    """For Azure / GCP, no built-in fallback exists. The CSPM
    scan error gets recorded but the drift run still completes —
    just with empty CSPM input."""
    repo = _fake_repo(tmp_path)
    monkeypatch.setattr(drift_tools, "scan_iac_repo", lambda *_a, **_kw: _stub_iac_report())
    monkeypatch.setattr(drift_tools, "is_prowler_available", lambda: False)

    result = correlate_drift(
        iac_repo_path=str(repo), cspm_provider="azure",
    )
    assert result["status"] == "ok"
    errors = result["tool_metadata"]["cspm_errors"]
    assert errors
    assert any("Prowler unavailable" in e["error"] for e in errors)


# ---------------------------------------------------------------------------
# Tracer emit round-trip
# ---------------------------------------------------------------------------


def test_each_classification_emits_to_tracer(
    monkeypatch, tmp_path, _tracer_reset,
) -> None:
    """End-to-end: one finding per classification ends up on the
    tracer with `category=drift` + `rule_id` set."""
    repo = _fake_repo(tmp_path)
    monkeypatch.setattr(drift_tools, "scan_iac_repo", lambda *_a, **_kw: _stub_iac_report(
        _iac("TF_AWS_S3_PUBLIC_ACL", name="agreed"),
        _iac("TF_AWS_S3_PUBLIC_ACL", name="pending"),
    ))
    monkeypatch.setattr(drift_tools, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        drift_tools, "scan_aws_account",
        lambda **_kw: _StubAwsReport([
            _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::agreed"),
            _cspm("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::orphan"),
        ]),
    )

    tracer = _tracer_reset
    correlate_drift(iac_repo_path=str(repo))

    drift_reports = [
        r for r in tracer.vulnerability_reports
        if r.get("category") == "drift"
    ]
    classifications = set()
    for r in drift_reports:
        title = r.get("title", "")
        for c in ("iac_root_cause", "drift", "iac_unfollowed"):
            if f"[drift:{c}]" in title:
                classifications.add(c)
    assert {"iac_root_cause", "drift", "iac_unfollowed"} <= classifications


def test_drift_classification_severity_bumped_one_step(
    monkeypatch, tmp_path, _tracer_reset,
) -> None:
    """`drift` (CSPM-side, no IaC peer) gets a one-notch severity
    bump because IaC ≠ live is itself an operational signal.
    `iac_root_cause` and `iac_unfollowed` keep their underlying
    severity."""
    repo = _fake_repo(tmp_path)
    monkeypatch.setattr(drift_tools, "scan_iac_repo", lambda *_a, **_kw: _stub_iac_report())
    monkeypatch.setattr(drift_tools, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        drift_tools, "scan_aws_account",
        lambda **_kw: _StubAwsReport([
            _cspm("AWS_S3_PUBLIC_ACL",
                  arn="arn:aws:s3:::orphan", sev="medium"),
        ]),
    )

    tracer = _tracer_reset
    correlate_drift(iac_repo_path=str(repo))

    drift_reports = [
        r for r in tracer.vulnerability_reports
        if r.get("category") == "drift"
        and "[drift:drift]" in r.get("title", "")
    ]
    assert len(drift_reports) == 1
    # medium bumped to high.
    assert drift_reports[0]["severity"] == "high"


def test_iac_root_cause_severity_unchanged(
    monkeypatch, tmp_path, _tracer_reset,
) -> None:
    repo = _fake_repo(tmp_path)
    monkeypatch.setattr(drift_tools, "scan_iac_repo", lambda *_a, **_kw: _stub_iac_report(
        _iac("TF_AWS_S3_PUBLIC_ACL", name="agreed", sev="medium"),
    ))
    monkeypatch.setattr(drift_tools, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        drift_tools, "scan_aws_account",
        lambda **_kw: _StubAwsReport([
            _cspm("AWS_S3_PUBLIC_ACL",
                  arn="arn:aws:s3:::agreed", sev="medium"),
        ]),
    )

    tracer = _tracer_reset
    correlate_drift(iac_repo_path=str(repo))

    drift_reports = [
        r for r in tracer.vulnerability_reports
        if "[drift:iac_root_cause]" in r.get("title", "")
    ]
    assert len(drift_reports) == 1
    assert drift_reports[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# Helper for stub AwsCspmReport
# ---------------------------------------------------------------------------


class _StubAwsReport:
    """Minimal stand-in for `AwsCspmReport` — only the fields
    `correlate_drift` reads (`findings`, `errors`, `account_id`,
    `regions_scanned`)."""

    def __init__(self, findings):
        self.findings = findings
        self.errors = []
        self.account_id = "123456789012"
        self.regions_scanned = ["us-east-1"]
