"""Tests for the `scan_cloud_attack_paths` specialist — engine
dispatch + tracer emit."""

from __future__ import annotations

import pytest

from strix.cloud_attack_paths import tools as cap_tools
from strix.cloud_attack_paths.tools import scan_cloud_attack_paths
from strix.cspm.aws import CspmFinding
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
    tracer = Tracer("cap-test")
    set_global_tracer(tracer)
    yield tracer


def _f(rule_id: str, *, arn: str, sev="high") -> CspmFinding:
    return CspmFinding(
        rule_id=rule_id, severity=sev,
        message=f"{rule_id} on {arn}",
        service="s3", region=None, resource_arn=arn,
        account_id="1", cwe=None, category="misconfig",
    )


class _StubAwsReport:
    def __init__(self, findings):
        self.findings = findings
        self.errors = []
        self.account_id = "1"
        self.regions_scanned = ["us-east-1"]


def test_specialist_emits_attack_paths_to_tracer(monkeypatch, _tracer_reset) -> None:
    """End-to-end: stub CSPM scan → attack-path detection →
    tracer emit. Each detected path lands as a tracer finding
    with category=cloud_attack_path."""
    monkeypatch.setattr(cap_tools, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        cap_tools, "scan_aws_account",
        lambda **_: _StubAwsReport([
            _f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::tfstate-prod"),
            _f("AWS_IAM_ROOT_ACCESS_KEY",
               arn="arn:aws:iam::1:root", sev="critical"),
        ]),
    )

    tracer = _tracer_reset
    result = scan_cloud_attack_paths(provider="aws")

    assert result["status"] == "ok"
    assert result["tool_metadata"]["engine"] == "cloud-attack-paths-v1"
    summary = result["tool_metadata"]["attack_paths_summary"]
    assert summary["total"] >= 2

    # Tracer emit.
    cap_reports = [
        r for r in tracer.vulnerability_reports
        if r.get("category") == "cloud_attack_path"
    ]
    assert len(cap_reports) >= 2
    # Each carries pattern_id as rule_id.
    rule_ids = {r.get("rule_id") for r in cap_reports}
    assert any(r.startswith("cap_") for r in rule_ids if r)


def test_specialist_critical_paths_count_in_metadata(
    monkeypatch, _tracer_reset,
) -> None:
    monkeypatch.setattr(cap_tools, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        cap_tools, "scan_aws_account",
        lambda **_: _StubAwsReport([
            _f("AWS_IAM_ROOT_ACCESS_KEY",
               arn="arn:aws:iam::1:root", sev="critical"),
        ]),
    )

    result = scan_cloud_attack_paths(provider="aws")
    assert result["tool_metadata"]["critical_paths"] >= 1


def test_specialist_pattern_allowlist(monkeypatch, _tracer_reset) -> None:
    monkeypatch.setattr(cap_tools, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        cap_tools, "scan_aws_account",
        lambda **_: _StubAwsReport([
            _f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::tfstate"),
            _f("AWS_IAM_ROOT_ACCESS_KEY",
               arn="arn:aws:iam::1:root"),
        ]),
    )

    result = scan_cloud_attack_paths(
        provider="aws", patterns=["cap_root_unsafe"],
    )
    # Pattern-summary should only carry cap_root_unsafe.
    summary = result["tool_metadata"]["attack_paths_summary"]
    pattern_keys = [k for k in summary if k.startswith("pattern:")]
    assert pattern_keys == ["pattern:cap_root_unsafe"]


def test_specialist_unknown_provider_errors() -> None:
    result = scan_cloud_attack_paths(provider="ibm-cloud")
    assert result["status"] == "error"
    assert "unsupported provider" in result["error"]


def test_specialist_prefers_prowler_when_available(
    monkeypatch, _tracer_reset,
) -> None:
    monkeypatch.setattr(cap_tools, "is_prowler_available", lambda: True)

    from strix.cspm.prowler import ProwlerScanResult
    monkeypatch.setattr(
        cap_tools, "run_prowler",
        lambda **_: ProwlerScanResult(
            provider="aws",
            findings=[_f("prowler:s3_bucket_public_access",
                          arn="arn:aws:s3:::tfstate-prod")],
            metadata={"prowler_version": "4.5.0"},
        ),
    )
    # Boto3 must not be called.
    monkeypatch.setattr(
        cap_tools, "scan_aws_account",
        lambda **_: (_ for _ in ()).throw(AssertionError("boto3 called")),
    )

    result = scan_cloud_attack_paths(provider="aws")
    assert result["status"] == "ok"
    assert result["tool_metadata"]["cspm_engine"] == "prowler"
