"""Tests for the unified `scan_cloud_account` specialist —
engine selection + Prowler-output → tracer compliance round-trip.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.cspm import prowler as prowler_module
from strix.cspm import tools as tools_module
from strix.cspm.aws import CspmFinding
from strix.cspm.prowler import ProwlerScanResult, parse_prowler_ocsf
from strix.cspm.tools import scan_cloud_account
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


FIXTURE = Path(__file__).parent / "fixtures" / "prowler_ocsf_sample.json"


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
    tracer = Tracer("cspm-dispatch-test")
    set_global_tracer(tracer)
    yield tracer


# ---------------------------------------------------------------------------
# Engine selection
# ---------------------------------------------------------------------------


def _stub_prowler_findings():
    return parse_prowler_ocsf(FIXTURE.read_text(encoding="utf-8"))


def _stub_run_prowler_ok(*_args, **_kwargs):
    findings = _stub_prowler_findings()
    return ProwlerScanResult(
        provider="aws", findings=findings,
        metadata={"prowler_version": "4.5.0-test"},
    )


def _stub_run_prowler_error(*_args, **_kwargs):
    return ProwlerScanResult(
        provider="aws", findings=[],
        errors=[{"source": "prowler", "error": "auth failed"}],
        metadata={"prowler_version": "4.5.0-test"},
    )


def _stub_scan_aws_account_with(*findings: CspmFinding):
    def _stub(*_args, **_kwargs):
        # Mimic the boto3 scanner return shape.
        from strix.cspm.aws.scanner import AwsCspmReport
        return AwsCspmReport(
            account_id="111122223333",
            regions_scanned=["us-east-1"],
            findings=list(findings),
        )
    return _stub


class _StubAwsReport:
    """Mirror of `strix.cspm.aws.scanner.AwsCspmReport` — only the
    fields `scan_cloud_account`'s boto3-fallback path reads."""

    def __init__(self, findings):
        self.findings = findings
        self.errors = []
        self.account_id = "123456789012"
        self.regions_scanned = ["us-east-1"]

    @property
    def findings_by_service(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.service] = out.get(f.service, 0) + 1
        return out


def test_prefers_prowler_when_available(monkeypatch) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: True)
    monkeypatch.setattr(tools_module, "run_prowler", _stub_run_prowler_ok)
    # Boto3 fallback should NOT be called.
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        lambda **_: (_ for _ in ()).throw(AssertionError("boto3 fallback called")),
    )

    result = scan_cloud_account(provider="aws")
    assert result["status"] == "ok"
    assert result["tool_metadata"]["engine"] == "prowler"
    assert result["tool_metadata"]["findings_total"] >= 4


def test_falls_back_to_boto3_when_prowler_missing(monkeypatch) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        _stub_scan_aws_account_with(CspmFinding(
            rule_id="AWS_S3_PUBLIC_ACL",
            severity="critical",
            message="bucket x is public",
            service="s3", region=None, resource_arn="arn:aws:s3:::x",
            cwe="CWE-732", category="misconfig",
        )),
    )

    result = scan_cloud_account(provider="aws")
    assert result["status"] == "ok"
    assert result["tool_metadata"]["engine"] == "boto3"
    assert result["tool_metadata"]["findings_total"] == 1


def test_prefers_boto3_when_force_disable(monkeypatch) -> None:
    """`prefer_prowler=False` skips Prowler even when installed."""
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: True)
    # If the test calls Prowler, fail.
    monkeypatch.setattr(
        tools_module, "run_prowler",
        lambda **_: (_ for _ in ()).throw(AssertionError("prowler called")),
    )
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        _stub_scan_aws_account_with(),
    )

    result = scan_cloud_account(provider="aws", prefer_prowler=False)
    assert result["tool_metadata"]["engine"] == "boto3"


def test_falls_back_to_boto3_when_prowler_errors_on_aws(monkeypatch) -> None:
    """Prowler errored and produced no findings → fall through to
    boto3 for AWS so the customer gets *some* output."""
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: True)
    monkeypatch.setattr(tools_module, "run_prowler", _stub_run_prowler_error)
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        _stub_scan_aws_account_with(CspmFinding(
            rule_id="AWS_IAM_ROOT_ACCESS_KEY",
            severity="critical", message="root key present",
            service="iam", region=None,
            resource_arn="arn:aws:iam::*:root",
            cwe="CWE-269", category="misconfig",
        )),
    )

    result = scan_cloud_account(provider="aws")
    assert result["tool_metadata"]["engine"] == "boto3-fallback"
    assert result["tool_metadata"]["findings_total"] == 1


def test_no_fallback_for_azure_when_prowler_missing(monkeypatch) -> None:
    """Built-in boto3 path doesn't cover Azure — when Prowler is
    missing for non-AWS, error explicitly with install hint."""
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: False)

    result = scan_cloud_account(provider="azure")
    assert result["status"] == "error"
    assert "Prowler is not installed" in result["error"]
    assert "azure" in result["error"].lower()


def test_unknown_provider_rejected(monkeypatch) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: True)
    result = scan_cloud_account(provider="oracle-cloud")
    assert result["status"] == "error"
    assert "unsupported provider" in result["error"]


# ---------------------------------------------------------------------------
# Compliance round-trip — Prowler's compliance dict survives end-to-end
# ---------------------------------------------------------------------------


def test_prowler_compliance_lands_on_tracer_report(
    monkeypatch, _tracer_reset,
) -> None:
    """End-to-end: Prowler-supplied per-finding compliance map
    (CIS-3.0:[2.1.5], SOC2:[CC6.1, CC6.6], NIST:[AC-3]) must
    survive enrichment and land on the report's
    `compliance_controls` field."""
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: True)
    monkeypatch.setattr(tools_module, "run_prowler", _stub_run_prowler_ok)

    tracer = _tracer_reset
    scan_cloud_account(provider="aws")

    s3_reports = [
        r for r in tracer.vulnerability_reports
        if r.get("rule_id") == "prowler:s3_bucket_public_access"
    ]
    assert len(s3_reports) == 1, (
        "Prowler S3 finding should land on the tracer"
    )
    controls = s3_reports[0].get("compliance_controls") or {}
    assert "cis_aws" in controls
    assert "2.1.5" in controls["cis_aws"]
    assert "soc2" in controls
    assert "CC6.1" in controls["soc2"]
    assert "CC6.6" in controls["soc2"]
    assert "nist_800_53" in controls
    assert "AC-3" in controls["nist_800_53"]


def test_azure_prowler_finding_lands_with_cis_azure(
    monkeypatch, _tracer_reset,
) -> None:
    """Verify the multi-cloud round-trip: an Azure finding's
    CIS-2.0 mapping resolves to cis_azure (not cis_aws)."""
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: True)
    monkeypatch.setattr(tools_module, "run_prowler", _stub_run_prowler_ok)

    tracer = _tracer_reset
    # provider=aws here — but the fixture has multi-cloud findings
    # and the dispatcher emits all of them. (Real usage would scan
    # one provider per invocation; the test exercises the parser
    # path which is provider-agnostic.)
    scan_cloud_account(provider="aws")

    azure_reports = [
        r for r in tracer.vulnerability_reports
        if r.get("rule_id")
        == "prowler:storage_blob_public_access_level_is_disabled"
    ]
    assert len(azure_reports) == 1
    controls = azure_reports[0].get("compliance_controls") or {}
    assert "cis_azure" in controls
    assert "3.7" in controls["cis_azure"]
    # Crucially: NOT in cis_aws.
    assert "3.7" not in (controls.get("cis_aws") or [])


def test_gcp_prowler_finding_lands_with_cis_gcp(
    monkeypatch, _tracer_reset,
) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: True)
    monkeypatch.setattr(tools_module, "run_prowler", _stub_run_prowler_ok)

    tracer = _tracer_reset
    scan_cloud_account(provider="aws")

    gcp_reports = [
        r for r in tracer.vulnerability_reports
        if r.get("rule_id") == "prowler:bigquery_dataset_public_access"
    ]
    assert len(gcp_reports) == 1
    controls = gcp_reports[0].get("compliance_controls") or {}
    assert "cis_gcp" in controls
    assert "7.1" in controls["cis_gcp"]
    assert "gdpr" in controls


def test_enrichment_unions_prowler_and_rule_id_mappings(
    monkeypatch, _tracer_reset,
) -> None:
    """If a Prowler check_id ALSO has a strix RULE_ID_TO_CONTROLS
    entry (we don't ship one for `prowler:...` keys today, but the
    union behaviour must be correct for future-proofing), both
    sources contribute. Exercises the union-not-overwrite path in
    enrich_finding_with_compliance."""
    from strix.compliance import mappings as mappings_module

    # Inject a synthetic mapping so the strix side adds something
    # the Prowler dict doesn't have.
    monkeypatch.setitem(
        mappings_module.RULE_ID_TO_CONTROLS,
        "prowler:s3_bucket_public_access",
        [("hipaa", "164.312(a)(1)")],   # not in fixture's compliance
    )
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: True)
    monkeypatch.setattr(tools_module, "run_prowler", _stub_run_prowler_ok)

    tracer = _tracer_reset
    scan_cloud_account(provider="aws")

    s3 = next(
        r for r in tracer.vulnerability_reports
        if r.get("rule_id") == "prowler:s3_bucket_public_access"
    )
    controls = s3.get("compliance_controls") or {}
    # From strix RULE_ID_TO_CONTROLS:
    assert "hipaa" in controls
    assert "164.312(a)(1)" in controls["hipaa"]
    # From Prowler's compliance dict:
    assert "2.1.5" in controls["cis_aws"]
    assert "CC6.1" in controls["soc2"]


# ---------------------------------------------------------------------------
# Severity-descending sort survives the dispatch
# ---------------------------------------------------------------------------


def test_findings_sorted_critical_first(monkeypatch) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: True)
    monkeypatch.setattr(tools_module, "run_prowler", _stub_run_prowler_ok)

    result = scan_cloud_account(provider="aws", include_attack_paths=False)
    severities = [d["severity"] for d in result["findings"]]
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    ranks = [sev_rank[s] for s in severities]
    assert ranks == sorted(ranks, reverse=True), (
        f"findings not severity-descending: {severities}"
    )


# ---------------------------------------------------------------------------
# Attack-path piggyback (Option B wiring — webappsec gets toxic
# combinations through the existing CSPM scan pipeline with NO
# wrapper-side changes).
# ---------------------------------------------------------------------------


def _stub_findings_that_trigger_attack_paths():
    """A finding set crafted to fire at least one attack-path
    pattern: root-unsafe (cap_root_unsafe) + public storage with
    credential-shaped name (cap_public_storage_credentials_risk)."""
    return [
        CspmFinding(
            rule_id="AWS_IAM_ROOT_ACCESS_KEY",
            severity="critical",
            message="root account access keys exist",
            service="iam", region=None,
            resource_arn="arn:aws:iam::*:root",
            cwe="CWE-269", category="misconfig",
        ),
        CspmFinding(
            rule_id="AWS_S3_PUBLIC_ACL",
            severity="critical",
            message="public ACL on prod-tfstate",
            service="s3", region=None,
            resource_arn="arn:aws:s3:::prod-tfstate",
            cwe="CWE-732", category="misconfig",
        ),
    ]


def test_attack_paths_emitted_by_default(monkeypatch, _tracer_reset) -> None:
    """The wrapper integration contract: scan_cloud_account ships
    attack paths as additional tracer findings by default. webappsec
    sees them in the same `vulnerabilities/*.md` round-trip as the
    underlying CSPM findings."""
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        lambda **_: _StubAwsReport(_stub_findings_that_trigger_attack_paths()),
    )

    tracer = _tracer_reset
    result = scan_cloud_account(provider="aws")
    assert result["status"] == "ok"

    # Metadata exposes the attack-path summary.
    assert "attack_paths_summary" in result["tool_metadata"]
    summary = result["tool_metadata"]["attack_paths_summary"]
    assert summary["total"] >= 1
    assert result["tool_metadata"]["attack_paths_emitted_to_tracer"] >= 1

    # Tracer reports carry the canonical `cloud_attack_path` category.
    cap_reports = [
        r for r in tracer.vulnerability_reports
        if r.get("category") == "cloud_attack_path"
    ]
    assert cap_reports
    # And the rule_id namespace matches the attack-path pattern IDs.
    assert all(
        (r.get("rule_id") or "").startswith("cap_") for r in cap_reports
    )


def test_attack_paths_opt_out_skips_emission(monkeypatch, _tracer_reset) -> None:
    """`include_attack_paths=False` keeps the legacy behaviour —
    callers wanting only CSPM findings (tests, minimal-noise scans)
    can suppress the piggyback."""
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        lambda **_: _StubAwsReport(_stub_findings_that_trigger_attack_paths()),
    )

    tracer = _tracer_reset
    result = scan_cloud_account(
        provider="aws", include_attack_paths=False,
    )
    assert result["status"] == "ok"
    assert "attack_paths_summary" not in result["tool_metadata"]
    # Zero `cloud_attack_path` findings on the tracer.
    cap_reports = [
        r for r in tracer.vulnerability_reports
        if r.get("category") == "cloud_attack_path"
    ]
    assert cap_reports == []


def test_attack_paths_pattern_allowlist_passes_through(
    monkeypatch, _tracer_reset,
) -> None:
    """The pattern allow-list reaches `analyze_cloud_attack_paths`
    intact — wrappers can narrow the analyzer (e.g. only root
    unsafe + wildcard admin) for fast scans."""
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        lambda **_: _StubAwsReport(_stub_findings_that_trigger_attack_paths()),
    )

    result = scan_cloud_account(
        provider="aws",
        attack_path_patterns=["cap_root_unsafe"],
    )
    summary = result["tool_metadata"]["attack_paths_summary"]
    pattern_keys = [k for k in summary if k.startswith("pattern:")]
    assert pattern_keys == ["pattern:cap_root_unsafe"]


def test_attack_path_analysis_failure_does_not_block_cspm_emit(
    monkeypatch, _tracer_reset,
) -> None:
    """If the analyzer raises (e.g. an upstream import broke), the
    underlying CSPM findings MUST still emit to the tracer. Drift
    in the optional piggyback can never mask the primary signal."""
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        lambda **_: _StubAwsReport([
            CspmFinding(
                rule_id="AWS_S3_PUBLIC_ACL", severity="critical",
                message="public", service="s3", region=None,
                resource_arn="arn:aws:s3:::data",
                cwe="CWE-732", category="misconfig",
            ),
        ]),
    )
    # Make the analyzer raise.
    import strix.cloud_attack_paths.api as cap_api

    def _boom(**_kwargs):
        raise RuntimeError("synthetic")
    monkeypatch.setattr(cap_api, "analyze_cloud_attack_paths", _boom)

    tracer = _tracer_reset
    result = scan_cloud_account(provider="aws")
    assert result["status"] == "ok"
    # CSPM emit happened.
    cspm_reports = [
        r for r in tracer.vulnerability_reports
        if r.get("rule_id") == "AWS_S3_PUBLIC_ACL"
    ]
    assert len(cspm_reports) == 1
    # Failure surfaced as a soft error in metadata.
    errors = result["tool_metadata"]["errors"]
    assert any(e.get("source") == "attack_paths" for e in errors)


def test_no_findings_skips_attack_path_analysis(
    monkeypatch, _tracer_reset,
) -> None:
    """When CSPM returns zero findings, attack-path analysis is
    correctly skipped — no spurious empty `attack_paths_summary`,
    no empty graph build."""
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        lambda **_: _StubAwsReport([]),
    )

    result = scan_cloud_account(provider="aws")
    assert result["status"] == "ok"
    assert "attack_paths_summary" not in result["tool_metadata"]
