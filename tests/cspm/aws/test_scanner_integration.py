"""End-to-end CSPM scanner tests + check-registry hygiene + the
compliance-mapping round-trip that auditors actually consume."""

from __future__ import annotations

import pytest

from strix.compliance.frameworks import FRAMEWORK_CIS_AWS, get_control
from strix.compliance.mappings import (
    RULE_ID_TO_CONTROLS,
    controls_for,
    controls_for_by_framework,
)
from strix.cspm.aws import list_registered_checks, run_checks
from strix.cspm.aws.scanner import AwsCspmReport, scan_aws_account
from strix.telemetry import compliance as compliance_module


# ---------------------------------------------------------------------------
# Registry hygiene
# ---------------------------------------------------------------------------


def test_checks_registered_across_services() -> None:
    """Each service module must register at least one check.
    Catches the easy mistake where adding a check file forgets
    the `@register_check` decorator."""
    by_service: dict[str, int] = {}
    for c in list_registered_checks():
        by_service[c["service"]] = by_service.get(c["service"], 0) + 1
    assert by_service.get("s3", 0) >= 3
    assert by_service.get("ec2", 0) >= 2   # SG + EBS + VPC
    assert by_service.get("iam", 0) >= 4
    assert by_service.get("rds", 0) >= 2
    assert by_service.get("cloudtrail", 0) >= 2


def test_iam_checks_are_global_scope() -> None:
    """IAM is a global service — checks must declare `scope=global`
    so the scanner runs them once, not once per region."""
    iam = [c for c in list_registered_checks() if c["service"] == "iam"]
    assert iam
    assert all(c["scope"] == "global" for c in iam), (
        "IAM checks must be scope=global"
    )


# ---------------------------------------------------------------------------
# run_checks — error isolation
# ---------------------------------------------------------------------------


def test_run_checks_isolates_failures(fake_factory) -> None:
    """A check that raises (e.g. AccessDenied on one service)
    must not stop the scan — other checks should still run and
    the failure should appear in the errors list."""
    # Register clients that ONLY answer one service call — every
    # other check will raise (missing method / missing paginator)
    # and we expect those to be captured as errors, not stop the
    # scan.
    fake_factory.register(
        service="iam", region=None,
        methods={"get_account_summary": {
            "SummaryMap": {"AccountAccessKeysPresent": 0},
        }},
    )

    findings, errors = run_checks(fake_factory, regions=["us-east-1"])
    # The iam_root_access_key_exists check returned [] (no
    # findings + no error) — so the call succeeded.
    # All other checks raised KeyError (no client registered) —
    # captured in errors.
    assert len(errors) > 5, (
        f"expected most checks to error, got {len(errors)}: {errors}"
    )
    assert all("error" in e and "check" in e for e in errors)


# ---------------------------------------------------------------------------
# scan_aws_account — end-to-end with dependency-injected factory
# ---------------------------------------------------------------------------


def test_scan_aws_account_returns_report(fake_factory) -> None:
    """Smoke test: scanner runs with a fake factory + minimal
    canned responses + a small region list."""
    fake_factory.register(
        service="sts", region="us-east-1",
        methods={"get_caller_identity": {"Account": "123456789012"}},
    )
    # Provide enough canned responses for the IAM checks to run
    # clean (no findings); the rest will error and land in
    # `report.errors`.
    fake_factory.register(
        service="iam", region=None,
        methods={
            "get_account_summary": {
                "SummaryMap": {"AccountAccessKeysPresent": 0},
            },
            "get_account_password_policy": {"PasswordPolicy": {
                "MinimumPasswordLength": 16,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
            }},
        },
        paginators={
            "list_users": [{"Users": []}],
            "list_policies": [{"Policies": []}],
        },
    )
    report = scan_aws_account(
        regions=["us-east-1"],
        client_factory=fake_factory,
    )
    assert isinstance(report, AwsCspmReport)
    assert report.account_id == "123456789012"
    assert report.regions_scanned == ["us-east-1"]
    # IAM ran clean → no IAM findings.
    iam_findings = [f for f in report.findings if f.service == "iam"]
    assert iam_findings == []


def test_scan_aws_account_stamps_account_id_on_findings(fake_factory) -> None:
    """`account_id` should be stamped on every finding so the
    wrapper can render multi-account dashboards cleanly."""
    fake_factory.register(
        service="sts", region="us-east-1",
        methods={"get_caller_identity": {"Account": "999888777666"}},
    )
    fake_factory.register(
        service="iam", region=None,
        methods={
            "get_account_summary": {
                "SummaryMap": {"AccountAccessKeysPresent": 1},
            },
            "get_account_password_policy": {"PasswordPolicy": {
                "MinimumPasswordLength": 16,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
            }},
        },
        paginators={
            "list_users": [{"Users": []}],
            "list_policies": [{"Policies": []}],
        },
    )
    report = scan_aws_account(
        regions=["us-east-1"],
        client_factory=fake_factory,
    )
    root_key_findings = [
        f for f in report.findings
        if f.rule_id == "AWS_IAM_ROOT_ACCESS_KEY"
    ]
    assert len(root_key_findings) == 1
    assert root_key_findings[0].account_id == "999888777666"


def test_scan_aws_account_sorts_findings_critical_first(fake_factory) -> None:
    """Severity-descending sort — critical first, info last —
    so the wrapper renders the highest-impact items at the top."""
    fake_factory.register(
        service="sts", region="us-east-1",
        methods={"get_caller_identity": {"Account": "111"}},
    )
    # Root key (critical) + weak password policy (medium)
    fake_factory.register(
        service="iam", region=None,
        methods={
            "get_account_summary": {
                "SummaryMap": {"AccountAccessKeysPresent": 1},
            },
            "get_account_password_policy": {"PasswordPolicy": {
                "MinimumPasswordLength": 6,
                "RequireSymbols": False,
                "RequireNumbers": False,
                "RequireUppercaseCharacters": False,
                "RequireLowercaseCharacters": False,
            }},
        },
        paginators={
            "list_users": [{"Users": []}],
            "list_policies": [{"Policies": []}],
        },
    )
    report = scan_aws_account(
        regions=["us-east-1"],
        client_factory=fake_factory,
    )
    iam_findings = [f for f in report.findings if f.service == "iam"]
    severities = [f.severity for f in iam_findings]
    assert severities[0] == "critical"
    assert "medium" in severities
    # Sort invariant — once we hit a lower severity, no higher
    # severity should appear after it.
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    ranks = [sev_rank[s] for s in severities]
    assert ranks == sorted(ranks, reverse=True)


# ---------------------------------------------------------------------------
# Compliance round-trip — every CSPM rule_id maps to a real CIS
# AWS control + the control exists in the catalog.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", [
    "AWS_S3_PUBLIC_ACL",
    "AWS_S3_VERSIONING_DISABLED",
    "AWS_S3_NO_DEFAULT_ENCRYPTION",
    "AWS_SG_OPEN_INGRESS_ADMIN",
    "AWS_SG_OPEN_INGRESS_WORLD",
    "AWS_IAM_ROOT_ACCESS_KEY",
    "AWS_IAM_USER_NO_MFA",
    "AWS_IAM_PASSWORD_POLICY_WEAK",
    "AWS_IAM_PASSWORD_POLICY_MISSING",
    "AWS_IAM_POLICY_WILDCARD_ADMIN",
    "AWS_RDS_PUBLIC_ACCESS",
    "AWS_RDS_NO_ENCRYPTION",
    "AWS_EBS_ENCRYPTION_BY_DEFAULT_DISABLED",
    "AWS_CLOUDTRAIL_NOT_MULTI_REGION",
    "AWS_CLOUDTRAIL_LOG_VALIDATION_DISABLED",
    "AWS_VPC_FLOW_LOGS_DISABLED",
])
def test_cspm_rule_maps_to_existing_cis_aws_control(rule_id: str) -> None:
    """Every live-scan rule must map to a control that exists in
    the CIS AWS catalog. Catches typos / drift on either side."""
    assert rule_id in RULE_ID_TO_CONTROLS, (
        f"{rule_id} not in RULE_ID_TO_CONTROLS — auditor evidence "
        f"would be missing"
    )
    for fw, cid in RULE_ID_TO_CONTROLS[rule_id]:
        assert get_control(fw, cid) is not None, (
            f"{rule_id} maps to ({fw}, {cid}) but the control "
            f"isn't in the {fw} catalog"
        )


def test_cspm_finding_gets_cis_aws_control_via_enrichment() -> None:
    """End-to-end: a finding shape resembling what
    `cspm.aws.tools._emit_finding` builds should pick up the
    CIS AWS control in the enricher output."""
    out = compliance_module.enrich_finding_with_compliance({
        "cwe": "CWE-732",
        "category": "misconfig",
        "rule_id": "AWS_S3_PUBLIC_ACL",
        "title": "Public S3 bucket",
    })
    controls = out["compliance_controls"]
    assert "2.1.5" in controls["cis_aws"]


def test_controls_for_cspm_rule_only() -> None:
    """A pure rule_id lookup against a CSPM rule returns the
    CIS AWS row alone (no CWE contamination)."""
    out = controls_for(rule_id="AWS_CLOUDTRAIL_NOT_MULTI_REGION")
    assert out == [(FRAMEWORK_CIS_AWS, "3.1")]


def test_controls_for_by_framework_groups_cis_aws() -> None:
    out = controls_for_by_framework(rule_id="AWS_IAM_ROOT_ACCESS_KEY")
    assert FRAMEWORK_CIS_AWS in out
    assert out[FRAMEWORK_CIS_AWS] == ["1.4"]
