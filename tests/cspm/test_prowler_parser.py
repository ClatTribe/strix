"""Tests for the Prowler OCSF parser + argv builder.

No subprocess invocations — pure data tests against a recorded
fixture covering multi-cloud (AWS / Azure / GCP), all OCSF
statuses (PASS / FAIL / MANUAL), and severity ladder.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.compliance.frameworks import (
    FRAMEWORK_CIS_AWS,
    FRAMEWORK_CIS_AZURE,
    FRAMEWORK_CIS_GCP,
    FRAMEWORK_GDPR,
    FRAMEWORK_ISO27001,
    FRAMEWORK_NIST_800_53,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
)
from strix.cspm.prowler import (
    _build_prowler_argv,
    _find_ocsf_output,
    _translate_framework,
    _translate_severity,
    parse_prowler_ocsf,
)


FIXTURE = Path(__file__).parent / "fixtures" / "prowler_ocsf_sample.json"


@pytest.fixture(scope="module")
def fixture_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def parsed(fixture_text):
    return parse_prowler_ocsf(fixture_text)


# ---------------------------------------------------------------------------
# Parser — basic shape
# ---------------------------------------------------------------------------


def test_parser_drops_pass_and_manual(parsed) -> None:
    """Fixture has 4 FAIL + 1 PASS + 1 MANUAL → only FAIL survives."""
    assert len(parsed) == 4
    rule_ids = {f.rule_id for f in parsed}
    assert "prowler:s3_bucket_object_versioning" not in rule_ids  # PASS
    assert "prowler:manual_thing" not in rule_ids                  # MANUAL


def test_parser_namespaces_rule_ids(parsed) -> None:
    """Prowler check_ids get a `prowler:` prefix so they're
    distinguishable from native strix rule IDs (`AWS_*`,
    `TF_AWS_*`, etc.) in the dashboard."""
    for f in parsed:
        assert f.rule_id.startswith("prowler:"), (
            f"{f.rule_id} missing prowler: prefix"
        )


def test_parser_handles_multi_provider(parsed) -> None:
    services = {f.service for f in parsed}
    assert services == {"s3", "iam", "storage", "bigquery"}
    accounts = {f.account_id for f in parsed}
    assert "123456789012" in accounts                       # AWS
    assert "00000000-0000-0000-0000-000000000001" in accounts  # Azure
    assert "my-gcp-project" in accounts                      # GCP


def test_severity_normalised(parsed) -> None:
    """`Critical` → `critical`, `High` → `high`, `Informational`
    → `info`. Pinned so a Prowler-side rename doesn't silently
    downgrade strix severities."""
    by_check = {f.rule_id: f.severity for f in parsed}
    assert by_check["prowler:s3_bucket_public_access"] == "high"
    assert by_check["prowler:iam_root_mfa_enabled"] == "critical"
    assert by_check["prowler:storage_blob_public_access_level_is_disabled"] == "medium"
    assert by_check["prowler:bigquery_dataset_public_access"] == "high"


def test_resource_arn_extracted_from_first_resource(parsed) -> None:
    s3 = next(
        f for f in parsed
        if f.rule_id == "prowler:s3_bucket_public_access"
    )
    assert s3.resource_arn == "arn:aws:s3:::mybucket-prod"


def test_region_global_collapses_to_none(parsed) -> None:
    """OCSF emits `region: global` for global services (IAM).
    The CspmFinding shape uses None for global — keeps it
    consistent with the boto3 path."""
    iam = next(
        f for f in parsed if f.rule_id == "prowler:iam_root_mfa_enabled"
    )
    assert iam.region is None


def test_message_uses_status_extended_when_available(parsed) -> None:
    """`status_extended` is the per-resource message Prowler
    populates ('S3 Bucket mybucket-prod has public access...'),
    far more useful than the generic check title. Prefer it
    when present."""
    s3 = next(
        f for f in parsed
        if f.rule_id == "prowler:s3_bucket_public_access"
    )
    assert "mybucket-prod" in s3.message


def test_metadata_preserves_check_context(parsed) -> None:
    s3 = next(
        f for f in parsed
        if f.rule_id == "prowler:s3_bucket_public_access"
    )
    md = s3.metadata
    assert md["source"] == "prowler"
    assert md["check_id"] == "s3_bucket_public_access"
    assert "remediation" in md
    assert "related_url" in md
    assert md["categories"] == ["data-protection"]


# ---------------------------------------------------------------------------
# Compliance translation
# ---------------------------------------------------------------------------


def test_compliance_translated_aws_cis(parsed) -> None:
    s3 = next(
        f for f in parsed
        if f.rule_id == "prowler:s3_bucket_public_access"
    )
    compliance = s3.metadata["prowler_compliance"]
    assert FRAMEWORK_CIS_AWS in compliance
    assert "2.1.5" in compliance[FRAMEWORK_CIS_AWS]
    assert FRAMEWORK_SOC2 in compliance
    assert "CC6.1" in compliance[FRAMEWORK_SOC2]
    assert FRAMEWORK_NIST_800_53 in compliance


def test_compliance_skips_unknown_frameworks(parsed) -> None:
    """`AWS-Foundational-Security-Best-Practices` is in the
    fixture but strix doesn't have a catalog for it — must be
    dropped, not silently mis-bucketed under another framework."""
    s3 = next(
        f for f in parsed
        if f.rule_id == "prowler:s3_bucket_public_access"
    )
    compliance = s3.metadata["prowler_compliance"]
    # AFSBP key is not present anywhere.
    for fw, ctrls in compliance.items():
        assert "S3.2" not in ctrls


def test_compliance_translated_azure(parsed) -> None:
    azure = next(
        f for f in parsed
        if f.rule_id == "prowler:storage_blob_public_access_level_is_disabled"
    )
    compliance = azure.metadata["prowler_compliance"]
    assert FRAMEWORK_CIS_AZURE in compliance
    assert "3.7" in compliance[FRAMEWORK_CIS_AZURE]
    assert FRAMEWORK_ISO27001 in compliance


def test_compliance_translated_gcp(parsed) -> None:
    gcp = next(
        f for f in parsed
        if f.rule_id == "prowler:bigquery_dataset_public_access"
    )
    compliance = gcp.metadata["prowler_compliance"]
    assert FRAMEWORK_CIS_GCP in compliance
    assert "7.1" in compliance[FRAMEWORK_CIS_GCP]
    assert FRAMEWORK_GDPR in compliance


def test_translate_framework_disambiguates_cis_by_provider() -> None:
    """`CIS` is ambiguous — same key in Prowler output across
    AWS / Azure / GCP. Translation must pick the right framework
    based on the finding's provider."""
    assert _translate_framework("CIS-3.0", "aws") == FRAMEWORK_CIS_AWS
    assert _translate_framework("CIS-2.0", "azure") == FRAMEWORK_CIS_AZURE
    assert _translate_framework("CIS-2.0", "gcp") == FRAMEWORK_CIS_GCP


def test_translate_framework_handles_common_synonyms() -> None:
    assert _translate_framework("ISO-27001-2013", "aws") == FRAMEWORK_ISO27001
    assert _translate_framework("ISO27001-2022", "aws") == FRAMEWORK_ISO27001
    assert _translate_framework("PCI-3.2.1", "aws") == FRAMEWORK_PCI_DSS
    assert _translate_framework("PCI-DSS-4.0", "aws") == FRAMEWORK_PCI_DSS
    assert _translate_framework("SOC2", "aws") == FRAMEWORK_SOC2
    assert _translate_framework("SOC-2", "aws") == FRAMEWORK_SOC2


def test_translate_framework_returns_none_for_unknown() -> None:
    """FedRAMP / ENS / AWS-Foundational don't have strix catalogs
    — return None so caller skips rather than mis-mapping."""
    assert _translate_framework("AWS-Foundational-Security-Best-Practices", "aws") is None
    assert _translate_framework("FedRAMP-Moderate-Revision-4", "aws") is None
    assert _translate_framework("ENS-RD2022", "aws") is None


# ---------------------------------------------------------------------------
# Severity ladder
# ---------------------------------------------------------------------------


def test_severity_map_complete() -> None:
    """Every Prowler severity string must map to a known strix
    severity — unknowns default to medium (defensive)."""
    assert _translate_severity("Critical") == "critical"
    assert _translate_severity("HIGH") == "high"
    assert _translate_severity("medium") == "medium"
    assert _translate_severity("Low") == "low"
    assert _translate_severity("Informational") == "info"
    assert _translate_severity("Info") == "info"
    assert _translate_severity("unknown") == "low"
    assert _translate_severity(None) == "medium"
    assert _translate_severity("Made-Up") == "medium"


# ---------------------------------------------------------------------------
# Parser robustness
# ---------------------------------------------------------------------------


def test_parser_handles_empty_list() -> None:
    assert parse_prowler_ocsf("[]") == []


def test_parser_handles_invalid_json() -> None:
    assert parse_prowler_ocsf("not json") == []


def test_parser_handles_single_object_not_list() -> None:
    """Some Prowler invocations emit one object per file rather
    than a wrapping list — handle both shapes."""
    single = (
        '{"status_code": "FAIL", "severity": "Low", '
        '"cloud": {"provider": "AWS", "account": {"uid": "1"}, "region": "us-east-1"}, '
        '"resources": [{"uid": "arn:1"}], '
        '"unmapped": {"check_id": "x", "service_name": "ec2"}}'
    )
    out = parse_prowler_ocsf(single)
    assert len(out) == 1


def test_parser_handles_missing_optional_fields() -> None:
    """A minimal FAIL with no risk_details / remediation / compliance
    should still produce a usable finding, not crash."""
    minimal = (
        '[{"status_code": "FAIL", "severity": "Medium", '
        '"cloud": {"provider": "GCP", "account": {"uid": "p"}}, '
        '"resources": [{"uid": "projects/p/instances/i"}], '
        '"unmapped": {"check_id": "bare", "service_name": "compute"}}]'
    )
    out = parse_prowler_ocsf(minimal)
    assert len(out) == 1
    f = out[0]
    assert f.rule_id == "prowler:bare"
    assert f.service == "compute"
    assert "prowler_compliance" not in f.metadata


# ---------------------------------------------------------------------------
# argv builder
# ---------------------------------------------------------------------------


def test_argv_builder_aws_basic(tmp_path) -> None:
    argv = _build_prowler_argv(
        provider="aws",
        output_dir=tmp_path, output_basename="x",
        profile=None, role_arn=None, regions=None,
        checks=None, services=None, compliance=None,
        extra_args=None,
    )
    assert argv[:2] == ["prowler", "aws"]
    assert "--output-formats" in argv
    assert "json-ocsf" in argv
    assert "--status" in argv and "FAIL" in argv
    assert "--no-banner" in argv


def test_argv_builder_aws_with_profile_and_role(tmp_path) -> None:
    argv = _build_prowler_argv(
        provider="aws",
        output_dir=tmp_path, output_basename="x",
        profile="prod", role_arn="arn:aws:iam::1:role/x",
        regions=["us-east-1", "eu-west-1"],
        checks=None, services=None, compliance=None,
        extra_args=None,
    )
    assert "--profile" in argv and "prod" in argv
    assert "--role" in argv and "arn:aws:iam::1:role/x" in argv
    assert "--filter-region" in argv
    assert "us-east-1" in argv and "eu-west-1" in argv


def test_argv_builder_compliance_filter(tmp_path) -> None:
    argv = _build_prowler_argv(
        provider="aws",
        output_dir=tmp_path, output_basename="x",
        profile=None, role_arn=None, regions=None,
        checks=None, services=None,
        compliance=["cis_3.0_aws", "soc2_aws"],
        extra_args=None,
    )
    assert "--compliance" in argv
    assert "cis_3.0_aws" in argv
    assert "soc2_aws" in argv


def test_argv_builder_azure_no_aws_flags(tmp_path) -> None:
    """Azure provider must NOT pick up `--profile` / `--role` /
    `--filter-region` — those are AWS-only flags and would error
    on the Prowler side."""
    argv = _build_prowler_argv(
        provider="azure",
        output_dir=tmp_path, output_basename="x",
        profile="should-be-ignored",
        role_arn="should-be-ignored",
        regions=["should-be-ignored"],
        checks=None, services=None, compliance=None,
        extra_args=None,
    )
    assert "--profile" not in argv
    assert "--role" not in argv
    assert "--filter-region" not in argv


def test_argv_builder_rejects_unknown_provider(tmp_path) -> None:
    with pytest.raises(ValueError, match="unsupported provider"):
        _build_prowler_argv(
            provider="ibm-cloud",
            output_dir=tmp_path, output_basename="x",
            profile=None, role_arn=None, regions=None,
            checks=None, services=None, compliance=None,
            extra_args=None,
        )


# ---------------------------------------------------------------------------
# Output discovery
# ---------------------------------------------------------------------------


def test_find_ocsf_output_basename_match(tmp_path) -> None:
    target = tmp_path / "scan.ocsf.json"
    target.write_text("[]")
    out = _find_ocsf_output(tmp_path, "scan")
    assert out == target


def test_find_ocsf_output_timestamped_suffix(tmp_path) -> None:
    """Some Prowler versions add a timestamp to the filename.
    Match with a glob fallback."""
    target = tmp_path / "scan-20260517-123000.ocsf.json"
    target.write_text("[]")
    out = _find_ocsf_output(tmp_path, "scan")
    assert out == target


def test_find_ocsf_output_returns_none_when_missing(tmp_path) -> None:
    assert _find_ocsf_output(tmp_path, "scan") is None
