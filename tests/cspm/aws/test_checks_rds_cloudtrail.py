"""Tests for RDS + CloudTrail CSPM checks."""

from __future__ import annotations

from strix.cspm.aws.checks.cloudtrail import (
    cloudtrail_log_file_validation_disabled,
    cloudtrail_no_multi_region_trail,
)
from strix.cspm.aws.checks.rds import (
    rds_instance_publicly_accessible,
    rds_instance_unencrypted,
)


def _db_page(*dbs):
    return {"DBInstances": list(dbs)}


def test_rds_public_access_detected(fake_factory) -> None:
    fake_factory.register(
        service="rds", region="us-east-1",
        paginators={
            "describe_db_instances": [_db_page({
                "DBInstanceIdentifier": "exposed-prod",
                "Engine": "postgres",
                "PubliclyAccessible": True,
                "DBInstanceArn": "arn:aws:rds:us-east-1:1:db:exposed-prod",
                "StorageEncrypted": True,
            })],
        },
    )
    out = rds_instance_publicly_accessible(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].rule_id == "AWS_RDS_PUBLIC_ACCESS"
    assert out[0].severity == "critical"


def test_rds_private_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="rds", region="us-east-1",
        paginators={
            "describe_db_instances": [_db_page({
                "DBInstanceIdentifier": "private",
                "PubliclyAccessible": False,
                "StorageEncrypted": True,
            })],
        },
    )
    assert rds_instance_publicly_accessible(fake_factory, "us-east-1") == []


def test_rds_unencrypted_detected(fake_factory) -> None:
    fake_factory.register(
        service="rds", region="us-east-1",
        paginators={
            "describe_db_instances": [_db_page({
                "DBInstanceIdentifier": "unenc",
                "Engine": "mysql",
                "StorageEncrypted": False,
                "DBInstanceArn": "arn:aws:rds:us-east-1:1:db:unenc",
            })],
        },
    )
    out = rds_instance_unencrypted(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].rule_id == "AWS_RDS_NO_ENCRYPTION"
    assert out[0].severity == "high"


def test_rds_encrypted_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="rds", region="us-east-1",
        paginators={
            "describe_db_instances": [_db_page({
                "DBInstanceIdentifier": "enc",
                "StorageEncrypted": True,
            })],
        },
    )
    assert rds_instance_unencrypted(fake_factory, "us-east-1") == []


def test_cloudtrail_no_multi_region_detected(fake_factory) -> None:
    """Account has only single-region trails → finding."""
    fake_factory.register(
        service="cloudtrail", region="us-east-1",
        methods={
            "describe_trails": {"trailList": [{
                "Name": "single", "TrailARN": "arn:single",
                "IsMultiRegionTrail": False,
            }]},
        },
    )
    out = cloudtrail_no_multi_region_trail(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].rule_id == "AWS_CLOUDTRAIL_NOT_MULTI_REGION"


def test_cloudtrail_inactive_multi_region_still_flagged(fake_factory) -> None:
    """A multi-region trail that isn't logging counts as no
    coverage — the audit history isn't actually being captured."""
    fake_factory.register(
        service="cloudtrail", region="us-east-1",
        methods={
            "describe_trails": {"trailList": [{
                "Name": "mr-disabled", "TrailARN": "arn:mr",
                "IsMultiRegionTrail": True,
            }]},
            "get_trail_status": {"IsLogging": False},
        },
    )
    out = cloudtrail_no_multi_region_trail(fake_factory, "us-east-1")
    assert len(out) == 1


def test_cloudtrail_active_multi_region_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="cloudtrail", region="us-east-1",
        methods={
            "describe_trails": {"trailList": [{
                "Name": "good", "TrailARN": "arn:good",
                "IsMultiRegionTrail": True,
            }]},
            "get_trail_status": {"IsLogging": True},
        },
    )
    assert cloudtrail_no_multi_region_trail(fake_factory, "us-east-1") == []


def test_cloudtrail_log_validation_disabled_detected(fake_factory) -> None:
    fake_factory.register(
        service="cloudtrail", region="us-east-1",
        methods={
            "describe_trails": {"trailList": [{
                "Name": "novalidation", "TrailARN": "arn:nv",
                "LogFileValidationEnabled": False,
                "HomeRegion": "us-east-1",
            }]},
        },
    )
    out = cloudtrail_log_file_validation_disabled(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].rule_id == "AWS_CLOUDTRAIL_LOG_VALIDATION_DISABLED"


def test_cloudtrail_log_validation_enabled_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="cloudtrail", region="us-east-1",
        methods={
            "describe_trails": {"trailList": [{
                "Name": "good", "TrailARN": "arn:good",
                "LogFileValidationEnabled": True,
                "HomeRegion": "us-east-1",
            }]},
        },
    )
    assert cloudtrail_log_file_validation_disabled(fake_factory, "us-east-1") == []


def test_cloudtrail_only_runs_in_us_east_1(fake_factory) -> None:
    """CloudTrail checks reflect global state — dispatch only from
    us-east-1 to avoid emitting N copies of the same finding."""
    fake_factory.register(
        service="cloudtrail", region="us-west-2",
        methods={"describe_trails": {"trailList": []}},
    )
    assert cloudtrail_no_multi_region_trail(fake_factory, "us-west-2") == []
    assert cloudtrail_log_file_validation_disabled(fake_factory, "us-west-2") == []
