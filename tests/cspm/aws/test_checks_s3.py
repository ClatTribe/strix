"""Tests for S3 CSPM checks."""

from __future__ import annotations

import pytest

from strix.cspm.aws.checks.s3 import (
    s3_bucket_no_default_encryption,
    s3_bucket_public_acl,
    s3_bucket_versioning_disabled,
)


_PUBLIC_GRANT = {
    "Grantee": {
        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
    },
    "Permission": "READ",
}


def test_public_acl_detected(fake_factory) -> None:
    fake_factory.register(
        service="s3", region="us-east-1",
        methods={
            "list_buckets": {"Buckets": [{"Name": "public-data"}]},
            "get_bucket_acl": {"Grants": [_PUBLIC_GRANT]},
        },
    )
    out = s3_bucket_public_acl(fake_factory, "us-east-1")
    assert len(out) == 1
    f = out[0]
    assert f.rule_id == "AWS_S3_PUBLIC_ACL"
    assert f.severity == "critical"
    assert "public-data" in f.message
    assert "AllUsers" in f.message
    assert f.resource_arn == "arn:aws:s3:::public-data"


def test_private_acl_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="s3", region="us-east-1",
        methods={
            "list_buckets": {"Buckets": [{"Name": "private-data"}]},
            "get_bucket_acl": {"Grants": [{
                "Grantee": {"ID": "owner-canonical-id", "Type": "CanonicalUser"},
                "Permission": "FULL_CONTROL",
            }]},
        },
    )
    assert s3_bucket_public_acl(fake_factory, "us-east-1") == []


def test_s3_check_only_runs_in_us_east_1(fake_factory) -> None:
    """S3 buckets are global — we dispatch only from us-east-1 to
    avoid emitting N copies of the same finding per region."""
    fake_factory.register(
        service="s3", region="us-west-2",
        methods={"list_buckets": {"Buckets": [{"Name": "x"}]}},
    )
    # Returns [] without even calling list_buckets — the check
    # short-circuits.
    assert s3_bucket_public_acl(fake_factory, "us-west-2") == []


def test_versioning_disabled_detected(fake_factory) -> None:
    fake_factory.register(
        service="s3", region="us-east-1",
        methods={
            "list_buckets": {"Buckets": [{"Name": "no-versioning"}]},
            "get_bucket_versioning": {},  # missing Status key → never enabled
        },
    )
    out = s3_bucket_versioning_disabled(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].rule_id == "AWS_S3_VERSIONING_DISABLED"
    assert out[0].severity == "medium"


def test_versioning_suspended_flagged(fake_factory) -> None:
    """`Suspended` is also a finding — bucket WAS versioned but
    isn't anymore. New writes are not versioned."""
    fake_factory.register(
        service="s3", region="us-east-1",
        methods={
            "list_buckets": {"Buckets": [{"Name": "suspended"}]},
            "get_bucket_versioning": {"Status": "Suspended"},
        },
    )
    out = s3_bucket_versioning_disabled(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].metadata["status"] == "suspended"


def test_versioning_enabled_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="s3", region="us-east-1",
        methods={
            "list_buckets": {"Buckets": [{"Name": "good"}]},
            "get_bucket_versioning": {"Status": "Enabled"},
        },
    )
    assert s3_bucket_versioning_disabled(fake_factory, "us-east-1") == []


def test_no_default_encryption_detected(fake_factory) -> None:
    """Botocore raises ClientError with the
    `ServerSideEncryptionConfigurationNotFoundError` code when a
    bucket has no default encryption — the check string-matches
    the message body."""
    err = Exception(
        "An error occurred (ServerSideEncryptionConfigurationNotFoundError) "
        "when calling the GetBucketEncryption operation: "
        "The server side encryption configuration was not found"
    )
    fake_factory.register(
        service="s3", region="us-east-1",
        methods={
            "list_buckets": {"Buckets": [{"Name": "noenc"}]},
            "get_bucket_encryption": err,
        },
    )
    out = s3_bucket_no_default_encryption(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].rule_id == "AWS_S3_NO_DEFAULT_ENCRYPTION"
    assert out[0].severity == "high"


def test_with_default_encryption_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="s3", region="us-east-1",
        methods={
            "list_buckets": {"Buckets": [{"Name": "enc"}]},
            "get_bucket_encryption": {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    }}],
                },
            },
        },
    )
    assert s3_bucket_no_default_encryption(fake_factory, "us-east-1") == []
