"""Tests for IAM CSPM checks."""

from __future__ import annotations

from strix.cspm.aws.checks.iam import (
    iam_password_policy_weak,
    iam_policy_wildcard_admin,
    iam_root_access_key_exists,
    iam_user_no_mfa,
)


def test_root_access_key_detected(fake_factory) -> None:
    fake_factory.register(
        service="iam", region=None,
        methods={"get_account_summary": {
            "SummaryMap": {"AccountAccessKeysPresent": 1},
        }},
    )
    out = iam_root_access_key_exists(fake_factory, None)
    assert len(out) == 1
    assert out[0].rule_id == "AWS_IAM_ROOT_ACCESS_KEY"
    assert out[0].severity == "critical"


def test_no_root_access_key_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="iam", region=None,
        methods={"get_account_summary": {
            "SummaryMap": {"AccountAccessKeysPresent": 0},
        }},
    )
    assert iam_root_access_key_exists(fake_factory, None) == []


def test_iam_user_console_access_no_mfa_detected(fake_factory) -> None:
    """User has a login profile (= console access) AND no MFA → finding."""
    fake_factory.register(
        service="iam", region=None,
        methods={
            "get_login_profile": {"LoginProfile": {"UserName": "alice"}},
            "list_mfa_devices": {"MFADevices": []},
        },
        paginators={
            "list_users": [{"Users": [{"UserName": "alice"}]}],
        },
    )
    out = iam_user_no_mfa(fake_factory, None)
    assert len(out) == 1
    assert out[0].rule_id == "AWS_IAM_USER_NO_MFA"
    assert out[0].metadata["username"] == "alice"


def test_iam_user_no_console_no_mfa_skipped(fake_factory) -> None:
    """Service-account-style IAM users (no login profile) don't
    need MFA — they should be skipped."""
    fake_factory.register(
        service="iam", region=None,
        methods={
            "get_login_profile": Exception(
                "NoSuchEntity: Login profile not found"
            ),
            "list_mfa_devices": {"MFADevices": []},
        },
        paginators={
            "list_users": [{"Users": [{"UserName": "ci-bot"}]}],
        },
    )
    assert iam_user_no_mfa(fake_factory, None) == []


def test_iam_user_with_mfa_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="iam", region=None,
        methods={
            "get_login_profile": {"LoginProfile": {"UserName": "bob"}},
            "list_mfa_devices": {"MFADevices": [{"SerialNumber": "arn:..."}]},
        },
        paginators={
            "list_users": [{"Users": [{"UserName": "bob"}]}],
        },
    )
    assert iam_user_no_mfa(fake_factory, None) == []


def test_password_policy_missing_detected(fake_factory) -> None:
    fake_factory.register(
        service="iam", region=None,
        methods={"get_account_password_policy": Exception(
            "NoSuchEntity: The Password Policy is not configured"
        )},
    )
    out = iam_password_policy_weak(fake_factory, None)
    assert len(out) == 1
    assert out[0].rule_id == "AWS_IAM_PASSWORD_POLICY_MISSING"


def test_password_policy_weak_detected(fake_factory) -> None:
    fake_factory.register(
        service="iam", region=None,
        methods={"get_account_password_policy": {"PasswordPolicy": {
            "MinimumPasswordLength": 8,           # < 14 → flagged
            "RequireSymbols": False,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
        }}},
    )
    out = iam_password_policy_weak(fake_factory, None)
    assert len(out) == 1
    assert out[0].rule_id == "AWS_IAM_PASSWORD_POLICY_WEAK"
    issues = out[0].metadata["issues"]
    assert any("MinimumPasswordLength" in i for i in issues)
    assert any("RequireSymbols" in i for i in issues)


def test_password_policy_strong_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="iam", region=None,
        methods={"get_account_password_policy": {"PasswordPolicy": {
            "MinimumPasswordLength": 16,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
        }}},
    )
    assert iam_password_policy_weak(fake_factory, None) == []


_WILDCARD_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*",
    }],
}

_SCOPED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::mybucket/*",
    }],
}


def test_wildcard_admin_policy_detected(fake_factory) -> None:
    fake_factory.register(
        service="iam", region=None,
        methods={
            "get_policy_version": {"PolicyVersion": {
                "Document": _WILDCARD_POLICY,
            }},
        },
        paginators={
            "list_policies": [{"Policies": [{
                "PolicyName": "evil-admin",
                "Arn": "arn:aws:iam::111111111111:policy/evil-admin",
                "DefaultVersionId": "v1",
            }]}],
        },
    )
    out = iam_policy_wildcard_admin(fake_factory, None)
    assert len(out) == 1
    assert out[0].rule_id == "AWS_IAM_POLICY_WILDCARD_ADMIN"
    assert out[0].severity == "critical"


def test_scoped_policy_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="iam", region=None,
        methods={
            "get_policy_version": {"PolicyVersion": {
                "Document": _SCOPED_POLICY,
            }},
        },
        paginators={
            "list_policies": [{"Policies": [{
                "PolicyName": "read-mybucket",
                "Arn": "arn:aws:iam::111111111111:policy/read-mybucket",
                "DefaultVersionId": "v1",
            }]}],
        },
    )
    assert iam_policy_wildcard_admin(fake_factory, None) == []


def test_deny_wildcard_not_flagged(fake_factory) -> None:
    """`Effect: Deny` + `Action: *` is a guardrail, not an
    admin grant — should NOT be flagged."""
    deny = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }],
    }
    fake_factory.register(
        service="iam", region=None,
        methods={
            "get_policy_version": {"PolicyVersion": {"Document": deny}},
        },
        paginators={
            "list_policies": [{"Policies": [{
                "PolicyName": "global-deny",
                "Arn": "arn:aws:iam::111111111111:policy/global-deny",
                "DefaultVersionId": "v1",
            }]}],
        },
    )
    assert iam_policy_wildcard_admin(fake_factory, None) == []
