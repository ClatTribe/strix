"""Tests for v4 attack-path patterns (masterroadmap §5 v2 expansion
— 18 → 25)."""

from __future__ import annotations

import pytest

from strix.cloud_attack_paths.graph import (
    CloudGraph,
    CloudIdentity,
    CloudPolicy,
    CloudResource,
    EDGE_EXPOSED_TO_INTERNET,
    EDGE_HAS_POLICY,
)
from strix.cloud_attack_paths.patterns import (
    BUILTIN_PATTERNS,
    find_attack_paths,
)


# ---------------------------------------------------------------------------
# Registry hygiene
# ---------------------------------------------------------------------------


def test_v4_total_pattern_count_at_least_twentyfive() -> None:
    """v3 was 18; v4 adds 7 → ≥ 25."""
    assert len(BUILTIN_PATTERNS) >= 25


@pytest.mark.parametrize("pid", [
    "cap_lambda_function_url_no_auth",
    "cap_iam_user_active_keys_no_mfa",
    "cap_cross_account_s3_share",
    "cap_unused_iam_role_high_priv",
    "cap_default_vpc_with_resources",
    "cap_secrets_via_environment",
    "cap_overpermissive_secrets_manager_resource_policy",
])
def test_v4_pattern_registered(pid: str) -> None:
    assert pid in BUILTIN_PATTERNS


# ---------------------------------------------------------------------------
# cap_lambda_function_url_no_auth
# ---------------------------------------------------------------------------


def test_lambda_function_url_no_auth_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:lambda:us-east-1:1:function:api",
        kind="lambda_function", is_public=True,
        attributes={
            "function_url_auth_type": "NONE",
            "function_url": "https://abc.lambda-url.us-east-1.on.aws/",
        },
    ))
    paths = find_attack_paths(g, patterns=["cap_lambda_function_url_no_auth"])
    assert len(paths) == 1
    assert paths[0].severity == "high"


def test_lambda_function_url_aws_iam_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:lambda:us-east-1:1:function:api",
        kind="lambda_function", is_public=True,
        attributes={"function_url_auth_type": "AWS_IAM"},
    ))
    paths = find_attack_paths(g, patterns=["cap_lambda_function_url_no_auth"])
    assert paths == []


# ---------------------------------------------------------------------------
# cap_iam_user_active_keys_no_mfa
# ---------------------------------------------------------------------------


def test_iam_user_active_keys_no_mfa_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:user/eve",
        kind="iam_user",
        attributes={
            "has_active_access_key": True,
            "mfa_enabled": False,
        },
    ))
    paths = find_attack_paths(g, patterns=["cap_iam_user_active_keys_no_mfa"])
    assert len(paths) == 1
    assert paths[0].severity == "high"


def test_iam_user_with_mfa_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:user/bob",
        kind="iam_user",
        attributes={
            "has_active_access_key": True,
            "mfa_enabled": True,
        },
    ))
    paths = find_attack_paths(g, patterns=["cap_iam_user_active_keys_no_mfa"])
    assert paths == []


def test_iam_user_no_keys_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:user/alice",
        kind="iam_user",
        attributes={
            "has_active_access_key": False,
            "mfa_enabled": False,
        },
    ))
    paths = find_attack_paths(g, patterns=["cap_iam_user_active_keys_no_mfa"])
    assert paths == []


# ---------------------------------------------------------------------------
# cap_cross_account_s3_share
# ---------------------------------------------------------------------------


def test_cross_account_s3_share_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::shared",
        kind="s3_bucket",
    ))
    g.add_node(CloudPolicy(
        arn="arn:aws:s3:::shared/policy",
        kind="bucket_policy",
        statements=[{
            "effect": "Allow",
            "principal": {"AWS": "arn:aws:iam::999:root"},
            "actions": ["s3:GetObject"],
            "resources": ["arn:aws:s3:::shared/*"],
        }],
    ))
    # Edge: bucket has policy.
    g.add_edge("arn:aws:s3:::shared", EDGE_HAS_POLICY,
               "arn:aws:s3:::shared/policy")
    paths = find_attack_paths(g, patterns=["cap_cross_account_s3_share"])
    assert len(paths) == 1
    assert paths[0].severity == "medium"
    assert "999" in paths[0].metadata["cross_account_principals"]


def test_same_account_s3_share_does_not_fire() -> None:
    """Bucket policy granting access within the same account
    (the bucket's owner) isn't cross-account — no finding."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::owned",
        kind="s3_bucket",
    ))
    g.add_node(CloudPolicy(
        arn="arn:aws:s3:::owned/policy",
        kind="bucket_policy",
        statements=[{
            "effect": "Allow",
            "principal": {"AWS": "arn:aws:iam:::root"},
            "actions": ["s3:GetObject"],
        }],
    ))
    g.add_edge("arn:aws:s3:::owned", EDGE_HAS_POLICY,
               "arn:aws:s3:::owned/policy")
    paths = find_attack_paths(g, patterns=["cap_cross_account_s3_share"])
    # No external account principal present.
    assert paths == []


# ---------------------------------------------------------------------------
# cap_unused_iam_role_high_priv
# ---------------------------------------------------------------------------


def test_unused_admin_role_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/old-admin",
        kind="iam_role",
        attributes={"days_since_used": 180},
    ))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/admin",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:role/old-admin", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/admin")
    paths = find_attack_paths(g, patterns=["cap_unused_iam_role_high_priv"])
    assert len(paths) == 1
    assert paths[0].metadata["days_since_used"] == 180


def test_recently_used_admin_role_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/active-admin",
        kind="iam_role",
        attributes={"days_since_used": 3},
    ))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/admin",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:role/active-admin", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/admin")
    paths = find_attack_paths(g, patterns=["cap_unused_iam_role_high_priv"])
    assert paths == []


def test_unused_low_priv_role_does_not_fire() -> None:
    """Unused but scoped role isn't a critical orphan — pattern
    only flags high-privilege idle roles."""
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/read-only",
        kind="iam_role",
        attributes={"days_since_used": 200},
    ))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/read",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["s3:GetObject"],
            "resources": ["arn:aws:s3:::data/*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:role/read-only", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/read")
    paths = find_attack_paths(g, patterns=["cap_unused_iam_role_high_priv"])
    assert paths == []


# ---------------------------------------------------------------------------
# cap_default_vpc_with_resources
# ---------------------------------------------------------------------------


def test_default_vpc_with_resources_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:vpc/vpc-default",
        kind="ec2_vpc",
        attributes={"is_default_vpc": True},
    ))
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-aaa",
        kind="ec2_instance",
        attributes={"vpc_arn": "arn:aws:ec2:us-east-1:1:vpc/vpc-default"},
    ))
    paths = find_attack_paths(g, patterns=["cap_default_vpc_with_resources"])
    assert len(paths) == 1
    assert paths[0].metadata["resource_count"] == 1


def test_default_vpc_empty_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:vpc/vpc-default",
        kind="ec2_vpc",
        attributes={"is_default_vpc": True},
    ))
    paths = find_attack_paths(g, patterns=["cap_default_vpc_with_resources"])
    assert paths == []


def test_non_default_vpc_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:vpc/vpc-prod",
        kind="ec2_vpc",
        attributes={"is_default_vpc": False},
    ))
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-aaa",
        kind="ec2_instance",
        attributes={"vpc_arn": "arn:aws:ec2:us-east-1:1:vpc/vpc-prod"},
    ))
    paths = find_attack_paths(g, patterns=["cap_default_vpc_with_resources"])
    assert paths == []


# ---------------------------------------------------------------------------
# cap_secrets_via_environment
# ---------------------------------------------------------------------------


def test_secrets_via_env_fires_on_password_key() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:lambda:us-east-1:1:function:api",
        kind="lambda_function",
        attributes={
            "environment_vars": {
                "DB_PASSWORD": "(redacted)",
                "FEATURE_FLAG": "true",
            },
        },
    ))
    paths = find_attack_paths(g, patterns=["cap_secrets_via_environment"])
    assert len(paths) == 1
    assert "DB_PASSWORD" in paths[0].metadata["matched_keys"]


def test_secrets_via_env_no_suspicious_keys() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:lambda:us-east-1:1:function:api",
        kind="lambda_function",
        attributes={
            "environment_vars": {
                "FEATURE_FLAG": "true",
                "LOG_LEVEL": "info",
            },
        },
    ))
    paths = find_attack_paths(g, patterns=["cap_secrets_via_environment"])
    assert paths == []


def test_secrets_via_env_handles_ecs_task() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ecs:us-east-1:1:task-definition/api:1",
        kind="ecs_task",
        attributes={
            "environment_vars": {"API_TOKEN": "x"},
        },
    ))
    paths = find_attack_paths(g, patterns=["cap_secrets_via_environment"])
    assert len(paths) == 1


# ---------------------------------------------------------------------------
# cap_overpermissive_secrets_manager_resource_policy
# ---------------------------------------------------------------------------


def test_secrets_manager_wildcard_resource_policy_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:secretsmanager:us-east-1:1:secret:db-creds",
        kind="secrets_manager_secret",
    ))
    g.add_node(CloudPolicy(
        arn="arn:aws:secretsmanager:us-east-1:1:secret:db-creds/policy",
        kind="kms_key_policy",
        statements=[{
            "effect": "Allow",
            "principal": "*",
            "actions": ["secretsmanager:GetSecretValue"],
        }],
    ))
    g.add_edge(
        "arn:aws:secretsmanager:us-east-1:1:secret:db-creds",
        EDGE_HAS_POLICY,
        "arn:aws:secretsmanager:us-east-1:1:secret:db-creds/policy",
    )
    paths = find_attack_paths(
        g, patterns=["cap_overpermissive_secrets_manager_resource_policy"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"


def test_secrets_manager_scoped_principal_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:secretsmanager:us-east-1:1:secret:db-creds",
        kind="secrets_manager_secret",
    ))
    g.add_node(CloudPolicy(
        arn="arn:aws:secretsmanager:us-east-1:1:secret:db-creds/policy",
        kind="kms_key_policy",
        statements=[{
            "effect": "Allow",
            "principal": {"AWS": "arn:aws:iam::1:role/app"},
            "actions": ["secretsmanager:GetSecretValue"],
        }],
    ))
    g.add_edge(
        "arn:aws:secretsmanager:us-east-1:1:secret:db-creds",
        EDGE_HAS_POLICY,
        "arn:aws:secretsmanager:us-east-1:1:secret:db-creds/policy",
    )
    paths = find_attack_paths(
        g, patterns=["cap_overpermissive_secrets_manager_resource_policy"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# Empty graph + sort stability
# ---------------------------------------------------------------------------


def test_v4_patterns_handle_empty_graph() -> None:
    paths = find_attack_paths(CloudGraph(), patterns=[
        "cap_lambda_function_url_no_auth",
        "cap_iam_user_active_keys_no_mfa",
        "cap_cross_account_s3_share",
        "cap_unused_iam_role_high_priv",
        "cap_default_vpc_with_resources",
        "cap_secrets_via_environment",
        "cap_overpermissive_secrets_manager_resource_policy",
    ])
    assert paths == []
