"""Tests for the CSPM → CloudGraph ingester."""

from __future__ import annotations

import pytest

from strix.cloud_attack_paths.graph import (
    CloudIdentity,
    CloudPolicy,
    CloudResource,
    EDGE_ATTACHED_TO,
    EDGE_EXPOSED_TO_INTERNET,
    EDGE_GRANTS_ACCESS_TO,
    EDGE_HAS_POLICY,
)
from strix.cloud_attack_paths.ingest import build_graph_from_cspm
from strix.cspm.aws import CspmFinding


def _f(rule_id: str, *, arn: str, service: str = "s3",
       region: str | None = None, severity: str = "high") -> CspmFinding:
    return CspmFinding(
        rule_id=rule_id, severity=severity,
        message=f"{rule_id} on {arn}",
        service=service, region=region, resource_arn=arn,
        account_id="123456789012",
        cwe="CWE-732", category="misconfig",
    )


# ---------------------------------------------------------------------------
# Phase 1: findings → nodes
# ---------------------------------------------------------------------------


def test_s3_finding_creates_resource_node() -> None:
    g = build_graph_from_cspm([
        _f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::data"),
    ])
    n = g.get_node("arn:aws:s3:::data")
    assert isinstance(n, CloudResource)
    assert n.kind == "s3_bucket"
    assert n.is_public is True
    assert n.is_data_store is True   # s3_bucket is a data-store kind


def test_iam_role_arn_creates_identity_node() -> None:
    g = build_graph_from_cspm([
        _f("AWS_IAM_USER_NO_MFA",
           arn="arn:aws:iam::123:role/admin",
           service="iam"),
    ])
    n = g.get_node("arn:aws:iam::123:role/admin")
    assert isinstance(n, CloudIdentity)
    assert n.kind == "iam_role"


def test_root_account_finding_flags_unsafe() -> None:
    g = build_graph_from_cspm([
        _f("AWS_IAM_ROOT_ACCESS_KEY",
           arn="arn:aws:iam::123:root",
           service="iam"),
    ])
    n = g.get_node("arn:aws:iam::123:root")
    assert isinstance(n, CloudIdentity)
    assert n.kind == "aws_root"
    assert n.attributes.get("root_unsafe") is True


def test_wildcard_policy_finding_seeds_admin_statement() -> None:
    g = build_graph_from_cspm([
        _f("AWS_IAM_POLICY_WILDCARD_ADMIN",
           arn="arn:aws:iam::123:policy/super",
           service="iam"),
    ])
    n = g.get_node("arn:aws:iam::123:policy/super")
    assert isinstance(n, CloudPolicy)
    assert n.has_wildcard_admin()


def test_public_exposure_rule_adds_edge() -> None:
    """`is_public` attribute AND `exposed_to_internet` edge both
    populated — pattern matchers can query either way."""
    g = build_graph_from_cspm([
        _f("AWS_SG_OPEN_INGRESS_ADMIN",
           arn="arn:aws:ec2:us-east-1:1:security-group/sg-aaa",
           service="ec2", region="us-east-1"),
    ])
    n = g.get_node("arn:aws:ec2:us-east-1:1:security-group/sg-aaa")
    assert n.is_public is True
    assert g.is_internet_exposed(n.arn)


# ---------------------------------------------------------------------------
# Phase 2: asset inventory enrichment
# ---------------------------------------------------------------------------


def test_assets_add_lambda_with_attached_role() -> None:
    """Asset inventory carries information CSPM findings don't —
    notably "this lambda has THIS role attached"."""
    g = build_graph_from_cspm(
        findings=[],
        assets=[
            {
                "arn": "arn:aws:lambda:us-east-1:1:function:api",
                "kind": "lambda_function",
                "is_public": True,
                "attached_role_arn": "arn:aws:iam::1:role/api-role",
            },
            {
                "arn": "arn:aws:iam::1:role/api-role",
                "kind": "iam_role",
                "trust_principals": ["lambda.amazonaws.com"],
            },
        ],
    )
    lam = g.get_node("arn:aws:lambda:us-east-1:1:function:api")
    role = g.get_node("arn:aws:iam::1:role/api-role")
    assert isinstance(lam, CloudResource)
    assert isinstance(role, CloudIdentity)
    assert lam.is_public
    # Edge: role --attached_to--> lambda.
    assert g.has_edge(
        role.arn, EDGE_ATTACHED_TO, lam.arn,
    )


def test_assets_policy_with_statements_creates_grants_edges() -> None:
    """Policies with explicit statements get `grants_access_to`
    edges to each named resource — pattern matchers can walk
    them."""
    g = build_graph_from_cspm(
        findings=[],
        assets=[{
            "arn": "arn:aws:iam::1:policy/p",
            "kind": "iam_managed_policy",
            "statements": [{
                "effect": "Allow",
                "actions": ["s3:GetObject"],
                "resources": ["arn:aws:s3:::secrets-bucket"],
            }],
        }],
    )
    p = g.get_node("arn:aws:iam::1:policy/p")
    assert isinstance(p, CloudPolicy)
    # Edge exists.
    assert g.has_edge(p.arn, EDGE_GRANTS_ACCESS_TO,
                      "arn:aws:s3:::secrets-bucket")
    # Target resource auto-created.
    target = g.get_node("arn:aws:s3:::secrets-bucket")
    assert target is not None


def test_assets_policy_attached_to_identity() -> None:
    g = build_graph_from_cspm(
        findings=[],
        assets=[{
            "arn": "arn:aws:iam::1:policy/p",
            "kind": "iam_managed_policy",
            "attached_to": ["arn:aws:iam::1:role/r"],
        }],
    )
    assert g.has_edge(
        "arn:aws:iam::1:role/r", EDGE_HAS_POLICY,
        "arn:aws:iam::1:policy/p",
    )


def test_assets_world_assumable_trust_policy() -> None:
    g = build_graph_from_cspm(
        findings=[],
        assets=[{
            "arn": "arn:aws:iam::1:role/world",
            "kind": "iam_role",
            "trust_principals": ["*"],
        }],
    )
    role = g.get_node("arn:aws:iam::1:role/world")
    assert role.is_world_assumable


# ---------------------------------------------------------------------------
# ARN-kind inference
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arn,expected_kind", [
    ("arn:aws:s3:::mybucket", "s3_bucket"),
    ("arn:aws:rds:us-east-1:1:db:prod", "rds_db_instance"),
    ("arn:aws:lambda:us-east-1:1:function:f", "lambda_function"),
    ("arn:aws:ec2:us-east-1:1:instance/i-aaa", "ec2_instance"),
    ("arn:aws:ec2:us-east-1:1:security-group/sg-aaa", "ec2_security_group"),
    ("arn:aws:iam::1:user/alice", "iam_user"),
    ("arn:aws:iam::1:role/admin", "iam_role"),
    ("arn:aws:iam::1:policy/super", "iam_managed_policy"),
    ("arn:aws:iam::1:root", "aws_root"),
    ("arn:aws:dynamodb:us-east-1:1:table/t", "dynamodb_table"),
    ("arn:aws:secretsmanager:us-east-1:1:secret:s-aaa", "secrets_manager_secret"),
])
def test_arn_kind_inference(arn: str, expected_kind: str) -> None:
    g = build_graph_from_cspm([_f("AWS_S3_PUBLIC_ACL", arn=arn)])
    n = g.get_node(arn)
    assert n is not None
    assert n.kind == expected_kind


def test_unknown_arn_falls_back_to_service_prefix() -> None:
    g = build_graph_from_cspm([
        _f("AWS_S3_PUBLIC_ACL", arn="arn:aws:newservice:us-east-1:1:thing/x"),
    ])
    n = g.get_node("arn:aws:newservice:us-east-1:1:thing/x")
    assert n is not None
    assert n.kind == "newservice_resource"


# ---------------------------------------------------------------------------
# Multi-source merge
# ---------------------------------------------------------------------------


def test_finding_then_asset_merges_not_clobbers() -> None:
    """When the same ARN appears in findings AND assets, attributes
    from BOTH sources accumulate — the finding's public flag
    survives the asset enrichment pass."""
    g = build_graph_from_cspm(
        findings=[_f("AWS_S3_PUBLIC_ACL", arn="arn:aws:s3:::x")],
        assets=[{
            "arn": "arn:aws:s3:::x",
            "kind": "s3_bucket",
            "is_data_store": True,
            "tag_owner": "alice",
        }],
    )
    n = g.get_node("arn:aws:s3:::x")
    assert n.is_public is True       # from finding
    assert n.is_data_store is True   # from asset
    assert n.attributes.get("tag_owner") == "alice"
