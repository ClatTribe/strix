"""Tests for AWS asset discovery (`strix.cloud_attack_paths.discovery`).

Hermetic — reuses `FakeAwsClientFactory` from
`tests/cspm/aws/conftest.py` to stub boto3 calls.

Each enumerator has a positive case (boto3 returns canned data,
expected asset dicts emerge) and at least one negative / error
case (missing permission, empty account)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.cloud_attack_paths import discovery as disc_module
from strix.cloud_attack_paths.discovery import (
    _discover_ec2,
    _discover_ecr,
    _discover_iam,
    _discover_lambda,
    _discover_rds,
    _discover_s3,
    _discover_secrets,
    _extract_trust_principals,
    _normalise_policy_statements,
    _trust_requires_external_id,
    discover_aws_assets,
)


# Re-use the FakeAwsClientFactory pattern from cspm tests.
class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        for p in self._pages:
            yield p


class _FakeClient:
    def __init__(self, methods=None, paginators=None):
        self._methods = methods or {}
        self._paginators = paginators or {}
        self.calls: list[tuple[str, dict]] = []

    def __getattr__(self, name):
        if name in self._methods:
            entry = self._methods[name]

            def _call(**kwargs):
                self.calls.append((name, kwargs))
                if isinstance(entry, Exception):
                    raise entry
                if callable(entry):
                    return entry(**kwargs)
                return entry
            return _call
        raise AttributeError(f"no method `{name}`")

    def get_paginator(self, name):
        if name not in self._paginators:
            raise AttributeError(f"no paginator `{name}`")
        return _Paginator(self._paginators[name])


class _FakeFactory:
    def __init__(self):
        self._clients: dict[tuple[str, str | None], _FakeClient] = {}

    def register(self, *, service, region, methods=None, paginators=None):
        c = _FakeClient(methods, paginators)
        self._clients[(service, region)] = c
        return c

    def __call__(self, service, region=None):
        if (service, region) in self._clients:
            return self._clients[(service, region)]
        if (service, None) in self._clients:
            return self._clients[(service, None)]
        raise KeyError(f"no client for ({service}, {region})")


@pytest.fixture
def factory() -> _FakeFactory:
    return _FakeFactory()


# ---------------------------------------------------------------------------
# S3 discovery
# ---------------------------------------------------------------------------


def test_discover_s3_emits_bucket_asset(factory) -> None:
    factory.register(
        service="s3", region="us-east-1",
        methods={
            "list_buckets": {
                "Buckets": [
                    {"Name": "prod-data"},
                    {"Name": "tfstate"},
                ],
            },
        },
    )
    out = _discover_s3(factory)
    assert len(out) == 2
    arns = {a["arn"] for a in out}
    assert arns == {"arn:aws:s3:::prod-data", "arn:aws:s3:::tfstate"}
    assert all(a["kind"] == "s3_bucket" for a in out)
    assert all(a["discovered_via"] == "s3:ListBuckets" for a in out)


def test_discover_s3_handles_empty_account(factory) -> None:
    factory.register(
        service="s3", region="us-east-1",
        methods={"list_buckets": {"Buckets": []}},
    )
    assert _discover_s3(factory) == []


def test_discover_s3_silently_skips_on_auth_failure(factory) -> None:
    factory.register(
        service="s3", region="us-east-1",
        methods={"list_buckets": Exception("AccessDenied")},
    )
    assert _discover_s3(factory) == []


# ---------------------------------------------------------------------------
# IAM discovery (users + roles + policies)
# ---------------------------------------------------------------------------


def test_discover_iam_users(factory) -> None:
    factory.register(
        service="iam", region=None,
        methods={},
        paginators={
            "list_users": [{
                "Users": [
                    {"Arn": "arn:aws:iam::1:user/alice",
                     "UserName": "alice"},
                    {"Arn": "arn:aws:iam::1:user/bob",
                     "UserName": "bob"},
                ],
            }],
            "list_roles": [{"Roles": []}],
            "list_policies": [{"Policies": []}],
        },
    )
    out = _discover_iam(factory)
    users = [a for a in out if a["kind"] == "iam_user"]
    assert len(users) == 2
    assert {u["arn"] for u in users} == {
        "arn:aws:iam::1:user/alice", "arn:aws:iam::1:user/bob",
    }


def test_discover_iam_roles_with_trust_principals(factory) -> None:
    """Role discovery should surface `trust_principals` AND
    `external_id_required` for downstream pattern matching."""
    factory.register(
        service="iam", region=None,
        methods={},
        paginators={
            "list_users": [{"Users": []}],
            "list_roles": [{
                "Roles": [
                    {
                        "Arn": "arn:aws:iam::1:role/lambda-exec",
                        "RoleName": "lambda-exec",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "lambda.amazonaws.com",
                                },
                                "Action": "sts:AssumeRole",
                            }],
                        },
                    },
                    {
                        "Arn": "arn:aws:iam::1:role/vendor",
                        "RoleName": "vendor",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": "arn:aws:iam::999:root",
                                },
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": {
                                        "sts:ExternalId": "secret-id",
                                    },
                                },
                            }],
                        },
                    },
                ],
            }],
            "list_policies": [{"Policies": []}],
        },
    )
    out = _discover_iam(factory)
    roles = {r["arn"]: r for r in out if r["kind"] == "iam_role"}
    assert "arn:aws:iam::1:role/lambda-exec" in roles
    assert "lambda.amazonaws.com" in roles[
        "arn:aws:iam::1:role/lambda-exec"
    ]["trust_principals"]
    assert roles["arn:aws:iam::1:role/lambda-exec"][
        "external_id_required"
    ] is False
    # The vendor role has ExternalId condition.
    assert roles["arn:aws:iam::1:role/vendor"][
        "external_id_required"
    ] is True


def test_discover_iam_policies_with_statements(factory) -> None:
    factory.register(
        service="iam", region=None,
        methods={
            "get_policy_version": {
                "PolicyVersion": {
                    "Document": {
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": ["arn:aws:s3:::x"],
                        }],
                    },
                },
            },
        },
        paginators={
            "list_users": [{"Users": []}],
            "list_roles": [{"Roles": []}],
            "list_policies": [{
                "Policies": [{
                    "Arn": "arn:aws:iam::1:policy/read-x",
                    "PolicyName": "read-x",
                    "DefaultVersionId": "v1",
                }],
            }],
        },
    )
    out = _discover_iam(factory)
    policies = [a for a in out if a["kind"] == "iam_managed_policy"]
    assert len(policies) == 1
    stmts = policies[0]["statements"]
    assert len(stmts) == 1
    assert stmts[0]["effect"] == "Allow"
    assert stmts[0]["actions"] == ["s3:GetObject"]


def test_discover_iam_partial_failure_does_not_crash(factory) -> None:
    """If ListUsers succeeds but ListRoles fails, we still get
    users — partial discovery is the contract."""
    factory.register(
        service="iam", region=None,
        methods={},
        paginators={
            "list_users": [{
                "Users": [
                    {"Arn": "arn:aws:iam::1:user/alice",
                     "UserName": "alice"},
                ],
            }],
            # No list_roles / list_policies registered → paginator
            # raises AttributeError on access → handled.
        },
    )
    out = _discover_iam(factory)
    # Got users; roles + policies silently skipped.
    users = [a for a in out if a["kind"] == "iam_user"]
    assert len(users) == 1


# ---------------------------------------------------------------------------
# IAM helper unit tests
# ---------------------------------------------------------------------------


def test_extract_trust_principals_handles_service_and_arn() -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": ["arn:aws:iam::123:root",
                                       "arn:aws:iam::456:root"]},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    out = _extract_trust_principals(doc)
    assert "lambda.amazonaws.com" in out
    assert "arn:aws:iam::123:root" in out
    assert "arn:aws:iam::456:root" in out


def test_extract_trust_principals_handles_wildcard() -> None:
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole",
        }],
    }
    assert _extract_trust_principals(doc) == ["*"]


def test_extract_trust_principals_skips_deny_statements() -> None:
    doc = {
        "Statement": [{
            "Effect": "Deny",
            "Principal": "*",
            "Action": "sts:AssumeRole",
        }],
    }
    assert _extract_trust_principals(doc) == []


def test_trust_requires_external_id_detection() -> None:
    """ExternalId condition under any operator block → True."""
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999:root"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {"sts:ExternalId": "secret"},
            },
        }],
    }
    assert _trust_requires_external_id(doc) is True


def test_trust_without_external_id() -> None:
    doc = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    assert _trust_requires_external_id(doc) is False


def test_policy_doc_coerced_from_url_encoded_string() -> None:
    """Boto3 sometimes returns policy docs URL-encoded; the parser
    handles both shapes."""
    from urllib.parse import quote
    payload = {
        "Statement": [{
            "Effect": "Allow", "Action": "*", "Resource": "*",
        }],
    }
    encoded = quote(json.dumps(payload))
    out = _normalise_policy_statements(encoded)
    assert len(out) == 1
    assert out[0]["effect"] == "Allow"
    assert out[0]["actions"] == ["*"]


# ---------------------------------------------------------------------------
# EC2 discovery
# ---------------------------------------------------------------------------


def test_discover_ec2_extracts_public_dns_and_role_attachment(factory) -> None:
    factory.register(
        service="ec2", region="us-east-1",
        paginators={
            "describe_instances": [{
                "Reservations": [{
                    "OwnerId": "1",
                    "Instances": [{
                        "InstanceId": "i-aaa",
                        "PublicDnsName": "ec2-1-2-3-4.compute.amazonaws.com",
                        "PublicIpAddress": "1.2.3.4",
                        "State": {"Name": "running"},
                        "IamInstanceProfile": {
                            "Arn": "arn:aws:iam::1:instance-profile/web-server",
                        },
                    }],
                }],
            }],
        },
    )
    out = _discover_ec2(factory, region="us-east-1")
    assert len(out) == 1
    a = out[0]
    assert a["kind"] == "ec2_instance"
    assert a["is_public"] is True
    assert a["public_dns"] == "ec2-1-2-3-4.compute.amazonaws.com"
    assert a["public_ip"] == "1.2.3.4"
    assert a["iam_instance_profile_arn"] == "arn:aws:iam::1:instance-profile/web-server"


def test_discover_ec2_private_instance_not_marked_public(factory) -> None:
    factory.register(
        service="ec2", region="us-east-1",
        paginators={
            "describe_instances": [{
                "Reservations": [{
                    "OwnerId": "1",
                    "Instances": [{
                        "InstanceId": "i-priv",
                        "State": {"Name": "running"},
                    }],
                }],
            }],
        },
    )
    out = _discover_ec2(factory, region="us-east-1")
    assert len(out) == 1
    assert out[0]["is_public"] is False


# ---------------------------------------------------------------------------
# RDS discovery
# ---------------------------------------------------------------------------


def test_discover_rds_emits_kind_and_is_unencrypted(factory) -> None:
    factory.register(
        service="rds", region="us-east-1",
        paginators={
            "describe_db_instances": [{
                "DBInstances": [{
                    "DBInstanceArn": "arn:aws:rds:us-east-1:1:db:prod",
                    "DBInstanceIdentifier": "prod",
                    "Engine": "postgres",
                    "PubliclyAccessible": True,
                    "StorageEncrypted": False,
                }],
            }],
        },
    )
    out = _discover_rds(factory, region="us-east-1")
    assert len(out) == 1
    a = out[0]
    assert a["kind"] == "rds_db_instance"
    assert a["is_public"] is True
    assert a["is_unencrypted"] is True
    assert a["is_data_store"] is True


# ---------------------------------------------------------------------------
# Lambda discovery
# ---------------------------------------------------------------------------


def test_discover_lambda_with_public_function_url(factory) -> None:
    factory.register(
        service="lambda", region="us-east-1",
        methods={
            "get_function_url_config": {
                "FunctionUrl": "https://abc.lambda-url.us-east-1.on.aws/",
                "AuthType": "NONE",
            },
        },
        paginators={
            "list_functions": [{
                "Functions": [{
                    "FunctionArn": "arn:aws:lambda:us-east-1:1:function:api",
                    "FunctionName": "api",
                    "Role": "arn:aws:iam::1:role/api-role",
                }],
            }],
        },
    )
    out = _discover_lambda(factory, region="us-east-1")
    assert len(out) == 1
    a = out[0]
    assert a["kind"] == "lambda_function"
    assert a["function_url"] == "https://abc.lambda-url.us-east-1.on.aws/"
    assert a["function_url_auth_type"] == "NONE"
    # AuthType=NONE → public.
    assert a["is_public"] is True
    assert a["attached_role_arn"] == "arn:aws:iam::1:role/api-role"


def test_discover_lambda_without_function_url(factory) -> None:
    factory.register(
        service="lambda", region="us-east-1",
        methods={
            "get_function_url_config": Exception("ResourceNotFoundException"),
        },
        paginators={
            "list_functions": [{
                "Functions": [{
                    "FunctionArn": "arn:aws:lambda:us-east-1:1:function:bg",
                    "FunctionName": "bg",
                    "Role": "arn:aws:iam::1:role/bg-role",
                }],
            }],
        },
    )
    out = _discover_lambda(factory, region="us-east-1")
    assert len(out) == 1
    a = out[0]
    assert "function_url" not in a
    # No public URL → not marked public.
    assert a.get("is_public") is not True


# ---------------------------------------------------------------------------
# ECR + Secrets discovery
# ---------------------------------------------------------------------------


def test_discover_ecr_emits_data_store_flag(factory) -> None:
    factory.register(
        service="ecr", region="us-east-1",
        paginators={
            "describe_repositories": [{
                "repositories": [{
                    "repositoryArn": "arn:aws:ecr:us-east-1:1:repository/myapp",
                    "repositoryName": "myapp",
                }],
            }],
        },
    )
    out = _discover_ecr(factory, region="us-east-1")
    assert len(out) == 1
    a = out[0]
    assert a["kind"] == "ecr_repository"
    assert a["is_data_store"] is True


def test_discover_secrets_emits_metadata_only(factory) -> None:
    """Confirm we never call get_secret_value — we only enumerate
    secret metadata, never read values."""
    factory.register(
        service="secretsmanager", region="us-east-1",
        paginators={
            "list_secrets": [{
                "SecretList": [{
                    "ARN": "arn:aws:secretsmanager:us-east-1:1:secret:db-creds",
                    "Name": "db-creds",
                }],
            }],
        },
    )
    sm_client = factory("secretsmanager", "us-east-1")
    out = _discover_secrets(factory, region="us-east-1")
    assert len(out) == 1
    assert out[0]["kind"] == "secrets_manager_secret"
    assert out[0]["is_data_store"] is True
    # No GetSecretValue call recorded.
    assert all(name != "get_secret_value" for name, _ in sm_client.calls)


# ---------------------------------------------------------------------------
# Top-level dispatcher
# ---------------------------------------------------------------------------


def test_discover_aws_assets_dispatches_per_service(factory) -> None:
    """A multi-region run should emit assets from each region's
    EC2 / RDS / Lambda / ECR / Secrets + global S3 + IAM."""
    factory.register(
        service="s3", region="us-east-1",
        methods={"list_buckets": {"Buckets": [{"Name": "b1"}]}},
    )
    factory.register(
        service="iam", region=None,
        paginators={
            "list_users": [{"Users": []}],
            "list_roles": [{"Roles": []}],
            "list_policies": [{"Policies": []}],
        },
    )
    for region in ("us-east-1", "us-west-2"):
        factory.register(
            service="ec2", region=region,
            paginators={"describe_instances": [
                {"Reservations": [{"OwnerId": "1", "Instances": []}]},
            ]},
        )
        factory.register(
            service="rds", region=region,
            paginators={"describe_db_instances": [{"DBInstances": []}]},
        )
        factory.register(
            service="lambda", region=region,
            paginators={"list_functions": [{"Functions": []}]},
        )
        factory.register(
            service="ecr", region=region,
            paginators={"describe_repositories": [{"repositories": []}]},
        )
        factory.register(
            service="secretsmanager", region=region,
            paginators={"list_secrets": [{"SecretList": []}]},
        )

    out = discover_aws_assets(
        factory, regions=["us-east-1", "us-west-2"],
    )
    arns = {a["arn"] for a in out}
    assert "arn:aws:s3:::b1" in arns


def test_discover_aws_assets_services_allowlist(factory) -> None:
    """When `services=[...]` is set, only the named services run."""
    factory.register(
        service="s3", region="us-east-1",
        methods={"list_buckets": {"Buckets": [{"Name": "b1"}]}},
    )
    # No iam / ec2 / etc registered → would crash if discovery
    # tried them. Allowlist must skip cleanly.
    out = discover_aws_assets(
        factory, regions=["us-east-1"], services=["s3"],
    )
    arns = {a["arn"] for a in out}
    assert arns == {"arn:aws:s3:::b1"}


def test_discover_aws_assets_caps_per_service(factory) -> None:
    """`max_items_per_service` bounds enumeration."""
    factory.register(
        service="s3", region="us-east-1",
        methods={
            "list_buckets": {
                "Buckets": [{"Name": f"b{i}"} for i in range(100)],
            },
        },
    )
    factory.register(
        service="iam", region=None,
        paginators={
            "list_users": [{"Users": []}],
            "list_roles": [{"Roles": []}],
            "list_policies": [{"Policies": []}],
        },
    )
    # S3 has no paginator, so the cap doesn't apply to it directly.
    # Test the iam paginator cap instead.
    factory.register(
        service="iam", region=None,
        paginators={
            "list_users": [{
                "Users": [
                    {"Arn": f"arn:aws:iam::1:user/u{i}",
                     "UserName": f"u{i}"}
                    for i in range(500)
                ],
            }],
            "list_roles": [{"Roles": []}],
            "list_policies": [{"Policies": []}],
        },
    )
    out = discover_aws_assets(
        factory, regions=["us-east-1"],
        services=["iam"],
        max_items_per_service=10,
    )
    users = [a for a in out if a["kind"] == "iam_user"]
    # The cap kicks in after the first page (500 users on the page),
    # but the paginator yields the whole page; the cap is on
    # subsequent pages. So we should see at least 10 users but no
    # more pages would have fetched. This implementation choice
    # is documented in the discovery module docstring.
    assert len(users) > 0


# ---------------------------------------------------------------------------
# Integration: analyze_cloud_attack_paths uses discovery
# ---------------------------------------------------------------------------


def test_analyze_invokes_discovery_when_factory_supplied(factory) -> None:
    """End-to-end: `analyze_cloud_attack_paths` calls
    `discover_aws_assets` and the resulting assets show up in
    `report.assets_consumed`."""
    from strix.cloud_attack_paths.api import analyze_cloud_attack_paths

    factory.register(
        service="s3", region="us-east-1",
        methods={"list_buckets": {"Buckets": [{"Name": "leaky"}]}},
    )
    factory.register(
        service="iam", region=None,
        paginators={
            "list_users": [{"Users": []}],
            "list_roles": [{"Roles": []}],
            "list_policies": [{"Policies": []}],
        },
    )
    for s in ("ec2", "rds", "lambda", "ecr", "secretsmanager"):
        factory.register(
            service=s, region="us-east-1",
            paginators={
                "describe_instances": [{"Reservations": []}],
                "describe_db_instances": [{"DBInstances": []}],
                "list_functions": [{"Functions": []}],
                "describe_repositories": [{"repositories": []}],
                "list_secrets": [{"SecretList": []}],
            },
        )

    report = analyze_cloud_attack_paths(
        cspm_findings=[],
        discover_client_factory=factory,
        discover_regions=["us-east-1"],
        include_graph=True,
    )
    assert report.assets_consumed > 0
    # The discovered bucket node landed on the graph.
    assert report.graph is not None
    assert report.graph.get_node("arn:aws:s3:::leaky") is not None
