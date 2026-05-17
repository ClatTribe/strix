"""Boto3 client factory with read-only safety guards.

`make_default_client_factory()` returns a callable
`(service, region) -> boto3 client` that:
  * Uses boto3's standard credential chain (env / profile / IAM
    role / IRSA).
  * Pins a sane default region per call.
  * Lazily imports boto3 so the rest of strix stays usable
    without AWS deps.

We do NOT install a botocore event hook to block Put*/Delete*/
Update* calls — those would defend against a bug in our check
code but mid-size customers should anchor on a least-privilege
read-only role (`SecurityAudit` AWS managed policy is the canonical
choice). The library docs make this contract explicit.
"""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


def _require_boto3():
    """Import boto3 lazily so the rest of strix doesn't break
    when AWS extras aren't installed."""
    try:
        import boto3  # noqa: PLC0415
        return boto3
    except ImportError as e:
        raise ImportError(
            "boto3 is required for CSPM AWS scanning. Install "
            "via `pip install strix-agent[aws]` or `pip install "
            "boto3`."
        ) from e


def make_default_client_factory(
    *,
    profile_name: str | None = None,
    role_arn: str | None = None,
) -> Any:
    """Return a `(service, region)` callable that uses boto3's
    standard credential chain.

    Args:
        profile_name: optional named profile from
            `~/.aws/credentials`. None → default credential chain.
        role_arn: when set, assume the role before creating
            service clients. Use this for cross-account scanning.

    Production deployment: leave both None and use an IAM role
    on the runner instance (EC2 instance profile / IRSA /
    Lambda role).
    """
    boto3 = _require_boto3()

    if role_arn:
        # Assume the role once, return short-lived credentials.
        # 1 hour is plenty for a full account scan and matches
        # what most security-audit roles allow as a max session.
        session_kwargs: dict[str, Any] = {}
        if profile_name:
            session_kwargs["profile_name"] = profile_name
        sts = boto3.session.Session(**session_kwargs).client("sts")
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="strix-cspm-scan",
        )["Credentials"]

        def _factory(service: str, region: str | None = None) -> Any:
            return boto3.client(
                service,
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )

        return _factory

    session_kwargs: dict[str, Any] = {}
    if profile_name:
        session_kwargs["profile_name"] = profile_name
    session = boto3.session.Session(**session_kwargs)

    def _factory(service: str, region: str | None = None) -> Any:
        return session.client(service, region_name=region)

    return _factory


def discover_regions(client_factory: Any) -> list[str]:
    """List every enabled region in the account via `ec2:DescribeRegions`.

    The IAM role used to scan needs at least `ec2:DescribeRegions`.
    On failure, returns the AWS-published default set so the scan
    still produces *some* output — better partial coverage than
    none.
    """
    try:
        client = client_factory("ec2", region="us-east-1")
        resp = client.describe_regions(AllRegions=False)
        out = sorted(r["RegionName"] for r in resp.get("Regions", []))
        if out:
            return out
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "cspm/aws: discover_regions failed (%s), falling back "
            "to default set", e, exc_info=True,
        )

    # Fallback: AWS commercial-partition defaults.
    return [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-central-1",
        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    ]


def get_caller_account_id(client_factory: Any) -> str | None:
    """Return the account ID via `sts:GetCallerIdentity`. None on
    failure — caller decides whether that's fatal."""
    try:
        sts = client_factory("sts", region="us-east-1")
        return sts.get_caller_identity()["Account"]
    except Exception as e:  # noqa: BLE001
        logger.debug("cspm/aws: get_caller_account_id failed: %s", e)
        return None
