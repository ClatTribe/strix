"""S3 bucket posture checks.

Note: `s3:ListAllMyBuckets` returns buckets globally regardless
of region — but per-bucket operations need to target the bucket's
home region. We dispatch from `us-east-1` (the global service
endpoint) and re-bind to the bucket's region only when the per-
bucket API rejects the global client. Most read-only S3 APIs
work fine against any region's endpoint though.

To avoid duplicate work (every region re-listing every bucket),
the S3 checks run only in `us-east-1` and skip other regions.
The `scope=regional` decorator still applies — `region` arrives
non-None — and we early-return when it isn't `us-east-1`.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.cspm.aws import CspmFinding, register_check


logger = logging.getLogger(__name__)


_S3_GLOBAL_GROUPS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def _list_buckets(s3) -> list[dict[str, Any]]:
    return s3.list_buckets().get("Buckets", []) or []


def _bucket_is_public_via_acl(s3, bucket_name: str) -> tuple[bool, list[str]]:
    """Return (is_public, grantee_uris)."""
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
    except Exception:  # noqa: BLE001
        return False, []
    public_uris: list[str] = []
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {}) or {}
        uri = grantee.get("URI", "")
        if uri in _S3_GLOBAL_GROUPS:
            public_uris.append(uri)
    return bool(public_uris), public_uris


@register_check(service="s3", scope="regional")
def s3_bucket_public_acl(client_factory, region: str | None):
    """CIS AWS Foundations 2.1.5 (live) — bucket has an ACL grant
    to AllUsers / AuthenticatedUsers."""
    if region != "us-east-1":
        return []
    s3 = client_factory("s3", region=region)
    out: list[CspmFinding] = []
    for b in _list_buckets(s3):
        name = b.get("Name", "")
        is_pub, uris = _bucket_is_public_via_acl(s3, name)
        if is_pub:
            out.append(CspmFinding(
                rule_id="AWS_S3_PUBLIC_ACL",
                severity="critical",
                message=(
                    f"S3 bucket `{name}` ACL grants access to "
                    f"{', '.join(uri.rsplit('/', 1)[-1] for uri in uris)} "
                    f"— bucket is publicly accessible."
                ),
                service="s3",
                region=None,           # S3 buckets are global
                resource_arn=f"arn:aws:s3:::{name}",
                cwe="CWE-732",
                category="misconfig",
                metadata={"grantee_uris": uris},
            ))
    return out


@register_check(service="s3", scope="regional")
def s3_bucket_versioning_disabled(client_factory, region: str | None):
    """CIS AWS Foundations 2.1.7 (live) — bucket has versioning
    disabled or never enabled. Without versioning, an accidental /
    malicious delete is unrecoverable."""
    if region != "us-east-1":
        return []
    s3 = client_factory("s3", region=region)
    out: list[CspmFinding] = []
    for b in _list_buckets(s3):
        name = b.get("Name", "")
        try:
            v = s3.get_bucket_versioning(Bucket=name)
        except Exception:  # noqa: BLE001
            continue
        status = (v.get("Status") or "").lower()
        # Boto returns:
        #   missing key OR "" → never enabled
        #   "enabled" / "suspended"
        if status != "enabled":
            out.append(CspmFinding(
                rule_id="AWS_S3_VERSIONING_DISABLED",
                severity="medium",
                message=(
                    f"S3 bucket `{name}` does not have versioning "
                    f"enabled (status: `{status or 'never enabled'}`)."
                ),
                service="s3",
                region=None,
                resource_arn=f"arn:aws:s3:::{name}",
                cwe="CWE-693",
                category="misconfig",
                metadata={"status": status or "never_enabled"},
            ))
    return out


@register_check(service="s3", scope="regional")
def s3_bucket_no_default_encryption(client_factory, region: str | None):
    """CIS AWS Foundations 2.1.1 (live) — bucket has no
    default-encryption config. New objects land in clear."""
    if region != "us-east-1":
        return []
    s3 = client_factory("s3", region=region)
    out: list[CspmFinding] = []
    for b in _list_buckets(s3):
        name = b.get("Name", "")
        try:
            s3.get_bucket_encryption(Bucket=name)
            # 200 → encryption is set; nothing to do.
        except Exception as e:  # noqa: BLE001
            # botocore raises ClientError('ServerSideEncryptionConfigurationNotFoundError')
            # when the bucket has no default encryption. We can't
            # type-narrow without importing botocore, so we string-
            # match — the wording is stable across botocore versions.
            msg = str(e)
            if "ServerSideEncryptionConfigurationNotFoundError" in msg:
                out.append(CspmFinding(
                    rule_id="AWS_S3_NO_DEFAULT_ENCRYPTION",
                    severity="high",
                    message=(
                        f"S3 bucket `{name}` has no default "
                        f"encryption configured — new objects "
                        f"land in clear."
                    ),
                    service="s3",
                    region=None,
                    resource_arn=f"arn:aws:s3:::{name}",
                    cwe="CWE-311",
                    category="misconfig",
                ))
            # Other errors (AccessDenied) are surfaced by the
            # outer try/except in run_checks.
    return out
