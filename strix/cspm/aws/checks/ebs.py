"""EBS posture checks."""

from __future__ import annotations

from strix.cspm.aws import CspmFinding, register_check


@register_check(service="ec2", scope="regional")
def ebs_encryption_by_default_disabled(client_factory, region: str | None):
    """CIS AWS Foundations 2.2.1 (live) — EBS account-level
    encryption-by-default is OFF for this region. Any new volume
    or snapshot created without an explicit `Encrypted=true` lands
    in clear."""
    if not region:
        return []
    ec2 = client_factory("ec2", region=region)
    try:
        resp = ec2.get_ebs_encryption_by_default()
    except Exception:  # noqa: BLE001
        return []
    if resp.get("EbsEncryptionByDefault"):
        return []
    return [CspmFinding(
        rule_id="AWS_EBS_ENCRYPTION_BY_DEFAULT_DISABLED",
        severity="high",
        message=(
            f"EBS encryption-by-default is disabled in `{region}`. "
            f"New volumes / snapshots without explicit "
            f"`Encrypted=true` land unencrypted."
        ),
        service="ec2",
        region=region,
        resource_arn=f"arn:aws:ec2:{region}:*:ebs-encryption-default",
        cwe="CWE-311",
        category="misconfig",
        metadata={"region": region},
    )]
