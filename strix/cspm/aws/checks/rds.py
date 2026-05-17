"""RDS posture checks."""

from __future__ import annotations

from strix.cspm.aws import CspmFinding, register_check


@register_check(service="rds", scope="regional")
def rds_instance_publicly_accessible(client_factory, region: str | None):
    """RDS instance with `PubliclyAccessible=True` — DB endpoint
    is resolvable from the public internet, attack surface is
    a security-group-only barrier."""
    if not region:
        return []
    rds = client_factory("rds", region=region)
    out: list[CspmFinding] = []
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page.get("DBInstances", []):
            if not db.get("PubliclyAccessible"):
                continue
            arn = db.get("DBInstanceArn") or (
                f"arn:aws:rds:{region}:*:db:{db.get('DBInstanceIdentifier')}"
            )
            out.append(CspmFinding(
                rule_id="AWS_RDS_PUBLIC_ACCESS",
                severity="critical",
                message=(
                    f"RDS instance `{db.get('DBInstanceIdentifier')}` "
                    f"({db.get('Engine')}) is marked publicly "
                    f"accessible. DB endpoint resolves from the "
                    f"public internet — only the SG stops access."
                ),
                service="rds",
                region=region,
                resource_arn=arn,
                cwe="CWE-200",
                category="misconfig",
                metadata={
                    "engine": db.get("Engine"),
                    "instance_id": db.get("DBInstanceIdentifier"),
                },
            ))
    return out


@register_check(service="rds", scope="regional")
def rds_instance_unencrypted(client_factory, region: str | None):
    """CIS AWS Foundations 2.3.1 (live) — RDS storage not
    encrypted at rest."""
    if not region:
        return []
    rds = client_factory("rds", region=region)
    out: list[CspmFinding] = []
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page.get("DBInstances", []):
            if db.get("StorageEncrypted"):
                continue
            arn = db.get("DBInstanceArn") or (
                f"arn:aws:rds:{region}:*:db:{db.get('DBInstanceIdentifier')}"
            )
            out.append(CspmFinding(
                rule_id="AWS_RDS_NO_ENCRYPTION",
                severity="high",
                message=(
                    f"RDS instance `{db.get('DBInstanceIdentifier')}` "
                    f"({db.get('Engine')}) has unencrypted storage "
                    f"at rest. Snapshots inherit the unencrypted "
                    f"state — backup-bucket compromise → data loss."
                ),
                service="rds",
                region=region,
                resource_arn=arn,
                cwe="CWE-311",
                category="misconfig",
                metadata={
                    "engine": db.get("Engine"),
                    "instance_id": db.get("DBInstanceIdentifier"),
                },
            ))
    return out
