"""VPC posture checks."""

from __future__ import annotations

from strix.cspm.aws import CspmFinding, register_check


@register_check(service="ec2", scope="regional")
def vpc_flow_logs_disabled(client_factory, region: str | None):
    """CIS AWS Foundations 3.9 (live) — every VPC should have
    flow logs enabled. Without them, network-level incident
    response is blind."""
    if not region:
        return []
    ec2 = client_factory("ec2", region=region)
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
    except Exception:  # noqa: BLE001
        return []
    if not vpcs:
        return []
    # Get all flow logs in this region; bucket the resource IDs they cover.
    try:
        flow_logs_resp = ec2.describe_flow_logs()
        covered = {
            fl.get("ResourceId")
            for fl in flow_logs_resp.get("FlowLogs", [])
            if fl.get("FlowLogStatus") == "ACTIVE"
        }
    except Exception:  # noqa: BLE001
        covered = set()
    out: list[CspmFinding] = []
    for vpc in vpcs:
        vpc_id = vpc.get("VpcId", "")
        if vpc_id in covered:
            continue
        out.append(CspmFinding(
            rule_id="AWS_VPC_FLOW_LOGS_DISABLED",
            severity="medium",
            message=(
                f"VPC `{vpc_id}` has no active flow logs. "
                f"Network-level incident response is blind for "
                f"this VPC."
            ),
            service="ec2",
            region=region,
            resource_arn=f"arn:aws:ec2:{region}:*:vpc/{vpc_id}",
            cwe="CWE-778",
            category="misconfig",
            metadata={"vpc_id": vpc_id},
        ))
    return out
