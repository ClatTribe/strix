"""EC2 / Security Group posture checks."""

from __future__ import annotations

from typing import Any

from strix.cspm.aws import CspmFinding, register_check


# Admin-class ports that should NEVER be exposed to 0.0.0.0/0.
# Critical-severity. Other open ports get high.
_ADMIN_PORTS = {22, 3389, 23, 5985, 5986, 3306, 5432, 1433, 27017, 6379}


def _ingress_rule_covers_port(rule: dict[str, Any], port: int) -> bool:
    """`-1` (all protocols) covers everything. Otherwise port must
    fall in [FromPort, ToPort]."""
    if rule.get("IpProtocol") == "-1":
        return True
    fp = rule.get("FromPort")
    tp = rule.get("ToPort")
    return fp is not None and tp is not None and fp <= port <= tp


@register_check(service="ec2", scope="regional")
def ec2_sg_open_ingress_admin_port(client_factory, region: str | None):
    """CIS AWS Foundations 5.2 (live) — SG with 0.0.0.0/0 ingress
    to a remote-admin port."""
    if not region:
        return []
    ec2 = client_factory("ec2", region=region)
    paginator = ec2.get_paginator("describe_security_groups")
    out: list[CspmFinding] = []
    for page in paginator.paginate():
        for sg in page.get("SecurityGroups", []):
            sg_id = sg.get("GroupId", "")
            sg_name = sg.get("GroupName", "")
            for rule in sg.get("IpPermissions", []):
                ipv4 = [
                    r.get("CidrIp") for r in rule.get("IpRanges", [])
                ]
                ipv6 = [
                    r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])
                ]
                world_v4 = "0.0.0.0/0" in ipv4
                world_v6 = "::/0" in ipv6
                if not (world_v4 or world_v6):
                    continue
                # Which admin ports does this rule cover?
                exposed = sorted(
                    p for p in _ADMIN_PORTS
                    if _ingress_rule_covers_port(rule, p)
                )
                if not exposed:
                    # World-open but on non-admin ports — still
                    # noteworthy, surface as high not critical.
                    out.append(CspmFinding(
                        rule_id="AWS_SG_OPEN_INGRESS_WORLD",
                        severity="high",
                        message=(
                            f"Security group `{sg_id}` ({sg_name}) "
                            f"allows ingress from the public internet "
                            f"on a non-admin port range "
                            f"({rule.get('FromPort')}-"
                            f"{rule.get('ToPort')}, proto="
                            f"{rule.get('IpProtocol')})."
                        ),
                        service="ec2",
                        region=region,
                        resource_arn=(
                            f"arn:aws:ec2:{region}:*:security-group/{sg_id}"
                        ),
                        cwe="CWE-284",
                        category="misconfig",
                        metadata={
                            "from_port": rule.get("FromPort"),
                            "to_port": rule.get("ToPort"),
                            "protocol": rule.get("IpProtocol"),
                            "ipv4_open": world_v4,
                            "ipv6_open": world_v6,
                        },
                    ))
                else:
                    out.append(CspmFinding(
                        rule_id="AWS_SG_OPEN_INGRESS_ADMIN",
                        severity="critical",
                        message=(
                            f"Security group `{sg_id}` ({sg_name}) "
                            f"allows ingress from the public internet "
                            f"to admin port(s) "
                            f"{', '.join(map(str, exposed))}."
                        ),
                        service="ec2",
                        region=region,
                        resource_arn=(
                            f"arn:aws:ec2:{region}:*:security-group/{sg_id}"
                        ),
                        cwe="CWE-284",
                        category="misconfig",
                        metadata={
                            "exposed_admin_ports": exposed,
                            "ipv4_open": world_v4,
                            "ipv6_open": world_v6,
                        },
                    ))
    return out
