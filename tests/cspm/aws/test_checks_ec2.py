"""Tests for EC2 / Security Group + EBS + VPC checks."""

from __future__ import annotations

from strix.cspm.aws.checks.ebs import ebs_encryption_by_default_disabled
from strix.cspm.aws.checks.ec2 import ec2_sg_open_ingress_admin_port
from strix.cspm.aws.checks.vpc import vpc_flow_logs_disabled


def _sg_page(*sgs):
    return {"SecurityGroups": list(sgs)}


def test_sg_open_ssh_critical(fake_factory) -> None:
    fake_factory.register(
        service="ec2", region="us-east-1",
        paginators={
            "describe_security_groups": [_sg_page({
                "GroupId": "sg-aaa",
                "GroupName": "web",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            })],
        },
    )
    out = ec2_sg_open_ingress_admin_port(fake_factory, "us-east-1")
    assert len(out) == 1
    f = out[0]
    assert f.rule_id == "AWS_SG_OPEN_INGRESS_ADMIN"
    assert f.severity == "critical"
    assert 22 in f.metadata["exposed_admin_ports"]


def test_sg_open_world_non_admin_high_not_critical(fake_factory) -> None:
    """World-open on port 8080 = high, not critical. Distinction
    matters for triage."""
    fake_factory.register(
        service="ec2", region="us-east-1",
        paginators={
            "describe_security_groups": [_sg_page({
                "GroupId": "sg-bbb",
                "GroupName": "api",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            })],
        },
    )
    out = ec2_sg_open_ingress_admin_port(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].rule_id == "AWS_SG_OPEN_INGRESS_WORLD"
    assert out[0].severity == "high"


def test_sg_all_protocols_world_treated_as_admin_exposed(fake_factory) -> None:
    """`IpProtocol=-1` covers every port — admin ports are by
    definition exposed."""
    fake_factory.register(
        service="ec2", region="us-east-1",
        paginators={
            "describe_security_groups": [_sg_page({
                "GroupId": "sg-ccc",
                "GroupName": "permissive",
                "IpPermissions": [{
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            })],
        },
    )
    out = ec2_sg_open_ingress_admin_port(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].rule_id == "AWS_SG_OPEN_INGRESS_ADMIN"


def test_sg_restricted_cidr_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="ec2", region="us-east-1",
        paginators={
            "describe_security_groups": [_sg_page({
                "GroupId": "sg-ddd",
                "GroupName": "bastion-only",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                    "Ipv6Ranges": [],
                }],
            })],
        },
    )
    assert ec2_sg_open_ingress_admin_port(fake_factory, "us-east-1") == []


def test_sg_ipv6_world_open_detected(fake_factory) -> None:
    """`::/0` is the IPv6 equivalent of `0.0.0.0/0`."""
    fake_factory.register(
        service="ec2", region="us-east-1",
        paginators={
            "describe_security_groups": [_sg_page({
                "GroupId": "sg-eee",
                "GroupName": "v6",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }],
            })],
        },
    )
    out = ec2_sg_open_ingress_admin_port(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].metadata["ipv6_open"] is True


def test_ebs_encryption_disabled_detected(fake_factory) -> None:
    fake_factory.register(
        service="ec2", region="us-east-1",
        methods={"get_ebs_encryption_by_default": {
            "EbsEncryptionByDefault": False,
        }},
    )
    out = ebs_encryption_by_default_disabled(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].rule_id == "AWS_EBS_ENCRYPTION_BY_DEFAULT_DISABLED"


def test_ebs_encryption_enabled_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="ec2", region="us-east-1",
        methods={"get_ebs_encryption_by_default": {
            "EbsEncryptionByDefault": True,
        }},
    )
    assert ebs_encryption_by_default_disabled(fake_factory, "us-east-1") == []


def test_vpc_without_flow_logs_detected(fake_factory) -> None:
    fake_factory.register(
        service="ec2", region="us-east-1",
        methods={
            "describe_vpcs": {"Vpcs": [{"VpcId": "vpc-aaa"}]},
            "describe_flow_logs": {"FlowLogs": []},
        },
    )
    out = vpc_flow_logs_disabled(fake_factory, "us-east-1")
    assert len(out) == 1
    assert out[0].rule_id == "AWS_VPC_FLOW_LOGS_DISABLED"


def test_vpc_with_active_flow_logs_not_flagged(fake_factory) -> None:
    fake_factory.register(
        service="ec2", region="us-east-1",
        methods={
            "describe_vpcs": {"Vpcs": [{"VpcId": "vpc-aaa"}]},
            "describe_flow_logs": {"FlowLogs": [{
                "ResourceId": "vpc-aaa",
                "FlowLogStatus": "ACTIVE",
            }]},
        },
    )
    assert vpc_flow_logs_disabled(fake_factory, "us-east-1") == []


def test_vpc_with_inactive_flow_logs_still_flagged(fake_factory) -> None:
    """A flow log in `STARTING` / `STOPPING` state doesn't count as
    coverage — we want ACTIVE only."""
    fake_factory.register(
        service="ec2", region="us-east-1",
        methods={
            "describe_vpcs": {"Vpcs": [{"VpcId": "vpc-aaa"}]},
            "describe_flow_logs": {"FlowLogs": [{
                "ResourceId": "vpc-aaa",
                "FlowLogStatus": "STOPPING",
            }]},
        },
    )
    out = vpc_flow_logs_disabled(fake_factory, "us-east-1")
    assert len(out) == 1


def test_no_vpcs_no_findings(fake_factory) -> None:
    fake_factory.register(
        service="ec2", region="us-east-1",
        methods={"describe_vpcs": {"Vpcs": []}},
    )
    assert vpc_flow_logs_disabled(fake_factory, "us-east-1") == []
