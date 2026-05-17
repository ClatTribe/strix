"""AWS CSPM scanner entry point.

Top-level interface:

    report = scan_aws_account(
        regions=["us-east-1", "us-west-2"],
        profile_name=None,
        role_arn=None,
    )

Returns an `AwsCspmReport` mirroring `IacReport` (shape stable
so wrappers consume one common Report API across IaC + CSPM).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from strix.cspm.aws import CspmFinding, run_checks
from strix.cspm.aws.client import (
    discover_regions,
    get_caller_account_id,
    make_default_client_factory,
)


logger = logging.getLogger(__name__)


@dataclass
class AwsCspmReport:
    account_id: str | None
    regions_scanned: list[str]
    findings: list[CspmFinding] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings
                   if (f.severity or "").lower() == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings
                   if (f.severity or "").lower() == "high")

    @property
    def findings_by_service(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.service] = out.get(f.service, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "regions_scanned": list(self.regions_scanned),
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "findings_by_service": self.findings_by_service,
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }


def scan_aws_account(
    *,
    regions: list[str] | None = None,
    profile_name: str | None = None,
    role_arn: str | None = None,
    client_factory=None,
) -> AwsCspmReport:
    """Run every registered CSPM check against an AWS account.

    Args:
        regions: list of region names to scan. None → auto-
            discover via `ec2:DescribeRegions`, falling back to a
            commercial-partition default set.
        profile_name: named AWS profile (default: standard
            boto3 credential chain).
        role_arn: optional cross-account role to assume before
            scanning.
        client_factory: dependency injection for tests. Production
            callers leave this None and the function builds the
            default boto3-backed factory.

    Returns:
        `AwsCspmReport` with per-finding records, account ID,
        regions scanned, and per-check errors.
    """
    factory = client_factory or make_default_client_factory(
        profile_name=profile_name, role_arn=role_arn,
    )

    account_id = get_caller_account_id(factory)
    if regions is None:
        regions = discover_regions(factory)

    findings, errors = run_checks(factory, regions=regions)

    # Stamp account_id on every finding for downstream rendering.
    if account_id:
        for f in findings:
            if not f.account_id:
                f.account_id = account_id

    # Severity-descending sort so the highest-priority items
    # surface first.
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(key=lambda f: -sev_rank.get((f.severity or "").lower(), 0))

    return AwsCspmReport(
        account_id=account_id,
        regions_scanned=list(regions),
        findings=findings,
        errors=errors,
    )
