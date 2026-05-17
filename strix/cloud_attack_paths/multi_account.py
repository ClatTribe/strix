"""Multi-account AWS scanner — fan out across an AWS Organization
via assume-role chains, union the findings + assets, build one
attack-path graph spanning the org.

masterroadmap §5 P1 — closes "multi-account / organisation-wide
traversal." Single-account scanning is the right MVP; real-world
production cloud footprints are 5-50 accounts (dev / staging /
prod / per-team / per-service / etc.) and attackers don't respect
account boundaries.

## How an attacker actually chains across accounts

  * Account A's IAM role has `Principal: {"AWS":
    "arn:aws:iam::B:root"}` in its trust policy — anyone in
    account B can call `sts:AssumeRole` on the role in account A.
  * Account B's user has a policy that grants `sts:AssumeRole`
    on the cross-account role.
  * Single-account graph of A doesn't see this; you need both
    A's roles AND B's identities + policies in one graph for the
    `cap_can_assume_chain_to_admin` pattern to traverse the
    cross-account edge.

## What this module does

  1. Accept a list of `role_arns` (one per target account).
  2. For each, build a boto3 client factory that assumes the
     role + run the per-account CSPM scan + asset discovery.
  3. Return the union of findings + assets as one list, ready
     for `analyze_cloud_attack_paths(cspm_findings=...,
     cloud_assets=...)`.

The unified graph automatically gets cross-account edges
because trust policies from each account's roles + policies
from each account's IAM principals end up as nodes in the same
graph. The `can_assume` edge derivation in `ingest.py` then
joins them.

## What this does NOT do

  * **AWS Organizations API enumeration** — caller supplies the
    explicit list of role ARNs. We don't call
    `organizations:ListAccounts` because that requires either
    being in the management account OR delegated admin, which
    is engagement-specific. Future PR can add it as an optional
    convenience.
  * **Parallel scanning** — accounts are scanned sequentially in
    v1. Fine for tens of accounts; future PR can add bounded
    concurrency for orgs at 100+ accounts.
  * **GCP / Azure multi-tenant** — AWS-specific in v1; multi-cloud
    fan-out is a follow-up.

## Safety contract

Per-account errors don't stop the whole fan-out. A denied
`sts:AssumeRole` on one role ARN doesn't blank the rest of the
org — partial results are emitted. Same read-only contract as
the single-account scanner.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from strix.cspm.aws import CspmFinding


logger = logging.getLogger(__name__)


@dataclass
class AccountScanResult:
    """Per-account result inside a multi-account run."""
    role_arn: str
    account_id: str | None = None
    findings: list[CspmFinding] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role_arn": self.role_arn,
            "account_id": self.account_id,
            "findings_count": len(self.findings),
            "assets_count": len(self.assets),
            "errors": list(self.errors),
        }


def enumerate_org_accounts(
    *,
    profile_name: str | None = None,
    role_arn: str | None = None,
    role_name_template: str = "OrganizationAccountAccessRole",
    _make_factory: Any | None = None,
) -> list[str]:
    """Enumerate AWS Organization member accounts and synthesise
    the standard cross-account role ARN for each.

    Args:
        profile_name: AWS profile to source the management-account
            credentials from.
        role_arn: optional cross-account role to assume into the
            management account before calling
            `organizations:ListAccounts`.
        role_name_template: the role NAME (not full ARN) strix
            should target in each member account. Default
            `OrganizationAccountAccessRole` is the AWS-default
            role auto-created when accounts are added to an
            organization.
        _make_factory: DI hook for tests.

    Returns:
        List of role ARNs (one per active member account), shaped
        as `arn:aws:iam::<account-id>:role/<role_name_template>`.
        Suspended accounts are skipped.

    Per-call errors (org permission denied / not a management
    account) return an empty list with a logged warning rather
    than raising. Caller can fall back to explicit role-arn list.
    """
    if _make_factory is None:
        from strix.cspm.aws.client import (  # noqa: PLC0415
            make_default_client_factory,
        )
        _make_factory = make_default_client_factory

    try:
        factory = _make_factory(
            profile_name=profile_name, role_arn=role_arn,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "enumerate_org_accounts: factory build failed: %s", e,
            exc_info=True,
        )
        return []

    try:
        org = factory("organizations", region="us-east-1")
        paginator = org.get_paginator("list_accounts")
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "enumerate_org_accounts: organizations client / "
            "paginator unavailable: %s", e,
        )
        return []

    role_arns: list[str] = []
    try:
        for page in paginator.paginate():
            for account in (page.get("Accounts") or []):
                if (account.get("Status") or "").upper() != "ACTIVE":
                    continue
                account_id = account.get("Id")
                if not account_id:
                    continue
                role_arns.append(
                    f"arn:aws:iam::{account_id}:role/{role_name_template}"
                )
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "enumerate_org_accounts: ListAccounts paginate failed: %s",
            e, exc_info=True,
        )
    return role_arns


def scan_multi_account(
    role_arns: list[str],
    *,
    profile_name: str | None = None,
    regions: list[str] | None = None,
    services: list[str] | None = None,
    # Dependency-injection hooks for tests.
    _make_factory: Any | None = None,
    _scan_aws_account: Any | None = None,
    _discover_aws_assets: Any | None = None,
    _get_caller_account_id: Any | None = None,
) -> list[AccountScanResult]:
    """Fan out CSPM + asset discovery across multiple AWS accounts.

    Args:
        role_arns: cross-account roles to assume. Each is scanned
            independently; per-role errors don't stop the rest.
        profile_name: base AWS profile name (used to source the
            initial credentials before each assume-role).
        regions: regions to enumerate per-region services in.
        services: optional allow-list of services to discover.
        _make_factory / _scan_aws_account / _discover_aws_assets /
            _get_caller_account_id: DI hooks for tests. None →
            real implementations imported lazily.

    Returns:
        One `AccountScanResult` per role_arn (in input order).
        On per-role failure: `findings` / `assets` empty;
        `errors` carries the diagnosis.
    """
    if not role_arns:
        return []

    # Resolve real implementations lazily so the module imports
    # without boto3 installed (tests can DI before that path).
    if _make_factory is None:
        from strix.cspm.aws.client import (  # noqa: PLC0415
            make_default_client_factory,
        )
        _make_factory = make_default_client_factory
    if _scan_aws_account is None:
        from strix.cspm.aws.scanner import (  # noqa: PLC0415
            scan_aws_account,
        )
        _scan_aws_account = scan_aws_account
    if _discover_aws_assets is None:
        from strix.cloud_attack_paths.discovery import (  # noqa: PLC0415
            discover_aws_assets,
        )
        _discover_aws_assets = discover_aws_assets
    if _get_caller_account_id is None:
        from strix.cspm.aws.client import (  # noqa: PLC0415
            get_caller_account_id,
        )
        _get_caller_account_id = get_caller_account_id

    results: list[AccountScanResult] = []
    for arn in role_arns:
        result = AccountScanResult(role_arn=arn)
        try:
            factory = _make_factory(
                profile_name=profile_name, role_arn=arn,
            )
        except Exception as e:  # noqa: BLE001
            result.errors.append({
                "role_arn": arn,
                "stage": "assume_role",
                "error": f"{type(e).__name__}: {e}",
            })
            results.append(result)
            logger.warning(
                "multi_account: assume-role %s failed: %s",
                arn, e, exc_info=True,
            )
            continue

        # Resolve account ID — useful for downstream cross-
        # account attribution.
        try:
            result.account_id = _get_caller_account_id(factory)
        except Exception:  # noqa: BLE001
            pass

        # CSPM scan.
        try:
            report = _scan_aws_account(
                regions=regions,
                client_factory=factory,
            )
            result.findings.extend(report.findings)
            for e in report.errors:
                result.errors.append({"stage": "cspm", **e})
        except Exception as e:  # noqa: BLE001
            result.errors.append({
                "stage": "cspm",
                "error": f"{type(e).__name__}: {e}",
            })

        # Asset discovery.
        try:
            assets = _discover_aws_assets(
                factory, regions=regions, services=services,
            )
            result.assets.extend(assets)
        except Exception as e:  # noqa: BLE001
            result.errors.append({
                "stage": "discovery",
                "error": f"{type(e).__name__}: {e}",
            })

        results.append(result)

    return results


def union_findings(
    results: list[AccountScanResult],
) -> list[CspmFinding]:
    """Concat every account's findings into one flat list ready
    for `analyze_cloud_attack_paths`."""
    out: list[CspmFinding] = []
    for r in results:
        out.extend(r.findings)
    return out


def union_assets(
    results: list[AccountScanResult],
) -> list[dict[str, Any]]:
    """Concat every account's assets. Cross-account `can_assume`
    edges materialise automatically in `build_graph_from_cspm`
    when one account's policy statements reference another
    account's role ARNs."""
    out: list[dict[str, Any]] = []
    for r in results:
        out.extend(r.assets)
    return out


def summarise(results: list[AccountScanResult]) -> dict[str, Any]:
    """Aggregate summary for tool_metadata."""
    return {
        "accounts_scanned": len(results),
        "accounts_succeeded": sum(
            1 for r in results
            if not any(e.get("stage") == "assume_role" for e in r.errors)
        ),
        "accounts_failed_assume_role": sum(
            1 for r in results
            if any(e.get("stage") == "assume_role" for e in r.errors)
        ),
        "total_findings": sum(len(r.findings) for r in results),
        "total_assets": sum(len(r.assets) for r in results),
        "per_account": [r.to_dict() for r in results],
    }
