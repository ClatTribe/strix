"""AWS CSPM — live-account read-only posture scanner.

Mirrors `strix/iac/rules/` shape:
  * `CspmFinding` dataclass (parallels `IacFinding`)
  * `@register_check(service=...)` decorator (parallels
    `@register_rule(platform=...)`)
  * `run_checks(client_factory, regions)` runs every registered
    check, returns a flat list of findings.

Why the parallel: the compliance pipeline reads `rule_id` /
`cwe` / `category` from finding-shaped dicts. Keeping the same
shape means CSPM findings flow through the existing CIS AWS
Foundations control mapping (`RULE_ID_TO_CONTROLS`) without
any per-source wiring.

Auth model:
  * `client_factory` is a callable `(service_name, region) ->
    boto3 client`. Default uses boto3's standard credential chain
    (env vars → ~/.aws/credentials → instance profile / IRSA).
  * Tests inject a fake factory that returns canned-response
    stub clients — hermetic, no AWS account needed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


logger = logging.getLogger(__name__)


# AWS service identifier (matches the boto3 service name —
# `s3`, `ec2`, `iam`, `rds`, `cloudtrail`).
ServiceName = str

# Where a check runs.
#   `global` — IAM, account-level — region is always None.
#   `regional` — runs once per region in the scan set.
CheckScope = str  # "global" | "regional"


@dataclass
class CspmFinding:
    """One live-cloud posture finding.

    Mirrors `IacFinding` but with cloud-native location fields
    (account_id + region + resource_arn) instead of file/line.

    `to_iac_compatible_dict()` reshapes to the IacFinding dict
    shape so the existing IaC → tracer emit path (and downstream
    compliance enrichment) handles CSPM findings without changes.
    """
    rule_id: str
    severity: str          # info | low | medium | high | critical
    message: str
    service: ServiceName
    region: str | None     # None for global services (IAM)
    resource_arn: str      # ARN or pseudo-ARN identifying the resource
    account_id: str | None = None
    cwe: str | None = None
    category: str | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "service": self.service,
            "region": self.region,
            "resource_arn": self.resource_arn,
            "account_id": self.account_id,
            "cwe": self.cwe,
            "category": self.category,
            "metadata": dict(self.metadata),
        }


# Type for the boto3 client factory. Tests pass a fake; production
# code passes the default boto3-backed factory.
class ClientFactory(Protocol):
    def __call__(self, service: str, region: str | None = None) -> Any: ...


# A check function takes a client factory + the region scope
# (None for global) and returns a list of findings.
CheckFn = Callable[[ClientFactory, str | None], list[CspmFinding]]


@dataclass(frozen=True)
class _RegisteredCheck:
    fn: CheckFn
    service: ServiceName
    scope: CheckScope
    name: str


_CHECKS: list[_RegisteredCheck] = []


def register_check(
    *, service: ServiceName, scope: CheckScope = "regional",
) -> Callable[[CheckFn], CheckFn]:
    """Decorator — register an AWS CSPM check.

    Args:
        service: boto3 service name (`s3` / `ec2` / `iam` / ...).
        scope: `"regional"` (default) runs once per scanned
            region; `"global"` runs once total (IAM, account
            settings).
    """
    if scope not in ("regional", "global"):
        raise ValueError(f"invalid scope: {scope}")

    def decorator(fn: CheckFn) -> CheckFn:
        _CHECKS.append(_RegisteredCheck(
            fn=fn, service=service, scope=scope, name=fn.__name__,
        ))
        return fn
    return decorator


def list_registered_checks() -> list[dict[str, str]]:
    """Introspection — used by tests + the status command."""
    return [
        {"name": c.name, "service": c.service, "scope": c.scope}
        for c in _CHECKS
    ]


def run_checks(
    client_factory: ClientFactory,
    regions: list[str],
) -> tuple[list[CspmFinding], list[dict[str, str]]]:
    """Run every registered check across the given region set.

    Returns `(findings, errors)`. Errors are per-(check, region)
    dicts so a single broken check (e.g. an AccessDenied on one
    service) doesn't suppress the rest of the scan.

    Per-check exceptions are caught + logged + recorded in the
    errors list. The standard CSPM failure mode is "this role
    can't List X" — we want to report that explicitly rather
    than silently dropping findings.
    """
    findings: list[CspmFinding] = []
    errors: list[dict[str, str]] = []

    for check in _CHECKS:
        if check.scope == "global":
            # Global checks run once, region=None.
            scopes = [None]
        else:
            scopes = list(regions)

        for region in scopes:
            try:
                out = check.fn(client_factory, region)
                if out:
                    findings.extend(out)
            except Exception as e:  # noqa: BLE001
                errors.append({
                    "check": check.name,
                    "service": check.service,
                    "region": region or "global",
                    "error": f"{type(e).__name__}: {e}",
                })
                logger.debug(
                    "cspm/aws: %s failed for %s: %s",
                    check.name, region or "global", e, exc_info=True,
                )

    return findings, errors


# Side-effect imports — register checks for each service. Order
# doesn't matter; the registry is a flat list.
from strix.cspm.aws.checks import (  # noqa: E402, F401
    cloudtrail as _cloudtrail,
    ebs as _ebs,
    ec2 as _ec2,
    iam as _iam,
    rds as _rds,
    s3 as _s3,
    vpc as _vpc,
)
