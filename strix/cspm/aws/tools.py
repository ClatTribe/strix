"""LLM-facing AWS CSPM specialist — `scan_aws_account`.

Emits one tracer finding per CSPM finding so the existing
compliance enrichment (CIS AWS Foundations Benchmark mapping
via `RULE_ID_TO_CONTROLS`) decorates each finding with auditor-
grade control evidence.
"""

from __future__ import annotations

import logging

from strix.cspm.aws.scanner import AwsCspmReport, scan_aws_account
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


def _emit_finding(*, finding, account_id: str | None) -> str | None:
    """Emit one CSPM finding to the tracer."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        title = (
            f"[cspm:aws:{finding.service}] {finding.rule_id} — "
            f"{finding.message[:120]}"
        )[:480]
        target = (
            f"aws://{account_id or 'unknown'}/"
            f"{finding.region or 'global'}/{finding.service}"
        )
        report_id = tracer.add_vulnerability_report(
            title=title,
            severity=finding.severity,
            cwe=finding.cwe,
            endpoint=finding.resource_arn,
            target=target,
            category=finding.category or "misconfig",
            rule_id=finding.rule_id,
            verification_status="verified",
            confidence=0.95,
            description=(
                f"AWS live-scan rule `{finding.rule_id}` matched "
                f"on resource `{finding.resource_arn}` in account "
                f"`{account_id or '?'}` "
                f"region `{finding.region or 'global'}`.\n\n"
                f"{finding.message}"
            ),
            impact=(
                "CSPM findings reflect the LIVE state of the AWS "
                "account, not declared infrastructure. A misconfig "
                "here affects production right now — either via "
                "IaC drift, a manual console change, or a resource "
                "created before IaC was adopted.\n\n"
                "Cross-asset follow-up:\n"
                "  * If your IaC scanner says the resource is OK "
                "but CSPM says it isn't, you have drift — re-apply "
                "Terraform OR import the resource into state.\n"
                "  * If both scanners agree, the IaC is the root "
                "cause — fix the IaC and re-apply."
            ),
            technical_analysis=(
                f"Rule: {finding.rule_id}\n"
                f"Service: {finding.service}\n"
                f"Region: {finding.region or '(global)'}\n"
                f"Account: {account_id or '(unknown)'}\n"
                f"Resource ARN: {finding.resource_arn}\n"
                f"Severity: {finding.severity}\n"
                f"CWE: {finding.cwe or '(none mapped)'}\n"
                f"Metadata: {finding.metadata}\n"
            ),
            remediation_steps=(
                "1. Fix the underlying configuration in AWS (console "
                "or aws CLI).\n"
                "2. If the resource is managed by IaC, update the IaC "
                "and re-apply — don't just fix in the console or it "
                "will drift again on the next deploy.\n"
                "3. Re-run `scan_aws_account` against the same "
                "account / region to confirm the finding clears."
            ),
        )
        return report_id
    except Exception as e:  # noqa: BLE001
        logger.debug("cspm/aws emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="cspm-aws-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 600},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190", "T1078.004"],
)
def scan_aws_account_tool(
    *,
    regions: list[str] | None = None,
    profile_name: str | None = None,
    role_arn: str | None = None,
) -> SpecialistResult:
    """Read-only CSPM scan of an AWS account. Runs the bundled
    check pack (S3 / EC2 / IAM / RDS / EBS / CloudTrail / VPC),
    emits one finding per live misconfig.

    Args:
        regions: list of region names. None → auto-discover.
        profile_name: AWS profile name. None → default credential
            chain.
        role_arn: optional role to assume (cross-account scan).

    Findings are CIS AWS Foundations Benchmark-mapped via the
    existing `RULE_ID_TO_CONTROLS` registry — the wrapper renders
    each finding with `compliance_controls.cis_aws: [...]`.
    """
    try:
        report = scan_aws_account(
            regions=regions,
            profile_name=profile_name,
            role_arn=role_arn,
        )
    except ImportError as e:
        return SpecialistResult(
            status="error",
            error=f"boto3 not installed: {e}",
        )
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"scan_aws_account failed: {type(e).__name__}: {e}",
        )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0

    for f in report.findings:
        rid = _emit_finding(finding=f, account_id=report.account_id)
        if rid:
            emitted_count += 1
        drafts.append(FindingDraft(
            title=(
                f"[cspm:aws:{f.service}] {f.rule_id} — "
                f"{f.message[:120]}"
            )[:480],
            severity=f.severity,
            cwe=f.cwe,
            endpoint=f.resource_arn,
            category=f.category or "misconfig",
            verification_status="verified",
            confidence=0.95,
            description=f.message[:480],
        ))
        evidence.append(
            f"cspm:aws: {f.rule_id} @ "
            f"{f.region or 'global'}/{f.resource_arn} ({f.severity})"
        )

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=[
            "compare findings against IaC scan — same finding on "
            "both sides = IaC root cause; CSPM-only = drift",
            "for IAM findings, audit attached policies + last-used "
            "data via Access Analyzer",
            "for SG / RDS public-access findings, verify whether "
            "the resource is intentionally internet-facing (some "
            "services need it) — false positives common in this "
            "class",
        ],
        tool_metadata={
            "engine": "cspm-aws-v1",
            "account_id": report.account_id,
            "regions_scanned": report.regions_scanned,
            "findings_total": len(report.findings),
            "findings_by_service": report.findings_by_service,
            "critical_count": report.critical_count,
            "high_count": report.high_count,
            "findings_emitted_to_tracer": emitted_count,
            "errors": report.errors[:10],
        },
    )
