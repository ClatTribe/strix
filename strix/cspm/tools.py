"""Unified CSPM specialist — `scan_cloud_account`.

Strategy:

  1. **Prefer Prowler** (Apache 2.0, 500+ checks, multi-cloud) when
     the binary is on $PATH. Prowler is the primary engine —
     better breadth, faster template velocity, multi-cloud out of
     the box.

  2. **Fall back to built-in boto3 checks** (AWS only) when Prowler
     isn't available. Same checks as `scan_aws_account_tool`;
     covers the air-gapped + minimal-install case.

Why both: the boto3 path is hermetic-testable, has no external
binary dep, and serves as the offline / sandbox baseline. The
Prowler path is what mid-size customers want in CI.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.cspm.aws import CspmFinding
from strix.cspm.aws.scanner import scan_aws_account
from strix.cspm.prowler import (
    ProwlerScanResult,
    is_prowler_available,
    run_prowler,
)
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


def _emit_finding(
    *, finding: CspmFinding, engine: str,
) -> str | None:
    """Emit one CSPM finding to the tracer. Mirrors the AWS-only
    emitter in `strix/cspm/aws/tools.py` but engine-agnostic.

    When Prowler attached its own per-finding compliance dict
    (`metadata.prowler_compliance`), we pre-populate
    `compliance_controls` on the report so the enricher unions
    rather than re-derives — Prowler's per-check compliance map
    is authoritative."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        title = (
            f"[cspm:{engine}:{finding.service}] {finding.rule_id} — "
            f"{finding.message[:120]}"
        )[:480]
        account = finding.account_id or "unknown"
        target = (
            f"aws://{account}/{finding.region or 'global'}/"
            f"{finding.service}"
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
                f"CSPM engine `{engine}` flagged resource "
                f"`{finding.resource_arn}` in account `{account}` "
                f"region `{finding.region or 'global'}`.\n\n"
                f"{finding.message}"
            ),
            impact=(
                "CSPM findings reflect LIVE cloud state. A misconfig "
                "here affects production right now — via IaC drift, "
                "manual console change, or a resource that pre-dates "
                "IaC adoption.\n\n"
                "Cross-asset follow-up:\n"
                "  * Cross-check with IaC scan — same finding both "
                "sides = IaC root cause; CSPM-only = drift.\n"
                "  * For IAM findings, validate via Access Analyzer."
            ),
            technical_analysis=(
                f"Engine: {engine}\n"
                f"Rule: {finding.rule_id}\n"
                f"Service: {finding.service}\n"
                f"Region: {finding.region or '(global)'}\n"
                f"Account: {account}\n"
                f"Resource ARN: {finding.resource_arn}\n"
                f"Severity: {finding.severity}\n"
                f"Metadata: {finding.metadata}\n"
            ),
            remediation_steps=(
                "1. Fix the underlying AWS / Azure / GCP configuration "
                "(console or vendor CLI).\n"
                "2. If the resource is IaC-managed, update the IaC and "
                "re-apply — otherwise the next deploy reintroduces "
                "the drift.\n"
                "3. Re-run `scan_cloud_account` to confirm the finding "
                "clears."
            ),
        )

        # Attach Prowler's per-finding compliance dict directly to
        # the report. The enricher (`enrich_finding_with_compliance`)
        # was updated to UNION rather than overwrite, so the
        # rule_id-driven strix mapping (when present) combines with
        # Prowler's authoritative map.
        if report_id:
            prowler_compliance = (
                finding.metadata.get("prowler_compliance")
                if isinstance(finding.metadata, dict) else None
            )
            if prowler_compliance:
                for report in tracer.vulnerability_reports:
                    if report.get("id") == report_id:
                        existing = report.get("compliance_controls") or {}
                        if not isinstance(existing, dict):
                            existing = {}
                        for fw, ctrls in prowler_compliance.items():
                            merged = sorted(
                                set(existing.get(fw, [])) | set(ctrls)
                            )
                            existing[fw] = merged
                        report["compliance_controls"] = existing
                        break

        return report_id
    except Exception as e:  # noqa: BLE001
        logger.debug("cspm emit failed: %s", e, exc_info=True)
        return None


def _findings_from_prowler(
    result: ProwlerScanResult,
) -> tuple[list[CspmFinding], list[dict[str, str]]]:
    return list(result.findings), list(result.errors)


def _findings_from_boto3(
    *,
    profile_name: str | None,
    role_arn: str | None,
    regions: list[str] | None,
) -> tuple[list[CspmFinding], list[dict[str, str]], dict[str, Any]]:
    report = scan_aws_account(
        regions=regions,
        profile_name=profile_name,
        role_arn=role_arn,
    )
    metadata = {
        "account_id": report.account_id,
        "regions_scanned": report.regions_scanned,
        "findings_by_service": report.findings_by_service,
    }
    return list(report.findings), list(report.errors), metadata


@register_specialist_tool(
    category="cspm-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 1800},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190", "T1078.004"],
)
def scan_cloud_account(
    *,
    provider: str = "aws",
    profile_name: str | None = None,
    role_arn: str | None = None,
    regions: list[str] | None = None,
    prefer_prowler: bool = True,
    prowler_compliance: list[str] | None = None,
    prowler_services: list[str] | None = None,
    include_attack_paths: bool = True,
    attack_path_patterns: list[str] | None = None,
) -> SpecialistResult:
    """Read-only CSPM scan of a cloud account.

    Engine selection: prefers Prowler (500+ checks, multi-cloud)
    when installed; falls back to strix's built-in boto3 checks
    for AWS otherwise. Set `prefer_prowler=False` to force the
    built-in path (useful in air-gapped / minimal envs).

    Args:
        provider: `aws` / `azure` / `gcp` / `kubernetes`. Built-in
            fallback only supports `aws`.
        profile_name: AWS profile name (passed to either engine).
        role_arn: assume-role ARN (cross-account scanning).
        regions: optional region filter (AWS).
        prefer_prowler: when True (default) and Prowler is on
            $PATH, use it. False forces the built-in path.
        prowler_compliance: optional Prowler `--compliance` filter
            (e.g. `["cis_3.0_aws"]`) — restricts checks to a
            framework subset for faster scans.
        prowler_services: optional Prowler `--service` filter
            (e.g. `["s3", "iam"]`).
        include_attack_paths: when True (default), runs the graph-
            based attack-path analyzer
            (`strix.cloud_attack_paths.analyze_cloud_attack_paths`)
            over the CSPM findings AFTER they're emitted and emits
            each detected toxic combination as an additional tracer
            finding with `category=cloud_attack_path`. Free
            piggyback — no extra network calls, just CPU over the
            already-collected findings. Set False in tests / minimal
            scans where the agent only needs the underlying CSPM
            output.
        attack_path_patterns: optional allow-list of attack-path
            pattern IDs to run (e.g. `["cap_root_unsafe"]`). None
            runs every built-in pattern.

    Findings flow through the standard compliance enricher.
    Prowler-supplied per-finding compliance maps union with
    strix's RULE_ID_TO_CONTROLS so neither source clobbers the
    other.
    """
    if provider not in ("aws", "azure", "gcp", "kubernetes"):
        return SpecialistResult(
            status="error",
            error=f"unsupported provider: {provider!r}",
        )

    findings: list[CspmFinding] = []
    errors: list[dict[str, str]] = []
    engine_used = "none"
    tool_metadata: dict[str, Any] = {"provider": provider}

    use_prowler = prefer_prowler and is_prowler_available()
    if use_prowler:
        engine_used = "prowler"
        result = run_prowler(
            provider=provider,
            profile=profile_name,
            role_arn=role_arn,
            regions=regions,
            compliance=prowler_compliance,
            services=prowler_services,
        )
        findings, errors = _findings_from_prowler(result)
        tool_metadata.update(result.metadata)
        if not findings and result.errors:
            # Prowler errored without producing findings — fall through
            # to built-in for AWS so the customer gets *some* output.
            if provider == "aws":
                logger.info(
                    "cspm: prowler failed (%s); falling back to boto3",
                    result.errors[0].get("error"),
                )
                use_prowler = False
                engine_used = "boto3-fallback"

    if not use_prowler:
        if provider != "aws":
            return SpecialistResult(
                status="error",
                error=(
                    f"Prowler is not installed (or failed) and the "
                    f"built-in CSPM engine only supports AWS — got "
                    f"`{provider}`. Install via `pip install prowler` "
                    f"to scan {provider} accounts."
                ),
            )
        if engine_used == "none":
            engine_used = "boto3"
        try:
            findings, boto3_errors, boto3_meta = _findings_from_boto3(
                profile_name=profile_name,
                role_arn=role_arn,
                regions=regions,
            )
            errors.extend(boto3_errors)
            tool_metadata.update(boto3_meta)
        except ImportError as e:
            return SpecialistResult(
                status="error",
                error=f"boto3 not installed: {e}",
            )
        except Exception as e:  # noqa: BLE001
            return SpecialistResult(
                status="error",
                error=f"built-in scan failed: {type(e).__name__}: {e}",
            )

    # Severity-descending so the wrapper surfaces highest-impact first.
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(
        key=lambda f: -sev_rank.get((f.severity or "").lower(), 0),
    )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted = 0

    for f in findings:
        rid = _emit_finding(finding=f, engine=engine_used)
        if rid:
            emitted += 1
        drafts.append(FindingDraft(
            title=(
                f"[cspm:{engine_used}:{f.service}] {f.rule_id} — "
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
            f"cspm:{engine_used}: {f.rule_id} @ "
            f"{f.region or 'global'}/{f.resource_arn} ({f.severity})"
        )

    # Attack-path analysis (PR #293 wiring — Option B / "smallest
    # delta" from the wrapper integration audit). Runs over the
    # already-collected findings; no extra network calls. Default-on
    # so webappsec gets toxic-combination findings flowing through
    # the existing tracer pipeline without any wrapper-side change —
    # each path emits as `category=cloud_attack_path` and rides the
    # same `vulnerabilities/*.md` round-trip the wrapper's worker
    # already ingests.
    attack_paths_summary: dict[str, int] | None = None
    attack_paths_emitted = 0
    if include_attack_paths and findings:
        try:
            # Lazy-import so we don't drag the cloud_attack_paths
            # package into every CSPM specialist load (it's still
            # standalone-callable via `scan_cloud_attack_paths`).
            from strix.cloud_attack_paths.api import (  # noqa: PLC0415
                analyze_cloud_attack_paths,
            )
            from strix.cloud_attack_paths.tools import (  # noqa: PLC0415
                _emit_attack_path,
            )

            ap_report = analyze_cloud_attack_paths(
                cspm_findings=findings,
                patterns=attack_path_patterns,
            )
            attack_paths_summary = ap_report.summary
            target_label = f"cspm:{provider}"
            for path in ap_report.paths:
                rid = _emit_attack_path(path=path, target=target_label)
                if rid:
                    attack_paths_emitted += 1
                drafts.append(FindingDraft(
                    title=f"[cloud-attack-path] {path.title}"[:480],
                    severity=path.severity,
                    cwe=None,
                    endpoint=(path.hops[0] if path.hops else target_label),
                    category="cloud_attack_path",
                    verification_status="verified",
                    confidence=path.confidence or 0.95,
                    description=path.narrative[:480],
                ))
                evidence.append(
                    f"cap:{path.pattern_id} sev={path.severity} "
                    f"hops={len(path.hops)}"
                )
        except Exception as e:  # noqa: BLE001
            # Attack-path analysis failure must NEVER block the CSPM
            # findings emit — they're already on the tracer at this
            # point. Surface as a soft error.
            logger.warning(
                "cspm: attack-path analysis failed: %s", e, exc_info=True,
            )
            errors.append({
                "source": "attack_paths",
                "error": f"{type(e).__name__}: {e}",
            })

    tool_metadata.update({
        "engine": engine_used,
        "findings_total": len(findings),
        "findings_emitted_to_tracer": emitted,
        "critical_count": sum(
            1 for f in findings if f.severity == "critical"
        ),
        "high_count": sum(
            1 for f in findings if f.severity == "high"
        ),
        "errors": errors[:10],
    })
    if attack_paths_summary is not None:
        tool_metadata["attack_paths_summary"] = attack_paths_summary
        tool_metadata["attack_paths_emitted_to_tracer"] = attack_paths_emitted

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=[
            "compare CSPM findings against IaC scan — overlap = IaC "
            "root cause; CSPM-only = drift requiring console fix + "
            "IaC alignment",
            "for cross-account scans, repeat with --role-arn against "
            "each account in the organization",
            "review `cloud_attack_path` findings first — each chains "
            "multiple CSPM hits into a single concrete attacker "
            "scenario with concrete remediation",
        ],
        tool_metadata=tool_metadata,
    )
