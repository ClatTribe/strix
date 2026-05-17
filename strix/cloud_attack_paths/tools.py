"""LLM-facing specialist + tracer emit for cloud attack paths.

Composes `scan_cloud_account` (CSPM) + `analyze_cloud_attack_paths`
(graph analysis) into one in-agent surface. Each detected attack
path becomes a tracer finding with `category=cloud_attack_path`
and the MITRE technique mapping the path covers.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.cloud_attack_paths.api import (
    AttackPathReport,
    analyze_cloud_attack_paths,
)
from strix.cloud_attack_paths.patterns import AttackPath
from strix.cspm.aws.scanner import scan_aws_account
from strix.cspm.prowler import is_prowler_available, run_prowler
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Severity bump rationale: attack paths combine N findings into one
# narrative — by definition the blast radius is wider than any
# constituent. We don't bump (severity is already chosen by the
# pattern), but we set confidence higher because graph-level
# evidence is stronger than single-finding evidence.
_PATH_CONFIDENCE = 0.95


def _emit_attack_path(*, path: AttackPath, target: str) -> str | None:
    """Emit one attack path to the tracer with classification +
    MITRE metadata."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        title = f"[cloud-attack-path] {path.title}"[:480]
        endpoint = path.hops[0] if path.hops else target

        description = (
            f"{path.narrative}\n\n"
            f"Hop chain: {' → '.join(path.hops)}"
        )

        report_id = tracer.add_vulnerability_report(
            title=title,
            severity=path.severity,
            endpoint=endpoint,
            target=target,
            category="cloud_attack_path",
            rule_id=path.pattern_id,
            verification_status="verified",
            confidence=path.confidence or _PATH_CONFIDENCE,
            description=description,
            impact=(
                "Cloud attack paths chain individual misconfigs into "
                "concrete attacker scenarios. A single 'public bucket' "
                "finding is a control violation; the same bucket "
                "containing terraform state with raw IAM keys is a "
                "full account compromise. Wrappers should prioritise "
                "attack-path findings above their constituent CSPM "
                "findings — the blast radius is the union of every "
                "permission an attacker collects walking the chain."
            ),
            technical_analysis=(
                f"Pattern ID: {path.pattern_id}\n"
                f"Severity: {path.severity}\n"
                f"Hops ({len(path.hops)}):\n"
                + "\n".join(f"  {i+1}. {h}" for i, h in enumerate(path.hops))
                + f"\nEvidence edges: {', '.join(path.evidence_edges) or '(none)'}\n"
                + f"MITRE: {', '.join(path.mitre_techniques) or '(none)'}\n"
                + f"Metadata: {path.metadata}"
            ),
            remediation_steps=path.remediation,
        )
        return report_id
    except Exception as e:  # noqa: BLE001
        logger.debug("attack-path emit failed: %s", e, exc_info=True)
        return None


def _collect_cspm_findings(
    *, provider: str, profile_name: str | None, role_arn: str | None,
    regions: list[str] | None, prefer_prowler: bool,
):
    """Mirror the dispatch logic in `strix.cspm.tools.scan_cloud_account`
    but return RAW findings (not emit-only). Attack-path analysis
    needs the unemitted finding objects to build the graph."""
    if prefer_prowler and is_prowler_available():
        result = run_prowler(
            provider=provider, profile=profile_name,
            role_arn=role_arn, regions=regions,
        )
        if result.findings or not result.errors:
            return result.findings, "prowler", result.errors, result.metadata

    if provider != "aws":
        return [], "none", [
            {"source": "cspm", "error": (
                f"Prowler unavailable and built-in fallback only "
                f"supports AWS; got `{provider}`"
            )},
        ], {}

    report = scan_aws_account(
        regions=regions, profile_name=profile_name, role_arn=role_arn,
    )
    return (
        report.findings, "boto3", report.errors,
        {
            "account_id": report.account_id,
            "regions_scanned": report.regions_scanned,
        },
    )


@register_specialist_tool(
    category="cloud-attack-path-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 1800},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190", "T1078.004", "T1552.001"],
)
def scan_cloud_attack_paths(
    *,
    provider: str = "aws",
    profile_name: str | None = None,
    role_arn: str | None = None,
    regions: list[str] | None = None,
    prefer_prowler: bool = True,
    patterns: list[str] | None = None,
) -> SpecialistResult:
    """Run a CSPM scan, build the cloud graph, detect attack paths,
    emit each path to the tracer.

    Args:
        provider: `aws` / `azure` / `gcp` / `kubernetes`. Built-in
            fallback only supports `aws`.
        profile_name / role_arn / regions: CSPM auth pass-through.
        prefer_prowler: use Prowler if installed (multi-cloud +
            500+ checks); falls back to built-in boto3 for AWS.
        patterns: optional allow-list of pattern IDs. None = all
            built-in patterns.

    Returns:
        `SpecialistResult` with one finding per detected attack
        path. `tool_metadata.attack_paths_summary` carries the
        per-pattern + per-severity counts the wrapper renders.
    """
    if provider not in ("aws", "azure", "gcp", "kubernetes"):
        return SpecialistResult(
            status="error",
            error=f"unsupported provider: {provider!r}",
        )

    findings, cspm_engine, cspm_errors, cspm_meta = _collect_cspm_findings(
        provider=provider, profile_name=profile_name,
        role_arn=role_arn, regions=regions,
        prefer_prowler=prefer_prowler,
    )

    if not findings and cspm_engine == "none":
        return SpecialistResult(
            status="error",
            error=(
                cspm_errors[0]["error"] if cspm_errors
                else "no CSPM engine available"
            ),
        )

    report = analyze_cloud_attack_paths(
        cspm_findings=findings, patterns=patterns,
    )

    target = f"cloud-attack-paths:{provider}"
    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted = 0

    for p in report.paths:
        rid = _emit_attack_path(path=p, target=target)
        if rid:
            emitted += 1
        drafts.append(FindingDraft(
            title=f"[cloud-attack-path] {p.title}"[:480],
            severity=p.severity,
            cwe=None,
            endpoint=p.hops[0] if p.hops else target,
            category="cloud_attack_path",
            verification_status="verified",
            confidence=p.confidence or _PATH_CONFIDENCE,
            description=p.narrative[:480],
        ))
        evidence.append(
            f"cap:{p.pattern_id} sev={p.severity} hops={len(p.hops)}"
        )

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=[
            "for critical attack paths, verify exploitability live "
            "where possible (anonymous S3 GET, SG port reachability, "
            "SQS SendMessage)",
            "audit IAM identities attached to internet-exposed "
            "compute resources — least-privilege them first",
            "where attack paths share a hop, fixing the shared hop "
            "clears multiple paths at once",
        ],
        tool_metadata={
            "engine": "cloud-attack-paths-v1",
            "provider": provider,
            "cspm_engine": cspm_engine,
            "cspm_findings_consumed": report.findings_consumed,
            "attack_paths_summary": report.summary,
            "attack_paths_total": len(report.paths),
            "critical_paths": len(report.critical_paths()),
            "findings_emitted_to_tracer": emitted,
            "cspm_metadata": cspm_meta,
            "cspm_errors": cspm_errors[:5],
        },
    )
