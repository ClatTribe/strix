"""LLM-facing drift specialist — `correlate_drift`.

Runs an IaC scan + a CSPM scan, correlates the two, emits one
tracer finding per drift entry with classification metadata so
downstream renderers can group by `iac_root_cause` / `drift` /
`iac_unfollowed`.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from strix.cspm.aws.scanner import scan_aws_account
from strix.cspm.prowler import is_prowler_available, run_prowler
from strix.drift.correlator import (
    DRIFT_CLASSIFICATION_DRIFT,
    DRIFT_CLASSIFICATION_IAC_ROOT_CAUSE,
    DRIFT_CLASSIFICATION_IAC_UNFOLLOWED,
    DriftFinding,
    DriftReport,
    correlate,
)
from strix.iac.scanner import scan_iac_repo
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Per-classification remediation copy. The drift-specific guidance
# is what makes the report actionable — generic "fix the misconfig"
# language would force the dev to figure out which side to touch.
_REMEDIATION_BY_CLASSIFICATION = {
    DRIFT_CLASSIFICATION_IAC_ROOT_CAUSE: (
        "Both IaC and live state flag this finding. The IaC is the "
        "root cause — fix the Terraform / K8s manifest and re-apply. "
        "The live finding will clear once the deploy lands."
    ),
    DRIFT_CLASSIFICATION_DRIFT: (
        "Live state has this finding but the IaC scan didn't flag "
        "it. Either (a) the resource was created outside IaC, or "
        "(b) someone modified it in the console after Terraform "
        "applied. Run `terraform plan` to see the diff. Either "
        "`terraform apply` to overwrite, or `terraform import` + "
        "update the IaC to match the intended live state."
    ),
    DRIFT_CLASSIFICATION_IAC_UNFOLLOWED: (
        "IaC declares this misconfig but the live state is clean. "
        "Either (a) the IaC hasn't been applied yet, or (b) someone "
        "hand-fixed the live resource without updating IaC — next "
        "`terraform apply` will reintroduce the issue. Fix the IaC "
        "before the next deploy."
    ),
}


def _classification_severity_floor(classification: str, severity: str) -> str:
    """Drift findings get a one-step bump because 'IaC ≠ live' is
    an operational signal in its own right — auditors flag drift
    even when the underlying control is medium-risk. iac_root_cause
    and iac_unfollowed inherit the underlying severity unchanged."""
    if classification != DRIFT_CLASSIFICATION_DRIFT:
        return severity
    ladder = ["info", "low", "medium", "high", "critical"]
    try:
        i = ladder.index(severity.lower())
    except ValueError:
        return severity
    return ladder[min(i + 1, len(ladder) - 1)]


def _emit_drift_finding(*, df: DriftFinding, target: str) -> str | None:
    """Emit a drift-classified finding to the tracer.

    Inherits CWE / rule_id from whichever side is populated so the
    existing compliance enrichment still attaches CIS / SOC 2
    controls. Adds classification + cross-source metadata.
    """
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None

        # Source-of-record for CWE + endpoint: IaC side if present
        # (more precise — file:line), else CSPM side.
        cwe = None
        endpoint = None
        if df.iac_finding is not None:
            cwe = df.iac_finding.cwe
            endpoint = (
                f"{df.iac_finding.file}:{df.iac_finding.line}"
                if df.iac_finding.line
                else df.iac_finding.file
            )
        if df.cspm_finding is not None:
            if cwe is None:
                cwe = df.cspm_finding.cwe
            if endpoint is None:
                endpoint = df.cspm_finding.resource_arn

        # The reported rule_id is the IaC one (we own it, less
        # vendor churn) when present; falls back to CSPM otherwise.
        rule_id = df.iac_rule_id or df.cspm_rule_id

        severity = _classification_severity_floor(
            df.classification, df.severity,
        )

        title = (
            f"[drift:{df.classification}] {df.rule_class} — "
            f"{df.resource_hint or '(unmatched)'}"
        )[:480]

        iac_msg = df.iac_finding.message if df.iac_finding else None
        cspm_msg = df.cspm_finding.message if df.cspm_finding else None
        description_parts = [
            f"Drift classification: **{df.classification}**.",
            f"Rule class: `{df.rule_class}`.",
            f"Resource hint: `{df.resource_hint or '(coarse match)'}`.",
        ]
        if iac_msg:
            description_parts.append(f"\nIaC finding:\n{iac_msg}")
        if cspm_msg:
            description_parts.append(f"\nCSPM finding:\n{cspm_msg}")
        description = "\n".join(description_parts)

        report_id = tracer.add_vulnerability_report(
            title=title,
            severity=severity,
            cwe=cwe,
            endpoint=endpoint or "drift:unknown",
            target=target,
            category="drift",
            rule_id=rule_id,
            verification_status="verified",
            confidence=(
                0.95
                if df.resource_hint
                and not str(df.resource_hint).startswith("coarse:")
                else 0.75
            ),
            description=description,
            impact=(
                "Drift between Terraform and live cloud state means "
                "one of three failure modes is in play:\n\n"
                "  * IaC is the wrong source of truth — operators "
                "are hand-fixing live resources outside the deploy "
                "pipeline.\n"
                "  * Resources exist outside IaC — they're not "
                "covered by code review, change management, or "
                "rollback.\n"
                "  * Pending deploys carry latent misconfigs — the "
                "next `terraform apply` will introduce a fresh "
                "vulnerability.\n\n"
                "Drift is what makes \"my IaC scan passed\" stop "
                "being meaningful evidence for auditors."
            ),
            remediation_steps=_REMEDIATION_BY_CLASSIFICATION.get(
                df.classification, "Investigate the discrepancy."
            ),
            technical_analysis=(
                f"Classification: {df.classification}\n"
                f"Rule class: {df.rule_class}\n"
                f"IaC rule_id: {df.iac_rule_id or '(none)'}\n"
                f"CSPM rule_id: {df.cspm_rule_id or '(none)'}\n"
                f"Resource hint: {df.resource_hint or '(none)'}\n"
                f"Severity (drift-adjusted): {severity}\n"
            ),
        )
        return report_id
    except Exception as e:  # noqa: BLE001
        logger.debug("drift emit failed: %s", e, exc_info=True)
        return None


def _run_cspm(
    *,
    provider: str,
    profile_name: str | None,
    role_arn: str | None,
    regions: list[str] | None,
    prefer_prowler: bool,
) -> tuple[list, list[dict], str, dict[str, Any]]:
    """Run a CSPM scan and return `(findings, errors, engine, metadata)`.
    Mirrors the dispatch logic in `strix.cspm.tools.scan_cloud_account`
    but returns the raw findings instead of emitting them — drift
    correlation needs the unemitted finding objects."""
    metadata: dict[str, Any] = {"provider": provider}
    if prefer_prowler and is_prowler_available():
        result = run_prowler(
            provider=provider,
            profile=profile_name,
            role_arn=role_arn,
            regions=regions,
        )
        metadata.update(result.metadata)
        if result.findings or not result.errors:
            return result.findings, result.errors, "prowler", metadata
        # Prowler errored without findings — fall through to boto3.
        logger.info("drift: prowler failed (%s), falling back to boto3",
                    result.errors[0].get("error"))

    if provider != "aws":
        return [], [{"source": "cspm",
                     "error": (
                         f"Prowler unavailable and built-in CSPM "
                         f"engine only supports AWS; got {provider}"
                     )}], "none", metadata

    report = scan_aws_account(
        regions=regions,
        profile_name=profile_name,
        role_arn=role_arn,
    )
    metadata["account_id"] = report.account_id
    metadata["regions_scanned"] = report.regions_scanned
    return report.findings, report.errors, "boto3", metadata


@register_specialist_tool(
    category="drift-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 1800},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1078.004", "T1078"],
)
def correlate_drift(
    *,
    iac_repo_path: str,
    cspm_provider: str = "aws",
    cspm_profile_name: str | None = None,
    cspm_role_arn: str | None = None,
    cspm_regions: list[str] | None = None,
    prefer_prowler: bool = True,
) -> SpecialistResult:
    """Run an IaC scan + a CSPM scan, cross-reference, and emit
    drift-classified findings.

    Args:
        iac_repo_path: directory to scan with the IaC engine
            (`strix.iac.scanner.scan_iac_repo`).
        cspm_provider: cloud to scan (`aws` / `azure` / `gcp` /
            `kubernetes`). Built-in fallback only supports `aws`.
        cspm_profile_name / cspm_role_arn / cspm_regions: pass-
            through CSPM auth + region filter.
        prefer_prowler: use Prowler when installed; falls back to
            built-in boto3 for AWS.

    Output:
        `tool_metadata.drift_summary` carries the count per
        classification. `findings` carries the per-drift tracer-
        emitted entries.
    """
    if not isinstance(iac_repo_path, str) or not iac_repo_path.strip():
        return SpecialistResult(
            status="error",
            error="iac_repo_path required",
        )
    repo = Path(iac_repo_path).expanduser().resolve()
    if not repo.is_dir():
        return SpecialistResult(
            status="error",
            error=f"iac_repo_path not a directory: {iac_repo_path}",
        )

    # ---- IaC scan ----
    try:
        iac_report = scan_iac_repo(repo)
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"IaC scan failed: {type(e).__name__}: {e}",
        )

    # ---- CSPM scan ----
    cspm_findings, cspm_errors, cspm_engine, cspm_meta = _run_cspm(
        provider=cspm_provider,
        profile_name=cspm_profile_name,
        role_arn=cspm_role_arn,
        regions=cspm_regions,
        prefer_prowler=prefer_prowler,
    )

    # ---- Correlate ----
    drift_report = correlate(
        iac_findings=iac_report.findings,
        cspm_findings=cspm_findings,
    )

    # ---- Emit ----
    target = f"drift:{iac_repo_path}+{cspm_provider}"
    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted = 0
    all_drift = (
        drift_report.iac_root_cause
        + drift_report.drift
        + drift_report.iac_unfollowed
    )
    for df in all_drift:
        rid = _emit_drift_finding(df=df, target=target)
        if rid:
            emitted += 1
        drafts.append(FindingDraft(
            title=(
                f"[drift:{df.classification}] {df.rule_class}"
            )[:480],
            severity=_classification_severity_floor(
                df.classification, df.severity,
            ),
            cwe=(
                df.iac_finding.cwe if df.iac_finding
                else (df.cspm_finding.cwe if df.cspm_finding else None)
            ),
            endpoint=(
                f"{df.iac_finding.file}:{df.iac_finding.line}"
                if df.iac_finding
                else (df.cspm_finding.resource_arn if df.cspm_finding else "drift:?")
            ),
            category="drift",
            verification_status="verified",
            confidence=0.9,
            description=(
                f"{df.classification} / {df.rule_class} / "
                f"{df.resource_hint or 'coarse'}"
            ),
        ))
        evidence.append(
            f"drift:{df.classification} class={df.rule_class} "
            f"resource={df.resource_hint or 'coarse'} "
            f"sev={df.severity}"
        )

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=[
            "for drift findings, run `terraform plan` in CI on a "
            "schedule + alert when the plan is non-empty",
            "for iac_unfollowed findings, ensure the IaC is "
            "actually applied — check the deploy pipeline's "
            "success history for the relevant module",
            "for iac_root_cause findings, prioritise — they're "
            "the easy wins since one IaC fix clears the live "
            "issue automatically",
        ],
        tool_metadata={
            "engine_iac": "iac-v1",
            "engine_cspm": cspm_engine,
            "drift_summary": drift_report.summary,
            "total_drift_signal": drift_report.total_drift_signal,
            "uncorrelated_cspm_count": len(drift_report.uncorrelated_cspm),
            "iac_findings_total": len(iac_report.findings),
            "cspm_findings_total": len(cspm_findings),
            "findings_emitted_to_tracer": emitted,
            "iac_errors": iac_report.errors[:5],
            "cspm_errors": cspm_errors[:5],
            "cspm_metadata": cspm_meta,
        },
    )
