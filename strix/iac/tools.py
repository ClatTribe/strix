"""LLM-facing IaC specialist — Phase 11 (`scan_iac`).

Walks a repo for IaC files (vercel.json / netlify.toml /
wrangler.toml / Dockerfile / docker-compose.yml), runs the
bundled rule pack, emits one finding per misconfig.

Cross-asset chain (per §4a):
  * IaC misconfig with `category="misconfig"` + CORS-credentials →
    DAST sends a cross-origin request with credentials; if it
    succeeds, the misconfig is proven exploitable.
  * IaC misconfig `category="open_redirect"` → DAST probes the
    matching path with a controlled redirect URL.
  * IaC misconfig `category="info_disclosure"` (hardcoded secret)
    → cross-reference with secrets-scan to confirm whether the
    secret was already published.
"""

from __future__ import annotations

import logging
from pathlib import Path

from strix.iac.scanner import scan_iac_repo
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


def _emit_finding(*, finding, repo_path: str) -> str | None:
    """Emit one IaC finding to the tracer."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        title = (
            f"[iac:{finding.platform or '?'}] {finding.rule_id} — "
            f"{finding.message[:120]}"
        )[:480]
        endpoint = (
            f"{finding.file}:{finding.line}"
            if finding.line else finding.file
        )
        report_id = tracer.add_vulnerability_report(
            title=title,
            severity=finding.severity,
            cwe=finding.cwe,
            endpoint=endpoint,
            target=repo_path,
            category=finding.category or "misconfig",
            rule_id=finding.rule_id,
            cve=None,
            cvss=None,
            verification_status="verified",
            confidence=0.9,
            description=(
                f"IaC rule `{finding.rule_id}` matched in "
                f"`{finding.file}`"
                + (f" at line {finding.line}" if finding.line else "")
                + f".\n\n{finding.message}"
            ),
            impact=(
                "IaC misconfigs ship as part of the deploy "
                "pipeline — they affect every environment "
                "(dev, staging, production) until the IaC file "
                "is fixed and redeployed.\n\n"
                "Cross-asset follow-up:\n"
                "  * `category=misconfig` (CORS / TLS / headers) → "
                "DAST probe with the matching specialist\n"
                "  * `category=open_redirect` → DAST sends a "
                "redirect probe to confirm exploitation\n"
                "  * `category=info_disclosure` (hardcoded secret) → "
                "rotate the credential immediately; check breach "
                "corpora for prior exposure"
            ),
            technical_analysis=(
                f"Rule: {finding.rule_id}\n"
                f"Platform: {finding.platform}\n"
                f"File: {finding.file}\n"
                f"Line: {finding.line or '(whole file)'}\n"
                f"Severity: {finding.severity}\n"
                f"CWE: {finding.cwe or '(none mapped)'}\n"
                f"Category: {finding.category or '(generic)'}\n"
                f"Metadata: {finding.metadata}\n"
            ),
            poc_description=(
                f"1. Open `{finding.file}` "
                f"{'at line ' + str(finding.line) if finding.line else ''}.\n"
                f"2. Confirm the matched pattern. The rule "
                f"message above explains the specific "
                f"misconfig.\n"
                f"3. If this is a runtime-affecting misconfig "
                f"(CORS, auth, redirect), follow up with the "
                f"matching DAST specialist on the deployed URL "
                f"to confirm the misconfig actually fires in "
                f"production."
            ),
            poc_script_code="",
            remediation_steps=(
                f"1. Apply the fix the rule message suggests.\n"
                f"2. Redeploy and re-run `scan_iac` on this "
                f"file to confirm the rule no longer matches.\n"
                f"3. If this finding crossed environments "
                f"(dev / staging / prod sharing one IaC file), "
                f"audit each environment for the same exposure."
            ),
            cvss_breakdown=None,
        )

        # KG: code-location surface — same shape as SAST. IaC
        # findings are file:line, not URL, so the tracer's URL-
        # auto-emit skips them. Add the code-shape triple here so
        # IaC misconfigs feed into chain queries (e.g., a CORS
        # misconfig in IaC + the deployed endpoint sharing the
        # same `category=misconfig` chain to a DAST CORS probe).
        try:
            from strix.agents.kg_emit import record_code_finding_in_kg

            record_code_finding_in_kg(
                finding_id=report_id,
                file_path=finding.file,
                start_line=finding.line if finding.line else 1,
                cwe=finding.cwe or "CWE-1390",
                severity=finding.severity,
                category=finding.category or "misconfig",
                rule_id=finding.rule_id,
                confidence=0.9,
            )
        except Exception:  # noqa: BLE001
            logger.debug("iac: KG code-finding emit failed", exc_info=True)

        return report_id
    except Exception as e:  # noqa: BLE001
        logger.debug("iac emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="iac-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=True,
    provenance="framework",
    mitre_techniques=["T1078", "T1190"],   # Valid Accounts, Public-Facing App
)
def scan_iac(
    *,
    repo_path: str,
    max_files: int = 200,
) -> SpecialistResult:
    """Walk `repo_path` for IaC files (vercel.json / netlify.toml /
    wrangler.toml / Dockerfile / docker-compose.yml), run the
    bundled vibe-coded rule pack, emit one finding per misconfig.

    Args:
        repo_path: directory to scan.
        max_files: hard cap on IaC files parsed (default 200).

    Findings are emitted with their raw severity from the rule —
    IaC checks don't currently get the route-reachability
    calibration that SAST gets (the misconfig affects the deploy
    surface, not a specific code path).
    """
    if not isinstance(repo_path, str) or not repo_path.strip():
        return SpecialistResult(status="error", error="repo_path required")
    repo_path = repo_path.strip()
    repo = Path(repo_path).resolve()
    if not repo.is_dir():
        return SpecialistResult(
            status="error",
            error=f"not a directory: {repo_path}",
        )

    try:
        report = scan_iac_repo(repo_path, max_files=max_files)
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"scan_iac_repo failed: {type(e).__name__}: {e}",
        )

    if not report.files_scanned:
        return SpecialistResult(
            status="partial",
            error="no IaC files found",
            evidence=[
                f"scan_iac walked {repo_path} but found no "
                f"recognised IaC files. Looked for: vercel.json, "
                f"netlify.toml, wrangler.toml, Dockerfile, "
                f"docker-compose.yml. If your IaC lives "
                f"elsewhere (Terraform / CDK / Pulumi), strix's "
                f"v1 IaC engine doesn't cover those — Phase 11.x "
                f"follow-ups will."
            ],
            tool_metadata={
                "engine": "iac-v1",
                "files_scanned": 0,
            },
        )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0

    for f in report.findings:
        rid = _emit_finding(finding=f, repo_path=repo_path)
        if rid:
            emitted_count += 1
        title = (
            f"[iac:{f.platform or '?'}] {f.rule_id} — {f.message[:120]}"
        )[:480]
        endpoint = (
            f"{f.file}:{f.line}" if f.line else f.file
        )
        drafts.append(FindingDraft(
            title=title,
            severity=f.severity,
            cwe=f.cwe,
            endpoint=endpoint,
            category=f.category or "misconfig",
            verification_status="verified",
            confidence=0.9,
            description=f.message[:480],
        ))
        evidence.append(
            f"iac: {f.rule_id} @ {f.file}:{f.line or '?'} ({f.severity})"
        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(repo_path, method="IaC", probed_for="iac_misconfig")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation",
            target=repo_path,
            actor={"tool_name": "scan_iac"},
            input={"repo_path": repo_path},
            output={
                "files_scanned": len(report.files_scanned),
                "findings_total": len(report.findings),
                "critical_count": report.critical_count,
                "high_count": report.high_count,
                "findings_emitted": emitted_count,
            },
        )
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            [
                "for IaC findings with category=misconfig (CORS / "
                "TLS / headers), follow up with the matching DAST "
                "specialist on the deployed URL to confirm runtime "
                "exposure",
                "for category=open_redirect, send a probe to the "
                "matching redirect path with a controlled URL",
                "for category=info_disclosure (hardcoded secret), "
                "rotate the credential AND check breach corpora "
                "for prior public exposure",
            ]
            if drafts else
            [
                "no IaC misconfigs found in the bundled rule pack. "
                "Phase 11.2 (Checkov integration) will add 1500+ "
                "rules covering Terraform / k8s / cloud APIs."
            ]
        ),
        tool_metadata={
            "engine": "iac-v1",
            "files_scanned": len(report.files_scanned),
            "files_by_platform": report.files_by_platform,
            "findings_total": len(report.findings),
            "findings_by_platform": report.findings_by_platform,
            "critical_count": report.critical_count,
            "high_count": report.high_count,
            "findings_emitted_to_tracer": emitted_count,
            "errors": report.errors[:10],
        },
    )
