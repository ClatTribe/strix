"""LLM-facing SAST specialist (Phase 7.1).

`scan_sast` walks a repo, runs Semgrep with our bundled
vibe-coded rule pack + the OWASP-Top-Ten registry pack, calibrates
severity (route-reachable bump, test-file demote), and emits one
finding per result.

Cross-asset routing per §4a:
  * Anchor-tool for `repository` / `local_code` AFTER
    `scan_sca_lockfiles` (deps before code; SCA findings are
    cheaper).
  * SAST sinks ↔ DAST cross-asset chain: a finding here on a
    request handler is the strongest single SAST→DAST signal.

Graceful degradation: if Semgrep isn't installed, returns
`status="partial"` with a clear "install semgrep" hint rather
than erroring. The lead-agent loop sees the partial and can
either fall back to other specialists or surface the gap to the
user via the wrapper.
"""

from __future__ import annotations

import logging
from pathlib import Path

from strix.sast.calibrate import calibrate_finding_severity, load_code_map
from strix.sast.diff import git_changed_files
from strix.sast.semgrep_runner import (
    SastFinding,
    SemgrepResult,
    is_semgrep_available,
    run_semgrep,
)
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


def _emit_finding(
    *, finding: SastFinding, calibrated_severity: str,
    repo_path: str, calibration_rationale: str,
) -> str | None:
    """Emit one SAST finding to the tracer."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        title = (
            f"{finding.rule_id} — {finding.message[:160]}"
        )[:480]
        report_id = tracer.add_vulnerability_report(
            title=title,
            severity=calibrated_severity,
            cwe=finding.cwe,
            endpoint=f"{finding.file}:{finding.line_start}",
            target=repo_path,
            category=finding.category or "sast",
            cve=None,
            cvss=None,
            verification_status="pattern_match",
            confidence=0.85,
            description=(
                f"SAST rule `{finding.rule_id}` matched at "
                f"`{finding.file}:{finding.line_start}-"
                f"{finding.line_end}`.\n\n"
                f"{finding.message}"
            ),
            impact=(
                "SAST findings are pattern matches against source "
                "code — they identify a vulnerable shape, not a "
                "confirmed exploit. The right next step:\n\n"
                "  * For request-handler files: send a probe to the "
                "matching endpoint with the relevant DAST specialist "
                "(scan_sqli / scan_xss / scan_path_traversal etc.).\n"
                "  * For non-handler files: confirm the function is "
                "reachable from a route handler by reading its "
                "callers; if dead code, demote the finding."
            ),
            technical_analysis=(
                f"Rule: {finding.rule_id}\n"
                f"File: {finding.file}\n"
                f"Lines: {finding.line_start}-{finding.line_end}\n"
                f"Language: {finding.language or '(unknown)'}\n"
                f"CWE: {finding.cwe or '(none mapped)'}\n"
                f"Category: {finding.category or '(generic)'}\n"
                f"Calibrated severity: {calibrated_severity} "
                f"(raw: {finding.severity})\n"
                f"Calibration: {calibration_rationale}\n"
            ),
            poc_description=(
                f"1. Open `{finding.file}` and read line "
                f"{finding.line_start}.\n"
                f"2. Identify the user-controlled input feeding "
                f"the matched pattern.\n"
                f"3. If the file is a request handler, follow up "
                f"with the matching DAST specialist to confirm "
                f"end-to-end exploitability.\n"
                f"4. If the file is not handler-reachable, treat "
                f"as a low-priority code-quality finding."
            ),
            poc_script_code="",
            remediation_steps=(
                f"1. Apply the fix the rule message suggests.\n"
                f"2. Re-run `scan_sast` on this file to confirm the "
                f"rule no longer matches.\n"
                f"3. If the fix involves an architectural change "
                f"(e.g. moving auth into middleware), open "
                f"hypotheses for the related routes that may now "
                f"need similar treatment."
            ),
            cvss_breakdown=None,
        )

        # KG: code-location surface (not URL-shaped). The tracer's
        # URL-auto-emit skips this finding because the endpoint is
        # `file:line` not http(s). We add the code-shape triple
        # here so cross-tool chaining can see SAST hits.
        try:
            from strix.agents.kg_emit import record_code_finding_in_kg

            record_code_finding_in_kg(
                finding_id=report_id,
                file_path=finding.file,
                start_line=finding.line_start,
                end_line=finding.line_end,
                cwe=finding.cwe or "CWE-1390",
                severity=calibrated_severity,
                category=finding.category or "sast",
                rule_id=finding.rule_id,
                confidence=0.85,
            )
        except Exception:  # noqa: BLE001
            logger.debug("sast: KG code-finding emit failed", exc_info=True)

        return report_id
    except Exception as e:  # noqa: BLE001
        logger.debug("sast emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="sast-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 600},
    sandbox_execution=True,
    provenance="framework",
    mitre_techniques=["T1059"],   # Command + Scripting Interpreter
)
def scan_sast(
    *,
    repo_path: str,
    since_commit: str | None = None,
    until_commit: str = "HEAD",
    extra_configs: list[str] | None = None,
    timeout: int = 600,
    max_findings: int = 200,
    sarif_output_path: str | None = None,
) -> SpecialistResult:
    """Run Semgrep on a repo with the strix vibe-coded rule pack
    and emit one finding per result.

    Args:
        repo_path: directory to analyse.
        since_commit: when set, scan only files changed between
            `since_commit` and `until_commit` (Phase 7.3 diff-aware
            mode). Default None → scan the whole repo.
        until_commit: tip ref for the diff. Default `HEAD`.
        extra_configs: additional Semgrep rule sources (file/dir
            paths or registry refs like `"p/django"`). Appended
            AFTER the bundled vibe-coded pack + OWASP-Top-Ten.
        timeout: hard wall-clock cap on the Semgrep invocation.
        max_findings: hard cap on findings emitted (bound LLM
            context). When exceeded, severity-descending sort is
            applied so highest-priority findings keep their slot.
        sarif_output_path: when set, write a SARIF 2.1.0 document
            with all findings + calibration breadcrumbs to this
            path (Phase 7.5). Required for GitHub Code Scanning
            integration. Severity used in SARIF is the calibrated
            severity, so dashboards see post-Phase-7.4 numbers.

    Findings are severity-calibrated:
      * Route-reachable file        → +1 tier (capped at critical)
      * Test-file location          → -1 tier (capped at info)
      * KEV / EPSS overrides don't apply (those are dep-CVE
        concepts, not source-code).
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

    if not is_semgrep_available():
        return SpecialistResult(
            status="partial",
            error=(
                "semgrep CLI not installed — SAST analysis skipped. "
                "Install with `pip install semgrep` (Python ≥ 3.8) "
                "to enable Phase 7 SAST findings."
            ),
            evidence=[
                "scan_sast: semgrep not on PATH; returning partial "
                "so the lead can fall back to other specialists "
                "rather than treat this as a fatal scan error."
            ],
            tool_metadata={
                "engine": "semgrep",
                "engine_available": False,
                "diff_aware": since_commit is not None,
            },
        )

    # Resolve targets — full repo, or diff-scoped subset.
    targets: list[str] = []
    diff_scope_meta: dict = {"applied": False}
    if since_commit:
        scope = git_changed_files(
            repo, since_commit=since_commit,
            until_commit=until_commit,
        )
        diff_scope_meta = {
            "applied": scope.usable,
            "files_in_diff": len(scope.files) if scope.usable else 0,
            "error": scope.error,
        }
        if scope.usable:
            if not scope.files:
                # Diff was clean — nothing source-relevant changed.
                return SpecialistResult(
                    status="ok",
                    findings=[],
                    evidence=[
                        f"scan_sast: diff {since_commit}..{until_commit} "
                        f"contains no SAST-relevant source files; "
                        f"nothing to scan."
                    ],
                    tool_metadata={
                        "engine": "semgrep",
                        "engine_available": True,
                        "diff_scope": diff_scope_meta,
                        "files_scanned": 0,
                        "rules_run": 0,
                        "findings_emitted_to_tracer": 0,
                    },
                )
            # Resolve to absolute paths for Semgrep.
            targets = [str(repo / f) for f in scope.files]
        else:
            # Diff resolution failed — fall back to full repo
            # scan rather than scanning nothing. This is the
            # safe failure mode.
            logger.info(
                "scan_sast: diff resolution failed (%s); "
                "falling back to full repo scan",
                scope.error,
            )
    if not targets:
        targets = [str(repo)]

    result: SemgrepResult = run_semgrep(
        targets, configs=None if extra_configs is None else None,
        extra_args=None, timeout=timeout,
    )
    # Append extra_configs as a second invocation? Simpler: wire
    # into `configs`. The default already includes vibe + OWASP;
    # extra_configs supplements.
    if extra_configs:
        # Re-run with the extra configs (Semgrep supports multiple
        # `--config` flags, but our `run_semgrep` API takes a list).
        # We do a second invocation and merge findings.
        extra_result = run_semgrep(
            targets, configs=extra_configs, timeout=timeout,
        )
        if extra_result.status == "ok":
            result.findings.extend(extra_result.findings)

    if result.status == "error":
        return SpecialistResult(
            status="error",
            error=result.error,
            tool_metadata={
                "engine": "semgrep",
                "engine_available": True,
                "diff_scope": diff_scope_meta,
            },
        )

    # Severity calibration — load code_map once, apply per finding.
    code_map = load_code_map(repo)
    calibrated_count = {"bumped": 0, "demoted": 0, "unchanged": 0}

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    severity_rank = {
        "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
    }

    # Calibrate first so we can sort by calibrated severity.
    annotated: list[tuple[SastFinding, str, str]] = []
    for f in result.findings:
        cal = calibrate_finding_severity(f, code_map=code_map)
        if cal.bumped:
            calibrated_count["bumped"] += 1
        elif cal.demoted:
            calibrated_count["demoted"] += 1
        else:
            calibrated_count["unchanged"] += 1
        annotated.append((f, cal.severity, cal.rationale))

    annotated.sort(
        key=lambda t: -severity_rank.get(t[1], 0),
    )
    annotated = annotated[:max_findings]

    for f, sev, rationale in annotated:
        rid = _emit_finding(
            finding=f, calibrated_severity=sev,
            repo_path=repo_path,
            calibration_rationale=rationale,
        )
        if rid:
            emitted_count += 1
        title = f"{f.rule_id} — {f.message[:120]}"
        if sev != f.severity:
            title += f" [calibrated:{f.severity}→{sev}]"
        drafts.append(FindingDraft(
            title=title[:480],
            severity=sev,
            cwe=f.cwe,
            endpoint=f"{f.file}:{f.line_start}",
            category=f.category or "sast",
            verification_status="pattern_match",
            confidence=0.85,
            description=f.message[:480],
        ))
        evidence.append(
            f"sast: {f.rule_id} @ {f.file}:{f.line_start} "
            f"({f.severity}{'→' + sev if sev != f.severity else ''})"
        )

    # ----- Phase 7.5: SARIF output -----
    # Emit AFTER calibration so dashboard severities reflect post-
    # 7.4 numbers, not raw Semgrep output. Calibration breadcrumbs
    # attach via the (rule:file:line) key so consumers see WHY a
    # severity changed.
    sarif_path_written: str | None = None
    if sarif_output_path:
        try:
            from strix.sast.sarif import write_sarif as _write_sarif

            cal_notes = {
                f"{f.rule_id}:{f.file}:{f.line_start}": rationale
                for f, sev, rationale in annotated
                if rationale and rationale != ""
            }
            # Promote each finding's calibrated severity into the
            # SastFinding before writing SARIF, so SARIF's `level`
            # reflects the post-Phase-7.4 value.
            calibrated_findings = []
            for f, sev, _rationale in annotated:
                from dataclasses import replace
                calibrated_findings.append(replace(f, severity=sev))
            written = _write_sarif(
                calibrated_findings,
                sarif_output_path,
                repo_path=repo_path,
                calibration_notes=cal_notes,
            )
            sarif_path_written = str(written)
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "sarif write failed for %s: %s",
                sarif_output_path, e, exc_info=True,
            )

    # SecurityContext + decision_log — same pattern as scan_sca_lockfiles.
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(repo_path, method="SAST", probed_for="sast_finding")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation",
            target=repo_path,
            actor={"tool_name": "scan_sast"},
            input={
                "repo_path": repo_path,
                "since_commit": since_commit,
                "until_commit": until_commit,
                "diff_scope_applied": diff_scope_meta.get("applied"),
            },
            output={
                "files_scanned": result.files_scanned,
                "rules_run": result.rules_run,
                "findings_total": len(result.findings),
                "findings_emitted": emitted_count,
                "calibration": calibrated_count,
            },
        )
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok" if result.status == "ok" else "partial",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            [
                "for SAST findings on request-handler files, follow "
                "up with the matching DAST specialist (scan_sqli / "
                "scan_xss / scan_path_traversal etc.) to confirm "
                "end-to-end exploitability",
                "for SAST findings on dep-CVE-tagged files, "
                "cross-reference with `scan_sca_lockfiles` to confirm "
                "the same package is the source",
            ]
            if drafts else
            [
                "no SAST findings — try expanding the rule corpus "
                "with `extra_configs=['p/javascript', 'p/python']` "
                "if the engine seems too quiet",
            ]
        ),
        tool_metadata={
            "engine": "semgrep",
            "engine_available": True,
            "diff_scope": diff_scope_meta,
            "files_scanned": result.files_scanned,
            "rules_run": result.rules_run,
            "config_paths": result.config_paths,
            "findings_total": len(result.findings),
            "findings_emitted_to_tracer": emitted_count,
            "calibration": calibrated_count,
            "sarif_output_path": sarif_path_written,
        },
    )
