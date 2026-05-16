"""LLM-facing specialist: run nuclei templates against a target.

Iterates the local nuclei-templates corpus filtered by tags /
severity / template_ids, runs each against `url`, and emits one
finding per matched template. Auto-injects auth from
SecurityContext.AuthState; records decision_log + per-target
probed_for=nuclei_runner.

The specialist is `llm=False` (deterministic) — the intelligence is
in the corpus + matcher rules, not in any agent loop. The LLM uses
this as a single tool call that fans out to thousands of probes
without paying token cost per template.

Cost / scope control
--------------------

By default we cap at 200 templates per call (the lead can request
more via `max_templates=`). The lead is expected to filter by tags
or severity to focus the run:

  * `tags=["cve", "apache"]`        — CVE templates affecting Apache
  * `severity=["critical", "high"]` — high-impact only
  * `template_ids=["log4j-rce", ...]` — specific templates

Without a corpus on disk, the call returns `status=partial` with a
hint to run `python -m strix.tools.nuclei_runner.refresh`.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from strix.tools.nuclei_runner.interpreter import run_template
from strix.tools.nuclei_runner.parser import parse_template_dir
from strix.tools.nuclei_runner.refresh import templates_dir
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Map nuclei severity → strix severity (mostly identical; nuclei
# uses "info" which we collapse to "low" in some contexts).
_SEV_MAP = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "info",
}


def _emit_finding(
    *,
    url: str,
    template,
    result,
) -> str | None:
    """Emit a CWE/CVE-tagged finding for one matched template."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        sev = _SEV_MAP.get(template.info.severity, "medium")
        # Pick the first CVE/CWE in the template if any.
        cve = template.info.cve_id[0] if template.info.cve_id else None
        cwe = template.info.cwe_id[0] if template.info.cwe_id else None
        if not cwe:
            # Nuclei templates without an explicit CWE are still
            # vuln-shaped — fall back to CWE-1390 (other) so the
            # `record_finding_in_kg` Vuln node has a typed CWE.
            cwe = "CWE-1390"
        ref_block = ""
        if template.info.reference:
            ref_block = "\n".join(
                f"  * {r}" for r in template.info.reference[:5]
            )
        tags_block = ", ".join(template.info.tags[:8])

        title = (
            template.info.name
            or f"Nuclei template {template.id}"
        ) + f" — confirmed at `{url}`"
        report_id = tracer.add_vulnerability_report(
            title=title,
            severity=sev,
            cwe=cwe,
            endpoint=url,
            target=url,
            category="nuclei",
            verification_status="verified",
            confidence=0.92,
            description=(
                f"Nuclei template `{template.id}` matched at `{url}`. "
                f"{template.info.description}"
                + (f"\n\nReferences:\n{ref_block}" if ref_block else "")
            ),
            impact=(
                f"Detected via the nuclei-templates corpus. Tags: "
                f"{tags_block or '(none)'}. "
                + (f"Tied to {cve}." if cve else "")
                + " Refer to the linked references for the full "
                + "exploitation chain and impact."
            ),
            technical_analysis=(
                f"Template id: {template.id}\n"
                f"Template path: {template.file_path}\n"
                f"Severity: {template.info.severity}\n"
                f"Matched request index: {result.matched_request_index}\n"
                f"Matched URL: {result.matched_path}\n"
                f"Status: {result.response_status}\n"
                f"Matchers fired: {result.matched_matchers}\n"
                f"Response excerpt:\n{result.response_body_excerpt[:1500]}"
            ),
            poc_description=(
                "Run the template manually to reproduce:\n"
                f"  nuclei -t {template.file_path} -u {url}"
            ),
            poc_script_code=f"nuclei -t {template.file_path} -u {url}",
            remediation_steps=(
                "Apply the patch / configuration change indicated by "
                "the template's references. For CVE templates, "
                "consult the vendor advisory and update to the "
                "patched version."
            ),
            cvss_breakdown=None,
            reasoning_trace=[
                f"Nuclei template `{template.id}` matched.",
                f"Severity per template metadata: {template.info.severity}.",
                f"Matchers that fired: {result.matched_matchers}.",
                "Auto-emitted from scan_nuclei_templates."
                + (f" CVE: {cve}." if cve else ""),
            ],
        )

        # Populate the KG so the finding chains into cross-tool
        # graph queries + the CVE-relevance evaluator can see
        # nuclei-matched CVEs against the customer's inventory.
        try:
            from strix.agents.kg_emit import record_finding_in_kg

            record_finding_in_kg(
                finding_id=report_id,
                url=url,
                # Nuclei doesn't expose a single "vulnerable param" —
                # use the template id as the surface differentiator
                # so multiple templates against the same URL stay
                # distinguishable in the graph.
                param=template.id,
                cwe=cwe,
                severity=sev,
                category="nuclei",
                method="GET",
                detection_kind=(
                    "cve" if cve else "template_match"
                ),
                confidence=0.92,
            )
        except Exception:  # noqa: BLE001
            logger.debug("nuclei_runner: KG emit failed", exc_info=True)

        return report_id
    except Exception as e:  # noqa: BLE001
        logger.debug("nuclei_runner: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="nuclei-runner",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 600},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190", "T1592"],
)
def scan_nuclei_templates(
    *,
    url: str,
    tags: list[str] | None = None,
    severity: list[str] | None = None,
    template_ids: list[str] | None = None,
    max_templates: int = 200,
    extra_headers: dict[str, str] | None = None,
    timeout_seconds: float = 15.0,
) -> SpecialistResult:
    """Run nuclei templates against `url`. Closes the static-payload
    gap: the corpus updates daily without us shipping new code.

    Args:
        url: target URL.
        tags: filter to templates with at least one matching tag
            (e.g. ["cve", "apache", "rce"]). Case-insensitive.
        severity: filter to {info, low, medium, high, critical}.
        template_ids: run only these specific templates.
        max_templates: cap (default 200). Lower for fast scans,
            raise for thorough sweeps. Caps fan-out cost.
        extra_headers: forwarded as auth / custom headers.
        timeout_seconds: per-request timeout.

    Returns:
        SpecialistResult. Auto-emits one finding per matched
        template. Returns `status=partial` when the corpus isn't
        on disk.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    corpus = templates_dir()
    if not corpus.exists():
        return SpecialistResult(
            status="partial",
            error=(
                f"nuclei-templates corpus not found at {corpus}. "
                "Run `python -m strix.tools.nuclei_runner.refresh` "
                "to clone (~150MB; daily incremental after that)."
            ),
            evidence=[
                "scan_nuclei_templates needs a local clone of "
                "https://github.com/projectdiscovery/nuclei-templates"
            ],
            next_probes_suggested=[
                "set STRIX_NUCLEI_TEMPLATES_DIR=/path/to/corpus or "
                "run the refresh CLI"
            ],
        )

    # Auto-include captured auth.
    extra_headers = dict(extra_headers or {})
    if "Authorization" not in extra_headers and "authorization" not in {
        h.lower() for h in extra_headers
    }:
        try:
            from strix.agents.security_context import list_auth_states
            for state in list_auth_states():
                if state.bearer:
                    extra_headers["Authorization"] = f"Bearer {state.bearer}"
                    break
                if state.cookies:
                    extra_headers["Cookie"] = "; ".join(
                        f"{k}={v}" for k, v in state.cookies.items()
                    )
                    break
        except Exception:  # noqa: BLE001
            pass

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    templates_run = 0
    templates_skipped_unsupported = 0
    started = time.monotonic()

    for tpl in parse_template_dir(
        corpus,
        tags=tags,
        severity=severity,
        template_ids=template_ids,
        only_supported=True,
        max_templates=max_templates,
    ):
        # Best-effort: per-template wall-time guard so a single
        # slow target doesn't burn the whole budget.
        if time.monotonic() - started > 600:
            evidence.append(
                "stopped early at 600s wall-time cap; raise "
                "default_budget.max_wall_seconds for longer sweeps"
            )
            break

        result = run_template(
            tpl,
            target_url=url,
            extra_headers=extra_headers,
            timeout_seconds=timeout_seconds,
        )
        templates_run += 1
        if result.error and "unsupported" in result.error:
            templates_skipped_unsupported += 1
            continue
        if not result.matched:
            continue

        rid = _emit_finding(url=url, template=tpl, result=result)
        if rid:
            emitted_count += 1
        sev = _SEV_MAP.get(tpl.info.severity, "medium")
        cwe = tpl.info.cwe_id[0] if tpl.info.cwe_id else None
        drafts.append(FindingDraft(
            title=(
                (tpl.info.name or f"Nuclei template {tpl.id}")
                + f" at `{url}`"
            )[:480],
            severity=sev,
            cwe=cwe,
            endpoint=url,
            category="nuclei",
            verification_status="verified",
            confidence=0.92,
            description=(
                f"Nuclei `{tpl.id}` matched ("
                f"matchers: {result.matched_matchers})"
            )[:8000],
        ))
        evidence.append(
            f"matched template={tpl.id} severity={tpl.info.severity} "
            f"path={result.matched_path}"
        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="GET", probed_for="nuclei_runner")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation",
            target=url,
            actor={"tool_name": "scan_nuclei_templates"},
            input={
                "tags": list(tags or []),
                "severity": list(severity or []),
                "template_ids": list(template_ids or []),
                "max_templates": max_templates,
            },
            output={
                "templates_run": templates_run,
                "findings_emitted": emitted_count,
                "drafts": len(drafts),
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
                "expand the run — drop filters or raise "
                "max_templates for thorough coverage",
                "if a CVE template fired, follow up with "
                "lookup_known_cves to gauge active exploitation",
            ]
            if drafts else
            [
                "no nuclei templates fired; try broader filters "
                "(e.g. tags=[\"cve\"]) or specific template_ids",
                "verify the corpus is fresh: `python -m "
                "strix.tools.nuclei_runner.refresh --status`",
            ]
        ),
        tool_metadata={
            "templates_run": templates_run,
            "templates_skipped_unsupported": templates_skipped_unsupported,
            "tags_filter": list(tags or []),
            "severity_filter": list(severity or []),
            "findings_emitted_to_tracer": emitted_count,
            "elapsed_seconds": round(time.monotonic() - started, 2),
        },
    )
