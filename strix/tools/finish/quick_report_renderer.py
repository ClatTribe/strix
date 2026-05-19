"""Templated quick-mode report renderer — V3-3 of the quick-mode
lightweight plan (docs/proposals/2026-05-19-quick-mode-lightweight.md).

## Why this exists

The `finish_scan` tool requires four prose fields:
`executive_summary`, `methodology`, `technical_analysis`,
`recommendations`. In standard / deep mode the lead LLM
synthesizes them from accumulated context — that's 3-8 LLM calls
in the report phase. In quick mode the threat model is
"deterministic findings only," and most of that prose is
boilerplate that can be templated from `findings.json` + the
v2-step-7 CWE templates with zero LLM calls.

## What this module does

Given the tracer's accumulated state (vulnerability_reports +
scan_config + run_metadata), produce a fully-formed dict matching
the shape `finish_scan` expects — ready to drop into
`tracer.update_scan_final_fields`.

The output is deterministic, byte-stable for a given findings
set, and entirely template-driven (zero LLM calls).

## Recall-safety contract

* The renderer NEVER fabricates findings — it reads
  `tracer.vulnerability_reports` verbatim and groups by severity
  / category.
* When `findings.json` is empty, the templated summary explicitly
  says "no findings emitted by the deterministic stack" — it
  doesn't hide the empty result behind generic prose.
* Per-finding remediation references the v2-step-7 CWE template
  fields (`recommended_action`, `fix_time_estimate`) when present;
  silent fall-through to the finding's own remediation_steps
  otherwise.
* Standard / deep modes never reach this code path — gated at
  the `finish_scan` integration point.

## Kill switch

`STRIX_QUICK_TEMPLATED_REPORT_DISABLED=1` skips the templated
renderer; the lead must provide all four fields itself the same
as standard / deep.
"""

from __future__ import annotations

import os
from typing import Any


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def is_disabled() -> bool:
    """Returns True when `STRIX_QUICK_TEMPLATED_REPORT_DISABLED` is
    truthy. Default is enabled (when scan_mode == quick)."""
    return os.environ.get(
        "STRIX_QUICK_TEMPLATED_REPORT_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def is_quick_mode() -> bool:
    """Returns True when the active scan is in quick / initial
    mode. The renderer only fires in those modes."""
    mode = (os.environ.get("STRIX_SCAN_MODE") or "").strip().lower()
    return mode in ("quick", "initial")


def _group_findings_by_severity(
    findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "").strip().lower() or "info"
        if sev not in out:
            sev = "info"
        out[sev].append(f)
    return out


def _format_targets(scan_config: dict[str, Any] | None) -> str:
    """Render the scan's targets as a short string. Tolerant to
    multiple shapes (legacy single-target, paired-asset list)."""
    if not scan_config:
        return "the configured target(s)"
    targets = scan_config.get("targets") or []
    if not targets:
        return "the configured target(s)"
    out: list[str] = []
    for t in targets:
        if isinstance(t, dict):
            v = t.get("original") or t.get("value") or t.get("target") or t.get("url")
            if isinstance(v, str) and v.strip():
                out.append(v.strip())
        elif isinstance(t, str) and t.strip():
            out.append(t.strip())
    if not out:
        return "the configured target(s)"
    if len(out) == 1:
        return out[0]
    return f"{len(out)} targets ({', '.join(out[:3])}{'…' if len(out) > 3 else ''})"


def render_executive_summary(
    findings: list[dict[str, Any]],
    scan_config: dict[str, Any] | None,
) -> str:
    """One-paragraph executive summary. Lists scope + counts +
    highest severity. Deterministic + short."""
    targets = _format_targets(scan_config)
    if not findings:
        return (
            f"Quick-mode scan of {targets} completed with no findings "
            "from the deterministic stack. Quick mode does not cover "
            "reasoning-bound vulnerability classes (BOLA / BFLA / mass "
            "assignment / business logic) — for those, re-run in "
            "standard or deep mode."
        )

    grouped = _group_findings_by_severity(findings)
    counts = {s: len(grouped[s]) for s in _SEVERITY_ORDER if grouped[s]}
    counts_str = ", ".join(f"{n} {sev}" for sev, n in counts.items())
    highest = next(s for s in _SEVERITY_ORDER if grouped[s]) if counts else "info"

    return (
        f"Quick-mode scan of {targets} surfaced {len(findings)} "
        f"finding(s) ({counts_str}). Highest severity: {highest}. "
        "All findings were confirmed by deterministic specialists "
        "(SAST / SCA / nuclei templates / payload-oracle scanners). "
        "Quick mode does not cover reasoning-bound classes — re-run "
        "in standard or deep mode for BOLA / BFLA / mass assignment "
        "/ business logic coverage."
    )


def render_methodology(scan_config: dict[str, Any] | None) -> str:
    """The methodology block is stable across quick-mode runs:
    deterministic recon + deterministic specialists, with the
    lead orchestrating but not running fresh-context dispatches."""
    return (
        "Quick-mode methodology:\n"
        "1. Recon — deterministic pipelines (httpx + subfinder + nuclei "
        "tech-stack fingerprint + SCA / SAST / IaC scans where the "
        "target type permits).\n"
        "2. Surface mapping — endpoint inventory + auth-flow detection "
        "from recon output, no LLM-driven crawling.\n"
        "3. Probing — deterministic specialists "
        "(scan_sqli / scan_xss / scan_idor / scan_path_traversal / "
        "scan_ssrf / scan_nuclei_templates) invoked per endpoint.\n"
        "4. Verification — findings emitted by deterministic specialists "
        "are auto-verified at the oracle level (payload reflected, "
        "time-based delta, static-analysis taint, CVE match).\n"
        "5. Report — this template, rendered from findings.json with "
        "zero LLM calls.\n\n"
        "NOT in quick-mode scope: multi-step LLM specialist dispatches, "
        "business-logic exploitation, attack-chain synthesis. For those, "
        "re-run in standard or deep mode."
    )


def render_technical_analysis(
    findings: list[dict[str, Any]],
) -> str:
    """A per-severity, per-finding technical breakdown. Reuses the
    specialist's own `description` + `technical_analysis` for each
    finding — those fields are already filled at emit time."""
    if not findings:
        return (
            "No findings were emitted by the deterministic specialist "
            "stack during this quick-mode scan. The absence of findings "
            "does not imply absence of vulnerabilities — quick mode is "
            "deliberately scoped to deterministic detection. Re-run in "
            "standard or deep mode for the reasoning-bound classes."
        )

    grouped = _group_findings_by_severity(findings)
    sections: list[str] = []
    for sev in _SEVERITY_ORDER:
        items = grouped[sev]
        if not items:
            continue
        sections.append(f"\n## {sev.upper()} ({len(items)} finding(s))\n")
        for f in items:
            title = f.get("title") or "Untitled finding"
            endpoint = f.get("endpoint") or f.get("target") or "(unknown target)"
            cwe = f.get("cwe") or ""
            short_desc = (f.get("description") or "").strip()
            # Trim very long descriptions to keep the report scannable;
            # full text remains in findings.json.
            if len(short_desc) > 280:
                short_desc = short_desc[:277] + "…"
            cwe_tag = f" [{cwe}]" if cwe else ""
            sections.append(
                f"- **{title}**{cwe_tag} on `{endpoint}`\n  {short_desc}"
            )
    return "Technical analysis\n" + "\n".join(sections)


def render_recommendations(findings: list[dict[str, Any]]) -> str:
    """Per-finding remediation guidance. Reuses the v2-step-7 CWE
    template fields when present, falls back to the finding's
    own `remediation_steps` / `recommended_action`."""
    if not findings:
        return (
            "No remediation actions required from this scan. "
            "Consider re-running in standard or deep mode for "
            "reasoning-bound coverage."
        )

    lines: list[str] = ["Prioritized remediation (by severity):\n"]
    grouped = _group_findings_by_severity(findings)
    for sev in _SEVERITY_ORDER:
        items = grouped[sev]
        if not items:
            continue
        lines.append(f"\n**{sev.upper()}**\n")
        for f in items:
            title = f.get("title") or "Untitled finding"
            action = (
                f.get("recommended_action")
                or f.get("remediation_steps")
                or "See finding entry in findings.json for remediation guidance."
            )
            # Keep each action a single short paragraph
            action = (action or "").strip().split("\n\n", 1)[0]
            if len(action) > 320:
                action = action[:317] + "…"
            fix_time = f.get("fix_time_estimate")
            time_tag = f" (est. {fix_time})" if fix_time else ""
            lines.append(f"- **{title}**{time_tag}\n  {action}")
    return "\n".join(lines)


def render_quick_report(
    findings: list[dict[str, Any]],
    scan_config: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Top-level entry point. Returns a dict with the four prose
    fields `finish_scan` expects. The returned strings are
    deterministic + non-empty (passes `finish_scan`'s validation
    untouched)."""
    return {
        "executive_summary": render_executive_summary(findings, scan_config),
        "methodology": render_methodology(scan_config),
        "technical_analysis": render_technical_analysis(findings),
        "recommendations": render_recommendations(findings),
    }


def should_apply_template() -> bool:
    """The gate `finish_scan` checks before invoking the renderer."""
    if is_disabled():
        return False
    return is_quick_mode()
