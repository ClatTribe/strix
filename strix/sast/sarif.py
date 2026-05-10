"""SARIF 2.1.0 output converter (Phase 7.5).

SARIF (Static Analysis Results Interchange Format) is the
industry-standard JSON format for static-analysis findings.
GitHub Code Scanning, Sonatype, and most enterprise SAST
dashboards consume SARIF natively. Shipping it as an output
option lets strix integrate into existing security-tooling
pipelines without bespoke glue.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html
JSON schema: https://json.schemastore.org/sarif-2.1.0.json

We emit a minimal but complete SARIF document covering:
  * `runs[].tool.driver` — name, version, info URI, full rule
    descriptors for every rule that produced a finding.
  * `runs[].results[]` — one entry per `SastFinding` with the
    `physicalLocation` shape (artifactLocation + region).
  * Per-result `level` (error/warning/note) mapped from severity
    AFTER calibration so consumers see the bumped/demoted
    values, not the raw Semgrep ones.
  * `runs[].results[].properties` — strix-specific metadata
    (CWE, calibration breadcrumb) so we don't lose it during
    SARIF round-trip.

Out of scope for v1:
  * Code-flow / data-flow `codeFlows` arrays (would need taint
    tracing — Phase 6.4 v2 / 7.4 v2 territory).
  * `fixes[]` autofix descriptors (we don't generate fixes yet;
    Phase 12).
  * `runs[].invocations[]` runtime details (CLI args, exit code).

These are SARIF-spec extensions; consumers tolerate their
absence. When Phase 6.4 v2 / 7.4 v2 / 12 land, this module
extends — the existing minimal output stays valid.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from strix.sast.semgrep_runner import SastFinding


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/"
    "schemas/sarif-schema-2.1.0.json"
)


# Severity → SARIF `level`. SARIF only has three levels (plus
# `none`); collapse our 5-tier ladder.
_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


# Severity → SARIF rank score (0-100). Used by some dashboards to
# sort findings within a level. We map our 5-tier ladder to the
# standard 20/40/60/80/100 scale.
_SEVERITY_TO_RANK: dict[str, float] = {
    "critical": 95.0,
    "high": 80.0,
    "medium": 60.0,
    "low": 40.0,
    "info": 20.0,
}


def _level_for(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get((severity or "").lower(), "warning")


def _rule_descriptor(finding: SastFinding) -> dict:
    """One-line `reportingDescriptor` per unique rule. SARIF
    de-dupes rules in `runs[].tool.driver.rules` and references
    them by index from each result. We keep it simple and emit
    one entry per (rule_id, message) pair encountered."""
    desc: dict = {
        "id": finding.rule_id,
        "shortDescription": {
            "text": (finding.message or finding.rule_id)[:200],
        },
        "fullDescription": {
            "text": finding.message or "",
        },
        "defaultConfiguration": {
            "level": _level_for(finding.severity),
            "rank": _SEVERITY_TO_RANK.get(finding.severity, 50.0),
        },
        "properties": {
            "tags": [],
            "vibe_pattern": bool(finding.metadata.get("vibe_pattern")),
        },
    }
    # SARIF tags are free-form strings; we map a few common ones
    # for compatibility with GitHub Code Scanning's category UI.
    if finding.cwe:
        desc["properties"]["security-severity"] = str(
            _SEVERITY_TO_RANK.get(finding.severity, 50.0)
        )
        desc["properties"]["cwe"] = finding.cwe
        desc["properties"]["tags"].append("security")
        desc["properties"]["tags"].append(finding.cwe.lower())
    if finding.category:
        desc["properties"]["tags"].append(finding.category)
    owasp = finding.metadata.get("owasp")
    if owasp:
        desc["properties"]["owasp"] = (
            owasp[0] if isinstance(owasp, list) else owasp
        )
    return desc


def _result_for(
    finding: SastFinding, rule_index: int, repo_path: str | None = None,
    calibration_note: str | None = None,
) -> dict:
    """One SARIF `result` per finding."""
    file_uri = finding.file or "(unknown)"
    # SARIF prefers repo-root-relative URIs without leading slash.
    if repo_path:
        try:
            f = Path(finding.file)
            if f.is_absolute():
                rel = f.resolve().relative_to(Path(repo_path).resolve())
                file_uri = str(rel)
        except (ValueError, OSError):
            pass

    out: dict = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _level_for(finding.severity),
        "rank": _SEVERITY_TO_RANK.get(finding.severity, 50.0),
        "message": {
            "text": finding.message or finding.rule_id,
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": file_uri,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": max(1, int(finding.line_start or 1)),
                    "endLine": max(
                        max(1, int(finding.line_start or 1)),
                        int(finding.line_end or finding.line_start or 1),
                    ),
                },
            },
        }],
        "properties": {
            "severity": finding.severity,
            "category": finding.category,
            "cwe": finding.cwe,
        },
    }
    if calibration_note:
        out["properties"]["calibration"] = calibration_note
    return out


def findings_to_sarif(
    findings: Iterable[SastFinding],
    *,
    tool_name: str = "strix-sast",
    tool_version: str = "0.1.0",
    info_uri: str = "https://github.com/ClatTribe/strix",
    repo_path: str | None = None,
    calibration_notes: dict[str, str] | None = None,
) -> dict:
    """Convert a sequence of `SastFinding` into a SARIF 2.1.0
    document.

    Args:
        findings: iterable of findings.
        tool_name: SARIF `tool.driver.name`. Default `"strix-sast"`.
        tool_version: SARIF `tool.driver.version`.
        info_uri: SARIF `tool.driver.informationUri`.
        repo_path: if provided, file URIs are normalised to
            paths relative to this root. SARIF consumers (GitHub
            Code Scanning especially) require repo-relative URIs.
        calibration_notes: optional dict keyed by `f"{rule_id}:
            {file}:{line_start}"` → calibration breadcrumb. When
            present, the breadcrumb attaches to the corresponding
            SARIF result's `properties.calibration` field so the
            wrapper can render WHY the severity changed.

    Returns:
        SARIF document as a Python dict. Caller serialises with
        `json.dumps(doc, indent=2)`.
    """
    findings_list = list(findings)

    # Deduplicate rules: SARIF references `rules[]` by index.
    rule_to_index: dict[str, int] = {}
    rules: list[dict] = []
    results: list[dict] = []

    for f in findings_list:
        if f.rule_id not in rule_to_index:
            rule_to_index[f.rule_id] = len(rules)
            rules.append(_rule_descriptor(f))
        idx = rule_to_index[f.rule_id]

        cal_key = f"{f.rule_id}:{f.file}:{f.line_start}"
        cal_note = (calibration_notes or {}).get(cal_key)
        results.append(_result_for(
            f, idx, repo_path=repo_path,
            calibration_note=cal_note,
        ))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": info_uri,
                    "rules": rules,
                },
            },
            "results": results,
            "originalUriBaseIds": (
                {"%SRCROOT%": {"uri": f"file://{repo_path}/"}}
                if repo_path else {}
            ),
            "columnKind": "utf16CodeUnits",
        }],
    }


def write_sarif(
    findings: Iterable[SastFinding],
    output_path: str | Path,
    *,
    tool_version: str = "0.1.0",
    repo_path: str | None = None,
    calibration_notes: dict[str, str] | None = None,
) -> Path:
    """Convert and write a SARIF document to disk.

    Returns the resolved output path. Pretty-prints with 2-space
    indentation (small enough that pretty is cheap; the file
    typically goes into a CI artifact bucket, where humans
    occasionally need to read it)."""
    doc = findings_to_sarif(
        findings,
        tool_version=tool_version,
        repo_path=repo_path,
        calibration_notes=calibration_notes,
    )
    p = Path(output_path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return p
