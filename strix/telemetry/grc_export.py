"""GRC-platform export renderers (roadmap §16 / PR #130).

Translates the engine's findings + control-mapping into the
platform-specific import schema that each GRC SaaS expects.
Static, no API calls — the operator (or wrapper) uploads the
file. Every B2B customer asks "do you integrate with $GRC_TOOL";
this lets the answer be "yes, the export goes here" without
per-platform live-API maintenance burden.

Supported platforms
-------------------

  * **Vanta** — JSON shape per Vanta's vulnerability-import API.
    https://developer.vanta.com/docs/vulnerabilities-overview
  * **Drata** — JSON per Drata's monitoring-import.
  * **Hyperproof** — JSON aligning with Hyperproof's evidence-
    import shape.
  * **Secureframe** — JSON per Secureframe's findings-ingest.
  * **ServiceNow GRC** — Flat-table JSON per ServiceNow's
    grc_finding ingest.
  * **Generic** — schema-neutral JSON usable by any platform that
    accepts custom-shape evidence (most do).

Why static formats vs. live APIs
--------------------------------

* No per-customer API-key plumbing on the engine side.
* No per-platform rate-limit handling — the wrapper / operator
  owns that.
* Easier auditor diff: the file is the artifact.
* No engine downtime when a platform rev-bumps its API.

The wrapper or operator uploads. Each platform's REST import
accepts a JSON file; pasting into a "Manual Evidence Upload" UI
also works. We deliberately produce one JSON per platform rather
than one file with all platforms' shapes — keeps the auditor's
mental model clean ("this file is the Vanta upload").
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable


logger = logging.getLogger(__name__)


# Severity → numeric for platforms that want CVSS-shaped scoring.
_SEVERITY_NUMERIC = {
    "info": 1.0,
    "low": 3.5,
    "medium": 6.0,
    "high": 8.5,
    "critical": 9.5,
}

# CWE → CVSS-vector hint for platforms that want a vector string.
# Coarse approximation; auditors care about the score not the vector.
_DEFAULT_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"


def _severity_score(finding: dict[str, Any]) -> float:
    sev = (finding.get("severity") or "").strip().lower()
    return _SEVERITY_NUMERIC.get(sev, 5.0)


# ---------------------------------------------------------------------------
# Per-platform renderers
# ---------------------------------------------------------------------------


def render_vanta(findings: list[dict[str, Any]], run_metadata: dict[str, Any]) -> dict[str, Any]:
    """Vanta vulnerability-import shape.

    Vanta accepts vulnerabilities with `external_id`, `severity`,
    `description`, and `evidence_url` per item. Multiple items
    per import call.
    """
    return {
        "format": "vanta",
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "vulnerabilities": [
            {
                "external_id": f.get("id"),
                "name": f.get("title", "")[:200],
                "severity": (f.get("severity") or "info").lower(),
                "cvss_score": _severity_score(f),
                "cve_id": f.get("cve"),
                "cwe_id": f.get("cwe"),
                "description": (f.get("description") or "")[:8000],
                "remediation": (f.get("recommended_action") or "")[:4000],
                "asset_url": f.get("target") or f.get("endpoint") or "",
                "verification_status": f.get("verification_status"),
                "first_detected": f.get("timestamp"),
            }
            for f in findings
        ],
        "scan_metadata": {
            "run_id": run_metadata.get("run_id"),
            "scan_mode": run_metadata.get("scan_mode"),
        },
    }


def render_drata(findings: list[dict[str, Any]], run_metadata: dict[str, Any]) -> dict[str, Any]:
    """Drata monitoring-import shape.

    Drata uses `evidence` as a top-level array; each item is an
    observation tied to a control. We attach `control_ids` from
    the engine's compliance_controls SOC 2 entries (Drata's
    primary framework).
    """
    return {
        "format": "drata",
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "evidence": [
            {
                "evidence_id": f.get("id"),
                "evidence_type": "scan_finding",
                "title": f.get("title"),
                "severity": (f.get("severity") or "info").lower(),
                "description": f.get("description"),
                "remediation": f.get("recommended_action"),
                "control_ids": (
                    (f.get("compliance_controls") or {}).get("soc2") or []
                ),
                "metadata": {
                    "cwe": f.get("cwe"),
                    "cve": f.get("cve"),
                    "verification_status": f.get("verification_status"),
                    "url": f.get("target") or f.get("endpoint"),
                    "data_classification": f.get("data_classification"),
                },
                "captured_at": f.get("timestamp"),
            }
            for f in findings
        ],
        "scan_run_id": run_metadata.get("run_id"),
    }


def render_hyperproof(findings: list[dict[str, Any]], run_metadata: dict[str, Any]) -> dict[str, Any]:
    """Hyperproof evidence-import shape.

    Hyperproof groups evidence by `control` and accepts metadata
    arrays. Multi-framework: we emit one record per finding per
    framework it implicates, so the same SQL injection ends up
    under SOC 2 CC6.1 AND PCI-DSS 6.5.1 if both are mapped.
    """
    records = []
    for f in findings:
        controls = f.get("compliance_controls") or {}
        any_emitted = False
        for framework in ("soc2", "pci_dss", "iso27001", "hipaa", "nist_800_53"):
            for control_id in controls.get(framework, []) or []:
                records.append({
                    "evidence_id": f"{f.get('id')}-{framework}-{control_id}",
                    "framework": framework,
                    "control": control_id,
                    "title": f.get("title"),
                    "severity": (f.get("severity") or "info").lower(),
                    "description": f.get("description"),
                    "remediation": f.get("recommended_action"),
                    "asset": f.get("target") or f.get("endpoint"),
                    "captured_at": f.get("timestamp"),
                })
                any_emitted = True
        # No control-mapping → emit a single record under "unmapped".
        if not any_emitted:
            records.append({
                "evidence_id": f"{f.get('id')}-unmapped",
                "framework": "unmapped",
                "control": None,
                "title": f.get("title"),
                "severity": (f.get("severity") or "info").lower(),
                "description": f.get("description"),
                "remediation": f.get("recommended_action"),
                "asset": f.get("target") or f.get("endpoint"),
                "captured_at": f.get("timestamp"),
            })

    return {
        "format": "hyperproof",
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "records": records,
        "scan_run_id": run_metadata.get("run_id"),
    }


def render_secureframe(findings: list[dict[str, Any]], run_metadata: dict[str, Any]) -> dict[str, Any]:
    """Secureframe findings-ingest shape.

    Secureframe wants `findings` array with `risk_level`, `cwe_id`,
    and `compliance_frameworks` per item.
    """
    return {
        "format": "secureframe",
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "findings": [
            {
                "id": f.get("id"),
                "name": f.get("title"),
                "risk_level": (f.get("severity") or "info").lower(),
                "cwe_id": f.get("cwe"),
                "cve_id": f.get("cve"),
                "description": f.get("description"),
                "remediation": f.get("recommended_action"),
                "asset": f.get("target") or f.get("endpoint"),
                "compliance_frameworks": list(
                    (f.get("compliance_controls") or {}).keys()
                ),
                "compliance_controls": f.get("compliance_controls") or {},
                "verification_status": f.get("verification_status"),
                "detected_at": f.get("timestamp"),
            }
            for f in findings
        ],
        "scan_run_id": run_metadata.get("run_id"),
    }


def render_servicenow(findings: list[dict[str, Any]], run_metadata: dict[str, Any]) -> dict[str, Any]:
    """ServiceNow GRC `grc_finding` ingest shape.

    ServiceNow wants flat-table records with stable column names.
    We map to the `vulnerable_item` table convention.
    """
    return {
        "format": "servicenow",
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "records": [
            {
                "u_short_description": (f.get("title") or "")[:160],
                "u_severity": (f.get("severity") or "info").upper(),  # ServiceNow uses LOW/MEDIUM/...
                "u_cwe_id": f.get("cwe") or "",
                "u_cve_id": f.get("cve") or "",
                "u_description": (f.get("description") or ""),
                "u_remediation": (f.get("recommended_action") or ""),
                "u_asset": (f.get("target") or f.get("endpoint") or ""),
                "u_state": (
                    "open"
                    if f.get("verification_status") in ("verified", "pattern_match")
                    else "review"
                ),
                "u_detected_at": f.get("timestamp"),
                "u_external_id": f.get("id"),
                "u_run_id": run_metadata.get("run_id"),
            }
            for f in findings
        ],
    }


def render_generic(findings: list[dict[str, Any]], run_metadata: dict[str, Any]) -> dict[str, Any]:
    """Schema-neutral JSON. Strix's own structured form, suitable
    for any platform that accepts custom-shape evidence (most do).
    Effectively findings.json from the compliance pack with a
    'generic' format tag."""
    return {
        "format": "generic",
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "run_id": run_metadata.get("run_id"),
        "run_name": run_metadata.get("run_name"),
        "scan_mode": run_metadata.get("scan_mode"),
        "scope_mode": run_metadata.get("scope_mode"),
        "targets": run_metadata.get("targets") or [],
        "count": len(findings),
        "findings": findings,
    }


_RENDERERS: dict[str, Callable[[list[dict[str, Any]], dict[str, Any]], dict[str, Any]]] = {
    "vanta": render_vanta,
    "drata": render_drata,
    "hyperproof": render_hyperproof,
    "secureframe": render_secureframe,
    "servicenow": render_servicenow,
    "generic": render_generic,
}

SUPPORTED_PLATFORMS: tuple[str, ...] = tuple(_RENDERERS.keys())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def export_for_platform(
    platform: str,
    *,
    findings: list[dict[str, Any]],
    run_metadata: dict[str, Any],
) -> dict[str, Any]:
    """Render the findings into the named platform's import shape.
    Raises ValueError when the platform isn't supported."""
    key = (platform or "").strip().lower()
    if key not in _RENDERERS:
        raise ValueError(
            f"Unsupported platform: {platform!r}. "
            f"Valid: {', '.join(SUPPORTED_PLATFORMS)}"
        )
    return _RENDERERS[key](findings, run_metadata)


def write_export(
    platform: str,
    *,
    findings: list[dict[str, Any]],
    run_metadata: dict[str, Any],
    output_path: str | Path,
) -> dict[str, Any]:
    """Render and write to disk. Returns `{platform, output_path,
    record_count}`."""
    rendered = export_for_platform(
        platform, findings=findings, run_metadata=run_metadata
    )
    out = Path(output_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(rendered, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    # record_count is platform-dependent — prefer top-level
    # `findings`/`vulnerabilities`/`evidence`/`records`.
    count = (
        len(rendered.get("findings") or [])
        or len(rendered.get("vulnerabilities") or [])
        or len(rendered.get("evidence") or [])
        or len(rendered.get("records") or [])
    )
    return {
        "platform": platform,
        "output_path": str(out),
        "record_count": count,
    }
