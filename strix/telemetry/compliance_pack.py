"""Compliance evidence-pack writer (roadmap §16 / PR #129).

When `--compliance-pack <dir>` is passed, Strix writes a complete
self-contained audit bundle to `<dir>/<run_id>/`:

  * `report.md` — human-readable rendered report (already in main
    flow; we copy it here)
  * `findings.csv` — flat CSV of every finding
  * `findings.json` — full structured findings dump (vulnerabilities.json)
  * `scope.json` — the scan scope (targets + scan_mode + scope_mode)
  * `scan_metadata.json` — run_meta.json copy + key-value summary
  * `control_attestation.md` — per-framework rollup: "SOC 2 CC6.6:
    12 checks tested, 2 findings, 10 clean assertions"
  * `signature.txt` — detached signature over the bundle's manifest
    (composes with the audit-trail signing in #127)
  * `manifest.json` — sha256 of every file + bundle metadata

Why a separate bundle vs. raw run dir
-------------------------------------

The strix run dir contains operational artifacts (events.jsonl,
debug logs, intermediate state). The auditor wants a deterministic,
date-stamped, content-addressable subset. Copying the right files
into `<dir>/<run_id>/` lets the operator hand the directory to
the auditor without redacting operational noise.

Why the manifest is signed
--------------------------

The audit-trail signing (#127) signs `events.jsonl`'s chain. The
compliance pack signing (here) signs the bundle's manifest — a
file-by-file SHA-256 list. Together they prove (a) the events
weren't tampered with mid-run, AND (b) the bundle handed to the
auditor is the same one Strix wrote. Detached signature over
manifest.json reuses the same `sign_chain_terminal` helper from
audit_trail — no key material duplication.

References
----------

* SOC 2 CC2.3 — communication of internal control information
* PCI-DSS Req 11.4 — pen-test reports as audit evidence
* HIPAA §164.308(a)(8) — security assessment evaluations
* ISO 27001 A.18.2.3 — review of independent reports
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import shutil
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# Frameworks we render in the control_attestation.md rollup. Keep
# in sync with the keys in `enrich_finding_with_compliance` (#103).
_FRAMEWORKS = (
    "soc2", "pci_dss", "iso_27001", "hipaa", "gdpr",
    "nist_800_53", "owasp", "cis",
)


def _sha256_of_path(path: Path) -> str:
    """Return hex SHA-256 of a file's bytes. ~64 KB chunked
    so large vulnerabilities.json files don't blow up RAM."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _findings_to_csv(findings: list[dict[str, Any]]) -> str:
    """Flatten the findings list into a CSV. Designed for auditor
    spreadsheet import — fields in audit-relevant order."""
    if not findings:
        return "id,title,severity,category,cwe,verification_status,target,endpoint\n"

    buf = StringIO()
    fieldnames = [
        "id", "title", "severity", "category", "cwe", "cve",
        "verification_status", "is_kev", "owasp_top_10",
        "owasp_api_top_10", "target", "endpoint",
        "description_plain", "recommended_action",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        row = {k: f.get(k, "") for k in fieldnames}
        # Severity is canonical lowercase per #106.
        row["severity"] = (row["severity"] or "").lower() if isinstance(
            row["severity"], str
        ) else ""
        # is_kev becomes string "true"/"false"/"" for CSV-friendliness.
        row["is_kev"] = (
            "" if f.get("is_kev") is None else str(bool(f.get("is_kev"))).lower()
        )
        # mitre_attack as comma-separated.
        mitre = f.get("mitre_attack") or []
        if mitre:
            row.setdefault("mitre_attack", ",".join(mitre))
        writer.writerow(row)
    return buf.getvalue()


def _build_control_attestation(
    findings: list[dict[str, Any]],
    *,
    check_summary: dict[str, Any] | None = None,
) -> str:
    """Build a per-framework rollup markdown.

    Output shape:

        # Control Attestation
        Generated 2026-05-04T00:00:00+00:00
        Total findings: 12
        Total checks: 47

        ## SOC 2 (Trust Services Criteria)
        ### CC6.1 (Logical access)
          - 2 findings (1 high, 1 medium)
          - controls implicated: <CWE-287, CWE-285>

        ### CC6.6 (Logical access — managed software)
          ...
    """
    lines = [
        "# Control attestation",
        "",
        f"Generated: {datetime.now(UTC).isoformat()}",
        f"Total findings: {len(findings)}",
    ]
    if check_summary and check_summary.get("total"):
        lines.append(f"Total checks: {check_summary['total']}")
    lines.append("")

    # Group findings by framework → control.
    framework_human = {
        "soc2": "SOC 2 (Trust Services Criteria)",
        "pci_dss": "PCI-DSS v4",
        "iso_27001": "ISO 27001 Annex A",
        "hipaa": "HIPAA Security Rule",
        "gdpr": "GDPR Art. 32",
        "nist_800_53": "NIST 800-53",
        "owasp": "OWASP Top 10 / API Top 10",
        "cis": "CIS Controls v8",
    }

    any_framework_with_findings = False
    for fw in _FRAMEWORKS:
        # control_id → list of finding records that touch it
        by_control: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            controls = (
                (f.get("compliance_controls") or {}).get(fw) or []
            )
            for c in controls:
                by_control.setdefault(c, []).append(f)

        if not by_control:
            continue
        any_framework_with_findings = True
        lines.append(f"## {framework_human.get(fw, fw)}")
        lines.append("")
        for control_id in sorted(by_control):
            relevant = by_control[control_id]
            sev_counts: dict[str, int] = {}
            for r in relevant:
                sev = (r.get("severity") or "").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            sev_str = ", ".join(
                f"{count} {sev}"
                for sev, count in sorted(
                    sev_counts.items(), key=lambda kv: kv[0]
                )
            )
            cwes = sorted({f.get("cwe") for f in relevant if f.get("cwe")})
            lines.append(f"### {control_id}")
            lines.append(f"- {len(relevant)} finding(s) — {sev_str}")
            if cwes:
                lines.append(f"- CWEs implicated: {', '.join(cwes)}")
            lines.append("")
        lines.append("")

    if not any_framework_with_findings:
        lines.append("No findings carry compliance-control mappings.")
        lines.append(
            "Either no findings emitted, or the engine's compliance-mapping "
            "module (#103) doesn't have a CWE → control entry for the "
            "categories that fired in this run."
        )

    return "\n".join(lines).rstrip() + "\n"


def _build_scope(run_metadata: dict[str, Any]) -> dict[str, Any]:
    """Extract scope-relevant fields from run_metadata."""
    return {
        "schema_version": 1,
        "run_id": run_metadata.get("run_id"),
        "run_name": run_metadata.get("run_name"),
        "targets": run_metadata.get("targets", []),
        "scan_mode": run_metadata.get("scan_mode"),
        "scope_mode": run_metadata.get("scope_mode"),
        "model_name": run_metadata.get("model_name"),
        "user_instructions": run_metadata.get("user_instructions"),
    }


def write_compliance_pack(
    *,
    output_dir: str | Path,
    run_id: str,
    run_metadata: dict[str, Any],
    findings: list[dict[str, Any]],
    run_dir: Path,
    check_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Render the full compliance pack to `<output_dir>/<run_id>/`.

    Returns a dict describing what was written:

        {
          success: bool,
          pack_dir: str,
          files: [str, ...],          # relative paths inside pack_dir
          manifest_path: str,
          signature_path: str,
          chain_terminal_hash: str,   # from audit_trail signing
        }

    Best-effort — failures during individual file writes are
    recorded but do NOT abort the pack write. The manifest will
    still list the files that succeeded so the auditor can see
    the partial state.
    """
    output_dir = Path(output_dir).expanduser().resolve()
    pack_dir = output_dir / run_id
    pack_dir.mkdir(parents=True, exist_ok=True)
    files_written: list[str] = []
    errors: list[str] = []

    # 1. Copy report.md from run_dir if it exists.
    src_report = run_dir / "report.md"
    if src_report.exists():
        try:
            shutil.copyfile(src_report, pack_dir / "report.md")
            files_written.append("report.md")
        except OSError as e:
            errors.append(f"report.md: {e}")

    # 2. findings.csv
    try:
        csv_text = _findings_to_csv(findings)
        (pack_dir / "findings.csv").write_text(csv_text, encoding="utf-8")
        files_written.append("findings.csv")
    except OSError as e:
        errors.append(f"findings.csv: {e}")

    # 3. findings.json — full structured dump.
    try:
        (pack_dir / "findings.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "run_id": run_id,
                    "generated_at": datetime.now(UTC).isoformat(),
                    "count": len(findings),
                    "findings": findings,
                },
                indent=2, ensure_ascii=False, default=str,
            ),
            encoding="utf-8",
        )
        files_written.append("findings.json")
    except OSError as e:
        errors.append(f"findings.json: {e}")

    # 4. scope.json
    try:
        (pack_dir / "scope.json").write_text(
            json.dumps(_build_scope(run_metadata), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        files_written.append("scope.json")
    except OSError as e:
        errors.append(f"scope.json: {e}")

    # 5. scan_metadata.json — full run_meta copy.
    try:
        (pack_dir / "scan_metadata.json").write_text(
            json.dumps(run_metadata, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        files_written.append("scan_metadata.json")
    except OSError as e:
        errors.append(f"scan_metadata.json: {e}")

    # 6. control_attestation.md
    try:
        (pack_dir / "control_attestation.md").write_text(
            _build_control_attestation(findings, check_summary=check_summary),
            encoding="utf-8",
        )
        files_written.append("control_attestation.md")
    except OSError as e:
        errors.append(f"control_attestation.md: {e}")

    # 7. manifest.json — sha256 of every file in the bundle.
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "files": [],
    }
    for rel in sorted(files_written):
        try:
            digest = _sha256_of_path(pack_dir / rel)
            size = (pack_dir / rel).stat().st_size
        except OSError as e:
            errors.append(f"manifest hash {rel}: {e}")
            continue
        manifest["files"].append({"path": rel, "sha256": digest, "size_bytes": size})

    try:
        manifest_path = pack_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        files_written.append("manifest.json")
    except OSError as e:
        errors.append(f"manifest.json: {e}")
        manifest_path = pack_dir / "manifest.json"

    # 8. signature.txt — detached signature over the manifest hash.
    try:
        from strix.telemetry.audit_trail import sign_chain_terminal

        manifest_hash = _sha256_of_path(manifest_path)
        sig_block = sign_chain_terminal(manifest_hash)
        sig_block["manifest_hash"] = manifest_hash
        sig_block["bundle_run_id"] = run_id
        sig_path = pack_dir / "signature.txt"
        sig_path.write_text(
            json.dumps(sig_block, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        files_written.append("signature.txt")
        chain_terminal_hash = sig_block.get("chain_terminal_hash") or manifest_hash
    except Exception as e:  # noqa: BLE001
        errors.append(f"signature.txt: {e}")
        chain_terminal_hash = ""

    out: dict[str, Any] = {
        "success": True,
        "pack_dir": str(pack_dir),
        "files": files_written,
        "manifest_path": str(pack_dir / "manifest.json"),
        "signature_path": str(pack_dir / "signature.txt"),
        "chain_terminal_hash": chain_terminal_hash,
    }
    if errors:
        out["errors"] = errors
    return out
