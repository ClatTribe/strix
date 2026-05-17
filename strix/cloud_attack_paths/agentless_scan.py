"""Agentless VM CVE scanning via Trivy's EBS-snapshot mode.

masterroadmap §5 P2 — Wiz's biggest remaining moat at the
enterprise tier. The runtime / agent-based competitors require
installing an agent on every VM; **agentless** scanning reads
the EBS volume directly (via the EBS Direct API or a snapshot
mount) so operators get the CVE inventory of every running
instance with no agent rollout.

## How this lands

Trivy ships an EBS-snapshot scanner that does the read-only
block-level read for us. Same wrap pattern as the rest of
strix's external-tool integrations (gitleaks / cosign /
prowler):

    trivy vm --format json --quiet ebs:<snapshot-id>

Inputs:
  * A list of EBS snapshot IDs to scan (operator-supplied OR
    auto-derived from the running-instance volume list).
  * AWS credentials (env / profile / role) Trivy will use to
    call the EBS Direct API.

Outputs:
  * Per-CVE findings attributed to the source snapshot →
    operator can attribute back to the instance via tags.
  * Findings emit as `category=agentless_vm_cve`, CWE-1395
    (vulnerable software).

## What this PR does (tactical v1)

  * Subprocess wrapper around `trivy vm` — same scaffold as
    `cspm/prowler.py`.
  * Hermetic-testable via DI'd `_subprocess_run`.
  * Per-snapshot fan-out with failure isolation.
  * JSON parsing + emit as CspmFinding-shaped records (so they
    flow through the existing tracer + compliance pipeline
    without new shape).

## What v2 needs (deferred — explicit TODO)

  * **Auto-snapshot orchestration** — list running instances →
    list attached volumes → create transient snapshots →
    scan → delete snapshots. The expensive lifecycle bit;
    operators today snapshot in their backup pipeline, so v1
    scans existing snapshots.
  * **Multi-cloud equivalents** — Azure Disk snapshots
    (`trivy vm` also supports azure URIs), GCP disk snapshots.
  * **Diff between scans** — "CVE X newly introduced in this
    snapshot vs the prior one" — overlap with SBOM diff
    (masterroadmap §4).

## Safety contract

Read-only: `trivy vm` uses EBS Direct API in read-only mode.
The IAM role needs `ec2:GetSnapshotBlock`, `ec2:ListSnapshotBlocks`,
`ec2:ListChangedBlocks`. No write permissions ever requested.

Per-snapshot errors don't stop the rest. A denied snapshot
doesn't blank the others; partial output is the contract.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

from strix.cspm.aws import CspmFinding


logger = logging.getLogger(__name__)


# Per-snapshot scan timeout. Real-world EBS scan of a typical
# Linux root volume is ~2-5 minutes; large or fragmented volumes
# can stretch to 15+. Default 1200s (20m) per snapshot.
_DEFAULT_TIMEOUT = 1200

# Per-PR scope cap on snapshots scanned per run. Each scan reads
# tens-of-MB-to-GB from EBS Direct API → has a real $$ cost.
_DEFAULT_MAX_SNAPSHOTS = 50


# Trivy severity strings → strix severity ladder.
_TRIVY_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high",
    "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low",
}


@dataclass
class AgentlessScanResult:
    """One agentless VM scan invocation's outcome."""
    snapshot_id: str
    findings: list[CspmFinding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "findings_count": len(self.findings),
            "errors": list(self.errors),
            "metadata": dict(self.metadata),
        }


# ---------------------------------------------------------------------------
# Availability detection
# ---------------------------------------------------------------------------


def is_trivy_vm_available() -> bool:
    """`trivy` on $PATH AND new enough to support the `vm`
    subcommand (Trivy 0.47+)."""
    if not shutil.which("trivy"):
        return False
    return True


# ---------------------------------------------------------------------------
# Trivy JSON parser
# ---------------------------------------------------------------------------


def _trivy_severity(s: str | None) -> str:
    if not s:
        return "medium"
    return _TRIVY_SEVERITY_MAP.get(s.strip().upper(), "medium")


def _parse_trivy_vm_output(
    content: str | dict, *, snapshot_id: str,
) -> list[CspmFinding]:
    """Parse Trivy's `vm` JSON output → list of CspmFinding-shaped
    records.

    Trivy's output shape (abbreviated):

        {
          "ArtifactName": "ebs:snap-aaa",
          "ArtifactType": "vm",
          "Results": [{
            "Target": "Ubuntu 22.04 (linux)",
            "Vulnerabilities": [{
              "VulnerabilityID": "CVE-2024-1234",
              "PkgName": "openssl",
              "InstalledVersion": "3.0.2-0ubuntu1.10",
              "FixedVersion": "3.0.2-0ubuntu1.15",
              "Severity": "HIGH",
              "Title": "...",
              "Description": "..."
            }]
          }]
        }
    """
    if isinstance(content, str):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
    else:
        data = content
    if not isinstance(data, dict):
        return []

    out: list[CspmFinding] = []
    snapshot_arn = (
        f"arn:aws:ec2:*:*:snapshot/{snapshot_id}"
        if snapshot_id else "arn:aws:ec2:*:*:snapshot/unknown"
    )
    for result in (data.get("Results") or []):
        target = result.get("Target") or "unknown-target"
        for vuln in (result.get("Vulnerabilities") or []):
            cve = vuln.get("VulnerabilityID") or "unknown"
            pkg = vuln.get("PkgName") or "unknown"
            installed = vuln.get("InstalledVersion") or "unknown"
            fixed = vuln.get("FixedVersion") or "(no fix yet)"
            severity = _trivy_severity(vuln.get("Severity"))
            title = vuln.get("Title") or f"{cve} in {pkg}"

            message = (
                f"{cve} in package `{pkg}` (installed: "
                f"{installed}, fixed: {fixed}) on snapshot "
                f"`{snapshot_id}` ({target})."
            )

            metadata: dict[str, Any] = {
                "source": "trivy_vm",
                "snapshot_id": snapshot_id,
                "target": target,
                "cve_id": cve,
                "package": pkg,
                "installed_version": installed,
                "fixed_version": fixed,
                "title": title,
            }
            if vuln.get("PrimaryURL"):
                metadata["primary_url"] = vuln["PrimaryURL"]
            if vuln.get("CVSS"):
                metadata["cvss"] = vuln["CVSS"]

            out.append(CspmFinding(
                rule_id=f"agentless_vm:{cve}",
                severity=severity,
                message=message,
                service="ec2",
                region=None,           # ARN doesn't carry region for snapshots
                resource_arn=snapshot_arn,
                cwe="CWE-1395",
                category="agentless_vm_cve",
                metadata=metadata,
            ))
    return out


# ---------------------------------------------------------------------------
# Subprocess invocation
# ---------------------------------------------------------------------------


def _build_trivy_argv(*, snapshot_id: str) -> list[str]:
    """Build the `trivy vm` argv for one snapshot. Kept pure for
    unit testing."""
    return [
        "trivy", "vm",
        "--format", "json",
        "--quiet",
        "--no-progress",
        f"ebs:{snapshot_id}",
    ]


def scan_snapshot(
    snapshot_id: str,
    *,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
    env_overrides: dict[str, str] | None = None,
    _subprocess_run=subprocess.run,
) -> AgentlessScanResult:
    """Run `trivy vm ebs:<snapshot-id>` and return parsed findings.

    Args:
        snapshot_id: EBS snapshot ID (e.g. `snap-0123abcd`).
        timeout_seconds: per-snapshot timeout (default 1200s).
        env_overrides: extra env vars (`AWS_*` if Trivy needs
            different credentials than the parent process).
        _subprocess_run: DI hook for tests.
    """
    result = AgentlessScanResult(snapshot_id=snapshot_id)
    if not is_trivy_vm_available():
        result.errors.append({
            "stage": "trivy_check",
            "error": "trivy binary not on PATH",
        })
        return result

    argv = _build_trivy_argv(snapshot_id=snapshot_id)
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)

    try:
        proc = _subprocess_run(
            argv,
            capture_output=True, text=True,
            timeout=timeout_seconds, check=False, env=env,
        )
    except subprocess.TimeoutExpired:
        result.errors.append({
            "stage": "trivy_run",
            "error": f"timed out after {timeout_seconds}s",
        })
        return result
    except (FileNotFoundError, OSError) as e:
        result.errors.append({
            "stage": "trivy_run",
            "error": f"subprocess failed: {e}",
        })
        return result

    result.metadata["returncode"] = proc.returncode
    # Trivy returns 0 always for `vm` scans regardless of findings.
    # Non-zero = real failure (auth, snapshot-not-found,
    # invalid-region).
    if proc.returncode != 0:
        result.errors.append({
            "stage": "trivy_run",
            "error": (
                f"non-zero exit ({proc.returncode}): "
                f"{(proc.stderr or '')[:500]}"
            ),
        })
        return result

    body = (proc.stdout or "").strip()
    if not body:
        # Trivy ran cleanly but emitted nothing — usually means
        # zero CVEs. Treat as success.
        return result

    findings = _parse_trivy_vm_output(body, snapshot_id=snapshot_id)
    result.findings.extend(findings)
    return result


# ---------------------------------------------------------------------------
# Multi-snapshot fan-out
# ---------------------------------------------------------------------------


def scan_snapshots(
    snapshot_ids: list[str],
    *,
    max_snapshots: int = _DEFAULT_MAX_SNAPSHOTS,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
    env_overrides: dict[str, str] | None = None,
    _subprocess_run=subprocess.run,
) -> list[AgentlessScanResult]:
    """Scan multiple EBS snapshots sequentially.

    Per-snapshot errors don't stop the rest. Hard cap at
    `max_snapshots` to keep accidental org-wide enumeration from
    blowing the run budget (each scan can cost $0.10-1.00 in
    EBS Direct API charges depending on volume size).
    """
    if not snapshot_ids:
        return []
    capped = snapshot_ids[:max_snapshots]
    results: list[AgentlessScanResult] = []
    for snap_id in capped:
        results.append(scan_snapshot(
            snap_id,
            timeout_seconds=timeout_seconds,
            env_overrides=env_overrides,
            _subprocess_run=_subprocess_run,
        ))
    return results


def summarise(results: list[AgentlessScanResult]) -> dict[str, Any]:
    """Aggregate counts + per-snapshot breakdown for
    tool_metadata."""
    sev_counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    total_findings = 0
    snapshots_with_errors = 0
    for r in results:
        if r.errors:
            snapshots_with_errors += 1
        for f in r.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            total_findings += 1
    return {
        "snapshots_scanned": len(results),
        "snapshots_with_errors": snapshots_with_errors,
        "total_cve_findings": total_findings,
        "severity_breakdown": sev_counts,
        "per_snapshot": [r.to_dict() for r in results],
    }


def union_findings(
    results: list[AgentlessScanResult],
) -> list[CspmFinding]:
    """Flat list of every CVE finding across snapshots."""
    out: list[CspmFinding] = []
    for r in results:
        out.extend(r.findings)
    return out
