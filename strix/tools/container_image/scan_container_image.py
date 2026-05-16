"""`scan_container_image` — container-image vulnerability specialist.

Wraps Trivy (de-facto-standard container scanner) and routes its
output through strix's existing finding-emission + KG pipeline.
Closes the `container_image` target-type gap: until now, the lead
catalog had no probe for `nginx:1.25` / `registry.example.com/foo/bar:tag`
targets even though the SCA / threat-intel / MOAK substrate could
all consume those findings if delivered.

Why Trivy
---------

Trivy (aquasec) is the standard container scanner — broad OS-package
coverage (Debian, Ubuntu, Alpine, RHEL, CentOS, Amazon Linux, Oracle,
Photon, Wolfi, etc.), broad language-package coverage (npm, pypi,
go, cargo, maven, gem, composer), maintained CVE DB, JSON output.
Grype (anchore) is a viable alternative; Trivy wins on language
ecosystem breadth and is more widely deployed in production CI.

Pipeline integration
--------------------

Each Trivy `Vulnerability` entry becomes:

  1. A `Package` record (the underlying package + version) — emitted
     into the KG as a `Dependency` node (Phase 6.2 — same shape that
     `scan_sca_lockfiles` uses). This means the MOAK CVE-relevance
     evaluator and the cross-target chaining graph see image-resident
     packages just like lockfile-resident ones.
  2. A finding via `tracer.add_vulnerability_report` with KEV / EPSS
     decoration pulled from strix's threat-intel cache (when present),
     falling back to Trivy's own severity when not.

Severity tuning
---------------

  * CISA KEV match            → critical (actively exploited)
  * EPSS ≥ 0.5                → escalate one tier
  * Otherwise Trivy's reported severity wins

Graceful degrade
----------------

When Trivy isn't installed, returns `status=partial` with
`engine_available=false` in `tool_metadata`. The lead can still
proceed and the wrapper can prompt the operator to install Trivy.

Kill switch
-----------

`STRIX_TRIVY_DISABLED=1` skips the probe entirely (returns `partial`).
Useful for air-gapped environments where Trivy can't refresh its DB.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404 — required for Trivy invocation
from typing import Any

from strix.sca.parsers.base import Package
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


_TRIVY_BIN = "trivy"
_DEFAULT_TIMEOUT_SECONDS = 600


# Map Trivy's severity strings to strix's canonical lowercase set.
# Trivy uses UNKNOWN / LOW / MEDIUM / HIGH / CRITICAL.
_TRIVY_SEV_MAP: dict[str, str] = {
    "UNKNOWN": "info",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}

_SEV_RANK: dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def _bump_severity(sev: str) -> str:
    rank = _SEV_RANK.get((sev or "").lower(), 1)
    inv = {v: k for k, v in _SEV_RANK.items()}
    return inv[min(4, rank + 1)]


# Map Trivy's `Type` (npm, gem, debian, ubuntu, alpine, etc.) to
# strix's canonical ecosystem strings. Used when emitting Package
# records into the KG. OS-package types (debian, ubuntu, alpine,
# rhel, etc.) all map to `os` — strix doesn't currently distinguish
# distro-level packages at the KG layer.
_ECOSYSTEM_MAP: dict[str, str] = {
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "pip": "pypi",
    "poetry": "pypi",
    "pipenv": "pypi",
    "uv": "pypi",
    "gem": "rubygems",
    "bundler": "rubygems",
    "cargo": "cargo",
    "composer": "composer",
    "gomod": "go",
    "gobinary": "go",
    "maven": "maven",
    "gradle": "maven",
    "nuget": "nuget",
    "swift": "swift",
    "cocoapods": "swift",
    # OS package families collapse to a single ecosystem label.
    "debian": "os",
    "ubuntu": "os",
    "alpine": "os",
    "rhel": "os",
    "centos": "os",
    "amazon": "os",
    "oracle": "os",
    "photon": "os",
    "rocky": "os",
    "fedora": "os",
    "suse": "os",
    "wolfi": "os",
    "chainguard": "os",
}


def _normalise_ecosystem(trivy_type: str) -> str:
    return _ECOSYSTEM_MAP.get((trivy_type or "").lower(), trivy_type or "unknown")


def _trivy_available() -> bool:
    """True iff `trivy` binary is on PATH AND the kill switch isn't set."""
    if os.environ.get("STRIX_TRIVY_DISABLED", "").strip() in {"1", "true", "yes"}:
        return False
    return shutil.which(_TRIVY_BIN) is not None


def _run_trivy_scan(
    image_ref: str, *, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> tuple[dict[str, Any] | None, str | None]:
    """Run `trivy image --format json <ref>`. Returns `(report, error)`.

    `report` is the parsed JSON when Trivy succeeded; `None` otherwise.
    `error` is a human-readable string when Trivy failed; `None` on
    success.

    Trivy exits non-zero on findings by default; we pass
    `--exit-code 0` so any non-zero exit means a real Trivy error.
    `--skip-db-update` keeps the call hermetic — operators run
    `trivy --download-db-only` ahead of scans (the wrapper's
    threat-intel-refresher pattern).
    """
    cmd = [
        _TRIVY_BIN, "image",
        "--format", "json",
        "--quiet",
        "--exit-code", "0",
        "--skip-db-update",
        "--severity", "LOW,MEDIUM,HIGH,CRITICAL",
        image_ref,
    ]
    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return None, f"trivy timed out after {timeout_seconds}s on {image_ref!r}"
    except OSError as e:
        return None, f"trivy invocation failed: {type(e).__name__}: {e}"

    if result.returncode != 0:
        return None, (
            f"trivy returned exit {result.returncode}: "
            f"{(result.stderr or '').strip()[:500]}"
        )
    if not result.stdout.strip():
        return None, "trivy produced no output"
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return None, f"trivy output not valid JSON: {e}"
    if not isinstance(report, dict):
        return None, f"trivy report not a dict (got {type(report).__name__})"
    return report, None


def _extract_packages_and_vulns(
    report: dict[str, Any],
) -> tuple[list[Package], list[dict[str, Any]]]:
    """Flatten Trivy's per-Result layered output into:

      * `packages` — one Package per distinct (ecosystem, name, version)
        seen across all Results. Drives KG `Dependency` emission.
      * `vulns` — Trivy Vulnerability entries augmented with the
        normalised ecosystem string (for downstream lookup).
    """
    packages: dict[tuple[str, str, str], Package] = {}
    vulns: list[dict[str, Any]] = []

    results = report.get("Results") or []
    if not isinstance(results, list):
        return [], []

    for r in results:
        if not isinstance(r, dict):
            continue
        trivy_type = str(r.get("Type") or "").strip()
        ecosystem = _normalise_ecosystem(trivy_type)
        target = str(r.get("Target") or "").strip()

        # `Packages` carries the SBOM-style list (every package the
        # layer contains, vulnerable or not). Used for full KG
        # dependency inventory.
        for pkg_entry in r.get("Packages") or []:
            if not isinstance(pkg_entry, dict):
                continue
            name = str(pkg_entry.get("Name") or "").strip().lower()
            version = str(pkg_entry.get("Version") or "").strip()
            if not name or not version:
                continue
            key = (ecosystem, name, version)
            if key not in packages:
                packages[key] = Package(
                    ecosystem=ecosystem,
                    name=name,
                    version=version,
                    source_path=target,
                    dev_only=False,
                )

        # `Vulnerabilities` carries the CVE matches.
        for vuln in r.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            name = str(vuln.get("PkgName") or "").strip().lower()
            version = str(vuln.get("InstalledVersion") or "").strip()
            if not name or not version:
                continue
            # Ensure the vulnerable package is in the package set
            # even when `Packages` was absent (Trivy emits Packages
            # only for `--list-all-pkgs` runs — default mode skips it).
            key = (ecosystem, name, version)
            if key not in packages:
                packages[key] = Package(
                    ecosystem=ecosystem,
                    name=name,
                    version=version,
                    source_path=target,
                    dev_only=False,
                )
            vulns.append({
                **vuln,
                "_ecosystem": ecosystem,
                "_target": target,
            })

    return list(packages.values()), vulns


def _decorate_with_threat_intel(
    cve_id: str, trivy_severity: str,
) -> tuple[str, bool, float | None]:
    """Pull KEV + EPSS for `cve_id` from strix's threat-intel cache.

    Returns `(adjusted_severity, kev, epss)`. The base severity is
    Trivy's; KEV match bumps to critical, EPSS≥0.5 bumps one tier.
    Falls through silently when the cache is unavailable.
    """
    severity = (trivy_severity or "low").lower()
    kev = False
    epss: float | None = None
    try:
        from strix.threat_intel.lookup import get_cve

        record = get_cve(cve_id)
        if record is not None:
            kev = bool(record.kev)
            epss = record.epss
            if kev:
                severity = "critical"
            elif epss is not None and epss >= 0.5:
                severity = _bump_severity(severity)
    except Exception:  # noqa: BLE001
        logger.debug("trivy decorate: threat-intel lookup failed for %s",
                     cve_id, exc_info=True)
    return severity, kev, epss


def _emit_image_finding(
    *,
    image_ref: str,
    vuln: dict[str, Any],
    severity: str,
    kev: bool,
    epss: float | None,
) -> str | None:
    """Emit one finding per (image, vulnerability) via the tracer."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None

        cve_id = str(vuln.get("VulnerabilityID") or "").strip()
        pkg_name = str(vuln.get("PkgName") or "").strip()
        installed_version = str(vuln.get("InstalledVersion") or "").strip()
        fixed_version = str(vuln.get("FixedVersion") or "").strip() or None
        title_text = str(vuln.get("Title") or "").strip()
        description_text = str(vuln.get("Description") or "").strip()
        primary_url = str(vuln.get("PrimaryURL") or "").strip()
        ecosystem = vuln.get("_ecosystem") or "unknown"
        target_layer = vuln.get("_target") or ""

        cwe_list = vuln.get("CweIDs") or []
        cwe = cwe_list[0] if cwe_list else None

        # Pull CVSS v3 from whichever vendor block is present.
        cvss_score = None
        cvss_vector = None
        cvss_data = vuln.get("CVSS") or {}
        if isinstance(cvss_data, dict):
            for vendor_block in cvss_data.values():
                if not isinstance(vendor_block, dict):
                    continue
                if "V3Score" in vendor_block and cvss_score is None:
                    cvss_score = vendor_block.get("V3Score")
                if "V3Vector" in vendor_block and cvss_vector is None:
                    cvss_vector = vendor_block.get("V3Vector")
                if cvss_score is not None and cvss_vector is not None:
                    break

        refs = vuln.get("References") or []
        ref_block = "\n".join(f"  * {r}" for r in refs[:5]) if refs else ""

        kev_note = ""
        if kev:
            kev_note = (
                "\n\n⚠️ Listed on the CISA Known Exploited Vulnerabilities "
                "(KEV) catalogue — actively exploited in the wild. Patch "
                "with priority."
            )

        epss_note = ""
        if epss is not None and epss >= 0.1:
            epss_note = (
                f"\n\nEPSS exploitation probability: {epss:.2%} — model "
                f"estimate of the likelihood this CVE is exploited within "
                f"the next 30 days."
            )

        fix_hint = (
            f"Upgrade `{pkg_name}` from `{installed_version}` to "
            f"`{fixed_version}` (or later)."
            if fixed_version else
            f"No fixed version is published for `{pkg_name}@{installed_version}`. "
            f"Mitigate by removing the package from the image, switching to "
            f"a maintained alternative, or applying upstream patches if "
            f"the project ships them."
        )

        title = (
            f"{cve_id}: {pkg_name}@{installed_version} ({ecosystem}) "
            f"in container image"
        )
        if title_text:
            title = f"{cve_id}: {title_text[:80]}"

        return tracer.add_vulnerability_report(
            title=title,
            severity=severity,
            cwe=cwe,
            cve=cve_id,
            endpoint=image_ref,
            target=image_ref,
            category="sca",
            verification_status="pattern_match",
            confidence=0.92,
            description=(
                f"The container image `{image_ref}` contains "
                f"`{pkg_name}@{installed_version}` ({ecosystem}) which "
                f"is affected by {cve_id}.\n\n"
                f"{description_text[:1500]}"
                f"{kev_note}{epss_note}"
            ),
            impact=(
                f"Container image dependency on a vulnerable package. "
                f"Exploitability depends on whether `{pkg_name}` is "
                f"reachable from the application's request path in the "
                f"deployed container. KEV/EPSS data above quantifies "
                f"in-the-wild risk."
            ),
            technical_analysis=(
                f"Image: {image_ref}\n"
                f"Layer / target: {target_layer}\n"
                f"Ecosystem: {ecosystem}\n"
                f"Package: {pkg_name}@{installed_version}\n"
                f"Fixed version: {fixed_version or '(unpatched)'}\n"
                f"CVE: {cve_id}\n"
                f"CVSS v3 score: {cvss_score or '(none)'}\n"
                f"CVSS v3 vector: {cvss_vector or '(none)'}\n"
                f"CWE: {cwe or '(none)'}\n"
                f"Primary reference: {primary_url}\n\n"
                f"References:\n{ref_block}"
            ),
            poc_description=(
                f"1. Pull the image: `docker pull {image_ref}`\n"
                f"2. Verify the vulnerable package is present:\n"
                f"   `docker run --rm {image_ref} <package-manager> "
                f"show {pkg_name}`\n"
                f"   (or `dpkg -s` / `apk info` / `rpm -q` for OS pkgs)\n"
                f"3. Cross-reference the CVE advisory at {primary_url} "
                f"for an exploit recipe."
            ),
            poc_script_code=(
                f"trivy image --severity HIGH,CRITICAL --quiet "
                f"{image_ref} | grep -A2 {cve_id}"
            ),
            remediation_steps=(
                f"{fix_hint}\n\n"
                f"Rebuild the image with the patched package, push to "
                f"the registry, and roll the deployment. If the package "
                f"is an OS dependency, rebuild on a newer base image "
                f"that ships the patched version."
            ),
            cvss_breakdown=None,
            reasoning_trace=[
                f"Trivy scan of {image_ref} reported {cve_id} affecting "
                f"{pkg_name}@{installed_version} ({ecosystem}).",
                f"Trivy-reported severity: {vuln.get('Severity') or '(none)'}.",
                f"KEV match: {kev}.",
                f"EPSS: {epss if epss is not None else '(unavailable)'}.",
                f"Final calibrated severity: {severity}.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_container_image: emit failed: %s", e, exc_info=True)
        return None


def _emit_kg_dependency(
    *, image_ref: str, package: Package,
) -> None:
    """Emit a `Dependency` KG node for a package observed in the
    image. Best-effort; never raises. Drives MOAK's feed-trigger
    so a future CVE landing for `(ecosystem, name, version)` can
    be cross-referenced against the customer's image inventory."""
    try:
        from strix.agents.kg_emit import record_dependency_in_kg

        record_dependency_in_kg(
            ecosystem=package.ecosystem,
            name=package.name,
            version=package.version,
            source=image_ref,
        )
    except ImportError:
        # `record_dependency_in_kg` may not be present in older
        # branches; ignore silently rather than crash the scan.
        pass
    except Exception:  # noqa: BLE001
        logger.debug(
            "scan_container_image: kg dependency emit failed",
            exc_info=True,
        )


@register_specialist_tool(
    category="container-image-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 600},
    sandbox_execution=False,
    provenance="framework",
    # T1525 Implant Internal Image (registry-side) +
    # T1610 Deploy Container.
    mitre_techniques=["T1525", "T1610"],
)
def scan_container_image(
    *,
    image_ref: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    max_findings: int = 500,
) -> SpecialistResult:
    """Scan a container image for vulnerable packages via Trivy and
    auto-emit findings.

    Args:
        image_ref: image reference. Examples — `nginx:1.25`,
            `registry.example.com/foo/bar:tag`,
            `nginx@sha256:0123...abcd`. Required.
        timeout_seconds: Trivy invocation timeout. Default 600s.
            Large images on a cold cache can hit this; raise for
            multi-gig images.
        max_findings: cap on findings emitted. Trivy can return
            thousands on broken base images; bound to keep the
            tracer payload sane. Default 500.

    Auto-emits one `add_vulnerability_report` per CVE-bearing
    package the image contains, plus one KG `Dependency` node per
    distinct package (vulnerable or not).

    Examples:
        # Public image
        scan_container_image(image_ref="nginx:1.25")

        # Private registry
        scan_container_image(image_ref="registry.example.com/svc/web:v1.2.0")

        # Digest-pinned
        scan_container_image(image_ref="nginx@sha256:0123abcd...")
    """
    if not isinstance(image_ref, str) or not image_ref.strip():
        return SpecialistResult(status="error", error="image_ref required")
    image_ref = image_ref.strip()

    if not _trivy_available():
        # Graceful degrade — wrapper / operator sees a clear signal
        # that the tool surface needs Trivy installed.
        return SpecialistResult(
            status="partial",
            error=(
                "trivy binary not found on PATH. Install via "
                "`brew install trivy` / `apt install trivy` / docker "
                "pull aquasec/trivy:latest, then re-run."
            ),
            tool_metadata={
                "engine_available": False,
                "image_ref": image_ref,
            },
        )

    report, err = _run_trivy_scan(image_ref, timeout_seconds=timeout_seconds)
    if report is None:
        return SpecialistResult(
            status="error",
            error=err or "trivy scan failed (no detail)",
            tool_metadata={
                "engine_available": True,
                "image_ref": image_ref,
            },
        )

    packages, vulns = _extract_packages_and_vulns(report)

    # Phase 1: emit Dependency KG nodes for every package the image
    # contains — vulnerable or not. Feeds MOAK feed-trigger.
    for pkg in packages:
        _emit_kg_dependency(image_ref=image_ref, package=pkg)

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    deduped_seen: set[tuple[str, str, str]] = set()

    # Phase 2: emit one finding per (CVE, pkg, version) — dedup so
    # the same CVE-package pair doesn't double-emit when Trivy
    # reports it from multiple layer scans.
    for vuln in vulns:
        if emitted_count >= max_findings:
            evidence.append(
                f"max_findings cap ({max_findings}) reached — "
                f"truncating output"
            )
            break

        cve_id = str(vuln.get("VulnerabilityID") or "").strip()
        pkg_name = str(vuln.get("PkgName") or "").strip().lower()
        installed_version = str(vuln.get("InstalledVersion") or "").strip()
        if not cve_id or not pkg_name or not installed_version:
            continue
        dedup_key = (cve_id, pkg_name, installed_version)
        if dedup_key in deduped_seen:
            continue
        deduped_seen.add(dedup_key)

        trivy_sev_raw = str(vuln.get("Severity") or "").strip().upper()
        trivy_sev = _TRIVY_SEV_MAP.get(trivy_sev_raw, "medium")
        adjusted_sev, kev, epss = _decorate_with_threat_intel(
            cve_id, trivy_sev,
        )

        report_id = _emit_image_finding(
            image_ref=image_ref,
            vuln=vuln,
            severity=adjusted_sev,
            kev=kev,
            epss=epss,
        )
        if report_id:
            emitted_count += 1
            drafts.append(FindingDraft(
                title=f"{cve_id}: {pkg_name}@{installed_version}",
                severity=adjusted_sev,
                cwe=(vuln.get("CweIDs") or [None])[0],
                endpoint=image_ref,
                category="sca",
                verification_status="pattern_match",
                confidence=0.92,
                description=(
                    f"{cve_id} affects {pkg_name}@{installed_version} "
                    f"in {image_ref}"
                ),
            ))
            evidence.append(
                f"{cve_id} → {pkg_name}@{installed_version} "
                f"(severity={adjusted_sev}, kev={kev}, "
                f"epss={epss if epss is not None else 'n/a'})"
            )

    # Phase 1.6 — decision provenance log.
    try:
        from strix.agents.decision_log import record_decision

        record_decision(
            kind="specialist_invocation",
            target=image_ref,
            actor={"tool_name": "scan_container_image"},
            input={"image_ref": image_ref},
            output={
                "findings_emitted": emitted_count,
                "packages_observed": len(packages),
                "vulnerabilities_observed": len(vulns),
            },
        )
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            ["correlate image CVEs against deployed workloads via cluster "
             "scanning (kube-bench / kubelet inventory)"]
            if drafts else
            ["image clean per Trivy DB; refresh DB via "
             "`trivy --download-db-only` if scan is older than 24 h"]
        ),
        tool_metadata={
            "engine_available": True,
            "image_ref": image_ref,
            "packages_observed": len(packages),
            "vulnerabilities_observed": len(vulns),
            "findings_emitted_to_tracer": emitted_count,
            "trivy_schema_version": report.get("SchemaVersion"),
            "image_metadata": report.get("Metadata") or {},
        },
    )
