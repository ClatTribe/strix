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


_DEFAULT_TRIVY_SCANNERS = "vuln,misconfig,secret"


def _trivy_scanners() -> str:
    """Trivy `--scanners` value. Defaults to `vuln,misconfig,secret`
    so the same scan surfaces CVEs + Dockerfile/Compose misconfigs +
    secrets-in-layers. Operators can override via
    `STRIX_TRIVY_SCANNERS` env var (e.g. `vuln` only for fast scans).
    """
    raw = os.environ.get("STRIX_TRIVY_SCANNERS", "").strip()
    return raw if raw else _DEFAULT_TRIVY_SCANNERS


def _run_trivy_scan(
    image_ref: str, *, timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> tuple[dict[str, Any] | None, str | None]:
    """Run `trivy image --format json <ref>` with the configured
    scanners. Returns `(report, error)`.

    `report` is the parsed JSON when Trivy succeeded; `None`
    otherwise. `error` is a human-readable string when Trivy failed;
    `None` on success.

    Scanners default to `vuln,misconfig,secret` — covers CVE
    package vulns + Dockerfile/Compose misconfigs (USER root,
    exposed ports, hardcoded passwords) + secrets-in-layers
    (AWS keys, JWT tokens, hardcoded API keys). Override via
    `STRIX_TRIVY_SCANNERS=vuln` for the original CVE-only behaviour.

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
        "--scanners", _trivy_scanners(),
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


def _extract_misconfigurations(
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Pull Trivy's `Misconfigurations[]` entries from every Result
    block whose `Class` is `config`. Each entry covers a single
    Dockerfile / docker-compose / Kubernetes misconfig finding (e.g.
    `DS002: Image user should not be 'root'`).

    Augments each entry with `_target` (the file path within the
    image — `Dockerfile` / `docker-compose.yml` / etc.) so the
    finding-emit step can attribute the issue to a specific layer.
    """
    out: list[dict[str, Any]] = []
    results = report.get("Results") or []
    if not isinstance(results, list):
        return []
    for r in results:
        if not isinstance(r, dict):
            continue
        klass = str(r.get("Class") or "").lower()
        if klass != "config":
            continue
        target = str(r.get("Target") or "").strip()
        config_type = str(r.get("Type") or "").strip()
        for mc in r.get("Misconfigurations") or []:
            if not isinstance(mc, dict):
                continue
            # Only `FAIL` status entries are real findings —
            # `PASS` / `EXCEPTION` shouldn't surface.
            status = str(mc.get("Status") or "").strip().upper()
            if status and status != "FAIL":
                continue
            out.append({
                **mc,
                "_target": target,
                "_config_type": config_type,
            })
    return out


def _extract_secrets(
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Pull Trivy's `Secrets[]` entries from every Result block
    whose `Class` is `secret`. Each entry is a secret leak detection
    (AWS access key, GitHub PAT, hardcoded JWT, etc.).

    Augments each entry with `_target` (the file path) so the
    emitter can point a reader at the exact location.
    """
    out: list[dict[str, Any]] = []
    results = report.get("Results") or []
    if not isinstance(results, list):
        return []
    for r in results:
        if not isinstance(r, dict):
            continue
        klass = str(r.get("Class") or "").lower()
        if klass != "secret":
            continue
        target = str(r.get("Target") or "").strip()
        for s in r.get("Secrets") or []:
            if not isinstance(s, dict):
                continue
            out.append({**s, "_target": target})
    return out


def _emit_misconfig_finding(
    *,
    image_ref: str,
    misconfig: dict[str, Any],
    severity: str,
) -> str | None:
    """Emit one finding per Trivy misconfiguration via the tracer."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None

        rule_id = str(misconfig.get("ID") or "").strip()
        avd_id = str(misconfig.get("AVDID") or "").strip()
        title = str(misconfig.get("Title") or "").strip()
        description_text = str(
            misconfig.get("Description") or ""
        ).strip()
        message = str(misconfig.get("Message") or "").strip()
        resolution = str(misconfig.get("Resolution") or "").strip()
        primary_url = str(misconfig.get("PrimaryURL") or "").strip()
        target_layer = misconfig.get("_target") or ""
        config_type = misconfig.get("_config_type") or ""
        refs = misconfig.get("References") or []
        ref_block = (
            "\n".join(f"  * {r}" for r in refs[:5]) if refs else ""
        )

        finding_title = (
            f"{rule_id}: {title} in {target_layer}"
            if rule_id and title and target_layer
            else (title or rule_id or "Container misconfiguration")
        )

        return tracer.add_vulnerability_report(
            title=finding_title,
            severity=severity,
            cwe=None,
            endpoint=image_ref,
            target=image_ref,
            category="misconfiguration",
            verification_status="pattern_match",
            confidence=0.92,
            description=(
                f"Trivy misconfiguration detection in container "
                f"image `{image_ref}`.\n\n"
                f"Rule: {rule_id} ({avd_id or 'no AVD id'})\n"
                f"Target file: {target_layer} ({config_type})\n\n"
                f"{description_text}"
                + (f"\n\nMessage: {message}" if message else "")
            ),
            impact=(
                f"Container-image configuration issue. {message or title}. "
                f"Direct exploitability depends on deployment posture; "
                f"this finding flags the misconfiguration as a "
                f"hardening gap."
            ),
            technical_analysis=(
                f"Image: {image_ref}\n"
                f"Target file: {target_layer}\n"
                f"Config type: {config_type}\n"
                f"Rule: {rule_id}\n"
                f"AVD ID: {avd_id or '(none)'}\n"
                f"Trivy-reported severity: {misconfig.get('Severity')}\n"
                f"Primary reference: {primary_url}\n\n"
                f"References:\n{ref_block}"
            ),
            poc_description=(
                f"1. Re-run Trivy with config scanner:\n"
                f"   `trivy image --scanners misconfig "
                f"--severity HIGH,CRITICAL {image_ref}`\n"
                f"2. Search for rule ID `{rule_id}` in the output.\n"
                f"3. Cross-reference the rule at {primary_url} for "
                f"vendor-recommended fix."
            ),
            poc_script_code=(
                f"trivy image --scanners misconfig --severity "
                f"HIGH,CRITICAL --quiet {image_ref} | "
                f"grep -A5 '{rule_id}'"
            ),
            remediation_steps=(
                resolution
                or f"Apply the fix referenced at {primary_url}."
            ),
            cvss_breakdown=None,
            reasoning_trace=[
                f"Trivy misconfig scan of {image_ref} reported "
                f"{rule_id} ({title}) in {target_layer}.",
                f"Status: FAIL (Trivy gated on Status=FAIL only).",
                f"Trivy-reported severity: {misconfig.get('Severity')}.",
                f"Final calibrated severity: {severity}.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "scan_container_image: misconfig emit failed: %s",
            e, exc_info=True,
        )
        return None


def _emit_secret_finding(
    *,
    image_ref: str,
    secret: dict[str, Any],
    severity: str,
) -> str | None:
    """Emit one finding per Trivy secret-leak detection."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None

        rule_id = str(secret.get("RuleID") or "").strip()
        category = str(secret.get("Category") or "").strip()
        title = str(secret.get("Title") or "").strip()
        match = str(secret.get("Match") or "").strip()
        start_line = secret.get("StartLine")
        target_path = secret.get("_target") or ""

        # Truncate the match to avoid leaking the entire secret into
        # logs / events — first 16 chars + ellipsis is enough to
        # identify the issue without exposing the key.
        match_preview = match[:16] + ("..." if len(match) > 16 else "")

        finding_title = (
            f"Leaked {category} secret ({rule_id}) in "
            f"{target_path}:{start_line}"
            if target_path and start_line is not None
            else f"Leaked {category or 'secret'} in container image"
        )

        return tracer.add_vulnerability_report(
            title=finding_title,
            severity=severity,
            cwe="CWE-798",
            endpoint=image_ref,
            target=image_ref,
            category="secrets",
            verification_status="pattern_match",
            confidence=0.92,
            description=(
                f"Trivy secret-scanner detection in container image "
                f"`{image_ref}`.\n\n"
                f"Rule: {rule_id} (category: {category})\n"
                f"File: {target_path}\n"
                f"Line: {start_line}\n"
                f"Match (truncated): `{match_preview}`\n\n"
                f"{title}"
            ),
            impact=(
                f"Secret material baked into a container image layer "
                f"is accessible to anyone who can pull the image. "
                f"Treat as compromised; rotate immediately. "
                f"Severity reflects the secret type's blast radius "
                f"(cloud-provider credentials = critical; service-"
                f"specific API tokens = high)."
            ),
            technical_analysis=(
                f"Image: {image_ref}\n"
                f"Target file: {target_path}\n"
                f"Rule: {rule_id}\n"
                f"Category: {category}\n"
                f"Start line: {start_line}\n"
                f"Trivy-reported severity: {secret.get('Severity')}\n"
                f"Match preview: {match_preview}"
            ),
            poc_description=(
                f"1. Pull the image: `docker pull {image_ref}`\n"
                f"2. Inspect the offending file:\n"
                f"   `docker run --rm {image_ref} cat {target_path}`\n"
                f"3. Re-run Trivy secret-scanner for full match "
                f"content:\n"
                f"   `trivy image --scanners secret {image_ref}`"
            ),
            poc_script_code=(
                f"trivy image --scanners secret --quiet {image_ref} | "
                f"grep -A5 '{rule_id}'"
            ),
            remediation_steps=(
                "1. ROTATE the leaked credential immediately — "
                "anyone with image-pull access has it.\n"
                "2. Remove the secret from the image layer history "
                "(rebuilding from a clean base layer; `docker image "
                "history` reveals when it was added).\n"
                "3. Refactor the build to read secrets from runtime "
                "env vars / a secret manager (AWS Secrets Manager, "
                "HashiCorp Vault, Doppler) — NEVER bake into a layer.\n"
                "4. Add a pre-commit / CI gate that runs "
                "`trivy fs --scanners secret` against the build "
                "context."
            ),
            cvss_breakdown=None,
            reasoning_trace=[
                f"Trivy secret scan of {image_ref} reported "
                f"{rule_id} ({category}) at {target_path}:{start_line}.",
                f"Trivy-reported severity: {secret.get('Severity')}.",
                f"Final calibrated severity: {severity}.",
                "Match content truncated in evidence to avoid log leak.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "scan_container_image: secret emit failed: %s",
            e, exc_info=True,
        )
        return None


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
    misconfigs = _extract_misconfigurations(report)
    secrets = _extract_secrets(report)

    # Phase 1: emit Dependency KG nodes for every package the image
    # contains — vulnerable or not. Feeds MOAK feed-trigger.
    for pkg in packages:
        _emit_kg_dependency(image_ref=image_ref, package=pkg)

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    deduped_seen: set[tuple[str, str, str]] = set()
    misconfig_emitted = 0
    secret_emitted = 0

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

    # Phase 3: emit one finding per Dockerfile / docker-compose /
    # Kubernetes misconfiguration. Trivy's `Status=FAIL` filter is
    # applied upstream in `_extract_misconfigurations`.
    misconfig_dedup: set[tuple[str, str]] = set()
    for mc in misconfigs:
        if emitted_count + misconfig_emitted >= max_findings:
            evidence.append(
                f"max_findings cap ({max_findings}) reached during "
                f"misconfig phase — truncating output"
            )
            break
        rule_id = str(mc.get("ID") or "").strip()
        target_layer = str(mc.get("_target") or "").strip()
        if not rule_id:
            continue
        dkey = (rule_id, target_layer)
        if dkey in misconfig_dedup:
            continue
        misconfig_dedup.add(dkey)

        trivy_sev = _TRIVY_SEV_MAP.get(
            str(mc.get("Severity") or "").strip().upper(),
            "medium",
        )
        report_id = _emit_misconfig_finding(
            image_ref=image_ref, misconfig=mc, severity=trivy_sev,
        )
        if report_id:
            misconfig_emitted += 1
            drafts.append(FindingDraft(
                title=(
                    f"{rule_id}: {str(mc.get('Title') or '')[:60]}"
                ),
                severity=trivy_sev,
                cwe=None,
                endpoint=image_ref,
                category="misconfiguration",
                verification_status="pattern_match",
                confidence=0.92,
                description=(
                    f"Misconfig {rule_id} in {target_layer} of "
                    f"{image_ref}"
                ),
            ))
            evidence.append(
                f"misconfig: {rule_id} ({target_layer}) "
                f"severity={trivy_sev}"
            )

    # Phase 4: emit one finding per secret-leak detection. Dedup by
    # (rule_id, target_path, start_line) so the same leak isn't
    # double-emitted from multiple layer scans.
    secret_dedup: set[tuple[str, str, Any]] = set()
    for s in secrets:
        if emitted_count + misconfig_emitted + secret_emitted >= max_findings:
            evidence.append(
                f"max_findings cap ({max_findings}) reached during "
                f"secret phase — truncating output"
            )
            break
        rule_id = str(s.get("RuleID") or "").strip()
        target_path = str(s.get("_target") or "").strip()
        start_line = s.get("StartLine")
        if not rule_id:
            continue
        skey = (rule_id, target_path, start_line)
        if skey in secret_dedup:
            continue
        secret_dedup.add(skey)

        trivy_sev = _TRIVY_SEV_MAP.get(
            str(s.get("Severity") or "").strip().upper(),
            "high",
        )
        report_id = _emit_secret_finding(
            image_ref=image_ref, secret=s, severity=trivy_sev,
        )
        if report_id:
            secret_emitted += 1
            category_short = str(s.get("Category") or "secret")
            drafts.append(FindingDraft(
                title=(
                    f"Leaked {category_short} ({rule_id}) at "
                    f"{target_path}"
                ),
                severity=trivy_sev,
                cwe="CWE-798",
                endpoint=image_ref,
                category="secrets",
                verification_status="pattern_match",
                confidence=0.92,
                description=(
                    f"{rule_id} secret detected at "
                    f"{target_path}:{start_line} in {image_ref}"
                ),
            ))
            evidence.append(
                f"secret: {rule_id} at {target_path}:{start_line} "
                f"(category={category_short}, severity={trivy_sev})"
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
                "findings_emitted_cves": emitted_count,
                "findings_emitted_misconfigs": misconfig_emitted,
                "findings_emitted_secrets": secret_emitted,
                "packages_observed": len(packages),
                "vulnerabilities_observed": len(vulns),
                "misconfigurations_observed": len(misconfigs),
                "secrets_observed": len(secrets),
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
            "misconfigurations_observed": len(misconfigs),
            "secrets_observed": len(secrets),
            "findings_emitted_cves": emitted_count,
            "findings_emitted_misconfigs": misconfig_emitted,
            "findings_emitted_secrets": secret_emitted,
            "findings_emitted_to_tracer": (
                emitted_count + misconfig_emitted + secret_emitted
            ),
            "trivy_scanners": _trivy_scanners(),
            "trivy_schema_version": report.get("SchemaVersion"),
            "image_metadata": report.get("Metadata") or {},
        },
    )
