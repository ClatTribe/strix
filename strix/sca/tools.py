"""LLM-facing SCA specialist.

`scan_sca_lockfiles` walks a repository for lockfiles, parses each
into a Package list, queries the threat-intel cache for CVEs, and
emits one finding per vulnerable package with a CVE.

Severity calibration:
  * CISA KEV match            → critical (actively exploited)
  * EPSS ≥ 0.5                → escalate one tier
  * Highest CVE severity wins overall

Auto-injects per-finding:
  * CVE id, CWE, CVSS score (from cache)
  * KEV flag + EPSS probability
  * Package metadata (ecosystem, name, version, dev_only, source lockfile)
  * Suggested remediation (upgrade hint)
"""

from __future__ import annotations

import logging
from typing import Any

from strix.sca.scanner import scan_repo_lockfiles
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _bump_severity(sev: str) -> str:
    rank = _SEV_RANK.get((sev or "").lower(), 1)
    inv = {v: k for k, v in _SEV_RANK.items()}
    return inv[min(4, rank + 1)]


def _emit_finding(
    *,
    package_match,
    repo_path: str,
    reachability=None,
) -> str | None:
    """Emit one finding per vulnerable package via tracer.

    `reachability` (Phase 6.4) is an optional `PackageReachability`
    record. When present, the finding's severity is demoted per the
    record's `adjusted_severity()` rule (KEV / EPSS override
    demotion), and the writeup includes the import evidence so
    reviewers see *why* a finding was demoted (or kept high)."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None

        pkg = package_match.package
        cves = package_match.cves

        # Pick the "headline" CVE — KEV first, then highest EPSS,
        # then highest CVSS.
        sorted_cves = sorted(
            cves,
            key=lambda c: (
                c.kev,
                c.epss or 0.0,
                c.cvss_score or 0.0,
            ),
            reverse=True,
        )
        headline = sorted_cves[0] if sorted_cves else None
        if headline is None:
            return None

        sev = (headline.severity or "high").lower()
        if headline.kev:
            sev = "critical"
        elif (headline.epss or 0.0) >= 0.5:
            sev = _bump_severity(sev)
        # Phase 6.4 — apply reachability demotion last; it's a no-op
        # when KEV / EPSS≥0.5 (override happens inside
        # adjusted_severity).
        if reachability is not None:
            sev = reachability.adjusted_severity(
                sev,
                kev=headline.kev,
                epss=headline.epss,
            )

        cve_summary_lines = []
        for c in sorted_cves[:5]:
            tags = []
            if c.kev:
                tags.append("KEV")
            if (c.epss or 0.0) >= 0.5:
                tags.append(f"EPSS={c.epss:.2f}")
            if c.cvss_score:
                tags.append(f"CVSS={c.cvss_score}")
            tag_str = f" [{' '.join(tags)}]" if tags else ""
            cve_summary_lines.append(
                f"  * {c.cve_id}{tag_str}: {(c.description or '')[:100]}"
            )

        title = (
            f"Vulnerable dependency `{pkg.ecosystem}:{pkg.name}@{pkg.version}` "
            f"({len(cves)} CVE{'s' if len(cves) > 1 else ''})"
        )
        if headline.kev:
            title += " [KEV — actively exploited]"
        # Reachability suffix — kept short so the title stays
        # scannable. Only added when status differs from
        # `direct_import` (the default-case "code uses it" status
        # adds noise to every title otherwise).
        if reachability is not None and reachability.status != "direct_import":
            title += f" [reachability={reachability.status}]"

        return tracer.add_vulnerability_report(
            title=title,
            severity=sev,
            cwe=(headline.kev_meta or {}).get("cwe") or None,
            endpoint=pkg.source_path,
            target=repo_path,
            category="vulnerable_dependency",
            cve=headline.cve_id,
            cvss=headline.cvss_score,
            verification_status="verified",
            confidence=0.95,
            description=(
                f"Dependency `{pkg.ecosystem}:{pkg.name}@{pkg.version}` "
                f"({'dev-only' if pkg.dev_only else 'runtime'}) is "
                f"affected by {len(cves)} known CVE"
                f"{'s' if len(cves) > 1 else ''}.\n\n"
                f"Top CVEs:\n" + "\n".join(cve_summary_lines)
            ),
            impact=(
                "Vulnerable third-party dependency. Concrete impact "
                "depends on the CVE class:\n"
                "  * RCE / deserialization → full host compromise\n"
                "  * SQLi / XSS in the package's API surface → "
                "    data exfiltration or session theft\n"
                "  * Auth bypass → account takeover\n"
                "  * DoS → service disruption\n"
                + (
                    "\n*This package is in the CISA KEV catalog — the "
                    "vulnerability is actively exploited in the wild "
                    "right now.*"
                    if headline.kev else ""
                )
                + (
                    f"\n*EPSS score {headline.epss:.2f} — high "
                    "probability of exploitation in the next 30 days.*"
                    if (headline.epss or 0.0) >= 0.5 else ""
                )
            ),
            technical_analysis=(
                f"Lockfile: {pkg.source_path}\n"
                f"Ecosystem: {pkg.ecosystem}\n"
                f"Package: {pkg.name}\n"
                f"Version: {pkg.version}\n"
                f"Dev-only: {pkg.dev_only}\n"
                f"Direct dependency: {pkg.direct}\n"
                + (
                    f"Reachability: {reachability.status} — "
                    f"{reachability.reason}\n"
                    + (
                        "Importing files: "
                        + ", ".join(reachability.importing_files[:5])
                        + ("\n" if reachability.importing_files else "\n")
                        if reachability.importing_files
                        else "Importing files: (none)\n"
                    )
                    if reachability is not None else ""
                )
                + f"\nMatching CVEs ({len(cves)}):\n"
                + "\n".join(cve_summary_lines)
            ),
            poc_description=(
                f"1. Identify the package version in the lockfile.\n"
                f"2. Cross-reference {headline.cve_id} for "
                f"exploitation details.\n"
                f"3. Confirm the vulnerable code path is reachable from "
                f"the application's entry points (Phase 6.4 reachability "
                f"analysis can automate this)."
            ),
            poc_script_code="",
            remediation_steps=(
                f"1. Upgrade `{pkg.name}` to a non-vulnerable version. "
                f"Check the CVE references for the patched version range.\n"
                f"2. After upgrade, regenerate the lockfile "
                f"(`{_lockfile_command(pkg.ecosystem)}`) and "
                f"re-run scan_sca_lockfiles to confirm the CVE no longer "
                f"matches.\n"
                f"3. If no patched version is available, consider "
                f"replacing the package or adding application-layer "
                f"mitigations.\n"
                f"4. Add the CVE to your risk register if you accept "
                f"the risk temporarily."
            ),
            cvss_breakdown=None,
            reasoning_trace=[
                f"Found `{pkg.name}@{pkg.version}` in {pkg.source_path}.",
                f"Threat-intel cache matched {len(cves)} CVE(s).",
                (
                    f"Headline CVE {headline.cve_id} is in CISA KEV "
                    "(actively exploited) → severity bumped to critical."
                    if headline.kev else
                    f"Headline CVE {headline.cve_id} EPSS={headline.epss}, "
                    f"CVSS={headline.cvss_score}."
                ),
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("sca emit failed: %s", e, exc_info=True)
        return None


def _lockfile_command(ecosystem: str) -> str:
    """Per-ecosystem regen command hint."""
    return {
        "npm": "npm install",
        "pypi": "pip-compile / poetry lock / uv lock",
        "rubygems": "bundle update",
        "cargo": "cargo update",
        "composer": "composer update",
        "go": "go mod tidy",
    }.get(ecosystem, "regenerate the lockfile")


@register_specialist_tool(
    category="sca-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1195"],   # Supply Chain Compromise
)
def scan_sca_lockfiles(
    *,
    repo_path: str,
    only_kev: bool = False,
    min_epss: float = 0.0,
    skip_dev_only: bool = True,
    max_lockfiles: int = 50,
    with_reachability: bool = True,
    only_reachable: bool = False,
) -> SpecialistResult:
    """Walk `repo_path` for lockfiles, parse each, match against the
    threat-intel cache, emit one finding per vulnerable package.

    Closes the #1 vuln source for vibe-coded apps: dependency CVEs.

    Args:
        repo_path: directory to scan.
        only_kev: filter to actively-exploited (CISA KEV).
        min_epss: filter to EPSS probability >= this.
        skip_dev_only: skip dev-only dependencies (default True —
            production runtime exposure is the main concern).
        max_lockfiles: hard cap to bound runtime.
        with_reachability: when True (default), enrich each finding
            with import-level reachability (Phase 6.4). Demotes
            severity for `unused` (-2 tiers) and `transitive_only`
            (-1 tier) packages. NEVER demotes KEV / EPSS≥0.5
            findings. Set False to skip the source-tree walk on
            very large repos.
        only_reachable: when True, suppress findings for packages
            classified as `unused` or `transitive_only`. Useful for
            dashboards that want zero-noise dep CVE views; default
            False so demoted findings are still surfaced (the
            wrapper renders the demotion badge).

    Auto-emits one finding per vulnerable package. Findings are
    severity-calibrated:
      * CISA KEV match → critical (actively exploited)
      * EPSS ≥ 0.5    → escalate one tier
      * Otherwise highest CVE severity wins
      * Reachability `unused`     → demote 2 tiers (unless KEV/EPSS)
      * Reachability `transitive_only` → demote 1 tier (unless KEV/EPSS)
    """
    if not isinstance(repo_path, str) or not repo_path.strip():
        return SpecialistResult(status="error", error="repo_path required")
    repo_path = repo_path.strip()

    try:
        report = scan_repo_lockfiles(
            repo_path,
            only_kev=only_kev,
            min_epss=min_epss,
            skip_dev_only=skip_dev_only,
            max_lockfiles=max_lockfiles,
        )
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"scan_repo_lockfiles failed: {type(e).__name__}: {e}",
        )

    if report.error:
        return SpecialistResult(status="error", error=report.error)

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0

    if not report.lockfiles_scanned:
        return SpecialistResult(
            status="partial",
            error="no lockfiles found",
            evidence=[
                f"scan_sca_lockfiles found no lockfiles under {repo_path}. "
                "Check that the path contains package-lock.json / yarn.lock /"
                "pnpm-lock.yaml / Pipfile.lock / poetry.lock / uv.lock / "
                "Cargo.lock / Gemfile.lock / composer.lock / go.sum."
            ],
            tool_metadata=report.to_dict(),
        )

    # ----- Phase 6.4: import-level reachability annotation -----
    # Computed once over the whole repo, indexed by (ecosystem, name)
    # so the per-package emit loop is O(1) lookup. We always pull
    # the dict (cheap), but skip the source-tree walk entirely when
    # `with_reachability=False`.
    reachability_map: dict = {}
    reachability_stats = {
        "direct_import": 0, "transitive_only": 0,
        "unused": 0, "unknown": 0,
    }
    if with_reachability:
        try:
            from strix.sca.reachability import annotate_matches as _annotate

            reachability_map = _annotate(
                report.vulnerable_packages, repo_path=repo_path,
            )
            for r in reachability_map.values():
                reachability_stats[r.status] = (
                    reachability_stats.get(r.status, 0) + 1
                )
        except Exception as e:  # noqa: BLE001
            logger.debug("sca: reachability annotate failed: %s", e, exc_info=True)
            reachability_map = {}

    suppressed_by_reachability = 0

    for match in report.vulnerable_packages:
        reach = reachability_map.get(
            (match.package.ecosystem, match.package.name)
        )
        # `only_reachable` policy: drop findings for unused /
        # transitive packages entirely. KEV / EPSS≥0.5 still passes
        # (those override demotion via `adjusted_severity`).
        if (
            only_reachable
            and reach is not None
            and reach.status in ("unused", "transitive_only")
            and not match.has_kev
            and (match.max_epss or 0.0) < 0.5
        ):
            suppressed_by_reachability += 1
            continue

        rid = _emit_finding(
            package_match=match,
            repo_path=repo_path,
            reachability=reach,
        )
        if rid:
            emitted_count += 1
        sev = match.severity_max
        if match.has_kev:
            sev = "critical"
        elif match.max_epss >= 0.5 and sev != "critical":
            sev = _bump_severity(sev)
        # Apply reachability demotion AFTER KEV/EPSS escalation —
        # the override happens inside `adjusted_severity` so KEV
        # findings can't be quietly demoted by a "we don't see the
        # import" signal.
        if reach is not None:
            sev = reach.adjusted_severity(
                sev,
                kev=match.has_kev,
                epss=match.max_epss,
            )
        title_suffix = ""
        if reach is not None and reach.status != "direct_import":
            title_suffix = f" [reachability={reach.status}]"
        drafts.append(FindingDraft(
            title=(
                f"Vulnerable dependency `{match.package.ecosystem}:"
                f"{match.package.name}@{match.package.version}` "
                f"({len(match.cves)} CVE{'s' if len(match.cves) > 1 else ''})"
                f"{title_suffix}"
            )[:480],
            severity=sev,
            cwe=None,
            endpoint=match.package.source_path,
            category="vulnerable_dependency",
            verification_status="verified",
            confidence=0.95,
            description=f"{len(match.cves)} matching CVE(s) in threat-intel cache",
        ))
        evidence.append(
            f"vuln_dep: {match.package.display_name} → "
            f"{len(match.cves)} CVE(s)"
            + (" [KEV]" if match.has_kev else "")
            + (f" [{reach.status}]" if reach is not None else "")
        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(
            repo_path, method="SCA",
            probed_for="vulnerable_dependency",
        )
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation",
            target=repo_path,
            actor={"tool_name": "scan_sca_lockfiles"},
            input={
                "repo_path": repo_path,
                "only_kev": only_kev,
                "min_epss": min_epss,
                "skip_dev_only": skip_dev_only,
                "lockfiles_scanned": report.lockfiles_scanned,
            },
            output={
                "packages_total": report.packages_total,
                "vulnerable_packages": len(report.vulnerable_packages),
                "total_cves": report.total_cves,
                "kev_count": report.kev_count,
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
                "follow up with `lookup_known_cves` for any KEV-listed CVEs "
                "to plan upgrade priority",
                "consider running scan_sca_lockfiles with only_kev=True "
                "for a tight critical-priority view",
            ]
            if drafts else
            [
                "no vulnerable dependencies matched the threat-intel cache; "
                "verify cache freshness via threat_intel_status (run "
                "`python -m strix.threat_intel.refresh` if stale)",
            ]
        ),
        tool_metadata={
            "lockfiles_scanned": report.lockfiles_scanned,
            "packages_total": report.packages_total,
            "packages_by_ecosystem": report.packages_by_ecosystem,
            "vulnerable_packages": len(report.vulnerable_packages),
            "total_cves": report.total_cves,
            "kev_count": report.kev_count,
            "critical_count": report.critical_count,
            "findings_emitted_to_tracer": emitted_count,
            # Phase 6.4 — per-status reachability rollup. Lets the
            # wrapper render a "we filtered N noise findings" badge
            # without re-walking the source tree itself.
            "reachability": {
                "enabled": with_reachability,
                "by_status": reachability_stats,
                "suppressed": suppressed_by_reachability,
            },
        },
    )
