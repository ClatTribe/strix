"""LLM-facing specialist + tracer emit for cloud attack paths.

Composes `scan_cloud_account` (CSPM) + `analyze_cloud_attack_paths`
(graph analysis) into one in-agent surface. Each detected attack
path becomes a tracer finding with `category=cloud_attack_path`
and the MITRE technique mapping the path covers.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.cloud_attack_paths.api import (
    AttackPathReport,
    analyze_cloud_attack_paths,
)
from strix.cloud_attack_paths.patterns import AttackPath
from strix.cspm.aws.scanner import scan_aws_account
from strix.cspm.prowler import is_prowler_available, run_prowler
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Severity bump rationale: attack paths combine N findings into one
# narrative — by definition the blast radius is wider than any
# constituent. We don't bump (severity is already chosen by the
# pattern), but we set confidence higher because graph-level
# evidence is stronger than single-finding evidence.
_PATH_CONFIDENCE = 0.95


def _emit_attack_path(
    *, path: AttackPath, target: str,
    live_verified: bool = False,
) -> str | None:
    """Emit one attack path to the tracer with classification +
    MITRE metadata.

    `live_verified=True` upgrades the tracer's `verification_status`
    to `"exploited"` — the engine-canonical signal for "we did
    more than pattern-match; an external probe confirmed the
    primitive fires." Mirrors the contract used elsewhere for
    MOAK-verified-live findings.
    """
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        title = f"[cloud-attack-path] {path.title}"[:480]
        endpoint = path.hops[0] if path.hops else target

        description = (
            f"{path.narrative}\n\n"
            f"Hop chain: {' → '.join(path.hops)}"
        )

        report_id = tracer.add_vulnerability_report(
            title=title,
            severity=path.severity,
            endpoint=endpoint,
            target=target,
            category="cloud_attack_path",
            rule_id=path.pattern_id,
            verification_status=(
                "exploited" if live_verified else "verified"
            ),
            confidence=path.confidence or _PATH_CONFIDENCE,
            description=description,
            impact=(
                "Cloud attack paths chain individual misconfigs into "
                "concrete attacker scenarios. A single 'public bucket' "
                "finding is a control violation; the same bucket "
                "containing terraform state with raw IAM keys is a "
                "full account compromise. Wrappers should prioritise "
                "attack-path findings above their constituent CSPM "
                "findings — the blast radius is the union of every "
                "permission an attacker collects walking the chain."
            ),
            technical_analysis=(
                f"Pattern ID: {path.pattern_id}\n"
                f"Severity: {path.severity}\n"
                f"Reachability score: "
                f"{getattr(path, 'reachability_score', 0.0):.2f}\n"
                f"Hops ({len(path.hops)}):\n"
                + "\n".join(f"  {i+1}. {h}" for i, h in enumerate(path.hops))
                + f"\nEvidence edges: {', '.join(path.evidence_edges) or '(none)'}\n"
                + f"MITRE: {', '.join(path.mitre_techniques) or '(none)'}\n"
                + f"Metadata: {path.metadata}"
            ),
            remediation_steps=path.remediation,
        )
        return report_id
    except Exception as e:  # noqa: BLE001
        logger.debug("attack-path emit failed: %s", e, exc_info=True)
        return None


def _collect_cspm_findings(
    *, provider: str, profile_name: str | None, role_arn: str | None,
    regions: list[str] | None, prefer_prowler: bool,
):
    """Mirror the dispatch logic in `strix.cspm.tools.scan_cloud_account`
    but return RAW findings (not emit-only). Attack-path analysis
    needs the unemitted finding objects to build the graph."""
    if prefer_prowler and is_prowler_available():
        result = run_prowler(
            provider=provider, profile=profile_name,
            role_arn=role_arn, regions=regions,
        )
        if result.findings or not result.errors:
            return result.findings, "prowler", result.errors, result.metadata

    if provider != "aws":
        return [], "none", [
            {"source": "cspm", "error": (
                f"Prowler unavailable and built-in fallback only "
                f"supports AWS; got `{provider}`"
            )},
        ], {}

    report = scan_aws_account(
        regions=regions, profile_name=profile_name, role_arn=role_arn,
    )
    return (
        report.findings, "boto3", report.errors,
        {
            "account_id": report.account_id,
            "regions_scanned": report.regions_scanned,
        },
    )


@register_specialist_tool(
    category="cloud-attack-path-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 1800},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190", "T1078.004", "T1552.001"],
)
def scan_cloud_attack_paths(
    *,
    provider: str = "aws",
    profile_name: str | None = None,
    role_arn: str | None = None,
    regions: list[str] | None = None,
    prefer_prowler: bool = True,
    patterns: list[str] | None = None,
    enable_live_probes: bool | None = None,
    auto_discover_assets: bool = True,
    additional_role_arns: list[str] | None = None,
    agentless_snapshot_ids: list[str] | None = None,
    cloudtrail_events_path: str | None = None,
    cloudtrail_events: list[dict[str, Any]] | None = None,
) -> SpecialistResult:
    """Run a CSPM scan, build the cloud graph, detect attack paths,
    emit each path to the tracer.

    Args:
        provider: `aws` / `azure` / `gcp` / `kubernetes`. Built-in
            fallback only supports `aws`.
        profile_name / role_arn / regions: CSPM auth pass-through.
        prefer_prowler: use Prowler if installed (multi-cloud +
            500+ checks); falls back to built-in boto3 for AWS.
        patterns: optional allow-list of pattern IDs. None = all
            built-in patterns.
        enable_live_probes: when True, opts into external
            verification probes (anonymous S3 HEAD, TCP
            reachability, etc.). OFF by default — probes can
            trigger SOC alerts + minor billing. See
            `strix.cloud_attack_paths.live_probes` for the safety
            contract. Engagement-level override via
            `STRIX_CLOUD_LIVE_PROBES=1` env.
        auto_discover_assets: when True (default) AND the CSPM
            scan used the AWS boto3 path, enumerate additional
            assets via read-only `Describe* / List* / Get*` APIs
            to enrich the cloud-attack-path graph beyond just
            CSPM-flagged resources. Same boto3 client factory is
            reused, so no extra auth setup needed. Skipped when
            Prowler ran (Prowler does its own enumeration) or
            when scanning non-AWS providers.
        additional_role_arns: when set, fan out the scan across
            additional AWS accounts via assume-role. Each ARN is
            scanned independently (CSPM + asset discovery); the
            findings + assets are unioned into the graph so
            cross-account attack-path chains (e.g. user in
            account A can assume admin in account B) materialise
            automatically. Per-role errors don't stop the rest
            — partial multi-account results are emitted. AWS-only;
            ignored for non-AWS providers.
        agentless_snapshot_ids: when set, run an agentless VM
            CVE scan (via `trivy vm ebs:<snapshot-id>`) on each
            EBS snapshot ID. Per-snapshot CVE findings union
            into the tracer output as `category=agentless_vm_cve`.
            Wiz's biggest moat against agent-based competitors;
            v1 wraps Trivy's EBS-snapshot scanner. AWS-only.
        cloudtrail_events_path: file path to a CloudTrail event
            export (JSON-lines OR `{"Records": [...]}` bundle).
            When set, runs the CDR rule engine against the events
            and emits per-rule findings as `category=cdr_detection`.
        cloudtrail_events: alternative to `cloudtrail_events_path`
            — pre-parsed event list. Useful when the caller is
            ingesting from `cloudtrail:LookupEvents` API or
            another live source.

    Returns:
        `SpecialistResult` with one finding per detected attack
        path. `tool_metadata.attack_paths_summary` carries the
        per-pattern + per-severity counts the wrapper renders.
        When live probes ran, `tool_metadata.live_probes_summary`
        also carries the verified / not-verified / error counts.
    """
    if provider not in ("aws", "azure", "gcp", "kubernetes"):
        return SpecialistResult(
            status="error",
            error=f"unsupported provider: {provider!r}",
        )

    findings, cspm_engine, cspm_errors, cspm_meta = _collect_cspm_findings(
        provider=provider, profile_name=profile_name,
        role_arn=role_arn, regions=regions,
        prefer_prowler=prefer_prowler,
    )

    if not findings and cspm_engine == "none":
        return SpecialistResult(
            status="error",
            error=(
                cspm_errors[0]["error"] if cspm_errors
                else "no CSPM engine available"
            ),
        )

    # Build a client factory for asset discovery when applicable.
    # Discovery only fires when we're on AWS AND auto_discover_assets
    # is on. Prowler-runs skip discovery (Prowler enumerates already);
    # cspm_engine reports which path actually ran.
    discover_factory = None
    if (
        auto_discover_assets
        and provider == "aws"
        and cspm_engine in ("boto3", "boto3-fallback")
    ):
        try:
            from strix.cspm.aws.client import make_default_client_factory  # noqa: PLC0415
            discover_factory = make_default_client_factory(
                profile_name=profile_name, role_arn=role_arn,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "scan_cloud_attack_paths: could not build discovery "
                "factory: %s", e, exc_info=True,
            )

    # Multi-account fan-out (AWS only). Each additional role_arn
    # gets its own CSPM scan + asset discovery; findings + assets
    # are unioned into the graph so cross-account attack-path
    # chains materialise via the existing can_assume edge
    # derivation. Per-role errors don't stop the rest of the
    # fan-out.
    multi_account_summary: dict[str, Any] | None = None
    extra_cspm_assets: list[dict[str, Any]] = []
    if (
        additional_role_arns
        and provider == "aws"
    ):
        try:
            from strix.cloud_attack_paths.multi_account import (  # noqa: PLC0415
                scan_multi_account, summarise,
                union_assets, union_findings,
            )
            multi_results = scan_multi_account(
                additional_role_arns,
                profile_name=profile_name,
                regions=regions,
            )
            findings.extend(union_findings(multi_results))
            extra_cspm_assets.extend(union_assets(multi_results))
            multi_account_summary = summarise(multi_results)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "scan_cloud_attack_paths: multi-account fan-out "
                "failed: %s", e, exc_info=True,
            )
            cspm_errors.append({
                "source": "multi_account",
                "error": f"{type(e).__name__}: {e}",
            })

    # Agentless VM CVE scan (masterroadmap §5 P2). Wraps Trivy's
    # EBS-snapshot mode; per-snapshot findings union into the
    # CSPM findings list so they ride the same tracer + emit
    # pipeline. AWS-only; non-AWS providers ignore the kwarg.
    agentless_summary: dict[str, Any] | None = None
    if agentless_snapshot_ids and provider == "aws":
        try:
            from strix.cloud_attack_paths.agentless_scan import (  # noqa: PLC0415
                scan_snapshots, summarise as summarise_agentless,
                union_findings as union_agentless_findings,
            )
            agentless_results = scan_snapshots(agentless_snapshot_ids)
            findings.extend(union_agentless_findings(agentless_results))
            agentless_summary = summarise_agentless(agentless_results)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "scan_cloud_attack_paths: agentless scan failed: %s",
                e, exc_info=True,
            )
            cspm_errors.append({
                "source": "agentless_vm_scan",
                "error": f"{type(e).__name__}: {e}",
            })

    # CDR — CloudTrail rule engine (masterroadmap §5 P3). Pure-
    # data transformation over a caller-supplied event list. Findings
    # adapt to CspmFinding shape via `.to_cspm_finding()` so they
    # ride the existing tracer + compliance pipeline. AWS-only.
    cdr_summary: dict[str, Any] | None = None
    if provider == "aws" and (cloudtrail_events_path or cloudtrail_events):
        try:
            from strix.cloud_attack_paths.cloudtrail_detection import (  # noqa: PLC0415
                detect, load_events_from_file,
                summarise as summarise_cdr,
            )
            events_list: list[dict[str, Any]] = list(cloudtrail_events or [])
            if cloudtrail_events_path:
                events_list.extend(
                    load_events_from_file(cloudtrail_events_path),
                )
            cdr_findings = detect(events_list)
            findings.extend(f.to_cspm_finding() for f in cdr_findings)
            cdr_summary = summarise_cdr(cdr_findings)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "scan_cloud_attack_paths: CDR rule engine failed: "
                "%s", e, exc_info=True,
            )
            cspm_errors.append({
                "source": "cdr",
                "error": f"{type(e).__name__}: {e}",
            })

    report = analyze_cloud_attack_paths(
        cspm_findings=findings, patterns=patterns,
        enable_live_probes=enable_live_probes,
        discover_client_factory=discover_factory,
        discover_regions=regions,
        cloud_assets=extra_cspm_assets or None,
    )

    target = f"cloud-attack-paths:{provider}"
    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted = 0

    # Aggregate live-probe outcomes for the metadata summary.
    live_probes_summary = {
        "verified": 0, "not_verified": 0, "error": 0, "skipped": 0,
    }
    any_probes_ran = False

    for p in report.paths:
        live_probe = (p.metadata or {}).get("live_probe")
        is_live_verified = (
            isinstance(live_probe, dict)
            and live_probe.get("status") == "verified"
        )
        if isinstance(live_probe, dict):
            any_probes_ran = True
            status = live_probe.get("status", "")
            if status in live_probes_summary:
                live_probes_summary[status] += 1
        # Verified-live paths carry confidence ≥0.99 (the upgrade
        # in `live_probes.upgrade_path_with_probe`); the draft +
        # tracer report inherit that. The tracer's
        # `verification_status="exploited"` carries the distinction
        # the FindingDraft schema's Literal doesn't yet permit —
        # wrappers read the tracer report for the auditor-grade
        # signal.
        rid = _emit_attack_path(
            path=p, target=target,
            live_verified=is_live_verified,
        )
        if rid:
            emitted += 1
        drafts.append(FindingDraft(
            title=f"[cloud-attack-path] {p.title}"[:480],
            severity=p.severity,
            cwe=None,
            endpoint=p.hops[0] if p.hops else target,
            category="cloud_attack_path",
            verification_status="verified",
            confidence=p.confidence or _PATH_CONFIDENCE,
            description=p.narrative[:480],
        ))
        evidence.append(
            f"cap:{p.pattern_id} sev={p.severity} hops={len(p.hops)}"
            + (f" probe={live_probe.get('status')}"
               if isinstance(live_probe, dict) else "")
        )

    # Reachability bucket counts for the dashboard rollup.
    reachability_buckets = {
        "directly_exposed": 0,    # score 1.0
        "1_hop_from_public": 0,   # 0.7
        "2_hops_from_public": 0,  # 0.4
        "deeper_or_isolated": 0,  # 0.1 or 0.0
    }
    for p in report.paths:
        rs = getattr(p, "reachability_score", 0.0) or 0.0
        if rs >= 1.0:
            reachability_buckets["directly_exposed"] += 1
        elif rs >= 0.7:
            reachability_buckets["1_hop_from_public"] += 1
        elif rs >= 0.4:
            reachability_buckets["2_hops_from_public"] += 1
        else:
            reachability_buckets["deeper_or_isolated"] += 1

    tool_metadata: dict[str, Any] = {
        "engine": "cloud-attack-paths-v1",
        "provider": provider,
        "cspm_engine": cspm_engine,
        "cspm_findings_consumed": report.findings_consumed,
        "attack_paths_summary": report.summary,
        "attack_paths_total": len(report.paths),
        "critical_paths": len(report.critical_paths()),
        "findings_emitted_to_tracer": emitted,
        "reachability_buckets": reachability_buckets,
        "cspm_metadata": cspm_meta,
        "cspm_errors": cspm_errors[:5],
    }
    if multi_account_summary is not None:
        tool_metadata["multi_account_summary"] = multi_account_summary
    if agentless_summary is not None:
        tool_metadata["agentless_scan_summary"] = agentless_summary
    if cdr_summary is not None:
        tool_metadata["cdr_summary"] = cdr_summary
    if any_probes_ran:
        tool_metadata["live_probes_summary"] = live_probes_summary
        tool_metadata["live_probes_enabled"] = True

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=[
            "for critical attack paths, verify exploitability live "
            "where possible (anonymous S3 GET, SG port reachability, "
            "SQS SendMessage)",
            "audit IAM identities attached to internet-exposed "
            "compute resources — least-privilege them first",
            "where attack paths share a hop, fixing the shared hop "
            "clears multiple paths at once",
        ],
        tool_metadata=tool_metadata,
    )
