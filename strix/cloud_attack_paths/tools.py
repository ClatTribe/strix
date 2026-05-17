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
    auto_snapshot_orchestration: bool = False,
    auto_snapshot_regions: list[str] | None = None,
    auto_snapshot_max_instances_per_region: int = 25,
    auto_snapshot_cleanup: bool = True,
    cloudtrail_events_path: str | None = None,
    cloudtrail_events: list[dict[str, Any]] | None = None,
    enumerate_org_accounts: bool = False,
    org_role_name: str = "OrganizationAccountAccessRole",
    azure_subscription_id: str | None = None,
    azure_services: list[str] | None = None,
    _azure_client_factory: Any | None = None,
    gcp_project_id: str | None = None,
    gcp_services: list[str] | None = None,
    _gcp_client_factory: Any | None = None,
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
        auto_snapshot_orchestration: when True, strix
            auto-discovers running EC2 instances, snapshots
            their attached volumes, runs Trivy on each transient
            snapshot, then deletes them. Closes the agentless
            v1→v2 gap: ops teams without an existing snapshot
            pipeline get CVE inventory of every live instance
            with no setup. Each snapshot is tagged
            `strix-transient=true` for cleanup attribution. Per
            `auto_snapshot_cleanup=False`, snapshots remain in
            the account for offline analysis. AWS-only.
        auto_snapshot_regions: regions to enumerate instances
            in (default = `regions` kwarg, or `["us-east-1"]`).
        auto_snapshot_max_instances_per_region: hard cap (per
            region) to bound the EBS Direct API cost. Default
            25; each scan reads tens-of-MB to GB depending on
            volume size.
        auto_snapshot_cleanup: when True (default), delete the
            transient snapshots after scanning. When False,
            snapshots remain in the account — useful for offline
            re-analysis at the cost of $0.05/GB-month storage.
            Either way, `tool_metadata.auto_snapshot_summary`
            carries the `manual_cleanup_required` list of un-
            deleted snapshot IDs so an operator can finish
            cleanup if a delete failed.
        cloudtrail_events_path: file path to a CloudTrail event
            export (JSON-lines OR `{"Records": [...]}` bundle).
            When set, runs the CDR rule engine against the events
            and emits per-rule findings as `category=cdr_detection`.
        cloudtrail_events: alternative to `cloudtrail_events_path`
            — pre-parsed event list. Useful when the caller is
            ingesting from `cloudtrail:LookupEvents` API or
            another live source.
        enumerate_org_accounts: when True, calls
            `organizations:ListAccounts` from the
            management-account credentials (resolved via
            `profile_name` / `role_arn`) and auto-populates the
            `additional_role_arns` list with the cross-account
            role ARNs for every active member account. Removes
            the manual "list every account's role" step for
            customers running an AWS Organization. AWS-only.
        org_role_name: role NAME (not full ARN) strix should
            assume in each member account when enumerating an
            org. Default `OrganizationAccountAccessRole` is
            the AWS-default created automatically when accounts
            are added to an organization.
        azure_subscription_id: when set AND `provider="azure"`,
            run read-only Azure asset discovery for the given
            subscription to enrich the cloud-attack-path graph
            beyond CSPM-flagged resources only. Mirrors the AWS
            `auto_discover_assets` enrichment. Discovers storage
            accounts, VMs, NSGs, public IPs, RBAC role
            assignments + definitions, key vaults, App Services
            + Function Apps, and ACR registries.
        azure_services: optional allow-list of Azure services
            to discover (e.g. `["storage", "compute"]`). None
            = all of them.
        _azure_client_factory: DI hook for tests — bypasses the
            real Azure SDK. None → real implementation looked
            up lazily (and gated on whether the SDK is
            available).
        gcp_project_id: when set AND `provider="gcp"`, run
            read-only GCP asset discovery for the given project
            to enrich the cloud-attack-path graph beyond
            CSPM-flagged resources only. Discovers GCS buckets,
            GCE instances, firewalls, service accounts +
            project-level IAM bindings, Cloud Functions,
            Cloud Run, Cloud SQL, Secret Manager secrets, and
            Artifact Registry repos.
        gcp_services: optional allow-list of GCP services to
            discover. None = all of them.
        _gcp_client_factory: DI hook for tests — bypasses the
            real google-cloud-* SDK.

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

    # Org-wide enumeration: when set, calls
    # `organizations:ListAccounts` from management-account
    # credentials and auto-populates additional_role_arns. Removes
    # the manual per-account-list maintenance for AWS Org
    # customers.
    org_enumerated_arns: list[str] = []
    if enumerate_org_accounts and provider == "aws":
        try:
            from strix.cloud_attack_paths.multi_account import (  # noqa: PLC0415
                enumerate_org_accounts as _enum_org,
            )
            org_enumerated_arns = _enum_org(
                profile_name=profile_name, role_arn=role_arn,
                role_name_template=org_role_name,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "scan_cloud_attack_paths: org enumeration failed: "
                "%s", e, exc_info=True,
            )
            cspm_errors.append({
                "source": "org_enumeration",
                "error": f"{type(e).__name__}: {e}",
            })

    # Combined list = caller-supplied + org-enumerated. Dedupe
    # to avoid scanning the same account twice if a role was
    # both explicitly listed AND in the org enumeration.
    combined_role_arns: list[str] = []
    if additional_role_arns:
        combined_role_arns.extend(additional_role_arns)
    for arn in org_enumerated_arns:
        if arn not in combined_role_arns:
            combined_role_arns.append(arn)

    if (
        combined_role_arns
        and provider == "aws"
    ):
        try:
            from strix.cloud_attack_paths.multi_account import (  # noqa: PLC0415
                scan_multi_account, summarise,
                union_assets, union_findings,
            )
            multi_results = scan_multi_account(
                combined_role_arns,
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

    # Auto-snapshot orchestration (masterroadmap §5 P2 v2). Closes
    # the v1→v2 gap of `agentless_snapshot_ids` (which required
    # the operator to pre-snapshot every volume out-of-band). When
    # enabled, strix lists running instances → snapshots their
    # attached volumes → runs `trivy vm` → deletes the snapshots.
    # AWS-only. Per-instance errors are isolated; any un-deleted
    # snapshot surfaces in `manual_cleanup_required` for operator
    # follow-up. Tag `strix-transient=true` on every snapshot.
    auto_snapshot_summary: dict[str, Any] | None = None
    if auto_snapshot_orchestration and provider == "aws":
        try:
            from strix.cloud_attack_paths.agentless_scan import (  # noqa: PLC0415
                auto_snapshot_and_scan,
                summarise as summarise_agentless2,
                union_findings as union_agentless_findings2,
            )
            from strix.cspm.aws.client import (  # noqa: PLC0415
                make_default_client_factory as _mk_factory,
            )
            auto_factory = _mk_factory(
                profile_name=profile_name, role_arn=role_arn,
            )
            auto_results, auto_lifecycle = auto_snapshot_and_scan(
                auto_factory,
                regions=auto_snapshot_regions or regions,
                max_instances_per_region=(
                    auto_snapshot_max_instances_per_region
                ),
                cleanup_on_completion=auto_snapshot_cleanup,
            )
            findings.extend(union_agentless_findings2(auto_results))
            scan_summary = summarise_agentless2(auto_results)
            auto_snapshot_summary = {
                "lifecycle": auto_lifecycle,
                "scan": scan_summary,
            }
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "scan_cloud_attack_paths: auto-snapshot "
                "orchestration failed: %s", e, exc_info=True,
            )
            cspm_errors.append({
                "source": "auto_snapshot_orchestration",
                "error": f"{type(e).__name__}: {e}",
            })

    # Azure asset discovery (masterroadmap §5 v2 deepening).
    # Parallel to AWS auto_discover_assets, but Azure SDK-based.
    # Opt-in via `azure_subscription_id`; tests inject the factory.
    azure_assets_count = 0  # always-bound for tool_metadata branch
    if provider == "azure" and azure_subscription_id:
        try:
            from strix.cloud_attack_paths.azure_discovery import (  # noqa: PLC0415
                discover_azure_assets,
            )
            az_factory = _azure_client_factory
            if az_factory is None:
                # Real impl is gated on whether the Azure SDK is
                # installed. Don't crash discovery if it isn't.
                try:
                    from strix.cspm.azure.client import (  # noqa: PLC0415
                        make_default_azure_client_factory,
                    )
                    az_factory = make_default_azure_client_factory()
                except Exception as e:  # noqa: BLE001
                    logger.debug(
                        "scan_cloud_attack_paths: azure SDK "
                        "client unavailable, skipping discovery: %s",
                        e,
                    )
                    az_factory = None
            if az_factory is not None:
                az_assets = discover_azure_assets(
                    az_factory, azure_subscription_id,
                    services=azure_services,
                )
                extra_cspm_assets.extend(az_assets)
                azure_assets_count = len(az_assets)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "scan_cloud_attack_paths: azure discovery "
                "failed: %s", e, exc_info=True,
            )
            cspm_errors.append({
                "source": "azure_discovery",
                "error": f"{type(e).__name__}: {e}",
            })

    # GCP asset discovery (masterroadmap §5 v2 deepening).
    # Parallel to AWS / Azure auto-discovery. Opt-in via
    # `gcp_project_id`; tests inject the factory.
    gcp_assets_count = 0  # always-bound for tool_metadata branch
    if provider == "gcp" and gcp_project_id:
        try:
            from strix.cloud_attack_paths.gcp_discovery import (  # noqa: PLC0415
                discover_gcp_assets,
            )
            g_factory = _gcp_client_factory
            if g_factory is None:
                try:
                    from strix.cspm.gcp.client import (  # noqa: PLC0415
                        make_default_gcp_client_factory,
                    )
                    g_factory = make_default_gcp_client_factory()
                except Exception as e:  # noqa: BLE001
                    logger.debug(
                        "scan_cloud_attack_paths: gcp SDK "
                        "client unavailable, skipping discovery: "
                        "%s", e,
                    )
                    g_factory = None
            if g_factory is not None:
                gcp_assets = discover_gcp_assets(
                    g_factory, gcp_project_id,
                    services=gcp_services,
                )
                extra_cspm_assets.extend(gcp_assets)
                gcp_assets_count = len(gcp_assets)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "scan_cloud_attack_paths: gcp discovery "
                "failed: %s", e, exc_info=True,
            )
            cspm_errors.append({
                "source": "gcp_discovery",
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
    if org_enumerated_arns:
        tool_metadata["org_enumerated_accounts"] = len(org_enumerated_arns)
    if agentless_summary is not None:
        tool_metadata["agentless_scan_summary"] = agentless_summary
    if auto_snapshot_summary is not None:
        tool_metadata["auto_snapshot_summary"] = auto_snapshot_summary
    if azure_assets_count:
        tool_metadata["azure_assets_discovered"] = azure_assets_count
    if gcp_assets_count:
        tool_metadata["gcp_assets_discovered"] = gcp_assets_count
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
