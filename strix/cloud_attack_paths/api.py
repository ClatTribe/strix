"""Public wrapper-facing API for cloud attack-path analysis.

This is the stable surface webappsec/ (and any other wrapper)
imports. Everything else in this module is implementation detail
subject to internal refactor — `analyze_cloud_attack_paths` +
`AttackPathReport` are the contract.

Two entry shapes for callers:

  1. **Pre-collected findings + assets**: caller already ran
     CSPM elsewhere and has the data in memory. Pass the lists
     directly; we build the graph + run patterns. No I/O.

  2. **Run from scratch**: caller hasn't scanned yet. Use the
     specialist tool `scan_cloud_attack_paths` (in `tools.py`)
     which composes `scan_cloud_account` + this API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from strix.cloud_attack_paths.graph import CloudGraph
from strix.cloud_attack_paths.ingest import build_graph_from_cspm
from strix.cloud_attack_paths.patterns import (
    AttackPath,
    PatternFn,
    find_attack_paths,
)
from strix.cspm.aws import CspmFinding


@dataclass
class AttackPathReport:
    """Aggregate result returned by `analyze_cloud_attack_paths`.

    Wrappers can:
      * Render `paths` as the primary user-facing list (grouped
        by `pattern_id` for dashboards).
      * Persist `to_dict()` JSON for trend / drift analysis.
      * Use `summary` for top-of-dashboard metrics.
      * Use `graph_summary` to render a node/edge count panel.
    """
    paths: list[AttackPath] = field(default_factory=list)
    graph: CloudGraph | None = None
    # Echoed inputs for caller convenience (no need to re-pass).
    findings_consumed: int = 0
    assets_consumed: int = 0

    @property
    def summary(self) -> dict[str, int]:
        by_sev: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        by_pattern: dict[str, int] = {}
        for p in self.paths:
            sev = (p.severity or "medium").lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_pattern[p.pattern_id] = by_pattern.get(p.pattern_id, 0) + 1
        return {
            "total": len(self.paths),
            **by_sev,
            **{f"pattern:{k}": v for k, v in by_pattern.items()},
        }

    @property
    def graph_summary(self) -> dict[str, int] | None:
        if self.graph is None:
            return None
        return self.graph.to_dict().get("summary")

    def critical_paths(self) -> list[AttackPath]:
        return [p for p in self.paths if p.severity == "critical"]

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "summary": self.summary,
            "findings_consumed": self.findings_consumed,
            "assets_consumed": self.assets_consumed,
            "paths": [p.to_dict() for p in self.paths],
        }
        if self.graph is not None:
            out["graph_summary"] = self.graph_summary
        return out


def analyze_cloud_attack_paths(
    *,
    cspm_findings: Iterable[CspmFinding] | None = None,
    cloud_assets: Iterable[dict[str, Any]] | None = None,
    patterns: list[str] | None = None,
    custom_patterns: dict[str, PatternFn] | None = None,
    include_graph: bool = False,
    enable_live_probes: bool | None = None,
    discover_client_factory: Any | None = None,
    discover_regions: list[str] | None = None,
    discover_services: list[str] | None = None,
) -> AttackPathReport:
    """Build a cloud graph + detect attack paths + return a report.

    This is the stable public API. The wrapper (webappsec/) and any
    other consumer is expected to import THIS function — internal
    modules may shift.

    Args:
        cspm_findings: iterable of `CspmFinding`. The minimum input;
            usually obtained from `strix.cspm.tools.scan_cloud_account`
            or directly from `strix.cspm.aws.scanner.scan_aws_account`.
        cloud_assets: optional list of resource / identity / policy
            dicts to enrich the graph beyond findings. See
            `strix.cloud_attack_paths.ingest.build_graph_from_cspm`
            for the recognised shape.
        patterns: optional allow-list of pattern IDs to run.
            None = all built-ins.
        custom_patterns: extra pattern functions to evaluate
            alongside built-ins. Useful for org-specific scenarios
            (e.g. "internal-only-VPC resource accidentally has a
            public LB") without forking strix.
        include_graph: when True, the returned report carries the
            full `CloudGraph` object. Default False — most wrappers
            only need the path list + summary. Pass True for
            visualisation use cases (graph-render dashboards).
        enable_live_probes: when True, attempts to externally verify
            each detected path via the registered probe (anonymous
            S3 HEAD, TCP reachability check, etc.). Verified paths
            get `confidence=0.99+`, prepended "VERIFIED LIVE"
            narrative, and probe evidence in `metadata.live_probe`.
            Defaults to None (defer to `STRIX_CLOUD_LIVE_PROBES`
            env var; OFF by default). See
            `strix.cloud_attack_paths.live_probes` for the safety
            contract — probes can trigger SOC alerts + AWS
            billing, so opt-in is explicit.
        discover_client_factory: when set, boto3 client factory
            used to enumerate AWS assets (S3 buckets, IAM
            principals + policies, EC2 instances, RDS DBs, Lambdas
            + function URLs, ECR repos, secrets) via the read-only
            `Describe* / List* / Get*` API surface. The discovered
            assets are merged with caller-supplied `cloud_assets`
            and CSPM findings to build the richest possible graph.
            Same factory shape as
            `strix.cspm.aws.client.make_default_client_factory`.
        discover_regions: regions to enumerate per-region services
            in. None → `["us-east-1"]`.
        discover_services: optional allow-list (`s3` / `iam` /
            `ec2` / `rds` / `lambda` / `ecr` / `secretsmanager`).
            None = all.

    Returns:
        `AttackPathReport` with sorted `paths` (critical-first),
        summary aggregates, and optional graph attached.

    Example (wrapper integration):

        >>> from strix.cspm.tools import scan_cloud_account
        >>> from strix.cloud_attack_paths import analyze_cloud_attack_paths
        >>>
        >>> # 1. Scan the account
        >>> scan = scan_cloud_account(provider="aws", profile_name="prod")
        >>> # 2. Compute attack paths
        >>> report = analyze_cloud_attack_paths(
        ...     cspm_findings=scan_findings_from_scan(scan),
        ... )
        >>> # 3. Render
        >>> for path in report.critical_paths():
        ...     print(path.title, path.severity)
    """
    findings_list = list(cspm_findings or [])
    assets_list = list(cloud_assets or [])

    # Auto-discovery enriches the caller's asset list with read-only
    # boto3 enumeration. Per-service errors don't stop discovery —
    # partial assets are still useful for partial patterns.
    if discover_client_factory is not None:
        try:
            from strix.cloud_attack_paths.discovery import (  # noqa: PLC0415
                discover_aws_assets,
            )
            discovered = discover_aws_assets(
                discover_client_factory,
                regions=discover_regions,
                services=discover_services,
            )
            assets_list.extend(discovered)
        except Exception as e:  # noqa: BLE001
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "analyze_cloud_attack_paths: discovery failed: %s", e,
                exc_info=True,
            )

    graph = build_graph_from_cspm(
        findings_list, assets=assets_list,
    )
    paths = find_attack_paths(
        graph, patterns=patterns, custom_patterns=custom_patterns,
    )

    # Live-probe verification (opt-in). When enabled, each path
    # whose pattern has a registered probe gets externally probed;
    # the AttackPath is upgraded in-place with proof / non-proof
    # evidence. Failures (probe error / no probe registered) leave
    # the path unchanged — pattern-derived signal is still good.
    from strix.cloud_attack_paths.live_probes import (
        is_live_probes_enabled,
        run_probe,
        upgrade_path_with_probe,
    )
    if is_live_probes_enabled(explicit=enable_live_probes):
        for p in paths:
            probe_result = run_probe(p)
            if probe_result is not None:
                upgrade_path_with_probe(p, probe_result)

    return AttackPathReport(
        paths=paths,
        graph=graph if include_graph else None,
        findings_consumed=len(findings_list),
        assets_consumed=len(assets_list),
    )
