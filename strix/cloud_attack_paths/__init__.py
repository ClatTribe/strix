"""Cloud attack-path reasoning — \"toxic combinations\" detection.

Wiz's core differentiator at the enterprise tier isn't its 1500-
check CSPM corpus — it's graph traversal that chains individual
findings into red-team scenarios:

  * \"Public bucket + terraform state + IAM keys with `s3:*`\" →
    one attack-path finding, critical.
  * \"Open SG + EC2 with IAM role + role can read secretsmanager\"
    → one attack-path finding, critical.
  * \"Public Lambda + assumes role with `iam:PassRole` + can
    assume admin\" → privilege chain to admin.

This module ships that capability at SMB price.

## Architecture

  1. `graph.py` defines pure-Python `CloudGraph` with typed nodes
     (`CloudResource` / `CloudIdentity` / `CloudPolicy`) + edges.

  2. `ingest.py` builds a graph from a list of `CspmFinding`
     plus an optional asset inventory passed by the caller.
     CSPM-only ingest gives a sparse graph (only resources that
     triggered checks); enriched ingest gives a fuller picture.

  3. `patterns.py` defines `AttackPath` + bundled pattern matchers
     — each pattern is a graph query that returns matching
     subgraphs as classified attack paths.

  4. `api.py` exposes `analyze_cloud_attack_paths(...)` — the
     stable Python entry point that webappsec / and any other
     wrapper calls. Returns an `AttackPathReport` with JSON-
     serialisable shape.

  5. `tools.py` registers `scan_cloud_attack_paths` as an LLM-
     callable specialist for in-agent use.

## What this does NOT do (yet)

  * Live verification of attack paths (anonymous S3 GET, RDS TCP
    probe, etc.) — graph reasoning only in v1. Live PoC probes
    land in a follow-up.

  * Full asset discovery via boto3 / Azure SDK / GCP SDK — relies
    on the caller's already-collected CSPM findings + optional
    asset list. Adding discovery is a follow-up PR.

  * Cross-account / organization-wide traversal — single-account
    in v1.
"""

from __future__ import annotations

from strix.cloud_attack_paths.api import (
    AttackPathReport,
    analyze_cloud_attack_paths,
)
from strix.cloud_attack_paths.graph import (
    CloudEdge,
    CloudGraph,
    CloudIdentity,
    CloudPolicy,
    CloudResource,
    EDGE_ATTACHED_TO,
    EDGE_CAN_ASSUME,
    EDGE_EXPOSED_TO_INTERNET,
    EDGE_GRANTS_ACCESS_TO,
    EDGE_HAS_POLICY,
)
from strix.cloud_attack_paths.discovery import discover_aws_assets
from strix.cloud_attack_paths.ingest import build_graph_from_cspm
from strix.cloud_attack_paths.live_probes import (
    PROBE_ERROR,
    PROBE_NOT_VERIFIED,
    PROBE_SKIPPED,
    PROBE_VERIFIED,
    ProbeResult,
    is_live_probes_enabled,
    list_registered_probes,
    register_probe,
    run_probe,
)
from strix.cloud_attack_paths.patterns import (
    AttackPath,
    BUILTIN_PATTERNS,
    find_attack_paths,
)
from strix.cloud_attack_paths.reachability import (
    apply_reachability_to_paths,
    compute_priority,
    compute_reachability,
    score_path,
)


# Side-effect import — register specialist tool.
from strix.cloud_attack_paths import tools as _tools  # noqa: E402, F401


__all__ = [
    # Public wrapper-facing API
    "analyze_cloud_attack_paths",
    "AttackPathReport",
    "AttackPath",
    # Graph primitives (for advanced callers)
    "CloudGraph",
    "CloudResource",
    "CloudIdentity",
    "CloudPolicy",
    "CloudEdge",
    # Edge type constants
    "EDGE_ATTACHED_TO",
    "EDGE_CAN_ASSUME",
    "EDGE_EXPOSED_TO_INTERNET",
    "EDGE_GRANTS_ACCESS_TO",
    "EDGE_HAS_POLICY",
    # Lower-level entry points
    "build_graph_from_cspm",
    "discover_aws_assets",
    "find_attack_paths",
    "BUILTIN_PATTERNS",
    # Reachability scoring
    "compute_reachability",
    "score_path",
    "apply_reachability_to_paths",
    "compute_priority",
    # Live-probe API (opt-in PoC verification)
    "ProbeResult",
    "PROBE_VERIFIED",
    "PROBE_NOT_VERIFIED",
    "PROBE_ERROR",
    "PROBE_SKIPPED",
    "register_probe",
    "run_probe",
    "list_registered_probes",
    "is_live_probes_enabled",
]
