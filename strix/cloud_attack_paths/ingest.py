"""Build a CloudGraph from CSPM findings (+ optional asset inventory).

Two-pass design:

  1. **From findings** — every `CspmFinding` produces a node for
     its `resource_arn` if we don't already have one, plus
     finding-derived attributes (is_public for known exposure
     rules, is_data_store for known data services, etc.).

  2. **From asset inventory (optional)** — caller-supplied list of
     resource / identity / policy dicts. Adds nodes the CSPM scan
     didn't trigger checks on AND establishes edges that need
     boto3-side metadata the CSPM finding doesn't carry (IAM
     attachment, trust relationships).

The graph is useful even with just step 1; step 2 is the
enrichment lever for wrappers that have already enumerated the
account via Prowler / boto3 / Cloud Asset Inventory APIs.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

from strix.cloud_attack_paths.graph import (
    CloudGraph,
    CloudIdentity,
    CloudPolicy,
    CloudResource,
    EDGE_ATTACHED_TO,
    EDGE_CAN_ASSUME,
    EDGE_EXPOSED_TO_INTERNET,
    EDGE_GRANTS_ACCESS_TO,
    EDGE_HAS_POLICY,
    EDGE_MAY_CONTAIN_CREDENTIALS,
)
from strix.cspm.aws import CspmFinding


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Heuristics — rule_id → graph-meaningful attributes
# ---------------------------------------------------------------------------


# Rules that flag a resource as internet-reachable. When any of
# these fire, the corresponding resource gets `is_public=True` +
# an `exposed_to_internet` edge — even when the rule was about
# something else (e.g. an unencrypted-but-public RDS gives us both
# the encryption signal AND the exposure signal).
_PUBLIC_EXPOSURE_RULE_IDS = frozenset({
    # boto3 path
    "AWS_S3_PUBLIC_ACL",
    "AWS_RDS_PUBLIC_ACCESS",
    "AWS_SG_OPEN_INGRESS_ADMIN",
    "AWS_SG_OPEN_INGRESS_WORLD",
    # prowler path
    "prowler:s3_bucket_public_access",
    "prowler:rds_instance_no_public_access",
    "prowler:ec2_securitygroup_allow_ingress_from_internet_to_port_22",
    "prowler:ec2_securitygroup_allow_ingress_from_internet_to_port_3389",
    "prowler:ec2_securitygroup_allow_ingress_from_internet_to_any_port",
    "prowler:ec2_securitygroup_allow_wide_open_public_ipv4",
    "prowler:lambda_function_url_cors_policy",
    "prowler:lambda_function_url_public",
    "prowler:elbv2_listener_underneath_tls12",
    # Azure / GCP
    "prowler:storage_blob_public_access_level_is_disabled",
    "prowler:bigquery_dataset_public_access",
})


# Rules that flag wildcard / admin-equivalent permissions.
_WILDCARD_ADMIN_RULE_IDS = frozenset({
    "AWS_IAM_POLICY_WILDCARD_ADMIN",
    "prowler:iam_policy_no_administrative_privileges",
    "prowler:iam_inline_policy_no_administrative_privileges",
})


# Rules that flag the root account being unsafe.
_ROOT_ACCOUNT_RULE_IDS = frozenset({
    "AWS_IAM_ROOT_ACCESS_KEY",
    "prowler:iam_root_hardware_mfa_enabled",
    "prowler:iam_root_mfa_enabled",
    "prowler:iam_avoid_root_usage",
})


# ARN → service kind. AWS ARN format:
# `arn:aws:<service>:<region>:<account>:<resource-type>/<resource-id>`.
# We pattern-match on service + resource-type prefix.
_ARN_KIND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^arn:aws:s3:::"), "s3_bucket"),
    (re.compile(r"^arn:aws:rds:.*:db:"), "rds_db_instance"),
    (re.compile(r"^arn:aws:rds:.*:cluster:"), "rds_cluster"),
    (re.compile(r"^arn:aws:lambda:.*:function:"), "lambda_function"),
    (re.compile(r"^arn:aws:ec2:.*:instance/"), "ec2_instance"),
    (re.compile(r"^arn:aws:ec2:.*:security-group/"), "ec2_security_group"),
    (re.compile(r"^arn:aws:ec2:.*:vpc/"), "ec2_vpc"),
    (re.compile(r"^arn:aws:ecr:.*:repository/"), "ecr_repository"),
    (re.compile(r"^arn:aws:dynamodb:.*:table/"), "dynamodb_table"),
    (re.compile(r"^arn:aws:secretsmanager:.*:secret:"), "secrets_manager_secret"),
    (re.compile(r"^arn:aws:kms:.*:key/"), "kms_key"),
    (re.compile(r"^arn:aws:iam::[^:]*:user/"), "iam_user"),
    (re.compile(r"^arn:aws:iam::[^:]*:role/"), "iam_role"),
    (re.compile(r"^arn:aws:iam::[^:]*:group/"), "iam_group"),
    (re.compile(r"^arn:aws:iam::[^:]*:policy/"), "iam_managed_policy"),
    (re.compile(r"^arn:aws:iam::[^:]*:root"), "aws_root"),
    (re.compile(r"^arn:aws:sqs:.*:"), "sqs_queue"),
    (re.compile(r"^arn:aws:sns:.*:"), "sns_topic"),
    # Azure: /subscriptions/<sub>/resourceGroups/<rg>/providers/...
    (re.compile(r"providers/Microsoft\.Storage/storageAccounts/"), "azure_storage_account"),
    (re.compile(r"providers/Microsoft\.Compute/virtualMachines/"), "azure_vm"),
    (re.compile(r"providers/Microsoft\.Sql/servers/"), "azure_sql_server"),
    # GCP: projects/<p>/<service>/<id>
    (re.compile(r"projects/[^/]+/datasets/"), "gcp_bigquery_dataset"),
    (re.compile(r"projects/[^/]+/buckets/"), "gcp_storage_bucket"),
    (re.compile(r"projects/[^/]+/instances/"), "gcp_compute_instance"),
]


# Service kinds whose primary purpose is storing data — heightens
# the severity of any attack path ending at them.
_DATA_STORE_KINDS = frozenset({
    "s3_bucket", "rds_db_instance", "rds_cluster", "dynamodb_table",
    "secrets_manager_secret", "kms_key", "ecr_repository",
    "azure_storage_account", "azure_sql_server",
    "gcp_bigquery_dataset", "gcp_storage_bucket",
})


# Service kinds that are compute resources — an IAM identity
# attached to one of these is "runtime-reachable" via that resource.
_COMPUTE_KINDS = frozenset({
    "ec2_instance", "lambda_function", "ecs_task", "eks_pod",
    "azure_vm", "gcp_compute_instance",
})


def _infer_kind_from_arn(arn: str) -> str:
    for pat, kind in _ARN_KIND_PATTERNS:
        if pat.search(arn):
            return kind
    # Fallback: extract the service from `arn:aws:<service>:`.
    m = re.match(r"^arn:aws:([a-z0-9_-]+):", arn)
    if m:
        return f"{m.group(1)}_resource"
    return "unknown_resource"


def _is_identity_kind(kind: str) -> bool:
    return kind in {"iam_user", "iam_role", "iam_group", "aws_root"}


def _is_policy_kind(kind: str) -> bool:
    return kind in {
        "iam_managed_policy", "iam_inline_policy",
        "bucket_policy", "kms_key_policy",
    }


# ---------------------------------------------------------------------------
# CSPM finding → graph
# ---------------------------------------------------------------------------


def _ensure_node_for_arn(
    graph: CloudGraph,
    arn: str,
    *,
    region: str | None = None,
    account_id: str | None = None,
    explicit_kind: str | None = None,
) -> CloudResource | CloudIdentity | CloudPolicy:
    """Look up or create the right kind of node for an ARN.

    Returns the node currently in the graph (existing or newly
    added). The kind is inferred from the ARN unless
    `explicit_kind` is supplied (caller knows better)."""
    if graph.has_node(arn):
        return graph.get_node(arn)  # type: ignore[return-value]

    kind = explicit_kind or _infer_kind_from_arn(arn)
    if _is_identity_kind(kind):
        node: Any = CloudIdentity(arn=arn, kind=kind)
    elif _is_policy_kind(kind):
        node = CloudPolicy(arn=arn, kind=kind)
    else:
        node = CloudResource(
            arn=arn,
            kind=kind,
            region=region,
            account_id=account_id,
            is_data_store=kind in _DATA_STORE_KINDS,
        )
    return graph.add_node(node)


def _apply_finding_signals(
    graph: CloudGraph, finding: CspmFinding, node: Any,
) -> None:
    """Update graph state based on a finding's semantic meaning."""
    if isinstance(node, CloudResource):
        if finding.rule_id in _PUBLIC_EXPOSURE_RULE_IDS:
            node.is_public = True
            graph.add_edge(node.arn, EDGE_EXPOSED_TO_INTERNET, None,
                           attributes={"rule_id": finding.rule_id})
        # Data-store-classified resources stay marked; rule-derived
        # signals (e.g. `bucket likely contains terraform state` —
        # not implemented yet but a hook) can flip is_data_store
        # via the heuristics layer.

    if isinstance(node, CloudPolicy):
        if finding.rule_id in _WILDCARD_ADMIN_RULE_IDS:
            # Insert a wildcard-admin statement if the policy is
            # otherwise empty (no upstream policy doc was passed).
            if not node.statements:
                node.statements.append({
                    "effect": "allow",
                    "actions": ["*"],
                    "resources": ["*"],
                    "source": "inferred_from_finding",
                })

    if isinstance(node, CloudIdentity) and node.kind == "aws_root":
        if finding.rule_id in _ROOT_ACCOUNT_RULE_IDS:
            node.attributes["root_unsafe"] = True


def build_graph_from_cspm(
    findings: Iterable[CspmFinding],
    *,
    assets: Iterable[dict[str, Any]] | None = None,
) -> CloudGraph:
    """Build a `CloudGraph` from CSPM findings (+ optional assets).

    Args:
        findings: every `CspmFinding` adds a node for its
            `resource_arn` if absent. Finding-specific semantics
            (public exposure, wildcard admin, root unsafe) update
            the relevant node + add edges.

        assets: optional caller-supplied dicts that ride alongside
            findings to enrich the graph beyond what findings
            alone surface. Recognised shapes:

              `{"arn": "...", "kind": "lambda_function", "region": "...",
                "attached_role_arn": "arn:...", "is_public": True}`

              `{"arn": "arn:aws:iam::...:role/x", "kind": "iam_role",
                "trust_principals": ["lambda.amazonaws.com"]}`

              `{"arn": "arn:aws:iam::...:policy/x",
                "kind": "iam_managed_policy",
                "statements": [{effect, actions, resources}, ...],
                "attached_to": ["arn:...role/y", ...]}`

            Unknown keys are stashed in `node.attributes`.

    Returns:
        A populated CloudGraph ready to be passed to
        `find_attack_paths`.
    """
    graph = CloudGraph()

    # --- Phase 1: findings ---
    for f in findings:
        if not f.resource_arn:
            continue
        node = _ensure_node_for_arn(
            graph, f.resource_arn,
            region=f.region, account_id=f.account_id,
        )
        _apply_finding_signals(graph, f, node)

    # --- Phase 2: caller-supplied assets ---
    for asset in assets or ():
        if not isinstance(asset, dict):
            continue
        arn = asset.get("arn")
        if not isinstance(arn, str) or not arn:
            continue
        kind = asset.get("kind")
        node = _ensure_node_for_arn(
            graph, arn, region=asset.get("region"),
            account_id=asset.get("account_id"),
            explicit_kind=kind if isinstance(kind, str) else None,
        )

        # Merge attributes (without clobbering finding-derived state).
        for k, v in asset.items():
            if k in ("arn", "kind", "region", "account_id"):
                continue
            if k == "is_public" and v is True and isinstance(node, CloudResource):
                node.is_public = True
                graph.add_edge(arn, EDGE_EXPOSED_TO_INTERNET, None,
                               attributes={"source": "asset_inventory"})
            elif k == "is_data_store" and v is True and isinstance(node, CloudResource):
                node.is_data_store = True
            elif k == "trust_principals" and isinstance(node, CloudIdentity):
                node.trust_principals = list(v or [])
            elif k == "statements" and isinstance(node, CloudPolicy):
                node.statements = list(v or [])
            elif k == "attached_role_arn" and isinstance(v, str) and v:
                # Compute resource ← IAM role attached. Edge:
                # role --attached_to--> resource.
                _ensure_node_for_arn(graph, v, explicit_kind="iam_role")
                graph.add_edge(v, EDGE_ATTACHED_TO, arn)
            elif k == "attached_to" and isinstance(v, list):
                for target in v:
                    if not isinstance(target, str) or not target:
                        continue
                    _ensure_node_for_arn(graph, target)
                    # Policy --has_policy(rev)--> identity edge.
                    graph.add_edge(target, EDGE_HAS_POLICY, arn)
            else:
                node.attributes[k] = v

    # --- Phase 3: derived edges from parsed policy statements ---
    # When a policy lists resources, add `grants_access_to` edges
    # so attack-path queries can walk policy → granted resource.
    for node in list(graph.nodes_by_type(CloudPolicy)):
        if not isinstance(node, CloudPolicy):
            continue
        for stmt in node.statements:
            if (stmt.get("effect") or "").lower() != "allow":
                continue
            for res in _as_iter(stmt.get("resources")):
                if not isinstance(res, str) or not res:
                    continue
                # Make sure the target exists so the edge has both ends.
                if res != "*":
                    _ensure_node_for_arn(graph, res)
                graph.add_edge(node.arn, EDGE_GRANTS_ACCESS_TO,
                               res if res != "*" else None)

    return graph


def _as_iter(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]
