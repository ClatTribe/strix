"""Tests for the v2 attack-path patterns (masterroadmap §5 P0
expansion — 5 → 13 patterns).

Each pattern has one positive case (graph constructed to fire it)
and one negative case (canonical not-fire scenario).
"""

from __future__ import annotations

import pytest

from strix.cloud_attack_paths.graph import (
    CloudGraph,
    CloudIdentity,
    CloudPolicy,
    CloudResource,
    EDGE_ATTACHED_TO,
    EDGE_CAN_ASSUME,
    EDGE_EXPOSED_TO_INTERNET,
    EDGE_HAS_POLICY,
)
from strix.cloud_attack_paths.patterns import (
    BUILTIN_PATTERNS,
    find_attack_paths,
)


# ---------------------------------------------------------------------------
# Registry hygiene
# ---------------------------------------------------------------------------


def test_v2_pattern_count_at_least_thirteen() -> None:
    """We promised 5 → 13+ patterns in this PR. Pin the count so
    a future refactor that drops one fails loudly."""
    assert len(BUILTIN_PATTERNS) >= 13


def test_v2_pattern_ids_have_cap_prefix() -> None:
    for pid in BUILTIN_PATTERNS:
        assert pid.startswith("cap_"), f"{pid} missing cap_ prefix"


# ---------------------------------------------------------------------------
# cap_public_database
# ---------------------------------------------------------------------------


def test_public_rds_fires_database_pattern() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:rds:us-east-1:1:db:prod",
        kind="rds_db_instance", is_public=True,
    ))
    g.add_edge("arn:aws:rds:us-east-1:1:db:prod",
               EDGE_EXPOSED_TO_INTERNET, None)
    paths = find_attack_paths(g, patterns=["cap_public_database"])
    assert len(paths) == 1
    assert paths[0].severity == "critical"
    assert "rds" in paths[0].title.lower()


def test_public_dynamodb_fires_database_pattern() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:dynamodb:us-east-1:1:table/Users",
        kind="dynamodb_table", is_public=True,
    ))
    g.add_edge("arn:aws:dynamodb:us-east-1:1:table/Users",
               EDGE_EXPOSED_TO_INTERNET, None)
    paths = find_attack_paths(g, patterns=["cap_public_database"])
    assert len(paths) == 1


def test_private_rds_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:rds:us-east-1:1:db:private",
        kind="rds_db_instance", is_public=False,
    ))
    paths = find_attack_paths(g, patterns=["cap_public_database"])
    assert paths == []


def test_public_s3_does_not_fire_database_pattern() -> None:
    """`cap_public_database` is specifically for DB kinds, not
    storage — storage has its own pattern."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::data", kind="s3_bucket", is_public=True,
    ))
    paths = find_attack_paths(g, patterns=["cap_public_database"])
    assert paths == []


# ---------------------------------------------------------------------------
# cap_public_secrets_store
# ---------------------------------------------------------------------------


def test_public_secrets_manager_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:secretsmanager:us-east-1:1:secret:db-creds",
        kind="secrets_manager_secret", is_public=True,
    ))
    paths = find_attack_paths(g, patterns=["cap_public_secrets_store"])
    assert len(paths) == 1
    assert paths[0].severity == "critical"


def test_public_kms_key_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:kms:us-east-1:1:key/abc",
        kind="kms_key", is_public=True,
    ))
    paths = find_attack_paths(g, patterns=["cap_public_secrets_store"])
    assert len(paths) == 1


def test_private_secret_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:secretsmanager:us-east-1:1:secret:db-creds",
        kind="secrets_manager_secret", is_public=False,
    ))
    paths = find_attack_paths(g, patterns=["cap_public_secrets_store"])
    assert paths == []


# ---------------------------------------------------------------------------
# cap_public_ecr_repository
# ---------------------------------------------------------------------------


def test_public_ecr_repo_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ecr:us-east-1:1:repository/myapp",
        kind="ecr_repository", is_public=True,
    ))
    paths = find_attack_paths(g, patterns=["cap_public_ecr_repository"])
    assert len(paths) == 1
    assert paths[0].severity == "high"


def test_private_ecr_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ecr:us-east-1:1:repository/myapp",
        kind="ecr_repository", is_public=False,
    ))
    paths = find_attack_paths(g, patterns=["cap_public_ecr_repository"])
    assert paths == []


# ---------------------------------------------------------------------------
# cap_admin_policy_attached_to_iam_user
# ---------------------------------------------------------------------------


def test_admin_policy_on_iam_user_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:user/alice", kind="iam_user"))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/admin", kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:user/alice", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/admin")
    paths = find_attack_paths(
        g, patterns=["cap_admin_policy_attached_to_iam_user"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"


def test_admin_policy_on_role_not_flagged_by_user_pattern() -> None:
    """Wildcard admin on a ROLE doesn't fire the user-specific
    pattern (it's covered by `cap_wildcard_admin_attached`)."""
    g = CloudGraph()
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:role/admin", kind="iam_role"))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/admin", kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:role/admin", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/admin")
    paths = find_attack_paths(
        g, patterns=["cap_admin_policy_attached_to_iam_user"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# cap_external_trust_without_external_id
# ---------------------------------------------------------------------------


def test_external_trust_without_external_id_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::111:role/vendor",
        kind="iam_role",
        trust_principals=["arn:aws:iam::999:root"],  # external account
    ))
    paths = find_attack_paths(
        g, patterns=["cap_external_trust_without_external_id"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "high"


def test_external_trust_with_external_id_suppressed() -> None:
    """When ExternalId IS required, the pattern doesn't fire."""
    g = CloudGraph()
    ident = CloudIdentity(
        arn="arn:aws:iam::111:role/vendor",
        kind="iam_role",
        trust_principals=["arn:aws:iam::999:root"],
    )
    ident.attributes["external_id_required"] = True
    g.add_node(ident)
    paths = find_attack_paths(
        g, patterns=["cap_external_trust_without_external_id"],
    )
    assert paths == []


def test_same_account_trust_does_not_fire() -> None:
    """Trust from the SAME account's root isn't external."""
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::111:role/internal",
        kind="iam_role",
        trust_principals=["arn:aws:iam::111:root"],
    ))
    paths = find_attack_paths(
        g, patterns=["cap_external_trust_without_external_id"],
    )
    assert paths == []


def test_world_assumable_role_not_double_fired() -> None:
    """`Principal: *` is handled by `cap_world_assumable_role`;
    the external-trust pattern must not also fire on it."""
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::111:role/external",
        kind="iam_role",
        trust_principals=["*"],
    ))
    paths = find_attack_paths(
        g, patterns=["cap_external_trust_without_external_id"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# cap_pass_role_present
# ---------------------------------------------------------------------------


def test_pass_role_action_fires_pattern() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:user/dev", kind="iam_user"))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/dev",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow",
            "actions": ["iam:PassRole", "ec2:RunInstances"],
            "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:user/dev", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/dev")
    paths = find_attack_paths(g, patterns=["cap_pass_role_present"])
    assert len(paths) == 1
    assert paths[0].severity == "high"


def test_no_pass_role_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:user/dev", kind="iam_user"))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/dev",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow",
            "actions": ["s3:GetObject"],
            "resources": ["arn:aws:s3:::x"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:user/dev", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/dev")
    paths = find_attack_paths(g, patterns=["cap_pass_role_present"])
    assert paths == []


def test_iam_star_action_fires_pass_role_pattern() -> None:
    """`iam:*` includes `iam:PassRole` — pattern fires."""
    g = CloudGraph()
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:user/dev", kind="iam_user"))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/dev",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["iam:*"],
            "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:user/dev", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/dev")
    paths = find_attack_paths(g, patterns=["cap_pass_role_present"])
    assert len(paths) == 1


# ---------------------------------------------------------------------------
# cap_can_assume_chain_to_admin
# ---------------------------------------------------------------------------


def test_1_hop_assume_chain_to_admin_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:user/dev", kind="iam_user"))
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:role/admin", kind="iam_role"))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/admin",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:role/admin", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/admin")
    g.add_edge("arn:aws:iam::1:user/dev", EDGE_CAN_ASSUME,
               "arn:aws:iam::1:role/admin")
    paths = find_attack_paths(
        g, patterns=["cap_can_assume_chain_to_admin"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"
    assert "1-hop" in paths[0].title


def test_2_hop_assume_chain_to_admin_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:user/dev", kind="iam_user"))
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:role/mid", kind="iam_role"))
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:role/admin", kind="iam_role"))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/admin",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:role/admin", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/admin")
    g.add_edge("arn:aws:iam::1:user/dev", EDGE_CAN_ASSUME,
               "arn:aws:iam::1:role/mid")
    g.add_edge("arn:aws:iam::1:role/mid", EDGE_CAN_ASSUME,
               "arn:aws:iam::1:role/admin")
    paths = find_attack_paths(
        g, patterns=["cap_can_assume_chain_to_admin"],
    )
    # Both the 1-hop (mid → admin) AND the 2-hop (dev → mid →
    # admin) should fire.
    titles = {p.title for p in paths}
    assert any("2-hop" in t for t in titles)


def test_no_assume_chain_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:user/dev", kind="iam_user"))
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:role/admin", kind="iam_role"))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/admin",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:role/admin", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/admin")
    # No can_assume edge from dev → admin.
    paths = find_attack_paths(
        g, patterns=["cap_can_assume_chain_to_admin"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# cap_admin_attached_to_compute_with_internet
# ---------------------------------------------------------------------------


def test_internet_compute_admin_chain_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-bad",
        kind="ec2_instance", is_public=True,
    ))
    g.add_edge("arn:aws:ec2:us-east-1:1:instance/i-bad",
               EDGE_EXPOSED_TO_INTERNET, None)
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:role/admin", kind="iam_role"))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/admin",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:role/admin", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/admin")
    g.add_edge("arn:aws:iam::1:role/admin", EDGE_ATTACHED_TO,
               "arn:aws:ec2:us-east-1:1:instance/i-bad")
    paths = find_attack_paths(
        g, patterns=["cap_admin_attached_to_compute_with_internet"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"
    assert paths[0].confidence >= 0.99
    # 3-hop narrative: compute, identity, policy.
    assert len(paths[0].hops) == 3


def test_admin_attached_to_private_compute_does_not_fire() -> None:
    """Same chain but compute is NOT internet-exposed —
    `cap_wildcard_admin_attached` still fires (general case),
    but the internet-specific extension doesn't."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-bad",
        kind="ec2_instance", is_public=False,
    ))
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:role/admin", kind="iam_role"))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/admin",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:role/admin", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/admin")
    g.add_edge("arn:aws:iam::1:role/admin", EDGE_ATTACHED_TO,
               "arn:aws:ec2:us-east-1:1:instance/i-bad")
    paths = find_attack_paths(
        g, patterns=["cap_admin_attached_to_compute_with_internet"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# cap_internet_resource_unencrypted
# ---------------------------------------------------------------------------


def test_public_unencrypted_rds_fires() -> None:
    g = CloudGraph()
    r = CloudResource(
        arn="arn:aws:rds:us-east-1:1:db:prod",
        kind="rds_db_instance", is_public=True,
    )
    r.attributes["is_unencrypted"] = True
    g.add_node(r)
    g.add_edge(r.arn, EDGE_EXPOSED_TO_INTERNET, None)
    paths = find_attack_paths(
        g, patterns=["cap_internet_resource_unencrypted"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"


def test_public_encrypted_rds_does_not_fire() -> None:
    g = CloudGraph()
    r = CloudResource(
        arn="arn:aws:rds:us-east-1:1:db:prod",
        kind="rds_db_instance", is_public=True,
    )
    # No is_unencrypted attribute → encrypted (default).
    g.add_node(r)
    paths = find_attack_paths(
        g, patterns=["cap_internet_resource_unencrypted"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# Ingester signal: is_unencrypted derived from CSPM findings
# ---------------------------------------------------------------------------


def test_ingester_marks_unencrypted_from_rds_finding() -> None:
    from strix.cloud_attack_paths.ingest import build_graph_from_cspm
    from strix.cspm.aws import CspmFinding

    findings = [
        CspmFinding(
            rule_id="AWS_RDS_PUBLIC_ACCESS",
            severity="critical", message="rds public",
            service="rds", region="us-east-1",
            resource_arn="arn:aws:rds:us-east-1:1:db:prod",
            account_id="1", cwe="CWE-200", category="misconfig",
        ),
        CspmFinding(
            rule_id="AWS_RDS_NO_ENCRYPTION",
            severity="high", message="rds unencrypted",
            service="rds", region="us-east-1",
            resource_arn="arn:aws:rds:us-east-1:1:db:prod",
            account_id="1", cwe="CWE-311", category="misconfig",
        ),
    ]
    graph = build_graph_from_cspm(findings)
    node = graph.get_node("arn:aws:rds:us-east-1:1:db:prod")
    assert node is not None
    assert node.is_public is True
    assert node.attributes.get("is_unencrypted") is True


def test_ingester_derives_can_assume_from_policy() -> None:
    """When an identity has a policy statement allowing
    `sts:AssumeRole` against a specific role ARN, the ingester
    must derive the `can_assume` edge so chain patterns work."""
    from strix.cloud_attack_paths.ingest import build_graph_from_cspm

    graph = build_graph_from_cspm(
        findings=[],
        assets=[
            {
                "arn": "arn:aws:iam::1:user/dev",
                "kind": "iam_user",
            },
            {
                "arn": "arn:aws:iam::1:role/admin",
                "kind": "iam_role",
            },
            {
                "arn": "arn:aws:iam::1:policy/dev-assume",
                "kind": "iam_managed_policy",
                "statements": [{
                    "effect": "Allow",
                    "actions": ["sts:AssumeRole"],
                    "resources": ["arn:aws:iam::1:role/admin"],
                }],
                "attached_to": ["arn:aws:iam::1:user/dev"],
            },
        ],
    )
    # Edge: user → can_assume → admin role.
    assert graph.has_edge(
        "arn:aws:iam::1:user/dev",
        EDGE_CAN_ASSUME,
        "arn:aws:iam::1:role/admin",
    )


# ---------------------------------------------------------------------------
# All-patterns smoke
# ---------------------------------------------------------------------------


def test_all_patterns_handle_empty_graph() -> None:
    g = CloudGraph()
    paths = find_attack_paths(g)
    assert paths == []


def test_find_attack_paths_sorts_critical_first_across_v2() -> None:
    """Build a graph that fires multiple v2 patterns at different
    severities; verify the final list is critical-first."""
    g = CloudGraph()
    # Critical: public secrets store.
    g.add_node(CloudResource(
        arn="arn:aws:secretsmanager:us-east-1:1:secret:s",
        kind="secrets_manager_secret", is_public=True,
    ))
    # High: public ECR.
    g.add_node(CloudResource(
        arn="arn:aws:ecr:us-east-1:1:repository/x",
        kind="ecr_repository", is_public=True,
    ))
    paths = find_attack_paths(g)
    severities = [p.severity for p in paths]
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    ranks = [sev_rank[s] for s in severities]
    assert ranks == sorted(ranks, reverse=True)
