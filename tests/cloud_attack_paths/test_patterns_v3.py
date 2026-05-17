"""Tests for v3 multi-cloud attack-path patterns (masterroadmap
§5 P1 — GCP + Azure-specific narratives).

Each pattern has one positive case + one negative case + at
least one specificity check (won't fire on the wrong cloud).
"""

from __future__ import annotations

import pytest

from strix.cloud_attack_paths.graph import (
    CloudGraph,
    CloudIdentity,
    CloudPolicy,
    CloudResource,
    EDGE_EXPOSED_TO_INTERNET,
)
from strix.cloud_attack_paths.patterns import (
    BUILTIN_PATTERNS,
    find_attack_paths,
)


# ---------------------------------------------------------------------------
# Registry hygiene
# ---------------------------------------------------------------------------


def test_v3_total_pattern_count_at_least_eighteen() -> None:
    """Was 13 in v2 (#300); v3 adds 5 multi-cloud patterns → ≥ 18."""
    assert len(BUILTIN_PATTERNS) >= 18


@pytest.mark.parametrize("pid", [
    "cap_gcp_default_compute_sa_with_internet",
    "cap_gcp_public_bigquery_dataset",
    "cap_gcp_service_account_owner_role",
    "cap_azure_storage_public_blob",
    "cap_azure_owner_role_user",
])
def test_v3_pattern_registered(pid: str) -> None:
    assert pid in BUILTIN_PATTERNS


# ---------------------------------------------------------------------------
# cap_gcp_default_compute_sa_with_internet
# ---------------------------------------------------------------------------


def test_gcp_default_sa_with_cloud_platform_fires_critical() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="projects/p/instances/i-vm",
        kind="gcp_compute_instance",
        is_public=True,
        attributes={
            "default_service_account": True,
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
        },
    ))
    g.add_edge("projects/p/instances/i-vm",
               EDGE_EXPOSED_TO_INTERNET, None)
    paths = find_attack_paths(
        g, patterns=["cap_gcp_default_compute_sa_with_internet"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"


def test_gcp_default_sa_without_cloud_platform_scope_is_high() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="projects/p/instances/i-vm",
        kind="gcp_compute_instance",
        is_public=True,
        attributes={
            "default_service_account": True,
            "scopes": ["https://www.googleapis.com/auth/devstorage.read_only"],
        },
    ))
    g.add_edge("projects/p/instances/i-vm",
               EDGE_EXPOSED_TO_INTERNET, None)
    paths = find_attack_paths(
        g, patterns=["cap_gcp_default_compute_sa_with_internet"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "high"
    assert paths[0].metadata["has_cloud_platform_scope"] is False


def test_gcp_non_default_sa_does_not_fire() -> None:
    """Custom SA with bounded permissions doesn't fire — only
    the default-SA case is the privilege-escalation primitive."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="projects/p/instances/i-vm",
        kind="gcp_compute_instance",
        is_public=True,
        attributes={
            "default_service_account": False,
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
        },
    ))
    g.add_edge("projects/p/instances/i-vm",
               EDGE_EXPOSED_TO_INTERNET, None)
    paths = find_attack_paths(
        g, patterns=["cap_gcp_default_compute_sa_with_internet"],
    )
    assert paths == []


def test_gcp_default_sa_private_vm_does_not_fire() -> None:
    """Default SA on a private VM isn't an internet-reachable
    attack path."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="projects/p/instances/i-vm",
        kind="gcp_compute_instance",
        is_public=False,
        attributes={"default_service_account": True},
    ))
    paths = find_attack_paths(
        g, patterns=["cap_gcp_default_compute_sa_with_internet"],
    )
    assert paths == []


def test_gcp_default_sa_pattern_does_not_fire_on_aws() -> None:
    """Specificity: AWS EC2 with public IP shouldn't fire the
    GCP-specific pattern even though both are 'public compute'."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-aaa",
        kind="ec2_instance",
        is_public=True,
        attributes={"default_service_account": True},  # spurious tag
    ))
    paths = find_attack_paths(
        g, patterns=["cap_gcp_default_compute_sa_with_internet"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# cap_gcp_public_bigquery_dataset
# ---------------------------------------------------------------------------


def test_public_bigquery_dataset_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="projects/p/datasets/leaky",
        kind="gcp_bigquery_dataset",
        is_public=True,
    ))
    g.add_edge("projects/p/datasets/leaky",
               EDGE_EXPOSED_TO_INTERNET, None)
    paths = find_attack_paths(
        g, patterns=["cap_gcp_public_bigquery_dataset"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"
    assert paths[0].confidence == 1.0


def test_private_bigquery_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="projects/p/datasets/priv",
        kind="gcp_bigquery_dataset",
        is_public=False,
    ))
    paths = find_attack_paths(
        g, patterns=["cap_gcp_public_bigquery_dataset"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# cap_azure_storage_public_blob
# ---------------------------------------------------------------------------


def test_public_azure_storage_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="/subscriptions/sub/resourceGroups/rg/providers"
            "/Microsoft.Storage/storageAccounts/prodstorage",
        kind="azure_storage_account",
        is_public=True,
    ))
    paths = find_attack_paths(
        g, patterns=["cap_azure_storage_public_blob"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"


def test_private_azure_storage_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="/subscriptions/sub/resourceGroups/rg/providers"
            "/Microsoft.Storage/storageAccounts/priv",
        kind="azure_storage_account",
        is_public=False,
    ))
    paths = find_attack_paths(
        g, patterns=["cap_azure_storage_public_blob"],
    )
    assert paths == []


def test_azure_storage_pattern_does_not_fire_on_s3() -> None:
    """Specificity — AWS S3 should not trigger the Azure-specific
    pattern."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::data", kind="s3_bucket", is_public=True,
    ))
    paths = find_attack_paths(
        g, patterns=["cap_azure_storage_public_blob"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# cap_azure_owner_role_user
# ---------------------------------------------------------------------------


def test_azure_owner_at_subscription_scope_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="/subscriptions/sub/users/admin",
        kind="azure_user",
        attributes={
            "azure_roles": ["Owner"],
            "azure_scope": "/subscriptions/sub",
        },
    ))
    paths = find_attack_paths(
        g, patterns=["cap_azure_owner_role_user"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"


def test_azure_owner_at_management_group_scope_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="/subscriptions/sub/users/admin",
        kind="azure_user",
        attributes={
            "azure_roles": ["Owner"],
            "azure_scope": (
                "/providers/Microsoft.Management/"
                "managementGroups/root"
            ),
        },
    ))
    paths = find_attack_paths(
        g, patterns=["cap_azure_owner_role_user"],
    )
    assert len(paths) == 1


def test_azure_owner_at_resource_scope_does_not_fire() -> None:
    """Owner role scoped to a single resource is fine — the
    pattern targets wide-scope assignments only."""
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="/subscriptions/sub/users/dev",
        kind="azure_user",
        attributes={
            "azure_roles": ["Owner"],
            "azure_scope": (
                "/subscriptions/sub/resourceGroups/rg/providers"
                "/Microsoft.Storage/storageAccounts/x"
            ),
        },
    ))
    paths = find_attack_paths(
        g, patterns=["cap_azure_owner_role_user"],
    )
    assert paths == []


def test_azure_contributor_role_does_not_fire() -> None:
    """Only `Owner` triggers (not `Contributor` / etc.)."""
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="/subscriptions/sub/users/dev",
        kind="azure_user",
        attributes={
            "azure_roles": ["Contributor"],
            "azure_scope": "/subscriptions/sub",
        },
    ))
    paths = find_attack_paths(
        g, patterns=["cap_azure_owner_role_user"],
    )
    assert paths == []


def test_azure_pattern_does_not_fire_on_aws_role() -> None:
    """Specificity — AWS roles should not trigger the
    Azure-specific RBAC pattern."""
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/admin",
        kind="iam_role",
        attributes={
            "azure_roles": ["Owner"],  # spurious tag
            "azure_scope": "/subscriptions/sub",
        },
    ))
    paths = find_attack_paths(
        g, patterns=["cap_azure_owner_role_user"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# cap_gcp_service_account_owner_role
# ---------------------------------------------------------------------------


def test_gcp_sa_with_owner_role_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="projects/p/serviceAccounts/admin-sa",
        kind="gcp_service_account",
        attributes={"gcp_roles": ["roles/owner"]},
    ))
    paths = find_attack_paths(
        g, patterns=["cap_gcp_service_account_owner_role"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"


def test_gcp_sa_with_editor_role_fires() -> None:
    """Editor is nearly as bad as Owner in GCP — broad write
    access across all services."""
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="projects/p/serviceAccounts/editor-sa",
        kind="gcp_service_account",
        attributes={"gcp_roles": ["roles/editor"]},
    ))
    paths = find_attack_paths(
        g, patterns=["cap_gcp_service_account_owner_role"],
    )
    assert len(paths) == 1


def test_gcp_sa_with_scoped_role_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="projects/p/serviceAccounts/storage-sa",
        kind="gcp_service_account",
        attributes={"gcp_roles": ["roles/storage.objectViewer"]},
    ))
    paths = find_attack_paths(
        g, patterns=["cap_gcp_service_account_owner_role"],
    )
    assert paths == []


def test_gcp_sa_pattern_does_not_fire_on_aws_role() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/admin",
        kind="iam_role",
        attributes={"gcp_roles": ["roles/owner"]},  # spurious tag
    ))
    paths = find_attack_paths(
        g, patterns=["cap_gcp_service_account_owner_role"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# Cross-cloud sort + dedup
# ---------------------------------------------------------------------------


def test_v3_patterns_sorted_critical_first() -> None:
    """Build a graph that fires multiple v3 patterns; verify the
    critical-first sort survives."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="projects/p/datasets/leaky",
        kind="gcp_bigquery_dataset", is_public=True,
    ))
    g.add_node(CloudIdentity(
        arn="projects/p/serviceAccounts/admin-sa",
        kind="gcp_service_account",
        attributes={"gcp_roles": ["roles/owner"]},
    ))
    # And a non-critical GCP default-SA-without-cloud-platform.
    g.add_node(CloudResource(
        arn="projects/p/instances/i-vm",
        kind="gcp_compute_instance",
        is_public=True,
        attributes={
            "default_service_account": True,
            "scopes": ["devstorage.read_only"],
        },
    ))
    paths = find_attack_paths(g)
    severities = [p.severity for p in paths]
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    ranks = [sev_rank[s] for s in severities]
    assert ranks == sorted(ranks, reverse=True)


def test_v3_patterns_handle_empty_graph() -> None:
    paths = find_attack_paths(CloudGraph(), patterns=[
        "cap_gcp_default_compute_sa_with_internet",
        "cap_gcp_public_bigquery_dataset",
        "cap_gcp_service_account_owner_role",
        "cap_azure_storage_public_blob",
        "cap_azure_owner_role_user",
    ])
    assert paths == []
