"""Tests for built-in attack-path patterns.

Each pattern test sets up a small graph that should (or shouldn't)
fire the pattern, then asserts the resulting AttackPath shape.
"""

from __future__ import annotations

import pytest

from strix.cloud_attack_paths.graph import (
    CloudGraph,
    CloudIdentity,
    CloudPolicy,
    CloudResource,
    EDGE_ATTACHED_TO,
    EDGE_EXPOSED_TO_INTERNET,
    EDGE_HAS_POLICY,
)
from strix.cloud_attack_paths.patterns import (
    BUILTIN_PATTERNS,
    find_attack_paths,
)


# ---------------------------------------------------------------------------
# Pattern: public storage credentials risk
# ---------------------------------------------------------------------------


def test_public_s3_bucket_with_state_name_fires_pattern() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::prod-tfstate",
        kind="s3_bucket",
        is_data_store=True,
        is_public=True,
    ))
    g.add_edge("arn:aws:s3:::prod-tfstate",
               EDGE_EXPOSED_TO_INTERNET, None)

    paths = find_attack_paths(
        g, patterns=["cap_public_storage_credentials_risk"],
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.severity == "critical"
    assert "prod-tfstate" in p.title
    assert p.confidence >= 0.85


def test_private_bucket_does_not_fire_pattern() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::private",
        kind="s3_bucket",
        is_data_store=True,
        is_public=False,
    ))
    paths = find_attack_paths(
        g, patterns=["cap_public_storage_credentials_risk"],
    )
    assert paths == []


def test_public_non_storage_does_not_fire_pattern() -> None:
    """A public Lambda isn't a storage resource — different pattern
    handles it."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:lambda:us-east-1:1:function:f",
        kind="lambda_function",
        is_public=True,
    ))
    paths = find_attack_paths(
        g, patterns=["cap_public_storage_credentials_risk"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# Pattern: internet-exposed compute with IAM
# ---------------------------------------------------------------------------


def test_public_lambda_with_iam_role_fires_pattern() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:lambda:us-east-1:1:function:api",
        kind="lambda_function", is_public=True,
    ))
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/api-role", kind="iam_role",
    ))
    g.add_edge("arn:aws:iam::1:role/api-role",
               EDGE_ATTACHED_TO,
               "arn:aws:lambda:us-east-1:1:function:api")

    paths = find_attack_paths(
        g, patterns=["cap_internet_exposed_compute_with_iam"],
    )
    assert len(paths) == 1
    p = paths[0]
    assert p.severity == "high"
    assert "api-role" in p.narrative


def test_public_compute_with_wildcard_admin_bumped_to_critical() -> None:
    """When the attached IAM identity has a wildcard-admin policy,
    severity is bumped from high to critical — one-step path to
    full account compromise."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-bad",
        kind="ec2_instance", is_public=True,
    ))
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/admin-role", kind="iam_role",
    ))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/admin",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:role/admin-role",
               EDGE_ATTACHED_TO,
               "arn:aws:ec2:us-east-1:1:instance/i-bad")
    g.add_edge("arn:aws:iam::1:role/admin-role",
               EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/admin")

    paths = find_attack_paths(
        g, patterns=["cap_internet_exposed_compute_with_iam"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"
    assert paths[0].metadata.get("wildcard_admin") is True


def test_public_compute_without_iam_does_not_fire() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-alone",
        kind="ec2_instance", is_public=True,
    ))
    paths = find_attack_paths(
        g, patterns=["cap_internet_exposed_compute_with_iam"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# Pattern: wildcard admin attached to runtime
# ---------------------------------------------------------------------------


def test_wildcard_admin_policy_attached_via_compute_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/everything",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/r", kind="iam_role",
    ))
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-1",
        kind="ec2_instance",
    ))
    g.add_edge("arn:aws:iam::1:role/r",
               EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/everything")
    g.add_edge("arn:aws:iam::1:role/r",
               EDGE_ATTACHED_TO,
               "arn:aws:ec2:us-east-1:1:instance/i-1")

    paths = find_attack_paths(
        g, patterns=["cap_wildcard_admin_attached"],
    )
    assert len(paths) == 1
    assert paths[0].severity == "critical"
    # Hop chain: policy → identity → compute.
    assert len(paths[0].hops) == 3


def test_wildcard_admin_policy_unattached_does_not_fire() -> None:
    """A wildcard policy that's defined but not attached to any
    runtime resource doesn't constitute an exploitable attack
    path — it's still bad practice, but the constituent rule
    catches it; this pattern is about runtime exploitability."""
    g = CloudGraph()
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/orphan",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    paths = find_attack_paths(
        g, patterns=["cap_wildcard_admin_attached"],
    )
    assert paths == []


# ---------------------------------------------------------------------------
# Pattern: root account unsafe
# ---------------------------------------------------------------------------


def test_root_unsafe_pattern_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:root", kind="aws_root",
        attributes={"root_unsafe": True},
    ))
    paths = find_attack_paths(g, patterns=["cap_root_unsafe"])
    assert len(paths) == 1
    assert paths[0].severity == "critical"
    assert paths[0].confidence == 1.0


def test_root_unsafe_pattern_quiet_without_signal() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:root", kind="aws_root"))
    paths = find_attack_paths(g, patterns=["cap_root_unsafe"])
    assert paths == []


# ---------------------------------------------------------------------------
# Pattern: world-assumable role
# ---------------------------------------------------------------------------


def test_world_assumable_role_fires() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/external",
        kind="iam_role",
        trust_principals=["*"],
    ))
    paths = find_attack_paths(g, patterns=["cap_world_assumable_role"])
    assert len(paths) == 1
    assert paths[0].severity == "high"


def test_world_assumable_with_admin_policy_is_critical() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/external-admin",
        kind="iam_role",
        trust_principals=["*"],
    ))
    g.add_node(CloudPolicy(
        arn="arn:aws:iam::1:policy/admin",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow", "actions": ["*"], "resources": ["*"],
        }],
    ))
    g.add_edge("arn:aws:iam::1:role/external-admin",
               EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/admin")

    paths = find_attack_paths(g, patterns=["cap_world_assumable_role"])
    assert len(paths) == 1
    assert paths[0].severity == "critical"
    assert paths[0].metadata.get("has_admin_policy_attached") is True


# ---------------------------------------------------------------------------
# find_attack_paths integration
# ---------------------------------------------------------------------------


def test_find_attack_paths_returns_critical_first() -> None:
    g = CloudGraph()
    # Critical: root unsafe.
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:root", kind="aws_root",
        attributes={"root_unsafe": True},
    ))
    # High: world-assumable role without admin policy.
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/x",
        kind="iam_role",
        trust_principals=["*"],
    ))

    paths = find_attack_paths(g)
    assert paths
    assert paths[0].severity == "critical"
    severities = [p.severity for p in paths]
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    ranks = [sev_rank[s] for s in severities]
    assert ranks == sorted(ranks, reverse=True)


def test_find_attack_paths_pattern_allowlist() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:root", kind="aws_root",
        attributes={"root_unsafe": True},
    ))
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/x",
        kind="iam_role", trust_principals=["*"],
    ))

    paths = find_attack_paths(g, patterns=["cap_root_unsafe"])
    assert all(p.pattern_id == "cap_root_unsafe" for p in paths)
    # The world-assumable pattern was registered but excluded.
    assert not any(
        p.pattern_id == "cap_world_assumable_role" for p in paths
    )


def test_custom_pattern_registered_alongside_builtins() -> None:
    """Wrapper integrations can supply their own pattern function
    without forking strix. Verify a trivial custom pattern fires."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::test", kind="s3_bucket",
    ))

    from strix.cloud_attack_paths.patterns import AttackPath

    def _every_bucket_pattern(graph: CloudGraph):
        return [
            AttackPath(
                pattern_id="custom_every_bucket",
                title=f"Bucket {r.arn}",
                severity="info",
                narrative="custom",
                hops=[r.arn],
            )
            for r in graph.resources_of_kind("s3_bucket")
        ]

    paths = find_attack_paths(
        g, custom_patterns={"custom_every_bucket": _every_bucket_pattern},
    )
    assert any(p.pattern_id == "custom_every_bucket" for p in paths)


def test_pattern_failure_does_not_stop_others(monkeypatch) -> None:
    """A pattern that raises an exception must not stop the rest
    of the patterns from running — robustness for third-party
    custom patterns."""
    from strix.cloud_attack_paths import patterns as patterns_mod

    g = CloudGraph()
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:root", kind="aws_root",
        attributes={"root_unsafe": True},
    ))

    def _broken(graph: CloudGraph):
        raise RuntimeError("oops")

    out = find_attack_paths(
        g, custom_patterns={"custom_broken": _broken},
    )
    # Root-unsafe still fires.
    assert any(p.pattern_id == "cap_root_unsafe" for p in out)


# ---------------------------------------------------------------------------
# Builtins registry hygiene
# ---------------------------------------------------------------------------


def test_all_builtin_pattern_ids_have_cap_prefix() -> None:
    """Naming convention enforcement so a future contributor
    doesn't drift."""
    for pid in BUILTIN_PATTERNS:
        assert pid.startswith("cap_"), f"{pid} missing cap_ prefix"


def test_builtin_patterns_handle_empty_graph() -> None:
    """No findings → no attack paths, no crashes."""
    g = CloudGraph()
    out = find_attack_paths(g)
    assert out == []
