"""Tests for CloudGraph primitives."""

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


# ---------------------------------------------------------------------------
# Node identity + dedup
# ---------------------------------------------------------------------------


def test_add_node_dedupes_by_node_key() -> None:
    g = CloudGraph()
    r1 = CloudResource(arn="arn:aws:s3:::data", kind="s3_bucket")
    r2 = CloudResource(arn="arn:aws:s3:::data", kind="s3_bucket")
    a = g.add_node(r1)
    b = g.add_node(r2)
    assert a is b is r1  # second add returns the existing node


def test_get_node_by_arn() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(arn="arn:aws:s3:::data", kind="s3_bucket"))
    n = g.get_node("arn:aws:s3:::data")
    assert isinstance(n, CloudResource)
    assert n.kind == "s3_bucket"


# ---------------------------------------------------------------------------
# Edge indexing
# ---------------------------------------------------------------------------


def test_outgoing_and_incoming() -> None:
    g = CloudGraph()
    g.add_node(CloudIdentity(arn="arn:role/r1", kind="iam_role"))
    g.add_node(CloudResource(arn="arn:ec2/i1", kind="ec2_instance"))
    g.add_edge("arn:role/r1", EDGE_ATTACHED_TO, "arn:ec2/i1")

    assert g.outgoing("arn:role/r1", EDGE_ATTACHED_TO) == {"arn:ec2/i1"}
    assert g.incoming("arn:ec2/i1", EDGE_ATTACHED_TO) == {"arn:role/r1"}
    assert g.has_edge("arn:role/r1", EDGE_ATTACHED_TO, "arn:ec2/i1")
    assert not g.has_edge("arn:role/r1", EDGE_ATTACHED_TO, "arn:other")


def test_self_edge_for_exposure() -> None:
    """Exposure edges target None (it's a flag, not a relationship)."""
    g = CloudGraph()
    g.add_node(CloudResource(arn="arn:aws:s3:::pub", kind="s3_bucket"))
    g.add_edge("arn:aws:s3:::pub", EDGE_EXPOSED_TO_INTERNET, None)
    assert g.is_internet_exposed("arn:aws:s3:::pub")


def test_is_internet_exposed_via_attribute() -> None:
    """Fast path — `is_public=True` on the resource counts as
    exposed even without an edge."""
    g = CloudGraph()
    r = CloudResource(arn="arn:aws:s3:::x", kind="s3_bucket", is_public=True)
    g.add_node(r)
    assert g.is_internet_exposed("arn:aws:s3:::x")


# ---------------------------------------------------------------------------
# Policy semantics
# ---------------------------------------------------------------------------


def test_policy_detects_wildcard_admin() -> None:
    p = CloudPolicy(
        arn="arn:aws:iam::1:policy/bad",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow",
            "actions": ["*"],
            "resources": ["*"],
        }],
    )
    assert p.has_wildcard_admin()


def test_policy_with_deny_wildcard_is_not_admin() -> None:
    """`Effect: Deny + Action:* + Resource:*` is a guardrail, not
    an admin grant."""
    p = CloudPolicy(
        arn="arn:aws:iam::1:policy/deny",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Deny",
            "actions": ["*"],
            "resources": ["*"],
        }],
    )
    assert not p.has_wildcard_admin()


def test_policy_with_scoped_action_is_not_admin() -> None:
    p = CloudPolicy(
        arn="arn:aws:iam::1:policy/scoped",
        kind="iam_managed_policy",
        statements=[{
            "effect": "Allow",
            "actions": ["s3:GetObject"],
            "resources": ["*"],
        }],
    )
    assert not p.has_wildcard_admin()


# ---------------------------------------------------------------------------
# Identity semantics
# ---------------------------------------------------------------------------


def test_identity_world_assumable_when_trust_has_wildcard() -> None:
    ident = CloudIdentity(
        arn="arn:aws:iam::1:role/r",
        kind="iam_role",
        trust_principals=["*"],
    )
    assert ident.is_world_assumable


def test_identity_not_world_assumable_with_specific_principal() -> None:
    ident = CloudIdentity(
        arn="arn:aws:iam::1:role/r",
        kind="iam_role",
        trust_principals=["lambda.amazonaws.com"],
    )
    assert not ident.is_world_assumable


# ---------------------------------------------------------------------------
# Public-resources query
# ---------------------------------------------------------------------------


def test_public_resources_returns_only_internet_exposed() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::pub", kind="s3_bucket", is_public=True,
    ))
    g.add_node(CloudResource(
        arn="arn:aws:s3:::priv", kind="s3_bucket", is_public=False,
    ))
    g.add_node(CloudResource(
        arn="arn:aws:s3:::pub2", kind="s3_bucket",
    ))
    g.add_edge("arn:aws:s3:::pub2", EDGE_EXPOSED_TO_INTERNET, None)

    pub = g.public_resources()
    arns = {r.arn for r in pub}
    assert arns == {"arn:aws:s3:::pub", "arn:aws:s3:::pub2"}


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def test_graph_to_dict_is_json_safe() -> None:
    import json
    g = CloudGraph()
    g.add_node(CloudResource(arn="arn:aws:s3:::x", kind="s3_bucket"))
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:role/r", kind="iam_role"))
    g.add_edge("arn:aws:iam::1:role/r", EDGE_ATTACHED_TO, "arn:aws:s3:::x")
    payload = json.dumps(g.to_dict())  # must not raise
    assert "nodes" in payload
    assert "edges" in payload


def test_graph_summary_counts() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(arn="arn:aws:s3:::a", kind="s3_bucket"))
    g.add_node(CloudResource(arn="arn:aws:s3:::b", kind="s3_bucket"))
    g.add_node(CloudIdentity(arn="arn:role/r", kind="iam_role"))
    g.add_node(CloudPolicy(arn="arn:policy/p", kind="iam_managed_policy"))
    g.add_edge("arn:role/r", EDGE_HAS_POLICY, "arn:policy/p")

    summary = g.to_dict()["summary"]
    assert summary["resource_count"] == 2
    assert summary["identity_count"] == 1
    assert summary["policy_count"] == 1
    assert summary["edge_count"] == 1
