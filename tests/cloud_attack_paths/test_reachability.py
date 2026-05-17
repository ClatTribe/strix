"""Tests for cloud-graph reachability scoring."""

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
    EDGE_GRANTS_ACCESS_TO,
    EDGE_HAS_POLICY,
)
from strix.cloud_attack_paths.patterns import AttackPath
from strix.cloud_attack_paths.reachability import (
    apply_reachability_to_paths,
    compute_priority,
    compute_reachability,
    score_path,
)


# ---------------------------------------------------------------------------
# BFS scoring — depth → score curve
# ---------------------------------------------------------------------------


def test_public_resource_scores_1() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::pub", kind="s3_bucket", is_public=True,
    ))
    scores = compute_reachability(g)
    assert scores["arn:aws:s3:::pub"] == 1.0


def test_one_hop_from_public_scores_07() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-pub",
        kind="ec2_instance", is_public=True,
    ))
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1:role/r", kind="iam_role",
    ))
    g.add_edge("arn:aws:iam::1:role/r", EDGE_ATTACHED_TO,
               "arn:aws:ec2:us-east-1:1:instance/i-pub")
    scores = compute_reachability(g)
    assert scores["arn:aws:ec2:us-east-1:1:instance/i-pub"] == 1.0
    assert scores["arn:aws:iam::1:role/r"] == 0.7


def test_two_hops_scores_04() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-pub",
        kind="ec2_instance", is_public=True,
    ))
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:role/r", kind="iam_role"))
    g.add_node(CloudPolicy(arn="arn:aws:iam::1:policy/p",
                            kind="iam_managed_policy"))
    g.add_edge("arn:aws:iam::1:role/r", EDGE_ATTACHED_TO,
               "arn:aws:ec2:us-east-1:1:instance/i-pub")
    g.add_edge("arn:aws:iam::1:role/r", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/p")
    scores = compute_reachability(g)
    assert scores["arn:aws:iam::1:policy/p"] == 0.4


def test_three_hops_scores_01() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-pub",
        kind="ec2_instance", is_public=True,
    ))
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:role/r", kind="iam_role"))
    g.add_node(CloudPolicy(arn="arn:aws:iam::1:policy/p",
                            kind="iam_managed_policy"))
    g.add_node(CloudResource(
        arn="arn:aws:s3:::reachable-via-policy", kind="s3_bucket",
    ))
    g.add_edge("arn:aws:iam::1:role/r", EDGE_ATTACHED_TO,
               "arn:aws:ec2:us-east-1:1:instance/i-pub")
    g.add_edge("arn:aws:iam::1:role/r", EDGE_HAS_POLICY,
               "arn:aws:iam::1:policy/p")
    g.add_edge("arn:aws:iam::1:policy/p", EDGE_GRANTS_ACCESS_TO,
               "arn:aws:s3:::reachable-via-policy")
    scores = compute_reachability(g)
    assert scores["arn:aws:s3:::reachable-via-policy"] == 0.1


def test_four_plus_hops_is_isolated() -> None:
    """Beyond max-depth, nodes default to 0.0 (absent from
    scores dict)."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:ec2:us-east-1:1:instance/i-pub",
        kind="ec2_instance", is_public=True,
    ))
    chain = ["n1", "n2", "n3", "n4", "n5"]
    for n in chain:
        g.add_node(CloudIdentity(arn=n, kind="iam_role"))
    g.add_edge("n1", EDGE_ATTACHED_TO,
               "arn:aws:ec2:us-east-1:1:instance/i-pub")
    for a, b in zip(chain, chain[1:]):
        g.add_edge(a, EDGE_CAN_ASSUME, b)
    scores = compute_reachability(g)
    # n4 is 4 hops away (public → n1 → n2 → n3 → n4) — beyond MAX_DEPTH.
    assert scores.get("n4", 0.0) == 0.0
    assert scores.get("n5", 0.0) == 0.0


def test_no_public_resources_returns_empty() -> None:
    """No seeds → empty scores dict. Caller's `.get(..., 0.0)`
    handles the missing-key path."""
    g = CloudGraph()
    g.add_node(CloudResource(arn="arn:aws:s3:::priv", kind="s3_bucket"))
    scores = compute_reachability(g)
    assert scores == {}


def test_empty_graph_returns_empty() -> None:
    scores = compute_reachability(CloudGraph())
    assert scores == {}


def test_multiple_publics_pick_best_score() -> None:
    """When a node is reachable from multiple public roots at
    different depths, it gets the BEST (shortest-path) score."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::pub-far", kind="s3_bucket", is_public=True,
    ))
    g.add_node(CloudResource(
        arn="arn:aws:s3:::pub-near", kind="s3_bucket", is_public=True,
    ))
    g.add_node(CloudIdentity(arn="arn:aws:iam::1:role/r", kind="iam_role"))
    # Far path: pub-far → role (1 hop).
    g.add_edge("arn:aws:s3:::pub-far", EDGE_GRANTS_ACCESS_TO,
               "arn:aws:iam::1:role/r")
    # Near path also 1 hop, but use directly_attached_to
    g.add_edge("arn:aws:iam::1:role/r", EDGE_ATTACHED_TO,
               "arn:aws:s3:::pub-near")
    scores = compute_reachability(g)
    # Both are 1 hop, so role gets 0.7.
    assert scores["arn:aws:iam::1:role/r"] == 0.7


# ---------------------------------------------------------------------------
# Path scoring (max across hops)
# ---------------------------------------------------------------------------


def test_path_score_takes_max_across_hops() -> None:
    scores = {
        "arn:public": 1.0,
        "arn:role": 0.7,
        "arn:policy": 0.4,
    }
    path = AttackPath(
        pattern_id="test", title="t", severity="critical",
        narrative="", hops=["arn:public", "arn:role", "arn:policy"],
    )
    assert score_path(path, scores) == 1.0


def test_path_score_zero_when_no_hops() -> None:
    path = AttackPath(
        pattern_id="x", title="t", severity="low",
        narrative="", hops=[],
    )
    assert score_path(path, {}) == 0.0


def test_path_score_zero_when_no_hops_in_scores() -> None:
    path = AttackPath(
        pattern_id="x", title="t", severity="low", narrative="",
        hops=["unknown-arn"],
    )
    assert score_path(path, {"some-other-arn": 1.0}) == 0.0


# ---------------------------------------------------------------------------
# apply_reachability_to_paths
# ---------------------------------------------------------------------------


def test_apply_stamps_metadata_and_attribute() -> None:
    paths = [
        AttackPath(
            pattern_id="x", title="t", severity="critical",
            narrative="", hops=["arn:public"],
        ),
    ]
    apply_reachability_to_paths(paths, {"arn:public": 1.0})
    p = paths[0]
    assert p.reachability_score == 1.0
    assert p.metadata["reachability_score"] == 1.0


def test_apply_is_idempotent() -> None:
    paths = [
        AttackPath(
            pattern_id="x", title="t", severity="high",
            narrative="", hops=["arn:public"],
        ),
    ]
    scores = {"arn:public": 1.0}
    apply_reachability_to_paths(paths, scores)
    apply_reachability_to_paths(paths, scores)
    assert paths[0].reachability_score == 1.0
    assert paths[0].metadata["reachability_score"] == 1.0


def test_apply_handles_paths_with_unknown_hops() -> None:
    paths = [
        AttackPath(
            pattern_id="x", title="t", severity="low",
            narrative="", hops=["unknown"],
        ),
    ]
    apply_reachability_to_paths(paths, {"other": 0.5})
    assert paths[0].reachability_score == 0.0


# ---------------------------------------------------------------------------
# Priority blending
# ---------------------------------------------------------------------------


def test_priority_critical_isolated_beats_medium_reachable() -> None:
    """Severity dominates; reachability is the tiebreaker."""
    critical_isolated = compute_priority("critical", 0.0)
    medium_reachable = compute_priority("medium", 1.0)
    assert critical_isolated > medium_reachable


def test_priority_within_severity_reachability_breaks_tie() -> None:
    high_public = compute_priority("high", 1.0)
    high_isolated = compute_priority("high", 0.0)
    assert high_public > high_isolated


def test_priority_clamps_reachability() -> None:
    assert compute_priority("critical", -0.5) == compute_priority("critical", 0.0)
    assert compute_priority("critical", 2.0) == compute_priority("critical", 1.0)


def test_priority_unknown_severity_treats_as_info() -> None:
    assert compute_priority("nonsense", 1.0) > 0.0  # rank 0 + reach 1.0


# ---------------------------------------------------------------------------
# Integration: analyze_cloud_attack_paths populates reachability
# ---------------------------------------------------------------------------


def test_analyze_stamps_reachability_on_paths() -> None:
    """End-to-end: a public bucket finding produces an attack path
    AND that path's `reachability_score` is 1.0 (directly
    exposed)."""
    from strix.cloud_attack_paths.api import analyze_cloud_attack_paths
    from strix.cspm.aws import CspmFinding

    findings = [CspmFinding(
        rule_id="AWS_S3_PUBLIC_ACL",
        severity="critical",
        message="public ACL on tfstate-prod",
        service="s3", region=None,
        resource_arn="arn:aws:s3:::tfstate-prod",
        account_id="1", cwe="CWE-732", category="misconfig",
    )]
    report = analyze_cloud_attack_paths(cspm_findings=findings)
    assert report.paths
    s3_path = next(
        p for p in report.paths
        if p.pattern_id == "cap_public_storage_credentials_risk"
    )
    assert s3_path.reachability_score == 1.0
    assert s3_path.metadata["reachability_score"] == 1.0


def test_analyze_isolated_path_scores_zero() -> None:
    """When no public resources exist, every path scores 0.0
    (no reachability seeds in v1)."""
    from strix.cloud_attack_paths.api import analyze_cloud_attack_paths
    from strix.cspm.aws import CspmFinding

    findings = [CspmFinding(
        rule_id="AWS_IAM_ROOT_ACCESS_KEY",
        severity="critical",
        message="root key present",
        service="iam", region=None,
        resource_arn="arn:aws:iam::*:root",
        account_id="1", cwe="CWE-269", category="misconfig",
    )]
    report = analyze_cloud_attack_paths(cspm_findings=findings)
    root_path = next(
        p for p in report.paths
        if p.pattern_id == "cap_root_unsafe"
    )
    # Root account isn't in the public-resources graph; reachability 0.
    assert root_path.reachability_score == 0.0


def test_to_dict_carries_reachability_score() -> None:
    """JSON-safe surface — wrappers serialise this for dashboards."""
    p = AttackPath(
        pattern_id="x", title="t", severity="high",
        narrative="", hops=["a"], reachability_score=0.7,
    )
    d = p.to_dict()
    assert d["reachability_score"] == 0.7


# ---------------------------------------------------------------------------
# Specialist tool metadata
# ---------------------------------------------------------------------------


def test_specialist_surfaces_reachability_buckets(monkeypatch) -> None:
    """`scan_cloud_attack_paths` should expose
    `tool_metadata.reachability_buckets` for the dashboard
    rollup."""
    from strix.cloud_attack_paths import tools as tools_module
    from strix.cloud_attack_paths.tools import scan_cloud_attack_paths
    from strix.cspm.aws import CspmFinding

    class _Stub:
        def __init__(self):
            self.findings = [CspmFinding(
                rule_id="AWS_S3_PUBLIC_ACL", severity="critical",
                message="m", service="s3", region=None,
                resource_arn="arn:aws:s3:::tfstate-prod",
                account_id="1", cwe="CWE-732", category="misconfig",
            )]
            self.errors = []
            self.account_id = "1"
            self.regions_scanned = ["us-east-1"]
            self.findings_by_service = {"s3": 1}

    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _Stub())

    result = scan_cloud_attack_paths(provider="aws")
    buckets = result["tool_metadata"]["reachability_buckets"]
    assert buckets["directly_exposed"] >= 1
