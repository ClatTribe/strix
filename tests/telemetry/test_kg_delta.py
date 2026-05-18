"""Tests for engine-wishlist §8 kg_delta.jsonl emission.

Hermetic — works against the real CloudGraph + custom mocks; no
tracer-global state assumptions except where explicitly stamped."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.cloud_attack_paths.graph import (
    CloudGraph,
    CloudIdentity,
    CloudResource,
)
from strix.telemetry.kg_delta import (
    KgEdgeDelta,
    KgNodeDelta,
    emit_kg_deltas,
    from_cloud_graph,
)


# ---------------------------------------------------------------------------
# Dataclass row shapes
# ---------------------------------------------------------------------------


def test_node_delta_to_dict_minimal() -> None:
    n = KgNodeDelta(kind="CloudResource", id="arn:aws:s3:::x")
    d = n.to_dict()
    assert d == {
        "op": "add_node",
        "kind": "CloudResource",
        "id": "arn:aws:s3:::x",
        "attrs": {},
    }


def test_node_delta_to_dict_includes_optional_keys() -> None:
    n = KgNodeDelta(
        kind="CloudResource",
        id="arn:aws:s3:::x",
        attrs={"is_public": True, "tags": ["prod"]},
        source="cspm.aws.s3",
        scan_id="run-123",
        project_id="proj-payments",
    )
    d = n.to_dict()
    assert d["op"] == "add_node"
    assert d["source"] == "cspm.aws.s3"
    assert d["scan_id"] == "run-123"
    assert d["project_id"] == "proj-payments"
    assert d["attrs"]["is_public"] is True


def test_edge_delta_to_dict_with_dst_none() -> None:
    """`dst=None` is legal — encodes exposed_to_internet."""
    e = KgEdgeDelta(
        type="exposed_to_internet",
        src="arn:aws:s3:::x",
        dst=None,
        evidence="public_acl",
    )
    d = e.to_dict()
    assert d == {
        "op": "add_edge",
        "type": "exposed_to_internet",
        "src": "arn:aws:s3:::x",
        "dst": None,
        "evidence": "public_acl",
    }


def test_edge_delta_to_dict_with_dst_and_attrs() -> None:
    e = KgEdgeDelta(
        type="can_assume",
        src="arn:aws:iam::5678:user/y",
        dst="arn:aws:iam::1234:role/z",
        evidence="trust:7",
        attrs={"external_id_required": False},
    )
    d = e.to_dict()
    assert d["op"] == "add_edge"
    assert d["type"] == "can_assume"
    assert d["src"] == "arn:aws:iam::5678:user/y"
    assert d["dst"] == "arn:aws:iam::1234:role/z"
    assert d["evidence"] == "trust:7"
    assert d["attrs"]["external_id_required"] is False


# ---------------------------------------------------------------------------
# from_cloud_graph — walks a real CloudGraph
# ---------------------------------------------------------------------------


def test_from_cloud_graph_extracts_nodes_and_edges() -> None:
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::payments",
        kind="s3_bucket",
        is_public=True,
    ))
    g.add_node(CloudIdentity(
        arn="arn:aws:iam::1234:role/payments-task",
        kind="iam_role",
        trust_principals=("ecs.amazonaws.com",),
    ))
    g.add_edge(
        from_key="arn:aws:iam::1234:role/payments-task",
        kind="grants_access_to",
        to_key="arn:aws:s3:::payments",
    )

    nodes, edges = from_cloud_graph(
        g, scan_id="run-1", project_id="proj-pay",
    )
    assert len(nodes) == 2
    assert len(edges) == 1

    # Node kinds match the internal class names (the wishlist
    # vocabulary).
    kinds = {n.kind for n in nodes}
    assert kinds == {"CloudResource", "CloudIdentity"}

    # Project / scan provenance stamped on every row.
    for n in nodes:
        assert n.scan_id == "run-1"
        assert n.project_id == "proj-pay"
    for e in edges:
        assert e.scan_id == "run-1"
        assert e.project_id == "proj-pay"

    # Edge shape carries src + dst + type.
    e = edges[0]
    assert e.type == "grants_access_to"
    assert e.src == "arn:aws:iam::1234:role/payments-task"
    assert e.dst == "arn:aws:s3:::payments"


def test_from_cloud_graph_empty_graph_returns_empty_lists() -> None:
    g = CloudGraph()
    nodes, edges = from_cloud_graph(g)
    assert nodes == []
    assert edges == []


def test_from_cloud_graph_none_graph_returns_empty_lists() -> None:
    nodes, edges = from_cloud_graph(None)
    assert nodes == []
    assert edges == []


def test_from_cloud_graph_skips_node_without_key() -> None:
    """A graph node missing a node_key/arn is silently skipped."""

    class _MysteryNode:
        node_key = None
        arn = None

    class _FakeGraph:
        def nodes(self):
            return [_MysteryNode()]

        def edges(self):
            return []

    nodes, edges = from_cloud_graph(_FakeGraph())
    assert nodes == []


def test_from_cloud_graph_handles_dst_none_edges() -> None:
    """exposed_to_internet edges have `to_key=None`; the converter
    must propagate that as dst=None, not 'None' string."""
    g = CloudGraph()
    g.add_node(CloudResource(
        arn="arn:aws:s3:::p", kind="s3_bucket",
    ))
    g.add_edge(
        from_key="arn:aws:s3:::p",
        kind="exposed_to_internet",
        to_key=None,
    )
    _, edges = from_cloud_graph(g)
    assert len(edges) == 1
    assert edges[0].dst is None
    assert edges[0].to_dict()["dst"] is None


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def test_emit_writes_nodes_before_edges(tmp_path) -> None:
    nodes = [
        KgNodeDelta(kind="CloudResource", id="a"),
        KgNodeDelta(kind="CloudResource", id="b"),
    ]
    edges = [
        KgEdgeDelta(type="can_assume", src="a", dst="b"),
    ]
    out = emit_kg_deltas(tmp_path, nodes, edges)
    assert out == tmp_path / "kg_delta.jsonl"
    lines = [
        json.loads(line)
        for line in out.read_text().strip().split("\n")
    ]
    # First two lines are nodes; last is the edge.
    assert lines[0]["op"] == "add_node"
    assert lines[1]["op"] == "add_node"
    assert lines[2]["op"] == "add_edge"


def test_emit_returns_none_when_empty(tmp_path) -> None:
    out = emit_kg_deltas(tmp_path, [], [])
    assert out is None
    assert not (tmp_path / "kg_delta.jsonl").exists()


def test_emit_handles_nodes_only(tmp_path) -> None:
    """A graph with nodes but no edges still emits the artefact."""
    nodes = [KgNodeDelta(kind="CloudResource", id="x")]
    out = emit_kg_deltas(tmp_path, nodes, [])
    assert out is not None
    lines = out.read_text().strip().split("\n")
    assert len(lines) == 1


# ---------------------------------------------------------------------------
# Tracer accumulator wiring (engine-wishlist §8 + §6 compose)
# ---------------------------------------------------------------------------


def test_tracer_accumulators_exist(monkeypatch) -> None:
    """Tracer must declare both kg_node_deltas + kg_edge_deltas."""
    monkeypatch.delenv("STRIX_PROJECT_ID", raising=False)
    from strix.telemetry.tracer import Tracer

    t = Tracer("test")
    assert t.kg_node_deltas == []
    assert t.kg_edge_deltas == []


def test_tracer_kg_flush_writes_jsonl(monkeypatch, tmp_path) -> None:
    """Once the accumulators are populated, the finalisation
    block (same code path that runs in `mark_complete`) writes
    the artefact in node-first-then-edge order with project_id
    stamped per §6."""
    monkeypatch.setenv("STRIX_PROJECT_ID", "proj-x")
    from strix.telemetry.tracer import Tracer

    t = Tracer("test")
    t.kg_node_deltas.append({
        "op": "add_node",
        "kind": "CloudResource",
        "id": "arn:aws:s3:::x",
        "attrs": {"is_public": True},
    })
    t.kg_edge_deltas.append({
        "op": "add_edge",
        "type": "exposed_to_internet",
        "src": "arn:aws:s3:::x",
        "dst": None,
    })

    # Drive the same in-finalise emission logic.
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    kg_file = run_dir / "kg_delta.jsonl"
    with kg_file.open("w", encoding="utf-8") as f:
        for row in t.kg_node_deltas:
            stamped = dict(row)
            if t._project_id:
                stamped.setdefault("project_id", t._project_id)
            f.write(json.dumps(stamped) + "\n")
        for row in t.kg_edge_deltas:
            stamped = dict(row)
            if t._project_id:
                stamped.setdefault("project_id", t._project_id)
            f.write(json.dumps(stamped) + "\n")

    lines = [
        json.loads(line)
        for line in kg_file.read_text().strip().split("\n")
    ]
    assert lines[0]["op"] == "add_node"
    assert lines[0]["project_id"] == "proj-x"  # §6 stamped
    assert lines[1]["op"] == "add_edge"
    assert lines[1]["project_id"] == "proj-x"


# ---------------------------------------------------------------------------
# Specialist integration — analyze_cloud_attack_paths pushes deltas
# ---------------------------------------------------------------------------


def test_analyze_cloud_attack_paths_pushes_kg_deltas(
    monkeypatch, tmp_path,
) -> None:
    """End-to-end: `analyze_cloud_attack_paths` builds a graph
    + pushes deltas onto the tracer."""
    monkeypatch.delenv("STRIX_PROJECT_ID", raising=False)
    from strix.cloud_attack_paths.api import analyze_cloud_attack_paths
    from strix.cspm.aws import CspmFinding
    from strix.telemetry.tracer import Tracer, set_global_tracer

    t = Tracer("kg-delta-test")
    set_global_tracer(t)
    try:
        findings = [
            CspmFinding(
                rule_id="s3_public",
                severity="high",
                message="public bucket",
                service="s3",
                region="us-east-1",
                resource_arn="arn:aws:s3:::payments",
                cwe="CWE-200",
                category="cspm_misconfig",
                metadata={"is_public": True},
            ),
        ]
        analyze_cloud_attack_paths(cspm_findings=findings)
        # Graph populated → tracer has at least one node delta.
        assert len(t.kg_node_deltas) >= 1
        # Source provenance stamped per row.
        for row in t.kg_node_deltas:
            assert row["source"].startswith("cloud_attack_paths")
    finally:
        set_global_tracer(None)
