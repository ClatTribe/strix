"""Tests for auto-snapshot orchestration
(`auto_snapshot_and_scan` + specialist integration).

Hermetic — boto3 client factory and `subprocess.run` are both
DI'd; no real AWS calls and no real `trivy` invocation."""

from __future__ import annotations

from typing import Any

import pytest

from strix.cloud_attack_paths import agentless_scan as agentless_module
from strix.cloud_attack_paths import tools as tools_module
from strix.cloud_attack_paths.agentless_scan import (
    TransientSnapshot,
    auto_snapshot_and_scan,
    create_transient_snapshots,
    delete_transient_snapshots,
    discover_running_instances_and_volumes,
)
from strix.cloud_attack_paths.tools import scan_cloud_attack_paths


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **_kwargs):
        for p in self._pages:
            yield p


class _FakeEc2:
    """Fake EC2 client with `describe_instances` paginator,
    `create_snapshot`, and `delete_snapshot`."""

    def __init__(
        self,
        *,
        instances: list[dict] | None = None,
        snapshots_to_return: list[str] | None = None,
        snapshot_raises: bool = False,
        delete_raises: bool = False,
    ):
        self._instances = instances or []
        self._snapshot_queue = list(snapshots_to_return or [])
        self.snapshot_calls: list[dict] = []
        self.delete_calls: list[dict] = []
        self._snapshot_raises = snapshot_raises
        self._delete_raises = delete_raises

    def get_paginator(self, name):
        if name == "describe_instances":
            return _Paginator([{
                "Reservations": [{"Instances": self._instances}],
            }])
        raise AttributeError(f"no paginator `{name}`")

    def create_snapshot(self, **kwargs):
        self.snapshot_calls.append(kwargs)
        if self._snapshot_raises:
            raise RuntimeError("synthetic snapshot failure")
        sid = (
            self._snapshot_queue.pop(0)
            if self._snapshot_queue
            else f"snap-fake-{len(self.snapshot_calls)}"
        )
        return {"SnapshotId": sid}

    def delete_snapshot(self, **kwargs):
        self.delete_calls.append(kwargs)
        if self._delete_raises:
            raise RuntimeError("synthetic delete failure")


def _factory_for(ec2_by_region: dict[str, _FakeEc2]):
    """Build a fake client_factory closure that hands out the
    pre-seeded EC2 client per region."""
    def _factory(service, region=None):
        if service != "ec2":
            raise KeyError(f"unexpected service: {service}")
        if region not in ec2_by_region:
            raise KeyError(f"unexpected region: {region}")
        return ec2_by_region[region]
    return _factory


# ---------------------------------------------------------------------------
# discover_running_instances_and_volumes
# ---------------------------------------------------------------------------


def test_discover_picks_only_running_instances_with_volumes() -> None:
    ec2 = _FakeEc2(instances=[
        {
            "InstanceId": "i-aaa",
            "BlockDeviceMappings": [
                {"Ebs": {"VolumeId": "vol-1"}},
                {"Ebs": {"VolumeId": "vol-2"}},
            ],
        },
        {
            # No volumes — skipped.
            "InstanceId": "i-bbb",
            "BlockDeviceMappings": [],
        },
        {
            # No InstanceId — skipped.
            "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-99"}}],
        },
    ])
    result = discover_running_instances_and_volumes(
        _factory_for({"us-east-1": ec2}), region="us-east-1",
    )
    assert result == [("i-aaa", ["vol-1", "vol-2"])]


def test_discover_honours_max_instances_cap() -> None:
    instances = [
        {"InstanceId": f"i-{n}",
         "BlockDeviceMappings": [{"Ebs": {"VolumeId": f"vol-{n}"}}]}
        for n in range(10)
    ]
    ec2 = _FakeEc2(instances=instances)
    result = discover_running_instances_and_volumes(
        _factory_for({"us-east-1": ec2}),
        region="us-east-1",
        max_instances=3,
    )
    assert len(result) == 3


def test_discover_returns_empty_on_client_failure() -> None:
    def _factory(service, region=None):
        raise PermissionError("denied")
    out = discover_running_instances_and_volumes(
        _factory, region="us-east-1",
    )
    assert out == []


# ---------------------------------------------------------------------------
# create_transient_snapshots
# ---------------------------------------------------------------------------


def test_create_snapshots_tags_with_strix_transient() -> None:
    ec2 = _FakeEc2(snapshots_to_return=["snap-aaa", "snap-bbb"])
    out = create_transient_snapshots(
        _factory_for({"us-east-1": ec2}),
        instances=[("i-1", ["vol-1", "vol-2"])],
        region="us-east-1",
    )
    assert len(out) == 2
    assert {s.snapshot_id for s in out} == {"snap-aaa", "snap-bbb"}
    # Tag attribution.
    for call in ec2.snapshot_calls:
        tags = call["TagSpecifications"][0]["Tags"]
        tag_keys = {t["Key"] for t in tags}
        assert "strix-transient" in tag_keys
        assert "strix-source-instance" in tag_keys


def test_create_snapshots_isolates_per_volume_errors() -> None:
    """If one snapshot creation fails, the rest succeed."""
    calls = {"n": 0}

    class _PartialFailEc2(_FakeEc2):
        def create_snapshot(self, **kwargs):
            self.snapshot_calls.append(kwargs)
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("bad volume")
            return {"SnapshotId": f"snap-{calls['n']}"}

    ec2 = _PartialFailEc2()
    out = create_transient_snapshots(
        _factory_for({"us-east-1": ec2}),
        instances=[("i-1", ["vol-1", "vol-2", "vol-3"])],
        region="us-east-1",
    )
    # 1st + 3rd succeed; 2nd raised → not in the output.
    assert len(out) == 2


# ---------------------------------------------------------------------------
# delete_transient_snapshots
# ---------------------------------------------------------------------------


def test_delete_groups_by_region_and_counts_outcomes() -> None:
    ec2_use1 = _FakeEc2()
    ec2_usw2 = _FakeEc2()
    snaps = [
        TransientSnapshot(snapshot_id="snap-a", volume_id="vol-a",
                          instance_id="i-a", region="us-east-1"),
        TransientSnapshot(snapshot_id="snap-b", volume_id="vol-b",
                          instance_id="i-b", region="us-west-2"),
    ]
    deleted, failed = delete_transient_snapshots(
        _factory_for({"us-east-1": ec2_use1, "us-west-2": ec2_usw2}),
        snaps,
    )
    assert deleted == 2
    assert failed == 0
    assert len(ec2_use1.delete_calls) == 1
    assert len(ec2_usw2.delete_calls) == 1


def test_delete_counts_failures_when_api_raises() -> None:
    ec2 = _FakeEc2(delete_raises=True)
    snaps = [
        TransientSnapshot(snapshot_id="snap-x", volume_id="vol-x",
                          instance_id="i-x", region="us-east-1"),
    ]
    deleted, failed = delete_transient_snapshots(
        _factory_for({"us-east-1": ec2}), snaps,
    )
    assert deleted == 0
    assert failed == 1


def test_delete_handles_factory_failure_per_region() -> None:
    """A client-build failure in one region marks every snapshot
    in that region as failed; other regions still run."""
    def _factory(service, region=None):
        if region == "us-east-1":
            raise PermissionError("denied")
        return _FakeEc2()
    snaps = [
        TransientSnapshot(snapshot_id="snap-1", volume_id="vol-1",
                          instance_id="i-1", region="us-east-1"),
        TransientSnapshot(snapshot_id="snap-2", volume_id="vol-2",
                          instance_id="i-2", region="us-east-1"),
        TransientSnapshot(snapshot_id="snap-3", volume_id="vol-3",
                          instance_id="i-3", region="us-west-2"),
    ]
    deleted, failed = delete_transient_snapshots(_factory, snaps)
    assert deleted == 1   # us-west-2 worked
    assert failed == 2    # us-east-1 region client build failed


# ---------------------------------------------------------------------------
# auto_snapshot_and_scan — end-to-end orchestration
# ---------------------------------------------------------------------------


def _ok_trivy_proc(stdout: str = ""):
    """Build a stub for subprocess.run that returns a clean
    Trivy-shaped proc."""
    class _Proc:
        returncode = 0
        stdout = ""
        stderr = ""
    p = _Proc()
    p.stdout = stdout or '{"Results": []}'
    return p


def test_auto_snapshot_end_to_end_clean_cleanup(
    monkeypatch,
) -> None:
    """Happy path: discover → snapshot → scan → delete. No
    snapshots left in the account."""
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    ec2 = _FakeEc2(
        instances=[{
            "InstanceId": "i-aaa",
            "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-1"}}],
        }],
        snapshots_to_return=["snap-aaa"],
    )

    def _stub_run(argv, **kwargs):
        return _ok_trivy_proc()

    results, lifecycle = auto_snapshot_and_scan(
        _factory_for({"us-east-1": ec2}),
        regions=["us-east-1"],
        _subprocess_run=_stub_run,
    )
    assert lifecycle["instances_discovered"] == 1
    assert lifecycle["snapshots_created"] == 1
    assert lifecycle["snapshots_deleted"] == 1
    assert lifecycle["snapshots_failed"] == 0
    assert lifecycle["manual_cleanup_required"] == []
    # Source-instance attribution propagated into scan metadata.
    assert results[0].metadata["source_instance"] == "i-aaa"
    assert results[0].metadata["source_volume"] == "vol-1"
    assert results[0].metadata["source_region"] == "us-east-1"


def test_auto_snapshot_no_running_instances_returns_empty(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    ec2 = _FakeEc2(instances=[])

    def _stub_run(*a, **kw):
        raise AssertionError("trivy should not run without snapshots")

    results, lifecycle = auto_snapshot_and_scan(
        _factory_for({"us-east-1": ec2}),
        regions=["us-east-1"],
        _subprocess_run=_stub_run,
    )
    assert results == []
    assert lifecycle["instances_discovered"] == 0
    assert lifecycle["snapshots_created"] == 0


def test_auto_snapshot_failed_cleanup_surfaces_manual_list(
    monkeypatch,
) -> None:
    """If delete fails, the snapshot IDs surface in the
    `manual_cleanup_required` list so an operator can finish."""
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    ec2 = _FakeEc2(
        instances=[{
            "InstanceId": "i-aaa",
            "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-1"}}],
        }],
        snapshots_to_return=["snap-aaa"],
        delete_raises=True,
    )

    def _stub_run(argv, **kwargs):
        return _ok_trivy_proc()

    _, lifecycle = auto_snapshot_and_scan(
        _factory_for({"us-east-1": ec2}),
        regions=["us-east-1"],
        _subprocess_run=_stub_run,
    )
    assert lifecycle["snapshots_failed"] == 1
    assert len(lifecycle["manual_cleanup_required"]) == 1
    assert (
        lifecycle["manual_cleanup_required"][0]["snapshot_id"]
        == "snap-aaa"
    )


def test_auto_snapshot_cleanup_disabled_leaves_snapshots(
    monkeypatch,
) -> None:
    """When `cleanup_on_completion=False`, snapshots remain in
    the account; the manual_cleanup_required list still names
    them for operator visibility."""
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    ec2 = _FakeEc2(
        instances=[{
            "InstanceId": "i-aaa",
            "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-1"}}],
        }],
        snapshots_to_return=["snap-aaa"],
    )

    def _stub_run(argv, **kwargs):
        return _ok_trivy_proc()

    _, lifecycle = auto_snapshot_and_scan(
        _factory_for({"us-east-1": ec2}),
        regions=["us-east-1"],
        cleanup_on_completion=False,
        _subprocess_run=_stub_run,
    )
    # No deletes attempted.
    assert ec2.delete_calls == []
    assert lifecycle["snapshots_deleted"] == 0
    # Snapshots surface for operator visibility.
    assert len(lifecycle["manual_cleanup_required"]) == 1


def test_auto_snapshot_multi_region(monkeypatch) -> None:
    """Two regions, two instances → two snapshots, both
    scanned, both deleted."""
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    ec2_use1 = _FakeEc2(
        instances=[{
            "InstanceId": "i-east",
            "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-e"}}],
        }],
        snapshots_to_return=["snap-east"],
    )
    ec2_usw2 = _FakeEc2(
        instances=[{
            "InstanceId": "i-west",
            "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-w"}}],
        }],
        snapshots_to_return=["snap-west"],
    )

    def _stub_run(argv, **kwargs):
        return _ok_trivy_proc()

    _, lifecycle = auto_snapshot_and_scan(
        _factory_for({"us-east-1": ec2_use1, "us-west-2": ec2_usw2}),
        regions=["us-east-1", "us-west-2"],
        _subprocess_run=_stub_run,
    )
    assert lifecycle["instances_discovered"] == 2
    assert lifecycle["snapshots_created"] == 2
    assert lifecycle["snapshots_deleted"] == 2


# ---------------------------------------------------------------------------
# Specialist integration
# ---------------------------------------------------------------------------


class _StubAwsReport:
    findings: list = []
    errors: list = []
    account_id = "1"
    regions_scanned = ["us-east-1"]
    findings_by_service = {}


def test_specialist_auto_snapshot_orchestration_flag(
    monkeypatch,
) -> None:
    """Setting `auto_snapshot_orchestration=True` calls
    `auto_snapshot_and_scan` and exposes the lifecycle summary
    in `tool_metadata.auto_snapshot_summary`."""
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())

    captured: dict[str, Any] = {}

    def fake_auto(factory, **kwargs):
        captured["called"] = True
        captured["kwargs"] = kwargs
        return [], {
            "instances_discovered": 5,
            "snapshots_created": 5,
            "snapshots_deleted": 5,
            "snapshots_failed": 0,
            "manual_cleanup_required": [],
            "per_region_errors": {},
        }

    monkeypatch.setattr(
        agentless_module, "auto_snapshot_and_scan", fake_auto,
    )
    # Avoid building the real boto3 client factory.
    monkeypatch.setattr(
        "strix.cspm.aws.client.make_default_client_factory",
        lambda **_: (lambda *a, **kw: object()),
    )

    result = scan_cloud_attack_paths(
        provider="aws",
        auto_snapshot_orchestration=True,
        auto_discover_assets=False,
    )
    assert result["status"] == "ok"
    summary = result["tool_metadata"]["auto_snapshot_summary"]
    assert summary["lifecycle"]["instances_discovered"] == 5
    assert summary["lifecycle"]["snapshots_deleted"] == 5
    assert captured.get("called") is True


def test_specialist_auto_snapshot_default_off(monkeypatch) -> None:
    """Default (no kwarg) doesn't call the auto-snapshot path."""
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())

    def _refuse(*a, **kw):
        raise AssertionError(
            "auto_snapshot_and_scan called without opt-in"
        )

    monkeypatch.setattr(
        agentless_module, "auto_snapshot_and_scan", _refuse,
    )

    result = scan_cloud_attack_paths(
        provider="aws", auto_discover_assets=False,
    )
    assert "auto_snapshot_summary" not in result["tool_metadata"]


def test_specialist_auto_snapshot_failure_does_not_crash(
    monkeypatch,
) -> None:
    """If the orchestration crashes (denied / quota), the rest
    of the scan still runs; the failure surfaces in
    cspm_errors."""
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())

    def _boom(*a, **kw):
        raise RuntimeError("synthetic orchestration crash")

    monkeypatch.setattr(
        agentless_module, "auto_snapshot_and_scan", _boom,
    )
    monkeypatch.setattr(
        "strix.cspm.aws.client.make_default_client_factory",
        lambda **_: (lambda *a, **kw: object()),
    )

    result = scan_cloud_attack_paths(
        provider="aws",
        auto_snapshot_orchestration=True,
        auto_discover_assets=False,
    )
    assert result["status"] == "ok"
    errors = result["tool_metadata"]["cspm_errors"]
    assert any(
        e.get("source") == "auto_snapshot_orchestration"
        for e in errors
    )
