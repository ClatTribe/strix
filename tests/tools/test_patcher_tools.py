"""Tool-surface tests for the patcher CRUD tools.

The underlying registry is exhaustively tested in
`tests/agents/test_patcher.py`. This file pins the tool wrappers:
arg parsing, return shape, error handling, §4 integration via the
`verify_patch` tool.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.agents import patcher
from strix.agents import verification_pipeline as vp
from strix.tools.workflow import patcher_tools


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    patcher.reset_for_testing()
    vp.reset_for_testing()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_PATCHER_DISABLED", raising=False)


def test_propose_patch_returns_record() -> None:
    r = patcher_tools.propose_patch(
        finding_id="F-001",
        diff="--- a/x\n+++ b/x\n@@\n-bad\n+good\n",
        commit_message="fix: parameterise query",
    )
    assert r["success"] is True
    assert r["patch"]["status"] == "proposed"
    assert r["patch"]["finding_id"] == "F-001"
    assert r["patch"]["applied"] is False


def test_propose_patch_idempotent() -> None:
    r1 = patcher_tools.propose_patch(
        finding_id="F-001", diff="d", commit_message="x",
    )
    r2 = patcher_tools.propose_patch(
        finding_id="F-001", diff="d", commit_message="x",
    )
    # Same patch_id (sha1 of same diff).
    assert r1["patch"]["patch_id"] == r2["patch"]["patch_id"]


def test_propose_patch_applied_flag() -> None:
    r = patcher_tools.propose_patch(
        finding_id="F-001", diff="d", commit_message="x", applied=True,
    )
    assert r["patch"]["applied"] is True


def test_mark_patch_applied() -> None:
    p = patcher_tools.propose_patch(
        finding_id="F-001", diff="d", commit_message="x",
    )
    r = patcher_tools.mark_patch_applied(patch_id=p["patch"]["patch_id"])
    assert r["success"] is True
    assert r["patch"]["applied"] is True


def test_mark_patch_applied_unknown() -> None:
    r = patcher_tools.mark_patch_applied(patch_id="PATCH-nope")
    assert r["success"] is False
    assert r["error"] == "not_found"


def test_verify_patch_success() -> None:
    p = patcher_tools.propose_patch(
        finding_id="F-001", diff="d", commit_message="x", applied=True,
    )
    r = patcher_tools.verify_patch(
        patch_id=p["patch"]["patch_id"],
        probe_result_still_fires=False,
    )
    assert r["success"] is True
    assert r["patch"]["status"] == "verified"


def test_verify_patch_regression() -> None:
    p = patcher_tools.propose_patch(
        finding_id="F-001", diff="d", commit_message="x", applied=True,
    )
    r = patcher_tools.verify_patch(
        patch_id=p["patch"]["patch_id"],
        probe_result_still_fires=True,
        probe_evidence="re-ran scan_sqli, error fingerprint still present",
    )
    assert r["success"] is False
    assert r["patch"]["status"] == "regressed"


def test_verify_patch_advances_pipeline() -> None:
    """End-to-end: §4 pipeline finding starts at EXPLOITED; after
    verify_patch with probe=not-firing, it lands on PATCHED."""
    pipeline = vp.get_pipeline()
    pipeline.register(finding_id="F-001", severity="medium")
    pipeline.advance("F-001", target_stage="DETECTED")
    pipeline.advance("F-001", target_stage="VERIFYING")
    pipeline.record_evidence(
        "F-001", method="payload_response", outcome="PASSED", tool="x",
    )
    pipeline.advance("F-001", target_stage="VERIFIED")
    pipeline.advance("F-001", target_stage="EXPLOITED")

    p = patcher_tools.propose_patch(
        finding_id="F-001", diff="d", commit_message="x", applied=True,
    )
    patcher_tools.verify_patch(
        patch_id=p["patch"]["patch_id"],
        probe_result_still_fires=False,
    )
    rec = pipeline.get("F-001")
    assert rec is not None
    assert rec.stage == "PATCHED"


def test_verify_patch_unknown() -> None:
    r = patcher_tools.verify_patch(
        patch_id="PATCH-nope",
        probe_result_still_fires=False,
    )
    assert r["success"] is False
    assert "not found" in r["reason"]
    assert r["patch"] is None


def test_list_patches_no_filter() -> None:
    patcher_tools.propose_patch(finding_id="F-001", diff="A", commit_message="x")
    patcher_tools.propose_patch(finding_id="F-002", diff="B", commit_message="y")
    r = patcher_tools.list_patches()
    assert r["total"] == 2


def test_list_patches_status_filter() -> None:
    p1 = patcher_tools.propose_patch(
        finding_id="F-001", diff="A", commit_message="x", applied=True,
    )
    p2 = patcher_tools.propose_patch(
        finding_id="F-002", diff="B", commit_message="y", applied=True,
    )
    patcher_tools.verify_patch(
        patch_id=p1["patch"]["patch_id"], probe_result_still_fires=False,
    )
    patcher_tools.verify_patch(
        patch_id=p2["patch"]["patch_id"], probe_result_still_fires=True,
    )
    verified = patcher_tools.list_patches(status="verified")
    assert verified["total"] == 1
    regressed = patcher_tools.list_patches(status="regressed")
    assert regressed["total"] == 1


def test_list_patches_finding_id_filter() -> None:
    patcher_tools.propose_patch(finding_id="F-001", diff="A", commit_message="x")
    patcher_tools.propose_patch(finding_id="F-002", diff="B", commit_message="y")
    r = patcher_tools.list_patches(finding_id="F-001")
    assert r["total"] == 1
