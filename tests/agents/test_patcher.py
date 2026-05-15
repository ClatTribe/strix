"""Tests for the Patcher / patch_verify state machine.

Covers:
  * Proposal idempotency on (finding_id, sha1(diff))
  * `applied` flag flip via mark_applied
  * `verify` happy path — probe says PoC no longer fires → verified
  * `verify` regression — probe says PoC still fires → regressed
  * Verified/regressed are terminal — re-verify is a no-op
  * `on_verified` callback fires (e.g. §4 pipeline auto-advance)
  * §4 integration — `advance_finding_to_patched` flips finding stage
  * Persistence to <run_dir>/patches.jsonl
  * Kill switch (STRIX_PATCHER_DISABLED)
  * Defensive: probe_fn raising is treated as regressed
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.agents import patcher
from strix.agents import verification_pipeline as vp


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    patcher.reset_for_testing()
    vp.reset_for_testing()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_PATCHER_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_PATCHER_PERSIST", raising=False)


# ---------------------------------------------------------------------------
# Proposal
# ---------------------------------------------------------------------------


def test_propose_creates_record() -> None:
    r = patcher.get_registry()
    p = r.propose(
        finding_id="F-001",
        diff="--- a/x\n+++ b/x\n@@\n-bad\n+good\n",
        commit_message="fix: parameterised query",
    )
    assert p.finding_id == "F-001"
    assert p.status == "proposed"
    assert p.applied is False
    assert p.patch_id.startswith("PATCH-")
    assert len(p.diff_hash) == 12


def test_propose_idempotent_on_same_diff() -> None:
    r = patcher.get_registry()
    p1 = r.propose(
        finding_id="F-001", diff="same diff", commit_message="x",
    )
    p2 = r.propose(
        finding_id="F-001", diff="same diff", commit_message="different commit msg",
    )
    assert p1 is p2  # same object returned
    assert p1.commit_message == "x"  # NOT overwritten


def test_propose_different_diff_different_patch() -> None:
    r = patcher.get_registry()
    p1 = r.propose(finding_id="F-001", diff="diff A", commit_message="x")
    p2 = r.propose(finding_id="F-001", diff="diff B", commit_message="y")
    assert p1.patch_id != p2.patch_id


def test_propose_caps_diff_at_16kb() -> None:
    r = patcher.get_registry()
    huge = "X" * 20000
    p = r.propose(finding_id="F-001", diff=huge, commit_message="x")
    assert len(p.diff) == 16384


def test_propose_with_applied_true() -> None:
    r = patcher.get_registry()
    p = r.propose(
        finding_id="F-001", diff="d", commit_message="x", applied=True,
    )
    assert p.applied is True


def test_re_propose_can_flip_applied() -> None:
    r = patcher.get_registry()
    r.propose(finding_id="F-001", diff="d", commit_message="x")
    p = r.propose(
        finding_id="F-001", diff="d", commit_message="x", applied=True,
    )
    assert p.applied is True


# ---------------------------------------------------------------------------
# mark_applied
# ---------------------------------------------------------------------------


def test_mark_applied_sets_flag() -> None:
    r = patcher.get_registry()
    p = r.propose(finding_id="F-001", diff="d", commit_message="x")
    updated = r.mark_applied(p.patch_id)
    assert updated is not None
    assert updated.applied is True


def test_mark_applied_unknown_returns_none() -> None:
    r = patcher.get_registry()
    assert r.mark_applied("PATCH-bogus") is None


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_verify_success_when_probe_says_not_firing() -> None:
    r = patcher.get_registry()
    p = r.propose(
        finding_id="F-001",
        diff="d", commit_message="fix",
        applied=True,
    )
    ok, reason, proposal = r.verify(
        p.patch_id,
        probe_fn=lambda: False,  # PoC no longer fires → patch worked
    )
    assert ok is True
    assert proposal is not None
    assert proposal.status == "verified"
    assert proposal.verified_at is not None


def test_verify_regression_when_probe_says_still_firing() -> None:
    r = patcher.get_registry()
    p = r.propose(
        finding_id="F-001", diff="d", commit_message="x", applied=True,
    )
    ok, reason, proposal = r.verify(
        p.patch_id,
        probe_fn=lambda: True,
    )
    assert ok is False
    assert proposal is not None
    assert proposal.status == "regressed"
    assert "still firing" in proposal.last_failure_reason


def test_verify_probe_raising_marks_regressed() -> None:
    r = patcher.get_registry()
    p = r.propose(
        finding_id="F-001", diff="d", commit_message="x", applied=True,
    )

    def _boom() -> bool:
        raise RuntimeError("probe blew up")

    ok, reason, proposal = r.verify(p.patch_id, probe_fn=_boom)
    assert ok is False
    assert proposal is not None
    assert proposal.status == "regressed"
    assert "RuntimeError" in proposal.last_failure_reason


def test_verify_unknown_returns_failure() -> None:
    r = patcher.get_registry()
    ok, reason, proposal = r.verify("PATCH-bogus", probe_fn=lambda: False)
    assert ok is False
    assert proposal is None
    assert "not found" in reason


def test_verified_is_terminal() -> None:
    r = patcher.get_registry()
    p = r.propose(finding_id="F-001", diff="d", commit_message="x", applied=True)
    r.verify(p.patch_id, probe_fn=lambda: False)
    # Calling verify again is idempotent; status stays verified.
    ok, reason, _ = r.verify(p.patch_id, probe_fn=lambda: True)
    assert ok is True  # still considered verified
    assert "already verified" in reason


def test_regressed_is_terminal() -> None:
    r = patcher.get_registry()
    p = r.propose(finding_id="F-001", diff="d", commit_message="x", applied=True)
    r.verify(p.patch_id, probe_fn=lambda: True)
    ok, reason, _ = r.verify(p.patch_id, probe_fn=lambda: False)
    assert ok is False
    assert "already regressed" in reason


# ---------------------------------------------------------------------------
# on_verified callback (used by tool wrapper to chain into §4)
# ---------------------------------------------------------------------------


def test_on_verified_callback_fires_only_on_success() -> None:
    r = patcher.get_registry()
    called: list[str] = []
    cb = lambda p: called.append(p.patch_id)

    p_success = r.propose(finding_id="F-001", diff="A", commit_message="x", applied=True)
    r.verify(p_success.patch_id, probe_fn=lambda: False, on_verified=cb)
    assert called == [p_success.patch_id]

    p_regress = r.propose(finding_id="F-002", diff="B", commit_message="y", applied=True)
    r.verify(p_regress.patch_id, probe_fn=lambda: True, on_verified=cb)
    # cb NOT called for regression — list is unchanged.
    assert called == [p_success.patch_id]


def test_on_verified_callback_exception_does_not_unverify_patch() -> None:
    """If the §4 pipeline callback raises, the patch must STAY
    verified — the callback is a side-effect, not a precondition."""
    r = patcher.get_registry()
    p = r.propose(finding_id="F-001", diff="d", commit_message="x", applied=True)

    def _boom_callback(_proposal: patcher.PatchProposal) -> None:
        raise RuntimeError("§4 advance broken")

    ok, _, proposal = r.verify(
        p.patch_id, probe_fn=lambda: False, on_verified=_boom_callback,
    )
    assert ok is True
    assert proposal is not None
    assert proposal.status == "verified"  # not un-verified


# ---------------------------------------------------------------------------
# §4 pipeline integration
# ---------------------------------------------------------------------------


def test_advance_finding_to_patched_advances_pipeline() -> None:
    """End-to-end: a finding moves SCANNED→...→VERIFIED→EXPLOITED,
    a patch is proposed + verified, and the finding auto-advances
    to PATCHED."""
    pipeline = vp.get_pipeline()
    pipeline.register(finding_id="F-001", severity="medium")
    pipeline.advance("F-001", target_stage="DETECTED")
    pipeline.advance("F-001", target_stage="VERIFYING")
    pipeline.record_evidence(
        "F-001",
        method="payload_response", outcome="PASSED", tool="x",
    )
    pipeline.advance("F-001", target_stage="VERIFIED")
    pipeline.advance("F-001", target_stage="EXPLOITED")

    r = patcher.get_registry()
    p = r.propose(finding_id="F-001", diff="d", commit_message="fix", applied=True)
    ok, _, _ = r.verify(
        p.patch_id,
        probe_fn=lambda: False,
        on_verified=patcher.advance_finding_to_patched,
    )
    assert ok is True
    rec = pipeline.get("F-001")
    assert rec is not None
    assert rec.stage == "PATCHED"


def test_advance_finding_to_patched_unknown_finding_is_silent() -> None:
    """When the linked finding isn't registered with §4 pipeline,
    `advance_finding_to_patched` no-ops without raising."""
    r = patcher.get_registry()
    p = r.propose(
        finding_id="F-NEVER-REGISTERED",
        diff="d", commit_message="x", applied=True,
    )
    ok, _, _ = r.verify(
        p.patch_id,
        probe_fn=lambda: False,
        on_verified=patcher.advance_finding_to_patched,
    )
    assert ok is True  # patch still verified despite the no-op


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


def test_list_patches_by_status() -> None:
    r = patcher.get_registry()
    p_a = r.propose(finding_id="F-001", diff="A", commit_message="x", applied=True)
    p_b = r.propose(finding_id="F-002", diff="B", commit_message="y", applied=True)
    r.verify(p_a.patch_id, probe_fn=lambda: False)
    r.verify(p_b.patch_id, probe_fn=lambda: True)
    assert len(r.list_patches(status="verified")) == 1
    assert len(r.list_patches(status="regressed")) == 1


def test_list_patches_by_finding_id() -> None:
    r = patcher.get_registry()
    r.propose(finding_id="F-001", diff="A", commit_message="x")
    r.propose(finding_id="F-002", diff="B", commit_message="y")
    r.propose(finding_id="F-001", diff="C", commit_message="z")
    f1 = r.list_patches(finding_id="F-001")
    assert len(f1) == 2


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_persistence_writes_jsonl(tmp_path: Path) -> None:
    r = patcher.get_registry()
    p = r.propose(finding_id="F-001", diff="d", commit_message="x")
    r.mark_applied(p.patch_id)
    r.verify(p.patch_id, probe_fn=lambda: False)

    log = tmp_path / "patches.jsonl"
    assert log.exists()
    records = [json.loads(line) for line in log.read_text().splitlines() if line]
    events = [r["event"] for r in records]
    assert "proposed" in events
    assert "applied" in events
    assert "verified" in events


def test_persistence_disabled_skips_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setenv("STRIX_PATCHER_PERSIST", "0")
    r = patcher.get_registry()
    r.propose(finding_id="F-001", diff="d", commit_message="x")
    assert not (tmp_path / "patches.jsonl").exists()


def test_persistence_without_run_dir_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_RUN_DIR", raising=False)
    r = patcher.get_registry()
    r.propose(finding_id="F-001", diff="d", commit_message="x")  # must not raise


# ---------------------------------------------------------------------------
# Kill switch + telemetry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "True", "yes", "ON"])
def test_kill_switch_telemetry_shape(
    val: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_PATCHER_DISABLED", val)
    assert patcher.get_registry_stats() == {"enabled": False, "patches": 0}


def test_telemetry_breakdown_by_status() -> None:
    r = patcher.get_registry()
    p_ok = r.propose(finding_id="F-001", diff="A", commit_message="x", applied=True)
    p_bad = r.propose(finding_id="F-002", diff="B", commit_message="y", applied=True)
    r.verify(p_ok.patch_id, probe_fn=lambda: False)
    r.verify(p_bad.patch_id, probe_fn=lambda: True)
    stats = patcher.get_registry_stats()
    assert stats["enabled"] is True
    assert stats["patches"] == 2
    assert stats["status_counts"]["verified"] == 1
    assert stats["status_counts"]["regressed"] == 1
