"""Tests for the auto_verify_patch tool — closes the §4
EXPLOITED → PATCHED loop without manual probe re-runs.

Covers:
  * Unknown patch_id → success=False
  * Patch exists but KG has no Vuln node → manual fallback hint
  * Registered handler returns no_longer_fires → §4 advances to PATCHED
  * Registered handler returns still_fires → patch marked regressed
  * Registered handler returns indeterminate → manual fallback hint
  * Handler raises → indeterminate (defensive)
  * No handler registered for category → manual_verification_required
  * KG kill switch → manual fallback
  * End-to-end: propose → mark applied → auto_verify (no_longer_fires)
    → §4 finding lands on PATCHED
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from strix.agents import knowledge_graph as kg
from strix.agents import kg_emit
from strix.agents import patcher
from strix.agents import rerun_registry as rr
from strix.agents import verification_pipeline as vp
from strix.tools.workflow import patcher_tools


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    kg.reset_for_testing()
    kg_emit.reset_surface_cache_for_testing()
    patcher.reset_for_testing()
    vp.reset_for_testing()
    rr.reset_for_testing()
    rr._registered = False
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_PATCHER_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_VERIFICATION_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_RERUN_REGISTRY_DISABLED", raising=False)
    yield


def _emit_finding_to_kg(
    finding_id: str = "F-001",
    category: str = "sqli",
    cwe: str = "CWE-89",
    url: str = "https://app/api/login",
    param: str = "username",
) -> None:
    """Seed the KG with a Vuln+Surface+AFFECTS triple for the test."""
    kg_emit.record_finding_in_kg(
        finding_id=finding_id, url=url, param=param,
        cwe=cwe, severity="critical", category=category,
        method="GET", detection_kind="error", confidence=0.95,
    )


# ---------------------------------------------------------------------------
# Lookup failures
# ---------------------------------------------------------------------------


def test_unknown_patch_returns_not_found() -> None:
    r = patcher_tools.auto_verify_patch(patch_id="PATCH-nope")
    assert r["success"] is False
    assert "not found" in r["reason"]
    assert r["patch"] is None


def test_patch_exists_but_no_kg_vuln() -> None:
    """Patch was proposed for a finding that never landed in the KG.
    auto_verify falls back to manual."""
    p = patcher_tools.propose_patch(
        finding_id="F-FLOATING", diff="d", commit_message="x", applied=True,
    )
    r = patcher_tools.auto_verify_patch(patch_id=p["patch"]["patch_id"])
    assert r["success"] is False
    assert "no KG Vuln" in r["reason"]


def test_no_handler_for_category() -> None:
    """Vuln node exists but no rerun handler registered for its
    category. auto_verify reports manual_verification_required."""
    # Register a handler for sqli only.
    def sqli_only(*, finding_context: dict) -> rr.RerunResult:
        return rr.RerunResult(outcome="no_longer_fires")
    rr.register_rerun(category="sqli", cwe="CWE-89")(sqli_only)

    # Emit a finding in an unregistered category.
    _emit_finding_to_kg(category="exotic_class", cwe="CWE-XXX")
    p = patcher_tools.propose_patch(
        finding_id="F-001", diff="d", commit_message="x", applied=True,
    )

    # auto_verify should NOT use the sqli handler — it must reject.
    r = patcher_tools.auto_verify_patch(patch_id=p["patch"]["patch_id"])
    assert r["success"] is False
    assert "manual_verification_required" in r["reason"]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_no_longer_fires_advances_pipeline_to_patched() -> None:
    """End-to-end: registered handler returns `no_longer_fires` →
    verify_patch fires → §4 finding lands on PATCHED."""
    # Register handler.
    def fake_rerun(*, finding_context: dict) -> rr.RerunResult:
        return rr.RerunResult(
            outcome="no_longer_fires",
            detail="re-fire returned no SQL error fingerprint",
            elapsed_seconds=0.5,
        )
    rr.register_rerun(category="sqli", cwe="CWE-89")(fake_rerun)

    # Walk a finding all the way to EXPLOITED.
    pipeline = vp.get_pipeline()
    pipeline.register(finding_id="F-001", severity="high")
    pipeline.advance("F-001", target_stage="DETECTED")
    pipeline.advance("F-001", target_stage="VERIFYING")
    pipeline.record_evidence(
        "F-001",
        method="payload_response", outcome="PASSED", tool="scan_sqli",
    )
    pipeline.record_evidence(
        "F-001",
        method="timing", outcome="PASSED", tool="manual",
    )
    pipeline.advance("F-001", target_stage="VERIFIED")
    pipeline.advance("F-001", target_stage="EXPLOITED")

    # Populate KG + propose patch.
    _emit_finding_to_kg(finding_id="F-001")
    p = patcher_tools.propose_patch(
        finding_id="F-001",
        diff="--- a/sql.py\n+++ b/sql.py\n@@\n-bad\n+good\n",
        commit_message="fix(auth): parameterise login query",
        applied=True,
    )

    # auto_verify — should succeed.
    r = patcher_tools.auto_verify_patch(patch_id=p["patch"]["patch_id"])
    assert r["success"] is True
    assert r["rerun_outcome"] == "no_longer_fires"
    assert "no SQL error fingerprint" in r["rerun_detail"]

    # §4 should now have finding at PATCHED.
    rec = pipeline.get("F-001")
    assert rec is not None
    assert rec.stage == "PATCHED"


def test_still_fires_marks_regressed() -> None:
    def fake_rerun(*, finding_context: dict) -> rr.RerunResult:
        return rr.RerunResult(
            outcome="still_fires",
            detail="error fingerprint still present",
        )
    rr.register_rerun(category="sqli", cwe="CWE-89")(fake_rerun)

    _emit_finding_to_kg(finding_id="F-002")
    p = patcher_tools.propose_patch(
        finding_id="F-002", diff="d", commit_message="x", applied=True,
    )
    r = patcher_tools.auto_verify_patch(patch_id=p["patch"]["patch_id"])
    assert r["success"] is False
    assert r["rerun_outcome"] == "still_fires"
    assert r["patch"]["status"] == "regressed"


def test_indeterminate_does_not_change_pipeline() -> None:
    """An `indeterminate` rerun (network error, missing context, etc.)
    does NOT advance or regress the patch. The Patcher must fall
    back to manual `verify_patch`."""
    def fake_rerun(*, finding_context: dict) -> rr.RerunResult:
        return rr.RerunResult(
            outcome="indeterminate",
            detail="transport error during re-probe",
        )
    rr.register_rerun(category="sqli", cwe="CWE-89")(fake_rerun)

    _emit_finding_to_kg(finding_id="F-003")
    p = patcher_tools.propose_patch(
        finding_id="F-003", diff="d", commit_message="x", applied=True,
    )
    r = patcher_tools.auto_verify_patch(patch_id=p["patch"]["patch_id"])
    assert r["success"] is False
    assert r["rerun_outcome"] == "indeterminate"
    assert r["patch"]["status"] == "proposed"  # NOT regressed
    assert "manual" in r["reason"].lower()


def test_handler_raising_treated_as_indeterminate() -> None:
    """If the rerun handler raises, auto_verify must treat it as
    indeterminate, NOT silently mark the patch verified."""
    def bad_rerun(*, finding_context: dict) -> rr.RerunResult:
        raise RuntimeError("handler exploded")
    rr.register_rerun(category="sqli", cwe="CWE-89")(bad_rerun)

    _emit_finding_to_kg(finding_id="F-004")
    p = patcher_tools.propose_patch(
        finding_id="F-004", diff="d", commit_message="x", applied=True,
    )
    r = patcher_tools.auto_verify_patch(patch_id=p["patch"]["patch_id"])
    assert r["success"] is False
    assert r["rerun_outcome"] == "indeterminate"
    assert "RuntimeError" in r["reason"]
    assert r["patch"]["status"] == "proposed"


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def test_registry_kill_switch_forces_manual(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_rerun(*, finding_context: dict) -> rr.RerunResult:
        return rr.RerunResult(outcome="no_longer_fires")
    rr.register_rerun(category="sqli", cwe="CWE-89")(fake_rerun)
    monkeypatch.setenv("STRIX_RERUN_REGISTRY_DISABLED", "1")

    _emit_finding_to_kg(finding_id="F-005")
    p = patcher_tools.propose_patch(
        finding_id="F-005", diff="d", commit_message="x", applied=True,
    )
    r = patcher_tools.auto_verify_patch(patch_id=p["patch"]["patch_id"])
    assert r["success"] is False
    assert "manual_verification_required" in r["reason"]


# ---------------------------------------------------------------------------
# Finding context propagation
# ---------------------------------------------------------------------------


def test_handler_receives_url_and_param_from_kg_surface() -> None:
    """The rerun handler gets `url`, `param`, `method` from the
    KG Surface neighbour (plus all Vuln props)."""
    captured: dict = {}

    def capture_handler(*, finding_context: dict) -> rr.RerunResult:
        captured.update(finding_context)
        return rr.RerunResult(outcome="no_longer_fires")

    rr.register_rerun(category="sqli", cwe="CWE-89")(capture_handler)

    _emit_finding_to_kg(
        finding_id="F-006",
        url="https://app/api/users",
        param="email",
    )
    p = patcher_tools.propose_patch(
        finding_id="F-006", diff="d", commit_message="x", applied=True,
    )
    patcher_tools.auto_verify_patch(patch_id=p["patch"]["patch_id"])

    assert captured["url"] == "https://app/api/users"
    assert captured["param"] == "email"
    assert captured["method"] == "GET"
    assert captured["cwe"] == "CWE-89"
    assert captured["category"] == "sqli"
    assert captured["detection_kind"] == "error"
    assert captured["finding_id"] == "F-006"
