"""Tests for v2 step 4 — structured specialist result + skip-lead-think.

The dispatched specialist's `complete_objective` accepts two new
optional kwargs:
  * `next_suggested_dispatch` — `{category, objective, target}` dict
    proposing the lead's next move
  * `blocks` — list of short noun phrases naming unmet preconditions

These fields land in `SpecialistRunResult.to_dict()` alongside an
`interesting` flag (derived) that the lead uses to decide whether to
deliberate or auto-advance.

Recall-safety contract pinned by tests:
  * Backwards compat: omitting the new args yields the same shape
    plus the new fields with empty / null defaults.
  * Malformed `next_suggested_dispatch` is silently rejected
    (returns None) — a buggy specialist response NEVER crashes
    the loop.
  * `interesting=True` always when findings_count > 0 (recall-
    critical: never auto-advance past a finding).
  * `interesting=True` when blocks present OR status==ERROR.
  * Single-dispatch + batch dispatch both propagate the fields.
"""

from __future__ import annotations

import pytest

from strix.agents import specialist_orchestrator as so


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_ORCHESTRATOR_MODE", raising=False)
    monkeypatch.delenv("STRIX_SPECIALIST_MAX_ITERATIONS", raising=False)
    monkeypatch.delenv("STRIX_SCAN_MODE", raising=False)
    monkeypatch.delenv("STRIX_DISPATCH_CAP_OVERRIDE", raising=False)
    monkeypatch.delenv("STRIX_VERDICT_CACHE_DISABLED", raising=False)
    so.reset_for_testing()
    yield
    so.reset_for_testing()


# ---------------------------------------------------------------------------
# Normalizer behaviour (pure functions; cheap to test exhaustively)
# ---------------------------------------------------------------------------


def test_normalize_suggested_dispatch_accepts_valid_dict() -> None:
    out = so._normalize_suggested_dispatch({
        "category": "IDOR",
        "objective": "verify cross-tenant access on /api/orders/{id}",
        "target": "https://crapi.local/api/orders/12",
    })
    assert out == {
        "category": "idor",
        "objective": "verify cross-tenant access on /api/orders/{id}",
        "target": "https://crapi.local/api/orders/12",
    }


def test_normalize_suggested_dispatch_accepts_dict_without_target() -> None:
    out = so._normalize_suggested_dispatch({
        "category": "xss",
        "objective": "probe reflected XSS on /search",
    })
    assert out == {"category": "xss", "objective": "probe reflected XSS on /search"}


def test_normalize_suggested_dispatch_rejects_missing_fields() -> None:
    assert so._normalize_suggested_dispatch({"category": "xss"}) is None
    assert so._normalize_suggested_dispatch({"objective": "probe"}) is None
    assert so._normalize_suggested_dispatch({"category": "", "objective": ""}) is None


def test_normalize_suggested_dispatch_rejects_non_dict() -> None:
    assert so._normalize_suggested_dispatch(None) is None
    assert so._normalize_suggested_dispatch("not a dict") is None
    assert so._normalize_suggested_dispatch(["a", "b"]) is None
    assert so._normalize_suggested_dispatch(42) is None


def test_normalize_blocks_handles_list_dedupe_and_trim() -> None:
    out = so._normalize_blocks(["  needs admin auth  ", "needs admin auth", "needs SAML"])
    assert out == ["needs admin auth", "needs SAML"]


def test_normalize_blocks_accepts_single_string() -> None:
    assert so._normalize_blocks("needs admin auth") == ["needs admin auth"]


def test_normalize_blocks_returns_empty_for_none_or_garbage() -> None:
    assert so._normalize_blocks(None) == []
    assert so._normalize_blocks([]) == []
    assert so._normalize_blocks({"not": "a list"}) == []
    assert so._normalize_blocks([None, 42, ""]) == []


# ---------------------------------------------------------------------------
# SpecialistRunResult.is_interesting + to_dict
# ---------------------------------------------------------------------------


def test_result_with_findings_is_interesting() -> None:
    r = so.SpecialistRunResult(
        category="sqli", objective="probe", status="PASSED",
        findings_count=1,
    )
    assert r.is_interesting() is True
    assert r.to_dict()["interesting"] is True


def test_result_with_blocks_is_interesting() -> None:
    r = so.SpecialistRunResult(
        category="sqli", objective="probe", status="BLOCKED",
        findings_count=0, blocks=["needs admin auth"],
    )
    assert r.is_interesting() is True


def test_result_with_error_is_interesting() -> None:
    r = so.SpecialistRunResult(
        category="sqli", objective="probe", status="ERROR",
        reason="LLM timeout",
    )
    assert r.is_interesting() is True


def test_result_passed_no_findings_is_boring() -> None:
    r = so.SpecialistRunResult(
        category="sqli", objective="probe", status="PASSED",
        findings_count=0,
    )
    assert r.is_interesting() is False


def test_result_blocked_clean_is_boring() -> None:
    r = so.SpecialistRunResult(
        category="sqli", objective="probe", status="BLOCKED",
        reason="no SQL backend", findings_count=0,
    )
    assert r.is_interesting() is False


def test_result_cache_hit_is_boring() -> None:
    r = so.SpecialistRunResult(
        category="sqli", objective="probe", status="CACHE_HIT_BLOCKED",
        reason="cache",
    )
    assert r.is_interesting() is False


def test_result_denied_by_scan_mode_is_boring() -> None:
    r = so.SpecialistRunResult(
        category="sqli", objective="probe", status="DENIED_BY_SCAN_MODE",
        reason="cap",
    )
    assert r.is_interesting() is False


def test_to_dict_includes_all_new_fields() -> None:
    r = so.SpecialistRunResult(
        category="sqli", objective="probe", status="BLOCKED",
        reason="no SQL backend",
        next_suggested_dispatch={"category": "idor", "objective": "x"},
        blocks=["needs admin auth"],
    )
    d = r.to_dict()
    assert d["next_suggested_dispatch"] == {"category": "idor", "objective": "x"}
    assert d["blocks"] == ["needs admin auth"]
    assert d["interesting"] is True  # blocks present


def test_to_dict_defaults_for_backward_compat() -> None:
    r = so.SpecialistRunResult(
        category="sqli", objective="probe", status="PASSED",
    )
    d = r.to_dict()
    assert d["next_suggested_dispatch"] is None
    assert d["blocks"] == []
    assert d["interesting"] is False


# ---------------------------------------------------------------------------
# signal_specialist_complete propagation (single dispatch)
# ---------------------------------------------------------------------------


def test_signal_with_structured_fields_lands_in_single_exit() -> None:
    so.signal_specialist_complete(
        status="BLOCKED",
        reason="no SQL backend",
        next_suggested_dispatch={
            "category": "idor",
            "objective": "probe IDOR on same surface",
        },
        blocks=["needs admin auth"],
    )
    sig = so.get_specialist_exit_signal()
    assert sig is not None
    assert sig["next_suggested_dispatch"] == {
        "category": "idor",
        "objective": "probe IDOR on same surface",
    }
    assert sig["blocks"] == ["needs admin auth"]


def test_signal_without_structured_fields_still_works() -> None:
    """Backwards compat: callers that don't pass the new kwargs
    still get a well-formed signal."""
    so.signal_specialist_complete(status="PASSED", reason="ok")
    sig = so.get_specialist_exit_signal()
    assert sig is not None
    assert sig["next_suggested_dispatch"] is None
    assert sig["blocks"] == []


def test_signal_with_malformed_suggestion_silently_drops_it() -> None:
    """A buggy specialist response (non-dict suggestion) MUST NOT
    crash the loop — the field just becomes None."""
    so.signal_specialist_complete(
        status="PASSED",
        next_suggested_dispatch="not a dict",
        blocks=42,
    )
    sig = so.get_specialist_exit_signal()
    assert sig is not None
    assert sig["next_suggested_dispatch"] is None
    assert sig["blocks"] == []


# ---------------------------------------------------------------------------
# End-to-end: dispatch_specialist propagates fields into result
# ---------------------------------------------------------------------------


def _fake_blocked_with_handoff_call(*, history, iteration, profile, **_):
    """Inner-LLM stub that returns BLOCKED + a next_suggested_dispatch."""
    return {
        "message": "BLOCKED with handoff.",
        "tool_calls": [{
            "tool": "complete_objective",
            "args": {
                "status": "BLOCKED",
                "reason": "no SQL backend on this surface",
                "summary": "ORM-only stack",
                "next_suggested_dispatch": {
                    "category": "idor",
                    "objective": "probe IDOR on /api/users/{id}",
                    "target": "https://vampi.local/api/users/42",
                },
                "blocks": ["needs admin auth state"],
            },
        }],
        "cost_usd": 0.001,
    }


def test_single_dispatch_propagates_handoff_into_result() -> None:
    r = so.dispatch_specialist(
        category="sqli", objective="probe SQLi on /api/users/42",
        target="https://vampi.local/api/users/42",
        inner_call_fn=_fake_blocked_with_handoff_call,
    )
    assert r["status"] == "BLOCKED"
    assert r["next_suggested_dispatch"] == {
        "category": "idor",
        "objective": "probe IDOR on /api/users/{id}",
        "target": "https://vampi.local/api/users/42",
    }
    assert r["blocks"] == ["needs admin auth state"]
    # blocks present → interesting=True even though findings_count==0
    assert r["interesting"] is True


def _fake_passed_no_finding_call(*, history, iteration, profile, **_):
    return {
        "message": "Done.",
        "tool_calls": [{
            "tool": "complete_objective",
            "args": {"status": "PASSED", "reason": "no SQL backend, ORM only"},
        }],
        "cost_usd": 0.001,
    }


def test_single_dispatch_passed_no_finding_is_boring() -> None:
    r = so.dispatch_specialist(
        category="sqli", objective="probe",
        target="https://vampi.local/api/users/42",
        inner_call_fn=_fake_passed_no_finding_call,
    )
    assert r["status"] == "PASSED"
    assert r["findings_count"] == 0
    assert r["interesting"] is False
    assert r["next_suggested_dispatch"] is None
    assert r["blocks"] == []


# ---------------------------------------------------------------------------
# End-to-end: batched dispatch propagates fields per-target
# ---------------------------------------------------------------------------


def _per_target_handoff_completer(target_handoffs: dict[str, dict]):
    """Build an inner_call_fn that emits per-target completions
    with structured handoff data."""
    keys = list(target_handoffs.keys())

    def call(*, history, iteration, profile, pending_targets, **_):
        if iteration >= len(keys):
            return {"message": "(no-op)", "tool_calls": [], "cost_usd": 0.0}
        tgt = keys[iteration]
        return {
            "message": f"Completing {tgt}",
            "tool_calls": [{
                "tool": "complete_objective",
                "args": {"target": tgt, **target_handoffs[tgt]},
            }],
            "cost_usd": 0.001,
        }

    return call


def test_batch_propagates_per_target_structured_fields() -> None:
    handoffs = {
        "/a": {
            "status": "BLOCKED",
            "reason": "no SQL backend",
            "next_suggested_dispatch": {
                "category": "idor", "objective": "probe a as IDOR",
            },
            "blocks": [],
        },
        "/b": {
            "status": "PASSED",
            "reason": "no SQL backend",
            "next_suggested_dispatch": None,
            "blocks": ["needs second tenant"],
        },
    }
    r = so.dispatch_specialist_batch(
        category="sqli",
        objectives=[
            {"target": "/a", "objective": "probe a"},
            {"target": "/b", "objective": "probe b"},
        ],
        inner_call_fn=_per_target_handoff_completer(handoffs),
    )
    by_obj = {br["objective"]: br for br in r["batch_results"]}
    assert by_obj["probe a"]["next_suggested_dispatch"] == {
        "category": "idor", "objective": "probe a as IDOR",
    }
    assert by_obj["probe a"]["blocks"] == []
    # /a has handoff but no blocks → not interesting (no findings,
    # no blocks, status BLOCKED). Lead takes next_suggested_dispatch.
    assert by_obj["probe a"]["interesting"] is False
    # /b has blocks → interesting=True even with PASSED
    assert by_obj["probe b"]["blocks"] == ["needs second tenant"]
    assert by_obj["probe b"]["interesting"] is True


def test_batch_handles_targets_without_handoff() -> None:
    """Specialists that don't fill the structured fields still
    produce a well-formed result — backwards-compat."""
    handoffs = {
        "/a": {"status": "PASSED", "reason": "ok"},
    }
    r = so.dispatch_specialist_batch(
        category="sqli",
        objectives=[{"target": "/a", "objective": "probe"}],
        inner_call_fn=_per_target_handoff_completer(handoffs),
    )
    assert len(r["batch_results"]) == 1
    br = r["batch_results"][0]
    assert br["next_suggested_dispatch"] is None
    assert br["blocks"] == []
    assert br["interesting"] is False


# ---------------------------------------------------------------------------
# Recall-safety canary: a finding ALWAYS marks the result interesting
# ---------------------------------------------------------------------------


def test_recall_canary_finding_always_interesting() -> None:
    """If the specialist emitted a finding, the result MUST be
    interesting regardless of what else is in it — the lead must
    deliberate to chain off the finding."""
    r = so.SpecialistRunResult(
        category="sqli", objective="probe", status="PASSED",
        findings_count=1,
        next_suggested_dispatch=None,
        blocks=[],
    )
    assert r.is_interesting() is True, (
        "recall canary: a finding emitted must mark the result "
        "interesting so the lead deliberates. Auto-advancing past "
        "a finding is a recall regression."
    )
