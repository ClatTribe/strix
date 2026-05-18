"""Tests for `dispatch_specialist_batch` — step 3 of the v2
cost-optimization plan (workflow phase 4 — specialist dispatch).

Discipline:
  * Each per-target completion lands in `batch_results`
    individually — recall is preserved per endpoint.
  * Batched dispatch counts as ONE call against the scan-mode
    counter (the cost win).
  * Verdict-cache integration is symmetric with single dispatch:
    PASSED never caches, BLOCKED + no-signal reason caches.
  * Cache HITS pre-filter objectives without consuming the
    scan-mode counter.
  * Targets that never receive a per-target completion land as
    ITERATION_CAP_REACHED so the lead can re-dispatch.
  * Empty / duplicate objectives are normalized away.

The inner LLM call is mocked via `inner_call_fn` so the loop
runs deterministically without real LLM cost.
"""

from __future__ import annotations

import pytest

from strix.agents import specialist_orchestrator as so
from strix.agents import specialist_verdict_cache as vc


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
# Helpers — inner_call_fn stubs that drive the batch loop deterministically
# ---------------------------------------------------------------------------


def _completer(verdicts: dict[str, dict[str, str]]):
    """Build an inner_call_fn that emits one
    `complete_objective(target=...)` call per iteration, in the
    order keys appear in `verdicts`.

    `verdicts` maps target -> {status, reason, summary}.
    """
    keys = list(verdicts.keys())

    def call(*, history, iteration, profile, pending_targets, **_):
        if iteration >= len(keys):
            return {"message": "(no-op)", "tool_calls": [], "cost_usd": 0.0}
        tgt = keys[iteration]
        return {
            "message": f"Completing {tgt}",
            "tool_calls": [{
                "tool": "complete_objective",
                "args": {
                    "target": tgt,
                    **verdicts[tgt],
                },
            }],
            "cost_usd": 0.001,
        }

    return call


def _never_completes(*, history, iteration, profile, pending_targets, **_):
    """Inner-LLM stub that never calls complete_objective."""
    return {"message": "thinking", "tool_calls": [], "cost_usd": 0.001}


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_batch_rejects_empty_category() -> None:
    r = so.dispatch_specialist_batch(
        category="",
        objectives=[{"target": "/x", "objective": "y"}],
        inner_call_fn=_completer({}),
    )
    assert r["error"] == "category required"
    assert r["batch_results"] == []


def test_batch_rejects_empty_objectives() -> None:
    r = so.dispatch_specialist_batch(
        category="sqli", objectives=[],
        inner_call_fn=_completer({}),
    )
    assert "non-empty list" in r["error"]


def test_batch_skips_objectives_missing_target_or_text() -> None:
    """Invalid entries get filtered; valid ones still run."""
    r = so.dispatch_specialist_batch(
        category="sqli",
        objectives=[
            {"target": "", "objective": "x"},
            {"target": "/x", "objective": ""},
            {"target": "/y", "objective": "probe y"},
        ],
        inner_call_fn=_completer({
            "/y": {"status": "PASSED", "reason": "ok"},
        }),
    )
    assert r.get("error") is None
    assert len(r["batch_results"]) == 1
    assert r["batch_results"][0]["status"] == "PASSED"


def test_batch_deduplicates_objectives_by_target() -> None:
    r = so.dispatch_specialist_batch(
        category="sqli",
        objectives=[
            {"target": "/api/users/42", "objective": "first"},
            {"target": "/api/users/42", "objective": "second"},
        ],
        inner_call_fn=_completer({
            "/api/users/42": {"status": "PASSED", "reason": "ok"},
        }),
    )
    assert len(r["batch_results"]) == 1


# ---------------------------------------------------------------------------
# Happy path — every target completes
# ---------------------------------------------------------------------------


def test_batch_all_targets_complete() -> None:
    """Three objectives, each signaled in sequence. Every
    target ends up in batch_results with the correct status."""
    r = so.dispatch_specialist_batch(
        category="sqli",
        objectives=[
            {"target": "/a", "objective": "probe a"},
            {"target": "/b", "objective": "probe b"},
            {"target": "/c", "objective": "probe c"},
        ],
        inner_call_fn=_completer({
            "/a": {"status": "PASSED", "reason": "ok-a"},
            "/b": {"status": "BLOCKED", "reason": "no SQL backend"},
            "/c": {"status": "PASSED", "reason": "ok-c"},
        }),
    )
    assert r["dispatched"] == 1
    assert r["cache_hits"] == 0
    by_status = sorted(
        (br["status"], br["reason"]) for br in r["batch_results"]
    )
    assert by_status == [
        ("BLOCKED", "no SQL backend"),
        ("PASSED", "ok-a"),
        ("PASSED", "ok-c"),
    ]


def test_batch_loop_exits_early_when_all_done() -> None:
    """Loop should not run more iterations than necessary —
    exits as soon as every target has a signal."""
    r = so.dispatch_specialist_batch(
        category="sqli",
        objectives=[
            {"target": "/a", "objective": "probe a"},
            {"target": "/b", "objective": "probe b"},
        ],
        max_iterations=50,  # generous cap
        inner_call_fn=_completer({
            "/a": {"status": "PASSED", "reason": "ok"},
            "/b": {"status": "PASSED", "reason": "ok"},
        }),
    )
    # Exits when both signaled — should be 2 iterations.
    assert r["iterations_used"] == 2


# ---------------------------------------------------------------------------
# Partial completion → ITERATION_CAP_REACHED
# ---------------------------------------------------------------------------


def test_batch_partial_completion_marks_remaining_iteration_cap() -> None:
    """Two of three targets complete, third gets ITERATION_CAP_REACHED
    so the lead knows it needs re-dispatch."""
    r = so.dispatch_specialist_batch(
        category="sqli",
        max_iterations=2,  # only 2 iterations
        objectives=[
            {"target": "/a", "objective": "probe a"},
            {"target": "/b", "objective": "probe b"},
            {"target": "/c", "objective": "probe c"},
        ],
        inner_call_fn=_completer({
            "/a": {"status": "PASSED", "reason": "ok"},
            "/b": {"status": "PASSED", "reason": "ok"},
            "/c": {"status": "PASSED", "reason": "ok"},
        }),
    )
    statuses = {br["status"] for br in r["batch_results"]}
    assert "ITERATION_CAP_REACHED" in statuses
    # The completed ones still show PASSED
    assert "PASSED" in statuses


def test_batch_never_completes_marks_all_iteration_cap() -> None:
    r = so.dispatch_specialist_batch(
        category="sqli",
        max_iterations=3,
        objectives=[{"target": "/a", "objective": "probe"}],
        inner_call_fn=_never_completes,
    )
    assert len(r["batch_results"]) == 1
    assert r["batch_results"][0]["status"] == "ITERATION_CAP_REACHED"


# ---------------------------------------------------------------------------
# Scan-mode counter — batch counts as ONE dispatch
# ---------------------------------------------------------------------------


def test_batch_counts_as_one_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 5-objective batch on `standard` mode should consume
    only 1 of the 8-dispatch budget."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "standard")
    so.dispatch_specialist_batch(
        category="sqli",
        objectives=[
            {"target": f"/api/users/{i}", "objective": "probe"}
            for i in range(5)
        ],
        inner_call_fn=_completer({
            f"/api/users/{i}": {"status": "PASSED", "reason": "ok"}
            for i in range(5)
        }),
    )
    assert so.get_dispatch_count() == 1


def test_batch_denied_when_scan_mode_cap_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If scan-mode cap is already exhausted, the batch is denied
    wholesale — every objective gets DENIED_BY_SCAN_MODE."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "quick")  # cap=0
    r = so.dispatch_specialist_batch(
        category="sqli",
        objectives=[
            {"target": "/a", "objective": "probe"},
            {"target": "/b", "objective": "probe"},
        ],
        inner_call_fn=_completer({}),
    )
    assert r["dispatched"] == 0
    statuses = {br["status"] for br in r["batch_results"]}
    assert statuses == {"DENIED_BY_SCAN_MODE"}


# ---------------------------------------------------------------------------
# Verdict-cache integration
# ---------------------------------------------------------------------------


def test_batch_cache_hits_pre_filter_without_dispatch() -> None:
    """Seed the cache with a no-signal BLOCKED on /api/users/{id}.
    A batch containing similar targets should pre-filter all of
    them — no LLM call, no scan-mode counter consumption."""
    # Seed cache
    vc.record(
        category="sqli", endpoint="/api/users/42", auth_state=None,
        status="BLOCKED", reason="no SQL backend",
        objective="seed",
    )
    r = so.dispatch_specialist_batch(
        category="sqli",
        objectives=[
            {"target": "/api/users/99", "objective": "probe"},
            {"target": "/api/users/100", "objective": "probe"},
        ],
        inner_call_fn=_never_completes,
    )
    assert r["dispatched"] == 0
    assert r["cache_hits"] == 2
    statuses = {br["status"] for br in r["batch_results"]}
    assert statuses == {"CACHE_HIT_BLOCKED"}
    # Scan-mode counter should not have moved.
    assert so.get_dispatch_count() == 0


def test_batch_partial_cache_hits_dispatch_remainder() -> None:
    """Some objectives cached, others fresh. Cached ones don't
    enter the loop; the loop probes only the uncached subset."""
    vc.record(
        category="sqli", endpoint="/api/users/42", auth_state=None,
        status="BLOCKED", reason="no SQL backend",
        objective="seed",
    )
    r = so.dispatch_specialist_batch(
        category="sqli",
        objectives=[
            {"target": "/api/users/99", "objective": "probe cached"},
            {"target": "/api/orders/12", "objective": "probe fresh"},
        ],
        inner_call_fn=_completer({
            "/api/orders/12": {"status": "PASSED", "reason": "ok"},
        }),
    )
    assert r["dispatched"] == 1
    assert r["cache_hits"] == 1
    statuses = sorted(br["status"] for br in r["batch_results"])
    assert statuses == ["CACHE_HIT_BLOCKED", "PASSED"]


def test_batch_records_blocked_no_signal_in_cache() -> None:
    """A batch that returns BLOCKED with a no-signal reason
    populates the verdict cache for the per-target shape — same
    semantics as single dispatch."""
    so.dispatch_specialist_batch(
        category="sqli",
        objectives=[
            {"target": "/api/products/1", "objective": "probe"},
        ],
        inner_call_fn=_completer({
            "/api/products/1": {
                "status": "BLOCKED",
                "reason": "no SQL backend on /api/products",
            },
        }),
    )
    # A follow-up single dispatch on similar shape should hit cache
    cached = vc.should_skip(
        category="sqli",
        endpoint="/api/products/99",
        auth_state=None,
    )
    assert cached is not None


def test_batch_does_not_cache_passed_results() -> None:
    """Critical recall safeguard — PASSED in batch mode must not
    cache, otherwise a successful exploit on /api/products/1
    would suppress dispatch on /api/products/99."""
    so.dispatch_specialist_batch(
        category="sqli",
        objectives=[
            {"target": "/api/products/1", "objective": "probe"},
        ],
        inner_call_fn=_completer({
            "/api/products/1": {"status": "PASSED", "reason": "ok"},
        }),
    )
    cached = vc.should_skip(
        category="sqli",
        endpoint="/api/products/99",
        auth_state=None,
    )
    assert cached is None


# ---------------------------------------------------------------------------
# complete_objective(target=...) backwards compat
# ---------------------------------------------------------------------------


def test_complete_objective_without_target_still_single_dispatch_signal() -> None:
    """The `target=None` default preserves single-dispatch
    behaviour: signal lands in `_SPECIALIST_EXIT`, not the
    batch state."""
    so.signal_specialist_complete(status="PASSED", reason="ok")
    sig = so.get_specialist_exit_signal()
    assert sig is not None
    assert sig["status"] == "PASSED"
    assert so.list_batch_exit_signals() == {}


def test_complete_objective_with_target_lands_in_batch_state() -> None:
    so.signal_specialist_complete(
        status="PASSED", reason="ok", target="/a",
    )
    assert so.get_specialist_exit_signal() is None
    sigs = so.list_batch_exit_signals()
    assert "/a" in sigs
    assert sigs["/a"]["status"] == "PASSED"


def test_pop_batch_exit_signal_clears_state() -> None:
    so.signal_specialist_complete(
        status="PASSED", reason="ok", target="/a",
    )
    popped = so.pop_batch_exit_signal("/a")
    assert popped is not None
    assert so.pop_batch_exit_signal("/a") is None  # already popped


# ---------------------------------------------------------------------------
# reset_for_testing clears batch state
# ---------------------------------------------------------------------------


def test_reset_clears_batch_state() -> None:
    so.signal_specialist_complete(
        status="PASSED", reason="ok", target="/a",
    )
    so.signal_specialist_complete(
        status="BLOCKED", reason="x", target="/b",
    )
    assert len(so.list_batch_exit_signals()) == 2
    so.reset_for_testing()
    assert so.list_batch_exit_signals() == {}
