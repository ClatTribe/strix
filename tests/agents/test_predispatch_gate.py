"""Tests for `strix/agents/predispatch_gate.py` — step 6 of the
v2 cost-optimization plan (workflow phase 4 — specialist dispatch).

Recall-safety contract pinned by tests:
  * The gate can ONLY short-circuit when a prober returns FOUND.
    UNCERTAIN / NOT_APPLICABLE / error always fall through to
    LLM dispatch.
  * A buggy prober (raises, returns wrong type) never blocks
    dispatch — it falls through to UNCERTAIN.
  * Categories without a registered prober pass through unchanged.
  * Kill switch (`STRIX_PREDISPATCH_GATE_DISABLED=1`) bypasses
    the gate entirely.
  * Successful pre-probe (FOUND) does NOT consume the scan-mode
    dispatch counter — that budget is preserved for harder cases.
"""

from __future__ import annotations

import pytest

from strix.agents import predispatch_gate as pg
from strix.agents import specialist_orchestrator as so


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_PREDISPATCH_GATE_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_SCAN_MODE", raising=False)
    monkeypatch.delenv("STRIX_DISPATCH_CAP_OVERRIDE", raising=False)
    monkeypatch.delenv("STRIX_VERDICT_CACHE_DISABLED", raising=False)
    # Snapshot + restore the registry so tests can register their
    # own probers without polluting one another.
    saved = dict(pg._PROBERS)
    so.reset_for_testing()
    yield
    pg._PROBERS.clear()
    pg._PROBERS.update(saved)
    so.reset_for_testing()


# ---------------------------------------------------------------------------
# Registry + try_short_circuit basics
# ---------------------------------------------------------------------------


def test_no_prober_registered_falls_through() -> None:
    pg._PROBERS.pop("never-heard-of", None)
    r = pg.try_short_circuit(
        category="never-heard-of",
        target="https://example.com",
        objective="probe",
    )
    assert r.verdict == "NOT_APPLICABLE"
    assert "no prober" in r.reason.lower()


def test_no_target_falls_through() -> None:
    @pg.register_prober("xtest-no-target")
    def _p(target: str, objective: str) -> pg.ProbeResult:
        return pg.ProbeResult(verdict="FOUND", summary="should not fire")

    r = pg.try_short_circuit(
        category="xtest-no-target",
        target=None,
        objective="probe",
    )
    assert r.verdict == "NOT_APPLICABLE"
    assert "no target" in r.reason.lower()


def test_kill_switch_short_circuits_to_not_applicable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @pg.register_prober("xtest-kill")
    def _p(target: str, objective: str) -> pg.ProbeResult:
        return pg.ProbeResult(
            verdict="FOUND", findings_count=1, summary="found!",
        )

    monkeypatch.setenv("STRIX_PREDISPATCH_GATE_DISABLED", "1")
    r = pg.try_short_circuit(
        category="xtest-kill",
        target="https://example.com",
        objective="probe",
    )
    assert r.verdict == "NOT_APPLICABLE"
    assert "disabled" in r.reason.lower()


def test_prober_found_propagates_summary_and_count() -> None:
    @pg.register_prober("xtest-found")
    def _p(target: str, objective: str) -> pg.ProbeResult:
        return pg.ProbeResult(
            verdict="FOUND",
            findings_count=2,
            summary="confirmed 2 things",
        )

    r = pg.try_short_circuit(
        category="xtest-found",
        target="https://example.com",
        objective="probe",
    )
    assert r.verdict == "FOUND"
    assert r.findings_count == 2
    assert r.summary == "confirmed 2 things"


def test_prober_uncertain_falls_through() -> None:
    @pg.register_prober("xtest-uncertain")
    def _p(target: str, objective: str) -> pg.ProbeResult:
        return pg.ProbeResult(
            verdict="UNCERTAIN", reason="nothing confirmed",
        )

    r = pg.try_short_circuit(
        category="xtest-uncertain",
        target="https://example.com",
        objective="probe",
    )
    assert r.verdict == "UNCERTAIN"


# ---------------------------------------------------------------------------
# Recall-safety: buggy probers never block dispatch
# ---------------------------------------------------------------------------


def test_prober_raising_falls_through_to_uncertain() -> None:
    @pg.register_prober("xtest-raise")
    def _p(target: str, objective: str) -> pg.ProbeResult:
        raise RuntimeError("boom")

    r = pg.try_short_circuit(
        category="xtest-raise",
        target="https://example.com",
        objective="probe",
    )
    assert r.verdict == "UNCERTAIN"
    assert "boom" in r.reason


def test_prober_returning_wrong_type_falls_through() -> None:
    @pg.register_prober("xtest-wrong-type")
    def _p(target: str, objective: str):  # type: ignore[no-untyped-def]
        return "I am not a ProbeResult"

    r = pg.try_short_circuit(
        category="xtest-wrong-type",
        target="https://example.com",
        objective="probe",
    )
    assert r.verdict == "UNCERTAIN"
    assert "wrong type" in r.reason.lower()


# ---------------------------------------------------------------------------
# run_with_finding_delta helper
# ---------------------------------------------------------------------------


def test_run_with_finding_delta_returns_found_when_tracer_count_grows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counter = {"n": 0}

    def fake_count() -> int:
        return counter["n"]

    monkeypatch.setattr(pg, "_findings_count", fake_count)

    def fake_call() -> None:
        counter["n"] += 1

    r = pg.run_with_finding_delta(
        fake_call,
        success_summary="found one!",
        uncertain_reason="nothing",
    )
    assert r.verdict == "FOUND"
    assert r.findings_count == 1
    assert r.summary == "found one!"


def test_run_with_finding_delta_returns_uncertain_when_no_growth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pg, "_findings_count", lambda: 5)

    r = pg.run_with_finding_delta(
        lambda: None,
        success_summary="x",
        uncertain_reason="no growth",
    )
    assert r.verdict == "UNCERTAIN"
    assert r.reason == "no growth"


def test_run_with_finding_delta_swallows_inner_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pg, "_findings_count", lambda: 0)

    def boom() -> None:
        raise ValueError("inner failure")

    r = pg.run_with_finding_delta(
        boom, success_summary="x", uncertain_reason="default",
    )
    assert r.verdict == "UNCERTAIN"
    assert "ValueError" in r.reason


# ---------------------------------------------------------------------------
# End-to-end: dispatch_specialist short-circuits on FOUND
# ---------------------------------------------------------------------------


def _fake_exit_call(*, history, iteration, profile, **_):
    return {
        "message": "I have completed the objective.",
        "tool_calls": [{
            "tool": "complete_objective",
            "args": {"status": "PASSED", "reason": "fake LLM exit"},
        }],
        "cost_usd": 0.001,
    }


def test_dispatch_skips_llm_loop_when_prober_finds_something() -> None:
    @pg.register_prober("xtest-end-to-end-found")
    def _p(target: str, objective: str) -> pg.ProbeResult:
        return pg.ProbeResult(
            verdict="FOUND",
            findings_count=1,
            summary="prober confirmed it",
        )

    # If the LLM loop ran, we'd see the PASSED-no-finding reason
    # from _fake_exit_call. If the gate short-circuited, we see
    # the gate's confirmed-finding reason instead.
    r = so.dispatch_specialist(
        category="xtest-end-to-end-found",
        objective="probe SQLi on /api/users",
        target="https://vampi.local/api/users",
        inner_call_fn=_fake_exit_call,
    )
    assert r["status"] == "PASSED"
    assert "pre-dispatch deterministic gate confirmed" in r["reason"]
    assert r["findings_count"] == 1
    assert r["summary"] == "prober confirmed it"


def test_dispatch_short_circuit_does_not_consume_scan_mode_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Critical cost-win: a successful pre-probe must NOT bump
    the scan-mode dispatch counter — that budget is preserved
    for harder cases the deterministic probers can't catch."""
    monkeypatch.setenv("STRIX_SCAN_MODE", "standard")

    @pg.register_prober("xtest-counter")
    def _p(target: str, objective: str) -> pg.ProbeResult:
        return pg.ProbeResult(
            verdict="FOUND", findings_count=1, summary="ok",
        )

    so.dispatch_specialist(
        category="xtest-counter", objective="probe",
        target="https://x.com/api",
        inner_call_fn=_fake_exit_call,
    )
    assert so.get_dispatch_count() == 0


def test_dispatch_falls_through_on_uncertain_prober() -> None:
    """Recall canary — when the prober says UNCERTAIN, the LLM
    dispatch MUST still run."""
    llm_called = {"n": 0}

    @pg.register_prober("xtest-fallthrough")
    def _p(target: str, objective: str) -> pg.ProbeResult:
        return pg.ProbeResult(
            verdict="UNCERTAIN", reason="nothing confirmed",
        )

    def counting_call(*, history, iteration, profile, **_):
        llm_called["n"] += 1
        return _fake_exit_call(history=history, iteration=iteration, profile=profile)

    so.dispatch_specialist(
        category="xtest-fallthrough", objective="probe",
        target="https://x.com/api",
        inner_call_fn=counting_call,
    )
    assert llm_called["n"] > 0, (
        "recall canary: UNCERTAIN prober must NOT block LLM "
        "dispatch — uncertainty always escalates"
    )


def test_dispatch_falls_through_when_no_prober_for_category() -> None:
    """A category without a registered prober runs LLM dispatch
    normally — zero behavior change."""
    pg._PROBERS.pop("never-heard-of-this", None)
    llm_called = {"n": 0}

    def counting_call(*, history, iteration, profile, **_):
        llm_called["n"] += 1
        return _fake_exit_call(history=history, iteration=iteration, profile=profile)

    so.dispatch_specialist(
        category="never-heard-of-this", objective="probe",
        target="https://x.com",
        inner_call_fn=counting_call,
    )
    assert llm_called["n"] > 0


def test_dispatch_falls_through_when_gate_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kill switch bypasses the gate even with a registered
    FOUND-returning prober."""
    monkeypatch.setenv("STRIX_PREDISPATCH_GATE_DISABLED", "1")

    @pg.register_prober("xtest-killswitch")
    def _p(target: str, objective: str) -> pg.ProbeResult:
        return pg.ProbeResult(
            verdict="FOUND", findings_count=1, summary="should not fire",
        )

    llm_called = {"n": 0}

    def counting_call(*, history, iteration, profile, **_):
        llm_called["n"] += 1
        return _fake_exit_call(history=history, iteration=iteration, profile=profile)

    so.dispatch_specialist(
        category="xtest-killswitch", objective="probe",
        target="https://x.com",
        inner_call_fn=counting_call,
    )
    # LLM dispatched, gate didn't short-circuit
    assert llm_called["n"] > 0


# ---------------------------------------------------------------------------
# Built-in sqli prober is registered
# ---------------------------------------------------------------------------


def test_sqli_prober_is_registered() -> None:
    """The built-in sqli prober ships as a registered prober."""
    assert "sqli" in pg.list_registered_categories()
