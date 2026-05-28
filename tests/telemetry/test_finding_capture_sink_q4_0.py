"""Tests for iter-Q4.0 — per-call finding capture sink (contextvar).

The sink lets the sandbox tool_server run N tools concurrently
without the `_tracer_lock` that previously serialised every fan-out
dispatch. When a sink is active, `add_vulnerability_report` routes
the finding into the per-call buffer and returns WITHOUT touching
the tracer's global `vulnerability_reports`, running the L1.5 hook
chain, or persisting. The host re-emits captured findings through
its own tracer (where the real hooks fire).

Covers:
  * sink active → finding lands in sink, NOT global list
  * sink active → L1.5 hook chain + save_run_data NOT invoked
  * no sink → normal global append (unchanged host behaviour)
  * push/pop nesting restores the previous sink
  * concurrent asyncio tasks get isolated sinks (no cross-contamination)
  * the sink survives across asyncio.to_thread (the path tools take)
"""

from __future__ import annotations

import asyncio

import pytest

from strix.telemetry.tracer import (
    Tracer,
    pop_finding_capture_sink,
    push_finding_capture_sink,
)


def _emit(tracer: Tracer, title: str) -> str:
    return tracer.add_vulnerability_report(
        title=title,
        severity="high",
        cwe="CWE-89",
        endpoint="http://x.test/p",
        category="sqli",
    )


class TestSinkRouting:
    def test_no_sink_appends_to_global(self):
        """Host path: no sink → finding lands in vulnerability_reports."""
        t = Tracer(run_name="test-no-sink")
        before = len(t.vulnerability_reports)
        _emit(t, "global finding")
        assert len(t.vulnerability_reports) == before + 1
        assert t.vulnerability_reports[-1]["title"] == "global finding"

    def test_sink_active_routes_to_sink_not_global(self):
        """Sandbox path: sink active → finding lands in sink ONLY."""
        t = Tracer(run_name="test-sink")
        before = len(t.vulnerability_reports)
        sink, token = push_finding_capture_sink()
        try:
            rid = _emit(t, "captured finding")
        finally:
            pop_finding_capture_sink(token)
        # Global list untouched.
        assert len(t.vulnerability_reports) == before
        # Sink got the finding.
        assert len(sink) == 1
        assert sink[0]["title"] == "captured finding"
        assert sink[0]["id"] == rid

    def test_sink_skips_save_run_data(self, monkeypatch):
        """When the sink is active, the expensive save_run_data() +
        L1.5 hook chain must NOT run (the sandbox tracer is just a
        capture buffer; the host re-emits with the real hooks)."""
        t = Tracer(run_name="test-sink-nosave")
        save_calls = {"n": 0}
        monkeypatch.setattr(
            t, "save_run_data", lambda *a, **k: save_calls.__setitem__("n", save_calls["n"] + 1),
        )
        sink, token = push_finding_capture_sink()
        try:
            _emit(t, "no-save finding")
        finally:
            pop_finding_capture_sink(token)
        assert save_calls["n"] == 0, "save_run_data must not run under a sink"

    def test_returns_report_id_even_under_sink(self):
        t = Tracer(run_name="test-sink-id")
        sink, token = push_finding_capture_sink()
        try:
            rid = _emit(t, "x")
        finally:
            pop_finding_capture_sink(token)
        assert isinstance(rid, str) and rid.startswith("vuln-")


class TestSinkNesting:
    def test_pop_restores_previous_sink(self):
        t = Tracer(run_name="test-nest")
        outer, outer_tok = push_finding_capture_sink()
        try:
            inner, inner_tok = push_finding_capture_sink()
            try:
                _emit(t, "inner")
            finally:
                pop_finding_capture_sink(inner_tok)
            # After popping inner, emissions go to outer.
            _emit(t, "outer")
        finally:
            pop_finding_capture_sink(outer_tok)
        assert [f["title"] for f in inner] == ["inner"]
        assert [f["title"] for f in outer] == ["outer"]

    def test_after_full_pop_global_append_resumes(self):
        t = Tracer(run_name="test-resume")
        before = len(t.vulnerability_reports)
        sink, token = push_finding_capture_sink()
        try:
            _emit(t, "captured")
        finally:
            pop_finding_capture_sink(token)
        # Global untouched during capture...
        assert len(t.vulnerability_reports) == before
        # ...and resumes after pop.
        _emit(t, "global again")
        assert len(t.vulnerability_reports) == before + 1


class TestConcurrentIsolation:
    def test_concurrent_tasks_have_isolated_sinks(self):
        """Two asyncio tasks each push their own sink — neither sees
        the other's findings. This is the property that lets the
        sandbox run concurrent tools without cross-contamination."""
        t = Tracer(run_name="test-concurrent")

        async def _worker(title: str, sink_out: list) -> None:
            sink, token = push_finding_capture_sink()
            try:
                # Yield so the two workers interleave.
                await asyncio.sleep(0)
                _emit(t, title)
                await asyncio.sleep(0)
                _emit(t, f"{title}-2")
            finally:
                pop_finding_capture_sink(token)
            sink_out.extend(sink)

        async def _run():
            a_out: list = []
            b_out: list = []
            await asyncio.gather(
                _worker("A", a_out),
                _worker("B", b_out),
            )
            return a_out, b_out

        a_out, b_out = asyncio.run(_run())
        # Each worker's sink contains ONLY its own findings.
        assert {f["title"] for f in a_out} == {"A", "A-2"}
        assert {f["title"] for f in b_out} == {"B", "B-2"}
        # Global list untouched by either.
        assert len(t.vulnerability_reports) == 0

    def test_sink_survives_to_thread(self):
        """Tools run via asyncio.to_thread; the contextvar sink must
        be visible inside the worker thread (asyncio.to_thread copies
        the calling context). This is exactly the tool_server path."""
        t = Tracer(run_name="test-to-thread")

        def _tool_body() -> None:
            # Runs in a worker thread — emits via the tracer just like
            # a real sandboxed OSS-tool wrapper does.
            _emit(t, "from-thread")

        async def _run() -> list:
            sink, token = push_finding_capture_sink()
            try:
                await asyncio.to_thread(_tool_body)
            finally:
                pop_finding_capture_sink(token)
            return sink

        sink = asyncio.run(_run())
        assert [f["title"] for f in sink] == ["from-thread"]
        assert len(t.vulnerability_reports) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
