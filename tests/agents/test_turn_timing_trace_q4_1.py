"""Tests for iter-Q4.1 — per-turn wall-time trace instrumentation.

`BaseAgent._emit_turn_timing` appends one JSONL row per agent turn to
`<run_dir>/turn_timing.jsonl` capturing (model_wall_s, tool_wall_s,
tool_names). The Q4 analysis uses this to decide whether the lead
loop is model-bound (Axis A/C) or tool-bound (Axis B).

These tests exercise the emitter + the `_action_tool_name` helper
directly (no full agent loop needed — the loop wiring is covered by
the existing base_agent tests; here we pin the trace contract).
"""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from strix.agents.base_agent import _action_tool_name


class _FakeTracer:
    def __init__(self, run_dir: Path):
        self._run_dir = run_dir

    def get_run_dir(self) -> Path:
        return self._run_dir


class _Emitter:
    """Minimal stand-in exposing just what `_emit_turn_timing` touches:
    `self.state.agent_id`, `self.state.iteration`, `self._turn_model_wall_s`.
    We bind the real method onto it so we test the actual code."""

    def __init__(self, agent_id="agent-1", iteration=3, model_wall=1.5):
        self.state = types.SimpleNamespace(agent_id=agent_id, iteration=iteration)
        self._turn_model_wall_s = model_wall

    # Bind the real method.
    from strix.agents.base_agent import BaseAgent
    _emit_turn_timing = BaseAgent._emit_turn_timing


@pytest.fixture(autouse=True)
def _reset_env(monkeypatch):
    monkeypatch.delenv("STRIX_TURN_TRACE", raising=False)


def _read_rows(run_dir: Path) -> list[dict]:
    path = run_dir / "turn_timing.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ----------------------------------------------------------------------
# _action_tool_name
# ----------------------------------------------------------------------

class TestActionToolName:
    def test_dict_toolname(self):
        assert _action_tool_name({"toolName": "scan_sqli_sqlmap"}) == "scan_sqli_sqlmap"

    def test_dict_tool_name_alias(self):
        assert _action_tool_name({"tool_name": "dalfox"}) == "dalfox"

    def test_dict_name_alias(self):
        assert _action_tool_name({"name": "nuclei"}) == "nuclei"

    def test_object_attr(self):
        obj = types.SimpleNamespace(tool_name="scan_idor")
        assert _action_tool_name(obj) == "scan_idor"

    def test_unknown_degrades(self):
        assert _action_tool_name({}) == "?"
        assert _action_tool_name(object()) == "?"


# ----------------------------------------------------------------------
# _emit_turn_timing
# ----------------------------------------------------------------------

class TestEmitTurnTiming:
    def test_writes_one_row_with_split(self, tmp_path):
        e = _Emitter(agent_id="lead", iteration=7, model_wall=2.25)
        tracer = _FakeTracer(tmp_path)
        e._emit_turn_timing(
            tracer, tool_wall_s=10.5, tool_names=["scan_sqli_sqlmap", "scan_xss_dalfox"],
        )
        rows = _read_rows(tmp_path)
        assert len(rows) == 1
        r = rows[0]
        assert r["agent_id"] == "lead"
        assert r["iteration"] == 7
        assert r["model_wall_s"] == 2.25
        assert r["tool_wall_s"] == 10.5
        assert r["n_tools"] == 2
        assert r["tool_names"] == ["scan_sqli_sqlmap", "scan_xss_dalfox"]
        assert r["cancelled"] is False
        assert isinstance(r["ts"], (int, float))

    def test_appends_across_turns(self, tmp_path):
        tracer = _FakeTracer(tmp_path)
        for i in range(3):
            e = _Emitter(iteration=i, model_wall=float(i))
            e._emit_turn_timing(tracer, tool_wall_s=float(i) * 2, tool_names=[f"t{i}"])
        rows = _read_rows(tmp_path)
        assert [r["iteration"] for r in rows] == [0, 1, 2]
        assert [r["tool_wall_s"] for r in rows] == [0.0, 2.0, 4.0]

    def test_no_tools_turn_records_zero_tool_wall(self, tmp_path):
        e = _Emitter()
        tracer = _FakeTracer(tmp_path)
        e._emit_turn_timing(tracer, tool_wall_s=0.0, tool_names=[])
        rows = _read_rows(tmp_path)
        assert rows[0]["n_tools"] == 0
        assert rows[0]["tool_wall_s"] == 0.0

    def test_cancelled_flag(self, tmp_path):
        e = _Emitter()
        tracer = _FakeTracer(tmp_path)
        e._emit_turn_timing(
            tracer, tool_wall_s=3.0, tool_names=["scan_sqli_sqlmap"], cancelled=True,
        )
        assert _read_rows(tmp_path)[0]["cancelled"] is True

    def test_model_wall_resets_after_emit(self, tmp_path):
        """After emitting, `_turn_model_wall_s` is cleared so a stale
        value can't bleed into the next turn."""
        e = _Emitter(model_wall=5.0)
        tracer = _FakeTracer(tmp_path)
        e._emit_turn_timing(tracer, tool_wall_s=1.0, tool_names=[])
        assert e._turn_model_wall_s is None

    def test_missing_model_wall_records_null(self, tmp_path):
        e = _Emitter()
        e._turn_model_wall_s = None
        tracer = _FakeTracer(tmp_path)
        e._emit_turn_timing(tracer, tool_wall_s=1.0, tool_names=[])
        assert _read_rows(tmp_path)[0]["model_wall_s"] is None

    def test_env_disable_skips_emit(self, tmp_path, monkeypatch):
        monkeypatch.setenv("STRIX_TURN_TRACE", "0")
        e = _Emitter()
        tracer = _FakeTracer(tmp_path)
        e._emit_turn_timing(tracer, tool_wall_s=1.0, tool_names=["x"])
        assert not (tmp_path / "turn_timing.jsonl").exists()

    def test_none_tracer_is_noop(self, tmp_path):
        """No tracer (no run dir) → silently skip, never raise."""
        e = _Emitter()
        e._emit_turn_timing(None, tool_wall_s=1.0, tool_names=["x"])
        # Nothing written anywhere; no exception.

    def test_emit_never_raises_on_io_error(self, tmp_path, monkeypatch):
        """A broken run dir must not crash the scan — emit swallows."""
        class _BadTracer:
            def get_run_dir(self):
                raise OSError("disk gone")
        e = _Emitter()
        # Should not raise.
        e._emit_turn_timing(_BadTracer(), tool_wall_s=1.0, tool_names=["x"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
