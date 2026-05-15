"""Tests for §6 tiered output management
(strix/runtime/output_tiering.py).

The doc identifies tool-output volume as the dominant context
cost. This module tiers output size:
  Tier 1 (≤ 15K)         → inline
  Tier 2 (15K - 100K)    → save to scratch + summary + path
  Tier 3 (> 100K)        → save with aggressive head/tail summary

Plus ANSI strip + repeat-line compression universally applied.

Tests cover:
  * ANSI escape stripping
  * Repeat-line compression
  * Tier-1 passthrough
  * Tier-2 scratch-save + summary rendering
  * Tier-3 over-threshold marker
  * Degraded mode (no scratch dir → head-tail summary)
  * Kill switch (STRIX_OUTPUT_TIERING_DISABLED)
  * Env-var threshold overrides
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from strix.runtime import output_tiering as ot


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "STRIX_OUTPUT_INLINE_MAX",
        "STRIX_OUTPUT_SCRATCH_MAX",
        "STRIX_OUTPUT_HARD_KILL",
        "STRIX_OUTPUT_TIERING_DISABLED",
        "STRIX_RUN_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


# ---------------------------------------------------------------------------
# ANSI strip
# ---------------------------------------------------------------------------


def test_strip_ansi_removes_color_codes() -> None:
    raw = "\x1b[31mERROR\x1b[0m: something broke"
    assert ot.strip_ansi(raw) == "ERROR: something broke"


def test_strip_ansi_handles_multiline() -> None:
    raw = (
        "\x1b[1;33mWarning\x1b[0m: bad\n"
        "\x1b[31m[FAIL]\x1b[0m: worse"
    )
    out = ot.strip_ansi(raw)
    assert "\x1b" not in out
    assert "Warning: bad" in out
    assert "[FAIL]: worse" in out


def test_strip_ansi_passthrough_when_no_escape() -> None:
    raw = "plain text, no escapes"
    assert ot.strip_ansi(raw) is raw      # short-circuit returns same object


def test_strip_ansi_handles_empty() -> None:
    assert ot.strip_ansi("") == ""


def test_strip_ansi_cursor_movement() -> None:
    """`tail -f` / progress bars use cursor sequences. Should
    strip those too."""
    raw = "Progress \x1b[2K\rProgress 50%\x1b[2K\rProgress 100%\n"
    out = ot.strip_ansi(raw)
    assert "\x1b" not in out


# ---------------------------------------------------------------------------
# Repeat-line compression
# ---------------------------------------------------------------------------


def test_compress_repeat_lines_triple_collapses() -> None:
    text = "line\n" * 5
    out = ot.compress_repeat_lines(text)
    assert "line\n" in out
    assert "[4 more identical lines]" in out


def test_compress_below_threshold_unchanged() -> None:
    """Two consecutive duplicates stay readable."""
    text = "line\nline\n"
    assert ot.compress_repeat_lines(text) == text


def test_compress_mixed_runs() -> None:
    """A run of 5 + a normal line + a run of 3 — both runs
    should compress independently."""
    text = "A\nA\nA\nA\nA\nB\nC\nC\nC\n"
    out = ot.compress_repeat_lines(text)
    assert "A\n" in out
    assert "[4 more identical lines]" in out
    assert "B\n" in out
    assert "C\n" in out
    assert "[2 more identical lines]" in out


def test_compress_handles_empty() -> None:
    assert ot.compress_repeat_lines("") == ""


def test_compress_handles_short_input() -> None:
    """Input shorter than threshold returns unchanged
    (avoids spurious processing)."""
    assert ot.compress_repeat_lines("x\n") == "x\n"


# ---------------------------------------------------------------------------
# Tier 1 — inline passthrough
# ---------------------------------------------------------------------------


def test_tier_1_short_output_inline() -> None:
    """Output below `STRIX_OUTPUT_INLINE_MAX` returns cleaned but
    otherwise unchanged."""
    output = "small output\n" * 50    # ~600 chars
    result = ot.apply_tiering(
        tool_name="test_tool", raw_output=output, execution_id="t1",
    )
    assert "small output" in result
    assert "tool_output_tier" not in result      # no tiering marker


def test_tier_1_applies_ansi_and_compression(tmp_path, monkeypatch) -> None:
    """Tier-1 path still gets the universal cleanups."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))

    raw = "\x1b[31mALERT\x1b[0m\n" + "dup\n" * 6
    result = ot.apply_tiering(
        tool_name="t", raw_output=raw, execution_id="x",
    )
    # ANSI stripped, repeats collapsed.
    assert "\x1b" not in result
    assert "ALERT" in result
    assert "[5 more identical lines]" in result


# ---------------------------------------------------------------------------
# Tier 2 — scratch save with summary
# ---------------------------------------------------------------------------


def test_tier_2_saves_to_scratch_with_summary(
    tmp_path, monkeypatch,
) -> None:
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.setenv("STRIX_OUTPUT_INLINE_MAX", "1000")
    monkeypatch.setenv("STRIX_OUTPUT_SCRATCH_MAX", "100000")

    big = "A" * 5000     # > 1K, < 100K → tier 2
    result = ot.apply_tiering(
        tool_name="my_tool", raw_output=big, execution_id="exec-42",
    )

    # Summary marker present.
    assert "tool_output_tier_2" in result
    assert "my_tool returned" in result
    # Head section visible.
    assert "--- HEAD ---" in result
    # File saved.
    saved = tmp_path / ".tool_output_scratch" / "tool_call_exec-42.txt"
    assert saved.exists()
    assert saved.read_text() == big


def test_tier_2_metadata_companion_file(
    tmp_path, monkeypatch,
) -> None:
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.setenv("STRIX_OUTPUT_INLINE_MAX", "1000")
    monkeypatch.setenv("STRIX_OUTPUT_SCRATCH_MAX", "100000")

    big = "B" * 5000
    ot.apply_tiering(
        tool_name="my_tool", raw_output=big, execution_id="exec-99",
    )
    meta = tmp_path / ".tool_output_scratch" / "tool_call_exec-99.json"
    assert meta.exists()
    import json
    parsed = json.loads(meta.read_text())
    assert parsed["tool_name"] == "my_tool"
    assert parsed["execution_id"] == "exec-99"
    assert parsed["cleaned_size_chars"] == 5000


def test_tier_2_filename_sanitises_execution_id(
    tmp_path, monkeypatch,
) -> None:
    """Bad chars in execution_id are sanitised to keep filenames
    safe (no path traversal, no shell-quoting issues)."""
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.setenv("STRIX_OUTPUT_INLINE_MAX", "100")

    ot.apply_tiering(
        tool_name="t",
        raw_output="X" * 500,
        execution_id="../evil/path",
    )
    # No "../evil/path" subdir created — sanitised.
    files = list((tmp_path / ".tool_output_scratch").glob("*.txt"))
    assert len(files) == 1
    assert ".." not in files[0].name
    assert "/" not in files[0].name


# ---------------------------------------------------------------------------
# Tier 3 — over-scratch-threshold
# ---------------------------------------------------------------------------


def test_tier_3_carries_warning_marker(
    tmp_path, monkeypatch,
) -> None:
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.setenv("STRIX_OUTPUT_INLINE_MAX", "100")
    monkeypatch.setenv("STRIX_OUTPUT_SCRATCH_MAX", "1000")
    monkeypatch.setenv("STRIX_OUTPUT_HARD_KILL", "5000000")

    huge = "C" * 5000   # over scratch_max=1000, under hard_kill
    result = ot.apply_tiering(
        tool_name="t", raw_output=huge, execution_id="exec-3",
    )
    assert "tool_output_tier_3" in result
    assert "LARGE" in result


def test_tier_4_when_over_hard_kill(
    tmp_path, monkeypatch,
) -> None:
    """The executor SHOULD reject before this, but the tiering
    has a defensive tier_4 marker for the bad case."""
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.setenv("STRIX_OUTPUT_INLINE_MAX", "100")
    monkeypatch.setenv("STRIX_OUTPUT_SCRATCH_MAX", "1000")
    monkeypatch.setenv("STRIX_OUTPUT_HARD_KILL", "2000")

    runaway = "D" * 5000   # over both scratch_max AND hard_kill
    result = ot.apply_tiering(
        tool_name="t", raw_output=runaway, execution_id="exec-runaway",
    )
    assert "tool_output_tier_4" in result
    assert "OVER HARD-KILL" in result


# ---------------------------------------------------------------------------
# Degraded mode — no scratch dir
# ---------------------------------------------------------------------------


def test_degraded_mode_no_run_dir(monkeypatch) -> None:
    """When no run dir is available, falls back to head-tail
    summary inline. Better than dumping 100K into the LLM."""
    # No STRIX_RUN_DIR; no tracer either (test env).
    monkeypatch.setenv("STRIX_OUTPUT_INLINE_MAX", "100")

    big = "X" * 5000
    result = ot.apply_tiering(
        tool_name="t", raw_output=big, execution_id="x",
    )
    # No scratch marker — using inline head/tail summary.
    assert "tool_output_tier_2" not in result
    assert "scratch dir unavailable" in result


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
def test_kill_switch_returns_input_unchanged(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_OUTPUT_TIERING_DISABLED", val)
    raw = "\x1b[31mhello\x1b[0m\n" + ("dup\n" * 10)
    result = ot.apply_tiering(
        tool_name="t", raw_output=raw, execution_id="x",
    )
    # No processing — ANSI not stripped, repeats not collapsed.
    assert result == raw


def test_kill_switch_disabled_default(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_OUTPUT_TIERING_DISABLED", raising=False)
    assert ot.is_tiering_disabled() is False


# ---------------------------------------------------------------------------
# Threshold env overrides
# ---------------------------------------------------------------------------


def test_threshold_env_overrides(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OUTPUT_INLINE_MAX", "100")
    monkeypatch.setenv("STRIX_OUTPUT_SCRATCH_MAX", "1000")
    monkeypatch.setenv("STRIX_OUTPUT_HARD_KILL", "10000")
    assert ot.get_inline_max() == 100
    assert ot.get_scratch_max() == 1000
    assert ot.get_hard_kill() == 10000


def test_threshold_garbage_falls_back_to_default(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OUTPUT_INLINE_MAX", "not-a-number")
    assert ot.get_inline_max() == 15_000   # default


def test_get_thresholds_snapshot(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_OUTPUT_INLINE_MAX", raising=False)
    monkeypatch.delenv("STRIX_OUTPUT_TIERING_DISABLED", raising=False)
    snap = ot.get_thresholds()
    assert snap["inline_max"] == 15_000
    assert snap["scratch_max"] == 102_400
    assert snap["hard_kill"] == 5_242_880
    assert snap["disabled"] is False


# ---------------------------------------------------------------------------
# Non-string defensive handling
# ---------------------------------------------------------------------------


def test_apply_tiering_passes_through_non_string() -> None:
    """If the executor accidentally passes a non-string, the
    tiering should not crash — just return as-is."""
    result = ot.apply_tiering(
        tool_name="t", raw_output=12345, execution_id="x",   # type: ignore[arg-type]
    )
    assert result == 12345


# ---------------------------------------------------------------------------
# Cost reduction — quantitative check
# ---------------------------------------------------------------------------


def test_compression_meaningfully_reduces_size(
    tmp_path, monkeypatch,
) -> None:
    """Repeat-line compression should produce a measurable
    reduction on tail-f-style output."""
    raw = "INFO: heartbeat\n" * 1000   # ~14K
    cleaned = ot.compress_repeat_lines(raw)
    assert len(cleaned) < len(raw) // 10   # >90% reduction
