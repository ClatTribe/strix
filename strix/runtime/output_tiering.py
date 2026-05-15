"""Tiered tool-output management (§6 of strixredteam.md).

Reduces the "tool output is the dominant context cost" problem by
tiering tool-result rendering by size:

  Tier 1 (≤ 15K chars)        → inline, no change
  Tier 2 (15K – 100K chars)   → save to scratch dir; agent gets
                                 summary + path; can `view` if needed
  Tier 3 (> 5M chars)         → reject at the caller — never let
                                 a result this large propagate

This replaces the prior `_format_tool_result` 10K head-tail
truncation: when a result is big, we **save the full content**
instead of throwing away the middle. The agent can re-read via
`str_replace_editor` if it needs the full picture, but the
default-rendered version stays under the context budget.

Plus two universal cleanups applied before tiering:
  * ANSI-escape stripping (terminal-control codes pollute the
    LLM's tokenisation badly; up to 30% of output size on tools
    like `nmap -A`).
  * Repeat-line compression (`tail -f`-style logs / sequence of
    identical lines collapse to `<line>\n... [N more identical
    lines]`).

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `STRIX_OUTPUT_INLINE_MAX` | 15000 | Tier-1 ceiling (chars) |
| `STRIX_OUTPUT_SCRATCH_MAX` | 102400 (100K) | Tier-2 ceiling |
| `STRIX_OUTPUT_HARD_KILL` | 5242880 (5M) | Tier-3 boundary |
| `STRIX_OUTPUT_TIERING_DISABLED` | unset | Kill switch — reverts to legacy truncation |

## Scratch dir layout

```
strix_runs/<run_id>/.tool_output_scratch/
  ├── tool_call_<execution_id>.txt    # full tool result
  ├── tool_call_<execution_id>.json   # metadata (tool_name, args, etc.)
  └── ...
```

When a result spills to tier 2, the rendered output is:

```
[tool_output_tier_2: 47KB saved to .tool_output_scratch/tool_call_xxx.txt]
Summary: <head> ... <tail>
Full output: view via str_replace_editor with this path.
```
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# Tier thresholds (chars). All read from env each call so a wrapper
# can mutate mid-run.
def get_inline_max() -> int:
    return _read_env_int("STRIX_OUTPUT_INLINE_MAX", 15_000)


def get_scratch_max() -> int:
    return _read_env_int("STRIX_OUTPUT_SCRATCH_MAX", 102_400)   # 100K


def get_hard_kill() -> int:
    return _read_env_int("STRIX_OUTPUT_HARD_KILL", 5_242_880)   # 5M


def is_tiering_disabled() -> bool:
    """Kill switch — reverts to the legacy 10K head-tail truncation
    in `_format_tool_result`. Useful for A/B benchmarking the
    cost reduction."""
    return os.environ.get(
        "STRIX_OUTPUT_TIERING_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _read_env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return max(1, int(float(raw)))
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# Cleanup passes — applied to ALL tool output regardless of tier
# ---------------------------------------------------------------------------


# ANSI escape regex — matches CSI sequences (most common in
# terminal output: colors, cursor movement, clear-line). Doesn't
# strip BEL or other one-byte controls; those rarely impact LLM
# tokenisation.
_ANSI_ESC_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi(text: str) -> str:
    """Strip ANSI escape sequences. Reduces output size on
    color-heavy tools (nmap, semgrep with --emoji, etc.) by
    10-30% in practice."""
    if not text or "\x1B" not in text:
        return text
    return _ANSI_ESC_RE.sub("", text)


def compress_repeat_lines(text: str, *, threshold: int = 3) -> str:
    """Collapse runs of identical consecutive lines into a single
    line plus a `... [N more identical lines]` marker. `tail -f`
    output, polling loops, and progress indicators are the main
    offenders this catches.

    Args:
      text: input string
      threshold: minimum number of identical lines before we
        compress. Default 3 — single duplicates stay readable,
        3+ get collapsed.
    """
    if not text:
        return text
    lines = text.splitlines(keepends=True)
    if len(lines) < threshold:
        return text

    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        j = i + 1
        while j < len(lines) and lines[j] == line:
            j += 1
        run_len = j - i
        if run_len >= threshold:
            out.append(line)
            out.append(f"... [{run_len - 1} more identical lines]\n")
        else:
            out.extend(lines[i:j])
        i = j
    return "".join(out)


# ---------------------------------------------------------------------------
# Scratch-dir lookup
# ---------------------------------------------------------------------------


def _resolve_run_dir() -> Path | None:
    """Find the active run's directory. Prefer the tracer's
    `get_run_dir()` (canonical); fall back to `STRIX_RUN_DIR` env
    var. Returns None when neither is available (e.g. unit
    tests not going through the full CLI entrypoint)."""
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is not None and hasattr(tracer, "get_run_dir"):
            d = tracer.get_run_dir()
            if d is not None:
                return Path(d)
    except Exception:  # noqa: BLE001
        pass

    env_dir = os.environ.get("STRIX_RUN_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    return None


def _scratch_dir() -> Path | None:
    """The scratch subdirectory of the active run dir. Created
    on first call. Returns None when no run dir is available;
    the caller should fall back to the legacy truncation."""
    run_dir = _resolve_run_dir()
    if run_dir is None:
        return None
    scratch = run_dir / ".tool_output_scratch"
    try:
        scratch.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.debug("could not create scratch dir %s: %s", scratch, e)
        return None
    return scratch


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def apply_tiering(
    *,
    tool_name: str,
    raw_output: str,
    execution_id: str | None = None,
) -> str:
    """Apply ANSI strip + repeat-line compression, then tier the
    result by size.

    Returns the rendered output string the LLM should see.

    Tier policy:
      ≤ inline_max          → return cleaned output as-is
      ≤ scratch_max         → save to scratch, return summary+path
      ≤ hard_kill           → save to scratch (aggressive head/
                              tail summary, full file still
                              preserved)
      > hard_kill           → save to scratch with WARNING marker;
                              the calling executor SHOULD have
                              killed at this size — defensive
                              fallback so we never raw-dump 5MB
                              into the LLM

    Kill switch: when `STRIX_OUTPUT_TIERING_DISABLED=1`, returns
    the input unchanged (the caller's legacy truncation applies).
    """
    if is_tiering_disabled():
        return raw_output

    if not isinstance(raw_output, str):
        return raw_output

    cleaned = compress_repeat_lines(strip_ansi(raw_output))

    inline_max = get_inline_max()
    scratch_max = get_scratch_max()
    hard_kill = get_hard_kill()

    n = len(cleaned)
    if n <= inline_max:
        return cleaned

    # Tier 2 / 3 — need scratch.
    scratch = _scratch_dir()
    if scratch is None:
        # Degraded mode — no run dir available. Fall back to
        # head-tail summary inline. Better than dumping 100K
        # into the LLM.
        return _head_tail_summary(cleaned, inline_max)

    # Save the full cleaned output.
    fname_id = execution_id or f"unknown-{int(time.time())}"
    safe_id = re.sub(r"[^a-zA-Z0-9_.-]", "_", fname_id)
    # Collapse runs of dots to avoid `..` path-traversal in filenames.
    safe_id = re.sub(r"\.{2,}", "_", safe_id)
    out_path = scratch / f"tool_call_{safe_id}.txt"
    try:
        out_path.write_text(cleaned, encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug("scratch write failed (%s): %s", out_path, e)
        return _head_tail_summary(cleaned, inline_max)

    # Companion metadata for tooling that wants to introspect.
    try:
        meta_path = scratch / f"tool_call_{safe_id}.json"
        meta_path.write_text(json.dumps({
            "tool_name": tool_name,
            "execution_id": execution_id,
            "raw_size_chars": len(raw_output),
            "cleaned_size_chars": n,
            "tiering_version": 1,
            "saved_at_monotonic": time.monotonic(),
        }, indent=2), encoding="utf-8")
    except OSError:
        pass

    if n <= scratch_max:
        tier = 2
        warning = ""
    elif n <= hard_kill:
        tier = 3
        warning = " (LARGE — verify this output is bounded)"
    else:
        # > 5M — should have been caught upstream; defensive only.
        tier = 4
        warning = (
            " (OVER HARD-KILL THRESHOLD — the tool executor should "
            "have rejected this; treat output as potentially "
            "runaway)"
        )

    return _render_tiered_marker(
        tool_name=tool_name,
        full_size=n,
        relative_path=str(out_path.relative_to(_resolve_run_dir())),
        cleaned=cleaned,
        tier=tier,
        warning=warning,
    )


def _render_tiered_marker(
    *, tool_name: str, full_size: int, relative_path: str,
    cleaned: str, tier: int, warning: str,
) -> str:
    """Build the agent-facing summary for a saved tool result.

    The summary shows:
      * Tier + size in human-readable form
      * Path to the full file (relative to run dir; the agent
        uses `str_replace_editor` to view if needed)
      * Head (1K) + tail (1K) of the cleaned output as preview
    """
    kb = full_size / 1024
    head = cleaned[:1024]
    tail = cleaned[-1024:] if full_size > 2048 else ""

    parts = [
        f"[tool_output_tier_{tier}: {tool_name} returned "
        f"{kb:.1f} KB — saved to {relative_path}{warning}]",
        "",
        "--- HEAD ---",
        head,
    ]
    if tail:
        parts.append("--- TAIL ---")
        parts.append(tail)
    parts.append("")
    parts.append(
        f"Full output ({full_size:,} chars) at: {relative_path}. "
        f"View with `str_replace_editor command=view path={relative_path}`."
    )
    return "\n".join(parts)


def _head_tail_summary(text: str, ceiling: int) -> str:
    """Degraded mode — no scratch dir available, but output too
    big to inline. Keep head + tail at ~40% each, drop the middle."""
    keep = ceiling * 4 // 10
    head = text[:keep]
    tail = text[-keep:]
    return (
        head
        + f"\n\n... [{len(text) - 2 * keep:,} chars middle elided "
        f"— scratch dir unavailable] ...\n\n"
        + tail
    )


# ---------------------------------------------------------------------------
# Inspection helpers (for tests + telemetry)
# ---------------------------------------------------------------------------


def get_thresholds() -> dict[str, int]:
    """Snapshot of current threshold values. Useful for telemetry
    (run_meta.json) so wrappers can see how the run was tiered."""
    return {
        "inline_max": get_inline_max(),
        "scratch_max": get_scratch_max(),
        "hard_kill": get_hard_kill(),
        "disabled": is_tiering_disabled(),
    }
