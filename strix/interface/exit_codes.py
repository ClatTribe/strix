"""Documented exit-code contract (roadmap §4).

Wrappers, CI gates, and orchestration scripts need a stable
exit-code contract they can rely on. Today `0/2 = success` is
documented in a code comment; this module promotes the contract
into a first-class API.

The contract:

| Code | Meaning |
|---|---|
| `0` | clean — scan ran to completion with NO findings |
| `1` | config / setup error (invalid args, sandbox spawn failed, target unreachable on `--preflight`, fatal LLM auth error) |
| `2` | clean — scan ran to completion WITH findings |
| `3` | budget exceeded (`--max-cost` / `--max-input-tokens` self-exit) |
| `130` | SIGINT (Ctrl+C) |
| `143` | SIGTERM (graceful cancel) |

Exit codes are stable across releases. New codes can be added
but existing ones never change semantic.

Usage from interface code:

```python
from strix.interface.exit_codes import EXIT_CLEAN_NO_FINDINGS, EXIT_CLEAN_WITH_FINDINGS

if scan_had_findings:
    sys.exit(EXIT_CLEAN_WITH_FINDINGS)
else:
    sys.exit(EXIT_CLEAN_NO_FINDINGS)
```

The CI / wrapper-side reading of these codes:

- **Pre-merge gate** (block on findings): `exit != 0` is a
  blocker — covers both `2` (findings) and `1` / `3`
  (operational issues).
- **Pass-on-cost-exceed** workflows: `exit == 3` is treated
  as a soft warning, not a block.
- **Cancel detection**: `exit in (130, 143)` differentiates
  user-cancelled from genuine failure.
"""

from __future__ import annotations

# Exit codes — single source of truth. Don't shadow these with
# local literals in interface code.

EXIT_CLEAN_NO_FINDINGS: int = 0
"""Scan ran to completion. No findings emitted."""

EXIT_CONFIG_ERROR: int = 1
"""Configuration / setup error: invalid args, sandbox spawn
failed, target unreachable on --preflight, fatal LLM auth error,
or any unhandled exception that aborts the run before
findings can be assessed."""

EXIT_CLEAN_WITH_FINDINGS: int = 2
"""Scan ran to completion. At least one finding emitted."""

EXIT_BUDGET_EXCEEDED: int = 3
"""Scan terminated by --max-cost / --max-input-tokens
self-exit. Findings emitted up to the termination point are
still in vulnerabilities.json; the run is partial."""

EXIT_DURATION_EXCEEDED: int = 4
"""Scan terminated by --max-duration self-exit. Wrappers and
CI gates should treat this similarly to EXIT_BUDGET_EXCEEDED:
not a failure, a deliberate cap that caught a runaway scan.
Findings emitted up to the termination point are still in
vulnerabilities.json."""

EXIT_SIGINT: int = 130
"""User pressed Ctrl+C (SIGINT). Standard POSIX convention:
128 + signal number."""

EXIT_SIGTERM: int = 143
"""Process received SIGTERM. Standard POSIX convention:
128 + signal number. Wrappers' "cancel scan" buttons
SHOULD send SIGTERM and trust this contract — Strix cancels
the in-flight LLM call, flushes events.jsonl, emits
run.cancelled, tears down the sandbox, exits 143."""


# All known codes — useful for wrapper / CI introspection.
ALL_CODES: dict[int, str] = {
    EXIT_CLEAN_NO_FINDINGS: "clean — no findings",
    EXIT_CONFIG_ERROR: "config / setup error",
    EXIT_CLEAN_WITH_FINDINGS: "clean — with findings",
    EXIT_BUDGET_EXCEEDED: "budget exceeded",
    EXIT_DURATION_EXCEEDED: "duration exceeded",
    EXIT_SIGINT: "SIGINT (Ctrl+C)",
    EXIT_SIGTERM: "SIGTERM (graceful cancel)",
}


def describe(code: int) -> str:
    """Human-readable description for a given exit code. Returns
    'unknown' for codes outside the documented contract."""
    return ALL_CODES.get(int(code), "unknown")


def is_success(code: int) -> bool:
    """True for codes that represent a completed run (no
    operational issue). 0 and 2 both qualify; 1/3/4/130/143 are
    not."""
    return int(code) in (EXIT_CLEAN_NO_FINDINGS, EXIT_CLEAN_WITH_FINDINGS)


def is_capped(code: int) -> bool:
    """True for codes that represent a deliberate self-exit due
    to budget / duration caps. Wrappers should treat these as
    successful (partial findings preserved), not as errors."""
    return int(code) in (EXIT_BUDGET_EXCEEDED, EXIT_DURATION_EXCEEDED)


def is_cancelled(code: int) -> bool:
    """True for SIGINT / SIGTERM cancellation."""
    return int(code) in (EXIT_SIGINT, EXIT_SIGTERM)
