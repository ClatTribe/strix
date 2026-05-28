"""iter-Q4.2 — dependency classifier for per-turn tool batches.

`process_tool_invocations` (Phase 1.7) gathers *all* tools the lead
emits in one turn with `asyncio.gather` and **no dependency ordering**.
That is a latent correctness hazard the moment the lead emits a
dependent pair in a single turn, e.g.::

    seed_auth(...)            # captures a session into SecurityContext
    scan_idor(endpoint=...)   # READS that captured session

Gathered together, `scan_idor` may start before `seed_auth` finishes
writing the auth state — a race (proposal §0.2, CLAUDE.md §3.6).

This module is the **safety guard**: it partitions a turn's tool batch
into dependency-ordered *waves*. Calls within a wave are mutually
independent and may run concurrently; waves run strictly in order, so
a tool that needs another tool's side-effect always runs in a later
wave than the tool that produces it.

It is deliberately a leaf module (no `strix` imports) so the executor
can import it without any circular-import risk.

The table is intentionally small and conservative — it encodes only
the side-effect dependencies we can name. A pair with no table entry
is treated as independent (the common case: N fan-out scans across
distinct endpoints), so the guard is zero-cost for the batches that
actually benefit from parallelism.
"""

from __future__ import annotations

from typing import Any


# Keyed by the *dependent* tool; valued by the set of tools whose
# side-effect must land before it. Read as: "TOOL_DEPENDENCIES[X] = the
# tools that must complete before X may start, IF they appear in the
# same turn's batch."
#
# Two real hazards are encoded:
#
#  1. Auth/session capture → multi-session readers. `scan_auth_flow`
#     and `seed_auth` write a captured session into the sandbox-side
#     `SecurityContext.AuthState`; the multi-session-authz and
#     app-logic tools read it. Batched together, the capture must win
#     the race (proposal §0.2).
#
#  2. Detector → verifier. The L2.5 verifier (`verify_finding`) takes a
#     `finding_id` that a detector must have already emitted into the
#     tracer; batched with its producer they race on
#     `vulnerability_reports` (proposal §3.1 risk note).
#
# Update this table (and the test fixtures in
# tests/tools/test_tool_dependencies_q4_2.py) together when a new
# state-coupled tool pair is introduced.
TOOL_DEPENDENCIES: dict[str, frozenset[str]] = {
    # --- auth/session-state readers depend on the writers ---
    "scan_idor": frozenset({"seed_auth", "scan_auth_flow"}),
    "scan_business_logic": frozenset({"seed_auth", "scan_auth_flow"}),
    "dispatch_l2_probe": frozenset({"seed_auth", "scan_auth_flow"}),
    # --- the verifier re-fires against a finding a detector emitted ---
    "verify_finding": frozenset(
        {
            "create_vulnerability_report",
            "scan_idor",
            "scan_sqli_sqlmap",
            "scan_xss_dalfox",
            "scan_auth_flow",
            "dispatch_l2_probe",
        }
    ),
}


def _invocation_tool_name(invocation: Any) -> str:
    """Best-effort tool name from a parsed invocation.

    The executor's invocation dicts carry the name under ``toolName``
    (see `_execute_single_tool`); accept the common aliases too and
    degrade to ``""`` (never matches a dependency) rather than raise —
    this only feeds wave-layering, and an unknown name is safely
    treated as a dependency-free (parallelisable) call.
    """
    if isinstance(invocation, dict):
        return str(
            invocation.get("toolName")
            or invocation.get("tool_name")
            or invocation.get("name")
            or ""
        )
    return str(
        getattr(invocation, "tool_name", None) or getattr(invocation, "name", None) or ""
    )


def _build_predecessors(names: list[str]) -> list[set[int]]:
    """``preds[i]`` = indices whose tool must complete before ``i``.

    An edge ``j -> i`` exists when ``names[j]`` is in
    ``TOOL_DEPENDENCIES[names[i]]`` — i.e. j produces a side-effect i
    consumes. Emission order is irrelevant; both directions of j vs i
    are considered.
    """
    n = len(names)
    preds: list[set[int]] = [set() for _ in range(n)]
    for i in range(n):
        deps = TOOL_DEPENDENCIES.get(names[i])
        if not deps:
            continue
        preds[i] = {j for j in range(n) if j != i and names[j] in deps}
    return preds


def _wave_levels(preds: list[set[int]]) -> list[int] | None:
    """Longest-path layer for each node, or ``None`` on a cycle.

    A DAG of n nodes converges within n-1 relaxation passes; if it is
    still changing after n+1 passes the graph has a cycle.
    """
    n = len(preds)
    wave_of = [0] * n
    for _ in range(n + 1):
        changed = False
        for i in range(n):
            best = max((wave_of[j] + 1 for j in preds[i]), default=0)
            if best > wave_of[i]:
                wave_of[i] = best
                changed = True
        if not changed:
            return wave_of
    return None


def partition_independent_calls(invocations: list[Any]) -> list[list[int]]:
    """Layer a turn's tool batch into dependency-ordered waves.

    Returns a list of index-lists (indices into ``invocations``). Calls
    in the same wave are mutually independent and MAY run concurrently;
    waves run strictly in order. A call lands in a wave strictly after
    every other in-batch call it depends on per ``TOOL_DEPENDENCIES`` —
    *regardless of emission order*, so ``scan_idor`` runs after
    ``seed_auth`` even if the model listed ``scan_idor`` first.

    Index order within a wave is ascending, so a caller that assembles
    results by index stays order-preserving.

    Properties:
      * No table entries / all-independent batch → a single wave
        ``[[0, 1, ..., n-1]]`` (identical to today's full-parallel
        gather — zero cost for the batches parallelism helps).
      * Pure dependency chain → one call per wave (fully serial).
      * Degrades to fully-serial if the graph fails to resolve (an
        accidental cycle) — correctness over speed.
    """
    n = len(invocations)
    if n <= 1:
        return [[0]] if n == 1 else []

    names = [_invocation_tool_name(inv) for inv in invocations]
    wave_of = _wave_levels(_build_predecessors(names))
    if wave_of is None:  # cycle → safe fully-serial fallback
        return [[i] for i in range(n)]

    waves: list[list[int]] = [[] for _ in range(max(wave_of) + 1)]
    for i, w in enumerate(wave_of):
        waves[w].append(i)
    return [layer for layer in waves if layer]
