"""Post-exploit pivot orchestrator — depth gap #2.

Once a finding lands with `verification_status='exploited'` (per
PR #255 / `strix.agents.proof_of_impact`), Strix has CAPTURED an
artifact — a stolen cookie, a dumped row, an IMDS blob, an RCE
command output, a captured flag. The scanner stops there.

A real attacker doesn't stop there. The captured artifact is the
*beginning* of the attack chain, not the end:

  * stolen cookie  → replay against admin endpoint → account takeover
  * IMDS metadata → IAM credential extract → S3 enumeration → exfil
  * RCE output    → spawn shell → scrape secrets → lateral move
  * dumped column → schema enumeration → sensitive-table dump
  * IDOR record   → bulk enumeration → cross-tenant data exposure

This module is that forward step. It reads the captured artifact's
impact-type (encoded in the `proof_of_impact` filename), looks up
the registered pivot specialists keyed on that impact-type, and
dispatches them against the same target — emitting NEW findings
linked to the source via the new `PIVOTED_FROM` KG edge.

Strix's existing `chaining_graph.py` does *narrative* chaining at
report-time (pattern-match findings to a known A→B class). This
module does *forward* chaining at attack-time — when A is captured,
fire B; when B is captured, fire C. The KG records the directed
provenance so the wrapper can render "this admin takeover came from
XSS-stolen-cookie which came from a reflected XSS on /search."

## Specialist contract

```python
def my_pivot_specialist(
    *, source_finding: dict, target_context: dict,
) -> PivotResult:
    \"\"\"Run a post-exploit pivot. `source_finding` is the
    canonical finding dict (must have proof_artifact_path).
    `target_context` carries the asset/surface info from the
    source's KG node.\"\"\"
    ...
```

A specialist should:
  1. Read the proof artifact from `source_finding['proof_artifact_path']`
  2. Use it to attempt the next step (replay cookie, fetch IAM
     creds, etc.)
  3. If successful with new captured impact: emit a new finding
     via the standard tracer + capture proof; return
     `PivotResult(outcome="pivoted", emitted_finding_id=...)`
  4. If the pivot didn't materialise impact: return
     `PivotResult(outcome="dead_end")` — chain terminates here

## Bounds (defence against runaway chains)

  * `max_depth` — caps the longest chain (default 3)
  * `pivot_budget` — caps total specialists dispatched per source
    finding (default 5)
  * `STRIX_PIVOT_ORCHESTRATOR_DISABLED=1` — global kill switch;
    `run_pivot_chain()` returns an empty result without dispatching

## What this module is NOT

  * Not a replacement for `specialist_orchestrator` — that handles
    the BFS over an asset's attack surface (Discover → Verify →
    Exploit). Pivot orchestrator only fires AFTER `exploited` lands.
  * Not a CVE→exploit synthesiser (that's depth gap #3 / MOAK-style).
  * Not the report-time narrative chainer (that's `chaining_graph`).
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Literal


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bounds + kill switch
# ---------------------------------------------------------------------------


DEFAULT_MAX_DEPTH = 3
DEFAULT_PIVOT_BUDGET = 5


def _kill_switched() -> bool:
    return os.environ.get("STRIX_PIVOT_ORCHESTRATOR_DISABLED") == "1"


# ---------------------------------------------------------------------------
# Specialist contract
# ---------------------------------------------------------------------------


PivotOutcome = Literal["pivoted", "dead_end", "error", "skipped"]


@dataclass
class PivotResult:
    """Structured outcome of one specialist's attempt to pivot
    from a captured proof-of-impact."""
    outcome: PivotOutcome
    specialist_name: str = ""
    detail: str = ""
    # When outcome == "pivoted": id of the new finding the
    # specialist emitted (must itself be `exploited` with
    # proof_artifact_path set). The orchestrator wires this up to
    # the source finding via a PIVOTED_FROM edge in the KG.
    emitted_finding_id: str | None = None
    elapsed_seconds: float = 0.0


PivotFn = Callable[..., PivotResult]


# ---------------------------------------------------------------------------
# Playbook registry
# ---------------------------------------------------------------------------


# Process-global, thread-safe. Two maps:
#   * `_specialists` — name → callable, populated by @register_pivot
#   * `_playbook`   — impact_type → ordered list of specialist names
# The order in the playbook is the order the orchestrator will try
# them in. Specialists earlier in the list should be the
# higher-yield / lower-cost ones.
_specialists: dict[str, PivotFn] = {}
_playbook: dict[str, list[str]] = {}
_registry_lock = threading.RLock()


def register_pivot(
    *,
    name: str,
    impact_types: list[str],
) -> Callable[[PivotFn], PivotFn]:
    """Decorator. Registers a pivot specialist + adds it to the
    playbook entries for every impact_type that triggers it.

    Example:
      ```python
      @register_pivot(
          name="cookie_replay_admin_probe",
          impact_types=["cookie_theft"],
      )
      def cookie_replay_admin_probe(*, source_finding, target_context):
          ...
      ```

    A specialist can be registered for multiple impact types
    when one captured artifact has multiple onward paths
    (e.g. `auth_bypass_session` and `cookie_theft` both unlock
    admin-endpoint probing).
    """
    def decorator(fn: PivotFn) -> PivotFn:
        with _registry_lock:
            _specialists[name] = fn
            for impact in impact_types:
                # Append-only — keep registration order so the
                # earliest-registered pivot fires first.
                if name not in _playbook.setdefault(impact, []):
                    _playbook[impact].append(name)
        return fn
    return decorator


def lookup_playbook(impact_type: str) -> list[str]:
    """Return the ordered list of specialist names registered for
    one impact type. Empty list when nothing is registered."""
    with _registry_lock:
        return list(_playbook.get(impact_type, []))


def reset_for_testing() -> None:
    """Clear both registry + playbook. Tests only."""
    with _registry_lock:
        _specialists.clear()
        _playbook.clear()


# ---------------------------------------------------------------------------
# Impact-type extraction from proof_artifact_path
# ---------------------------------------------------------------------------


def _impact_type_from_proof_path(path: str | None) -> str | None:
    """The `proof_of_impact` helper writes artifacts as
    `<fingerprint>.<impact_type>.bin`. We extract the
    impact_type from the filename so the orchestrator doesn't
    need a separate finding field for it."""
    if not path or not isinstance(path, str):
        return None
    name = path.rsplit("/", 1)[-1]
    # name shape: "<fp>.<impact_type>.bin"
    parts = name.split(".")
    if len(parts) < 3:
        return None
    # impact_type is the second-to-last segment (right before .bin)
    return parts[-2]


# ---------------------------------------------------------------------------
# KG provenance edge
# ---------------------------------------------------------------------------


def _record_pivot_edge(
    *, source_finding_id: str, target_finding_id: str,
) -> None:
    """Drop a `PIVOTED_FROM` edge in the KG (target → source). Fail-
    open: any failure logs + continues. The orchestrator's result
    is the authoritative chain record; the KG edge is the queryable
    view of it."""
    try:
        from strix.agents import knowledge_graph as kg

        graph = kg.get_kg()
        source_vuln = None
        target_vuln = None
        for node in graph.query_nodes(type="Vuln"):
            fid = node.props.get("finding_id")
            if fid == source_finding_id:
                source_vuln = node
            elif fid == target_finding_id:
                target_vuln = node
            if source_vuln is not None and target_vuln is not None:
                break

        if source_vuln is None or target_vuln is None:
            logger.debug(
                "pivot_orchestrator: missing Vuln node(s) for "
                "PIVOTED_FROM edge — source=%s target=%s",
                source_finding_id, target_finding_id,
            )
            return

        graph.add_edge(
            type="PIVOTED_FROM",
            source=target_vuln.id,
            target=source_vuln.id,
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "pivot_orchestrator: PIVOTED_FROM edge write failed",
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# Orchestrator entry point
# ---------------------------------------------------------------------------


@dataclass
class PivotChainOutcome:
    """Top-level result of `run_pivot_chain` — one entry per
    specialist invocation, in attempt order."""
    source_finding_id: str
    impact_type: str | None
    specialists_attempted: list[PivotResult] = field(default_factory=list)
    chain_terminated_reason: str = ""

    @property
    def emitted_finding_ids(self) -> list[str]:
        """The findings that materialised from this chain."""
        return [
            r.emitted_finding_id for r in self.specialists_attempted
            if r.outcome == "pivoted" and r.emitted_finding_id
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_finding_id": self.source_finding_id,
            "impact_type": self.impact_type,
            "specialists_attempted": [
                {
                    "specialist_name": r.specialist_name,
                    "outcome": r.outcome,
                    "detail": r.detail,
                    "emitted_finding_id": r.emitted_finding_id,
                    "elapsed_seconds": r.elapsed_seconds,
                }
                for r in self.specialists_attempted
            ],
            "emitted_finding_ids": list(self.emitted_finding_ids),
            "chain_terminated_reason": self.chain_terminated_reason,
        }


def run_pivot_chain(
    *,
    source_finding: dict[str, Any],
    target_context: dict[str, Any] | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    pivot_budget: int = DEFAULT_PIVOT_BUDGET,
    _depth: int = 1,
) -> PivotChainOutcome:
    """Run the post-exploit pivot chain rooted at `source_finding`.

    Args:
        source_finding: a canonical finding dict. MUST have
            `verification_status='exploited'` AND
            `proof_artifact_path` set — those are the entry
            conditions for the orchestrator. Anything else
            short-circuits with `chain_terminated_reason`.
        target_context: optional `{asset_id, surface_url, auth, ...}`
            block describing where the target lives. Passed verbatim
            to each specialist; specialists own the interpretation.
        max_depth: max recursive depth (chain length). Default 3 —
            enough for the canonical "XSS → cookie → admin-endpoint"
            shape without unbounded recursion.
        pivot_budget: max specialists dispatched per source finding.
            Default 5 — prevents a single source from spawning every
            registered specialist when only the top-ranked one is
            likely to land.
        _depth: internal — current recursion depth. Don't pass.

    Returns:
        `PivotChainOutcome` with one `PivotResult` per specialist
        attempted, in attempt order, plus the list of finding IDs
        the chain produced.
    """
    source_id = source_finding.get("id", "")
    target_context = target_context or {}

    # ---- Entry guards ----
    if _kill_switched():
        return PivotChainOutcome(
            source_finding_id=source_id, impact_type=None,
            chain_terminated_reason="kill_switch",
        )

    vs = (source_finding.get("verification_status") or "").strip().lower()
    if vs != "exploited":
        return PivotChainOutcome(
            source_finding_id=source_id, impact_type=None,
            chain_terminated_reason=(
                f"source verification_status={vs!r} — pivot only runs "
                f"on `exploited` findings"
            ),
        )

    proof_path = source_finding.get("proof_artifact_path")
    impact_type = _impact_type_from_proof_path(proof_path)
    if impact_type is None:
        return PivotChainOutcome(
            source_finding_id=source_id, impact_type=None,
            chain_terminated_reason=(
                "no impact_type derivable from proof_artifact_path — "
                "scanner emitted `exploited` without a parseable "
                "proof artifact filename"
            ),
        )

    if _depth > max_depth:
        return PivotChainOutcome(
            source_finding_id=source_id, impact_type=impact_type,
            chain_terminated_reason=f"max_depth={max_depth} reached",
        )

    playbook = lookup_playbook(impact_type)
    if not playbook:
        return PivotChainOutcome(
            source_finding_id=source_id, impact_type=impact_type,
            chain_terminated_reason=(
                f"no pivot specialists registered for impact_type={impact_type!r}"
            ),
        )

    # ---- Dispatch loop ----
    outcome = PivotChainOutcome(
        source_finding_id=source_id, impact_type=impact_type,
    )
    dispatched = 0
    for specialist_name in playbook:
        if dispatched >= pivot_budget:
            outcome.chain_terminated_reason = (
                f"pivot_budget={pivot_budget} exhausted "
                f"after {dispatched} specialist(s)"
            )
            break
        with _registry_lock:
            fn = _specialists.get(specialist_name)
        if fn is None:
            # Registered name without callable — defensive; should
            # not happen given the registration pattern.
            outcome.specialists_attempted.append(PivotResult(
                outcome="error",
                specialist_name=specialist_name,
                detail="specialist not found in registry",
            ))
            continue

        try:
            result = fn(
                source_finding=source_finding,
                target_context=target_context,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "pivot_orchestrator: specialist %s raised",
                specialist_name, exc_info=True,
            )
            outcome.specialists_attempted.append(PivotResult(
                outcome="error",
                specialist_name=specialist_name,
                detail=f"specialist raised: {type(exc).__name__}: {exc}",
            ))
            dispatched += 1
            continue

        # Normalise the specialist's reported name (defence — they
        # might forget to set it on the result).
        if not result.specialist_name:
            result.specialist_name = specialist_name
        outcome.specialists_attempted.append(result)
        dispatched += 1

        if (
            result.outcome == "pivoted"
            and result.emitted_finding_id
        ):
            _record_pivot_edge(
                source_finding_id=source_id,
                target_finding_id=result.emitted_finding_id,
            )

    if not outcome.chain_terminated_reason:
        outcome.chain_terminated_reason = "playbook_exhausted"

    return outcome
