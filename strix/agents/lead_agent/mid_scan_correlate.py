"""iter-27.2 — mid-scan correlate at phase boundaries.

The existing `correlate_findings` tool runs once at the end of the
scan (the report phase) to synthesize attack chains. By then most
follow-up dispatches have already happened. The L2-iter-26 proposal
§4 (Gap 9) called this out: chains are most useful when fed back into
the Lead's planning DURING the scan, not after it.

This module runs `correlate_findings` automatically at each
workflow phase boundary. When a transition produces new chains:

  * The parent finding of each chain is bumped one severity tier.
  * A `chain_summary` block is attached: `{chain_id, kind, members[]}`.
  * A `reasoning_trace` line is appended explaining the boost.

L2 then sees these elevated findings on its next
`list_pending_findings()` call — the deterministic specialist
dispatch picks them up first.

Recall-safe: any internal exception logs + returns 0 chains.
Phase transitions never fail because of correlator errors.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger(__name__)


# Severity promotion table for newly-chained findings. Same one
# used by the corroborator (kept duplicate to avoid an import cycle).
_PROMOTE_TIER: dict[str, str] = {
    "info": "low",
    "informational": "low",
    "low": "medium",
    "medium": "high",
    "high": "critical",
    "critical": "critical",
}


@dataclass(frozen=True)
class PhaseCorrelationResult:
    """One mid-scan correlator invocation outcome."""
    from_phase: str
    to_phase: str
    chains_built: int
    new_chains: int
    findings_promoted: int
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_phase": self.from_phase,
            "to_phase": self.to_phase,
            "chains_built": self.chains_built,
            "new_chains": self.new_chains,
            "findings_promoted": self.findings_promoted,
            "error": self.error,
        }


# Track which chain IDs we've already processed so re-invocation
# at later phase boundaries doesn't double-promote the same chain.
_lock = threading.RLock()
_seen_chain_ids: set[str] = set()


def clear_seen_chain_cache() -> None:
    """Wipe the per-scan seen-chain cache. Tests use this between cases."""
    with _lock:
        _seen_chain_ids.clear()


def _bump_severity(current: str | None) -> str:
    return _PROMOTE_TIER.get((current or "info").lower().strip(), "info")


def correlate_at_phase_boundary(
    from_phase: str, to_phase: str,
    *, min_chain_size: int = 2,
) -> PhaseCorrelationResult:
    """Build attack chains across all findings emitted so far; promote
    parents of NEW chains; return a result summary.

    Args:
        from_phase: phase we're leaving.
        to_phase: phase we're entering.
        min_chain_size: smallest chain we promote on (default 2 —
            single-finding "chains" are just the finding itself).

    Returns:
        ``PhaseCorrelationResult`` — never raises.
    """
    try:
        from strix.finding_chains import build_chains, normalise_findings
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return PhaseCorrelationResult(
                from_phase=from_phase, to_phase=to_phase,
                chains_built=0, new_chains=0, findings_promoted=0,
                error="tracer not initialised",
            )

        raw = list(getattr(tracer, "vulnerability_reports", []) or [])
        if len(raw) < min_chain_size:
            return PhaseCorrelationResult(
                from_phase=from_phase, to_phase=to_phase,
                chains_built=0, new_chains=0, findings_promoted=0,
            )

        findings = normalise_findings(raw)
        chains = build_chains(findings, min_chain_size=min_chain_size)
        if not chains:
            return PhaseCorrelationResult(
                from_phase=from_phase, to_phase=to_phase,
                chains_built=0, new_chains=0, findings_promoted=0,
            )

        promoted = 0
        new_chains_count = 0
        with _lock:
            for ch in chains:
                cid = getattr(ch, "id", None) or getattr(ch, "chain_id", None)
                if not cid:
                    continue
                if cid in _seen_chain_ids:
                    continue
                _seen_chain_ids.add(cid)
                new_chains_count += 1
                promoted += _promote_chain_parent(tracer, ch, to_phase)

        return PhaseCorrelationResult(
            from_phase=from_phase, to_phase=to_phase,
            chains_built=len(chains),
            new_chains=new_chains_count,
            findings_promoted=promoted,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("mid-scan correlate failed: %s", e)
        return PhaseCorrelationResult(
            from_phase=from_phase, to_phase=to_phase,
            chains_built=0, new_chains=0, findings_promoted=0,
            error=f"{type(e).__name__}: {e}",
        )


def _promote_chain_parent(
    tracer: Any, chain: Any, to_phase: str,
) -> int:
    """For a fresh chain, promote the first-member finding's severity
    one tier and attach a `chain_summary` block. Returns 1 if a
    finding was promoted, 0 otherwise (e.g. chain has no members the
    tracer can find)."""
    members = getattr(chain, "members", None) or getattr(chain, "findings", None)
    if not members:
        return 0
    # `members` is a list of Finding dataclasses or finding-id strings;
    # normalise to a list of IDs.
    member_ids: list[str] = []
    for m in members:
        fid = (
            getattr(m, "id", None)
            or getattr(m, "finding_id", None)
            or (m if isinstance(m, str) else None)
        )
        if isinstance(fid, str):
            member_ids.append(fid)
    if not member_ids:
        return 0

    # The parent we promote is the FIRST member (earliest emission).
    parent_id = member_ids[0]
    parent = next(
        (
            r for r in tracer.vulnerability_reports
            if r.get("id") == parent_id
        ),
        None,
    )
    if parent is None:
        return 0

    chain_id = getattr(chain, "id", None) or getattr(chain, "chain_id", None) or ""
    chain_kind = getattr(chain, "kind", None) or getattr(chain, "label", None) or "chain"

    old_sev = parent.get("severity") or "info"
    new_sev = _bump_severity(old_sev)
    parent["severity"] = new_sev
    parent["chain_summary"] = {
        "chain_id": chain_id,
        "kind": chain_kind,
        "members": member_ids,
        "promoted_at_phase": to_phase,
    }
    trace = parent.get("reasoning_trace") or []
    if isinstance(trace, str):
        trace = [trace]
    parent["reasoning_trace"] = list(trace) + [
        f"l1.5 (mid-scan correlate at {to_phase}): chained with "
        f"{len(member_ids) - 1} other finding(s) → severity bumped "
        f"{old_sev} → {new_sev}"
    ]
    return 1
