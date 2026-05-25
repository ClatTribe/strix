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


# iter-33.4 — chain-kind → next-exploit-step prompt map.
# When mid_scan_correlate promotes a chain, this attaches a
# `next_exploit_step` directive on the parent finding so the L2
# Lead's next `list_pending_findings()` sees a concrete action
# rather than just an elevated severity.
#
# The strings are generic per chain kind — no SUT-specific paths /
# identifiers. They tell the LLM WHAT exploitation pattern to try
# next, not the exact URL.
_CHAIN_KIND_TO_NEXT_STEPS: dict[str, str] = {
    "heuristic_privilege_escalation_chain": (
        "Chain detected: auth-bypass + authz-missing. "
        "Next exploit step: (1) use the auth-bypass to obtain a session "
        "(default creds / forged JWT / etc.), (2) hit the authz-missing "
        "endpoint with that session, (3) enumerate admin-only resources "
        "the broken-authz endpoint exposes. Tier-3+ challenges typically "
        "land here — admin-panel access, role escalation, data dump."
    ),
    "heuristic_credential_extraction_chain": (
        "Chain detected: injection + credential exposure. "
        "Next exploit step: (1) confirm the injection extracts the "
        "credential material visible in the disclosure finding, "
        "(2) attempt to authenticate as another user with the extracted "
        "secret, (3) probe whether the credential unlocks higher-privilege "
        "paths (admin panel, mass-data endpoints). Tier-4+ challenges "
        "often hide here."
    ),
    "heuristic_data_exfil_chain": (
        "Chain detected: injection + data-read-without-auth. "
        "Next exploit step: (1) chain the injection to enumerate IDs "
        "the unprotected endpoint accepts, (2) iterate ID ranges to "
        "exfiltrate the full dataset, (3) check if any record holds "
        "secrets / tokens that would extend the chain. Tier-4+ "
        "challenges including 'dump all users' / 'dump all orders'."
    ),
    "heuristic_bola_at_scale_chain": (
        "Chain detected: BOLA/IDOR + weak auth token. "
        "Next exploit step: (1) forge JWTs / sessions for arbitrary "
        "user IDs using the weak-token finding, (2) sweep the IDOR "
        "endpoint across the forged-user ID space, (3) extract "
        "per-user objects (baskets, orders, profile data). Tier-5+ "
        "'mass account takeover' challenges hide here."
    ),
    # Strict-match chain kinds (existing linkers) — generic guidance.
    "sca_sast_dast": (
        "Chain detected: SCA + SAST + DAST agreement on same CWE. "
        "Next: re-verify the DAST PoC against the patched-dependency "
        "version (confirm regression) and capture proof artifact."
    ),
    "sast_dast": (
        "Chain detected: SAST + DAST agreement on same CWE+endpoint. "
        "Next: capture the SAST hint (file:line + variable) and use it "
        "to craft a more precise DAST payload."
    ),
    "iac_dast": (
        "Chain detected: IaC misconfig + DAST finding. "
        "Next: confirm the misconfig is the proximate cause of the "
        "runtime finding; remediation is at infra layer, not app."
    ),
}

# Default fallback for unmapped chain kinds.
_DEFAULT_NEXT_STEP = (
    "Chain detected — multiple findings on the same target share a "
    "common attack surface. Next: try combining the exploit primitives "
    "into a multi-step PoC (e.g. exploit A to enable exploit B's "
    "preconditions), or use the chain's parent severity as a priority "
    "signal for which path to deepen."
)


def _next_step_for_kind(kind: str | None) -> str:
    """Return the iter-33.4 next-exploit-step prompt for a chain kind.

    `kind` is the `link_type` constant (or chain_type aggregate) that
    fired the chain. Falls back to `_DEFAULT_NEXT_STEP` for unmapped
    kinds — better to nudge than to stay silent.
    """
    if not isinstance(kind, str):
        return _DEFAULT_NEXT_STEP
    return _CHAIN_KIND_TO_NEXT_STEPS.get(kind, _DEFAULT_NEXT_STEP)


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
    chain_kind = (
        getattr(chain, "kind", None)
        or getattr(chain, "label", None)
        or getattr(chain, "chain_type", None)
        or "chain"
    )

    old_sev = parent.get("severity") or "info"
    new_sev = _bump_severity(old_sev)
    parent["severity"] = new_sev
    # iter-33.4 — surface the next exploit step on the chain_summary
    # so the L2 Lead's next list_pending_findings() call sees not just
    # an elevated severity but a concrete action prompt.
    next_step = _next_step_for_kind(chain_kind)
    parent["chain_summary"] = {
        "chain_id": chain_id,
        "kind": chain_kind,
        "members": member_ids,
        "promoted_at_phase": to_phase,
        "next_exploit_step": next_step,  # iter-33.4
    }
    trace = parent.get("reasoning_trace") or []
    if isinstance(trace, str):
        trace = [trace]
    parent["reasoning_trace"] = list(trace) + [
        f"l1.5 (mid-scan correlate at {to_phase}): chained with "
        f"{len(member_ids) - 1} other finding(s) → severity bumped "
        f"{old_sev} → {new_sev}",
        # iter-33.4 — re-prompt the agent with the concrete next step.
        # Reasoning_trace is rendered to the LLM via list_pending_findings,
        # so this text becomes part of the next-turn context.
        f"l1.5 (iter-33.4 next-step): {next_step}",
    ]
    return 1
