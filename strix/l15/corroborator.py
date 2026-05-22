"""iter-25.3 — mid-scan corroborator (Gap 2 in docs/L2-optimization.md).

A real security engineer reads three findings of the same CWE on the
same surface from three different tools (e.g. SAST + DAST + SBOM) and
mentally stacks them into ONE critical finding with very high
confidence. Strix today emits them as three separate medium-severity
findings; ``correlate_findings`` would build the chain only at the
post-scan step.

This module runs at finding-emission time. For each new finding it
checks: do I already have ≥1 *different-source* finding for the same
(CWE, surface) tuple? If yes, this new finding is the corroborator and
we should:

  1. Promote the FIRST (parent) finding's severity to ``critical``,
     attach a ``corroborated_by`` list referencing this new finding +
     any prior sibling ids.
  2. Demote the new finding (and any prior siblings) to ``info`` with
     a ``role: corroborator`` flag so the LLM doesn't waste cycles on
     it independently.

Stable identity = parent (the first finding emitted for a given tuple
this run); subsequent ones are corroborators that boost the parent.

Two findings from the **same source** never trigger promotion — that's
not corroboration, that's duplication (handled by Gap 5 root-cause
collapse).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Literal


logger = logging.getLogger(__name__)


_PROMOTE_TIER = {
    "info": "low",
    "informational": "low",
    "low": "medium",
    "medium": "high",
    "high": "critical",
    "critical": "critical",
}


CorroboratorAction = Literal["nothing", "register_parent", "boost_parent"]


@dataclass(frozen=True)
class CorroboratorDecision:
    """Outcome of mid-scan corroborator pass.

    * ``nothing`` — first or only finding for this (CWE, surface);
      no parent yet. Caller emits as-is and the ledger records the
      finding id as the (potential future) parent.
    * ``register_parent`` — same as ``nothing`` (alias).
    * ``boost_parent`` — at least one prior different-source finding
      exists for this tuple. Caller should:
        1. Promote the parent's severity to ``new_parent_severity``
        2. Append this new finding's id to the parent's
           ``corroborated_by[]``
        3. Demote this new finding to ``info`` with
           ``role=corroborator`` and ``corroborates=parent_id``
    """
    action: CorroboratorAction
    parent_id: str | None = None
    new_parent_severity: str | None = None
    trace_line: str | None = None
    prior_sibling_ids: tuple[str, ...] = ()


@dataclass
class _ParentRecord:
    finding_id: str
    cwe: str
    surface: str
    sources: set[str] = field(default_factory=set)
    siblings: list[str] = field(default_factory=list)
    boosted: bool = False


def _surface_key(finding: dict[str, Any]) -> str:
    """Best-effort identifier for the 'thing under test'.

    A URL takes priority (DAST scope); falls back to file path (SAST /
    SCA / IaC scope). Two findings with empty surface still bucket
    together so we don't accidentally cross-correlate unrelated dead
    findings.
    """
    endpoint = finding.get("endpoint") or finding.get("url")
    if isinstance(endpoint, str) and endpoint.strip():
        # Strip query string — same path with different ?q= is still
        # the same surface for corroboration purposes.
        return endpoint.strip().split("?", 1)[0].lower()
    code_locs = finding.get("code_locations") or []
    if isinstance(code_locs, list) and code_locs:
        first = code_locs[0]
        if isinstance(first, dict):
            p = first.get("file") or first.get("path")
            if isinstance(p, str) and p.strip():
                return p.strip().lower()
    for key in ("file", "path", "target"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
    return ""


def _cwe_key(finding: dict[str, Any]) -> str:
    cwe = finding.get("cwe")
    if isinstance(cwe, str):
        c = cwe.strip().upper()
        # Normalise "CWE-89", "cwe:89", "89" → "CWE-89"
        if c.startswith("CWE:"):
            c = "CWE-" + c[4:]
        elif c.isdigit():
            c = "CWE-" + c
        return c
    return ""


def _source_key(finding: dict[str, Any]) -> str:
    """The tool that produced this finding.

    For corroboration we care about *cross-tool* agreement, so two
    findings from the same tool (e.g. semgrep firing on two rules) do
    not corroborate. Pull source from ``discovery_source_tool`` first
    (set by sandbox specialists), then check the nested
    ``discovery_method.source_tool`` (the tracer wraps the flat arg
    into this nested block at emission), then fall back to ``tool`` /
    ``source`` / the rule_id prefix.
    """
    for key in ("discovery_source_tool", "tool", "source"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
    dm = finding.get("discovery_method")
    if isinstance(dm, dict):
        v = dm.get("source_tool")
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
    rid = finding.get("rule_id") or finding.get("check_id")
    if isinstance(rid, str) and rid.strip():
        # `nuclei-` / `semgrep:` / `trivy-` prefixes are stable
        first = rid.split("-", 1)[0].split(":", 1)[0]
        if first:
            return first.lower()
    return "unknown"


class CorroboratorLedger:
    """Process-local (CWE, surface) → parent ledger.

    Tests call ``corroborator_ledger.clear()`` between cases.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._parents: dict[tuple[str, str], _ParentRecord] = {}

    def clear(self) -> None:
        with self._lock:
            self._parents.clear()

    def check(
        self,
        finding: dict[str, Any],
        *,
        proposed_finding_id: str,
    ) -> CorroboratorDecision:
        """Decide whether this finding boosts an existing parent."""
        try:
            cwe = _cwe_key(finding)
            surface = _surface_key(finding)
            source = _source_key(finding)
            if not cwe or not surface:
                return CorroboratorDecision(action="nothing")

            key = (cwe, surface)
            with self._lock:
                parent = self._parents.get(key)
                if parent is None:
                    # First finding for this tuple — register and pass.
                    self._parents[key] = _ParentRecord(
                        finding_id=proposed_finding_id,
                        cwe=cwe,
                        surface=surface,
                        sources={source},
                    )
                    return CorroboratorDecision(action="register_parent")

                # Same source as the parent OR already-seen source →
                # not corroboration, just duplication. Skip.
                if source in parent.sources:
                    parent.siblings.append(proposed_finding_id)
                    return CorroboratorDecision(action="nothing")

                # Different source → corroboration!
                parent.sources.add(source)
                parent.siblings.append(proposed_finding_id)

                # Severity bump for parent (idempotent — only the
                # first cross-source corroboration drives the bump,
                # subsequent ones extend the corroborated_by list).
                sev = (finding.get("severity") or "").lower().strip()
                if not parent.boosted:
                    parent.boosted = True
                    # Bump one tier from whatever the parent's effective
                    # severity was. We use the new finding's severity
                    # as a proxy when the parent's severity isn't
                    # available to the ledger (this is fine because the
                    # CALLER applies the bump based on the parent dict
                    # they own).
                    new_sev = _PROMOTE_TIER.get(sev, "critical")
                else:
                    # Already-corroborated parents stay where they are;
                    # we just attach the new sibling id.
                    new_sev = None

                return CorroboratorDecision(
                    action="boost_parent",
                    parent_id=parent.finding_id,
                    new_parent_severity=new_sev,
                    prior_sibling_ids=tuple(parent.siblings[:-1]),
                    trace_line=(
                        f"l1.5: corroborated by {source} on {cwe}@{surface} "
                        f"— promoted parent {parent.finding_id} severity"
                        if new_sev
                        else (
                            f"l1.5: additional corroboration from {source} on "
                            f"{cwe}@{surface}"
                        )
                    ),
                )
        except Exception as e:  # noqa: BLE001
            logger.debug("corroborator_ledger check failed: %s — nothing", e)
            return CorroboratorDecision(action="nothing")


# Module-level singleton.
corroborator_ledger = CorroboratorLedger()
