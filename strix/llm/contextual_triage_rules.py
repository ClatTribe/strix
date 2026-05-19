"""Contextual triage rules (R9 + R10) — MA-S2 P0-APM-B.

## Why this exists

MA-S2 APM-1.3 is the single highest-leverage MA-S2 control:

> "A Critical CVE in a component that is not reachable from any
>  external attack surface may be appropriately deprioritized.
>  A Medium CVE in a component that is the first link in a
>  traversable attack path to a privileged credential store must
>  be treated as urgent."

This module ships the two rules that operationalize APM-1.3 on
top of:
  * The `contextual_priority` block (P0-CVS-B) — gives us
    `reachability.verdict` + `raw_severity`.
  * The `attack_paths.jsonl` artefact (P0-APM-A) — gives us the
    `attack_path_membership` for each finding.

## Rules

### R9 — unreachable_high_downgrade

Fires when ALL of:
  * `reachability.verdict == "unreachable"`
  * `raw_severity` ∈ {high, critical}
  * `attack_path_membership` is empty (not part of any chain)

Action: downgrade `priority_tier` to `p4_suppressible`.

Recall safety: the SAST/SCA/DAST reachability layer MUST report
`"unreachable"` deliberately — `"unknown"` does NOT trigger R9.
We never downgrade based on absence of evidence.

### R10 — chain_first_link_upgrade

Fires when ALL of:
  * `attack_path_membership` is non-empty (finding is in ≥1 chain)
  * AT LEAST one of those chains has `max_severity == critical`
  * The finding is the **first stage** (step=1) of that chain

Action: upgrade `priority_tier` to `p0_emergency`.

Recall safety: UPGRADE only — never DROP. If R10 fires on a
finding that R9 also wants to downgrade, R10 wins (the chain
context overrides the per-finding unreachability heuristic;
the chain demonstrates exploitability that the per-finding
reachability check missed).

## Doctrine — preserved across the boundary

R9/R10 mutate ONLY `contextual_priority.priority_tier`. They
do NOT touch `raw_cvss`, `raw_severity`, `max_chained_severity`,
or any other engine signal. The two-signal layering invariant
from webappsec/ma-s2-proposal.md §4 holds.

## Kill switch

`STRIX_CONTEXTUAL_TRIAGE_DISABLED=1` skips both rules entirely.
The contextual_priority block from P0-CVS-B is the final
authority.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


_HIGH_TIER = {"high", "critical"}


def is_disabled() -> bool:
    return os.environ.get(
        "STRIX_CONTEXTUAL_TRIAGE_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def rule_r9_unreachable_high_downgrade(
    *, contextual_priority: dict[str, Any],
) -> str | None:
    """R9 — return the new priority_tier when the rule fires;
    None when it doesn't.

    Conservative: requires reachability.verdict == 'unreachable'
    explicitly (not 'unknown'). We never downgrade based on
    absence of evidence."""
    cp = contextual_priority or {}
    reach = cp.get("reachability") or {}
    verdict = (reach.get("verdict") or "").strip().lower()
    if verdict != "unreachable":
        return None
    sev = (cp.get("raw_severity") or "").strip().lower()
    if sev not in _HIGH_TIER:
        return None
    membership = cp.get("attack_path_membership") or []
    if isinstance(membership, list) and len(membership) > 0:
        # Finding IS in a chain — R10's domain, not R9's.
        return None
    return "p4_suppressible"


def rule_r10_chain_first_link_upgrade(
    *, contextual_priority: dict[str, Any],
    finding_id: str | None,
    attack_paths: list[dict[str, Any]],
) -> str | None:
    """R10 — return `p0_emergency` when the finding is the first
    stage of a critical-severity chain.

    `attack_paths` is the loaded list of paths from
    attack_paths.jsonl. Each path has `stages[]` and
    `max_severity`."""
    if not finding_id:
        return None
    cp = contextual_priority or {}
    membership = cp.get("attack_path_membership") or []
    if not membership:
        # Not in any chain — can't upgrade via chain context.
        # (Note: P0-APM-A doesn't populate attack_path_membership
        # automatically yet; the applier below derives it from
        # the loaded paths file.)
        pass
    for path in attack_paths or []:
        if not isinstance(path, dict):
            continue
        if (path.get("max_severity") or "").lower() != "critical":
            continue
        stages = path.get("stages") or []
        if not isinstance(stages, list) or not stages:
            continue
        first = stages[0]
        if not isinstance(first, dict):
            continue
        if (first.get("step") == 1
                and first.get("finding_id") == finding_id):
            return "p0_emergency"
    return None


def _membership_for_finding(
    finding_id: str | None, attack_paths: list[dict[str, Any]],
) -> list[str]:
    """Compute the attack_path_membership list for a finding by
    walking the loaded paths. This is what P0-APM-A's
    `attack_path_membership` field on contextual_priority is
    supposed to carry — we derive it here at scan completion."""
    if not finding_id:
        return []
    out: list[str] = []
    for path in attack_paths or []:
        if not isinstance(path, dict):
            continue
        for stage in (path.get("stages") or []):
            if isinstance(stage, dict) and stage.get("finding_id") == finding_id:
                pid = path.get("id")
                if isinstance(pid, str) and pid and pid not in out:
                    out.append(pid)
                break
    return out


def _max_chained_severity_for_finding(
    finding_id: str | None, attack_paths: list[dict[str, Any]],
) -> str | None:
    """Worst-case severity across all chains containing the
    finding."""
    if not finding_id:
        return None
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    inv = {v: k for k, v in rank.items()}
    best = -1
    for path in attack_paths or []:
        if not isinstance(path, dict):
            continue
        if not any(
            isinstance(s, dict) and s.get("finding_id") == finding_id
            for s in (path.get("stages") or [])
        ):
            continue
        sev = (path.get("max_severity") or "").lower()
        r = rank.get(sev, -1)
        if r > best:
            best = r
    return inv.get(best) if best >= 0 else None


def load_attack_paths(run_dir: Path) -> list[dict[str, Any]]:
    """Read attack_paths.jsonl from the run dir. Returns an empty
    list when the file doesn't exist / is unparseable — never
    raises."""
    f = run_dir / "attack_paths.jsonl"
    if not f.exists():
        return []
    out: list[dict[str, Any]] = []
    try:
        with f.open(encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if isinstance(rec, dict):
                        out.append(rec)
                except json.JSONDecodeError:
                    continue
    except OSError as e:
        logger.debug("attack_paths.jsonl read failed: %s", e)
        return []
    return out


def apply_contextual_triage_rules(
    *,
    findings: list[dict[str, Any]],
    attack_paths: list[dict[str, Any]],
) -> dict[str, int]:
    """Apply R9 + R10 to every finding in `findings`.

    Mutates `contextual_priority.priority_tier` in place. Also
    populates `attack_path_membership` + `max_chained_severity`
    from `attack_paths` (the chain-membership data wasn't
    available at emit time — only at scan completion when the
    paths file is finalized).

    Returns a stats dict: {r9_downgrades: int, r10_upgrades: int}.

    Recall safety:
      * R10 always wins when both rules want to fire (chain
        context overrides per-finding unreachability).
      * Kill switch short-circuits to zero applications.
      * Per-finding failures don't propagate — the rest of the
        findings still process.
    """
    stats = {"r9_downgrades": 0, "r10_upgrades": 0}
    if is_disabled() or not isinstance(findings, list):
        return stats

    for f in findings:
        if not isinstance(f, dict):
            continue
        try:
            cp = f.get("contextual_priority") or {}
            if not isinstance(cp, dict):
                continue
            finding_id = f.get("id")

            # First — backfill attack_path_membership +
            # max_chained_severity from the loaded paths. The
            # contextual_priority builder couldn't do this at
            # emit time (paths aren't built yet).
            membership = _membership_for_finding(finding_id, attack_paths)
            if membership:
                cp["attack_path_membership"] = membership
                worst = _max_chained_severity_for_finding(
                    finding_id, attack_paths,
                )
                if worst:
                    cp["max_chained_severity"] = worst

            # R10 first — upgrades always win.
            r10_tier = rule_r10_chain_first_link_upgrade(
                contextual_priority=cp,
                finding_id=finding_id,
                attack_paths=attack_paths,
            )
            if r10_tier:
                cp["priority_tier"] = r10_tier
                stats["r10_upgrades"] += 1
                continue

            # R9 — only if R10 didn't fire.
            r9_tier = rule_r9_unreachable_high_downgrade(
                contextual_priority=cp,
            )
            if r9_tier:
                cp["priority_tier"] = r9_tier
                stats["r9_downgrades"] += 1
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "contextual triage rule application failed for finding %s: %s",
                f.get("id"), e,
            )
            continue
    return stats
