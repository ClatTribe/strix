"""Hypothesis-experiment-result loop (workitem.md Phase 5.1).

Adds the missing layer on top of `active_hypotheses` and
`decision_log` so the lead always picks the **highest-EV
unconfirmed hypothesis next** instead of freelancing. Surfaces
stuck-without-progress patterns so the lead can dismiss dead ends
and free attention budget.

What this module adds (vs. existing primitives)
------------------------------------------------

`active_hypotheses` already lets you `open_hypothesis` /
`confirm_hypothesis` / `dismiss_hypothesis`. `decision_log` records
every probe / signal / finding. Both are working stores. What's
missing is the **scheduling loop**:

  * `score_hypothesis(record)` — EV score combining
    severity-by-category, age, probe activity, surface specificity.
  * `pick_next_hypothesis()` — return the highest-EV `investigating`
    record. Lead calls this between probes to focus attention.
  * `find_stuck_hypotheses(min_age_seconds, min_probes)` — return
    records that have been investigating beyond a threshold without
    enough probe activity. Surfaces dead ends for dismissal.
  * `probes_for_hypothesis(hypothesis_id)` — walk `decision_log` for
    every probe / signal that linked to `hypothesis_id`.
  * `record_probe_for_hypothesis(...)` — wrapper around
    `record_decision` that auto-links the probe to a hypothesis.

EV score components
-------------------

Each `investigating` hypothesis gets a 0.0-1.0 score:

  * **category_severity** (0.5 weight) — categories with
    historically-critical findings (sqli, rce, deserialization,
    cmd_injection, ssrf, idor, xxe) score higher than info-level
    categories (csrf, weak-config).
  * **age_decay** (0.2 weight) — hypotheses opened recently score
    higher (0.0 after ~30 minutes); old hypotheses without progress
    are likely going to stay unconfirmed.
  * **probe_density** (0.2 weight) — hypotheses with at least one
    probe recorded score higher (someone's actively chasing).
  * **surface_specificity** (0.1 weight) — hypotheses with a fully-
    qualified surface (URL + param) score higher than handwave
    surfaces ("admin endpoints").

The weights are the starting point; future Phase 6.1 active-learning
tuning can adjust them based on hit/miss telemetry.

Best-effort throughout. None values, missing modules, malformed
records all degrade gracefully — never raise out of the loop.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


logger = logging.getLogger(__name__)


# Severity weights per category. Higher score = pick first.
_CATEGORY_SEVERITY: dict[str, float] = {
    "sqli": 1.0,
    "command_injection": 1.0,
    "deserialization": 1.0,
    "rce": 1.0,
    "auth_bypass": 1.0,
    "ssti": 0.95,
    "xxe": 0.9,
    "ssrf": 0.85,
    "path_traversal": 0.85,
    "idor": 0.85,
    "missing_auth": 0.85,
    "secrets_exposure": 0.8,
    "subdomain_takeover": 0.75,
    "nosql_injection": 0.75,
    "xpath_injection": 0.75,
    "ldap_injection": 0.7,
    "xss": 0.7,
    "open_redirect": 0.5,
    "clickjacking": 0.4,
    "csrf": 0.4,
    "csp": 0.3,
    "weak_config": 0.3,
}
_DEFAULT_SEVERITY = 0.5

# Age decay: 30 minutes to fall to ~0.0.
_AGE_HALF_LIFE_SECONDS = 30 * 60


# Default stuck threshold: if a hypothesis has been investigating
# for ≥10 minutes with 0-1 probes recorded, it's stuck.
_STUCK_AGE_SECONDS = 10 * 60
_STUCK_PROBE_THRESHOLD = 1


@dataclass
class StuckHypothesis:
    """A hypothesis flagged as `stuck` — investigated long enough
    without probe activity that it should be dismissed or
    re-prioritised."""
    hypothesis_id: str
    hypothesis: str
    surface: str
    age_seconds: float
    probes_recorded: int
    suggested_action: str = "dismiss_or_revisit"

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "hypothesis": self.hypothesis,
            "surface": self.surface,
            "age_seconds": self.age_seconds,
            "probes_recorded": self.probes_recorded,
            "suggested_action": self.suggested_action,
        }


def _parse_iso(ts: str | None) -> datetime | None:
    if not isinstance(ts, str):
        return None
    try:
        # Python 3.11+ accepts the `Z` suffix; older code may write it.
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _surface_specificity(surface: str | None) -> float:
    """How specific is the surface? URL + param > URL > handwave."""
    if not isinstance(surface, str) or not surface.strip():
        return 0.0
    s = surface.strip()
    # Has a URL?
    has_url = bool(re.search(r"https?://", s))
    # Has a param hint? Rough heuristic — `?xxx=` or `(param=`.
    has_param = bool(re.search(r"[?&]\w+=|\bparam=|\bin\s+`?\w", s))
    if has_url and has_param:
        return 1.0
    if has_url:
        return 0.7
    # Just a path (e.g. "/admin/login")?
    if s.startswith("/") and len(s) > 1:
        return 0.5
    return 0.2


def score_hypothesis(record: dict[str, Any], *,
                     probes_count: int | None = None,
                     now: datetime | None = None) -> float:
    """Compute the EV score (0.0-1.0) for one investigating
    hypothesis. Higher = pick sooner.

    `probes_count` may be passed by the caller to avoid an N+1 walk
    of decision_log when scoring many hypotheses at once.
    """
    if not isinstance(record, dict):
        return 0.0
    if record.get("status") != "investigating":
        # Resolved hypotheses don't compete for next-pick attention.
        return 0.0

    # 1. Category severity (0.5 weight).
    category = (record.get("category") or "").strip().lower()
    cat_score = _CATEGORY_SEVERITY.get(category, _DEFAULT_SEVERITY)

    # 2. Age decay (0.2 weight).
    opened_at = _parse_iso(record.get("opened_at"))
    if opened_at is None:
        age_score = 0.5
    else:
        now_ts = now or datetime.now(timezone.utc)
        age_seconds = max(0.0, (now_ts - opened_at).total_seconds())
        # Exponential-ish decay; 0 at age=0, ~0.0 at age=2*half_life.
        age_score = max(
            0.0,
            1.0 - (age_seconds / (_AGE_HALF_LIFE_SECONDS * 2)),
        )

    # 3. Probe density (0.2 weight).
    if probes_count is None:
        probes_count = _count_probes(record.get("hypothesis_id"))
    # Sigmoid-ish: 0 probes → 0.0; 1 → 0.5; 2+ → 0.8-1.0.
    probe_score = min(1.0, probes_count * 0.4)

    # 4. Surface specificity (0.1 weight).
    surface_score = _surface_specificity(record.get("surface"))

    return (
        0.5 * cat_score
        + 0.2 * age_score
        + 0.2 * probe_score
        + 0.1 * surface_score
    )


def _count_probes(hypothesis_id: str | None) -> int:
    """Walk decision_log for probes / signals that linked to this
    hypothesis."""
    if not hypothesis_id:
        return 0
    try:
        from strix.agents.decision_log import list_decisions
    except Exception:  # noqa: BLE001
        return 0
    try:
        decisions = list_decisions()
    except Exception:  # noqa: BLE001
        return 0
    n = 0
    for d in decisions:
        if d.kind not in ("probe", "signal", "specialist_invocation"):
            continue
        if d.links.get("hypothesis_id") == hypothesis_id:
            n += 1
    return n


def pick_next_hypothesis(
    *, only_category: str | None = None,
) -> dict[str, Any] | None:
    """Return the highest-EV `investigating` hypothesis. Returns
    None when no hypotheses are open."""
    try:
        from strix.agents.active_hypotheses import list_active_hypotheses
    except Exception:  # noqa: BLE001
        return None
    try:
        records = list_active_hypotheses(only_status="investigating")
    except Exception:  # noqa: BLE001
        return None
    if only_category:
        records = [
            r for r in records
            if (r.get("category") or "").lower() == only_category.lower()
        ]
    if not records:
        return None
    now = datetime.now(timezone.utc)
    scored = [
        (score_hypothesis(r, now=now), r)
        for r in records
    ]
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return scored[0][1]


def rank_hypotheses(
    *, top_n: int = 10,
) -> list[tuple[float, dict[str, Any]]]:
    """Return all investigating hypotheses sorted by EV score, with
    the score attached. Useful for the lead's `agent_self_audit`
    surface."""
    try:
        from strix.agents.active_hypotheses import list_active_hypotheses
    except Exception:  # noqa: BLE001
        return []
    try:
        records = list_active_hypotheses(only_status="investigating")
    except Exception:  # noqa: BLE001
        return []
    now = datetime.now(timezone.utc)
    scored = [
        (score_hypothesis(r, now=now), r)
        for r in records
    ]
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return scored[:top_n]


def find_stuck_hypotheses(
    *,
    min_age_seconds: float = _STUCK_AGE_SECONDS,
    max_probes: int = _STUCK_PROBE_THRESHOLD,
) -> list[StuckHypothesis]:
    """Return investigating hypotheses that are old AND have ≤
    `max_probes` probes recorded against them. These are stuck —
    the lead should dismiss them or re-prioritise."""
    try:
        from strix.agents.active_hypotheses import list_active_hypotheses
    except Exception:  # noqa: BLE001
        return []
    try:
        records = list_active_hypotheses(only_status="investigating")
    except Exception:  # noqa: BLE001
        return []
    out: list[StuckHypothesis] = []
    now = datetime.now(timezone.utc)
    for r in records:
        opened_at = _parse_iso(r.get("opened_at"))
        if opened_at is None:
            continue
        age = max(0.0, (now - opened_at).total_seconds())
        if age < min_age_seconds:
            continue
        probes = _count_probes(r.get("hypothesis_id"))
        if probes > max_probes:
            continue
        out.append(StuckHypothesis(
            hypothesis_id=str(r.get("hypothesis_id") or ""),
            hypothesis=str(r.get("hypothesis") or ""),
            surface=str(r.get("surface") or ""),
            age_seconds=age,
            probes_recorded=probes,
            suggested_action=(
                "dismiss" if probes == 0 else "deepen_or_dismiss"
            ),
        ))
    out.sort(key=lambda s: s.age_seconds, reverse=True)
    return out


def probes_for_hypothesis(hypothesis_id: str) -> list[Any]:
    """Walk decision_log returning every probe / signal /
    specialist_invocation decision linked to `hypothesis_id`.

    Returns the raw Decision objects (chronological order)."""
    if not isinstance(hypothesis_id, str) or not hypothesis_id.strip():
        return []
    try:
        from strix.agents.decision_log import list_decisions
    except Exception:  # noqa: BLE001
        return []
    try:
        decisions = list_decisions()
    except Exception:  # noqa: BLE001
        return []
    return [
        d for d in decisions
        if d.kind in ("probe", "signal", "specialist_invocation")
        and d.links.get("hypothesis_id") == hypothesis_id
    ]


def record_probe_for_hypothesis(
    *,
    hypothesis_id: str,
    target: str,
    payload_label: str | None = None,
    payload: str | None = None,
    output: dict[str, Any] | None = None,
    actor: dict[str, Any] | None = None,
) -> str:
    """Convenience wrapper around `record_decision` that auto-links
    the probe to a hypothesis. Returns the new decision_id (empty
    string on failure)."""
    try:
        from strix.agents.decision_log import record_decision
    except Exception:  # noqa: BLE001
        return ""
    if not isinstance(hypothesis_id, str) or not hypothesis_id.strip():
        return ""
    try:
        return record_decision(
            kind="probe",
            target=target,
            input={
                "payload_label": payload_label,
                "payload": payload,
            },
            output=output or {},
            actor=actor or {},
            links={"hypothesis_id": hypothesis_id},
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "record_probe_for_hypothesis failed: %s", e, exc_info=True,
        )
        return ""


def loop_health_summary() -> dict[str, Any]:
    """One-call summary the lead can include in `agent_self_audit`:

    {
      "open_count": 7,
      "stuck_count": 2,
      "next_pick": {hypothesis_id, hypothesis, score},
      "stuck": [{hypothesis_id, ...}, ...]
    }
    """
    try:
        from strix.agents.active_hypotheses import list_active_hypotheses
    except Exception:  # noqa: BLE001
        return {"open_count": 0, "stuck_count": 0, "next_pick": None, "stuck": []}
    try:
        open_records = list_active_hypotheses(only_status="investigating")
    except Exception:  # noqa: BLE001
        open_records = []
    next_pick = pick_next_hypothesis()
    next_pick_summary: dict[str, Any] | None = None
    if next_pick:
        score = score_hypothesis(next_pick)
        next_pick_summary = {
            "hypothesis_id": next_pick.get("hypothesis_id"),
            "hypothesis": next_pick.get("hypothesis"),
            "surface": next_pick.get("surface"),
            "category": next_pick.get("category"),
            "score": round(score, 3),
        }
    stuck = find_stuck_hypotheses()
    return {
        "open_count": len(open_records),
        "stuck_count": len(stuck),
        "next_pick": next_pick_summary,
        "stuck": [s.to_dict() for s in stuck[:5]],
    }
