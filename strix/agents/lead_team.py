"""Lead-team orchestrator (roadmap §8.0 reference impl).

Thin wrapper over the existing `create_agent` / `view_agent_graph` /
`tracer.get_existing_vulnerabilities` primitives that gives a lead
agent a high-level API for the standard team-coordination patterns:

1. **Spawn** specialists by category (auto-applies the
   specialist-registry profile + budget caps).
2. **Wait** for all spawned specialists to terminate (completion /
   stop / max-iterations / budget-exceeded — see §8 of
   `docs/lead-team-protocol.md`).
3. **Collect** findings emitted by the team, dedup'd by
   fingerprint, ranked by (severity × KEV × verification_status).
4. **Summarise** team metrics (spawn count, completion rate,
   per-category cost / token usage).

Use it OR call `create_agent` directly — both are supported. The
helper is reference, not enforcement; lead agents that need
custom orchestration (e.g. spawn-on-demand based on intermediate
findings) should bypass it.

Example:

```python
from strix.agents.lead_team import LeadTeam

team = LeadTeam(self.state)
team.spawn(category="sqli-specialist", task="Probe /api/login.", name="SQL-1")
team.spawn(category="xss-specialist", task="Probe /api/login.", name="XSS-1")
team.spawn(category="ssrf-scanner", task="Probe /api/proxy.", name="SSRF-1")
team.wait_for_all(timeout=600)
findings = team.collect_findings()
report = team.summary()
```

The orchestrator is best-effort: every method swallows exceptions
from the underlying primitives so the lead-agent loop never
breaks because of bookkeeping. Failures are logged.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


_SEVERITY_RANK = {
    "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
}


_VERIFICATION_RANK = {
    "could_not_verify": 1,
    "needs_review": 2,
    "inconclusive": 3,
    "pattern_match": 4,
    "verified": 5,
}


@dataclass
class _SpawnRecord:
    """Record of a single spawn call. Tracks the agent_id returned
    by `create_agent` plus the requested category + name for
    summary reporting."""
    category: str | None
    name: str
    agent_id: str | None
    success: bool
    error: str | None = None


@dataclass
class LeadTeamSummary:
    """Aggregate metrics for a team run."""
    spawn_count: int
    spawn_success_count: int
    spawn_failure_count: int
    completed_count: int
    running_count: int
    failed_count: int
    by_category: dict[str, int]
    findings_count: int
    canonical_finding_count: int
    spawn_records: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spawn_count": self.spawn_count,
            "spawn_success_count": self.spawn_success_count,
            "spawn_failure_count": self.spawn_failure_count,
            "completed_count": self.completed_count,
            "running_count": self.running_count,
            "failed_count": self.failed_count,
            "by_category": dict(self.by_category),
            "findings_count": self.findings_count,
            "canonical_finding_count": self.canonical_finding_count,
            "spawn_records": list(self.spawn_records),
        }


class LeadTeam:
    """Reference orchestrator for §8 sub-agent teams.

    Constructed with the lead's `AgentState`. The state's
    `agent_id` is used as the `parent_id` for every spawned
    specialist via `create_agent`'s existing parent-tracking.
    """

    def __init__(self, lead_state: Any):
        if lead_state is None:
            raise ValueError("LeadTeam requires the lead agent's state")
        self._lead_state = lead_state
        self._spawns: list[_SpawnRecord] = []

    # ------------------------------------------------------------------
    # Spawn
    # ------------------------------------------------------------------

    def spawn(
        self,
        *,
        task: str,
        name: str,
        category: str | None = None,
        skills: str | None = None,
        budget: dict[str, Any] | None = None,
        inherit_context: bool = True,
    ) -> _SpawnRecord:
        """Spawn one specialist via `create_agent`. Records the
        outcome on the team. Returns the SpawnRecord (also
        appended to `self._spawns`)."""
        try:
            from strix.tools.agents_graph.agents_graph_actions import create_agent

            result = create_agent(
                agent_state=self._lead_state,
                task=task,
                name=name,
                inherit_context=inherit_context,
                skills=skills,
                category=category,
                budget=budget,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning("LeadTeam.spawn failed: %s", e, exc_info=True)
            record = _SpawnRecord(
                category=category, name=name, agent_id=None,
                success=False, error=f"spawn_exception: {e}",
            )
            self._spawns.append(record)
            return record

        success = bool(result.get("success"))
        record = _SpawnRecord(
            category=category,
            name=name,
            agent_id=result.get("agent_id"),
            success=success,
            error=None if success else str(result.get("error") or "spawn returned success=False"),
        )
        self._spawns.append(record)
        return record

    def spawn_many(
        self, specs: list[dict[str, Any]],
    ) -> list[_SpawnRecord]:
        """Convenience: spawn multiple specialists from a list of
        dicts. Each dict keys must match `spawn`'s parameters
        (`task`, `name`, optional `category` / `skills` / `budget` /
        `inherit_context`).

        Returns the list of SpawnRecords in order."""
        out: list[_SpawnRecord] = []
        for spec in specs:
            if not isinstance(spec, dict):
                continue
            try:
                record = self.spawn(
                    task=spec.get("task", ""),
                    name=spec.get("name") or spec.get("category") or "specialist",
                    category=spec.get("category"),
                    skills=spec.get("skills"),
                    budget=spec.get("budget"),
                    inherit_context=spec.get("inherit_context", True),
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("LeadTeam.spawn_many entry failed: %s", e)
                continue
            out.append(record)
        return out

    # ------------------------------------------------------------------
    # Wait
    # ------------------------------------------------------------------

    def wait_for_all(
        self,
        *,
        timeout: float = 600.0,
        poll_interval: float = 2.0,
    ) -> dict[str, str]:
        """Block until every spawned specialist is in a terminal
        state (completed / stopped / max-iterations / budget-
        exceeded) OR `timeout` seconds elapse.

        Returns a map `{agent_id: terminal_status}`. Specialists
        that didn't finish before `timeout` get the status
        `"timed_out"`.

        Best-effort: returns immediately with whatever info is
        available if the agents_graph helper isn't reachable."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        target_ids = [r.agent_id for r in self._spawns if r.agent_id]
        if not target_ids:
            return {}

        terminal_states = {"completed", "failed", "stopped", "budget_exceeded"}
        status_map: dict[str, str] = {aid: "unknown" for aid in target_ids}

        while time.monotonic() < deadline:
            try:
                from strix.tools.agents_graph.agents_graph_actions import view_agent_graph

                graph = view_agent_graph(self._lead_state)
                nodes = (graph or {}).get("nodes") or []
                pending = 0
                for node in nodes:
                    aid = node.get("id")
                    status = (node.get("status") or "").lower()
                    if aid in status_map:
                        status_map[aid] = status or status_map[aid]
                        if status not in terminal_states:
                            pending += 1
                if pending == 0:
                    break
            except Exception as e:  # noqa: BLE001
                logger.debug("LeadTeam.wait_for_all view failed: %s", e)
                break
            time.sleep(max(0.05, poll_interval))

        # Mark stragglers.
        for aid, status in status_map.items():
            if status not in terminal_states and status != "unknown":
                # Still running past deadline.
                status_map[aid] = "timed_out"
            elif status == "unknown":
                status_map[aid] = "unknown"
        return status_map

    # ------------------------------------------------------------------
    # Collect findings
    # ------------------------------------------------------------------

    def collect_findings(
        self,
        *,
        dedup_by_fingerprint: bool = True,
    ) -> list[dict[str, Any]]:
        """Return the team's findings, deduplicated by `fingerprint`
        and ranked by (severity × verification_status).

        When `dedup_by_fingerprint=False`, every finding is returned
        in original order (for cases where the lead wants to
        inspect cross-specialist duplicates manually).
        """
        try:
            from strix.telemetry.tracer import get_global_tracer

            tracer = get_global_tracer()
            if tracer is None:
                return []
            all_findings = list(tracer.get_existing_vulnerabilities())
        except Exception as e:  # noqa: BLE001
            logger.warning("LeadTeam.collect_findings failed: %s", e)
            return []

        if not dedup_by_fingerprint:
            return all_findings

        by_fp: dict[str, dict[str, Any]] = {}
        unfingerprinted: list[dict[str, Any]] = []
        for f in all_findings:
            fp = f.get("fingerprint")
            if not fp:
                unfingerprinted.append(f)
                continue
            existing = by_fp.get(fp)
            if existing is None:
                by_fp[fp] = f
                continue
            # Conflict adjudication: pick the higher-rank finding.
            if _finding_rank(f) > _finding_rank(existing):
                by_fp[fp] = f

        deduped = list(by_fp.values()) + unfingerprinted
        deduped.sort(key=lambda x: -_finding_rank(x))
        return deduped

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> LeadTeamSummary:
        """Aggregate team-level metrics: spawn count / per-category
        breakdown / completion rate / finding totals."""
        try:
            from strix.tools.agents_graph.agents_graph_actions import view_agent_graph

            graph = view_agent_graph(self._lead_state)
            nodes = (graph or {}).get("nodes") or []
        except Exception:  # noqa: BLE001
            nodes = []

        target_ids = {r.agent_id for r in self._spawns if r.agent_id}
        completed = running = failed = 0
        for node in nodes:
            if node.get("id") not in target_ids:
                continue
            status = (node.get("status") or "").lower()
            if status == "completed":
                completed += 1
            elif status in ("failed", "budget_exceeded"):
                failed += 1
            elif status in ("running", "waiting"):
                running += 1

        by_category: dict[str, int] = {}
        for r in self._spawns:
            if r.success:
                cat = r.category or "(uncategorised)"
                by_category[cat] = by_category.get(cat, 0) + 1

        try:
            findings = self.collect_findings(dedup_by_fingerprint=True)
            findings_count = len(findings)
            canonical = sum(1 for f in findings if f.get("is_canonical", True))
        except Exception:  # noqa: BLE001
            findings_count = 0
            canonical = 0

        return LeadTeamSummary(
            spawn_count=len(self._spawns),
            spawn_success_count=sum(1 for r in self._spawns if r.success),
            spawn_failure_count=sum(1 for r in self._spawns if not r.success),
            completed_count=completed,
            running_count=running,
            failed_count=failed,
            by_category=by_category,
            findings_count=findings_count,
            canonical_finding_count=canonical,
            spawn_records=[
                {"category": r.category, "name": r.name, "agent_id": r.agent_id,
                 "success": r.success, "error": r.error}
                for r in self._spawns
            ],
        )


# ---------------------------------------------------------------------------
# Adjudication helpers
# ---------------------------------------------------------------------------


def _finding_rank(f: dict[str, Any]) -> int:
    """Composite rank for adjudicating duplicate findings:

    higher = more authoritative.

    - Severity dominates (info=1, critical=5).
    - KEV decoration adds a bonus (in-the-wild exploitation).
    - Verification status adds a bonus (verified > pattern_match).
    - Canonical-contract status adds a small tiebreaker.
    """
    sev = (f.get("severity") or "").lower()
    severity_score = _SEVERITY_RANK.get(sev, 0) * 100

    kev_score = 50 if f.get("is_kev") else 0
    if f.get("kev_ransomware_use"):
        kev_score += 25

    vs = (f.get("verification_status") or "").lower()
    vs_score = _VERIFICATION_RANK.get(vs, 0) * 5

    canonical_score = 1 if f.get("is_canonical", True) else 0

    return severity_score + kev_score + vs_score + canonical_score
