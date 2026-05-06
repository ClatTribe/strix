"""Roadmap §8.5 Phase 3 — single-lead-agent architecture.

See [`single-agent.md §2.1`](../../single-agent.md) for the
architectural specification; [`roadmap.md §8.5`](../../roadmap.md)
for the phase tracking; this PR is Phase 3a (skeleton + tool
catalog filtering + env-gate; LLM-driven specialist-tools land in
Phase 3b).
"""

from strix.agents.lead_agent.lead_agent import (
    LeadAgent,
    is_single_lead_architecture_enabled,
)
from strix.agents.lead_agent.watchdog import (
    WatchdogState,
    emit_watchdog_terminated,
)
# Phase 6 — registers `reflect` + `list_reflections` tools as side
# effects of import.
from strix.agents.lead_agent import reflection as _reflection  # noqa: F401


__all__ = [
    "LeadAgent",
    "WatchdogState",
    "emit_watchdog_terminated",
    "is_single_lead_architecture_enabled",
]
