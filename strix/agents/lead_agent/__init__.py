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


__all__ = [
    "LeadAgent",
    "is_single_lead_architecture_enabled",
]
