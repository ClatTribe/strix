"""Agent self-audit between phases (roadmap §17.6 / §18 row 9 second-half).

Between recon → exploit, exploit → validate, validate → report,
the lead runs a structured self-audit: "Did I cover what's in
the surface_map? Which categories did I skip? Which sub-agents
are stuck?" Today this is implicit (the LLM thinks-in-prose);
this tool makes it explicit + structured + gradeable for the
RLHF FP-loop.
"""

from .self_audit_tool import agent_self_audit


__all__ = ["agent_self_audit"]
