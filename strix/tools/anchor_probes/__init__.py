"""iter-35.2 — sandbox-side wrappers for the 11 anchor-prepass probes.

Per CLAUDE.md §3.6 the prepass historically called these 11 helpers
directly in-process on the host (urllib / sockets / ftplib). That
violated the sandbox-only rule for two reasons:
  1. Network policy enforcement: host-side calls bypass the sandbox's
     egress controls.
  2. Reachability: targets that resolve only inside the sandbox's
     network (e.g. `host.docker.internal` / private docker-compose
     networks) aren't reachable from host process.

This module registers each probe as a sandbox-dispatchable tool so
the prepass can call them via `execute_tool(..., agent_state=...)`,
which routes through the sandbox tool_server HTTP API. The actual
probe implementations stay in `strix/agents/lead_agent/anchor_prepass`
(lazy-imported at call time to avoid circular module loading).
"""

from .anchor_probes import *  # noqa: F403
