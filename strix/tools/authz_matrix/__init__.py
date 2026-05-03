"""Authorization matrix testing.

Roadmap §7.2. The classical pen-test approach to authorization: for each
(role × resource × verb) cell, send the request as that role and record the
outcome. This tool turns it into a single deterministic call the agent
invokes after recon completes — replacing the agent's natural fragmented
multi-session approach where authorization gaps slip through.
"""

from .authz_matrix import authz_matrix_check


__all__ = ["authz_matrix_check"]
