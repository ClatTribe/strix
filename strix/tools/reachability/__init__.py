"""Reachability scoring on candidate findings (roadmap §7.1).

Reads `code_map.json` (#94), scores each existing finding's
reachability from internet-facing entrypoints (route handlers),
and either deprioritises dead-code findings to `severity=info` or
flags auth-path findings as fix-now.

Targets the user's zero-false-positive rule: a SQL injection in
dead code is technically a finding but practically noise. Drop
its priority. A SQL injection on the auth path is the same
technical class but exponentially worse impact. Promote it.
"""

from .reachability import score_reachability


__all__ = ["score_reachability"]
