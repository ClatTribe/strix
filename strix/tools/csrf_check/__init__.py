"""CSRF posture analyzer.

Roadmap §7.2 web-app expert-pentester gap audit (🟡 important).
For state-changing forms enumerated from `bfs_crawl` output, replay
with the token removed / mutated / origin-swapped / referer-stripped
and flag forms that accept any of those. Single deterministic test
that converts "does this app actually validate CSRF tokens?" from a
guess into a yes/no answer.
"""

from .csrf_check import csrf_check


__all__ = ["csrf_check"]
