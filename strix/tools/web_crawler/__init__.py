"""BFS web crawler with JS-bundle endpoint extraction.

Roadmap §7.2 + §3 (--seed-url / --openapi).

Today's web-app target depth is bounded by the agent's depth-first improvisation
through the surface — large SPAs hide most of their attack surface inside
bundled JS that the agent never reaches. This tool runs a breadth-first crawl
that combines HTML link extraction, JS-bundle path-pattern mining, and
OpenAPI spec consumption (when supplied) to produce a deterministic
endpoint inventory the rest of the web-app team can pivot off.
"""

from .crawler import bfs_crawl


__all__ = ["bfs_crawl"]
