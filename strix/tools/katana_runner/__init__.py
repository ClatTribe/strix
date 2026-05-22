"""iter-22.1 — Katana JS-aware crawler wrapper.

Per `docs/L1-optimization.md §3.7`: replace the in-house
`bfs_crawl` single-threaded Python with the Rust-fast Go-based
katana (ProjectDiscovery). Katana already lives in the sandbox
via the go-builder stage — only the wrapper was missing.
"""

from __future__ import annotations

from strix.tools.katana_runner.crawl_with_katana import (  # noqa: F401
    crawl_with_katana,
)


__all__ = ["crawl_with_katana"]
