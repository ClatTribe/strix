"""iter-22.8 — Dalfox XSS scanner wrapper.

Per `docs/L1-optimization.md §6 iter-22.8`: replace the in-house
`scan_xss` partial implementation with dalfox's mature XSS
payload library + filter-bypass support.
"""

from __future__ import annotations

from strix.tools.dalfox_runner.scan_xss_dalfox import (  # noqa: F401
    scan_xss_dalfox,
)


__all__ = ["scan_xss_dalfox"]
