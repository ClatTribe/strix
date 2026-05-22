"""iter-22.4 — Hadolint Dockerfile-linter wrapper.

`docs/L1-optimization.md §3.3` calls for replacing our regex-based
Dockerfile anti-pattern checks with the Haskell-based Hadolint
binary. Hadolint ships ~80 rules (DL3000-series + SC2000-series
from shellcheck), maps each to a CWE, and outputs structured JSON.
"""

from __future__ import annotations

from strix.tools.hadolint_runner.scan_dockerfile_hadolint import (  # noqa: F401
    scan_dockerfile_hadolint,
)


__all__ = ["scan_dockerfile_hadolint"]
