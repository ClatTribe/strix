"""Shared fixtures for recon-pipeline tests.

Disables the v2-step-5 recon cache by default for every test in
this directory. The pipeline tests assert that the inner recon
steps actually ran (artifacts written to disk, phase events
emitted, etc.); they don't care about the cache, and a stale
entry from a prior test run polluting the user's
`~/.cache/strix/recon` would cause spurious failures.

Tests that specifically exercise the cache (like
`tests/agents/test_recon_cache.py`) set their own
`STRIX_RECON_CACHE_DIR` and re-enable lookup in their own
autouse fixtures.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _disable_recon_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_RECON_CACHE_DISABLED", "1")
