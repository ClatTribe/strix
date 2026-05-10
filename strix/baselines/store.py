"""JSONL-backed store for `EndpointBaseline` records.

Append-only with last-line-wins semantics on read. Each line is
a JSON object holding one baseline. Lookup builds an in-memory
index lazily on first read; for monorepo-scale recon walks we
stay well under 100k endpoints, so the linear-scan-on-load cost
is negligible.

Test injection:
  * `BaselineStore(path=tmp_path / "x.jsonl")` — point at any
    file location for unit tests.
  * `default_store_path()` returns the conventional
    `strix_runs/<run>/behavioural_baselines.jsonl` location;
    used by production code paths.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from strix.baselines.capture import EndpointBaseline


logger = logging.getLogger(__name__)


def default_store_path() -> Path:
    """Where the production code writes baselines.

    Uses the same `STRIX_RUN_DIR` env-var that other artefacts
    follow when present; otherwise falls back to `cwd /
    behavioural_baselines.jsonl` so a bare invocation still
    persists state somewhere predictable.
    """
    run_dir = os.environ.get("STRIX_RUN_DIR")
    if run_dir:
        p = Path(run_dir) / "behavioural_baselines.jsonl"
    else:
        p = Path.cwd() / "behavioural_baselines.jsonl"
    return p


class BaselineStore:
    """Append-only JSONL store. Last entry per endpoint wins."""

    def __init__(self, *, path: Path | str | None = None):
        self.path = Path(path) if path else default_store_path()
        self._index: dict[str, EndpointBaseline] | None = None

    # ---- public API ------------------------------------------------

    def write(self, baseline: EndpointBaseline) -> None:
        """Append `baseline` as a JSON line. Creates the parent
        dir if needed."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(baseline.to_dict()) + "\n")
        # Refresh in-memory index if we already had one loaded.
        if self._index is not None:
            self._index[baseline.endpoint] = baseline

    def read(self, endpoint: str) -> EndpointBaseline | None:
        """Return the latest baseline for `endpoint` or None."""
        idx = self._load_index()
        return idx.get(endpoint)

    def all(self) -> list[EndpointBaseline]:
        """All known baselines (latest per endpoint)."""
        idx = self._load_index()
        return list(idx.values())

    # ---- internals -------------------------------------------------

    def _load_index(self) -> dict[str, EndpointBaseline]:
        if self._index is not None:
            return self._index
        idx: dict[str, EndpointBaseline] = {}
        if not self.path.exists():
            self._index = idx
            return idx
        try:
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        # Skip corrupt lines silently — the store
                        # is append-only, so a torn write doesn't
                        # need to invalidate the whole file.
                        continue
                    if not isinstance(d, dict):
                        continue
                    ep = d.get("endpoint")
                    if not isinstance(ep, str) or not ep:
                        continue
                    idx[ep] = EndpointBaseline.from_dict(d)
        except OSError as e:
            logger.debug("baselines: read failed for %s: %s",
                         self.path, e)
        self._index = idx
        return idx
