"""engine-wishlist §7 — shared MOAK Researcher cache across
batched scans.

Pairs with §1 batch mode. The MOAK Researcher phase re-derives
stack architecture, framework versions, and exploit-class
priorities every scan. For a project of 50 microservices the
architectural map is largely shared across targets — Researcher
pays the full cost 50× when it could pay it once.

When `STRIX_PROJECT_ID` is set (§6) and the batch contains
multiple targets in the same project, the engine runs Researcher
once at the start of the batch and caches the output here.
Subsequent target scans in the same batch (and follow-up batched
runs within `_CACHE_TTL_SECONDS` on the same project) reuse the
cache instead of re-running Researcher.

## v1 scope

This v1 ships the **cache file format + read / write contract +
TTL check**. The actual Researcher-phase invocation that POPULATES
the cache and CONSUMES it lives in the agent layer; that hook
is deferred to a follow-up so this PR stays a contained dispatch-
layer change. The cache infrastructure is here today so the
wrapper can probe + verify the contract; the engine starts
consuming it once §7-phase-2 lands.

## File path

`<workdir>/researcher_cache/<project_id>.json`

(`workdir` defaults to `strix_runs/`; can be overridden via the
`--shared-researcher-cache` flag for explicit pairing.)

## Schema

```json
{
  "project_id": "proj-payments",
  "engine_version": "v1",
  "created_at": "2026-05-18T...",
  "expires_at": "2026-05-19T...",
  "researcher_output": {
    "stack": ["python", "django", "postgres"],
    "exploit_class_priorities": ["sqli", "orm_inject", ...],
    "architecture_notes": "..."
  }
}
```

Cache files older than `_CACHE_TTL_SECONDS` are treated as
expired — read returns None.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# Per the wishlist: "follow-up batched runs within 24h on the
# same project". Bump if the architectural drift cadence is
# observed faster in practice.
_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours

# Bump when the Researcher output shape changes incompatibly —
# old caches with a mismatched version are rejected and the
# next run re-derives.
_CACHE_VERSION = "v1"


@dataclass
class ResearcherCacheEntry:
    """One cached Researcher output."""

    project_id: str
    researcher_output: dict[str, Any]
    created_at: str
    expires_at: str
    engine_version: str = _CACHE_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "engine_version": self.engine_version,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "researcher_output": dict(self.researcher_output),
        }


def cache_path(
    project_id: str,
    *,
    workdir: Path = Path("strix_runs"),
) -> Path:
    """The deterministic file path for a project's cache."""
    return workdir / "researcher_cache" / f"{project_id}.json"


def write_cache(
    project_id: str,
    researcher_output: dict[str, Any],
    *,
    workdir: Path = Path("strix_runs"),
    ttl_seconds: int = _CACHE_TTL_SECONDS,
) -> Path | None:
    """Write a Researcher cache entry. Returns the file path or
    None when the write failed.
    """
    if not project_id:
        return None
    now = datetime.now(UTC)
    entry = ResearcherCacheEntry(
        project_id=project_id,
        researcher_output=researcher_output,
        created_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(now + timedelta(seconds=ttl_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ",
        ),
    )
    out_path = cache_path(project_id, workdir=workdir)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(entry.to_dict(), f, indent=2, ensure_ascii=False)
    except OSError as e:
        logger.warning(
            "researcher_cache: write failed (%s): %s", out_path, e,
        )
        return None
    return out_path


def read_cache(
    project_id: str,
    *,
    workdir: Path = Path("strix_runs"),
    explicit_path: Path | None = None,
) -> ResearcherCacheEntry | None:
    """Read + validate a cache entry. Returns None when:

      * The file doesn't exist
      * The file is malformed JSON
      * The cache version is older than `_CACHE_VERSION`
      * The cache has expired (`expires_at` < now)
    """
    if explicit_path is not None:
        p = Path(explicit_path)
    else:
        if not project_id:
            return None
        p = cache_path(project_id, workdir=workdir)

    if not p.is_file():
        return None

    try:
        body = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("researcher_cache: read failed: %s", e)
        return None
    if not isinstance(body, dict):
        return None

    version = body.get("engine_version")
    if version != _CACHE_VERSION:
        logger.debug(
            "researcher_cache: version mismatch %s ≠ %s",
            version, _CACHE_VERSION,
        )
        return None

    # TTL check.
    expires_at = body.get("expires_at") or ""
    try:
        expires_dt = datetime.strptime(
            expires_at, "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=UTC)
    except ValueError:
        return None
    if datetime.now(UTC) >= expires_dt:
        logger.debug("researcher_cache: expired for %s", project_id)
        return None

    output = body.get("researcher_output")
    if not isinstance(output, dict):
        return None

    return ResearcherCacheEntry(
        project_id=body.get("project_id", ""),
        researcher_output=output,
        created_at=body.get("created_at", ""),
        expires_at=expires_at,
        engine_version=version,
    )


def invalidate_cache(
    project_id: str, *, workdir: Path = Path("strix_runs"),
) -> bool:
    """Delete the cache entry for `project_id`. Returns True
    when a file was removed, False when no cache existed."""
    p = cache_path(project_id, workdir=workdir)
    if p.is_file():
        try:
            p.unlink()
            return True
        except OSError as e:
            logger.warning(
                "researcher_cache: invalidate failed (%s): %s",
                p, e,
            )
    return False
