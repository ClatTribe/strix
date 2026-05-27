"""iter-Q5.14 — `get_recon_artifact(kind, name=None)`.

Per CLAUDE.md §1.5.7 READ STATE bucket and the consolidated Q5
proposal §7 Gap 2. The prepass produces katana crawl output,
OpenAPI specs, GraphQL schemas, SBOMs, subdomain lists, tech-stack
fingerprints. These are NOT findings — they're raw recon data the
lead may want to grep, re-read, or sample-inspect. Pre-Q5.14 they
got dropped from context by the iter-Q2.1 stratified compactor
after a few turns.

Q5.14 reads them from `<run_dir>/recon/<kind>.json` (or a name-
qualified subdir when the prepass surfaced multiple of the same
kind).

## Supported kinds

  endpoints         — flat list of URLs found by crawl_with_katana /
                      webapp_recon_pipeline
  openapi_spec      — full ingested OpenAPI/Swagger document
  graphql_schema    — discovered GraphQL types + operations from inql
                      / discover_graphql_endpoints
  sbom              — CycloneDX SBOM from sbom_extract
  subdomains        — subfinder + bbot discovered subdomains
  tech_stack        — fingerprint_tech_stack result
  auth_endpoints    — login/register/MFA endpoints discovered by
                      seed_auth + webapp_recon_pipeline

When the prepass tool didn't run (or produced no artifact), the
tool returns `status="not_found"` with a clear reason. Best-effort:
disk I/O failures return a structured error, never raise.

## Sample output

```
{
  success: True,
  status: "ok",
  kind: "endpoints",
  artifact: {"endpoints": ["...", "..."], "count": 47, ...},
  artifact_size_chars: 4231,
}
```
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)


# Supported kinds + their canonical disk locations under
# `<run_dir>/recon/`. The prepass orchestrator (iter-Q5.14
# follow-up) will be responsible for writing into these paths;
# this iter only adds the READ side. Until prepass writes them,
# the tool returns not_found gracefully.
_KIND_FILENAMES: dict[str, str] = {
    "endpoints": "endpoints.json",
    "openapi_spec": "openapi_spec.json",
    "graphql_schema": "graphql_schema.json",
    "sbom": "sbom.json",
    "subdomains": "subdomains.json",
    "tech_stack": "tech_stack.json",
    "auth_endpoints": "auth_endpoints.json",
}


def _recon_dir() -> Path | None:
    """Resolve the run's recon dir."""
    run_dir = os.environ.get("STRIX_RUN_DIR")
    if not run_dir:
        return None
    return Path(run_dir) / "recon"


@register_tool(sandbox_execution=False, provenance="framework")
def get_recon_artifact(
    kind: str,
    name: str | None = None,
) -> dict[str, Any]:
    """Read a recon artifact persisted by anchor_prepass.

    Per CLAUDE.md §1.5.6 — pure READ STATE primitive. The prepass
    artifacts live in `<run_dir>/recon/`; the LLM can't read disk,
    so this tool exposes them.

    Args:
        kind: one of:
            ``endpoints``, ``openapi_spec``, ``graphql_schema``,
            ``sbom``, ``subdomains``, ``tech_stack``,
            ``auth_endpoints``.
        name: optional qualifier for assets that may produce multiple
            artifacts of the same kind (e.g., multiple GraphQL
            endpoints on the same target). When None, returns the
            top-level artifact; when set, reads
            `<run_dir>/recon/<kind>/<name>.json`.

    Returns:
        ```
        {success: bool, status: "ok"|"not_found"|"error", kind,
         name?, artifact?, artifact_size_chars?, reason?}
        ```
    """
    if not isinstance(kind, str) or not kind.strip():
        return {
            "success": False, "status": "error",
            "reason": f"kind is required (one of {sorted(_KIND_FILENAMES)!r})",
        }
    kind_norm = kind.strip().lower()
    if kind_norm not in _KIND_FILENAMES:
        return {
            "success": False, "status": "error",
            "reason": (
                f"unknown kind {kind!r}; valid: "
                f"{sorted(_KIND_FILENAMES)!r}"
            ),
        }

    base = _recon_dir()
    if base is None:
        return {
            "success": True, "status": "not_found",
            "kind": kind_norm,
            "reason": (
                "STRIX_RUN_DIR not set — no scan run in flight. The "
                "prepass writes recon artifacts only during an active "
                "scan."
            ),
        }

    if name and isinstance(name, str) and name.strip():
        path = base / kind_norm / f"{name.strip()}.json"
    else:
        path = base / _KIND_FILENAMES[kind_norm]

    if not path.exists():
        return {
            "success": True, "status": "not_found",
            "kind": kind_norm,
            "name": name,
            "reason": (
                f"recon artifact {path!s} not present. Either the "
                f"prepass tool that produces this kind didn't fire "
                f"(check `workflow_status` + `tools_run`), or the "
                f"target type doesn't generate this artifact (e.g. "
                f"`graphql_schema` on a non-GraphQL target)."
            ),
        }

    try:
        body = path.read_text(encoding="utf-8")
        artifact = json.loads(body)
    except (OSError, ValueError) as e:
        logger.debug(
            "get_recon_artifact read failed for %s: %s", path, e,
        )
        return {
            "success": False, "status": "error",
            "kind": kind_norm,
            "reason": f"failed to read {path!s}: {type(e).__name__}: {e}",
        }

    return {
        "success": True, "status": "ok",
        "kind": kind_norm,
        "name": name,
        "artifact": artifact,
        "artifact_size_chars": len(body),
    }
