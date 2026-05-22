"""iter-23.3 — `map_graphql_inql` subprocess wrapper.

inql is a Python tool (`pip install inql`) for fingerprinting and
introspecting GraphQL endpoints. When `__schema` introspection is
allowed, inql produces a full schema map — every Query, Mutation, and
Subscription operation with its argument types.

This complements the in-house `graphql_introspect` tool (which does a
single introspection query) by additionally:

  * Generating ready-to-replay query templates for every operation
    (so phase-2 specialists can iterate them without re-discovering)
  * Detecting deprecated / debug-only fields that survived a hardening
  * Identifying mutations that bypass typical REST-style authz checks

Schema map shape:
    operations: [{kind: query|mutation|subscription, name: str,
                  args: [{name, type}, ...]}, ...]

Recall safety: ``status=partial`` when binary missing OR when target
returns introspection-disabled.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_INQL_BIN = "inql"
_DEFAULT_TIMEOUT_SECONDS = 120


def _inql_available() -> bool:
    if os.environ.get(
        "STRIX_INQL_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_INQL_BIN) is not None


def _parse_schema_json(blob: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull operation list out of a GraphQL introspection JSON blob."""
    operations: list[dict[str, Any]] = []
    schema = (blob.get("data") or {}).get("__schema") or blob.get("__schema") or {}
    if not isinstance(schema, dict):
        return operations
    type_map = {t.get("name"): t for t in (schema.get("types") or []) if isinstance(t, dict)}
    for kind, root_key in (
        ("query", "queryType"),
        ("mutation", "mutationType"),
        ("subscription", "subscriptionType"),
    ):
        root = schema.get(root_key)
        if not isinstance(root, dict):
            continue
        root_name = root.get("name")
        if not root_name or root_name not in type_map:
            continue
        for field in (type_map[root_name].get("fields") or []):
            if not isinstance(field, dict):
                continue
            name = field.get("name")
            if not name:
                continue
            args: list[dict[str, str]] = []
            for arg in (field.get("args") or []):
                if not isinstance(arg, dict):
                    continue
                t = arg.get("type") or {}
                # Surface the bare type-name; introspection nests with kind/ofType
                tname = ""
                while isinstance(t, dict):
                    if t.get("name"):
                        tname = t["name"]
                        break
                    t = t.get("ofType")
                args.append({"name": arg.get("name") or "", "type": tname or "Unknown"})
            operations.append({"kind": kind, "name": name, "args": args})
    return operations


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1595.002"],  # Vulnerability Scanning: Active Scanning
)
def map_graphql_inql(
    target_url: str,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Map a GraphQL endpoint's schema via inql introspection.

    Args:
        target_url: full URL to the GraphQL endpoint
            (``https://api.example.com/graphql``).
        headers: optional dict of headers to pass via ``-H key:value``
            (e.g. ``{"Authorization": "Bearer ..."}``).

    Returns:
        ```
        {success, status, target, total_operations: int,
         operations: [{kind, name, args:[{name, type}, ...]}, ...],
         reason?}
        ```
    """
    if not target_url or not target_url.strip():
        return {
            "success": False, "status": "error", "target": target_url,
            "total_operations": 0, "operations": [],
            "reason": "target_url required",
        }
    if not _inql_available():
        return {
            "success": True, "status": "partial", "target": target_url,
            "total_operations": 0, "operations": [],
            "reason": (
                "inql binary not on PATH (or STRIX_INQL_DISABLED=1). "
                "Install via `pipx install inql`."
            ),
        }

    # inql -t <url> --generate-html=false --no-generate-queries --pretty
    # produces ``schema.json`` in cwd. Use a tmpdir; parse after exit.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="inql_") as tmpdir:
        cmd: list[str] = [
            _INQL_BIN,
            "-t", target_url.strip(),
            "-o", tmpdir,
        ]
        for k, v in (headers or {}).items():
            cmd.extend(["-H", f"{k}: {v}"])

        try:
            subprocess.run(  # noqa: S603
                cmd, check=False, capture_output=True,
                timeout=_DEFAULT_TIMEOUT_SECONDS, text=True,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return {
                "success": False, "status": "error", "target": target_url,
                "total_operations": 0, "operations": [],
                "reason": f"inql invocation failed: {type(e).__name__}: {e}",
            }

        # inql drops `schema.json` (or similar) under tmpdir; find any json
        schema_blob: dict[str, Any] | None = None
        for p in Path(tmpdir).rglob("*.json"):
            try:
                blob = json.loads(p.read_text())
            except (OSError, ValueError):
                continue
            if isinstance(blob, dict) and (
                "data" in blob or "__schema" in blob
            ):
                schema_blob = blob
                break
        if schema_blob is None:
            return {
                "success": True, "status": "partial", "target": target_url,
                "total_operations": 0, "operations": [],
                "reason": (
                    "inql produced no schema.json — endpoint likely has "
                    "introspection disabled (which is good security)."
                ),
            }

        operations = _parse_schema_json(schema_blob)
        return {
            "success": True,
            "status": "ok",
            "target": target_url,
            "total_operations": len(operations),
            "operations": operations,
        }
