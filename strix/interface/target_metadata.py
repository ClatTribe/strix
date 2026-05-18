"""engine-wishlist §3 — target-metadata pass-through.

The wrapper's `targets.metadata` JSONB carries rich upstream
context that the engine's Researcher phase rederives from cold
start every time: GitHub repo language, AWS resource tags,
last-deploy timestamp, dependency manifest hints, asset owner
from CODEOWNERS, deploy target.

This module loads a per-target metadata blob from a file (or env
var) and surfaces it to:

  1. `tracer.run_metadata["target_metadata"]` — lands in
     `run_meta.json` for auditability / wrapper round-trips.
  2. `LLMConfig.system_prompt_context["target_metadata"]` —
     reachable from the system-prompt jinja template so the
     Researcher prompt can prioritise probes by ecosystem
     (Django + PCI → ORM injection + admin-auth bypass first;
     static marketing site → skip auth probes).

## Shape

Documented keys (per engine-wishlist.md §3):

```json
{
  "language": "python",
  "framework_hints": ["django", "celery", "redis"],
  "last_active": "2026-05-12T...",
  "tags": ["prod", "pci-scope"],
  "owner": "@payments-team",
  "deploy_target": "kubernetes"
}
```

But the contract is **permissive** — no schema enforcement. The
engine treats unknown keys as opaque additional context; the
wrapper can extend the shape without coordinating with engine
releases.

## Failure mode

Loading is best-effort. A missing file / malformed JSON / empty
blob returns `{}` and logs a warning. The scan never blocks on
metadata problems.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# Hard cap on the loaded blob — prevents a runaway 50MB metadata
# file from blowing the run. The doc-shaped blob is ~1KB; even a
# 100-tag wrapper-side enrichment fits in <50KB.
_MAX_METADATA_BYTES = 1 * 1024 * 1024  # 1 MB

# Documented keys we render explicitly in the prompt. Unknown
# keys are still passed through but rendered under a generic
# "Other metadata" section.
DOCUMENTED_KEYS = (
    "language",
    "framework_hints",
    "last_active",
    "tags",
    "owner",
    "deploy_target",
)


def load_target_metadata(
    *,
    path: str | None = None,
    env_var: str = "STRIX_TARGET_METADATA",
) -> dict[str, Any]:
    """Load the target-metadata blob.

    Args:
        path: explicit `--target-metadata-file` argument. Takes
            precedence when set.
        env_var: env-var name to fall back to. Default
            `STRIX_TARGET_METADATA` (wishlist contract).

    Returns:
        A dict on success; `{}` on any failure or when neither
        source is set. The dict is the parsed JSON content
        verbatim — no schema enforcement.
    """
    file_path: Path | None = None
    if path:
        file_path = Path(path)
    else:
        env_path = os.environ.get(env_var)
        if env_path:
            file_path = Path(env_path)

    if file_path is None:
        return {}

    try:
        if not file_path.is_file():
            logger.warning(
                "target_metadata: path %s not a file; ignoring",
                file_path,
            )
            return {}
        size = file_path.stat().st_size
        if size > _MAX_METADATA_BYTES:
            logger.warning(
                "target_metadata: file %s is %d bytes (> %d cap); "
                "ignoring", file_path, size, _MAX_METADATA_BYTES,
            )
            return {}
        raw = file_path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning(
            "target_metadata: failed to read %s: %s",
            file_path, e,
        )
        return {}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.warning(
            "target_metadata: malformed JSON in %s: %s",
            file_path, e,
        )
        return {}

    if not isinstance(data, dict):
        logger.warning(
            "target_metadata: top-level value in %s is not an "
            "object (got %s); ignoring",
            file_path, type(data).__name__,
        )
        return {}

    return data


def render_for_prompt(metadata: dict[str, Any]) -> str:
    """Render the metadata blob as a compact text block the
    system-prompt template can interpolate.

    Empty metadata returns an empty string so the template can
    skip the section entirely.
    """
    if not metadata:
        return ""

    lines: list[str] = []
    lines.append("Target metadata (from wrapper):")

    # Render documented keys in stable order first.
    for key in DOCUMENTED_KEYS:
        if key in metadata:
            value = metadata[key]
            lines.append(f"  - {key}: {_format_value(value)}")

    # Then any extra keys the wrapper added.
    extra_keys = sorted(
        k for k in metadata.keys() if k not in DOCUMENTED_KEYS
    )
    if extra_keys:
        lines.append("  Other metadata:")
        for k in extra_keys:
            lines.append(f"    - {k}: {_format_value(metadata[k])}")

    lines.append("")
    lines.append(
        "Use this context to prioritise exploit classes — e.g. "
        "Django + PCI scope → ORM injection + admin-auth bypass "
        "first; static marketing site → skip auth probes."
    )
    return "\n".join(lines)


def _format_value(v: Any) -> str:
    """Compact, human-readable rendering of a metadata value."""
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) if v else "(empty)"
    if isinstance(v, dict):
        # Single-level depth — avoid blowing up the prompt with
        # nested structures. The doc shape only has flat values.
        return ", ".join(f"{k}={v[k]}" for k in sorted(v.keys()))
    return str(v)
