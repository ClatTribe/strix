"""composer.lock parser (PHP)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from strix.sca.parsers.base import Package, register_parser


logger = logging.getLogger(__name__)


@register_parser(filenames=["composer.lock"])
def parse_composer_lock(path: Path) -> list[Package]:
    """composer.lock has `packages` and `packages-dev` arrays."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for section, dev_only in (("packages", False), ("packages-dev", True)):
        items = doc.get(section)
        if not isinstance(items, list):
            continue
        for entry in items:
            if not isinstance(entry, dict):
                continue
            name = (entry.get("name") or "").lower().strip()
            version = (entry.get("version") or "").strip()
            # composer often pins as "v1.2.3" — strip the leading "v"
            # for canonical version compare.
            if version.startswith("v") and len(version) > 1 and version[1].isdigit():
                version = version[1:]
            if not name or not version:
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            out.append(Package(
                ecosystem="composer",
                name=name,
                version=version,
                dev_only=dev_only,
                source_path=str(path),
                metadata={
                    "license": entry.get("license", []),
                    "type": entry.get("type", ""),
                },
            ))
    return out
