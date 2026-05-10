"""Cargo.lock parser (Rust)."""

from __future__ import annotations

import logging
from pathlib import Path

from strix.sca.parsers.base import Package, register_parser


logger = logging.getLogger(__name__)


@register_parser(filenames=["cargo.lock"])
def parse_cargo_lock(path: Path) -> list[Package]:
    """Cargo.lock is TOML with a `[[package]]` array of tables."""
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]
        with path.open("rb") as f:
            doc = tomllib.load(f)
    except Exception as e:  # noqa: BLE001
        logger.debug("sca/cargo: parse failed for %s: %s", path, e)
        return []
    pkgs = doc.get("package")
    if not isinstance(pkgs, list):
        return []
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for entry in pkgs:
        if not isinstance(entry, dict):
            continue
        name = (entry.get("name") or "").lower().strip()
        version = (entry.get("version") or "").strip()
        if not name or not version:
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Package(
            ecosystem="cargo",
            name=name,
            version=version,
            source_path=str(path),
            metadata={
                "source": entry.get("source", ""),
                "checksum": entry.get("checksum", ""),
            },
        ))
    return out
