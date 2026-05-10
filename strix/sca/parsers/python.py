"""Python lockfile parsers — requirements.txt + Pipfile.lock +
poetry.lock + uv.lock.

Notes:
  * `requirements*.txt` ranges from "pinned versions only" to
    "version ranges + markers + URLs." We only emit packages with
    pinned versions (==) since SCA can't match against ranges.
  * `Pipfile.lock` is JSON.
  * `poetry.lock` is TOML.
  * `uv.lock` is TOML (similar shape to poetry.lock but newer).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from strix.sca.parsers.base import Package, register_parser


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------


# `name==version` shape; only handle pinned versions.
_REQ_PINNED_RE = re.compile(
    r"^\s*([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._+!\-]+)",
)


@register_parser(patterns=[
    r"^requirements.*\.txt$",
    r"^constraints.*\.txt$",
])
def parse_requirements(path: Path) -> list[Package]:
    """Parse pip requirements.txt (pinned versions only)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_PINNED_RE.match(line)
        if not m:
            continue
        name = m.group(1).lower().strip().replace("_", "-")
        version = m.group(2).strip()
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Package(
            ecosystem="pypi",
            name=name,
            version=version,
            source_path=str(path),
        ))
    return out


# ---------------------------------------------------------------------------
# Pipfile.lock (JSON)
# ---------------------------------------------------------------------------


@register_parser(filenames=["pipfile.lock"])
def parse_pipfile_lock(path: Path) -> list[Package]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for section, dev_only in (("default", False), ("develop", True)):
        deps = doc.get(section)
        if not isinstance(deps, dict):
            continue
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            ver = (info.get("version") or "").strip()
            if ver.startswith("=="):
                ver = ver[2:]
            ver = ver.strip()
            if not ver:
                continue
            canon = name.lower().strip().replace("_", "-")
            key = (canon, ver)
            if key in seen:
                continue
            seen.add(key)
            out.append(Package(
                ecosystem="pypi",
                name=canon,
                version=ver,
                dev_only=dev_only,
                source_path=str(path),
                metadata={"hashes": info.get("hashes", [])},
            ))
    return out


# ---------------------------------------------------------------------------
# poetry.lock + uv.lock (TOML)
# ---------------------------------------------------------------------------


@register_parser(filenames=["poetry.lock", "uv.lock"])
def parse_poetry_or_uv_lock(path: Path) -> list[Package]:
    """Both poetry.lock and uv.lock use a `[[package]]` array of
    tables. Same parser handles both."""
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]
        with path.open("rb") as f:
            doc = tomllib.load(f)
    except Exception as e:  # noqa: BLE001
        logger.debug("sca/poetry-or-uv parse failed for %s: %s", path, e)
        return []
    pkgs = doc.get("package")
    if not isinstance(pkgs, list):
        return []
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for entry in pkgs:
        if not isinstance(entry, dict):
            continue
        name = (entry.get("name") or "").lower().strip().replace("_", "-")
        version = (entry.get("version") or "").strip()
        if not name or not version:
            continue
        category = (entry.get("category") or "main").lower()
        dev_only = (category == "dev")
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Package(
            ecosystem="pypi",
            name=name,
            version=version,
            dev_only=dev_only,
            source_path=str(path),
            metadata={
                "category": category,
                "optional": bool(entry.get("optional", False)),
            },
        ))
    return out
