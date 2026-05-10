"""Common Package dataclass + parser registry.

Every per-ecosystem parser returns `list[Package]`. A central
registry maps lockfile filename patterns → parser function so
`parse_lockfile(path)` can auto-dispatch.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


logger = logging.getLogger(__name__)


@dataclass
class Package:
    """One package extracted from a lockfile.

    `version_pattern` mirrors the threat-intel cache convention so
    `find_vulnerabilities` can match CPE / GHSA range expressions
    directly without a second translation layer.
    """
    ecosystem: str        # "npm" | "pypi" | "rubygems" | "cargo" | "composer" | "go"
    name: str             # canonical package name (lowercased for match)
    version: str          # exact version string from the lockfile
    dev_only: bool = False
    direct: bool = True   # False for transitive
    source_path: str = "" # lockfile path
    metadata: dict = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "dev_only": self.dev_only,
            "direct": self.direct,
            "source_path": self.source_path,
            "metadata": dict(self.metadata),
        }


_FILENAME_PARSERS: dict[str, Callable[[Path], list[Package]]] = {}
_PATTERN_PARSERS: list[tuple[re.Pattern, Callable[[Path], list[Package]]]] = []


def register_parser(
    *,
    filenames: list[str] | None = None,
    patterns: list[str] | None = None,
) -> Callable[[Callable[[Path], list[Package]]], Callable[[Path], list[Package]]]:
    """Decorator: register a per-ecosystem parser.

    `filenames` matches by exact basename (case-insensitive).
    `patterns` matches by regex on basename. Both register the same
    function — common case is just one or the other.
    """
    def decorator(fn: Callable[[Path], list[Package]]):
        for name in (filenames or []):
            _FILENAME_PARSERS[name.lower()] = fn
        for pat in (patterns or []):
            _PATTERN_PARSERS.append((re.compile(pat, re.IGNORECASE), fn))
        return fn
    return decorator


def _parser_for(path: Path) -> Callable[[Path], list[Package]] | None:
    """Resolve the parser for a given filesystem path. Returns None
    when no registered parser matches."""
    base = path.name.lower()
    if base in _FILENAME_PARSERS:
        return _FILENAME_PARSERS[base]
    for pat, fn in _PATTERN_PARSERS:
        if pat.search(base):
            return fn
    return None


def parse_lockfile(path: str | Path) -> list[Package]:
    """Auto-detect lockfile format from filename and parse.

    Returns an empty list when:
      * file doesn't exist
      * format isn't recognised
      * parser raises (logged at debug level)
    """
    p = Path(path)
    if not p.exists() or not p.is_file():
        return []
    parser = _parser_for(p)
    if parser is None:
        return []
    try:
        return parser(p)
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "sca: parser %s failed for %s: %s",
            parser.__name__, p, e, exc_info=True,
        )
        return []


def find_lockfiles(repo_path: str | Path, *, max_files: int = 100) -> list[Path]:
    """Walk `repo_path` recursively, returning paths of files that
    a registered parser would handle. Skips common heavy directories
    (node_modules, .git, vendor, dist, build) to avoid scanning the
    inside of installed dependencies."""
    import os
    skip_dirs = {
        "node_modules", ".git", "vendor", "dist", "build",
        "target", ".venv", "venv", "__pycache__", ".tox",
        "site-packages",
    }
    out: list[Path] = []
    root = Path(repo_path)
    if not root.exists():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        # Mutate dirnames in place to prevent recursion into skip_dirs.
        dirnames[:] = [d for d in dirnames if d.lower() not in skip_dirs]
        for f in filenames:
            full = Path(dirpath) / f
            if _parser_for(full) is not None:
                out.append(full)
                if len(out) >= max_files:
                    return out
    return out
