"""go.sum / go.mod parser (Go modules)."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from strix.sca.parsers.base import Package, register_parser


logger = logging.getLogger(__name__)


# go.sum entries:
#   github.com/foo/bar v1.2.3 h1:hash...
#   github.com/foo/bar v1.2.3/go.mod h1:hash...
_GO_SUM_RE = re.compile(
    r"^([^\s]+)\s+([^\s]+?)(/go\.mod)?\s+h1:[^\s]+",
    re.MULTILINE,
)


@register_parser(filenames=["go.sum"])
def parse_go_sum(path: Path) -> list[Package]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for m in _GO_SUM_RE.finditer(text):
        name = m.group(1).strip()
        version = m.group(2).strip()
        # Strip "+incompatible" suffix.
        if version.endswith("+incompatible"):
            version = version[:-len("+incompatible")]
        if not name or not version:
            continue
        # Lowercase the module path for case-insensitive matching;
        # GHSA Go ecosystem uses lowercase.
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Package(
            ecosystem="go",
            name=name.lower(),
            version=version,
            source_path=str(path),
        ))
    return out


# go.mod has a `require` block listing direct dependencies; we don't
# parse it for version data (go.sum is the lockfile of record), but
# detecting it lets us skip directories that have only go.mod.
@register_parser(filenames=["go.mod"])
def parse_go_mod(path: Path) -> list[Package]:
    """Best-effort go.mod parser — extracts direct deps for
    completeness when go.sum isn't present (rare in real
    projects)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    # Match both `require X v1.2.3` and `require ( X v1.2.3 ... )` blocks.
    for m in re.finditer(
        r"(?:^|\n)\s*([^\s]+)\s+(v[0-9][^\s]*)\s*(?://[^\n]*)?$",
        text,
        re.MULTILINE,
    ):
        candidate = m.group(1).strip()
        # Skip non-module-path tokens (e.g. "require", "module", "go").
        if "." not in candidate or candidate in ("require", "go", "module", "toolchain"):
            continue
        version = m.group(2).strip()
        if version.endswith("+incompatible"):
            version = version[:-len("+incompatible")]
        canon = candidate.lower()
        if not canon or not version:
            continue
        key = (canon, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Package(
            ecosystem="go",
            name=canon,
            version=version,
            direct=True,
            source_path=str(path),
        ))
    return out
