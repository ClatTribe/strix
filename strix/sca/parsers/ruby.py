"""Gemfile.lock parser (Ruby)."""

from __future__ import annotations

import logging
from pathlib import Path

from strix.sca.parsers.base import Package, register_parser


logger = logging.getLogger(__name__)


@register_parser(filenames=["gemfile.lock"])
def parse_gemfile_lock(path: Path) -> list[Package]:
    """Gemfile.lock has a `GEM` section followed by `specs:` lines:

        GEM
          remote: https://rubygems.org/
          specs:
            actionview (7.0.4)
              activesupport (= 7.0.4)
            ...

    Top-level entries (4-space-indented `name (version)`) are
    packages; deeper indentation is dependencies of those packages.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    in_gem_section = False
    for raw in text.splitlines():
        if raw.startswith("GEM") or raw.startswith("PATH") or raw.startswith("GIT"):
            in_gem_section = True
            continue
        if raw.startswith("DEPENDENCIES") or raw.startswith("BUNDLED WITH"):
            in_gem_section = False
            continue
        if not in_gem_section:
            continue
        # Only "    name (version)" lines (4 leading spaces, no more).
        if not raw.startswith("    ") or raw.startswith("      "):
            continue
        body = raw[4:]
        # `name (version)` — version is in parentheses
        if "(" not in body or ")" not in body:
            continue
        name = body[:body.index("(")].strip()
        version = body[body.index("(") + 1: body.index(")")].strip()
        # Skip range specifiers (= X, >= X) — these are dep refs, not pinned versions.
        if any(c in version for c in ["<", ">", "~", "="]):
            continue
        canon = name.lower().strip()
        if not canon or not version:
            continue
        key = (canon, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Package(
            ecosystem="rubygems",
            name=canon,
            version=version,
            source_path=str(path),
        ))
    return out
