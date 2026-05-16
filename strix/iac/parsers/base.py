"""Common IacFile dataclass + parser registry for Phase 11.

Mirrors `strix/sca/parsers/base.py`'s shape: each platform parser
registers via `@register_parser(filenames=..., patterns=...)` and
returns an `IacFile` record. The scanner walks a repo, dispatches
files to registered parsers, and runs rules against the parsed
structure.

`IacFile` is deliberately less structured than `Package` from SCA —
each platform has wildly different schemas (vercel.json's nested
headers array vs Dockerfile's directive list). Each parser stores
the platform-shaped data in `IacFile.data` and the rule registry
dispatches on `platform` to apply the right checks.

We don't try to be format-agnostic; that direction lies madness.
Instead we ship platform-specific parsers + platform-specific rule
modules and accept that adding "now do Terraform" means a new
parser + a new rule module.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


logger = logging.getLogger(__name__)


# Platforms strix's IaC engine recognises today. Adding a new one:
#   1. Add a constant here.
#   2. Add a parser that emits IacFile(platform=PLATFORM_X, ...).
#   3. Add a rule module under `strix/iac/rules/`.
PLATFORM_VERCEL = "vercel"
PLATFORM_NETLIFY = "netlify"
PLATFORM_CLOUDFLARE = "cloudflare"
PLATFORM_DOCKER = "docker"
PLATFORM_DOCKER_COMPOSE = "docker-compose"
PLATFORM_TERRAFORM = "terraform"
PLATFORM_KUBERNETES = "kubernetes"
PLATFORM_HELM = "helm"


@dataclass
class IacFile:
    """One parsed IaC file.

    Per-platform parsers populate `data` with a platform-specific
    structure (a dict for JSON / YAML / TOML configs; a list of
    parsed directives for Dockerfile). Rules read `data` directly
    via `platform` dispatch.
    """
    platform: str            # one of PLATFORM_* constants
    path: str                # absolute path to the file
    data: dict | list        # parsed contents (platform-shaped)
    raw_text: str = ""       # original file text — useful for
                             # rules that need line-precise hits
    parse_error: str | None = None  # set when parsing failed
                                     # but a partial result was salvaged

    @property
    def basename(self) -> str:
        return Path(self.path).name


_FILENAME_PARSERS: dict[str, Callable[[Path], IacFile | None]] = {}
_PATTERN_PARSERS: list[
    tuple[re.Pattern, Callable[[Path], IacFile | None]]
] = []


def register_parser(
    *,
    filenames: list[str] | None = None,
    patterns: list[str] | None = None,
) -> Callable:
    """Decorator: register an IaC parser.

    `filenames` matches by exact basename (case-insensitive).
    `patterns` matches by regex on basename — useful for
    Dockerfile variants like `Dockerfile.dev`.
    """
    def decorator(fn: Callable[[Path], IacFile | None]):
        for name in (filenames or []):
            _FILENAME_PARSERS[name.lower()] = fn
        for pat in (patterns or []):
            _PATTERN_PARSERS.append(
                (re.compile(pat, re.IGNORECASE), fn),
            )
        return fn
    return decorator


def _parser_for(path: Path) -> Callable[[Path], IacFile | None] | None:
    base = path.name.lower()
    if base in _FILENAME_PARSERS:
        return _FILENAME_PARSERS[base]
    for pat, fn in _PATTERN_PARSERS:
        if pat.search(base):
            return fn
    return None


def parse_iac_file(path: str | Path) -> IacFile | None:
    """Auto-detect platform from filename and parse. Returns
    None when no parser matches OR when parsing raised hard."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    parser = _parser_for(p)
    if parser is None:
        return None
    try:
        return parser(p)
    except Exception as e:  # noqa: BLE001
        logger.debug("iac: parser %s failed for %s: %s",
                     parser.__name__, p, e, exc_info=True)
        return None


# Same skip-dirs convention as the SCA / SAST walkers — never
# descend into installed deps, build outputs, or VCS metadata.
_SKIP_DIRS = frozenset({
    "node_modules", ".git", "vendor", "dist", "build",
    "target", ".venv", "venv", "__pycache__", ".tox",
    "site-packages", ".next", ".nuxt", ".cache", ".terraform",
})


def find_iac_files(
    repo_path: str | Path, *, max_files: int = 200,
) -> list[Path]:
    """Walk `repo_path` returning paths of files a registered IaC
    parser would handle. Skips heavy dirs."""
    import os

    out: list[Path] = []
    root = Path(repo_path)
    if not root.exists() or not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_DIRS]
        for f in filenames:
            full = Path(dirpath) / f
            if _parser_for(full) is not None:
                out.append(full)
                if len(out) >= max_files:
                    return out
    return out
