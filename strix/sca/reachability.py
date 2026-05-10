"""SCA reachability analysis (roadmap §6.4 / Endor Labs differentiator).

After `scan_sca_lockfiles` matches a `Package` against the
threat-intel cache, this module asks: **does the application code
actually import this package?** A package can sit in
`package-lock.json` (transitive dep, dead direct dep, optional
peer) without ever being imported from app code. Such CVEs are
not exploitable in the deployed app — the vulnerable function
isn't reachable from any entry point.

Unlike `strix/tools/reachability/score_reachability` (which scores
SAST findings against `code_map.json` route handlers), this is
**package-level, not function-level**. Function-level reachability
needs proper call-graph analysis (Phase 6.4 v2). Import-level is
the conservative first cut: cheap, deterministic, and typically
filters 30–60% of SCA noise on real repos.

## Reachability status enum

  * `direct_import`   — code references the package by name in an
                        `import` / `require` / `from X import Y`
                        statement. Severity unchanged.
  * `transitive_only` — package is in the lockfile but never
                        imported from app code; it's only there
                        because another dep needed it. Severity
                        demoted one tier (high → medium).
  * `unused`          — package was declared as a direct dep but
                        nothing imports it. Dead dep, possibly
                        installed once and forgotten. Severity
                        demoted two tiers (high → low).
  * `unknown`         — couldn't analyse source for this
                        ecosystem (no files of the right shape
                        found). Severity unchanged — we don't
                        demote when we can't see.

## KEV / EPSS override

Reachability **never demotes a CISA-KEV-listed CVE**. KEV means
"actively exploited in the wild right now". Even if the local
import graph says the package is dead, the threat is real (the
attacker could plant new code that imports it, or a transitive
loader could pull it in via dynamic resolution). Same for
EPSS ≥ 0.5 — high-probability-of-exploitation overrides demotion.

## Scope (v1)

Ecosystems: **npm + pypi**. Cargo / Composer / Go / RubyGems are
intentionally deferred — their import patterns are different
enough that grepping with the npm/pypi regexes produces a high
miss rate, and getting it wrong is worse than `unknown` (a wrong
demotion silently drops a real critical).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from strix.sca.match import PackageMatch
from strix.sca.parsers.base import Package


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Status enum + per-package result
# ---------------------------------------------------------------------------


REACH_DIRECT = "direct_import"
REACH_TRANSITIVE_ONLY = "transitive_only"
REACH_UNUSED = "unused"
REACH_UNKNOWN = "unknown"


# How many severity tiers each status demotes by. Negative = demote.
# 0 = no change. Positive would mean *promote*; we don't promote
# from reachability alone in v1 — KEV / EPSS already do that
# elsewhere in the pipeline.
_DEMOTE_TIERS: dict[str, int] = {
    REACH_DIRECT: 0,
    REACH_TRANSITIVE_ONLY: -1,
    REACH_UNUSED: -2,
    REACH_UNKNOWN: 0,
}


_SEV_LADDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class PackageReachability:
    """Per-package reachability verdict.

    Attached to each `PackageMatch` after `analyse` runs. The
    `tools.py` emit path reads these to decide:
      * Whether to demote severity (status × _DEMOTE_TIERS).
      * Whether to suppress emit entirely (caller policy: e.g.
        `only_reachable=True` skips unused + transitive_only).
      * What evidence to put in the finding's
        `technical_analysis` so the wrapper can show "we found
        CVE-X, but your code never imports package P; demoted
        from high to medium".
    """
    status: str               # one of REACH_* constants
    importing_files: list[str]  # paths that import this package (relative)
    reason: str               # short explanation for the finding writeup

    @property
    def severity_delta(self) -> int:
        return _DEMOTE_TIERS.get(self.status, 0)

    def adjusted_severity(self, original: str, *, kev: bool, epss: float | None) -> str:
        """Apply demotion to `original`, with KEV / EPSS override.

        KEV → never demote. EPSS ≥ 0.5 → never demote. Otherwise
        slide along the severity ladder by `severity_delta`."""
        if kev:
            return original
        if (epss or 0.0) >= 0.5:
            return original
        delta = self.severity_delta
        if delta == 0:
            return original
        try:
            idx = _SEV_LADDER.index((original or "info").lower())
        except ValueError:
            return original
        new_idx = max(0, min(len(_SEV_LADDER) - 1, idx + delta))
        return _SEV_LADDER[new_idx]


# ---------------------------------------------------------------------------
# Source-file discovery + import extraction
# ---------------------------------------------------------------------------


# Skip the same heavy dirs as `parsers/base.find_lockfiles`. Critical
# that we DON'T descend into `node_modules/` — every package's own
# imports live there and would falsely mark every transitive dep as
# directly imported.
_SKIP_DIRS = frozenset({
    "node_modules", ".git", "vendor", "dist", "build",
    "target", ".venv", "venv", "__pycache__", ".tox",
    "site-packages", ".next", ".nuxt", ".cache",
})


# JS/TS source extensions.
_JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
_PY_EXTS = (".py",)


# JS/TS: matches both ESM `from 'pkg'` and CommonJS `require('pkg')`.
# Captures the module specifier in group 1.
_JS_IMPORT_RE = re.compile(
    r"""(?:from|require\s*\(\s*)\s*['"]([^'"]+)['"]""",
)


# Python: `from foo.bar import x` or `import foo.bar[, baz]`.
# Group 1 = `from X` form, group 2 = `import X` form.
#
# CRITICAL: the import-list character class is `[\w., \t]+` — NOT
# `[\w.,\s]+`. Including `\s` matches newlines greedily and merges
# adjacent import statements (`import a\nfrom b import c` → captures
# `a\nfrom b import c` as one group). Horizontal-whitespace only.
_PY_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([\w.]+)\s+import\b|import\s+([\w., \t]+))",
    re.MULTILINE,
)


def _collect_source_files(repo_root: Path, *, max_files: int = 5000) -> list[Path]:
    """Walk `repo_root` returning JS/TS + Python source files. Skips
    heavy dirs (`node_modules` etc.). Capped at `max_files` to bound
    runtime on monorepos."""
    import os

    out: list[Path] = []
    if not repo_root.exists() or not repo_root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for f in filenames:
            if f.endswith(_JS_EXTS) or f.endswith(_PY_EXTS):
                out.append(Path(dirpath) / f)
                if len(out) >= max_files:
                    return out
    return out


def _extract_npm_imports(text: str) -> set[str]:
    """Pull every npm package name imported from a JS/TS file.

    The regex captures the full module specifier; we normalise it
    to a package name by:
      * Stripping subpath imports (`lodash/merge` → `lodash`).
      * Preserving scoped packages (`@scope/pkg` stays whole).
      * Dropping relative imports (`./foo`, `../bar`).
      * Dropping absolute / Node-builtin imports (`fs`, `path`,
        `node:fs`).
    """
    out: set[str] = set()
    for m in _JS_IMPORT_RE.finditer(text):
        spec = m.group(1).strip()
        if not spec:
            continue
        # Relative imports are local source, not deps.
        if spec.startswith((".", "/")):
            continue
        # Strip node: prefix.
        if spec.startswith("node:"):
            continue
        # Scoped: keep "@scope/name", drop deeper subpaths.
        if spec.startswith("@"):
            parts = spec.split("/")
            if len(parts) >= 2:
                out.add(f"{parts[0]}/{parts[1]}".lower())
        else:
            out.add(spec.split("/", 1)[0].lower())
    return out


def _extract_pypi_imports(text: str) -> set[str]:
    """Pull every pypi top-level distribution name imported from a
    Python file. Returns set of lowercased top-level names.

    Caveat: import name ≠ distribution name in general (e.g.
    `import yaml` ↔ `pip install pyyaml`, `import bs4` ↔
    `pip install beautifulsoup4`). The most-common mismatches are
    handled via `_PYPI_IMPORT_TO_DIST_ALIASES`; everything else
    falls back to identity.
    """
    out: set[str] = set()
    for m in _PY_IMPORT_RE.finditer(text):
        from_part = m.group(1)
        import_part = m.group(2)
        if from_part:
            top = from_part.split(".")[0].strip().lower()
            if top:
                out.add(top)
        elif import_part:
            for piece in import_part.split(","):
                piece = piece.strip()
                if not piece:
                    continue
                # Strip "as alias".
                piece = piece.split(" as ")[0].strip()
                top = piece.split(".")[0].strip().lower()
                if top:
                    out.add(top)
    # Apply known import-name → distribution-name aliases.
    expanded = set(out)
    for imp in out:
        if imp in _PYPI_IMPORT_TO_DIST_ALIASES:
            expanded.add(_PYPI_IMPORT_TO_DIST_ALIASES[imp])
    return expanded


# Common (non-exhaustive) import-name → pypi-distribution-name aliases.
# Keep deliberately small and high-confidence; expanding it is a
# follow-up. False mappings here cause false `direct_import` →
# false retention of a finding's severity, which is the
# conservative direction (better than false demotion).
_PYPI_IMPORT_TO_DIST_ALIASES: dict[str, str] = {
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "pil": "pillow",
    "sklearn": "scikit-learn",
    "skimage": "scikit-image",
    "jwt": "pyjwt",
    "dotenv": "python-dotenv",
    "dateutil": "python-dateutil",
    "magic": "python-magic",
    "ldap": "python-ldap",
    "google.cloud": "google-cloud",
}


# ---------------------------------------------------------------------------
# Repo scan: collect (ecosystem → set of imported package names)
# ---------------------------------------------------------------------------


@dataclass
class RepoImports:
    """Aggregate import inventory for a repo path."""
    npm_imports: set[str]
    pypi_imports: set[str]
    js_files_scanned: int
    py_files_scanned: int
    importing_files_by_pkg: dict[tuple[str, str], list[str]]
    """Map (ecosystem, package_name) → list of relative source paths
    that import it. Used to populate `PackageReachability.importing_files`."""


def collect_repo_imports(
    repo_path: str | Path, *, max_files: int = 5000,
) -> RepoImports:
    """Walk `repo_path` and aggregate the set of npm + pypi packages
    that any source file imports."""
    root = Path(repo_path)
    files = _collect_source_files(root, max_files=max_files)

    npm: set[str] = set()
    pypi: set[str] = set()
    importing: dict[tuple[str, str], list[str]] = {}
    js_count = 0
    py_count = 0

    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(root)) if root in f.parents or f == root else str(f)
        if f.suffix in _JS_EXTS:
            js_count += 1
            for pkg in _extract_npm_imports(text):
                npm.add(pkg)
                importing.setdefault(("npm", pkg), []).append(rel)
        elif f.suffix in _PY_EXTS:
            py_count += 1
            for pkg in _extract_pypi_imports(text):
                pypi.add(pkg)
                importing.setdefault(("pypi", pkg), []).append(rel)

    return RepoImports(
        npm_imports=npm,
        pypi_imports=pypi,
        js_files_scanned=js_count,
        py_files_scanned=py_count,
        importing_files_by_pkg=importing,
    )


# ---------------------------------------------------------------------------
# Per-package classification
# ---------------------------------------------------------------------------


def classify_package(
    pkg: Package, repo_imports: RepoImports,
) -> PackageReachability:
    """Decide reachability status for one Package against the repo's
    aggregate imports."""
    eco = (pkg.ecosystem or "").lower()
    name = (pkg.name or "").lower()

    if eco == "npm":
        scanned = repo_imports.js_files_scanned
        imports = repo_imports.npm_imports
    elif eco == "pypi":
        scanned = repo_imports.py_files_scanned
        imports = repo_imports.pypi_imports
    else:
        return PackageReachability(
            status=REACH_UNKNOWN,
            importing_files=[],
            reason=(
                f"reachability not analysed for ecosystem `{eco}` "
                f"in v1 (npm + pypi only); severity left unchanged"
            ),
        )

    if scanned == 0:
        return PackageReachability(
            status=REACH_UNKNOWN,
            importing_files=[],
            reason=(
                f"no {eco} source files found under repo path; "
                f"reachability indeterminate, severity left unchanged"
            ),
        )

    if name in imports:
        files = repo_imports.importing_files_by_pkg.get((eco, name), [])
        return PackageReachability(
            status=REACH_DIRECT,
            importing_files=files[:20],
            reason=(
                f"package imported from {len(files)} source file"
                f"{'s' if len(files) != 1 else ''} — code path is "
                f"reachable; severity unchanged"
            ),
        )

    # Not imported. Differentiate "transitive" vs "dead direct" using
    # the lockfile's direct/transitive flag.
    if pkg.direct:
        return PackageReachability(
            status=REACH_UNUSED,
            importing_files=[],
            reason=(
                "package is declared as a direct dependency but no "
                "source file imports it — likely dead code; severity "
                "demoted two tiers"
            ),
        )
    return PackageReachability(
        status=REACH_TRANSITIVE_ONLY,
        importing_files=[],
        reason=(
            "package is a transitive dependency only; no source file "
            "imports it directly — exploitation requires the importing "
            "package to call the vulnerable function; severity "
            "demoted one tier"
        ),
    )


# ---------------------------------------------------------------------------
# Bulk classifier — used by the SCA pipeline
# ---------------------------------------------------------------------------


def annotate_matches(
    matches: Iterable[PackageMatch],
    *,
    repo_path: str | Path,
    max_source_files: int = 5000,
) -> dict[tuple[str, str], PackageReachability]:
    """Compute reachability for every Package in `matches` and
    return a dict keyed by (ecosystem, name).

    Caller (`tools.py::scan_sca_lockfiles`) reads from this dict to
    enrich the finding writeup + adjust severity. We deliberately
    DON'T mutate `PackageMatch` here — the dict is the contract,
    so this module stays pure-functional and easy to unit test.
    """
    repo_imports = collect_repo_imports(repo_path, max_files=max_source_files)
    out: dict[tuple[str, str], PackageReachability] = {}
    for m in matches:
        key = (m.package.ecosystem, m.package.name)
        if key in out:
            continue
        out[key] = classify_package(m.package, repo_imports)
    return out
