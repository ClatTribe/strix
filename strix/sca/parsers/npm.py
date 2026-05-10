"""npm lockfile parsers — package-lock.json (v1/v2/v3) + yarn.lock
+ pnpm-lock.yaml.

Per-format notes:

  * **package-lock.json v1** — has `dependencies` map at top level
  * **package-lock.json v2/v3** — has `packages` map keyed by path,
    plus legacy `dependencies` for v2 backwards compat
  * **yarn.lock** — custom format (key blocks separated by blank lines)
  * **pnpm-lock.yaml** — YAML; `packages:` map keyed by `/<name>@<version>`

Output: list of `Package` records keyed by canonical name + version.
Transitive deps included; `direct=False` for them. `dev_only` is set
when the package is exclusively in `devDependencies` chains.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from strix.sca.parsers.base import Package, register_parser


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# package-lock.json
# ---------------------------------------------------------------------------


@register_parser(filenames=["package-lock.json"])
def parse_package_lock(path: Path) -> list[Package]:
    """Parse npm v1/v2/v3 package-lock.json."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("sca/npm: failed to parse %s: %s", path, e)
        return []

    out: list[Package] = []
    seen: set[tuple[str, str]] = set()  # (name, version)

    # v2/v3: packages map keyed by node_modules path.
    packages = doc.get("packages")
    if isinstance(packages, dict):
        # The empty-key entry "" describes the root project; skip.
        for pkg_path, info in packages.items():
            if not isinstance(info, dict) or pkg_path == "":
                continue
            # Path looks like "node_modules/express" or
            # "node_modules/express/node_modules/qs". The package
            # name is the last `node_modules/<name>` segment.
            m = re.findall(r"node_modules/([^/]+)", pkg_path)
            if not m:
                continue
            name = m[-1].lower().strip()
            version = (info.get("version") or "").strip()
            if not name or not version:
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            out.append(Package(
                ecosystem="npm",
                name=name,
                version=version,
                dev_only=bool(info.get("dev")),
                direct=info.get("indirect", False) is False,
                source_path=str(path),
                metadata={
                    "resolved": info.get("resolved", ""),
                    "integrity": info.get("integrity", ""),
                    "license": info.get("license"),
                },
            ))

    # v1: top-level `dependencies` map (also present in v2 for
    # backwards compat — only walk when v2 packages was empty).
    if not out:
        deps = doc.get("dependencies")
        if isinstance(deps, dict):
            _walk_v1_deps(deps, out=out, seen=seen, source_path=path,
                          dev_only=False, depth=0)

    return out


def _walk_v1_deps(
    deps: dict[str, Any], *, out: list[Package],
    seen: set[tuple[str, str]], source_path: Path,
    dev_only: bool, depth: int,
) -> None:
    """Recursive walk of v1 `dependencies` tree."""
    if depth > 50:  # cycle guard
        return
    for name, info in deps.items():
        if not isinstance(info, dict):
            continue
        version = (info.get("version") or "").strip()
        if not name or not version:
            continue
        canon = name.lower().strip()
        key = (canon, version)
        if key in seen:
            continue
        seen.add(key)
        is_dev = dev_only or bool(info.get("dev"))
        out.append(Package(
            ecosystem="npm",
            name=canon,
            version=version,
            dev_only=is_dev,
            direct=(depth == 0),
            source_path=str(source_path),
            metadata={"resolved": info.get("resolved", "")},
        ))
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1_deps(
                nested, out=out, seen=seen, source_path=source_path,
                dev_only=is_dev, depth=depth + 1,
            )


# ---------------------------------------------------------------------------
# yarn.lock (Yarn v1 — classic format)
# ---------------------------------------------------------------------------


_YARN_BLOCK_RE = re.compile(
    r'^"?([^"\n,]+)"?(?:,\s*"?([^"\n,]+)"?)*:\s*$', re.MULTILINE,
)
_YARN_VERSION_RE = re.compile(r'^\s+version\s+"([^"]+)"', re.MULTILINE)


@register_parser(filenames=["yarn.lock"])
def parse_yarn_lock(path: Path) -> list[Package]:
    """Parse yarn.lock (Yarn 1.x classic format).

    Yarn 2+ uses Berry format which is YAML-shaped — we parse it as
    YAML if the file starts with `__metadata:`."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # Detect Yarn 2+ Berry format.
    if text.lstrip().startswith("__metadata:") or "__metadata:" in text[:200]:
        return _parse_yarn_berry(text, path)

    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    # Yarn 1 file is blocks like:
    #   "express@^4.17.1":
    #     version "4.17.3"
    #     resolved "..."
    blocks = re.split(r"\n\n+", text)
    for block in blocks:
        first_line = block.split("\n", 1)[0].strip()
        if not first_line.endswith(":"):
            continue
        # Strip trailing colon; the line may be one or more
        # comma-separated keys: `"foo@^1.0.0", "foo@^2.0.0":`
        spec_str = first_line[:-1].strip()
        # Extract version
        v_match = _YARN_VERSION_RE.search(block)
        if not v_match:
            continue
        version = v_match.group(1).strip()
        # The key string contains one or more "name@range" specs;
        # the FIRST gives us the canonical name.
        first_spec = spec_str.split(",", 1)[0].strip().strip('"')
        # Strip the version constraint.
        if "@" in first_spec.lstrip("@"):
            # Handle scoped names: "@scope/name@^1"
            if first_spec.startswith("@"):
                # Find the second `@`
                idx = first_spec.find("@", 1)
                name = first_spec[:idx] if idx > 0 else first_spec
            else:
                name = first_spec.split("@", 1)[0]
        else:
            name = first_spec
        name = name.lower().strip()
        if not name or not version:
            continue
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(Package(
            ecosystem="npm",
            name=name,
            version=version,
            dev_only=False,  # yarn 1 doesn't track dev in lockfile
            direct=False,    # can't tell from lockfile alone
            source_path=str(path),
        ))
    return out


def _parse_yarn_berry(text: str, path: Path) -> list[Package]:
    """Parse Yarn 2+ Berry lockfile (YAML)."""
    try:
        import yaml
        doc = yaml.safe_load(text)
    except Exception as e:  # noqa: BLE001
        logger.debug("sca/yarn-berry parse failed: %s", e)
        return []
    if not isinstance(doc, dict):
        return []
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for key, info in doc.items():
        if key in ("__metadata", "type") or not isinstance(info, dict):
            continue
        version = (info.get("version") or "").strip()
        if not version:
            continue
        # Key is like "express@npm:^4.17.1" or
        # "@scope/name@npm:^1.0.0,@scope/name@npm:^2.0.0"
        first_spec = str(key).split(",", 1)[0].strip()
        if first_spec.startswith("@"):
            idx = first_spec.find("@", 1)
            name = first_spec[:idx] if idx > 0 else first_spec
        else:
            name = first_spec.split("@", 1)[0]
        name = name.lower().strip()
        if not name:
            continue
        kk = (name, version)
        if kk in seen:
            continue
        seen.add(kk)
        out.append(Package(
            ecosystem="npm",
            name=name,
            version=version,
            source_path=str(path),
        ))
    return out


# ---------------------------------------------------------------------------
# pnpm-lock.yaml
# ---------------------------------------------------------------------------


@register_parser(filenames=["pnpm-lock.yaml"])
def parse_pnpm_lock(path: Path) -> list[Package]:
    """Parse pnpm-lock.yaml. The `packages:` map is keyed by
    `/<name>/<version>` or `/<name>@<version>` depending on lockfile
    version."""
    try:
        import yaml
        text = path.read_text(encoding="utf-8", errors="replace")
        doc = yaml.safe_load(text)
    except Exception as e:  # noqa: BLE001
        logger.debug("sca/pnpm parse failed: %s", e)
        return []
    if not isinstance(doc, dict):
        return []
    pkgs = doc.get("packages")
    if not isinstance(pkgs, dict):
        return []
    out: list[Package] = []
    seen: set[tuple[str, str]] = set()
    for key, info in pkgs.items():
        if not isinstance(key, str):
            continue
        # Strip leading slash.
        spec = key.lstrip("/").strip()
        # Modern format: "express@4.18.0" or "@scope/name@1.0.0"
        if "@" in spec.lstrip("@"):
            if spec.startswith("@"):
                idx = spec.find("@", 1)
                if idx > 0:
                    name = spec[:idx]
                    version = spec[idx + 1:]
                else:
                    continue
            else:
                name, version = spec.split("@", 1)
        else:
            # Legacy format: "/express/4.18.0/<peer-id>"
            parts = spec.split("/")
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]
            else:
                continue
        # Strip suffix like "_<peer-id>" or "(peer-deps...)"
        version = re.split(r"[_()]", version)[0].strip()
        name = name.lower().strip()
        if not name or not version:
            continue
        kk = (name, version)
        if kk in seen:
            continue
        seen.add(kk)
        info = info if isinstance(info, dict) else {}
        out.append(Package(
            ecosystem="npm",
            name=name,
            version=version,
            dev_only=bool(info.get("dev")),
            source_path=str(path),
        ))
    return out
