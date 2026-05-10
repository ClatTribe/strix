"""CLI for refreshing the local nuclei-templates corpus.

Usage:
    python -m strix.tools.nuclei_runner.refresh           # update or fetch
    python -m strix.tools.nuclei_runner.refresh --status  # show local state
    python -m strix.tools.nuclei_runner.refresh --branch main

Default location: `~/.cache/strix/nuclei_templates/` (override via
`STRIX_NUCLEI_TEMPLATES_DIR` env). Uses `git clone` on first run,
`git pull` on subsequent runs.

The corpus is ~150MB on disk after clone; subsequent updates are
incremental. Designed for daily cron / GitHub Actions / sidecar.

Exit codes:
  0 — refresh succeeded (or already up to date)
  1 — git operation failed
  2 — bad arguments
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path


logger = logging.getLogger(__name__)


_REPO = "https://github.com/projectdiscovery/nuclei-templates.git"
_DEFAULT_BRANCH = "main"


def templates_dir() -> Path:
    """Resolve the on-disk templates dir."""
    env = os.environ.get("STRIX_NUCLEI_TEMPLATES_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".cache" / "strix" / "nuclei_templates"


def _git_available() -> bool:
    return shutil.which("git") is not None


def _run(cmd: list[str], *, cwd: Path | None = None) -> int:
    """Run a git command; return exit code."""
    logger.info("nuclei_runner refresh: %s (cwd=%s)", " ".join(cmd), cwd or "<cwd>")
    try:
        r = subprocess.run(cmd, cwd=cwd, check=False)
        return r.returncode
    except Exception as e:  # noqa: BLE001
        logger.warning("nuclei_runner refresh subprocess failed: %s", e)
        return 1


def _is_git_repo(p: Path) -> bool:
    return (p / ".git").exists()


def refresh(
    *,
    repo: str = _REPO,
    branch: str = _DEFAULT_BRANCH,
    target: Path | None = None,
) -> dict[str, object]:
    """Clone or update the nuclei-templates corpus.

    Returns:
        {"status": "ok" | "error", "action": "cloned" | "pulled" |
         "noop" | "no_git", "path": "...", "error": ...}
    """
    if not _git_available():
        return {
            "status": "error",
            "action": "no_git",
            "path": str(target or templates_dir()),
            "error": (
                "git not found on PATH. Install git or pre-populate "
                "the corpus at the expected directory."
            ),
        }

    target = target or templates_dir()
    target.parent.mkdir(parents=True, exist_ok=True)

    if not target.exists():
        rc = _run(["git", "clone", "--depth", "1",
                   "--branch", branch, repo, str(target)])
        if rc != 0:
            return {
                "status": "error",
                "action": "clone_failed",
                "path": str(target),
                "error": f"git clone exited {rc}",
            }
        return {"status": "ok", "action": "cloned", "path": str(target)}

    if not _is_git_repo(target):
        return {
            "status": "error",
            "action": "not_git_repo",
            "path": str(target),
            "error": (
                f"{target} exists but is not a git repo. Remove it "
                "or set STRIX_NUCLEI_TEMPLATES_DIR to a different path."
            ),
        }

    rc = _run(["git", "fetch", "--depth", "1", "origin", branch], cwd=target)
    if rc != 0:
        return {
            "status": "error",
            "action": "fetch_failed",
            "path": str(target),
            "error": f"git fetch exited {rc}",
        }
    rc = _run(["git", "reset", "--hard", f"origin/{branch}"], cwd=target)
    if rc != 0:
        return {
            "status": "error",
            "action": "reset_failed",
            "path": str(target),
            "error": f"git reset exited {rc}",
        }
    return {"status": "ok", "action": "pulled", "path": str(target)}


def status() -> dict[str, object]:
    """Local-state diagnostic."""
    p = templates_dir()
    out: dict[str, object] = {
        "path": str(p),
        "exists": p.exists(),
        "is_git_repo": _is_git_repo(p) if p.exists() else False,
    }
    if p.exists():
        # Count YAML files.
        n = 0
        for root, _dirs, files in os.walk(p):
            for f in files:
                if f.endswith((".yaml", ".yml")):
                    n += 1
        out["template_count"] = n
        if _is_git_repo(p):
            r = subprocess.run(
                ["git", "log", "-1", "--format=%H %ci %s"],
                cwd=p, capture_output=True, text=True, check=False,
            )
            out["latest_commit"] = (r.stdout or "").strip()[:200]
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="strix.tools.nuclei_runner.refresh",
        description="Clone or update the nuclei-templates corpus.",
    )
    p.add_argument("--branch", default=_DEFAULT_BRANCH)
    p.add_argument("--status", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    if args.status:
        s = status()
        print(f"Path: {s['path']}")
        print(f"Exists: {s['exists']}")
        print(f"Git repo: {s['is_git_repo']}")
        if s.get("template_count") is not None:
            print(f"YAML templates: {s['template_count']:,}")
        if s.get("latest_commit"):
            print(f"Latest commit: {s['latest_commit']}")
        return 0

    result = refresh(branch=args.branch)
    print(f"action: {result['action']}")
    print(f"path: {result['path']}")
    if result["status"] != "ok":
        print(f"error: {result.get('error')}", file=sys.stderr)
        return 1
    print("status: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
