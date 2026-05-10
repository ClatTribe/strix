"""Git-diff-aware file scoping (Phase 7.3).

For PR-time scanning, only run SAST rules on files actually
changed in the diff. Vibe-coded apps push 10–50 PRs/day; running
the full repo on each is wasteful and a noise vector (every
existing finding re-emits on every push).

The lead-agent-facing `scan_sast` accepts `since_commit=` and
optionally `until_commit=`. We resolve those to a list of changed
file paths via `git diff --name-only --diff-filter=AM`:

  * `A` — added files (run rules on them)
  * `M` — modified files (run rules on them)
  * `D` — deleted (skip — the file is gone; old findings won't fire)
  * `R` — renamed (treat the destination as modified)

When the repo isn't a git checkout, or the commit refs don't
resolve, return `DiffScope(usable=False)` so the caller falls
back to a full repo scan rather than scanning nothing.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


logger = logging.getLogger(__name__)


_SAST_FILE_EXTS: tuple[str, ...] = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".go", ".rb", ".php", ".cs", ".kt", ".swift",
)


@dataclass
class DiffScope:
    """Result of resolving a diff range to a file list.

    `usable=False` means the caller should run the full repo
    scan — diff resolution failed (not a git repo, ref doesn't
    exist, etc.). `files=[]` with `usable=True` means the diff
    was clean (no source changes); the caller should NOT run a
    full scan in this case — there's nothing to scan.
    """
    usable: bool
    files: list[str] = field(default_factory=list)
    error: str | None = None


def git_changed_files(
    repo_path: str | Path,
    *,
    since_commit: str = "HEAD~1",
    until_commit: str = "HEAD",
    file_exts: tuple[str, ...] = _SAST_FILE_EXTS,
) -> DiffScope:
    """Return paths of source files changed between two refs.

    Args:
        repo_path: directory containing the git checkout.
        since_commit: base ref (the "from" side of the diff).
            Default `HEAD~1`. PR workflows typically pass
            `origin/main` or `merge-base origin/main HEAD`.
        until_commit: tip ref (the "to" side). Default `HEAD`.
        file_exts: only return files matching one of these
            extensions. Default = SAST-supported languages.

    Returns:
        `DiffScope`. `files` contains paths RELATIVE to the
        repo root with forward-slash separators (matches the
        path Semgrep emits in findings).
    """
    repo = Path(repo_path).resolve()
    if not repo.is_dir():
        return DiffScope(usable=False, error=f"not a directory: {repo}")
    if shutil.which("git") is None:
        return DiffScope(usable=False, error="git not on PATH")
    if not (repo / ".git").exists():
        # Could be a worktree / submodule whose .git is a file
        # pointer — `git rev-parse` will tell us.
        try:
            r = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                cwd=str(repo), capture_output=True, text=True,
                timeout=5, check=False,
            )
            if r.returncode != 0:
                return DiffScope(
                    usable=False,
                    error=f"not a git repository: {repo}",
                )
        except (subprocess.TimeoutExpired, OSError) as e:
            return DiffScope(usable=False, error=str(e))

    cmd = [
        "git", "diff",
        "--name-only",
        "--diff-filter=AMR",   # added / modified / renamed
        f"{since_commit}...{until_commit}",
    ]
    try:
        r = subprocess.run(
            cmd, cwd=str(repo), capture_output=True, text=True,
            timeout=15, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return DiffScope(usable=False, error=str(e))

    if r.returncode != 0:
        # Most common cause: unknown ref. Caller falls back to
        # full scan rather than failing the whole pipeline.
        return DiffScope(
            usable=False,
            error=(
                f"git diff failed (rc={r.returncode}): "
                f"{(r.stderr or '').strip()[:200]}"
            ),
        )

    raw_files = [line.strip() for line in (r.stdout or "").splitlines()
                 if line.strip()]
    filtered: list[str] = []
    for f in raw_files:
        # Diff outputs are repo-root-relative with forward slashes.
        # Filter by extension.
        if not f.endswith(file_exts):
            continue
        # Skip files that no longer exist (rename or delete cases
        # the filter didn't fully exclude).
        full = repo / f
        if not full.exists():
            continue
        filtered.append(f)

    return DiffScope(usable=True, files=filtered)
