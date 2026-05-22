"""iter-25.8 — git-blame enrichment (Gap 6 in docs/L2-optimization.md).

Real engineers ask "Who wrote this, when, and what was the commit
message?" for every code-anchored finding. Three reasons:

  1. New code = higher attention (production drift, missed review).
  2. PR context sometimes reveals "this was a quick hack, will fix later."
  3. Authorship helps with remediation routing.

This module attaches `{author, commit_date, days_since_change,
commit_subject}` to every code-anchored finding by shelling out to
`git blame -L line,line --porcelain` once per (repo_sha, file, line)
tuple. Results are memoised in a process-local cache so the same
finding hit by multiple specialists doesn't shell out repeatedly.

On monorepos, `git blame -L` is O(file history) and can be the
dominant cost. The cache amortises that; for findings with no `line`
we skip blame entirely.

Recall-safe: any git error / timeout returns ``None`` and the
caller's enrichment hook leaves the finding unchanged.
"""

from __future__ import annotations

import datetime as _dt
import logging
import shutil
import subprocess  # noqa: S404
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


_GIT_TIMEOUT_S = 8


@dataclass(frozen=True)
class GitBlame:
    """One blame record for a (file, line) pair."""
    author: str
    commit_date: str          # ISO 8601 (YYYY-MM-DD)
    days_since_change: int
    commit_subject: str
    commit_sha: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "author": self.author,
            "commit_date": self.commit_date,
            "days_since_change": self.days_since_change,
            "commit_subject": self.commit_subject,
            "commit_sha": self.commit_sha,
        }


def _git_available() -> bool:
    return shutil.which("git") is not None


def _find_repo_root(path: Path) -> Path | None:
    """Walk up from ``path`` to find the nearest .git dir."""
    cur = path.resolve()
    if cur.is_file():
        cur = cur.parent
    for _ in range(50):  # cap traversal
        if (cur / ".git").exists():
            return cur
        if cur == cur.parent:
            return None
        cur = cur.parent
    return None


def _parse_porcelain(out: str) -> GitBlame | None:
    """Parse `git blame --porcelain -L N,N` output into a GitBlame."""
    author = "unknown"
    subject = ""
    sha = ""
    date_ts: int | None = None
    for line in out.splitlines():
        if not line:
            continue
        if not sha and len(line) >= 40 and line[40:41] == " ":
            sha = line[:40]
            continue
        if line.startswith("author "):
            author = line.split(" ", 1)[1].strip()
        elif line.startswith("author-time "):
            try:
                date_ts = int(line.split(" ", 1)[1].strip())
            except ValueError:
                date_ts = None
        elif line.startswith("summary "):
            subject = line.split(" ", 1)[1].strip()
    if not sha or date_ts is None:
        return None
    commit_date = _dt.datetime.fromtimestamp(
        date_ts, tz=_dt.timezone.utc,
    ).strftime("%Y-%m-%d")
    days_since = (
        _dt.datetime.now(tz=_dt.timezone.utc)
        - _dt.datetime.fromtimestamp(date_ts, tz=_dt.timezone.utc)
    ).days
    return GitBlame(
        author=author,
        commit_date=commit_date,
        days_since_change=max(0, days_since),
        commit_subject=subject,
        commit_sha=sha,
    )


# (repo_root, file_rel, line) → GitBlame
_blame_cache: dict[tuple[str, str, int], GitBlame | None] = {}
_cache_lock = threading.RLock()


def clear_cache() -> None:
    """Wipe the blame cache. Tests call this between cases."""
    with _cache_lock:
        _blame_cache.clear()


def get_blame(file: str, line: int) -> GitBlame | None:
    """Return blame for (file, line) — memoised, recall-safe."""
    try:
        if not file or line is None or line < 1:
            return None
        if not _git_available():
            return None
        path = Path(file)
        if not path.exists():
            return None
        repo_root = _find_repo_root(path)
        if repo_root is None:
            return None
        try:
            rel = str(path.resolve().relative_to(repo_root))
        except ValueError:
            return None

        key = (str(repo_root), rel, int(line))
        with _cache_lock:
            if key in _blame_cache:
                return _blame_cache[key]

        try:
            result = subprocess.run(  # noqa: S603
                [
                    "git", "-C", str(repo_root), "blame",
                    "-L", f"{line},{line}",
                    "--porcelain", rel,
                ],
                check=False, capture_output=True,
                timeout=_GIT_TIMEOUT_S, text=True,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug("git blame timeout/OS error: %s", e)
            with _cache_lock:
                _blame_cache[key] = None
            return None

        if result.returncode != 0:
            with _cache_lock:
                _blame_cache[key] = None
            return None

        blame = _parse_porcelain(result.stdout or "")
        with _cache_lock:
            _blame_cache[key] = blame
        return blame
    except Exception as e:  # noqa: BLE001
        logger.debug("get_blame failed: %s", e)
        return None


def enrich_finding_with_blame(finding: dict[str, Any]) -> None:
    """Attach git-blame info to a finding under ``git_blame``.

    Mutates ``finding`` in place. No-op if blame can't be obtained.
    """
    try:
        code_locs = finding.get("code_locations") or []
        if not (isinstance(code_locs, list) and code_locs):
            return
        first = code_locs[0]
        if not isinstance(first, dict):
            return
        file = first.get("file") or first.get("path")
        line = first.get("line") or first.get("start_line")
        if not file or not line:
            return
        if isinstance(line, str) and line.isdigit():
            line = int(line)
        if not isinstance(line, int):
            return
        blame = get_blame(str(file), line)
        if blame is not None:
            finding["git_blame"] = blame.to_dict()
    except Exception as e:  # noqa: BLE001
        logger.debug("enrich_finding_with_blame failed: %s", e)
