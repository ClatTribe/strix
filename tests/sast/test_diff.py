"""Unit tests for `strix.sast.diff` — Phase 7.3 git-diff-aware
file scoping."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from strix.sast.diff import DiffScope, git_changed_files


def _run(cmd: list[str], cwd: Path) -> int:
    """Run a command in `cwd`, return exit code. Used to set up
    a real tmpfs git repo for the integration tests."""
    return subprocess.run(
        cmd, cwd=str(cwd), capture_output=True, text=True,
        check=False,
    ).returncode


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Initialise a tmpfs git repo with one initial commit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    assert _run(["git", "init", "-q"], repo) == 0
    assert _run(["git", "config", "user.email", "t@t"], repo) == 0
    assert _run(["git", "config", "user.name", "t"], repo) == 0
    assert _run(["git", "config", "commit.gpgsign", "false"], repo) == 0

    (repo / "app.js").write_text("console.log('initial');\n")
    (repo / "model.py").write_text("# initial\n")
    (repo / "README.md").write_text("doc\n")
    assert _run(["git", "add", "-A"], repo) == 0
    assert _run(["git", "commit", "-q", "-m", "initial"], repo) == 0
    return repo


def test_returns_unusable_when_not_a_git_repo(tmp_path: Path) -> None:
    scope = git_changed_files(tmp_path)
    assert scope.usable is False
    assert "not a git repository" in (scope.error or "")


def test_returns_unusable_when_path_not_directory(tmp_path: Path) -> None:
    scope = git_changed_files(tmp_path / "nonexistent")
    assert scope.usable is False


def test_diff_scope_lists_modified_files(git_repo: Path) -> None:
    """Modify one .py + one .js file; both should appear in the
    diff scope."""
    (git_repo / "app.js").write_text("console.log('updated');\n")
    (git_repo / "model.py").write_text("# updated\n")
    _run(["git", "add", "-A"], git_repo)
    _run(["git", "commit", "-q", "-m", "update"], git_repo)

    scope = git_changed_files(git_repo, since_commit="HEAD~1")
    assert scope.usable is True
    assert "app.js" in scope.files
    assert "model.py" in scope.files


def test_diff_scope_filters_non_source_files(git_repo: Path) -> None:
    """README.md change should NOT appear — markdown isn't a SAST
    target language."""
    (git_repo / "README.md").write_text("changed\n")
    _run(["git", "add", "-A"], git_repo)
    _run(["git", "commit", "-q", "-m", "doc"], git_repo)

    scope = git_changed_files(git_repo, since_commit="HEAD~1")
    assert scope.usable is True
    assert "README.md" not in scope.files


def test_diff_scope_filters_added_files(git_repo: Path) -> None:
    """Added files should be in scope (--diff-filter=AMR)."""
    (git_repo / "newfile.ts").write_text("export {};\n")
    _run(["git", "add", "-A"], git_repo)
    _run(["git", "commit", "-q", "-m", "add"], git_repo)

    scope = git_changed_files(git_repo, since_commit="HEAD~1")
    assert "newfile.ts" in scope.files


def test_diff_scope_skips_deleted_files(git_repo: Path) -> None:
    """Deleted files have nothing to scan; --diff-filter excludes
    them. Critical correctness — running rules on a phantom
    deleted-path target would error in Semgrep."""
    (git_repo / "app.js").unlink()
    _run(["git", "add", "-A"], git_repo)
    _run(["git", "commit", "-q", "-m", "rm"], git_repo)

    scope = git_changed_files(git_repo, since_commit="HEAD~1")
    assert "app.js" not in scope.files


def test_diff_scope_invalid_ref_returns_unusable(git_repo: Path) -> None:
    scope = git_changed_files(git_repo, since_commit="totally-fake-ref")
    assert scope.usable is False
    assert "git diff failed" in (scope.error or "")


def test_diff_scope_empty_when_nothing_changed(git_repo: Path) -> None:
    """Same ref on both sides → empty file list, usable=True
    (caller knows there's nothing to scan; should NOT fall back
    to full repo)."""
    scope = git_changed_files(git_repo, since_commit="HEAD", until_commit="HEAD")
    assert scope.usable is True
    assert scope.files == []
