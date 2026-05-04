"""Tests for clone_repository --branch support (roadmap §3 / PR #117).

Hermetic — `subprocess.run` is monkeypatched so no real `git clone`
is invoked. We assert the constructed argv shape, not the actual
clone behaviour (that's git's responsibility).
"""

from __future__ import annotations

import subprocess
from typing import Any
from unittest.mock import MagicMock

import pytest

from strix.interface import utils as iface_utils


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    # Prevent the real git binary from running.
    monkeypatch.setattr(iface_utils.shutil, "which", lambda _: "/usr/bin/git")
    # Default subprocess.run returns success.
    completed = MagicMock()
    completed.returncode = 0
    completed.stdout = ""
    completed.stderr = ""
    monkeypatch.setattr(
        iface_utils.subprocess,
        "run",
        MagicMock(return_value=completed),
    )
    yield


def _captured_argv(monkeypatch, **run_kwargs) -> list[str]:
    """Run a clone and return the argv that subprocess.run saw."""
    captured: dict[str, Any] = {}

    def fake_run(args, *a, **kw):
        captured["args"] = list(args)
        completed = MagicMock()
        completed.returncode = 0
        return completed

    monkeypatch.setattr(iface_utils.subprocess, "run", fake_run)

    iface_utils.clone_repository(
        "https://github.com/example/repo.git",
        "test-run",
        **run_kwargs,
    )
    return captured["args"]


def test_no_branch_default_clone(monkeypatch) -> None:
    """Without --branch, the argv is the bare `git clone <url> <dest>`."""
    argv = _captured_argv(monkeypatch)

    # First three are git binary, "clone", url; we don't assert the
    # destination path (it's a tmp dir).
    assert argv[0] == "/usr/bin/git"
    assert argv[1] == "clone"
    assert "https://github.com/example/repo.git" in argv
    # No --branch / --single-branch.
    assert "--branch" not in argv
    assert "--single-branch" not in argv


def test_with_branch_adds_branch_and_single_branch_flags(monkeypatch) -> None:
    argv = _captured_argv(monkeypatch, branch="develop")

    assert "--branch" in argv
    assert "develop" in argv
    # Position: --branch immediately precedes the ref name.
    branch_idx = argv.index("--branch")
    assert argv[branch_idx + 1] == "develop"
    # `--single-branch` keeps the working tree small.
    assert "--single-branch" in argv


def test_with_tag_branch_works(monkeypatch) -> None:
    """`--branch v1.2.3` (a tag) is also valid."""
    argv = _captured_argv(monkeypatch, branch="v1.2.3")
    assert "v1.2.3" in argv


def test_branch_arg_is_keyword_only(monkeypatch) -> None:
    """`branch` MUST be passed as kwarg — not positional. This
    prevents accidental misuse where someone passes a 4th
    positional and it ends up as the branch."""
    with pytest.raises(TypeError):
        iface_utils.clone_repository(
            "https://github.com/example/repo.git",
            "run",
            "dest",
            "develop",  # should fail — branch is keyword-only
        )


def test_clone_failure_propagates(monkeypatch) -> None:
    def boom(*_a, **_kw):
        raise subprocess.CalledProcessError(
            returncode=128, cmd=["git", "clone"], stderr=b"fatal: not a git repo"
        )

    monkeypatch.setattr(iface_utils.subprocess, "run", boom)

    with pytest.raises(SystemExit):
        iface_utils.clone_repository(
            "https://github.com/example/bad.git",
            "test-run",
        )
