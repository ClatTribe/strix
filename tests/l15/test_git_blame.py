"""Tests for iter-25.8 — git-blame enrichment."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

import pytest

from strix.l15.git_blame import (
    GitBlame,
    _find_repo_root,
    _parse_porcelain,
    clear_cache,
    enrich_finding_with_blame,
    get_blame,
)


@pytest.fixture(autouse=True)
def _clean():
    clear_cache()
    yield
    clear_cache()


# --------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------

_SAMPLE_PORCELAIN = """\
abcdef0123456789abcdef0123456789abcdef01 17 17 1
author Alice Researcher
author-mail <alice@example.com>
author-time 1700000000
author-tz +0000
committer Alice Researcher
committer-mail <alice@example.com>
committer-time 1700000000
committer-tz +0000
summary fix: harden auth endpoint
previous 1234abcd src/auth.py
filename src/auth.py
\tdef login(username, password):
"""


def test_parse_porcelain_extracts_fields():
    blame = _parse_porcelain(_SAMPLE_PORCELAIN)
    assert blame is not None
    assert blame.author == "Alice Researcher"
    assert blame.commit_date == "2023-11-14"  # 1700000000 UTC
    assert blame.commit_subject == "fix: harden auth endpoint"
    assert blame.commit_sha == "abcdef0123456789abcdef0123456789abcdef01"
    assert blame.days_since_change >= 0


def test_parse_porcelain_returns_none_on_garbage():
    assert _parse_porcelain("not porcelain output") is None
    assert _parse_porcelain("") is None


# --------------------------------------------------------------------
# get_blame — repo discovery + subprocess
# --------------------------------------------------------------------

def test_no_file_returns_none(monkeypatch):
    assert get_blame("", 1) is None
    assert get_blame("/nonexistent/file.py", 1) is None


def test_line_zero_returns_none(tmp_path, monkeypatch):
    f = tmp_path / "x.py"
    f.write_text("hi")
    assert get_blame(str(f), 0) is None


def test_no_repo_root_returns_none(tmp_path):
    """A file outside any .git dir returns None."""
    f = tmp_path / "lonely.py"
    f.write_text("x = 1\n")
    assert get_blame(str(f), 1) is None


def test_blame_invokes_git_and_parses(tmp_path, monkeypatch):
    """End-to-end: file in fake repo, mocked git output."""
    (tmp_path / ".git").mkdir()
    f = tmp_path / "src" / "auth.py"
    f.parent.mkdir(parents=True)
    f.write_text("def login(): pass\n")

    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = _SAMPLE_PORCELAIN
    fake.stderr = ""

    # Mock git binary presence
    import shutil
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/git" if b == "git" else None)
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))

    blame = get_blame(str(f), 1)
    assert blame is not None
    assert blame.author == "Alice Researcher"


def test_blame_caches_results(tmp_path, monkeypatch):
    """Same (file, line) → only one subprocess call."""
    (tmp_path / ".git").mkdir()
    f = tmp_path / "x.py"
    f.write_text("y = 1\n")

    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = _SAMPLE_PORCELAIN
    fake.stderr = ""

    import shutil
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/git" if b == "git" else None)

    call_count = {"n": 0}

    def _counting_run(*a, **kw):
        call_count["n"] += 1
        return fake

    monkeypatch.setattr(subprocess, "run", _counting_run)

    get_blame(str(f), 1)
    get_blame(str(f), 1)
    get_blame(str(f), 1)
    assert call_count["n"] == 1


def test_git_failure_caches_none(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    f = tmp_path / "x.py"
    f.write_text("y = 1\n")

    fake = MagicMock()
    fake.returncode = 128  # git error
    fake.stdout = ""
    fake.stderr = "fatal: file not tracked"

    import shutil
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/git" if b == "git" else None)
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))

    assert get_blame(str(f), 1) is None


def test_git_timeout_returns_none(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    f = tmp_path / "x.py"
    f.write_text("y = 1\n")

    import shutil
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/git" if b == "git" else None)

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="git", timeout=8)

    monkeypatch.setattr(subprocess, "run", _boom)
    assert get_blame(str(f), 1) is None


# --------------------------------------------------------------------
# enrich_finding_with_blame — mutation hook
# --------------------------------------------------------------------

def test_enrich_mutates_finding(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    f = tmp_path / "auth.py"
    f.write_text("def login(): pass\n")

    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = _SAMPLE_PORCELAIN
    fake.stderr = ""

    import shutil
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/git" if b == "git" else None)
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))

    finding = {
        "code_locations": [{"file": str(f), "line": 1}],
    }
    enrich_finding_with_blame(finding)
    assert "git_blame" in finding
    assert finding["git_blame"]["author"] == "Alice Researcher"


def test_enrich_no_op_without_code_location():
    finding = {"endpoint": "https://e.com/x"}
    enrich_finding_with_blame(finding)
    assert "git_blame" not in finding


def test_enrich_handles_string_line_number(tmp_path, monkeypatch):
    """SAST tools sometimes pass line as a string."""
    (tmp_path / ".git").mkdir()
    f = tmp_path / "x.py"
    f.write_text("y = 1\n")
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = _SAMPLE_PORCELAIN
    fake.stderr = ""
    import shutil
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/git" if b == "git" else None)
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))

    finding = {"code_locations": [{"file": str(f), "line": "1"}]}
    enrich_finding_with_blame(finding)
    assert "git_blame" in finding
