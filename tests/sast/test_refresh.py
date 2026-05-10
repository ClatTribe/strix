"""Tests for `strix.sast.refresh` — Phase 7 / §6a dynamic SAST
registry refresh hook."""

from __future__ import annotations

import pytest

from strix.sast.refresh import (
    _bundled_rule_count,
    main,
    refresh_semgrep_registry,
)


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _runner(rc=0, stdout="", stderr=""):
    def r(cmd, **kwargs):
        return _FakeProc(rc, stdout, stderr)
    return r


# ---------------------------------------------------------------------------
# Availability gating
# ---------------------------------------------------------------------------


def test_refresh_returns_unavailable_when_semgrep_missing() -> None:
    """No semgrep on PATH → status='unavailable' with install
    hint, NOT an error. Same contract as `scan_sast`."""
    runner = _runner(rc=127)  # version check fails
    result = refresh_semgrep_registry(runner=runner)
    assert result["status"] == "unavailable"
    assert "semgrep" in (result["error"] or "").lower()


def test_refresh_returns_ok_when_update_succeeds() -> None:
    """The version-check call AND the update call both must
    succeed. Use a runner that returns 0 for both."""
    runner = _runner(rc=0, stdout="updated registry pack")
    result = refresh_semgrep_registry(runner=runner)
    assert result["status"] == "ok"
    assert "updated" in result["stdout"]


def test_refresh_returns_error_on_update_failure() -> None:
    """version=ok, update=fail → status='error'."""
    calls = []
    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[1] == "--version":
            return _FakeProc(0, stdout="1.45.0")
        return _FakeProc(2, stderr="registry unreachable")
    result = refresh_semgrep_registry(runner=runner)
    assert result["status"] == "error"
    assert "unreachable" in (result["error"] or "")


def test_refresh_returns_error_on_timeout() -> None:
    import subprocess
    def runner(cmd, **kwargs):
        if cmd[1] == "--version":
            return _FakeProc(0, stdout="1.45.0")
        raise subprocess.TimeoutExpired(cmd, 120)
    result = refresh_semgrep_registry(runner=runner)
    assert result["status"] == "error"
    assert "timed out" in (result["error"] or "").lower() or \
           "TimeoutExpired" in (result["error"] or "")


# ---------------------------------------------------------------------------
# Status reporting
# ---------------------------------------------------------------------------


def test_bundled_rule_count_matches_corpus() -> None:
    """The count must reflect the actual files on disk — anti-rot
    test that catches the corpus accidentally getting deleted."""
    n = _bundled_rule_count()
    # Phase 7.2 corpus has 30+ rules.
    assert n >= 30, n


def test_main_status_returns_zero(capsys) -> None:
    rc = main(["--status"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Bundled vibe_coded/ rules:" in out
    assert "Semgrep available:" in out
