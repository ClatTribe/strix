"""Tests for --quiet mode (roadmap §4 / PR #121).

The --quiet flag suppresses Rich panels for server-side / CI usage
where the terminal is non-TTY and ANSI-escape pollution is
unhelpful in logs. events.jsonl / vulnerabilities.json /
run_meta.json are unaffected — they're tracer-driven file writes
that never go to console.
"""

from __future__ import annotations

import argparse
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from strix.interface.main import display_completion_message


@pytest.fixture
def _fake_args(tmp_path):
    """Build a minimal argparse-like namespace with the relevant flags."""
    return argparse.Namespace(
        quiet=False,
        targets_info=[
            {"original": "https://example.com", "type": "web_application", "details": {}},
        ],
    )


def test_quiet_mode_suppresses_completion_panel(_fake_args, tmp_path) -> None:
    """When --quiet is set, display_completion_message returns
    immediately without touching console."""
    _fake_args.quiet = True

    captured = StringIO()
    with patch("strix.interface.main.Console") as MockConsole:
        instance = MockConsole.return_value
        # Calling print on the instance should never happen.
        display_completion_message(_fake_args, tmp_path / "results")

    # The Console class itself shouldn't even be instantiated in quiet mode.
    MockConsole.assert_not_called()


def test_non_quiet_mode_renders_panel(_fake_args, tmp_path) -> None:
    """Without --quiet, display_completion_message constructs a Console
    and prints to it."""
    _fake_args.quiet = False

    with patch("strix.interface.main.Console") as MockConsole:
        instance = MockConsole.return_value
        display_completion_message(_fake_args, tmp_path / "results")

    # Console was used.
    assert MockConsole.called


def test_quiet_mode_default_false(_fake_args, tmp_path) -> None:
    """Default value: quiet is False — full output."""
    # Don't set _fake_args.quiet at all (or set to default False).
    _fake_args.quiet = False

    with patch("strix.interface.main.Console") as MockConsole:
        display_completion_message(_fake_args, tmp_path / "results")

    assert MockConsole.called


def test_quiet_attribute_missing_renders_panel(tmp_path) -> None:
    """Backward compat: when an args namespace doesn't have the
    `quiet` attribute at all (older callers), behaviour is unchanged
    — full output."""
    minimal_args = argparse.Namespace(
        targets_info=[{"original": "x", "type": "web_application", "details": {}}],
    )

    with patch("strix.interface.main.Console") as MockConsole:
        # getattr fallback to False when 'quiet' doesn't exist.
        display_completion_message(minimal_args, tmp_path / "results")

    assert MockConsole.called
