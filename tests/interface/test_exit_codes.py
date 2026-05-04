"""Tests for the documented exit-code contract (roadmap §4)."""

from __future__ import annotations

import pytest

from strix.interface import exit_codes


def test_clean_codes() -> None:
    assert exit_codes.EXIT_CLEAN_NO_FINDINGS == 0
    assert exit_codes.EXIT_CLEAN_WITH_FINDINGS == 2


def test_error_code() -> None:
    assert exit_codes.EXIT_CONFIG_ERROR == 1


def test_budget_code() -> None:
    assert exit_codes.EXIT_BUDGET_EXCEEDED == 3


def test_signal_codes() -> None:
    assert exit_codes.EXIT_SIGINT == 130   # 128 + 2
    assert exit_codes.EXIT_SIGTERM == 143  # 128 + 15


def test_describe_known_codes() -> None:
    assert "no findings" in exit_codes.describe(0).lower()
    assert "config" in exit_codes.describe(1).lower()
    assert "with findings" in exit_codes.describe(2).lower()
    assert "budget" in exit_codes.describe(3).lower()
    assert "sigint" in exit_codes.describe(130).lower()
    assert "sigterm" in exit_codes.describe(143).lower()


def test_describe_unknown_code() -> None:
    assert exit_codes.describe(42) == "unknown"
    assert exit_codes.describe(99) == "unknown"


def test_is_success_true_for_clean_codes() -> None:
    assert exit_codes.is_success(0) is True
    assert exit_codes.is_success(2) is True


def test_is_success_false_for_other_codes() -> None:
    assert exit_codes.is_success(1) is False
    assert exit_codes.is_success(3) is False
    assert exit_codes.is_success(130) is False
    assert exit_codes.is_success(143) is False


def test_is_cancelled() -> None:
    assert exit_codes.is_cancelled(130) is True
    assert exit_codes.is_cancelled(143) is True
    assert exit_codes.is_cancelled(0) is False
    assert exit_codes.is_cancelled(1) is False


def test_all_codes_documented() -> None:
    """Every constant exported should be in ALL_CODES."""
    code_constants = [
        exit_codes.EXIT_CLEAN_NO_FINDINGS,
        exit_codes.EXIT_CONFIG_ERROR,
        exit_codes.EXIT_CLEAN_WITH_FINDINGS,
        exit_codes.EXIT_BUDGET_EXCEEDED,
        exit_codes.EXIT_SIGINT,
        exit_codes.EXIT_SIGTERM,
    ]
    for code in code_constants:
        assert code in exit_codes.ALL_CODES


def test_no_overlapping_codes() -> None:
    """Each documented code is unique."""
    codes = [
        exit_codes.EXIT_CLEAN_NO_FINDINGS,
        exit_codes.EXIT_CONFIG_ERROR,
        exit_codes.EXIT_CLEAN_WITH_FINDINGS,
        exit_codes.EXIT_BUDGET_EXCEEDED,
        exit_codes.EXIT_SIGINT,
        exit_codes.EXIT_SIGTERM,
    ]
    assert len(codes) == len(set(codes))


def test_is_success_string_input_handled() -> None:
    """The functions coerce str → int gracefully."""
    assert exit_codes.is_success("0") is True
    assert exit_codes.is_success("2") is True
    assert exit_codes.is_success("1") is False
