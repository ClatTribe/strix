"""Tests for the matcher engine (word / regex / status / size / binary)."""

from __future__ import annotations

import pytest

from strix.tools.nuclei_runner.matchers import (
    evaluate_matchers,
    evaluate_one,
)
from strix.tools.nuclei_runner.parser import Matcher


def _m(**kw) -> Matcher:
    return Matcher(type=kw.pop("type"), **kw)


# ---------------------------------------------------------------------------
# Word matcher
# ---------------------------------------------------------------------------


def test_word_match_or_default() -> None:
    m = _m(type="word", words=["alpha", "beta"])
    assert evaluate_one(m, body="this contains alpha", headers={}, status=200)
    assert not evaluate_one(m, body="nothing useful", headers={}, status=200)


def test_word_match_and_condition() -> None:
    m = _m(type="word", words=["alpha", "beta"], condition="and")
    assert evaluate_one(m, body="alpha then beta", headers={}, status=200)
    assert not evaluate_one(m, body="just alpha", headers={}, status=200)


def test_word_match_case_insensitive() -> None:
    m = _m(type="word", words=["FOO"], case_insensitive=True)
    assert evaluate_one(m, body="foo bar", headers={}, status=200)


def test_word_match_negative() -> None:
    m = _m(type="word", words=["set-cookie:"], negative=True,
           case_insensitive=True)
    # Body has no "set-cookie:" → negative match → True.
    assert evaluate_one(m, body="ok", headers={}, status=200)
    # Body has "Set-Cookie:" → negative match → False.
    assert not evaluate_one(m, body="Set-Cookie: x=1", headers={}, status=200)


def test_word_match_part_header() -> None:
    m = _m(type="word", words=["X-Powered-By"], part="header")
    headers = {"X-Powered-By": "Express", "Content-Type": "text/html"}
    assert evaluate_one(m, body="", headers=headers, status=200)


# ---------------------------------------------------------------------------
# Regex matcher
# ---------------------------------------------------------------------------


def test_regex_match() -> None:
    m = _m(type="regex", regex=[r"version\s+\d+\.\d+"])
    assert evaluate_one(m, body="version 1.2", headers={}, status=200)
    assert not evaluate_one(m, body="no version", headers={}, status=200)


def test_regex_match_invalid_pattern_returns_false() -> None:
    m = _m(type="regex", regex=["[invalid"])
    assert not evaluate_one(m, body="anything", headers={}, status=200)


def test_regex_match_case_insensitive() -> None:
    m = _m(type="regex", regex=[r"^apache"], case_insensitive=True)
    assert evaluate_one(m, body="Apache HTTP Server", headers={}, status=200)


# ---------------------------------------------------------------------------
# Status matcher
# ---------------------------------------------------------------------------


def test_status_match_single() -> None:
    m = _m(type="status", status=[200])
    assert evaluate_one(m, body="", headers={}, status=200)
    assert not evaluate_one(m, body="", headers={}, status=404)


def test_status_match_list() -> None:
    m = _m(type="status", status=[200, 301, 302])
    assert evaluate_one(m, body="", headers={}, status=302)
    assert not evaluate_one(m, body="", headers={}, status=500)


# ---------------------------------------------------------------------------
# Size matcher
# ---------------------------------------------------------------------------


def test_size_match_exact() -> None:
    m = _m(type="size", size=[5])
    assert evaluate_one(m, body="hello", headers={}, status=200)
    assert not evaluate_one(m, body="hello world", headers={}, status=200)


# ---------------------------------------------------------------------------
# Binary matcher
# ---------------------------------------------------------------------------


def test_binary_match_zip_magic() -> None:
    m = _m(type="binary", binary=["504b0304"])  # ZIP magic
    body = "PK\x03\x04 some payload"
    assert evaluate_one(m, body=body, headers={}, status=200)


def test_binary_match_no_match() -> None:
    m = _m(type="binary", binary=["DEADBEEF"])
    assert not evaluate_one(m, body="hello", headers={}, status=200)


# ---------------------------------------------------------------------------
# evaluate_matchers — composition
# ---------------------------------------------------------------------------


def test_evaluate_matchers_and_all_must_match() -> None:
    matchers = [
        _m(type="word", words=["Apache"]),
        _m(type="status", status=[200]),
    ]
    ok, _ = evaluate_matchers(matchers, condition="and",
                              body="Apache 2.4", headers={}, status=200)
    assert ok
    ok, _ = evaluate_matchers(matchers, condition="and",
                              body="Apache 2.4", headers={}, status=500)
    assert not ok


def test_evaluate_matchers_or_any_match() -> None:
    matchers = [
        _m(type="word", words=["nope"]),
        _m(type="status", status=[200]),
    ]
    ok, matched = evaluate_matchers(matchers, condition="or",
                                    body="hello", headers={}, status=200)
    assert ok
    assert len(matched) == 1
    assert matched[0].type == "status"


def test_evaluate_matchers_default_condition_is_or() -> None:
    matchers = [_m(type="status", status=[404])]
    ok, _ = evaluate_matchers(matchers, condition="",
                              body="", headers={}, status=404)
    assert ok


def test_evaluate_matchers_unknown_type_returns_false() -> None:
    matchers = [_m(type="dsl")]
    ok, _ = evaluate_matchers(matchers, condition="or",
                              body="", headers={}, status=200)
    assert not ok
