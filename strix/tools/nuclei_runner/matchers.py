"""Matcher evaluation against an HTTP response.

Each `Matcher` (parser.Matcher) has a `type` field that selects one
of these evaluators. The interpreter applies all matchers per
request and combines results with AND/OR per the request's
`matchers_condition`.

`evaluate_matchers(matchers, condition, response_body, status_code,
headers)` is the single entry point.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable

from strix.tools.nuclei_runner.parser import Matcher


logger = logging.getLogger(__name__)


def _select_part(
    part: str, *, body: str, headers: dict[str, str], status: int,
) -> str:
    """Select the portion of the response a matcher operates on."""
    p = (part or "body").lower()
    if p == "body":
        return body or ""
    if p == "header":
        return "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    if p == "all" or p == "response":
        hb = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        return f"HTTP/1.1 {status}\n{hb}\n\n{body or ''}"
    if p == "status":
        return str(status)
    # Some templates use part=raw — treat as `all`.
    return body or ""


def _word_match(m: Matcher, hay: str) -> bool:
    if not m.words:
        return False
    if m.case_insensitive:
        hay_l = hay.lower()
        words = [w.lower() for w in m.words]
    else:
        hay_l = hay
        words = m.words
    if m.condition == "and":
        return all(w in hay_l for w in words)
    return any(w in hay_l for w in words)


def _regex_match(m: Matcher, hay: str) -> bool:
    if not m.regex:
        return False
    flags = re.IGNORECASE if m.case_insensitive else 0
    matches = []
    for pat in m.regex:
        try:
            matches.append(bool(re.search(pat, hay, flags)))
        except re.error as e:
            logger.debug("nuclei_runner: bad regex %r: %s", pat, e)
            matches.append(False)
    if m.condition == "and":
        return all(matches)
    return any(matches)


def _status_match(m: Matcher, status_code: int) -> bool:
    if not m.status:
        return False
    return status_code in m.status


def _size_match(m: Matcher, body: str) -> bool:
    if not m.size:
        return False
    return len(body) in m.size


def _binary_match(m: Matcher, hay: str) -> bool:
    if not m.binary:
        return False
    # Each binary entry is a hex string (e.g. "504b0304" for the ZIP
    # magic). Decode and substring-search the hay's bytes.
    hay_bytes = (hay or "").encode("utf-8", errors="replace")
    for entry in m.binary:
        try:
            needle = bytes.fromhex(entry.replace(" ", "").replace("\n", ""))
        except ValueError:
            continue
        if needle in hay_bytes:
            if m.condition != "and":
                return True
        elif m.condition == "and":
            return False
    return m.condition == "and"


def evaluate_one(
    m: Matcher, *, body: str, headers: dict[str, str], status: int,
) -> bool:
    """Evaluate a single matcher. `negative=True` flips the result."""
    if m.type == "word":
        hay = _select_part(m.part, body=body, headers=headers, status=status)
        result = _word_match(m, hay)
    elif m.type == "regex":
        hay = _select_part(m.part, body=body, headers=headers, status=status)
        result = _regex_match(m, hay)
    elif m.type == "status":
        result = _status_match(m, status)
    elif m.type == "size":
        result = _size_match(m, body)
    elif m.type == "binary":
        hay = _select_part(m.part, body=body, headers=headers, status=status)
        result = _binary_match(m, hay)
    else:
        # Unknown type — defensive False.
        result = False
    if m.negative:
        result = not result
    return result


def evaluate_matchers(
    matchers: Iterable[Matcher], *,
    condition: str,
    body: str, headers: dict[str, str], status: int,
) -> tuple[bool, list[Matcher]]:
    """Evaluate all matchers; return (overall_match, matched_list).

    `condition` is "and" or "or". Default for nuclei is "or" — any
    matcher hits → template fires.
    """
    cond = (condition or "or").lower()
    matchers_list = list(matchers)
    matched: list[Matcher] = []
    for m in matchers_list:
        if evaluate_one(m, body=body, headers=headers, status=status):
            matched.append(m)
    if cond == "and":
        return len(matched) == len(matchers_list), matched
    return len(matched) > 0, matched
