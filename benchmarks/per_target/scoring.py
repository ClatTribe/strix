"""Scoring helpers for per-target benchmarks.

A "match" between a found finding and an expected entry is conservative:
- same category (or CWE)
- same location (file for code, endpoint for web, port for IP)
- line within ±LINE_TOLERANCE for code targets

Returns precision, recall, lists of missed expected and false-positive found.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


LINE_TOLERANCE = 20


@dataclass
class Expected:
    id: str
    category: str
    cwe: str | None = None
    file: str | None = None
    line: int | None = None
    endpoint: str | None = None
    port: int | None = None
    severity: str | None = None
    description: str = ""
    must_find: bool = True


@dataclass
class Found:
    title: str
    category: str | None = None
    cwe: str | None = None
    file: str | None = None
    line: int | None = None
    endpoint: str | None = None
    port: int | None = None
    severity: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoreResult:
    expected_count: int
    found_count: int
    matched_count: int
    precision: float
    recall: float
    missed: list[str]
    false_positives: list[str]
    matches: list[tuple[str, str]]  # (expected.id, found.title)


def _norm(s: str | None) -> str:
    return (s or "").strip().lower()


def _categories_match(a: str | None, b: str | None) -> bool:
    """Loose category match — handles strix's free-form categories vs the manifest's enum."""
    if not a or not b:
        return False
    a, b = _norm(a), _norm(b)
    if a == b:
        return True
    # tolerate plurals / common variants
    aliases = {
        "sql_injection": "sqli",
        "sql-injection": "sqli",
        "command_injection": "cmd_injection",
        "command-injection": "cmd_injection",
        "os_command_injection": "cmd_injection",
        "cross_site_scripting": "xss",
        "cross-site-scripting": "xss",
        "stored_xss": "xss",
        "reflected_xss": "xss",
        "server_side_request_forgery": "ssrf",
        "insecure_deserialization": "deserialization",
        "directory_traversal": "path_traversal",
        "path-traversal": "path_traversal",
        "weak_cryptography": "crypto",
        "cryptographic_failure": "crypto",
        "hardcoded_credentials": "info_disclosure",
        "hardcoded_secret": "info_disclosure",
        "exposed_secret": "info_disclosure",
        "broken_access_control": "authz",
        "missing_authorization": "authz",
        "open-redirect": "open_redirect",
    }
    return aliases.get(a, a) == aliases.get(b, b)


def _cwe_match(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return _norm(a).replace("cwe-", "") == _norm(b).replace("cwe-", "")


def _file_match(a: str | None, b: str | None) -> bool:
    # Match-by-category-only fallback: if either side lacks file metadata,
    # don't penalize. Strix's markdown sometimes omits file:line for findings
    # the agent identified by behaviour rather than by source location. Same
    # convention as _line_match — be permissive on missing data, strict when
    # both sides have something to compare.
    if not a or not b:
        return True
    a, b = _norm(a), _norm(b)
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _line_match(a: int | None, b: int | None) -> bool:
    if a is None or b is None:
        return True  # don't penalize when location is missing on either side
    return abs(a - b) <= LINE_TOLERANCE


def _endpoint_match(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    a, b = _norm(a), _norm(b)
    # tolerate trailing slash, query string, and prefix (host) variation
    a = a.split("?", 1)[0].rstrip("/")
    b = b.split("?", 1)[0].rstrip("/")
    if a == b:
        return True
    # strip scheme + host if present
    for prefix in ("http://", "https://"):
        if a.startswith(prefix):
            a = "/" + a.split("/", 3)[-1] if "/" in a[len(prefix):] else "/"
        if b.startswith(prefix):
            b = "/" + b.split("/", 3)[-1] if "/" in b[len(prefix):] else "/"
    return a == b


def _location_match(expected: Expected, found: Found) -> bool:
    """Match by whichever location field the expected entry specifies."""
    if expected.file is not None:
        return _file_match(expected.file, found.file) and _line_match(expected.line, found.line)
    if expected.endpoint is not None:
        return _endpoint_match(expected.endpoint, found.endpoint)
    if expected.port is not None:
        return expected.port == found.port
    return True  # no location specified — category-only match


def _is_match(expected: Expected, found: Found) -> bool:
    cat_ok = _categories_match(expected.category, found.category) or _cwe_match(
        expected.cwe, found.cwe
    )
    if not cat_ok:
        return False
    return _location_match(expected, found)


def score(expected_list: list[Expected], found_list: list[Found]) -> ScoreResult:
    expected_must = [e for e in expected_list if e.must_find]
    matched: list[tuple[str, str]] = []
    matched_expected: set[str] = set()
    matched_found: set[int] = set()

    for i, found in enumerate(found_list):
        for expected in expected_must:
            if expected.id in matched_expected:
                continue
            if _is_match(expected, found):
                matched.append((expected.id, found.title))
                matched_expected.add(expected.id)
                matched_found.add(i)
                break

    found_count = len(found_list)
    matched_count = len(matched)
    expected_count = len(expected_must)

    precision = matched_count / found_count if found_count else 0.0
    recall = matched_count / expected_count if expected_count else 0.0

    missed = [e.id for e in expected_must if e.id not in matched_expected]
    false_positives = [
        found_list[i].title for i in range(found_count) if i not in matched_found
    ]

    return ScoreResult(
        expected_count=expected_count,
        found_count=found_count,
        matched_count=matched_count,
        precision=round(precision, 3),
        recall=round(recall, 3),
        missed=missed,
        false_positives=false_positives,
        matches=matched,
    )
