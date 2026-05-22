"""iter-25.1 — pre-emission FP filters (Gap 7 in docs/L2-optimization.md).

A real security engineer dismisses an obvious FP in 2 seconds; the LLM
burns ~2000 tokens doing the same `dismiss_finding` call. This module
runs a small deterministic rule pack at finding-emission time and
returns one of:

  * ``ALLOW``  — pass through unchanged (most findings)
  * ``DEMOTE`` — pass through but downgrade severity one tier
    (e.g. SAST hit in `tests/` dir)
  * ``DROP``   — drop entirely (e.g. AWS key in `examples/README.md`)

Heuristics intentionally kept conservative: when in doubt, ``ALLOW``.
Critical-severity findings are never DROPped to avoid masking a real
security incident in a test-data fixture (e.g. live prod key
accidentally committed under tests/).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Literal


logger = logging.getLogger(__name__)


# Module-level constants — easy to override from tests via monkeypatch
# if a future fixture needs different conventions.

# File-path patterns that signal "this is test/example code, not prod"
_TEST_PATH_FRAGMENTS = (
    "/tests/", "/test/", "/__tests__/",
    "/spec/", "/specs/",
    "/fixtures/", "/_fixtures/", "/testdata/",
)
_TEST_FILENAME_SUFFIXES = (
    "_test.py", "_test.go", "_test.rs",
    ".test.ts", ".test.tsx", ".test.js", ".test.jsx",
    ".spec.ts", ".spec.js", ".spec.tsx", ".spec.jsx",
    "Test.java", "Tests.java",
)

# Strongly demote (not drop) if these match — there have been real prod
# incidents involving leaked secrets in test fixtures, so we keep them
# visible at info level for human review.
_DEMOTE_PATH_FRAGMENTS = _TEST_PATH_FRAGMENTS + (
    "/mocks/", "/__mocks__/", "/stubs/",
)

# Hard-drop paths — documentation and example code should never gate a
# scan's severity.
_DROP_PATH_FRAGMENTS = (
    "/examples/", "/example/",
    "/docs/", "/doc/", "/documentation/",
    "/samples/", "/sample/",
    "/demo/", "/demos/",
    "/tutorial/", "/tutorials/",
)
_DOC_FILE_SUFFIXES = (".md", ".rst", ".txt", ".adoc")

# Common placeholder secret values — these are the regexes SAST/secret
# scanners pick up by mistake.
_PLACEHOLDER_PATTERNS = (
    re.compile(r"^\s*['\"]?(test|placeholder|example|dummy|sample|"
               r"changeme|change-me|todo|xxx+|fixme|"
               r"your[-_]?(?:api[-_]?)?key[-_]?here|"
               r"replace[-_]?me|<.+?>)['\"]?\s*$",
               re.IGNORECASE),
)

# `os.getenv("KEY", "default")` shaped matches where the default is
# clearly a placeholder. If we see `os.getenv(...)` referenced and the
# match is the *default*, it's almost never a real secret.
_GETENV_DEFAULT_RE = re.compile(
    r"""(?ix)
    \bos\.getenv\(
        \s*['"][A-Z_][A-Z0-9_]*['"]\s*,\s*       # env var name
        ['"]([^'"]+)['"]\s*                        # default value (group 1)
    \)
    """,
)


Decision = Literal["allow", "demote", "drop"]


@dataclass(frozen=True)
class FpFilterDecision:
    """Outcome of the FP filter pass."""
    decision: Decision
    reason: str = ""

    @property
    def is_allow(self) -> bool:
        return self.decision == "allow"

    @property
    def is_demote(self) -> bool:
        return self.decision == "demote"

    @property
    def is_drop(self) -> bool:
        return self.decision == "drop"


def _file_path(finding: dict[str, Any]) -> str | None:
    """Pull the most-specific file path off a vulnerability report dict.

    `add_vulnerability_report` puts the per-line location info into
    `code_locations: [{file, line, ...}, ...]`. Older paths put it on
    `target` or directly on the finding under `file`.
    """
    code_locs = finding.get("code_locations") or []
    if isinstance(code_locs, list) and code_locs:
        first = code_locs[0]
        if isinstance(first, dict):
            p = first.get("file") or first.get("path")
            if isinstance(p, str) and p.strip():
                return p.strip()
    for key in ("file", "path", "target"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _evidence_snippet(finding: dict[str, Any]) -> str:
    """Concatenate any field that might carry the matched code line."""
    parts: list[str] = []
    for key in (
        "description", "technical_analysis", "poc_description",
        "matched_text", "evidence",
    ):
        v = finding.get(key)
        if isinstance(v, str):
            parts.append(v)
    code_locs = finding.get("code_locations") or []
    if isinstance(code_locs, list):
        for loc in code_locs:
            if isinstance(loc, dict):
                v = loc.get("snippet") or loc.get("code")
                if isinstance(v, str):
                    parts.append(v)
    return "\n".join(parts)


def _norm_path(path: str) -> str:
    """Lowercase + forward-slashes + leading `/` so prefix checks match
    whether the input was `examples/x.py` or `/repo/examples/x.py`."""
    p = path.replace("\\", "/").lower()
    if not p.startswith("/"):
        p = "/" + p
    return p


def _is_test_path(path: str) -> bool:
    """File lives under a tests/ tree OR matches a *_test.* suffix."""
    p = _norm_path(path)
    if any(frag in p for frag in _TEST_PATH_FRAGMENTS):
        return True
    name = PurePosixPath(p).name
    return any(name.endswith(s.lower()) for s in _TEST_FILENAME_SUFFIXES)


def _is_doc_or_example_path(path: str) -> bool:
    p = _norm_path(path)
    if any(frag in p for frag in _DROP_PATH_FRAGMENTS):
        return True
    name = PurePosixPath(p).name
    return any(name.endswith(s) for s in _DOC_FILE_SUFFIXES)


def _looks_like_placeholder(value: str) -> bool:
    if not value:
        return False
    return any(rx.search(value) for rx in _PLACEHOLDER_PATTERNS)


def _is_getenv_default_match(snippet: str) -> bool:
    """The matched line is the default-value branch of os.getenv()."""
    m = _GETENV_DEFAULT_RE.search(snippet)
    if not m:
        return False
    default_val = m.group(1)
    return _looks_like_placeholder(default_val)


def pre_emission_fp_filter(finding: dict[str, Any]) -> FpFilterDecision:
    """Run the FP heuristic pack against a vuln-report dict.

    Returns ``FpFilterDecision(decision, reason)``. The caller is
    responsible for actually applying the decision (downgrade severity
    / skip emission). Pure function: does not mutate ``finding``.

    Safety contract:
      * Never DROP a `critical` finding — a real prod incident in a
        test-data dir must still surface for human review.
      * Always ALLOW if any internal lookup raises — recall-safe.
    """
    try:
        severity = str(finding.get("severity") or "").lower().strip()
        path = _file_path(finding)
        evidence = _evidence_snippet(finding)

        # Rule 5: low-severity match inside a .md/.rst/.txt → drop
        if path:
            name = PurePosixPath(path.replace("\\", "/")).name.lower()
            if (
                severity in ("low", "info", "informational")
                and any(name.endswith(s) for s in _DOC_FILE_SUFFIXES)
            ):
                return FpFilterDecision(
                    decision="drop",
                    reason=(
                        f"low-severity match inside documentation file "
                        f"({name})"
                    ),
                )

        # Rule 2: docs/examples/samples/tutorials path → drop unless critical
        if path and _is_doc_or_example_path(path):
            if severity == "critical":
                return FpFilterDecision(
                    decision="allow",
                    reason=(
                        "critical severity preserved despite docs/example "
                        "path — possible real leak in docs"
                    ),
                )
            return FpFilterDecision(
                decision="drop",
                reason=f"file in docs/example tree ({path})",
            )

        # Rule 1: test-file path → demote unless critical
        if path and _is_test_path(path):
            if severity == "critical":
                return FpFilterDecision(
                    decision="allow",
                    reason=(
                        "critical severity preserved despite test path "
                        "— possible real leak in fixture"
                    ),
                )
            return FpFilterDecision(
                decision="demote",
                reason=f"finding in test path ({path})",
            )

        # Rule 3: os.getenv(KEY, "placeholder") default branch → drop
        if evidence and _is_getenv_default_match(evidence):
            if severity == "critical":
                return FpFilterDecision(
                    decision="allow",
                    reason="critical severity preserved despite getenv-default match",
                )
            return FpFilterDecision(
                decision="drop",
                reason="match is os.getenv() default placeholder value",
            )

        # Rule 4: secret-like value is a known placeholder
        # (we look at the description/poc fields which often carry the
        # masked secret value)
        for key in ("masked", "matched_value", "raw_value"):
            v = finding.get(key)
            if isinstance(v, str) and _looks_like_placeholder(v):
                if severity == "critical":
                    return FpFilterDecision(
                        decision="allow",
                        reason="critical severity preserved despite placeholder",
                    )
                return FpFilterDecision(
                    decision="drop",
                    reason=f"value matches placeholder regex ({v!r})",
                )

        return FpFilterDecision(decision="allow", reason="")
    except Exception as e:  # noqa: BLE001
        logger.debug("pre_emission_fp_filter failed: %s — passthrough", e)
        return FpFilterDecision(decision="allow", reason="filter-error-passthrough")


# Severity demotion table — used by tracer when decision == "demote".
_DEMOTE_TIER = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "info",
    "info": "info",
    "informational": "info",
}


def demoted_severity(current: str | None) -> str:
    """Return the one-tier-lower severity label."""
    if not current:
        return "info"
    return _DEMOTE_TIER.get(current.lower().strip(), "info")
