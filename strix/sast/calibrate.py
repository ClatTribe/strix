"""Severity calibration for SAST findings (Phase 7.4).

Raw Semgrep severity is `ERROR` / `WARNING` / `INFO` (mapped to
high / medium / low in `semgrep_runner.py`). The actual
exploitability of a finding depends on whether the vulnerable
code is reachable from a real entry point:

  * SQLi sink in a private helper called only by tests → `low`
  * SAME SQLi sink reachable from a public HTTP route → `critical`

We use two cheap deterministic signals:

  1. **Route reachability** — the finding's file is the same as,
     or transitively imports, a file containing a route handler
     (per `code_map.json`'s `routes[]` list, or imports of route
     files). When True, severity bumps one tier (capped at
     `critical`).
  2. **Test-file demotion** — the finding's file path matches a
     test pattern (`tests/`, `__tests__/`, `*_test.py`, etc.).
     When True, severity demotes one tier (down to `info`).

Both signals are conservative: route-reachability requires a
file-level proximity (no full call-graph analysis), and the
test-file heuristic only catches conventional layouts. False
negatives are biased toward the safer "keep severity" outcome.

Inputs available today:
  * `code_map.json` — emitted by `build_code_map` (Phase 1.7).
    Has `routes[]` with `{file, method, path, ...}` per handler.
  * Phase 6.4 reachability — package-level only; doesn't help
    here since a SAST finding isn't tied to a package.

The full call-graph reachability work is Phase 6.4 v2 (deferred);
when it ships, this module will pivot to "is the finding's
function transitively called from a route handler?" instead of
the current file-proximity heuristic.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from strix.sast.semgrep_runner import SastFinding


logger = logging.getLogger(__name__)


_SEV_LADDER = ["info", "low", "medium", "high", "critical"]


_TEST_DIR_RE = re.compile(
    r"(^|[/\\])(tests?|_tests?_?|spec[s]?|__tests__)([/\\]|$)",
    re.IGNORECASE,
)


@dataclass
class Calibration:
    """The signals + the resulting severity. Returned alongside
    each finding so reviewers see WHY a severity changed."""
    severity: str           # final severity after calibration
    original_severity: str
    bumped: bool = False     # route-reachable → +1 tier
    demoted: bool = False    # test file → -1 tier
    rationale: str = ""


def _is_test_file(path: str) -> bool:
    if not path:
        return False
    if _TEST_DIR_RE.search(path):
        return True
    base = Path(path).name
    return (
        base.startswith("test_")
        or base.endswith("_test.py")
        or base.endswith(".test.js")
        or base.endswith(".test.ts")
        or base.endswith(".test.tsx")
        or base.endswith(".spec.js")
        or base.endswith(".spec.ts")
    )


def _shift(sev: str, delta: int) -> str:
    try:
        idx = _SEV_LADDER.index((sev or "info").lower())
    except ValueError:
        return sev
    new_idx = max(0, min(len(_SEV_LADDER) - 1, idx + delta))
    return _SEV_LADDER[new_idx]


def _route_files_from_code_map(code_map: dict) -> set[str]:
    """Return the set of file paths that contain route handlers,
    per `code_map.json`. Path strings are returned as-is (they're
    relative to repo root in the canonical artifact)."""
    out: set[str] = set()
    routes = code_map.get("routes") if isinstance(code_map, dict) else None
    if not isinstance(routes, list):
        return out
    for r in routes:
        if isinstance(r, dict):
            f = r.get("file")
            if isinstance(f, str) and f:
                out.add(f)
    return out


def calibrate_finding_severity(
    finding: SastFinding,
    *,
    code_map: dict | None = None,
) -> Calibration:
    """Apply route-reachability bump + test-file demote to one
    finding. Returns the `Calibration` (does NOT mutate the
    input).

    Resolution order:
      1. Test-file demote (if file matches test pattern).
      2. Route-reachability bump (if `code_map` is available AND
         the finding's file is in the `routes[]` set).

    Both can apply (e.g. a test file that's also referenced as a
    route — unusual but possible). When both fire, they cancel:
    delta = -1 + 1 = 0.
    """
    delta = 0
    bumped = False
    demoted = False
    notes: list[str] = []

    if _is_test_file(finding.file):
        delta -= 1
        demoted = True
        notes.append(
            "finding is in a test file (matches test/spec naming "
            "convention) — exploitation requires running the test "
            "suite as code, which a real attacker can't do; "
            "severity demoted one tier"
        )

    if code_map is not None:
        route_files = _route_files_from_code_map(code_map)
        # Direct match: the finding's file IS a route handler file.
        if finding.file and finding.file in route_files:
            delta += 1
            bumped = True
            notes.append(
                f"finding is in a route-handler file — directly "
                f"reachable from the public HTTP surface; severity "
                f"bumped one tier"
            )
        else:
            # Suffix match — code_map paths are repo-relative; if
            # the finding's path has a longer prefix (e.g. an
            # absolute path), still match the trailing portion.
            for rf in route_files:
                if finding.file.endswith("/" + rf) or finding.file == rf:
                    delta += 1
                    bumped = True
                    notes.append(
                        f"finding is in a route-handler file (matched "
                        f"`{rf}` from code_map); reachable from the "
                        f"public HTTP surface; severity bumped one tier"
                    )
                    break

    new_sev = _shift(finding.severity, delta)
    return Calibration(
        severity=new_sev,
        original_severity=finding.severity,
        bumped=bumped,
        demoted=demoted,
        rationale=" + ".join(notes) if notes else (
            "no calibration signal (file isn't a test file and isn't "
            "a route-handler file in code_map); severity unchanged"
        ),
    )


def load_code_map(repo_path: str | Path) -> dict | None:
    """Best-effort: read `code_map.json` from the conventional
    location next to the repo, or from the strix run dir.

    Returns None when the artifact isn't present — caller passes
    `code_map=None` to `calibrate_finding_severity` and only the
    test-file demote applies.
    """
    repo = Path(repo_path).resolve()
    candidates = [
        repo / "code_map.json",
        repo.parent / "code_map.json",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            try:
                return json.loads(c.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                logger.debug("calibrate: couldn't load %s: %s", c, e)
    return None
