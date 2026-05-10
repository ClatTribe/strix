"""SAST — Static Application Security Testing (roadmap §7).

Pre-PR code-review-grade analysis of source files. Anchors on the
Semgrep CLI as the analysis engine, runs Semgrep's official rule
registry plus a curated set of custom rules targeting AI-generated
patterns specific to vibe-coded apps.

Architecture
------------

  strix/sast/
    semgrep_runner.py — invoke the `semgrep` CLI, parse JSON output,
                        graceful-degrade when not installed.
    rules/vibe_coded/ — YAML rules targeting AI-generated patterns
                        (Express mass-assignment, Next.js missing
                        authz, dangerously-set-innerhtml, etc.).
    diff.py           — git-diff-aware file scoping (Phase 7.3).
    calibrate.py      — severity calibration via Phase 6.4
                        reachability + Phase 1.7 code_map routes.
                        Demotes findings in dead code, escalates
                        findings reachable from public routes.
    tools.py          — `scan_sast` LLM-facing specialist.

What's shipped in v1 (this PR)
------------------------------

  * `semgrep_runner.run()` with graceful degradation
  * 9 starter custom rules targeting top vibe-coded patterns
  * Diff-aware mode via `since_commit` argument
  * Severity calibration v1 (route-reachability bumps,
    test-file demotion)
  * `scan_sast` specialist tool

Deferred to follow-up PRs (per the AISecurityEngineer.md scope)
-------------------------------------------------------------------

  * 7.2 — full 50+ rule corpus (we ship 9 anchors here)
  * 7.5 — SARIF output (industry-standard format for GitHub Code
    Scanning integration). Adds ~300 LOC of pure mapping; orthogonal
    to the analysis engine.
"""

from strix.sast.calibrate import calibrate_finding_severity  # noqa: F401
from strix.sast.diff import (  # noqa: F401
    DiffScope,
    git_changed_files,
)
from strix.sast.semgrep_runner import (  # noqa: F401
    SastFinding,
    SemgrepResult,
    is_semgrep_available,
    run_semgrep,
)
from strix.sast.tools import scan_sast  # noqa: F401
