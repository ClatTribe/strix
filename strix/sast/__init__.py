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

What's shipped
--------------

  * `semgrep_runner.run()` with graceful degradation (PR #219 v1)
  * 35+ custom rules targeting vibe-coded patterns: Express,
    Python (Django/Flask), React/Next.js, LLM/AI features, crypto,
    file handling, JWT, sessions (PR #219 v1 ships 9 anchors;
    this expansion brings the corpus to 35+).
  * Diff-aware mode via `since_commit` argument
  * Severity calibration v1 (route-reachability bumps,
    test-file demotion)
  * SARIF 2.1.0 output (Phase 7.5) — pass `sarif_output_path=`
    to `scan_sast` to emit a SARIF document for GitHub Code
    Scanning ingestion. Calibration breadcrumbs attach as
    per-result `properties.calibration`.
  * `scan_sast` specialist tool

Deferred to a future phase
--------------------------

  * 7.4 v2 — function-level call-graph reachability (proper
    "is the vulnerable function transitively called from a
    route?"). Same blocker as Phase 6.4 v2 — needs a real
    AST + dataflow + call-graph engine. Multi-week project,
    not a Phase-7 sub-bullet.
"""

from strix.sast.calibrate import calibrate_finding_severity  # noqa: F401
from strix.sast.diff import (  # noqa: F401
    DiffScope,
    git_changed_files,
)
from strix.sast.sarif import (  # noqa: F401
    SARIF_SCHEMA,
    SARIF_VERSION,
    findings_to_sarif,
    write_sarif,
)
from strix.sast.semgrep_runner import (  # noqa: F401
    SastFinding,
    SemgrepResult,
    is_semgrep_available,
    run_semgrep,
)
from strix.sast.tools import scan_sast  # noqa: F401
