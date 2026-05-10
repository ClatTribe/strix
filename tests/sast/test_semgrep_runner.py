"""Unit tests for `strix.sast.semgrep_runner` — Phase 7.1.

Tests inject a fake `subprocess.run`-compatible runner so they
don't need Semgrep installed. The test corpus pins:

  * `is_semgrep_available` returns True/False from runner exit code.
  * `_normalise_finding` translates Semgrep JSON → SastFinding.
  * `run_semgrep` returns `unavailable` status when Semgrep isn't
    installed (graceful degradation).
  * `run_semgrep` parses canned JSON output cleanly.
  * Exit-code → status mapping (0/1 = ok, 2 = partial, else error).
  * Path → language inference + CWE → category mapping.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from strix.sast.semgrep_runner import (
    SastFinding,
    SemgrepResult,
    VIBE_CODED_RULES_DIR,
    _CWE_TO_CATEGORY,
    _infer_language_from_path,
    _normalise_finding,
    is_semgrep_available,
    run_semgrep,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_runner(returncode: int, stdout: str = "", stderr: str = ""):
    """Build a runner callable returning a fixed FakeProc."""
    def runner(cmd, **kwargs):
        return _FakeProc(returncode=returncode, stdout=stdout, stderr=stderr)
    return runner


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------


def test_is_available_true_when_version_returns_zero() -> None:
    assert is_semgrep_available(run=_fake_runner(0, stdout="1.45.0\n")) is True


def test_is_available_false_when_version_nonzero() -> None:
    assert is_semgrep_available(run=_fake_runner(127)) is False


def test_is_available_false_on_filenotfound() -> None:
    def runner(cmd, **kwargs):
        raise FileNotFoundError("no semgrep")
    assert is_semgrep_available(run=runner) is False


# ---------------------------------------------------------------------------
# Path → language inference
# ---------------------------------------------------------------------------


def test_infer_language_from_path() -> None:
    assert _infer_language_from_path("app.js") == "javascript"
    assert _infer_language_from_path("src/index.tsx") == "typescript"
    assert _infer_language_from_path("model.py") == "python"
    assert _infer_language_from_path("main.go") == "go"
    assert _infer_language_from_path("Service.java") == "java"
    assert _infer_language_from_path("noext") is None
    assert _infer_language_from_path("") is None


# ---------------------------------------------------------------------------
# CWE → category map (must include the rules we ship)
# ---------------------------------------------------------------------------


def test_cwe_to_category_covers_shipped_rule_cwes() -> None:
    """Every CWE used by a rule we ship must have a category
    mapping — otherwise the finding category falls to None and
    the lead's cross-asset routing can't pivot to a DAST
    specialist."""
    shipped_cwes = {
        "CWE-22",   # path traversal
        "CWE-79",   # XSS (dangerouslySetInnerHTML)
        "CWE-89",   # SQLi (string concat)
        "CWE-94",   # cmd injection (eval)
        "CWE-338",  # crypto (Math.random for tokens)
        "CWE-798",  # info disclosure (hardcoded JWT secret)
        "CWE-862",  # authz (Next.js server action)
        "CWE-915",  # mass assignment
        "CWE-918",  # SSRF (fetch user URL)
        "CWE-1004", # misconfig (permissive CORS)
    }
    for cwe in shipped_cwes:
        assert cwe in _CWE_TO_CATEGORY, (
            f"CWE {cwe} from a shipped rule has no category mapping; "
            f"add to _CWE_TO_CATEGORY in semgrep_runner.py"
        )


# ---------------------------------------------------------------------------
# _normalise_finding — JSON → SastFinding
# ---------------------------------------------------------------------------


def test_normalise_basic_finding() -> None:
    raw = {
        "check_id": "strix-sql-string-concat-user-input",
        "path": "src/handlers/user.js",
        "start": {"line": 42, "col": 1},
        "end": {"line": 42, "col": 80},
        "extra": {
            "message": "SQL via template literal",
            "severity": "ERROR",
            "metadata": {"cwe": ["CWE-89"], "owasp": ["A03:2021"]},
        },
    }
    f = _normalise_finding(raw)
    assert f.rule_id == "strix-sql-string-concat-user-input"
    assert f.file == "src/handlers/user.js"
    assert f.line_start == 42
    assert f.line_end == 42
    assert f.severity == "high"
    assert f.cwe == "CWE-89"
    assert f.category == "sqli"
    assert f.language == "javascript"


def test_normalise_severity_mapping() -> None:
    """ERROR → high, WARNING → medium, INFO → low."""
    for sg_sev, expected in (("ERROR", "high"), ("WARNING", "medium"),
                              ("INFO", "low"), ("UNKNOWN", "medium")):
        raw = {
            "check_id": "x", "path": "a.js",
            "start": {"line": 1}, "end": {"line": 1},
            "extra": {"severity": sg_sev, "message": ""},
        }
        assert _normalise_finding(raw).severity == expected, sg_sev


def test_normalise_cwe_string_form() -> None:
    """Semgrep sometimes emits CWE as a plain string instead of list."""
    raw = {
        "check_id": "x", "path": "a.py",
        "start": {"line": 1}, "end": {"line": 1},
        "extra": {
            "severity": "WARNING",
            "metadata": {"cwe": "CWE-89: SQL Injection"},
        },
    }
    assert _normalise_finding(raw).cwe == "CWE-89"


def test_normalise_cwe_missing_returns_none_category() -> None:
    raw = {
        "check_id": "x", "path": "a.py",
        "start": {"line": 1}, "end": {"line": 1},
        "extra": {"severity": "WARNING", "metadata": {}},
    }
    f = _normalise_finding(raw)
    assert f.cwe is None
    assert f.category is None


def test_normalise_unknown_cwe_returns_none_category() -> None:
    """A CWE we don't have a category for → category=None
    (caller falls back to 'sast' default)."""
    raw = {
        "check_id": "x", "path": "a.py",
        "start": {"line": 1}, "end": {"line": 1},
        "extra": {"severity": "WARNING", "metadata": {"cwe": ["CWE-9999"]}},
    }
    assert _normalise_finding(raw).category is None


# ---------------------------------------------------------------------------
# run_semgrep — graceful degradation + parsing
# ---------------------------------------------------------------------------


def test_run_semgrep_unavailable_when_binary_missing(tmp_path: Path) -> None:
    """Binary not on PATH → returns `unavailable`, not an error."""
    runner = _fake_runner(127)  # version check fails
    result = run_semgrep(tmp_path, runner=runner)
    assert result.status == "unavailable"
    assert "semgrep" in (result.error or "").lower()


def test_run_semgrep_parses_findings(tmp_path: Path) -> None:
    """Canned JSON output → list of normalised SastFindings."""
    semgrep_output = {
        "results": [
            {
                "check_id": "strix-eval-with-user-input",
                "path": "app.js",
                "start": {"line": 10}, "end": {"line": 10},
                "extra": {
                    "message": "eval on user input",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-94"]},
                },
            },
            {
                "check_id": "strix-react-dangerously-set-innerhtml-user-input",
                "path": "components/Comment.jsx",
                "start": {"line": 25}, "end": {"line": 27},
                "extra": {
                    "message": "dangerouslySetInnerHTML from user input",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-79"]},
                },
            },
        ],
        "errors": [],
        "paths": {"scanned": ["app.js", "components/Comment.jsx"]},
    }

    call_log: list[list[str]] = []

    def runner(cmd, **kwargs):
        call_log.append(list(cmd))
        if cmd[:2] == ["semgrep", "--version"]:
            return _FakeProc(0, stdout="1.45.0\n")
        if cmd[:2] == ["semgrep", "scan"]:
            return _FakeProc(1, stdout=json.dumps(semgrep_output))
        return _FakeProc(127)

    result = run_semgrep(tmp_path, runner=runner)
    assert result.status == "ok"
    assert len(result.findings) == 2
    assert result.findings[0].rule_id == "strix-eval-with-user-input"
    assert result.findings[0].cwe == "CWE-94"
    assert result.findings[1].cwe == "CWE-79"
    # Default config includes the bundled rules dir + OWASP pack.
    scan_call = next(c for c in call_log if c[:2] == ["semgrep", "scan"])
    assert "--config" in scan_call
    assert any(str(VIBE_CODED_RULES_DIR) in c for c in scan_call)
    assert "p/owasp-top-ten" in scan_call


def test_run_semgrep_partial_when_errors_present(tmp_path: Path) -> None:
    """Exit code 2 with `errors` array populated → status=partial,
    findings still extracted. Critical: don't drop findings just
    because a rule failed to compile."""
    semgrep_output = {
        "results": [
            {
                "check_id": "rule-1", "path": "a.py",
                "start": {"line": 1}, "end": {"line": 1},
                "extra": {"severity": "WARNING", "message": ""},
            },
        ],
        "errors": [{"type": "rule-parse-error", "message": "bad rule"}],
    }

    def runner(cmd, **kwargs):
        if cmd[:2] == ["semgrep", "--version"]:
            return _FakeProc(0, stdout="1.45.0\n")
        return _FakeProc(2, stdout=json.dumps(semgrep_output))

    result = run_semgrep(tmp_path, runner=runner)
    assert result.status == "partial"
    assert len(result.findings) == 1


def test_run_semgrep_error_on_unexpected_exit(tmp_path: Path) -> None:
    """Exit code outside {0,1,2} = hard failure."""
    def runner(cmd, **kwargs):
        if cmd[:2] == ["semgrep", "--version"]:
            return _FakeProc(0, stdout="1.45.0\n")
        return _FakeProc(7, stderr="boom")
    result = run_semgrep(tmp_path, runner=runner)
    assert result.status == "error"
    assert "code 7" in (result.error or "")


def test_run_semgrep_error_on_invalid_json(tmp_path: Path) -> None:
    def runner(cmd, **kwargs):
        if cmd[:2] == ["semgrep", "--version"]:
            return _FakeProc(0, stdout="1.45.0\n")
        return _FakeProc(0, stdout="not json")
    result = run_semgrep(tmp_path, runner=runner)
    assert result.status == "error"
    assert "JSON" in (result.error or "")


def test_run_semgrep_no_targets_returns_error(tmp_path: Path) -> None:
    runner = _fake_runner(0, stdout="1.45.0\n")
    result = run_semgrep([], runner=runner)
    assert result.status == "error"


def test_run_semgrep_extra_args_passed_through(tmp_path: Path) -> None:
    captured: dict[str, list] = {}

    def runner(cmd, **kwargs):
        if cmd[:2] == ["semgrep", "--version"]:
            return _FakeProc(0, stdout="1.45.0\n")
        captured["scan_cmd"] = list(cmd)
        return _FakeProc(0, stdout=json.dumps({"results": []}))

    run_semgrep(
        tmp_path,
        extra_args=["--exclude-rule", "rule-foo"],
        runner=runner,
    )
    assert "--exclude-rule" in captured["scan_cmd"]
    assert "rule-foo" in captured["scan_cmd"]


# ---------------------------------------------------------------------------
# Bundled rule corpus exists
# ---------------------------------------------------------------------------


def test_vibe_coded_rules_dir_exists() -> None:
    """The packaged rule corpus must be on disk where the runner
    expects it."""
    assert VIBE_CODED_RULES_DIR.exists()
    assert VIBE_CODED_RULES_DIR.is_dir()
    yaml_files = list(VIBE_CODED_RULES_DIR.glob("*.yml"))
    # 9 rules per the README; allow drift in either direction.
    assert len(yaml_files) >= 8, [p.name for p in yaml_files]
