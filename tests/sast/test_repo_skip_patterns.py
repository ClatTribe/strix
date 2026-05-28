"""iter-Q5.41 — tests for the L1-SAST file-tree skip patterns.

Hermetic — covers the pattern resolver + the semgrep CLI integration.
The end-to-end semgrep run is exercised by existing `test_semgrep_runner`
tests; this module focuses on the new exclude_paths plumbing."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.agents.lead_agent.anchor_prepass import (
    _REPO_SKIP_PATTERNS_DEFAULT,
    _get_repo_skip_patterns,
)
from strix.sast.semgrep_runner import run_semgrep


@pytest.fixture(autouse=True)
def _clean(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_REPO_SKIP_PATTERNS_DISABLE", raising=False)
    monkeypatch.delenv("STRIX_REPO_SKIP_PATTERNS_EXTRA", raising=False)


# ---------------------------------------------------------------------------
# Pattern resolver
# ---------------------------------------------------------------------------


def test_default_patterns_cover_vendored_dirs() -> None:
    pats = _get_repo_skip_patterns()
    for required in ("node_modules", "vendor", ".git", "__pycache__",
                     "dist", "build"):
        assert required in pats, (
            f"canonical L1-SAST skip list must include {required!r}"
        )


def test_default_patterns_include_minified_and_maps() -> None:
    pats = _get_repo_skip_patterns()
    assert "*.min.js" in pats
    assert "*.min.css" in pats
    assert "*.map" in pats


def test_default_patterns_include_binary_extensions() -> None:
    """semgrep wastes wall time parsing binaries it can't analyze.
    Skip them by extension."""
    pats = _get_repo_skip_patterns()
    for ext in ("*.jar", "*.war", "*.zip", "*.exe", "*.dll", "*.so",
                "*.pyc", "*.class"):
        assert ext in pats, f"binary extension {ext!r} must be skipped"


def test_default_patterns_include_python_venv_dirs() -> None:
    pats = _get_repo_skip_patterns()
    for d in ("venv", ".venv", "env"):
        assert d in pats


def test_default_patterns_include_ide_dirs() -> None:
    pats = _get_repo_skip_patterns()
    for d in (".idea", ".vscode"):
        assert d in pats


def test_default_patterns_include_ios_vendor_dirs() -> None:
    """Mobile/iOS apps vendor deps under Pods/ + Carthage/. Without
    skip, semgrep treats them as project source → FP explosion."""
    pats = _get_repo_skip_patterns()
    assert "Pods" in pats
    assert "Carthage" in pats


def test_disable_env_returns_empty(monkeypatch) -> None:
    """Ablation: STRIX_REPO_SKIP_PATTERNS_DISABLE=1 → no exclusions
    (every file scanned). Useful for measuring the filter's lift."""
    monkeypatch.setenv("STRIX_REPO_SKIP_PATTERNS_DISABLE", "1")
    assert _get_repo_skip_patterns() == []


@pytest.mark.parametrize("val", ["1", "true", "yes", "on", "TRUE"])
def test_disable_env_truthy_values(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_REPO_SKIP_PATTERNS_DISABLE", val)
    assert _get_repo_skip_patterns() == []


def test_extra_env_appends_patterns(monkeypatch) -> None:
    """Operators can extend without forking via
    STRIX_REPO_SKIP_PATTERNS_EXTRA=pat1,pat2,..."""
    monkeypatch.setenv(
        "STRIX_REPO_SKIP_PATTERNS_EXTRA", "mydir,internal/*,fixtures",
    )
    out = _get_repo_skip_patterns()
    assert "mydir" in out
    assert "internal/*" in out
    assert "fixtures" in out
    # Defaults still present.
    assert "node_modules" in out


def test_extra_env_deduplicates(monkeypatch) -> None:
    """Operator-supplied pattern matching a default doesn't appear twice."""
    monkeypatch.setenv(
        "STRIX_REPO_SKIP_PATTERNS_EXTRA", "node_modules,vendor",
    )
    out = _get_repo_skip_patterns()
    assert out.count("node_modules") == 1
    assert out.count("vendor") == 1


def test_default_tuple_is_frozen() -> None:
    """Anti-mutation guard: callers must not accidentally edit the
    constant. _REPO_SKIP_PATTERNS_DEFAULT is a tuple."""
    assert isinstance(_REPO_SKIP_PATTERNS_DEFAULT, tuple)


# ---------------------------------------------------------------------------
# semgrep CLI plumbing — `--exclude PATTERN` appears once per pattern
# ---------------------------------------------------------------------------


def _shutil_for_semgrep(monkeypatch) -> None:
    """Make semgrep look available so run_semgrep enters its main path."""
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/semgrep" if b == "semgrep" else None,
    )


def test_run_semgrep_passes_exclude_flags(monkeypatch, tmp_path) -> None:
    """Each pattern in exclude_paths becomes a `--exclude PATTERN` pair
    in the semgrep argv."""
    _shutil_for_semgrep(monkeypatch)

    captured_cmd: dict[str, list[str]] = {}

    def _fake_run(cmd, **_kw):
        captured_cmd["argv"] = list(cmd)
        m = MagicMock()
        m.returncode = 0
        m.stdout = "{}"
        m.stderr = ""
        return m

    target = tmp_path / "src"
    target.mkdir()
    run_semgrep(
        [str(target)],
        exclude_paths=["node_modules", "vendor", "*.min.js"],
        runner=_fake_run,
    )
    argv = captured_cmd["argv"]
    # Pairs of (--exclude, PATTERN) flagspecs.
    pairs = [
        (argv[i], argv[i + 1])
        for i in range(len(argv) - 1)
        if argv[i] == "--exclude"
    ]
    pattern_values = [p for _, p in pairs]
    assert "node_modules" in pattern_values
    assert "vendor" in pattern_values
    assert "*.min.js" in pattern_values
    # Sanity: 3 patterns → exactly 3 --exclude pairs.
    assert len(pairs) == 3


def test_run_semgrep_no_excludes_when_arg_omitted(monkeypatch, tmp_path) -> None:
    """Backward-compat: callers not passing exclude_paths see the same
    argv shape as pre-iter-Q5.41."""
    _shutil_for_semgrep(monkeypatch)

    captured_cmd: dict[str, list[str]] = {}

    def _fake_run(cmd, **_kw):
        captured_cmd["argv"] = list(cmd)
        m = MagicMock()
        m.returncode = 0
        m.stdout = "{}"
        m.stderr = ""
        return m

    target = tmp_path / "src"
    target.mkdir()
    run_semgrep([str(target)], runner=_fake_run)
    argv = captured_cmd["argv"]
    assert "--exclude" not in argv


def test_run_semgrep_empty_excludes_emits_no_flags(monkeypatch, tmp_path) -> None:
    """An explicit empty list is treated the same as None."""
    _shutil_for_semgrep(monkeypatch)

    captured_cmd: dict[str, list[str]] = {}

    def _fake_run(cmd, **_kw):
        captured_cmd["argv"] = list(cmd)
        m = MagicMock()
        m.returncode = 0
        m.stdout = "{}"
        m.stderr = ""
        return m

    target = tmp_path / "src"
    target.mkdir()
    run_semgrep([str(target)], exclude_paths=[], runner=_fake_run)
    argv = captured_cmd["argv"]
    assert "--exclude" not in argv


# ---------------------------------------------------------------------------
# scan_sast → run_semgrep plumbing
# ---------------------------------------------------------------------------


def test_scan_sast_passes_default_patterns_to_semgrep(monkeypatch, tmp_path) -> None:
    """scan_sast should apply the canonical strix patterns even when the
    caller doesn't supply exclude_paths. Verified by intercepting the
    semgrep CLI argv."""
    _shutil_for_semgrep(monkeypatch)

    captured: list[list[str]] = []

    def _fake_run(cmd, **_kw):
        captured.append(list(cmd))
        m = MagicMock()
        m.returncode = 0
        m.stdout = "{}"
        m.stderr = ""
        return m

    # Patch subprocess.run via the run_semgrep injection point.
    import strix.sast.semgrep_runner as sr
    original = sr.run_semgrep

    def _wrap(*args, **kwargs):
        kwargs["runner"] = _fake_run
        return original(*args, **kwargs)

    monkeypatch.setattr(sr, "run_semgrep", _wrap)
    # Also patch the import path inside scan_sast.
    import strix.sast.tools as sast_tools
    monkeypatch.setattr(sast_tools, "run_semgrep", _wrap)

    repo = tmp_path / "myproject"
    repo.mkdir()
    (repo / "main.py").write_text("import os\n", encoding="utf-8")

    sast_tools.scan_sast(repo_path=str(repo))

    # At least one semgrep invocation; argv contains node_modules / vendor.
    assert captured, "scan_sast must have invoked semgrep"
    # `captured[0]` is is_semgrep_available's `["semgrep", "--version"]`
    # call (also intercepted by the runner injection); the actual scan
    # invocation is the call that has "scan" in its argv.
    scan_argvs = [c for c in captured if "scan" in c]
    assert scan_argvs, "no semgrep scan invocation captured"
    first_argv = scan_argvs[0]
    excludes_seen = [
        first_argv[i + 1]
        for i in range(len(first_argv) - 1)
        if first_argv[i] == "--exclude"
    ]
    assert "node_modules" in excludes_seen
    assert "vendor" in excludes_seen
    assert ".git" in excludes_seen
    assert "*.min.js" in excludes_seen


def test_scan_sast_appends_caller_exclude_paths(monkeypatch, tmp_path) -> None:
    """A caller's exclude_paths supplement the default — not replace them."""
    _shutil_for_semgrep(monkeypatch)

    captured: list[list[str]] = []

    def _fake_run(cmd, **_kw):
        captured.append(list(cmd))
        m = MagicMock()
        m.returncode = 0
        m.stdout = "{}"
        m.stderr = ""
        return m

    import strix.sast.semgrep_runner as sr
    original = sr.run_semgrep

    def _wrap(*args, **kwargs):
        kwargs["runner"] = _fake_run
        return original(*args, **kwargs)

    import strix.sast.tools as sast_tools
    monkeypatch.setattr(sast_tools, "run_semgrep", _wrap)

    repo = tmp_path / "myproject"
    repo.mkdir()
    (repo / "x.py").write_text("x=1\n", encoding="utf-8")

    sast_tools.scan_sast(
        repo_path=str(repo),
        exclude_paths=["custom_fixtures", "playground/*"],
    )

    # `captured[0]` is is_semgrep_available's `["semgrep", "--version"]`
    # call (also intercepted by the runner injection); the actual scan
    # invocation is the call that has "scan" in its argv.
    scan_argvs = [c for c in captured if "scan" in c]
    assert scan_argvs, "no semgrep scan invocation captured"
    first_argv = scan_argvs[0]
    excludes = [
        first_argv[i + 1]
        for i in range(len(first_argv) - 1)
        if first_argv[i] == "--exclude"
    ]
    # Default present.
    assert "node_modules" in excludes
    # Caller-supplied appended.
    assert "custom_fixtures" in excludes
    assert "playground/*" in excludes


def test_scan_sast_disable_env_drops_all_excludes(monkeypatch, tmp_path) -> None:
    """Ablation: STRIX_REPO_SKIP_PATTERNS_DISABLE=1 → scan_sast invokes
    semgrep with NO --exclude flags (every file scanned)."""
    monkeypatch.setenv("STRIX_REPO_SKIP_PATTERNS_DISABLE", "1")
    _shutil_for_semgrep(monkeypatch)

    captured: list[list[str]] = []

    def _fake_run(cmd, **_kw):
        captured.append(list(cmd))
        m = MagicMock()
        m.returncode = 0
        m.stdout = "{}"
        m.stderr = ""
        return m

    import strix.sast.semgrep_runner as sr
    original = sr.run_semgrep

    def _wrap(*args, **kwargs):
        kwargs["runner"] = _fake_run
        return original(*args, **kwargs)

    import strix.sast.tools as sast_tools
    monkeypatch.setattr(sast_tools, "run_semgrep", _wrap)

    repo = tmp_path / "myproject"
    repo.mkdir()
    (repo / "x.py").write_text("x=1\n", encoding="utf-8")

    sast_tools.scan_sast(repo_path=str(repo))

    # `captured[0]` is is_semgrep_available's `["semgrep", "--version"]`
    # call (also intercepted by the runner injection); the actual scan
    # invocation is the call that has "scan" in its argv.
    scan_argvs = [c for c in captured if "scan" in c]
    assert scan_argvs, "no semgrep scan invocation captured"
    first_argv = scan_argvs[0]
    assert "--exclude" not in first_argv
