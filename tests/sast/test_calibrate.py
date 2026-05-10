"""Unit tests for `strix.sast.calibrate` — Phase 7.4 severity
calibration via reachability + test-file demote."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.sast.calibrate import (
    Calibration,
    _is_test_file,
    _shift,
    calibrate_finding_severity,
    load_code_map,
)
from strix.sast.semgrep_runner import SastFinding


def _f(file: str, severity: str = "high") -> SastFinding:
    return SastFinding(
        rule_id="r", file=file, line_start=1, line_end=1,
        message="", severity=severity,
    )


# ---------------------------------------------------------------------------
# Test-file detection
# ---------------------------------------------------------------------------


def test_is_test_file_pytest_naming() -> None:
    assert _is_test_file("tests/test_foo.py")
    assert _is_test_file("test_helpers.py")
    assert _is_test_file("src/utils_test.py")


def test_is_test_file_jest_naming() -> None:
    assert _is_test_file("__tests__/Component.test.js")
    assert _is_test_file("Button.test.tsx")
    assert _is_test_file("api.spec.ts")


def test_is_test_file_dir_patterns() -> None:
    assert _is_test_file("tests/handlers/auth.py")
    assert _is_test_file("spec/lib/util.rb")
    assert _is_test_file("tests/integration/end_to_end.go")


def test_is_test_file_negative_for_normal_paths() -> None:
    assert not _is_test_file("src/handlers/user.js")
    assert not _is_test_file("app.py")
    assert not _is_test_file("controllers/api.ts")
    assert not _is_test_file("")


# ---------------------------------------------------------------------------
# _shift severity ladder
# ---------------------------------------------------------------------------


def test_shift_up_one_tier() -> None:
    assert _shift("high", 1) == "critical"
    assert _shift("medium", 1) == "high"
    assert _shift("low", 1) == "medium"


def test_shift_down_one_tier() -> None:
    assert _shift("high", -1) == "medium"
    assert _shift("low", -1) == "info"
    assert _shift("info", -1) == "info"  # clamped


def test_shift_critical_capped_at_critical() -> None:
    assert _shift("critical", 1) == "critical"
    assert _shift("critical", 5) == "critical"


def test_shift_unknown_severity_unchanged() -> None:
    assert _shift("garbage", 1) == "garbage"


# ---------------------------------------------------------------------------
# calibrate_finding_severity — no code_map → only test-file demote
# ---------------------------------------------------------------------------


def test_calibrate_no_code_map_no_test_file_unchanged() -> None:
    cal = calibrate_finding_severity(_f("src/handler.js"))
    assert cal.severity == "high"
    assert cal.bumped is False
    assert cal.demoted is False


def test_calibrate_test_file_demotes_one_tier() -> None:
    cal = calibrate_finding_severity(_f("tests/test_handler.py", severity="critical"))
    assert cal.severity == "high"
    assert cal.demoted is True
    assert "test file" in cal.rationale.lower()


def test_calibrate_test_file_demote_clamps_at_info() -> None:
    cal = calibrate_finding_severity(_f("tests/test_x.py", severity="info"))
    assert cal.severity == "info"


# ---------------------------------------------------------------------------
# calibrate_finding_severity — with code_map → route bump
# ---------------------------------------------------------------------------


def _code_map(*route_files: str) -> dict:
    return {
        "schema_version": 1,
        "routes": [{"file": rf} for rf in route_files],
    }


def test_calibrate_route_file_bumps_one_tier() -> None:
    cm = _code_map("src/routes/users.js")
    cal = calibrate_finding_severity(
        _f("src/routes/users.js", severity="medium"),
        code_map=cm,
    )
    assert cal.severity == "high"
    assert cal.bumped is True
    assert "route" in cal.rationale.lower()


def test_calibrate_non_route_file_unchanged() -> None:
    cm = _code_map("src/routes/users.js")
    cal = calibrate_finding_severity(
        _f("src/utils/helpers.js", severity="medium"),
        code_map=cm,
    )
    assert cal.severity == "medium"
    assert cal.bumped is False


def test_calibrate_route_bump_caps_at_critical() -> None:
    cm = _code_map("src/handler.js")
    cal = calibrate_finding_severity(
        _f("src/handler.js", severity="critical"),
        code_map=cm,
    )
    assert cal.severity == "critical"


def test_calibrate_route_bump_and_test_demote_cancel() -> None:
    """A test file that's also referenced as a route handler →
    -1 + 1 = 0. Severity unchanged."""
    cm = _code_map("tests/handler_test.py")
    cal = calibrate_finding_severity(
        _f("tests/handler_test.py", severity="medium"),
        code_map=cm,
    )
    assert cal.severity == "medium"
    assert cal.bumped is True
    assert cal.demoted is True


def test_calibrate_route_path_suffix_match() -> None:
    """When the finding's path is absolute and code_map's path is
    relative, the match should still fire via suffix matching."""
    cm = _code_map("src/api/users.js")
    cal = calibrate_finding_severity(
        _f("/repo/src/api/users.js", severity="medium"),
        code_map=cm,
    )
    assert cal.bumped is True


# ---------------------------------------------------------------------------
# load_code_map — best-effort artifact reading
# ---------------------------------------------------------------------------


def test_load_code_map_from_repo(tmp_path: Path) -> None:
    cm = {"schema_version": 1, "routes": [{"file": "a.js"}]}
    (tmp_path / "code_map.json").write_text(json.dumps(cm))
    loaded = load_code_map(tmp_path)
    assert loaded == cm


def test_load_code_map_missing_returns_none(tmp_path: Path) -> None:
    assert load_code_map(tmp_path) is None


def test_load_code_map_invalid_json_returns_none(tmp_path: Path) -> None:
    (tmp_path / "code_map.json").write_text("not json")
    assert load_code_map(tmp_path) is None
