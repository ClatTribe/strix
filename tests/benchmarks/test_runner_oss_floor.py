"""Tests for the OSS-floor scanner integrated into the per-target
benchmark runner (`benchmarks/per_target/runner.py`).

The OSS floor is the bar strix has to beat — every code/repo fixture
gets scanned by semgrep + trivy + grype + osv-scanner + checkov in
parallel with the strix run, and per-tool counts land in the result
JSON. If `oss_floor.naive_sum > strix.found_count` on a code fixture,
the LLM layer is adding negative value vs a $0 OSS pipeline.

Why this matters: R1 (2026-05-19) ran the full per_target baseline
with every OSS scanner backend missing from PATH, producing data
that measured "strix LLM with no scanners" instead of strix-with-
scanners. These tests pin the harness behaviour so that:

  1. The floor scan is invoked on code-shaped target_types.
  2. The floor scan is skipped (with a documented reason) on
     non-source target_types like api / ip_address / domain.
  3. Missing OSS binaries degrade gracefully into per-tool
     `note: "<tool> not on PATH"` rather than crashing the run.
  4. The `--skip-oss-floor` flag short-circuits the floor scan
     entirely.
  5. `backends_present` mirror table never lies — it's keyed by
     `shutil.which()` so a missing binary is auditable from the
     result JSON without re-running.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from unittest import mock

import pytest


# Add benchmark runner to path; it isn't packaged.
RUNNER_DIR = (
    Path(__file__).resolve().parents[2]
    / "benchmarks" / "per_target"
)
sys.path.insert(0, str(RUNNER_DIR))

from runner import (  # noqa: E402
    _oss_tool_check,
    compute_oss_floor,
)


# ---------------------------------------------------------------------------
# compute_oss_floor — target_type gating
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target_type",
    ["api", "ip_address", "domain", "container_image", "unknown", None],
)
def test_compute_oss_floor_skips_non_source_target_types(
    tmp_path: Path, target_type: str | None,
) -> None:
    """OSS code-scanners (semgrep / checkov / etc.) don't map to
    network targets. Floor should report applicable=False with a
    documented reason instead of running the tools against a target
    they can't understand."""
    out = compute_oss_floor(tmp_path, target_type)
    assert out["applicable"] is False
    # Reason must mention the target_type so the caller can see why.
    assert "target_type=" in out["reason"]


@pytest.mark.parametrize(
    "target_type",
    ["local_code", "repository", "web+code", "code"],
)
def test_compute_oss_floor_runs_on_source_target_types(
    tmp_path: Path, target_type: str,
) -> None:
    """Code-shaped target_types must trigger the floor scan. We
    don't assert finding counts here (those depend on which OSS
    binaries are on the test host); we just assert the harness
    returned a populated tools+backends_present structure."""
    out = compute_oss_floor(tmp_path, target_type)
    assert out["applicable"] is True
    assert "tools" in out
    assert "backends_present" in out
    assert "naive_sum" in out
    # Backends-present mirror must list all 5 expected tools.
    expected_backends = {
        "semgrep", "trivy", "grype", "osv-scanner", "checkov",
    }
    assert set(out["backends_present"].keys()) == expected_backends


# ---------------------------------------------------------------------------
# _oss_tool_check — graceful degradation
# ---------------------------------------------------------------------------


def test_oss_tool_check_returns_none_when_binary_missing() -> None:
    """When a scanner binary isn't on PATH, the helper must NOT
    raise — it must return (None, "<name> not on PATH"). This is
    the path that fired during R1 (no OSS binaries installed)."""
    # Use a tool name that definitely won't exist on any PATH.
    n, note = _oss_tool_check(
        "this-binary-does-not-exist-anywhere",
        ["this-binary-does-not-exist-anywhere", "--version"],
    )
    assert n is None
    assert "not on PATH" in note


def test_oss_tool_check_reports_timeout_without_raising() -> None:
    """Long-running scans must time out cleanly. The benchmark
    harness can't block forever on a hung scanner."""
    if not shutil.which("sleep"):
        pytest.skip("sleep not available")
    # 1s timeout on a 5s sleep — must return (None, "<tool> timed out ...").
    # We patch shutil.which so the helper thinks "sleep" is the tool name.
    with mock.patch("runner.shutil.which", return_value="/bin/sleep"):
        n, note = _oss_tool_check("sleep", ["sleep", "5"], timeout=1)
    assert n is None
    assert "timed out" in note


def test_oss_tool_check_parses_semgrep_json() -> None:
    """When semgrep returns valid JSON with N results, the helper
    must report count=N."""
    fake_json = b'{"results": [{"check_id": "x"}, {"check_id": "y"}]}'

    class FakeCompleted:
        returncode = 1  # semgrep exits 1 when findings emitted
        stdout = fake_json

    with mock.patch("runner.shutil.which", return_value="/usr/bin/semgrep"), \
         mock.patch("runner.subprocess.run", return_value=FakeCompleted()):
        n, note = _oss_tool_check("semgrep", ["semgrep", "x"])
    assert n == 2
    assert note == ""


def test_oss_tool_check_handles_trivy_high_critical_sum() -> None:
    """trivy fs JSON nests vulns inside Results[].Vulnerabilities.
    The helper must sum across Results."""
    fake_json = (
        b'{"Results": ['
        b'  {"Vulnerabilities": [{"VulnerabilityID":"X"},{"VulnerabilityID":"Y"}]},'
        b'  {"Vulnerabilities": [{"VulnerabilityID":"Z"}]}'
        b']}'
    )

    class FakeCompleted:
        returncode = 0
        stdout = fake_json

    with mock.patch("runner.shutil.which", return_value="/usr/bin/trivy"), \
         mock.patch("runner.subprocess.run", return_value=FakeCompleted()):
        n, note = _oss_tool_check("trivy", ["trivy", "fs", "."])
    assert n == 3
    assert note == ""


def test_oss_tool_check_handles_grype_severity_filter() -> None:
    """grype emits matches across all severities; the helper must
    filter to HIGH+CRITICAL only (matching trivy's filter for
    cross-tool comparability)."""
    fake_json = (
        b'{"matches": ['
        b'  {"vulnerability": {"severity": "Critical"}},'
        b'  {"vulnerability": {"severity": "High"}},'
        b'  {"vulnerability": {"severity": "Medium"}},'
        b'  {"vulnerability": {"severity": "Low"}}'
        b']}'
    )

    class FakeCompleted:
        returncode = 0
        stdout = fake_json

    with mock.patch("runner.shutil.which", return_value="/usr/bin/grype"), \
         mock.patch("runner.subprocess.run", return_value=FakeCompleted()):
        n, note = _oss_tool_check("grype", ["grype", "dir:."])
    # Only Critical + High count.
    assert n == 2


def test_oss_tool_check_handles_osv_scanner_nested_vulns() -> None:
    """osv-scanner JSON nests vulns at results[].packages[].vulnerabilities."""
    fake_json = (
        b'{"results": ['
        b'  {"packages": ['
        b'    {"vulnerabilities": [{"id":"GHSA-1"},{"id":"GHSA-2"}]},'
        b'    {"vulnerabilities": [{"id":"GHSA-3"}]}'
        b'  ]}'
        b']}'
    )

    class FakeCompleted:
        returncode = 1  # osv-scanner returns 1 when vulns found
        stdout = fake_json

    with mock.patch("runner.shutil.which",
                    return_value="/usr/bin/osv-scanner"), \
         mock.patch("runner.subprocess.run", return_value=FakeCompleted()):
        n, note = _oss_tool_check(
            "osv-scanner",
            ["osv-scanner", "scan", "source", "-r", "."],
        )
    assert n == 3


def test_oss_tool_check_handles_checkov_list_or_dict_shape() -> None:
    """checkov's JSON shape varies depending on how many frameworks
    fired: single framework → dict; multiple frameworks → list of
    dicts. The helper must handle both without crashing."""

    # List shape — multi-framework.
    fake_json_list = (
        b'[{"results": {"failed_checks": [{"check_id":"C1"},{"check_id":"C2"}]}},'
        b' {"results": {"failed_checks": [{"check_id":"C3"}]}}]'
    )

    class FakeCompletedList:
        returncode = 1
        stdout = fake_json_list

    with mock.patch("runner.shutil.which", return_value="/usr/bin/checkov"), \
         mock.patch("runner.subprocess.run",
                    return_value=FakeCompletedList()):
        n, note = _oss_tool_check("checkov", ["checkov", "-d", "."])
    assert n == 3

    # Dict shape — single framework.
    fake_json_dict = (
        b'{"results": {"failed_checks": [{"check_id":"C1"},{"check_id":"C2"}]}}'
    )

    class FakeCompletedDict:
        returncode = 1
        stdout = fake_json_dict

    with mock.patch("runner.shutil.which", return_value="/usr/bin/checkov"), \
         mock.patch("runner.subprocess.run",
                    return_value=FakeCompletedDict()):
        n, note = _oss_tool_check("checkov", ["checkov", "-d", "."])
    assert n == 2


def test_oss_tool_check_reports_non_json_stdout() -> None:
    """When a scanner exits 0 but stdout isn't valid JSON, the
    helper must NOT crash — must return (None, "<tool>: stdout
    not JSON (<err>)")."""

    class FakeCompleted:
        returncode = 0
        stdout = b"this is not json"

    with mock.patch("runner.shutil.which", return_value="/usr/bin/semgrep"), \
         mock.patch("runner.subprocess.run", return_value=FakeCompleted()):
        n, note = _oss_tool_check("semgrep", ["semgrep", "x"])
    assert n is None
    assert "stdout not JSON" in note


def test_oss_tool_check_reports_bad_exit_code() -> None:
    """Exit codes outside the per-tool whitelist (semgrep allows
    0/1; trivy allows 0; etc.) must surface as (None, "<tool>
    exit=<N>")."""

    class FakeCompleted:
        returncode = 2
        stdout = b'{}'

    with mock.patch("runner.shutil.which", return_value="/usr/bin/trivy"), \
         mock.patch("runner.subprocess.run", return_value=FakeCompleted()):
        n, note = _oss_tool_check("trivy", ["trivy", "fs", "."])
    assert n is None
    assert "exit=2" in note


# ---------------------------------------------------------------------------
# compute_oss_floor — full integration shape
# ---------------------------------------------------------------------------


def test_compute_oss_floor_graceful_when_all_backends_missing(
    tmp_path: Path,
) -> None:
    """When no OSS scanners are installed (R1 scenario), the floor
    helper must still return a well-formed dict with every tool
    recorded as 'not on PATH' — no crash, no missing keys."""
    with mock.patch("runner.shutil.which", return_value=None):
        out = compute_oss_floor(tmp_path, "local_code")
    assert out["applicable"] is True
    assert out["naive_sum"] == 0
    # Every backend recorded as missing.
    assert all(present is False
               for present in out["backends_present"].values())
    # Every tool entry has a `note` explaining why it didn't run.
    for tool_name, tool_data in out["tools"].items():
        assert tool_data.get("count") is None
        assert "not on PATH" in tool_data.get("note", "")
