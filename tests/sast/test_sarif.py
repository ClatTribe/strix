"""Unit tests for `strix.sast.sarif` — Phase 7.5 SARIF 2.1.0
output converter.

Pins the JSON shape that GitHub Code Scanning + standard SARIF
consumers expect: `version`, `$schema`, `runs[].tool.driver.rules`,
`runs[].results[]` with `physicalLocation`, severity → `level`
mapping, and the strix-specific `properties.calibration` that
preserves the post-7.4 breadcrumb.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.sast.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    findings_to_sarif,
    write_sarif,
)
from strix.sast.semgrep_runner import SastFinding


def _f(
    rule_id: str = "strix-r",
    file: str = "src/handler.js",
    line: int = 1,
    severity: str = "high",
    cwe: str | None = "CWE-89",
    category: str | None = "sqli",
    message: str = "test",
) -> SastFinding:
    return SastFinding(
        rule_id=rule_id, file=file,
        line_start=line, line_end=line,
        message=message, severity=severity,
        cwe=cwe, category=category, language="javascript",
    )


# ---------------------------------------------------------------------------
# Top-level shape
# ---------------------------------------------------------------------------


def test_sarif_version_and_schema() -> None:
    doc = findings_to_sarif([])
    assert doc["version"] == SARIF_VERSION
    assert doc["$schema"] == SARIF_SCHEMA
    assert "2.1.0" in doc["$schema"]


def test_sarif_empty_findings_produces_valid_doc() -> None:
    """Zero findings → still a valid SARIF doc with empty rules
    + results arrays. Consumers may rely on the `runs` array being
    non-empty even when results are."""
    doc = findings_to_sarif([])
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "strix-sast"
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_sarif_tool_driver_metadata() -> None:
    doc = findings_to_sarif([], tool_name="custom-name", tool_version="9.9.9")
    drv = doc["runs"][0]["tool"]["driver"]
    assert drv["name"] == "custom-name"
    assert drv["version"] == "9.9.9"
    assert "informationUri" in drv


# ---------------------------------------------------------------------------
# Severity → SARIF level mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("severity,level", [
    ("critical", "error"),
    ("high", "error"),
    ("medium", "warning"),
    ("low", "note"),
    ("info", "note"),
])
def test_severity_maps_to_sarif_level(severity: str, level: str) -> None:
    doc = findings_to_sarif([_f(severity=severity)])
    assert doc["runs"][0]["results"][0]["level"] == level


def test_severity_unknown_falls_back_to_warning() -> None:
    doc = findings_to_sarif([_f(severity="garbage")])
    assert doc["runs"][0]["results"][0]["level"] == "warning"


# ---------------------------------------------------------------------------
# Rule deduplication
# ---------------------------------------------------------------------------


def test_duplicate_rule_id_emits_one_descriptor() -> None:
    """SARIF expects unique rule descriptors. Two findings with the
    same rule_id should produce ONE rule entry, two results both
    referencing it by index."""
    findings = [_f(rule_id="dup-rule"), _f(rule_id="dup-rule", line=20)]
    doc = findings_to_sarif(findings)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    results = doc["runs"][0]["results"]
    assert len(rules) == 1
    assert rules[0]["id"] == "dup-rule"
    assert len(results) == 2
    # Both results reference index 0.
    assert results[0]["ruleIndex"] == 0
    assert results[1]["ruleIndex"] == 0


def test_distinct_rules_get_distinct_indices() -> None:
    findings = [
        _f(rule_id="rule-a"),
        _f(rule_id="rule-b"),
        _f(rule_id="rule-a"),
    ]
    doc = findings_to_sarif(findings)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 2
    ids = [r["id"] for r in rules]
    assert "rule-a" in ids
    assert "rule-b" in ids


# ---------------------------------------------------------------------------
# Result physicalLocation shape
# ---------------------------------------------------------------------------


def test_result_has_physical_location() -> None:
    doc = findings_to_sarif([_f(file="app.js", line=42)])
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert "physicalLocation" in loc
    pl = loc["physicalLocation"]
    assert pl["artifactLocation"]["uri"] == "app.js"
    assert pl["region"]["startLine"] == 42
    assert pl["region"]["endLine"] == 42


def test_result_endline_uses_finding_endline() -> None:
    """Multi-line findings carry both startLine and endLine."""
    f = _f()
    f.line_start = 10
    f.line_end = 15
    doc = findings_to_sarif([f])
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 10
    assert region["endLine"] == 15


def test_result_clamps_line_to_minimum_1() -> None:
    """SARIF requires startLine >= 1. Findings that somehow have
    line=0 must clamp."""
    f = _f()
    f.line_start = 0
    f.line_end = 0
    doc = findings_to_sarif([f])
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] >= 1


# ---------------------------------------------------------------------------
# repo_path → relative URI normalisation
# ---------------------------------------------------------------------------


def test_absolute_path_normalised_to_repo_relative(tmp_path: Path) -> None:
    """SARIF consumers (GitHub) require repo-relative URIs.
    When `repo_path` is supplied, absolute paths under it should
    be rewritten."""
    src = tmp_path / "src"
    src.mkdir()
    handler = src / "handler.js"
    handler.write_text("// stub")

    f = _f(file=str(handler.resolve()))
    doc = findings_to_sarif([f], repo_path=str(tmp_path))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/handler.js"


def test_relative_path_passes_through_unchanged() -> None:
    """A path that's already repo-relative (the Semgrep convention)
    should NOT be modified."""
    f = _f(file="src/handler.js")
    doc = findings_to_sarif([f], repo_path="/repo")
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/handler.js"


def test_originaluribaseids_set_when_repo_path_present() -> None:
    """SARIF 2.1.0 uses `originalUriBaseIds` to anchor relative
    URIs to a repo root. This is what GitHub Code Scanning uses
    to render the file links correctly."""
    doc = findings_to_sarif([_f()], repo_path="/repo")
    assert "originalUriBaseIds" in doc["runs"][0]
    assert "%SRCROOT%" in doc["runs"][0]["originalUriBaseIds"]


# ---------------------------------------------------------------------------
# CWE / category propagation into rule + result properties
# ---------------------------------------------------------------------------


def test_rule_descriptor_carries_cwe_and_category() -> None:
    f = _f(cwe="CWE-79", category="xss")
    doc = findings_to_sarif([f])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["cwe"] == "CWE-79"
    assert "xss" in rule["properties"]["tags"]
    assert "cwe-79" in rule["properties"]["tags"]
    # GitHub Code Scanning specifically reads `security-severity`.
    assert "security-severity" in rule["properties"]


def test_result_properties_preserve_finding_metadata() -> None:
    f = _f(severity="medium", cwe="CWE-89", category="sqli")
    doc = findings_to_sarif([f])
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["severity"] == "medium"
    assert props["cwe"] == "CWE-89"
    assert props["category"] == "sqli"


# ---------------------------------------------------------------------------
# Calibration breadcrumb propagation
# ---------------------------------------------------------------------------


def test_calibration_note_attaches_to_matching_result() -> None:
    """`calibration_notes` keyed by `rule:file:line` should populate
    the matching result's `properties.calibration`."""
    f = _f(rule_id="r-a", file="src/x.js", line=5)
    notes = {"r-a:src/x.js:5": "route-reachable bump applied"}
    doc = findings_to_sarif([f], calibration_notes=notes)
    res = doc["runs"][0]["results"][0]
    assert res["properties"]["calibration"] == "route-reachable bump applied"


def test_calibration_absent_when_key_doesnt_match() -> None:
    f = _f(rule_id="r-a", file="src/x.js", line=5)
    notes = {"different-key": "wrong"}
    doc = findings_to_sarif([f], calibration_notes=notes)
    res = doc["runs"][0]["results"][0]
    assert "calibration" not in res["properties"]


# ---------------------------------------------------------------------------
# write_sarif — file output
# ---------------------------------------------------------------------------


def test_write_sarif_creates_valid_json_file(tmp_path: Path) -> None:
    out = tmp_path / "out.sarif"
    written = write_sarif([_f()], out)
    assert written == out.resolve()
    assert out.exists()
    doc = json.loads(out.read_text())
    assert doc["version"] == SARIF_VERSION


def test_write_sarif_creates_parent_directories(tmp_path: Path) -> None:
    """Intermediate dirs that don't exist yet should be created
    automatically — common case is writing into a CI artifact dir
    that the runner just provisioned."""
    out = tmp_path / "deep" / "nested" / "out.sarif"
    write_sarif([_f()], out)
    assert out.exists()


def test_write_sarif_pretty_prints() -> None:
    """SARIF files end up in CI artifact buckets where humans
    occasionally need to read them. Pretty-print with 2-space
    indent."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
        path = Path(tmp.name)
    try:
        write_sarif([_f()], path)
        text = path.read_text()
        # Should have indented structure, not all on one line.
        assert "\n  " in text
        # File ends with a newline (POSIX convention).
        assert text.endswith("\n")
    finally:
        path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# JSON serialisation round-trip
# ---------------------------------------------------------------------------


def test_sarif_serialises_cleanly() -> None:
    """Regression guard: `findings_to_sarif` returns a dict that
    must serialise without TypeErrors. Catches accidentally
    leaking SastFinding dataclass instances or Path objects into
    the output."""
    f = _f()
    doc = findings_to_sarif([f], repo_path="/repo")
    # If anything in `doc` isn't JSON-serialisable, this raises.
    serialised = json.dumps(doc)
    assert isinstance(serialised, str)
    assert "strix-sast" in serialised
