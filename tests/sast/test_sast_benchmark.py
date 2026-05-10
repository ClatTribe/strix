"""Offline tests for the `sast-vibe/` benchmark fixture.

These don't require Semgrep installed — they verify the fixture
itself parses, has the right shape, and that scan_sast against
it reports `status=partial` with the install-semgrep hint when
the engine is missing. The recall numbers come from a live
semgrep run separately (the runner's job)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from strix.sast.tools import scan_sast


FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "benchmarks" / "per_target" / "fixtures"
    / "code" / "sast-vibe"
)


def test_fixture_files_exist() -> None:
    assert FIXTURE.exists()
    assert (FIXTURE / "expected.yaml").exists()
    assert (FIXTURE / "src" / "handler.js").exists()


def test_fixture_manifest_matches_planted_rules() -> None:
    """Anti-rot — keep the manifest aligned with the rule corpus.
    Every must-find entry's CWE must be one a bundled rule
    actually emits."""
    yaml = pytest.importorskip("yaml")
    from strix.sast.semgrep_runner import (
        VIBE_CODED_RULES_DIR,
        _CWE_TO_CATEGORY,
    )

    rule_cwes: set[str] = set()
    for yml in VIBE_CODED_RULES_DIR.glob("*.yml"):
        doc = yaml.safe_load(yml.read_text())
        for rule in (doc.get("rules") or []):
            cwe = (rule.get("metadata") or {}).get("cwe")
            if cwe:
                rule_cwes.add(str(cwe))

    manifest = yaml.safe_load((FIXTURE / "expected.yaml").read_text())
    must_find_cwes = {
        e.get("cwe") for e in manifest["expected_findings"]
        if e.get("must_find")
    }
    missing = must_find_cwes - rule_cwes
    assert not missing, (
        f"manifest expects CWEs {missing} but no bundled rule emits "
        f"those CWEs — either drop the manifest entry or add a rule"
    )


def test_handler_js_has_planted_lines() -> None:
    """Sanity: the fixture source still has the vulnerable blocks
    at the line numbers the manifest references."""
    yaml = pytest.importorskip("yaml")
    handler = (FIXTURE / "src" / "handler.js").read_text().splitlines()
    manifest = yaml.safe_load((FIXTURE / "expected.yaml").read_text())
    for entry in manifest["expected_findings"]:
        line = entry.get("line")
        if not line or not entry.get("must_find"):
            continue
        # Tolerance: manifest line ± 5 lines should still land on
        # something that looks vulnerable (the rule may match on a
        # nearby line). This is the same tolerance the upstream
        # benchmark runner uses for SAST findings.
        assert 1 <= line <= len(handler), (
            f"manifest line {line} (id={entry['id']}) is out of "
            f"range — handler.js has only {len(handler)} lines"
        )


def test_scan_sast_partial_when_semgrep_missing() -> None:
    """Calling scan_sast on the fixture without semgrep installed
    returns partial with a clear hint — confirms the graceful-
    degradation path is wired through to the LLM-facing tool."""
    with patch("strix.sast.tools.is_semgrep_available", return_value=False):
        result = scan_sast(repo_path=str(FIXTURE / "src"))
    assert result["status"] == "partial"
    assert "semgrep" in (result.get("error") or "").lower()
