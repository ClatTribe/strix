"""Integration test: the FP pre-filter is wired into
`create_vulnerability_report` between CVSS calculation and the LLM
dedupe call.

This is the *integration* point — `tests/llm/test_fp_filter.py`
covers the rules in isolation. Here we verify:
  1. A DROP verdict short-circuits the report path before any LLM
     call (proving the cost win is real).
  2. A DOWNGRADE verdict adjusts severity but the finding still
     lands in the tracer.
  3. The kill switch (`STRIX_FP_FILTER_DISABLED=1`) bypasses the
     filter entirely.

The tracer + dedupe are stubbed; the test never hits a real LLM.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from strix.tools.reporting.reporting_actions import create_vulnerability_report


# Valid CVSS for a high-severity finding (CVSS v3 single-letter codes
# per `_validate_cvss_parameters`).
_HIGH_CVSS_XML = (
    "<attack_vector>N</attack_vector>"
    "<attack_complexity>L</attack_complexity>"
    "<privileges_required>N</privileges_required>"
    "<user_interaction>N</user_interaction>"
    "<scope>U</scope>"
    "<confidentiality>H</confidentiality>"
    "<integrity>H</integrity>"
    "<availability>N</availability>"
)


def _good_args() -> dict[str, Any]:
    """A minimal valid create_vulnerability_report call. Tests
    override the fields they need to trigger specific FP rules."""
    return {
        "title": "SQL injection on POST /api/login",
        "description": "Unauthenticated SQLi via username field.",
        "impact": "Full database read.",
        "target": "https://vampi.local/api/login",
        "technical_analysis": (
            "Union-based SQLi; payload reflected in response."
        ),
        "poc_description": "POST with crafted username field.",
        "poc_script_code": (
            "curl -X POST https://vampi.local/api/login "
            "-d 'username=admin\\' UNION SELECT 1,2,3-- &password=x'"
        ),
        "remediation_steps": "Use parameterized queries.",
        "cvss_breakdown": _HIGH_CVSS_XML,
        "endpoint": "/api/login",
        "method": "POST",
        "cwe": "CWE-89",
    }


@pytest.fixture
def _mock_tracer() -> MagicMock:
    """Stub tracer matching the minimal interface the report path
    reads: `scan_config`, `get_existing_vulnerabilities`,
    `add_vulnerability_report`."""
    t = MagicMock()
    t.scan_config = {
        "targets": [{"original": "https://vampi.local/api/"}],
    }
    t.get_existing_vulnerabilities.return_value = []
    t.add_vulnerability_report.return_value = "vuln-id-1"
    return t


def test_fp_filter_drops_out_of_scope_finding(
    _mock_tracer: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A finding emitted against a host outside the scan's scope
    is rejected by R3 — without an LLM call."""
    monkeypatch.delenv("STRIX_FP_FILTER_DISABLED", raising=False)
    args = _good_args()
    args["target"] = "https://attacker.example.com/leak"
    args["endpoint"] = "https://attacker.example.com/leak"

    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=_mock_tracer,
    ), patch("strix.llm.dedupe.check_duplicate") as dedupe:
        result = create_vulnerability_report(**args)

    assert result["success"] is False
    assert "FP pre-filter" in result["message"]
    assert "R3_out_of_scope" in result["rejected_by"]
    # The cost win — no LLM call was issued.
    dedupe.assert_not_called()
    # The tracer's persist path was never reached.
    _mock_tracer.add_vulnerability_report.assert_not_called()


def test_fp_filter_drops_trivial_poc(
    _mock_tracer: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Upstream validation catches *empty* PoCs; R1 catches the
    case where the agent emitted a non-empty but trivial string
    like 'TBD' or 'xxx' to satisfy required-field validation."""
    monkeypatch.delenv("STRIX_FP_FILTER_DISABLED", raising=False)
    args = _good_args()
    args["poc_script_code"] = "TBD"  # passes validation, fails R1 (<5 chars)

    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=_mock_tracer,
    ), patch("strix.llm.dedupe.check_duplicate") as dedupe:
        result = create_vulnerability_report(**args)

    assert result["success"] is False
    assert "R1_empty_poc" in result["rejected_by"]
    dedupe.assert_not_called()


def test_fp_filter_downgrades_banner_grab_high_to_low(
    _mock_tracer: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A high-tier finding tagged with CWE-200 + banner-grab PoC
    is downgraded to `low`. The finding STILL lands — only the
    severity changes."""
    monkeypatch.delenv("STRIX_FP_FILTER_DISABLED", raising=False)
    args = _good_args()
    args["title"] = "Server banner exposed"
    args["cwe"] = "CWE-200"
    args["poc_script_code"] = "curl -sI https://vampi.local/"
    args["technical_analysis"] = "Server: nginx/1.18.0 in response."
    args["poc_description"] = "Inspect headers with curl -sI"

    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=_mock_tracer,
    ), patch(
        "strix.llm.dedupe.check_duplicate",
        return_value={"is_duplicate": False},
    ):
        result = create_vulnerability_report(**args)

    assert result["success"] is True
    # CVSS yields `high`, but the FP filter downgrades to `low`.
    assert result["severity"] == "low"
    # The downgraded severity was passed to the tracer's persist.
    persist_kwargs = _mock_tracer.add_vulnerability_report.call_args.kwargs
    assert persist_kwargs["severity"] == "low"


def test_fp_filter_allows_legitimate_high_severity_finding(
    _mock_tracer: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real SQLi finding should pass cleanly through the filter
    AND reach the dedupe / persist path."""
    monkeypatch.delenv("STRIX_FP_FILTER_DISABLED", raising=False)

    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=_mock_tracer,
    ), patch(
        "strix.llm.dedupe.check_duplicate",
        return_value={"is_duplicate": False},
    ) as dedupe:
        result = create_vulnerability_report(**_good_args())

    assert result["success"] is True
    # Severity was NOT downgraded — high CVSS stays high.
    assert result["severity"] in ("high", "critical")
    # Both the dedupe LLM and the persist were reached.
    dedupe.assert_called_once()
    _mock_tracer.add_vulnerability_report.assert_called_once()


def test_fp_filter_kill_switch_bypasses_filter(
    _mock_tracer: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the kill switch on, an out-of-scope finding flows
    through to the dedupe step (no DROP)."""
    monkeypatch.setenv("STRIX_FP_FILTER_DISABLED", "1")
    args = _good_args()
    args["target"] = "https://attacker.example.com/leak"
    args["endpoint"] = "https://attacker.example.com/leak"

    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=_mock_tracer,
    ), patch(
        "strix.llm.dedupe.check_duplicate",
        return_value={"is_duplicate": False},
    ) as dedupe:
        result = create_vulnerability_report(**args)

    # Reached the dedupe LLM call — kill switch worked.
    assert dedupe.called
    assert result["success"] is True


def test_fp_filter_drop_does_not_call_tracer_persist(
    _mock_tracer: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DROP must be cheap — verify no tracer mutation occurs on
    rejection beyond reading scan_config + existing list."""
    monkeypatch.delenv("STRIX_FP_FILTER_DISABLED", raising=False)
    args = _good_args()
    args["poc_script_code"] = ""  # R1 DROP

    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=_mock_tracer,
    ), patch("strix.llm.dedupe.check_duplicate") as dedupe:
        result = create_vulnerability_report(**args)

    assert result["success"] is False
    _mock_tracer.add_vulnerability_report.assert_not_called()
    dedupe.assert_not_called()
