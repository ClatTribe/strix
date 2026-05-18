"""Integration test: the CWE template auto-fill is wired into
`create_vulnerability_report` between the FP filter and the LLM
dedupe call.

Pins:
  1. A finding with a known CWE + blank optional fields gets the
     template fields auto-populated.
  2. A finding where the agent supplied those fields keeps the
     agent's values (recall-safety contract).
  3. The kill switch (`STRIX_CWE_TEMPLATES_DISABLED=1`) bypasses
     the auto-fill.
  4. The success response surfaces `template_applied` so the
     wrapper can see which findings got auto-filled.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from strix.tools.reporting.reporting_actions import create_vulnerability_report


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


def _sqli_args(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "title": "SQL injection on POST /api/login",
        "description": "Unauthenticated SQLi via username field.",
        "impact": "Full database read.",
        "target": "https://vampi.local/api/login",
        "technical_analysis": "Union-based SQLi; payload reflected.",
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
    base.update(overrides)
    return base


@pytest.fixture
def _mock_tracer() -> MagicMock:
    t = MagicMock()
    t.scan_config = {"targets": [{"original": "https://vampi.local/api/"}]}
    t.get_existing_vulnerabilities.return_value = []
    t.add_vulnerability_report.return_value = "vuln-id-1"
    return t


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_CWE_TEMPLATES_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_FP_FILTER_DISABLED", raising=False)


def test_template_fills_missing_fields(
    _mock_tracer: MagicMock,
) -> None:
    """Agent emits a CWE-89 finding with the optional fields
    blank — template auto-fills them."""
    args = _sqli_args()  # no recommended_action / fix_time / business_impact_plain

    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=_mock_tracer,
    ), patch(
        "strix.llm.dedupe.check_duplicate",
        return_value={"is_duplicate": False},
    ):
        result = create_vulnerability_report(**args)

    assert result["success"] is True
    assert result.get("template_applied") is True
    assert result.get("template_cwe") == "CWE-89"
    # Tracer received the auto-filled values
    persist_kwargs = _mock_tracer.add_vulnerability_report.call_args.kwargs
    assert "parameterized" in persist_kwargs["recommended_action"].lower()
    assert persist_kwargs["fix_time_estimate"]
    assert persist_kwargs["business_impact_plain"]


def test_template_preserves_agent_supplied_values(
    _mock_tracer: MagicMock,
) -> None:
    """Agent supplies its own recommended_action — template MUST
    NOT overwrite it."""
    args = _sqli_args(
        recommended_action="Switch to our internal QueryBuilder.",
    )
    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=_mock_tracer,
    ), patch(
        "strix.llm.dedupe.check_duplicate",
        return_value={"is_duplicate": False},
    ):
        create_vulnerability_report(**args)

    persist_kwargs = _mock_tracer.add_vulnerability_report.call_args.kwargs
    assert persist_kwargs["recommended_action"] == "Switch to our internal QueryBuilder."


def test_template_kill_switch(
    _mock_tracer: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With kill switch on, no fields auto-fill."""
    monkeypatch.setenv("STRIX_CWE_TEMPLATES_DISABLED", "1")
    args = _sqli_args()
    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=_mock_tracer,
    ), patch(
        "strix.llm.dedupe.check_duplicate",
        return_value={"is_duplicate": False},
    ):
        result = create_vulnerability_report(**args)

    assert result.get("template_applied") is not True
    persist_kwargs = _mock_tracer.add_vulnerability_report.call_args.kwargs
    assert persist_kwargs["recommended_action"] is None


def test_unknown_cwe_no_template_applied(
    _mock_tracer: MagicMock,
) -> None:
    """A CWE without a registered template causes no auto-fill —
    response surfaces no `template_applied` key."""
    args = _sqli_args(cwe="CWE-99999")
    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=_mock_tracer,
    ), patch(
        "strix.llm.dedupe.check_duplicate",
        return_value={"is_duplicate": False},
    ):
        result = create_vulnerability_report(**args)

    assert result["success"] is True
    assert result.get("template_applied") is not True
    persist_kwargs = _mock_tracer.add_vulnerability_report.call_args.kwargs
    assert persist_kwargs["recommended_action"] is None
