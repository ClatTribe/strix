"""Tests for iter-Q5.11 + Q5.11b — L2-audience fields on
`create_vulnerability_report`.

Per CLAUDE.md §1.5.6 (tools are LLM's hands, not its brain), the
reasoning lives in the LLM's response text; the commit rides on
this tool. Two parameters carry the commit:

  * chain_summary — multi-finding exploit narrative
  * customer_priority — re-ranked priority for this customer's
    context (distinct from intrinsic severity)

Plus iter-Q5.11b — observation mode (severity="observation" for
inconclusive partial signals — Gap 4 from the consolidated Q5
proposal §7).
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


def _good_args() -> dict[str, Any]:
    return {
        "title": "SQL injection on POST /api/login",
        "description": "Unauthenticated SQLi via username field.",
        "impact": "Full database read.",
        "target": "https://example.local/api/login",
        "technical_analysis": "Union-based SQLi; payload reflected in response.",
        "poc_description": "POST with crafted username field.",
        "poc_script_code": (
            "curl -X POST https://example.local/api/login "
            "-d 'username=admin\\' UNION SELECT 1,2,3-- &password=x'"
        ),
        "remediation_steps": "Use parameterized queries.",
        "cvss_breakdown": _HIGH_CVSS_XML,
        "endpoint": "/api/login",
        "method": "POST",
        "cwe": "CWE-89",
    }


@pytest.fixture
def fake_tracer(monkeypatch):
    tracer = MagicMock()
    tracer.scan_config = {"targets": ["https://example.local"]}
    tracer.get_existing_vulnerabilities.return_value = []
    tracer.add_vulnerability_report.return_value = "vuln-0001"
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: tracer,
    )
    return tracer


@pytest.fixture(autouse=True)
def _no_dedupe(monkeypatch):
    """Stub the LLM dedupe call so it doesn't fire on every test."""
    monkeypatch.setattr(
        "strix.llm.dedupe.check_duplicate",
        lambda *a, **kw: {"is_duplicate": False},
    )


@pytest.fixture(autouse=True)
def _no_fp_drop(monkeypatch):
    """Default to PASS verdicts so the test exercises the success path
    of the new fields. Tests that need DROP/DOWNGRADE override."""
    from strix.llm.fp_filter import FPRuleResult
    monkeypatch.setattr(
        "strix.llm.fp_filter.evaluate",
        lambda *a, **kw: FPRuleResult(verdict="PASS", rule="", reason=""),
    )


# ---------------------------------------------------------------------------
# iter-Q5.11 — chain_summary
# ---------------------------------------------------------------------------


def test_chain_summary_passes_through_to_tracer(fake_tracer):
    chain = (
        "CSRF on /api/transfer combined with the open-redirect at "
        "/return makes a one-click account drain."
    )
    out = create_vulnerability_report(
        chain_summary=chain,
        **_good_args(),
    )
    assert out["success"] is True
    call_kwargs = fake_tracer.add_vulnerability_report.call_args.kwargs
    assert call_kwargs["chain_summary"] == chain


def test_chain_summary_optional(fake_tracer):
    """When not supplied, the finding still emits — the chain narrative
    is a per-finding bonus, not a requirement."""
    out = create_vulnerability_report(**_good_args())
    assert out["success"] is True
    call_kwargs = fake_tracer.add_vulnerability_report.call_args.kwargs
    assert call_kwargs.get("chain_summary") is None


# ---------------------------------------------------------------------------
# iter-Q5.11 — customer_priority
# ---------------------------------------------------------------------------


def test_customer_priority_passes_through_to_tracer(fake_tracer):
    out = create_vulnerability_report(
        customer_priority=2,
        **_good_args(),
    )
    assert out["success"] is True
    call_kwargs = fake_tracer.add_vulnerability_report.call_args.kwargs
    assert call_kwargs["customer_priority"] == 2


def test_customer_priority_distinct_from_intrinsic_severity(fake_tracer):
    """The whole point of customer_priority: it's separate from
    severity. A low-severity finding on a critical customer endpoint
    can carry priority=1; severity stays "high" / "low" / etc."""
    out = create_vulnerability_report(
        customer_priority=1,
        **_good_args(),
    )
    call_kwargs = fake_tracer.add_vulnerability_report.call_args.kwargs
    assert call_kwargs["customer_priority"] == 1
    # severity is computed from CVSS; not affected by customer_priority
    assert call_kwargs["severity"] != "1"


# ---------------------------------------------------------------------------
# iter-Q5.11b — observation mode
# ---------------------------------------------------------------------------


def test_observation_mode_relaxes_required_fields(fake_tracer):
    """Observation mode lets the lead commit an inconclusive
    finding without filling in PoC + remediation. The lead has only
    one piece of signal — "this looks weird" — and that's worth
    committing instead of losing to compaction."""
    args = _good_args()
    # The inconclusive observation only has title + target + a
    # description of the signal. Everything else is missing.
    args["technical_analysis"] = ""
    args["poc_description"] = ""
    args["poc_script_code"] = ""
    args["remediation_steps"] = ""
    args["impact"] = ""
    out = create_vulnerability_report(observation=True, **args)
    assert out["success"] is True, (
        f"observation mode must accept minimal input, got: {out}"
    )


def test_observation_severity_forced(fake_tracer):
    """observation=True forces severity='observation' regardless
    of CVSS — the synthetic tier marks the finding as inconclusive
    so triage views can filter."""
    args = _good_args()
    args["technical_analysis"] = ""
    args["poc_description"] = ""
    args["poc_script_code"] = ""
    args["remediation_steps"] = ""
    args["impact"] = ""
    out = create_vulnerability_report(observation=True, **args)
    assert out["success"] is True
    call_kwargs = fake_tracer.add_vulnerability_report.call_args.kwargs
    assert call_kwargs["severity"] == "observation"


def test_non_observation_severity_unaffected(fake_tracer):
    """observation=False (default) leaves severity computed from
    CVSS as before — no regression on the normal emission path."""
    out = create_vulnerability_report(**_good_args())
    assert out["success"] is True
    call_kwargs = fake_tracer.add_vulnerability_report.call_args.kwargs
    assert call_kwargs["severity"] != "observation"
    # _HIGH_CVSS_XML maps to critical (CIA = H,H,N + AV=N)
    assert call_kwargs["severity"] in ("critical", "high")


# ---------------------------------------------------------------------------
# Combined: chain + customer_priority + observation
# ---------------------------------------------------------------------------


def test_observation_can_still_carry_chain_summary(fake_tracer):
    """An observation can still hint at a chain — 'might combine
    with finding X' is the most natural observation shape."""
    args = _good_args()
    args["technical_analysis"] = ""
    args["poc_description"] = ""
    args["poc_script_code"] = ""
    args["remediation_steps"] = ""
    args["impact"] = ""
    out = create_vulnerability_report(
        observation=True,
        chain_summary="May chain with vuln-0001 if confirmed",
        customer_priority=5,
        **args,
    )
    assert out["success"] is True
    call_kwargs = fake_tracer.add_vulnerability_report.call_args.kwargs
    assert call_kwargs["severity"] == "observation"
    assert call_kwargs["chain_summary"] == "May chain with vuln-0001 if confirmed"
    assert call_kwargs["customer_priority"] == 5


# ---------------------------------------------------------------------------
# Tracer-side persistence
# ---------------------------------------------------------------------------


def test_tracer_persists_chain_summary_field():
    """The tracer must write chain_summary into the report dict so
    list_pending_findings / get_finding / run_summary all see it."""
    from strix.telemetry.tracer import Tracer
    tracer = Tracer(run_name="q5-11-test")
    rid = tracer.add_vulnerability_report(
        title="x",
        severity="high",
        chain_summary="A + B = ATO",
    )
    assert rid.startswith("vuln-")
    matching = [r for r in tracer.vulnerability_reports if r["id"] == rid]
    assert len(matching) == 1
    assert matching[0]["chain_summary"] == "A + B = ATO"


def test_tracer_persists_customer_priority_field():
    from strix.telemetry.tracer import Tracer
    tracer = Tracer(run_name="q5-11-test")
    rid = tracer.add_vulnerability_report(
        title="x",
        severity="high",
        customer_priority=3,
    )
    matching = [r for r in tracer.vulnerability_reports if r["id"] == rid]
    assert matching[0]["customer_priority"] == 3


def test_tracer_omits_chain_summary_when_blank():
    """Empty / whitespace-only chain_summary must not write the
    field (keeps the report dict clean for downstream consumers)."""
    from strix.telemetry.tracer import Tracer
    tracer = Tracer(run_name="q5-11-test")
    rid = tracer.add_vulnerability_report(
        title="x",
        severity="high",
        chain_summary="   ",
    )
    matching = [r for r in tracer.vulnerability_reports if r["id"] == rid]
    assert "chain_summary" not in matching[0]


def test_tracer_omits_customer_priority_when_zero_or_negative():
    """Per the integer guard — only positive priorities persist.
    Zero / negative would be malformed inputs."""
    from strix.telemetry.tracer import Tracer
    tracer = Tracer(run_name="q5-11-test")
    rid = tracer.add_vulnerability_report(
        title="x",
        severity="high",
        customer_priority=0,
    )
    matching = [r for r in tracer.vulnerability_reports if r["id"] == rid]
    assert "customer_priority" not in matching[0]
