"""Tests for finding.kill_chain — multi-step finding context.

Roadmap §1. Pattern-matcher tools emit findings as standalone alerts.
A real adversarial agent's value is the chain. This event groups the
ordered steps that led to a finding.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, _normalize_kill_chain, set_global_tracer


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


def _events_for(run_name: str, tmp_path) -> list[dict[str, Any]]:
    p = tmp_path / "strix_runs" / run_name / "events.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# _normalize_kill_chain
# ---------------------------------------------------------------------------


def test_normalize_returns_none_for_empty_or_invalid() -> None:
    assert _normalize_kill_chain(None) is None
    assert _normalize_kill_chain([]) is None
    assert _normalize_kill_chain("not a list") is None
    # All non-dict entries → no usable steps → None.
    assert _normalize_kill_chain(["string", 42]) is None


def test_normalize_keeps_only_steps_with_content() -> None:
    """A step with only step_number/type and nothing else isn't useful."""
    chain = [
        {"step_number": 1, "type": "recon"},  # empty content — dropped
        {"step_number": 2, "description": "Found admin panel"},
    ]
    out = _normalize_kill_chain(chain)
    assert out is not None
    assert len(out) == 1
    assert out[0]["description"] == "Found admin panel"


def test_normalize_fills_missing_step_numbers() -> None:
    chain = [
        {"description": "Step A"},
        {"description": "Step B"},
        {"step_number": 5, "description": "Step C"},
    ]
    out = _normalize_kill_chain(chain)
    assert [s["step_number"] for s in out] == [1, 2, 5]


def test_normalize_clamps_unknown_type_to_discovery() -> None:
    chain = [
        {"description": "X", "type": "exploitation"},
        {"description": "Y", "type": "completely-bogus-type"},
        {"description": "Z", "type": ""},
    ]
    out = _normalize_kill_chain(chain)
    types = [s["type"] for s in out]
    assert types == ["exploitation", "discovery", "discovery"]


def test_normalize_strips_string_fields() -> None:
    chain = [{"description": "  has leading/trailing  ", "tool": " curl "}]
    out = _normalize_kill_chain(chain)
    assert out[0]["description"] == "has leading/trailing"
    assert out[0]["tool"] == "curl"


def test_normalize_accepts_string_step_number() -> None:
    """`step_number` arrives as a string (XML attribute) and should coerce."""
    chain = [{"step_number": "3", "description": "X"}]
    out = _normalize_kill_chain(chain)
    assert out[0]["step_number"] == 3


def test_normalize_skips_non_dict_entries() -> None:
    chain = [
        {"description": "A"},
        "not a dict",
        42,
        {"description": "B"},
    ]
    out = _normalize_kill_chain(chain)
    assert len(out) == 2


# ---------------------------------------------------------------------------
# add_vulnerability_report — kill_chain integration
# ---------------------------------------------------------------------------


def test_finding_with_kill_chain_emits_separate_event(tmp_path) -> None:
    t = Tracer("kc-run")
    set_global_tracer(t)
    chain = [
        {"step_number": 1, "type": "recon", "description": "Found /admin", "tool": "http"},
        {"step_number": 2, "type": "exploitation", "description": "Logged in admin:admin"},
        {"step_number": 3, "type": "impact", "description": "Dumped 1247 users"},
    ]
    report_id = t.add_vulnerability_report(
        title="Default Admin Credentials Lead to Full User Dump",
        severity="high",
        category="auth",
        cwe="CWE-521",
        kill_chain=chain,
    )
    events = _events_for("kc-run", tmp_path)
    kc_events = [e for e in events if e["event_type"] == "finding.kill_chain"]
    assert len(kc_events) == 1
    payload = kc_events[0]["payload"]
    assert payload["report_id"] == report_id
    assert payload["step_count"] == 3
    assert payload["title"] == "Default Admin Credentials Lead to Full User Dump"
    assert payload["severity"] == "high"
    assert len(payload["chain"]) == 3
    assert payload["chain"][0]["type"] == "recon"


def test_finding_without_kill_chain_does_not_emit_event(tmp_path) -> None:
    """Single-step pattern-match findings don't get a kill_chain event."""
    t = Tracer("nochain-run")
    set_global_tracer(t)
    t.add_vulnerability_report(title="Some pattern hit", severity="info")
    events = _events_for("nochain-run", tmp_path)
    assert not [e for e in events if e["event_type"] == "finding.kill_chain"]


def test_finding_dict_persists_kill_chain(tmp_path) -> None:
    """The chain should also live on the report dict so the report markdown
    + vulnerabilities.json artifact carry it."""
    t = Tracer("persist-run")
    set_global_tracer(t)
    chain = [{"description": "Step A", "type": "recon"}]
    t.add_vulnerability_report(title="X", severity="medium", kill_chain=chain)
    assert "kill_chain" in t.vulnerability_reports[0]
    assert t.vulnerability_reports[0]["kill_chain"][0]["description"] == "Step A"


def test_kill_chain_event_after_finding_created(tmp_path) -> None:
    """Order matters: finding.created precedes finding.kill_chain so consumers
    reading in order see the finding before the chain context."""
    t = Tracer("order-run")
    set_global_tracer(t)
    chain = [{"description": "X"}]
    t.add_vulnerability_report(title="A", severity="high", kill_chain=chain)
    events = _events_for("order-run", tmp_path)
    types = [e["event_type"] for e in events]
    created_idx = types.index("finding.created")
    chain_idx = types.index("finding.kill_chain")
    assert created_idx < chain_idx


def test_invalid_chain_does_not_break_finding_creation() -> None:
    """A malformed kill_chain payload shouldn't take down report creation."""
    t = Tracer("err-run")
    set_global_tracer(t)
    report_id = t.add_vulnerability_report(
        title="X",
        severity="info",
        kill_chain="this is not a list",  # type: ignore[arg-type]
    )
    assert report_id  # report still created
    assert "kill_chain" not in t.vulnerability_reports[0]


def test_kill_chain_event_payload_includes_fingerprint(tmp_path) -> None:
    """report_id is the primary key; fingerprint lets triage layers join
    against §11 finding-fingerprint without re-resolving."""
    t = Tracer("fp-run")
    set_global_tracer(t)
    chain = [{"description": "X"}]
    t.add_vulnerability_report(
        title="X", severity="medium", endpoint="/api", cwe="CWE-89", kill_chain=chain
    )
    events = _events_for("fp-run", tmp_path)
    kc = next(e for e in events if e["event_type"] == "finding.kill_chain")
    assert kc["payload"]["fingerprint"]
    assert kc["payload"]["fingerprint"] == t.vulnerability_reports[0]["fingerprint"]


# ---------------------------------------------------------------------------
# XML parser at the agent boundary (parse_kill_chain_xml)
# ---------------------------------------------------------------------------


def test_parse_kill_chain_xml_full_shape() -> None:
    from strix.tools.reporting.reporting_actions import parse_kill_chain_xml

    xml = """<kill_chain>
      <step number="1" type="recon">
        <description>Found admin panel</description>
        <tool>http_request</tool>
        <evidence>HTTP 200 with login form</evidence>
      </step>
      <step number="2" type="exploitation">
        <description>Default credentials worked</description>
        <evidence>302 redirect with session cookie</evidence>
      </step>
    </kill_chain>"""
    parsed = parse_kill_chain_xml(xml)
    assert parsed is not None
    assert len(parsed) == 2
    assert parsed[0]["step_number"] == 1
    assert parsed[0]["type"] == "recon"
    assert parsed[0]["description"] == "Found admin panel"
    assert parsed[0]["tool"] == "http_request"
    assert parsed[1]["step_number"] == 2
    assert parsed[1]["type"] == "exploitation"


def test_parse_kill_chain_xml_handles_missing_attrs() -> None:
    from strix.tools.reporting.reporting_actions import parse_kill_chain_xml

    xml = """<kill_chain>
      <step><description>Step without attrs</description></step>
    </kill_chain>"""
    parsed = parse_kill_chain_xml(xml)
    assert parsed is not None
    # No number attr → tracer normalizer will assign a position; parser leaves it absent.
    assert "step_number" not in parsed[0]
    assert "type" not in parsed[0]
    assert parsed[0]["description"] == "Step without attrs"


def test_parse_kill_chain_xml_returns_none_for_empty() -> None:
    from strix.tools.reporting.reporting_actions import parse_kill_chain_xml

    assert parse_kill_chain_xml("") is None
    assert parse_kill_chain_xml("   ") is None
    assert parse_kill_chain_xml(None) is None  # type: ignore[arg-type]


def test_parse_kill_chain_xml_returns_none_for_no_steps() -> None:
    from strix.tools.reporting.reporting_actions import parse_kill_chain_xml

    assert parse_kill_chain_xml("<kill_chain></kill_chain>") is None


def test_parse_kill_chain_xml_pipes_through_to_finding(tmp_path) -> None:
    """Round-trip: agent passes XML, tool parses, tracer emits the event."""
    from strix.tools.reporting.reporting_actions import parse_kill_chain_xml

    xml = """<kill_chain>
      <step number="1" type="recon"><description>S1</description></step>
      <step number="2" type="impact"><description>S2</description></step>
    </kill_chain>"""
    parsed = parse_kill_chain_xml(xml)

    t = Tracer("rt-run")
    set_global_tracer(t)
    t.add_vulnerability_report(
        title="X", severity="high", category="auth", kill_chain=parsed
    )
    events = _events_for("rt-run", tmp_path)
    kc = next(e for e in events if e["event_type"] == "finding.kill_chain")
    assert kc["payload"]["step_count"] == 2
    assert kc["payload"]["chain"][0]["type"] == "recon"
    assert kc["payload"]["chain"][1]["type"] == "impact"
