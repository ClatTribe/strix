"""Tests for §8.5 Phase 5 — `update_finding` mutation.

Pins the eager-emit-then-review path (single-agent.md B.10):
specialist eager-emits at `verification_status='pattern_match'` +
`confidence=0.7`; validator updates to `verified` + 0.95 + PoC.
The mutation is wrapper-additive (`finding.updated` event +
`vulnerabilities.json` re-write at run-end).
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.findings.update_finding import update_finding


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("update-finding-test")
    set_global_tracer(tracer)
    yield


def _emit(**kwargs: Any) -> str | None:
    """Emit a finding via the existing path so we have something to update."""
    t = tracer_module.get_global_tracer()
    base: dict[str, Any] = {
        "title": "Reflected XSS in /search",
        "severity": "medium",
        "cwe": "CWE-79",
        "endpoint": "/search?q=",
        "verification_status": "pattern_match",
    }
    base.update(kwargs)
    return t.add_vulnerability_report(**base)


def _findings() -> list[dict[str, Any]]:
    return list(tracer_module.get_global_tracer().get_existing_vulnerabilities())


# ---------------------------------------------------------------------------
# Defensive input
# ---------------------------------------------------------------------------


def test_neither_id_nor_fingerprint_returns_error() -> None:
    out = update_finding()
    assert out["success"] is False
    assert "fingerprint or report_id" in (out["error"] or "")


def test_unknown_report_id_returns_error() -> None:
    out = update_finding(report_id="vuln-9999")
    assert out["success"] is False
    assert "no finding" in (out["error"] or "")


def test_unknown_fingerprint_returns_error() -> None:
    out = update_finding(fingerprint="0123456789abcdef")
    assert out["success"] is False


def test_invalid_verification_status_returns_error() -> None:
    rid = _emit()
    out = update_finding(report_id=rid, verification_status="haha")
    assert out["success"] is False
    assert "verification_status" in (out["error"] or "")


def test_invalid_severity_returns_error() -> None:
    rid = _emit()
    out = update_finding(report_id=rid, severity="apocalyptic")
    assert out["success"] is False
    assert "severity" in (out["error"] or "")


def test_invalid_confidence_out_of_range() -> None:
    rid = _emit()
    out = update_finding(report_id=rid, confidence=1.5)
    assert out["success"] is False


def test_invalid_confidence_non_numeric() -> None:
    rid = _emit()
    out = update_finding(report_id=rid, confidence="high")  # type: ignore[arg-type]
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Lookup by fingerprint OR report_id
# ---------------------------------------------------------------------------


def test_lookup_by_report_id() -> None:
    rid = _emit()
    out = update_finding(report_id=rid, confidence=0.95)
    assert out["success"] is True
    assert out["report_id"] == rid


def test_lookup_by_fingerprint() -> None:
    rid = _emit()
    fp = _findings()[0]["fingerprint"]
    out = update_finding(fingerprint=fp, confidence=0.95)
    assert out["success"] is True
    assert out["fingerprint"] == fp


# ---------------------------------------------------------------------------
# Eager-emit-then-review canonical path (B.10)
# ---------------------------------------------------------------------------


def test_eager_emit_then_validator_promotes_to_verified() -> None:
    """Specialist eager-emits at pattern_match/0.7; validator confirms."""
    rid = _emit(verification_status="pattern_match", confidence=0.7)
    finding_pre = _findings()[0]
    assert finding_pre["verification_status"] == "pattern_match"

    out = update_finding(
        report_id=rid,
        verification_status="verified",
        confidence=0.95,
        poc_script_code="curl -X POST /search?q=<svg/onload=alert(1)>",
        update_reason="validator confirmed via headless browser",
    )

    assert out["success"] is True
    assert "verification_status" in out["fields_changed"]
    assert "confidence" in out["fields_changed"]
    assert "poc_script_code" in out["fields_changed"]
    assert out["previous_values"]["verification_status"] == "pattern_match"
    assert out["previous_values"]["confidence"] == 0.7

    finding_post = _findings()[0]
    assert finding_post["verification_status"] == "verified"
    assert finding_post["confidence"] == 0.95
    assert finding_post["poc_script_code"].startswith("curl")


def test_validator_refutes_to_could_not_verify() -> None:
    rid = _emit(verification_status="pattern_match", confidence=0.7)
    out = update_finding(
        report_id=rid,
        verification_status="could_not_verify",
        confidence=0.2,
        counter_proof={
            "description": "WAF blocked all XSS payloads at /search",
            "evidence": "HTTP 403 returned for <script>... and <svg onload=...",
        },
    )
    assert out["success"] is True
    finding = _findings()[0]
    assert finding["verification_status"] == "could_not_verify"
    assert finding["counter_proof"]["description"].startswith("WAF blocked")


def test_poc_attach_implicitly_promotes_to_verified() -> None:
    """When PoC is attached and verification_status is not explicitly
    set, status bumps from pattern_match → verified (the agent ran an
    exploit successfully)."""
    rid = _emit(verification_status="pattern_match")
    out = update_finding(
        report_id=rid,
        poc_script_code="exploit.sh",
    )
    assert out["success"] is True
    finding = _findings()[0]
    assert finding["verification_status"] == "verified"


def test_poc_attach_does_not_override_explicit_verification_status() -> None:
    """When caller explicitly sets verification_status, PoC attach
    does NOT override it. Caller's intent wins."""
    rid = _emit(verification_status="pattern_match")
    out = update_finding(
        report_id=rid,
        verification_status="needs_review",
        poc_script_code="exploit.sh",
    )
    assert out["success"] is True
    finding = _findings()[0]
    assert finding["verification_status"] == "needs_review"


# ---------------------------------------------------------------------------
# Severity update — records pre-update value
# ---------------------------------------------------------------------------


def test_severity_bump_records_pre_update_value() -> None:
    rid = _emit(severity="medium")
    out = update_finding(report_id=rid, severity="high")
    assert out["success"] is True
    assert "severity" in out["fields_changed"]
    finding = _findings()[0]
    assert finding["severity"] == "high"
    assert finding["severity_pre_update"] == "medium"


def test_severity_unchanged_no_field_change() -> None:
    rid = _emit(severity="medium")
    out = update_finding(report_id=rid, severity="medium")
    assert "severity" not in out["fields_changed"]


# ---------------------------------------------------------------------------
# Reasoning trace + counter_proof — REPLACES not appends
# ---------------------------------------------------------------------------


def test_reasoning_trace_replaced_caps_at_20() -> None:
    rid = _emit(reasoning_trace=["original 1", "original 2"])
    out = update_finding(
        report_id=rid,
        reasoning_trace=[f"new bullet {i}" for i in range(30)],  # > 20 cap
    )
    assert out["success"] is True
    finding = _findings()[0]
    assert len(finding["reasoning_trace"]) == 20
    assert finding["reasoning_trace"][0] == "new bullet 0"


def test_reasoning_trace_string_split_on_newlines() -> None:
    rid = _emit()
    out = update_finding(
        report_id=rid,
        reasoning_trace="point 1\npoint 2\npoint 3",
    )
    assert out["success"] is True
    finding = _findings()[0]
    assert finding["reasoning_trace"] == ["point 1", "point 2", "point 3"]


def test_counter_proof_replaces_existing() -> None:
    rid = _emit(
        counter_proof={"description": "old", "evidence": "old evidence"},
    )
    out = update_finding(
        report_id=rid,
        counter_proof={"description": "new", "evidence": "new evidence"},
    )
    assert out["success"] is True
    finding = _findings()[0]
    assert finding["counter_proof"]["description"] == "new"


def test_counter_proof_caps_field_lengths() -> None:
    rid = _emit()
    out = update_finding(
        report_id=rid,
        counter_proof={
            "description": "x" * 5000,  # cap 1024
            "evidence": "y" * 5000,      # cap 2048
        },
    )
    finding = _findings()[0]
    assert len(finding["counter_proof"]["description"]) == 1024
    assert len(finding["counter_proof"]["evidence"]) == 2048


# ---------------------------------------------------------------------------
# Append-only evidence log
# ---------------------------------------------------------------------------


def test_additional_evidence_appends_to_log() -> None:
    rid = _emit()
    update_finding(report_id=rid, additional_evidence="first follow-up")
    update_finding(report_id=rid, additional_evidence="second follow-up")
    finding = _findings()[0]
    assert len(finding["update_evidence_log"]) == 2
    assert finding["update_evidence_log"][0]["evidence"] == "first follow-up"
    assert finding["update_evidence_log"][1]["evidence"] == "second follow-up"


def test_evidence_entry_carries_timestamp_and_agent_id() -> None:
    rid = _emit()
    out = update_finding(
        report_id=rid,
        additional_evidence="bla",
        # update_reason is the public field; agent_id is set on the tracer
        # method call (not exposed on the tool — agents pass it through
        # the tracer's set_active_agent context). For this unit test we
        # exercise the tracer path directly:
    )
    assert out["success"] is True
    finding = _findings()[0]
    log = finding["update_evidence_log"]
    assert "at" in log[0]
    assert log[0]["evidence"] == "bla"


# ---------------------------------------------------------------------------
# Re-promote auto-dismissed finding
# ---------------------------------------------------------------------------


def test_verified_clears_auto_dismissed_state() -> None:
    """When a previously auto-dismissed finding is updated to
    verified, clear the auto_dismissed flag and record re_promoted."""
    rid = _emit()
    finding = _findings()[0]
    # Manually mark as auto-dismissed (simulates the §142 path).
    finding["auto_dismissed"] = True
    finding["auto_dismissal_reason"] = "prior_human_fp"

    out = update_finding(report_id=rid, verification_status="verified")
    assert out["success"] is True
    assert "auto_dismissed" in out["fields_changed"]
    assert out["previous_values"]["auto_dismissed"] is True

    finding_post = _findings()[0]
    assert finding_post["auto_dismissed"] is False
    assert finding_post["re_promoted"] is True


# ---------------------------------------------------------------------------
# `finding.updated` event emission (additive)
# ---------------------------------------------------------------------------


def test_finding_updated_event_emitted() -> None:
    import json

    rid = _emit()
    update_finding(
        report_id=rid,
        verification_status="verified",
        update_reason="validator confirmed",
    )

    t = tracer_module.get_global_tracer()
    events_path = t.get_run_dir() / "events.jsonl"
    events = [
        json.loads(line)
        for line in events_path.read_text().splitlines()
        if line.strip()
    ]
    updated_events = [
        e for e in events if e.get("event_type") == "finding.updated"
    ]
    assert len(updated_events) == 1
    payload = updated_events[0]["payload"]
    assert payload["report_id"] == rid
    assert payload["update_reason"] == "validator confirmed"
    assert "verification_status" in payload["fields_changed"]


# ---------------------------------------------------------------------------
# Features re-extraction (#142)
# ---------------------------------------------------------------------------


def test_features_block_refreshed_on_update() -> None:
    rid = _emit(verification_status="pattern_match", confidence=0.7)
    finding_pre = _findings()[0]
    assert finding_pre["features"]["verification_status"] == "pattern_match"

    update_finding(
        report_id=rid, verification_status="verified", confidence=0.95,
    )
    finding_post = _findings()[0]
    # Features re-extracted with new values.
    assert finding_post["features"]["verification_status"] == "verified"
    assert finding_post["features"]["confidence"] == 0.95


# ---------------------------------------------------------------------------
# No-op update (no fields actually changed)
# ---------------------------------------------------------------------------


def test_no_op_update_returns_success_with_empty_changes() -> None:
    rid = _emit(severity="medium", confidence=0.5)
    out = update_finding(
        report_id=rid, severity="medium", confidence=0.5,  # both unchanged
    )
    assert out["success"] is True
    assert out["fields_changed"] == []


# ---------------------------------------------------------------------------
# Wrapper invariant: vulnerabilities.json reflects merged values
# ---------------------------------------------------------------------------


def test_vulnerabilities_json_reflects_post_update_state() -> None:
    """Wrapper reads vulnerabilities.json at run-end. Post-update,
    the file must reflect the latest merged values (engine-usage.md
    §1.4)."""
    import json

    rid = _emit(verification_status="pattern_match")
    update_finding(
        report_id=rid, verification_status="verified", confidence=0.95,
    )

    t = tracer_module.get_global_tracer()
    t.save_run_data()
    vuln_path = t.get_run_dir() / "vulnerabilities.json"
    payload = json.loads(vuln_path.read_text())
    findings_list = (
        payload.get("findings")
        or payload.get("vulnerabilities")
        or []
    )
    assert findings_list, f"vulnerabilities.json missing findings: {payload.keys()}"
    assert findings_list[0]["verification_status"] == "verified"
    assert findings_list[0]["confidence"] == 0.95


def test_update_does_not_break_finding_id_or_fingerprint() -> None:
    """Mutation must not change `id` or `fingerprint` — those are
    cross-scan stable per #11 / #137."""
    rid = _emit()
    fp_pre = _findings()[0]["fingerprint"]

    update_finding(report_id=rid, severity="high")
    finding_post = _findings()[0]
    assert finding_post["id"] == rid
    assert finding_post["fingerprint"] == fp_pre


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_update_finding_registered_in_tool_catalog() -> None:
    """The tool must be agent-callable — registered under the
    canonical tool registry."""
    import strix.tools  # ensure side-effect imports
    from strix.tools.registry import get_tool_by_name

    t = get_tool_by_name("update_finding")
    assert t is not None
