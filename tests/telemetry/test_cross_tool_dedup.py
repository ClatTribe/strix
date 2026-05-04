"""Tests for cross-tool finding deduplication (roadmap §9 / rule-3).

When two tools (or the same tool re-running) emit findings sharing
the same `fingerprint`, the tracer merges them into ONE record with
an accumulated `detected_by` list. Multi-detector agreement is a
zero-false-positive confidence signal the wrapper renders as a
"high confidence" badge.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
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


def _emit(tracer: Tracer, **overrides: Any) -> str:
    base = {
        "title": "SQLi in /api/users",
        "severity": "high",
        "category": "sql_injection",
        "endpoint": "https://app.example.com/api/users",
        "verification_status": "needs_review",
        "description_plain": "p",
        "recommended_action": "a",
        "cwe": "CWE-89",
    }
    base.update(overrides)
    return tracer.add_vulnerability_report(**base)


def _events(tracer: Tracer) -> list[dict[str, Any]]:
    events_file = tracer.get_run_dir() / "events.jsonl"
    if not events_file.exists():
        return []
    return [
        json.loads(l) for l in events_file.read_text().splitlines() if l.strip()
    ]


# ---------------------------------------------------------------------------
# Basic dedup
# ---------------------------------------------------------------------------


def test_two_findings_same_fingerprint_merge() -> None:
    tracer = Tracer("dedup-1")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    rid_a = _emit(tracer, title="SQLi in /api/users")
    rid_b = _emit(tracer, title="SQLi in /api/users")

    assert rid_a == rid_b  # second call returned the existing id
    findings = tracer.get_existing_vulnerabilities()
    assert len(findings) == 1


def test_two_findings_different_fingerprint_dont_merge() -> None:
    tracer = Tracer("dedup-2")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    _emit(tracer, title="SQLi in /api/users", endpoint="https://x/a")
    _emit(tracer, title="SQLi in /api/users", endpoint="https://x/b")  # different endpoint

    findings = tracer.get_existing_vulnerabilities()
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# detected_by accumulator
# ---------------------------------------------------------------------------


def test_detected_by_accumulates_from_category() -> None:
    """When new findings don't carry explicit detected_by, the
    category becomes the detector name."""
    tracer = Tracer("dedup-by-cat")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    _emit(tracer, category="sql_injection")
    _emit(tracer, category="sql_injection")  # same fingerprint

    findings = tracer.get_existing_vulnerabilities()
    assert len(findings) == 1
    # Both contributors registered.
    assert findings[0]["detected_by"] == ["sql_injection"]
    assert findings[0]["detection_count"] == 1


def test_detected_by_explicit_list() -> None:
    """When findings carry explicit detected_by, both contributors
    are tracked."""
    tracer = Tracer("dedup-explicit")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    # First finding carries explicit detector.
    rid_a = tracer.add_vulnerability_report(
        title="SQLi", severity="high", category="sql_injection",
        endpoint="https://x", verification_status="pattern_match",
        description_plain="p", recommended_action="a", cwe="CWE-89",
    )
    # Manually set detected_by on the existing record (simulating a
    # tool that emits its detector identity).
    findings = tracer.get_existing_vulnerabilities()
    findings[0]["detected_by"] = ["semgrep"]

    # Second emission with same fingerprint.
    tracer.add_vulnerability_report(
        title="SQLi", severity="high", category="sql_injection",
        endpoint="https://x", verification_status="pattern_match",
        description_plain="p", recommended_action="a", cwe="CWE-89",
    )

    findings = tracer.get_existing_vulnerabilities()
    assert len(findings) == 1
    # 'semgrep' (existing) + 'sql_injection' (from category) merged.
    assert "semgrep" in findings[0]["detected_by"]
    assert "sql_injection" in findings[0]["detected_by"]
    assert findings[0]["detection_count"] == 2


def test_detected_by_dedup_within_list() -> None:
    """The same detector firing twice doesn't double-count."""
    tracer = Tracer("dedup-self")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    _emit(tracer, category="sql_injection")
    _emit(tracer, category="sql_injection")
    _emit(tracer, category="sql_injection")

    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["detected_by"] == ["sql_injection"]
    assert findings[0]["detection_count"] == 1


# ---------------------------------------------------------------------------
# Severity ladder on merge
# ---------------------------------------------------------------------------


def test_severity_promoted_on_merge() -> None:
    """When a higher-severity tool agrees, the merged finding takes
    the higher severity."""
    tracer = Tracer("dedup-sev")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    _emit(tracer, severity="medium")
    _emit(tracer, severity="critical")

    findings = tracer.get_existing_vulnerabilities()
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["severity_promoted_from"] == "medium"


def test_severity_not_demoted_on_merge() -> None:
    """A lower-severity follow-up doesn't downgrade."""
    tracer = Tracer("dedup-sev-down")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    _emit(tracer, severity="critical")
    _emit(tracer, severity="low")

    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def test_dedup_merges_audit_log() -> None:
    """Each merge appends to dedup_merges[] for audit."""
    tracer = Tracer("dedup-audit")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    _emit(tracer, title="SQLi", severity="medium")
    _emit(tracer, title="SQLi", severity="high")
    _emit(tracer, title="SQLi", severity="critical")

    findings = tracer.get_existing_vulnerabilities()
    merges = findings[0].get("dedup_merges") or []
    assert len(merges) == 2
    assert all("merged_at" in m for m in merges)


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------


def test_corroboration_event_emitted_on_merge(tmp_path) -> None:
    tracer = Tracer("dedup-event")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    _emit(tracer)
    _emit(tracer)

    events = _events(tracer)
    corr = [
        e for e in events
        if (e.get("event_type") or e.get("event")) == "finding.detection_corroborated"
    ]
    assert len(corr) == 1
    payload = corr[0].get("payload") or {}
    assert payload.get("detection_count") == 1
    assert "fingerprint" in payload


def test_no_corroboration_event_on_first_finding(tmp_path) -> None:
    tracer = Tracer("dedup-first")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    _emit(tracer)

    events = _events(tracer)
    corr = [
        e for e in events
        if (e.get("event_type") or e.get("event")) == "finding.detection_corroborated"
    ]
    assert corr == []


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_finding_without_fingerprint_no_merge() -> None:
    """If for some reason fingerprint computation fails, the new
    finding is appended (no false-merge)."""
    tracer = Tracer("dedup-no-fp")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    rid_a = _emit(tracer)
    # Manually clear the existing finding's fingerprint to simulate
    # the missing-fingerprint case.
    findings = tracer.get_existing_vulnerabilities()
    findings[0].pop("fingerprint", None)
    rid_b = _emit(tracer)

    # Two separate ids — no merge happened on the fingerprint-less one.
    findings = tracer.get_existing_vulnerabilities()
    # The first record has no fingerprint, the second one has one,
    # so they don't match. We end up with 2.
    assert len(findings) == 2


def test_merge_returns_existing_id() -> None:
    """add_vulnerability_report returns the existing finding's id
    on merge, so callers that record the id continue to point at
    the right record."""
    tracer = Tracer("dedup-id")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    rid_a = _emit(tracer, title="SQLi in /api")
    rid_b = _emit(tracer, title="SQLi in /api")
    rid_c = _emit(tracer, title="SQLi in /api")

    assert rid_a == rid_b == rid_c
    assert len(tracer.get_existing_vulnerabilities()) == 1


# ---------------------------------------------------------------------------
# Real-world: SAST + dynamic agree on same SQLi
# ---------------------------------------------------------------------------


def test_sast_plus_dynamic_corroboration_high_confidence() -> None:
    """The canonical wrapper-facing case: a SAST tool (semgrep
    pattern) and a dynamic prober (sqli-specialist) BOTH find the
    same SQLi — the wrapper sees `detection_count=2` and renders
    a high-confidence badge."""
    tracer = Tracer("dedup-corroborate")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "x"}]})

    # SAST pass — emit with detected_by=semgrep on a placeholder
    # field; we'll set it manually since the canonical
    # add_vulnerability_report doesn't carry detected_by yet.
    rid_a = _emit(tracer, category="sql_injection", title="SQLi /api/users")
    findings = tracer.get_existing_vulnerabilities()
    findings[0]["detected_by"] = ["semgrep"]

    # Dynamic pass — same finding. Default detected_by ←
    # category="sql_injection".
    rid_b = _emit(tracer, category="sql_injection", title="SQLi /api/users")

    findings = tracer.get_existing_vulnerabilities()
    assert len(findings) == 1
    assert findings[0]["detection_count"] == 2
    assert {"semgrep", "sql_injection"} <= set(findings[0]["detected_by"])
