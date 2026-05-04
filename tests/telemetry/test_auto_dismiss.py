"""Tests for RLHF Phase 1 / A4 — auto-dismiss on prior-FP fingerprint.

Pins the tracer integration: when the wrapper has previously
labeled a finding's fingerprint as FP, the next scan auto-dismisses
rather than re-presenting the same finding for re-triage.

The mutation contract is:
  * `auto_dismissed = True`
  * `auto_dismissal_reason = "prior_human_fp"`
  * `severity_pre_auto_dismissal = <original severity>`
  * `verification_status = "could_not_verify"`
  * `prior_label_attribution` recorded (notes stripped)
  * `finding.auto_dismissed` event emitted
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import (
    Tracer,
    compute_finding_fingerprint,
    set_global_tracer,
)


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
    monkeypatch.delenv("STRIX_FEEDBACK_FROM", raising=False)
    monkeypatch.delenv("STRIX_FP_AUTO_DISMISS", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    # Divert ~/.strix lookup so the home-fallback path can't pick up
    # a real cumulative feedback file from the dev's machine.
    monkeypatch.setenv("HOME", str(tmp_path))
    tracer = Tracer("auto-dismiss-test")
    set_global_tracer(tracer)
    yield


def _findings() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


def _emit(**kwargs: Any) -> str | None:
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


def _expected_fingerprint(title: str, cwe: str, endpoint: str) -> str:
    return compute_finding_fingerprint(title=title, cwe=cwe, endpoint=endpoint)


def _write_feedback(
    run_dir: Path,
    fingerprint: str,
    *,
    verdict: str = "fp",
    fp_reason: str | None = "framework_default_blocked",
    notes: str | None = None,
    labeled_at: str = "2026-01-01T00:00:00Z",
) -> Path:
    feedback_path = run_dir / "feedback.jsonl"
    rec: dict[str, Any] = {
        "schema_version": 1,
        "finding_fingerprint": fingerprint,
        "verdict": verdict,
        "labeled_at": labeled_at,
    }
    if fp_reason is not None:
        rec["fp_reason"] = fp_reason
    if notes is not None:
        rec["notes"] = notes
    with feedback_path.open("a") as f:
        f.write(json.dumps(rec) + "\n")
    return feedback_path


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_auto_dismiss_triggers_on_prior_fp() -> None:
    t = tracer_module.get_global_tracer()
    fp = _expected_fingerprint("Reflected XSS in /search", "CWE-79", "/search?q=")
    _write_feedback(t.get_run_dir(), fp)

    _emit()
    finding = _findings()[0]

    assert finding["auto_dismissed"] is True
    assert finding["auto_dismissal_reason"] == "prior_human_fp"
    assert finding["severity_pre_auto_dismissal"] == "medium"
    assert finding["verification_status"] == "could_not_verify"


def test_auto_dismiss_records_prior_label_attribution() -> None:
    t = tracer_module.get_global_tracer()
    fp = _expected_fingerprint("Reflected XSS in /search", "CWE-79", "/search?q=")
    _write_feedback(t.get_run_dir(), fp)

    _emit()
    finding = _findings()[0]

    attribution = finding["prior_label_attribution"]
    assert attribution["verdict"] == "fp"
    assert attribution["fp_reason"] == "framework_default_blocked"
    assert attribution["labeled_at"] == "2026-01-01T00:00:00Z"


def test_auto_dismiss_strips_notes_from_attribution() -> None:
    """`notes` may carry sensitive operator commentary — must be
    stripped before attaching attribution to the finding artifact."""
    t = tracer_module.get_global_tracer()
    fp = _expected_fingerprint("Reflected XSS in /search", "CWE-79", "/search?q=")
    _write_feedback(
        t.get_run_dir(), fp,
        notes="confidential triage note — internal customer name",
    )

    _emit()
    attribution = _findings()[0]["prior_label_attribution"]
    assert "notes" not in attribution


def test_auto_dismiss_emits_event() -> None:
    t = tracer_module.get_global_tracer()
    fp = _expected_fingerprint("Reflected XSS in /search", "CWE-79", "/search?q=")
    _write_feedback(t.get_run_dir(), fp)

    _emit()

    events_path = t.get_run_dir() / "events.jsonl"
    events = [
        json.loads(line)
        for line in events_path.read_text().splitlines()
        if line.strip()
    ]
    auto_events = [
        e for e in events if e.get("event_type") == "finding.auto_dismissed"
    ]
    assert len(auto_events) == 1
    payload = auto_events[0]["payload"]
    assert payload["fingerprint"] == fp
    assert payload["auto_dismissal_reason"] == "prior_human_fp"


# ---------------------------------------------------------------------------
# Negative paths — when auto-dismiss must NOT trigger
# ---------------------------------------------------------------------------


def test_no_feedback_file_no_auto_dismiss() -> None:
    """No feedback at all → no `auto_dismissed` field on finding."""
    _emit()
    finding = _findings()[0]
    assert finding.get("auto_dismissed") is None or finding["auto_dismissed"] is False


def test_unrelated_fingerprint_does_not_trigger() -> None:
    t = tracer_module.get_global_tracer()
    _write_feedback(t.get_run_dir(), "some-other-fingerprint")

    _emit()
    finding = _findings()[0]
    # The finding's fingerprint doesn't match → no auto-dismissal.
    assert finding.get("auto_dismissed") is None or finding["auto_dismissed"] is False


def test_mixed_history_does_not_auto_dismiss_under_conservative() -> None:
    """Conservative policy refuses to dismiss when both TP and FP
    exist in history — labeler disagrees with themselves."""
    t = tracer_module.get_global_tracer()
    fp = _expected_fingerprint("Reflected XSS in /search", "CWE-79", "/search?q=")
    _write_feedback(t.get_run_dir(), fp, verdict="fp")
    _write_feedback(t.get_run_dir(), fp, verdict="tp", fp_reason=None,
                    labeled_at="2026-01-02T00:00:00Z")

    _emit()
    finding = _findings()[0]
    assert finding.get("auto_dismissed") is None or finding["auto_dismissed"] is False


def test_off_policy_disables_auto_dismiss(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_FP_AUTO_DISMISS", "off")
    t = tracer_module.get_global_tracer()
    fp = _expected_fingerprint("Reflected XSS in /search", "CWE-79", "/search?q=")
    _write_feedback(t.get_run_dir(), fp)

    _emit()
    finding = _findings()[0]
    assert finding.get("auto_dismissed") is None or finding["auto_dismissed"] is False


def test_aggressive_policy_dismisses_with_latest_fp(monkeypatch) -> None:
    """Aggressive: latest FP wins regardless of prior TPs."""
    monkeypatch.setenv("STRIX_FP_AUTO_DISMISS", "aggressive")
    t = tracer_module.get_global_tracer()
    fp = _expected_fingerprint("Reflected XSS in /search", "CWE-79", "/search?q=")
    _write_feedback(t.get_run_dir(), fp, verdict="tp", fp_reason=None,
                    labeled_at="2026-01-01T00:00:00Z")
    _write_feedback(t.get_run_dir(), fp, verdict="fp",
                    labeled_at="2026-01-02T00:00:00Z")

    _emit()
    finding = _findings()[0]
    assert finding["auto_dismissed"] is True


# ---------------------------------------------------------------------------
# Features extraction always runs alongside auto-dismiss
# ---------------------------------------------------------------------------


def test_features_block_attached_regardless_of_dismissal() -> None:
    """Features extraction (A2) runs unconditionally; auto-dismissed
    findings still carry features so the FP classifier can train on them."""
    t = tracer_module.get_global_tracer()
    fp = _expected_fingerprint("Reflected XSS in /search", "CWE-79", "/search?q=")
    _write_feedback(t.get_run_dir(), fp)

    _emit()
    finding = _findings()[0]
    assert "features" in finding
    assert finding["features"]["schema_version"] == 1


def test_features_block_attached_when_no_feedback() -> None:
    _emit()
    finding = _findings()[0]
    assert "features" in finding
    assert finding["features"]["category"] == "xss"  # CWE-79 → xss
    assert finding["features"]["severity"] == "medium"
    assert finding["features"]["severity_ordinal"] == 3
