"""Tests for dismiss_finding (roadmap §12 / PR #118).

Hermetic — uses a real Tracer in tmp_path; verifies the
finding.dismissed event lands with the documented schema.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


import strix.tools.finding_dismissed.finding_dismissed  # noqa: F401

fd_module = sys.modules["strix.tools.finding_dismissed.finding_dismissed"]
dismiss_finding = fd_module.dismiss_finding


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
    tracer = Tracer("dismiss-test")
    set_global_tracer(tracer)
    yield


def _load_events(tmp_path) -> list[dict[str, Any]]:
    p = tmp_path / "strix_runs" / "dismiss-test" / "events.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_emits_finding_dismissed_event(tmp_path) -> None:
    out = dismiss_finding(
        surface="/api/users/123 ?name= parameter",
        hypothesis="reflected XSS via name parameter",
        evidence="Response HTML-encodes < as &lt; and \" as &quot;",
        dismissal_reason="input_properly_encoded",
    )

    assert out["success"] is True
    assert out["dismissal_reason"] == "input_properly_encoded"
    assert "/api/users" in out["surface"]

    events = _load_events(tmp_path)
    dismissed = [e for e in events if e.get("event_type") == "finding.dismissed"]
    assert len(dismissed) == 1
    payload = dismissed[0]["payload"]
    assert payload["surface"].startswith("/api/users")
    assert "reflected XSS" in payload["hypothesis"]
    assert "HTML-encodes" in payload["evidence"]
    assert payload["dismissal_reason"] == "input_properly_encoded"


def test_optional_severity_and_cwe_carried(tmp_path) -> None:
    dismiss_finding(
        surface="POST /password-reset",
        hypothesis="missing CSRF on POST",
        evidence="Returns 403 without X-CSRF-Token",
        dismissal_reason="csrf_token_validated",
        candidate_severity="high",
        cwe="CWE-352",
    )

    events = _load_events(tmp_path)
    dismissed = [e for e in events if e.get("event_type") == "finding.dismissed"]
    assert len(dismissed) == 1
    payload = dismissed[0]["payload"]
    assert payload["candidate_severity"] == "high"
    assert payload["cwe"] == "CWE-352"


# ---------------------------------------------------------------------------
# Validation — required fields
# ---------------------------------------------------------------------------


def test_empty_surface_rejected() -> None:
    out = dismiss_finding(
        surface="",
        hypothesis="something",
        evidence="something",
        dismissal_reason="other",
    )
    assert out["success"] is False
    assert "surface" in out["message"]


def test_empty_hypothesis_rejected() -> None:
    out = dismiss_finding(
        surface="x",
        hypothesis="",
        evidence="something",
        dismissal_reason="other",
    )
    assert out["success"] is False
    assert "hypothesis" in out["message"]


def test_empty_evidence_rejected() -> None:
    out = dismiss_finding(
        surface="x",
        hypothesis="x",
        evidence="",
        dismissal_reason="other",
    )
    assert out["success"] is False
    assert "evidence" in out["message"]


# ---------------------------------------------------------------------------
# Validation — closed enums
# ---------------------------------------------------------------------------


def test_invalid_dismissal_reason_rejected() -> None:
    out = dismiss_finding(
        surface="x",
        hypothesis="x",
        evidence="x",
        dismissal_reason="not-a-real-reason",
    )
    assert out["success"] is False
    assert "dismissal_reason" in out["message"]


@pytest.mark.parametrize("reason", [
    "input_properly_encoded",
    "framework_default_blocked",
    "csrf_token_validated",
    "auth_enforced",
    "not_reflected",
    "different_origin",
    "out_of_scope",
    "false_positive_signature",
    "compensating_control",
    "intended_behavior",
    "test_fixture",
    "deprecated_path",
    "other",
])
def test_each_canonical_reason_accepted(tmp_path, reason: str) -> None:
    out = dismiss_finding(
        surface="x",
        hypothesis="x",
        evidence="x",
        dismissal_reason=reason,
    )
    assert out["success"] is True


def test_invalid_severity_rejected() -> None:
    out = dismiss_finding(
        surface="x",
        hypothesis="x",
        evidence="x",
        dismissal_reason="other",
        candidate_severity="extreme",  # not canonical
    )
    assert out["success"] is False
    assert "candidate_severity" in out["message"]


def test_severity_normalised_to_lowercase(tmp_path) -> None:
    """Per #106, machine-readable severity is canonical lowercase."""
    out = dismiss_finding(
        surface="x",
        hypothesis="x",
        evidence="x",
        dismissal_reason="other",
        candidate_severity="HIGH",  # uppercase input
    )
    assert out["success"] is True

    events = _load_events(tmp_path)
    dismissed = [e for e in events if e.get("event_type") == "finding.dismissed"]
    assert len(dismissed) == 1
    assert dismissed[0]["payload"]["candidate_severity"] == "high"  # normalised


# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------


def test_oversized_fields_truncated(tmp_path) -> None:
    """Surface / hypothesis capped at 512; evidence at 2048."""
    big = "X" * 5000
    out = dismiss_finding(
        surface=big,
        hypothesis=big,
        evidence=big,
        dismissal_reason="other",
    )
    assert out["success"] is True

    events = _load_events(tmp_path)
    dismissed = [e for e in events if e.get("event_type") == "finding.dismissed"]
    assert len(dismissed) == 1
    payload = dismissed[0]["payload"]
    assert len(payload["surface"]) <= 512
    assert len(payload["hypothesis"]) <= 512
    assert len(payload["evidence"]) <= 2048


# ---------------------------------------------------------------------------
# No-tracer fallback
# ---------------------------------------------------------------------------


def test_tracer_missing_returns_success_with_message(monkeypatch) -> None:
    """When no tracer is set, we still return success but the
    message indicates the local-only state."""
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    # Override any global tracer.
    monkeypatch.setattr(tracer_module, "get_global_tracer", lambda: None)

    out = dismiss_finding(
        surface="x",
        hypothesis="x",
        evidence="x",
        dismissal_reason="other",
    )
    assert out["success"] is True
    assert "tracer unavailable" in out["message"].lower() or "emitted" in out["message"].lower()


# ---------------------------------------------------------------------------
# Tool registration sanity
# ---------------------------------------------------------------------------


def test_tool_registered() -> None:
    from strix.tools.registry import get_tool_by_name
    fn = get_tool_by_name("dismiss_finding")
    assert fn is not None
