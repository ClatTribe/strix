"""Tests for active-hypothesis shared state (roadmap §17.6 / §18 row 9)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.agents import active_hypotheses
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
    tracer = Tracer("hypotheses-test")
    set_global_tracer(tracer)
    active_hypotheses.reset_for_testing()
    yield


def _events(tmp_path) -> list[dict[str, Any]]:
    p = tmp_path / "strix_runs" / "hypotheses-test" / "events.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


def _artifact(tmp_path):
    return tmp_path / "strix_runs" / "hypotheses-test" / "active_hypotheses.jsonl"


# ---------------------------------------------------------------------------
# open_hypothesis
# ---------------------------------------------------------------------------


def test_open_hypothesis_returns_id(tmp_path) -> None:
    out = active_hypotheses.open_hypothesis(
        hypothesis="POST /password-reset is vulnerable to host-header poisoning",
        surface="POST /password-reset",
        agent_id="agent-001",
        agent_category="auth-attacker",
        category="host_header_injection",
    )
    assert out["success"] is True
    assert out["hypothesis_id"].startswith("hyp_")
    assert len(out["hypothesis_id"]) >= 12
    assert out["status"] == "investigating"


def test_open_hypothesis_writes_artifact(tmp_path) -> None:
    active_hypotheses.open_hypothesis(
        hypothesis="hypothesis text", surface="/x"
    )
    path = _artifact(tmp_path)
    assert path.exists()
    lines = path.read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["status"] == "investigating"
    assert rec["surface"] == "/x"


def test_open_hypothesis_emits_event(tmp_path) -> None:
    active_hypotheses.open_hypothesis(
        hypothesis="h", surface="/x", agent_id="a-1", category="xss"
    )
    events = _events(tmp_path)
    opened = [e for e in events if e.get("event_type") == "hypothesis.opened"]
    assert len(opened) == 1
    assert opened[0]["payload"]["surface"] == "/x"
    assert opened[0]["payload"]["category"] == "xss"


def test_open_rejects_empty_hypothesis() -> None:
    out = active_hypotheses.open_hypothesis(hypothesis="", surface="/x")
    assert out["success"] is False
    assert "hypothesis" in out["message"]


def test_open_rejects_empty_surface() -> None:
    out = active_hypotheses.open_hypothesis(hypothesis="h", surface="")
    assert out["success"] is False
    assert "surface" in out["message"]


def test_open_caps_long_text() -> None:
    out = active_hypotheses.open_hypothesis(
        hypothesis="X" * 5000, surface="Y" * 5000
    )
    assert len(out["hypothesis"]) <= 1024
    assert len(out["surface"]) <= 512


# ---------------------------------------------------------------------------
# confirm_hypothesis
# ---------------------------------------------------------------------------


def test_confirm_hypothesis_writes_state_change(tmp_path) -> None:
    opened = active_hypotheses.open_hypothesis(
        hypothesis="h", surface="/x"
    )
    confirmed = active_hypotheses.confirm_hypothesis(
        hypothesis_id=opened["hypothesis_id"],
        resolution="Confirmed via PoC",
        linked_finding_id="vuln-001",
    )
    assert confirmed["success"] is True
    assert confirmed["status"] == "confirmed"

    # Two lines in the artifact: open, confirm.
    path = _artifact(tmp_path)
    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["linked_finding_id"] == "vuln-001"


def test_confirm_emits_event(tmp_path) -> None:
    opened = active_hypotheses.open_hypothesis(hypothesis="h", surface="/x")
    active_hypotheses.confirm_hypothesis(hypothesis_id=opened["hypothesis_id"])

    events = _events(tmp_path)
    confirmed = [e for e in events if e.get("event_type") == "hypothesis.confirmed"]
    assert len(confirmed) == 1


def test_confirm_rejects_empty_id() -> None:
    out = active_hypotheses.confirm_hypothesis(hypothesis_id="")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# dismiss_hypothesis
# ---------------------------------------------------------------------------


def test_dismiss_hypothesis_with_canonical_reason(tmp_path) -> None:
    opened = active_hypotheses.open_hypothesis(hypothesis="h", surface="/x")
    out = active_hypotheses.dismiss_hypothesis(
        hypothesis_id=opened["hypothesis_id"],
        dismissal_reason="framework_default_blocked",
        resolution="Django CSRF middleware enforces token validation",
    )
    assert out["success"] is True
    assert out["status"] == "dismissed"
    assert out["dismissal_reason"] == "framework_default_blocked"


def test_dismiss_rejects_unknown_reason() -> None:
    opened = active_hypotheses.open_hypothesis(hypothesis="h", surface="/x")
    out = active_hypotheses.dismiss_hypothesis(
        hypothesis_id=opened["hypothesis_id"],
        dismissal_reason="not-a-real-reason",
    )
    assert out["success"] is False
    assert "dismissal_reason" in out["message"]


@pytest.mark.parametrize(
    "reason",
    [
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
    ],
)
def test_dismiss_each_canonical_reason_accepted(reason: str) -> None:
    opened = active_hypotheses.open_hypothesis(hypothesis="h", surface="/x")
    out = active_hypotheses.dismiss_hypothesis(
        hypothesis_id=opened["hypothesis_id"], dismissal_reason=reason
    )
    assert out["success"] is True


def test_dismiss_emits_event(tmp_path) -> None:
    opened = active_hypotheses.open_hypothesis(hypothesis="h", surface="/x")
    active_hypotheses.dismiss_hypothesis(
        hypothesis_id=opened["hypothesis_id"],
        dismissal_reason="other",
    )
    events = _events(tmp_path)
    dismissed = [e for e in events if e.get("event_type") == "hypothesis.dismissed"]
    assert len(dismissed) == 1


# ---------------------------------------------------------------------------
# list_active_hypotheses (read API)
# ---------------------------------------------------------------------------


def test_list_returns_all_when_no_filter() -> None:
    active_hypotheses.open_hypothesis(hypothesis="h1", surface="/a")
    active_hypotheses.open_hypothesis(hypothesis="h2", surface="/b")
    out = active_hypotheses.list_active_hypotheses()
    assert len(out) == 2


def test_list_orders_by_opened_at() -> None:
    """Latest-line wins on merge but ordering is by opened_at."""
    h1 = active_hypotheses.open_hypothesis(hypothesis="first", surface="/a")
    h2 = active_hypotheses.open_hypothesis(hypothesis="second", surface="/b")
    out = active_hypotheses.list_active_hypotheses()
    assert out[0]["hypothesis_id"] == h1["hypothesis_id"]
    assert out[1]["hypothesis_id"] == h2["hypothesis_id"]


def test_list_filter_by_status() -> None:
    h1 = active_hypotheses.open_hypothesis(hypothesis="open", surface="/a")
    h2 = active_hypotheses.open_hypothesis(hypothesis="confirmed", surface="/b")
    h3 = active_hypotheses.open_hypothesis(hypothesis="dismissed", surface="/c")

    active_hypotheses.confirm_hypothesis(hypothesis_id=h2["hypothesis_id"])
    active_hypotheses.dismiss_hypothesis(
        hypothesis_id=h3["hypothesis_id"], dismissal_reason="other"
    )

    investigating = active_hypotheses.list_active_hypotheses(only_status="investigating")
    confirmed = active_hypotheses.list_active_hypotheses(only_status="confirmed")
    dismissed = active_hypotheses.list_active_hypotheses(only_status="dismissed")

    assert {r["hypothesis_id"] for r in investigating} == {h1["hypothesis_id"]}
    assert {r["hypothesis_id"] for r in confirmed} == {h2["hypothesis_id"]}
    assert {r["hypothesis_id"] for r in dismissed} == {h3["hypothesis_id"]}


def test_list_filter_by_surface() -> None:
    active_hypotheses.open_hypothesis(hypothesis="a", surface="POST /login")
    active_hypotheses.open_hypothesis(hypothesis="b", surface="GET /search")

    out = active_hypotheses.list_active_hypotheses(surface="login")
    assert len(out) == 1
    assert "login" in out[0]["surface"].lower()


def test_list_filter_by_category() -> None:
    active_hypotheses.open_hypothesis(hypothesis="a", surface="/a", category="xss")
    active_hypotheses.open_hypothesis(hypothesis="b", surface="/b", category="ssrf")

    out = active_hypotheses.list_active_hypotheses(category="xss")
    assert len(out) == 1
    assert out[0]["category"] == "xss"


def test_list_unknown_status_returns_empty() -> None:
    active_hypotheses.open_hypothesis(hypothesis="h", surface="/x")
    out = active_hypotheses.list_active_hypotheses(only_status="bogus")
    assert out == []


def test_list_handles_empty_artifact() -> None:
    out = active_hypotheses.list_active_hypotheses()
    assert out == []


def test_list_skips_malformed_lines(tmp_path) -> None:
    """Garbage lines in the artifact don't break read."""
    h = active_hypotheses.open_hypothesis(hypothesis="h", surface="/x")
    path = _artifact(tmp_path)
    with path.open("a", encoding="utf-8") as f:
        f.write("not-json\n")
    out = active_hypotheses.list_active_hypotheses()
    assert len(out) == 1
    assert out[0]["hypothesis_id"] == h["hypothesis_id"]


# ---------------------------------------------------------------------------
# is_surface_under_investigation (sister-specialist guard)
# ---------------------------------------------------------------------------


def test_is_under_investigation_true_for_open_hypothesis() -> None:
    active_hypotheses.open_hypothesis(hypothesis="h", surface="POST /login")
    assert active_hypotheses.is_surface_under_investigation("/login") is True
    assert active_hypotheses.is_surface_under_investigation("login") is True
    assert active_hypotheses.is_surface_under_investigation("LOGIN") is True


def test_is_under_investigation_false_after_resolution() -> None:
    h = active_hypotheses.open_hypothesis(hypothesis="h", surface="/x")
    assert active_hypotheses.is_surface_under_investigation("/x") is True
    active_hypotheses.confirm_hypothesis(hypothesis_id=h["hypothesis_id"])
    assert active_hypotheses.is_surface_under_investigation("/x") is False


def test_is_under_investigation_category_filter() -> None:
    active_hypotheses.open_hypothesis(
        hypothesis="h", surface="/login", category="xss"
    )
    assert active_hypotheses.is_surface_under_investigation("/login", category="xss") is True
    assert active_hypotheses.is_surface_under_investigation("/login", category="ssrf") is False


def test_is_under_investigation_empty_surface_returns_false() -> None:
    assert active_hypotheses.is_surface_under_investigation("") is False


# ---------------------------------------------------------------------------
# Tracer-absent fallback
# ---------------------------------------------------------------------------


def test_open_works_without_tracer(monkeypatch) -> None:
    """Without a tracer, file-write fails silently but the in-process
    record is still returned. Reads return [] (no artifact)."""
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "get_global_tracer", lambda: None)

    out = active_hypotheses.open_hypothesis(hypothesis="h", surface="/x")
    # Tool returns success — file-write best-effort.
    assert out["success"] is True
    assert out["hypothesis_id"].startswith("hyp_")


# ---------------------------------------------------------------------------
# Agent-tool registration sanity
# ---------------------------------------------------------------------------


def test_agent_tools_registered() -> None:
    from strix.tools.registry import get_tool_by_name

    assert get_tool_by_name("open_hypothesis") is not None
    assert get_tool_by_name("confirm_hypothesis") is not None
    assert get_tool_by_name("dismiss_hypothesis") is not None
    assert get_tool_by_name("list_hypotheses") is not None
