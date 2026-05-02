"""Tests for run.summary event + run_summary.json artifact + summary text builder.

Roadmap §1. The summary is built from final tracer state — vulnerability_reports,
scan_config, get_check_summary(). These tests exercise the data-shape contract
that downstream consumers (CI logs, dashboards, Slack) will rely on.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, _build_summary_text, set_global_tracer


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
    events_path = tmp_path / "strix_runs" / run_name / "events.jsonl"
    if not events_path.exists():
        return []
    return [json.loads(line) for line in events_path.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# build_run_summary — data shape
# ---------------------------------------------------------------------------


def test_build_summary_empty_run() -> None:
    """A run with no findings + no checks still returns a well-formed payload."""
    t = Tracer("empty-run")
    set_global_tracer(t)
    summary = t.build_run_summary()
    assert summary["schema_version"] == 1
    assert summary["run_name"] == "empty-run"
    assert summary["findings_summary"]["total"] == 0
    assert summary["findings_summary"]["by_severity"] == {}
    assert summary["top_findings"] == []
    assert summary["checks"]["total"] == 0
    assert "no findings" in summary["summary_text"]


def test_build_summary_targets_from_scan_config() -> None:
    t = Tracer("with-targets")
    set_global_tracer(t)
    t.set_scan_config({"targets": [
        {"type": "domain", "value": "example.com"},
        {"type": "ip_address", "value": "1.2.3.4"},
    ]})
    summary = t.build_run_summary()
    values = [tg["value"] for tg in summary["targets"]]
    assert values == ["example.com", "1.2.3.4"]
    types = [tg.get("type") for tg in summary["targets"]]
    assert types == ["domain", "ip_address"]


def test_build_summary_target_string_form() -> None:
    """scan_config.targets entries that are bare strings should still be accepted."""
    t = Tracer("string-targets")
    set_global_tracer(t)
    t.set_scan_config({"targets": ["example.com"]})
    summary = t.build_run_summary()
    assert summary["targets"][0]["value"] == "example.com"


def test_build_summary_findings_severity_breakdown() -> None:
    t = Tracer("finds-run")
    set_global_tracer(t)
    t.add_vulnerability_report(title="A", severity="critical", category="auth")
    t.add_vulnerability_report(title="B", severity="high", category="auth")
    t.add_vulnerability_report(title="C", severity="medium", category="info_disclosure")
    t.add_vulnerability_report(title="D", severity="low", category="info_disclosure")
    t.add_vulnerability_report(title="E", severity="info", category="info_disclosure")
    t.add_vulnerability_report(title="F", severity="info", category="dns_security")

    summary = t.build_run_summary()
    fs = summary["findings_summary"]
    assert fs["total"] == 6
    assert fs["by_severity"] == {
        "critical": 1, "high": 1, "medium": 1, "low": 1, "info": 2,
    }
    # by_category counts.
    assert fs["by_category"]["info_disclosure"] == 3
    assert fs["by_category"]["auth"] == 2
    assert fs["by_category"]["dns_security"] == 1


def test_build_summary_top_findings_sorted_by_severity() -> None:
    t = Tracer("top-finds")
    set_global_tracer(t)
    # Insert in shuffled order; expect critical→high→medium→low→info ordering in output.
    t.add_vulnerability_report(title="info-finding", severity="info")
    t.add_vulnerability_report(title="critical-finding", severity="critical")
    t.add_vulnerability_report(title="medium-finding", severity="medium")
    t.add_vulnerability_report(title="high-finding", severity="high")
    t.add_vulnerability_report(title="low-finding", severity="low")
    t.add_vulnerability_report(title="extra-info", severity="info")

    summary = t.build_run_summary()
    titles = [f["title"] for f in summary["top_findings"]]
    assert titles[0] == "critical-finding"
    assert titles[1] == "high-finding"
    assert titles[2] == "medium-finding"
    # Cap is 5.
    assert len(summary["top_findings"]) == 5


def test_build_summary_includes_check_aggregate() -> None:
    t = Tracer("check-run")
    set_global_tracer(t)
    cid1 = t.start_check(category="dns_security", surface="example.com", tool="x")
    t.complete_check(cid1, result="not_vulnerable")
    cid2 = t.start_check(category="email_security", surface="example.com", tool="y")
    t.complete_check(cid2, result="vulnerable")
    cid3 = t.start_check(category="dns_security", surface="example.com", tool="z")
    t.complete_check(cid3, result="not_vulnerable")

    summary = t.build_run_summary()
    assert summary["checks"]["total"] == 3
    assert summary["checks"]["by_result"]["not_vulnerable"] == 2
    assert summary["checks"]["by_result"]["vulnerable"] == 1


# ---------------------------------------------------------------------------
# _build_summary_text — plain-English headline shape
# ---------------------------------------------------------------------------


def test_summary_text_no_findings() -> None:
    text = _build_summary_text(
        targets=[{"value": "example.com", "type": "domain"}],
        duration_seconds=42.0,
        findings_total=0,
        by_severity={},
        by_category={},
        check_summary={"total": 5, "by_result": {"not_vulnerable": 5, "vulnerable": 0, "inconclusive": 0}},
    )
    assert "example.com" in text
    assert "no findings" in text
    assert "5 check(s) ran" in text
    assert text.endswith(".")


def test_summary_text_with_findings_and_categories() -> None:
    text = _build_summary_text(
        targets=[{"value": "example.com", "type": "domain"}],
        duration_seconds=125.0,
        findings_total=3,
        by_severity={"high": 1, "medium": 2},
        by_category={"email_security": 2, "dns_security": 1},
        check_summary={"total": 0, "by_result": {}},
    )
    assert "1 high" in text
    assert "2 medium" in text
    assert "email_security" in text
    # When duration >= 60 use minutes.
    assert "2.1m" in text


def test_summary_text_short_duration_in_seconds() -> None:
    text = _build_summary_text(
        targets=[],
        duration_seconds=15.0,
        findings_total=0,
        by_severity={},
        by_category={},
        check_summary={"total": 0, "by_result": {}},
    )
    assert "15s" in text


def test_summary_text_multi_target() -> None:
    text = _build_summary_text(
        targets=[{"value": "a"}, {"value": "b"}, {"value": "c"}],
        duration_seconds=30.0,
        findings_total=0,
        by_severity={},
        by_category={},
        check_summary={"total": 0, "by_result": {}},
    )
    assert "Scanned 3 targets" in text


# ---------------------------------------------------------------------------
# Event emission + run_summary.json artifact (via save_run_data)
# ---------------------------------------------------------------------------


def test_save_run_data_emits_run_summary_event(tmp_path) -> None:
    t = Tracer("evt-run")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    t.add_vulnerability_report(title="A finding", severity="medium", category="dns_security")

    t.save_run_data(mark_complete=True)

    events = _events_for("evt-run", tmp_path)
    summary_events = [e for e in events if e["event_type"] == "run.summary"]
    assert len(summary_events) == 1
    payload = summary_events[0]["payload"]
    assert payload["schema_version"] == 1
    assert payload["findings_summary"]["total"] == 1
    assert payload["targets"][0]["value"] == "example.com"
    assert "summary_text" in payload


def test_save_run_data_emits_summary_before_completed(tmp_path) -> None:
    """Order matters: consumers reading events in order should see summary
    before the terminal run.completed signal."""
    t = Tracer("order-run")
    set_global_tracer(t)
    t.save_run_data(mark_complete=True)
    events = _events_for("order-run", tmp_path)
    types = [e["event_type"] for e in events]
    summary_idx = types.index("run.summary")
    completed_idx = types.index("run.completed")
    assert summary_idx < completed_idx


def test_save_run_data_persists_run_summary_json(tmp_path) -> None:
    t = Tracer("json-run")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    t.add_vulnerability_report(title="X", severity="high")
    t.save_run_data(mark_complete=True)

    artifact = tmp_path / "strix_runs" / "json-run" / "run_summary.json"
    assert artifact.exists()
    data = json.loads(artifact.read_text())
    assert data["schema_version"] == 1
    assert data["findings_summary"]["total"] == 1
    assert data["findings_summary"]["by_severity"]["high"] == 1


def test_run_summary_event_emitted_only_once(tmp_path) -> None:
    """save_run_data may be called multiple times during a scan, but
    run.summary (like run.completed) should fire exactly once."""
    t = Tracer("once-run")
    set_global_tracer(t)
    t.save_run_data(mark_complete=True)
    t.save_run_data(mark_complete=True)
    events = _events_for("once-run", tmp_path)
    summaries = [e for e in events if e["event_type"] == "run.summary"]
    assert len(summaries) == 1


def test_save_run_data_without_mark_complete_skips_summary(tmp_path) -> None:
    """Intermediate save_run_data calls (mark_complete=False) shouldn't
    emit run.summary — only the final one does."""
    t = Tracer("partial-run")
    set_global_tracer(t)
    t.save_run_data(mark_complete=False)
    events = _events_for("partial-run", tmp_path)
    assert not [e for e in events if e["event_type"] == "run.summary"]
