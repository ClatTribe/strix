"""Tests for the coverage matrix module + tracer integration (roadmap §7.0)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import coverage as coverage_module
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


def _load_events(events_path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in events_path.read_text().splitlines() if line]


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
    monkeypatch.delenv("STRIX_KEV_DISABLED", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


# ---------------------------------------------------------------------------
# Pure-module tests
# ---------------------------------------------------------------------------


def test_required_categories_for_domain_standard() -> None:
    cats = coverage_module.required_categories(["domain"], "standard")
    assert "dns_security" in cats
    assert "email_security" in cats
    assert "subdomain_takeover" in cats


def test_required_categories_unknown_target_empty() -> None:
    cats = coverage_module.required_categories(["mystery_type"], "standard")
    assert cats == set()


def test_required_categories_unknown_scan_mode_falls_back_to_standard() -> None:
    cats_std = coverage_module.required_categories(["domain"], "standard")
    cats_unknown = coverage_module.required_categories(["domain"], "extreme")
    assert cats_unknown == cats_std


def test_required_categories_multi_target_unions() -> None:
    cats = coverage_module.required_categories(["domain", "web_application"], "quick")
    # quick web: sqli/xss/idor; quick domain: dns_security/subdomain_takeover
    assert "sqli" in cats
    assert "dns_security" in cats


def test_compute_gaps_no_matrix_status() -> None:
    report = coverage_module.compute_gaps(
        target_types=["ip_address"],
        scan_mode="standard",
        completed_categories=set(),
    )
    assert report["status"] == "no_matrix"
    assert report["coverage_percent"] is None


def test_compute_gaps_complete() -> None:
    report = coverage_module.compute_gaps(
        target_types=["domain"],
        scan_mode="standard",
        completed_categories={"dns_security", "email_security", "subdomain_takeover"},
    )
    assert report["status"] == "complete"
    assert report["gaps"] == []
    assert report["coverage_percent"] == 1.0
    assert report["covered"] == ["dns_security", "email_security", "subdomain_takeover"]


def test_compute_gaps_incomplete() -> None:
    report = coverage_module.compute_gaps(
        target_types=["domain"],
        scan_mode="standard",
        completed_categories={"dns_security"},
    )
    assert report["status"] == "incomplete"
    assert "email_security" in report["gaps"]
    assert "subdomain_takeover" in report["gaps"]
    assert report["coverage_percent"] is not None
    assert 0.0 < report["coverage_percent"] < 1.0


def test_override_via_env_var(monkeypatch, tmp_path) -> None:
    custom = tmp_path / "matrix.json"
    custom.write_text(
        json.dumps(
            {"domain": {"standard": ["custom_category", "another_one"]}}
        )
    )
    monkeypatch.setenv("STRIX_COVERAGE_MATRIX_PATH", str(custom))

    cats = coverage_module.required_categories(["domain"], "standard")
    assert cats == {"custom_category", "another_one"}


def test_override_invalid_json_falls_back_to_default(monkeypatch, tmp_path) -> None:
    bad = tmp_path / "matrix.json"
    bad.write_text("not json {{{")
    monkeypatch.setenv("STRIX_COVERAGE_MATRIX_PATH", str(bad))

    cats = coverage_module.required_categories(["domain"], "standard")
    assert "dns_security" in cats  # default matrix used as fallback


def test_override_wrong_shape_falls_back(monkeypatch, tmp_path) -> None:
    bad = tmp_path / "matrix.json"
    bad.write_text(json.dumps({"domain": "not-a-mode-dict"}))
    monkeypatch.setenv("STRIX_COVERAGE_MATRIX_PATH", str(bad))

    cats = coverage_module.required_categories(["domain"], "standard")
    assert "dns_security" in cats  # default matrix used as fallback


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def test_tracer_emits_coverage_complete_event(tmp_path) -> None:
    tracer = Tracer("cov-complete")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {
            "targets": [{"type": "domain", "value": "example.com"}],
            "scan_mode": "standard",
        }
    )

    # Cover all required for domain/standard.
    for cat in ("dns_security", "email_security", "subdomain_takeover"):
        cid = tracer.start_check(category=cat, surface="example.com")
        tracer.complete_check(cid, "not_vulnerable")

    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "cov-complete" / "events.jsonl"
    events = _load_events(events_path)
    coverage_events = [e for e in events if e["event_type"].startswith("run.coverage_")]
    assert len(coverage_events) == 1
    assert coverage_events[0]["event_type"] == "run.coverage_complete"
    assert coverage_events[0]["payload"]["coverage_percent"] == 1.0
    assert coverage_events[0]["payload"]["gaps"] == []


def test_tracer_emits_coverage_gap_event(tmp_path) -> None:
    tracer = Tracer("cov-gap")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {
            "targets": [{"type": "domain", "value": "example.com"}],
            "scan_mode": "standard",
        }
    )

    # Cover only dns_security; expect gaps for email_security + subdomain_takeover.
    cid = tracer.start_check(category="dns_security", surface="example.com")
    tracer.complete_check(cid, "not_vulnerable")

    tracer.save_run_data(mark_complete=True)

    events_path = tmp_path / "strix_runs" / "cov-gap" / "events.jsonl"
    events = _load_events(events_path)
    gap_events = [e for e in events if e["event_type"] == "run.coverage_gap"]
    assert len(gap_events) == 1
    payload = gap_events[0]["payload"]
    assert "email_security" in payload["gaps"]
    assert "subdomain_takeover" in payload["gaps"]
    assert payload["covered"] == ["dns_security"]
    assert payload["status"] == "incomplete"


def test_tracer_writes_coverage_json(tmp_path) -> None:
    tracer = Tracer("cov-json")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {
            "targets": [{"type": "domain", "value": "example.com"}],
            "scan_mode": "quick",
        }
    )
    cid = tracer.start_check(category="dns_security", surface="example.com")
    tracer.complete_check(cid, "not_vulnerable")
    tracer.save_run_data(mark_complete=True)

    coverage_path = tmp_path / "strix_runs" / "cov-json" / "coverage.json"
    assert coverage_path.exists()
    data = json.loads(coverage_path.read_text())
    assert data["scan_mode"] == "quick"
    assert data["target_types"] == ["domain"]
    assert "subdomain_takeover" in data["gaps"]
    assert data["status"] == "incomplete"
    assert data["schema_version"] == 1


def test_tracer_no_matrix_status_for_ip(tmp_path) -> None:
    tracer = Tracer("cov-ip")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {
            "targets": [{"type": "ip_address", "value": "192.0.2.1"}],
            "scan_mode": "standard",
        }
    )
    tracer.save_run_data(mark_complete=True)

    coverage_path = tmp_path / "strix_runs" / "cov-ip" / "coverage.json"
    assert coverage_path.exists()
    data = json.loads(coverage_path.read_text())
    # ip_address has empty matrix today → status=no_matrix, no event emitted.
    assert data["status"] == "no_matrix"
    assert data["coverage_percent"] is None

    events = _load_events(tmp_path / "strix_runs" / "cov-ip" / "events.jsonl")
    assert not any(e["event_type"].startswith("run.coverage_") for e in events)


def test_tracer_partial_save_doesnt_emit_coverage(tmp_path) -> None:
    """A partial save_run_data (mark_complete=False) shouldn't claim coverage."""
    tracer = Tracer("cov-partial")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {
            "targets": [{"type": "domain", "value": "example.com"}],
            "scan_mode": "quick",
        }
    )
    cid = tracer.start_check(category="dns_security", surface="example.com")
    tracer.complete_check(cid, "not_vulnerable")
    tracer.save_run_data()  # mark_complete defaults to False

    coverage_path = tmp_path / "strix_runs" / "cov-partial" / "coverage.json"
    assert not coverage_path.exists()


def test_tracer_multi_target_unions_required(tmp_path) -> None:
    tracer = Tracer("cov-multi")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {
            "targets": [
                {"type": "domain", "value": "example.com"},
                {"type": "web_application", "value": "https://example.com"},
            ],
            "scan_mode": "quick",
        }
    )
    # Cover dns_security only — leaves both domain (subdomain_takeover) and
    # web (sqli, xss, idor) gaps.
    cid = tracer.start_check(category="dns_security")
    tracer.complete_check(cid, "not_vulnerable")
    tracer.save_run_data(mark_complete=True)

    data = json.loads(
        (tmp_path / "strix_runs" / "cov-multi" / "coverage.json").read_text()
    )
    assert "subdomain_takeover" in data["gaps"]
    assert "sqli" in data["gaps"]
    assert "xss" in data["gaps"]
    assert "idor" in data["gaps"]
    assert data["target_types"] == ["domain", "web_application"]
