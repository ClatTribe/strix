"""Tests for the phase + check event API on the tracer (roadmap §1)."""

from __future__ import annotations

import json
from typing import Any

import pytest

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
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


# ---------------------------------------------------------------------------
# Phase events
# ---------------------------------------------------------------------------


def test_enter_phase_emits_event(tmp_path) -> None:
    tracer = Tracer("phase-enter")
    set_global_tracer(tracer)
    pid = tracer.enter_phase("recon", focus="dns_security")
    assert pid.startswith("phase-")

    events = _load_events(tmp_path / "strix_runs" / "phase-enter" / "events.jsonl")
    entered = [e for e in events if e["event_type"] == "phase.entered"]
    assert len(entered) == 1
    assert entered[0]["payload"]["phase"] == "recon"
    assert entered[0]["payload"]["focus"] == "dns_security"
    assert entered[0]["payload"]["phase_id"] == pid
    assert entered[0]["status"] == "recon"


def test_complete_phase_emits_event(tmp_path) -> None:
    tracer = Tracer("phase-complete")
    set_global_tracer(tracer)
    pid = tracer.enter_phase("exploit")
    tracer.complete_phase(pid, summary={"checks_run": 5})

    events = _load_events(tmp_path / "strix_runs" / "phase-complete" / "events.jsonl")
    completed = [e for e in events if e["event_type"] == "phase.completed"]
    assert len(completed) == 1
    assert completed[0]["payload"]["phase_id"] == pid
    assert completed[0]["payload"]["summary"] == {"checks_run": 5}
    assert "duration_seconds" in completed[0]["payload"]


def test_complete_phase_unknown_id_is_silent(tmp_path) -> None:
    tracer = Tracer("phase-unknown")
    set_global_tracer(tracer)
    # Should not raise.
    tracer.complete_phase("phase-bogus-id")
    events = _load_events(tmp_path / "strix_runs" / "phase-unknown" / "events.jsonl")
    assert not any(e["event_type"] == "phase.completed" for e in events)


def test_custom_phase_name_tagged(tmp_path) -> None:
    tracer = Tracer("phase-custom")
    set_global_tracer(tracer)
    tracer.enter_phase("triage")  # not in canonical list

    events = _load_events(tmp_path / "strix_runs" / "phase-custom" / "events.jsonl")
    entered = [e for e in events if e["event_type"] == "phase.entered"]
    assert entered[0]["payload"].get("custom") is True


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_start_and_complete_check(tmp_path) -> None:
    tracer = Tracer("check-basic")
    set_global_tracer(tracer)
    cid = tracer.start_check(category="sqli", surface="/api/users", tool="sqlmap_check")
    tracer.complete_check(cid, "vulnerable", confidence=0.9, finding_id="vuln-0001")

    events = _load_events(tmp_path / "strix_runs" / "check-basic" / "events.jsonl")
    started = [e for e in events if e["event_type"] == "check.started"]
    completed = [e for e in events if e["event_type"] == "check.completed"]
    assert len(started) == 1 and len(completed) == 1
    assert started[0]["payload"]["category"] == "sqli"
    assert started[0]["payload"]["surface"] == "/api/users"
    assert completed[0]["payload"]["result"] == "vulnerable"
    assert completed[0]["payload"]["confidence"] == 0.9
    assert completed[0]["payload"]["finding_id"] == "vuln-0001"


def test_complete_check_invalid_result_coerced_to_inconclusive(tmp_path) -> None:
    tracer = Tracer("check-coerce")
    set_global_tracer(tracer)
    cid = tracer.start_check(category="xss")
    tracer.complete_check(cid, "weird-status")

    events = _load_events(tmp_path / "strix_runs" / "check-coerce" / "events.jsonl")
    completed = [e for e in events if e["event_type"] == "check.completed"]
    assert completed[0]["payload"]["result"] == "inconclusive"


def test_complete_check_default_confidence(tmp_path) -> None:
    tracer = Tracer("check-conf")
    set_global_tracer(tracer)
    cid_v = tracer.start_check(category="sqli")
    tracer.complete_check(cid_v, "vulnerable")
    cid_n = tracer.start_check(category="sqli")
    tracer.complete_check(cid_n, "not_vulnerable")
    cid_i = tracer.start_check(category="sqli")
    tracer.complete_check(cid_i, "inconclusive")

    events = _load_events(tmp_path / "strix_runs" / "check-conf" / "events.jsonl")
    completed = [e for e in events if e["event_type"] == "check.completed"]
    by_result = {e["payload"]["result"]: e["payload"]["confidence"] for e in completed}
    assert by_result["vulnerable"] == 1.0
    assert by_result["not_vulnerable"] == 1.0
    assert by_result["inconclusive"] == 0.5


def test_complete_check_unknown_id_is_silent(tmp_path) -> None:
    tracer = Tracer("check-unknown")
    set_global_tracer(tracer)
    tracer.complete_check("check-bogus", "vulnerable")
    events = _load_events(tmp_path / "strix_runs" / "check-unknown" / "events.jsonl")
    assert not any(e["event_type"] == "check.completed" for e in events)


# ---------------------------------------------------------------------------
# Aggregation: get_check_summary + checks_summary.json
# ---------------------------------------------------------------------------


def test_check_summary_aggregates_across_categories(tmp_path) -> None:
    tracer = Tracer("check-agg")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["example.com"]})

    # 1 sqli vulnerable, 2 sqli not_vulnerable, 1 xss inconclusive
    for _ in range(2):
        cid = tracer.start_check(category="sqli", surface="/api/users")
        tracer.complete_check(cid, "not_vulnerable")
    cid = tracer.start_check(category="sqli", surface="/login")
    tracer.complete_check(cid, "vulnerable", finding_id="vuln-0001")
    cid = tracer.start_check(category="xss", surface="/search")
    tracer.complete_check(cid, "inconclusive")

    summary = tracer.get_check_summary()
    assert summary["total"] == 4
    assert summary["by_result"]["vulnerable"] == 1
    assert summary["by_result"]["not_vulnerable"] == 2
    assert summary["by_result"]["inconclusive"] == 1
    assert summary["by_category"]["sqli"]["vulnerable"] == 1
    assert summary["by_category"]["sqli"]["not_vulnerable"] == 2
    assert summary["by_category"]["xss"]["inconclusive"] == 1
    assert len(summary["not_vulnerable"]) == 2


def test_checks_summary_json_written(tmp_path) -> None:
    tracer = Tracer("check-json")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["example.com"]})

    cid = tracer.start_check(category="email_security", surface="example.com")
    tracer.complete_check(cid, "not_vulnerable", evidence="SPF present")
    tracer.save_run_data()

    json_path = tmp_path / "strix_runs" / "check-json" / "checks_summary.json"
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert data["total"] == 1
    assert data["by_result"]["not_vulnerable"] == 1
    assert data["schema_version"] == 1
    assert len(data["not_vulnerable"]) == 1
    assert data["not_vulnerable"][0]["category"] == "email_security"


def test_checks_summary_json_skipped_when_no_checks(tmp_path) -> None:
    tracer = Tracer("check-empty")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["example.com"]})
    tracer.save_run_data()

    json_path = tmp_path / "strix_runs" / "check-empty" / "checks_summary.json"
    assert not json_path.exists()


# ---------------------------------------------------------------------------
# record_phase tool
# ---------------------------------------------------------------------------


def test_record_phase_enter_returns_phase_id(tmp_path) -> None:
    from strix.tools.recon.phase import record_phase

    tracer = Tracer("phase-tool")
    set_global_tracer(tracer)
    out = record_phase("recon")
    assert out["success"] is True
    assert out["action"] == "enter"
    assert out["phase_id"].startswith("phase-")


def test_record_phase_complete_requires_id(tmp_path) -> None:
    from strix.tools.recon.phase import record_phase

    tracer = Tracer("phase-tool-complete")
    set_global_tracer(tracer)
    out = record_phase("recon", action="complete")
    assert out["success"] is False
    assert "phase_id" in out["error"]


def test_record_phase_full_lifecycle(tmp_path) -> None:
    from strix.tools.recon.phase import record_phase

    tracer = Tracer("phase-lifecycle")
    set_global_tracer(tracer)
    enter_out = record_phase("recon", focus="dns_security")
    assert enter_out["success"] is True
    complete_out = record_phase("recon", action="complete", phase_id=enter_out["phase_id"])
    assert complete_out["success"] is True

    events = _load_events(tmp_path / "strix_runs" / "phase-lifecycle" / "events.jsonl")
    assert any(e["event_type"] == "phase.entered" for e in events)
    assert any(e["event_type"] == "phase.completed" for e in events)


def test_record_phase_invalid_action(tmp_path) -> None:
    from strix.tools.recon.phase import record_phase

    tracer = Tracer("phase-bad-action")
    set_global_tracer(tracer)
    out = record_phase("recon", action="abandon")
    assert out["success"] is False
    assert "invalid action" in out["error"]


# ---------------------------------------------------------------------------
# Recon tools auto-emit check events
# ---------------------------------------------------------------------------


def test_dns_hygiene_emits_check_events(monkeypatch, tmp_path) -> None:
    from strix.tools.recon import dns_hygiene

    tracer = Tracer("dns-checks")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["example.com"]})

    # Mock dig to return canned responses for SPF + DMARC.
    responses = {
        "example.com|TXT": '"v=spf1 include:_spf.google.com -all"',  # SPF present
        "_dmarc.example.com|TXT": '"v=DMARC1; p=quarantine; rua=mailto:d@example.com"',
    }

    def fake_dig(query: str, record_type: str = "A", **_: Any) -> str:
        return responses.get(f"{query}|{record_type}", "")

    monkeypatch.setattr(dns_hygiene, "dig", fake_dig)
    out = dns_hygiene.dns_hygiene_check("example.com", checks="spf,dmarc")
    assert out["success"] is True

    summary = tracer.get_check_summary()
    assert summary["total"] == 2
    assert summary["by_result"]["not_vulnerable"] == 2
    # SPF and DMARC categorize under email_security.
    assert summary["by_category"]["email_security"]["not_vulnerable"] == 2


def test_subdomain_takeover_emits_check_events(monkeypatch, tmp_path) -> None:
    from strix.tools.recon import takeover

    tracer = Tracer("takeover-checks")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["example.com"]})

    monkeypatch.setattr(
        takeover, "dig",
        lambda q, t="A", **_: "old-app.herokuapp.com." if t == "CNAME" and q == "app.example.com" else ""
    )
    monkeypatch.setattr(
        takeover, "http_get_text",
        lambda url, **_: (404, "<html><body>No such app</body></html>"),
    )

    out = takeover.subdomain_takeover_check("example.com", subdomains="app.example.com")
    assert out["candidates"] == 1

    summary = tracer.get_check_summary()
    assert summary["total"] == 1
    assert summary["by_category"]["subdomain_takeover"]["vulnerable"] == 1


def test_cloud_assets_emits_one_check_per_provider(monkeypatch, tmp_path) -> None:
    from strix.tools.recon import cloud_assets

    tracer = Tracer("cloud-checks")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["example.com"]})

    monkeypatch.setattr(
        cloud_assets, "http_head", lambda url, **_: (404, {})
    )
    cloud_assets.discover_cloud_assets("example", providers="s3,gcs")

    summary = tracer.get_check_summary()
    # 1 check per provider (s3, gcs).
    assert summary["total"] == 2
    assert summary["by_category"]["info_disclosure"]["not_vulnerable"] == 2
