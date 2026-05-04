"""Tests for the surface_map.json handoff schema (roadmap §8.0).

Tests cover:

- validate_surface_map: each violation code path
- has_canonical_errors: filters warns
- load_surface_map: parses + validates
- load_surface_map handles missing file
- load_surface_map handles malformed JSON
- Round-trip: a real surface_map produced by the domain_pipeline
  fixture validates clean
- Producer-side hook: domain_pipeline._write_surface_map emits
  handoff.shape_violation events on non-canonical data
- Consumer-side hook: cross_target_correlate auto-loads via the
  validator
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.agents.handoffs.surface_map import (
    SurfaceMapViolation,
    has_canonical_errors,
    load_surface_map,
    validate_surface_map,
)
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


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


def _canonical_surface_map(**overrides: Any) -> dict[str, Any]:
    base = {
        "schema_version": 1,
        "domain": "example.com",
        "generated_at": "2026-05-04T12:00:00+00:00",
        "phase_id": "phase-recon-001",
        "dns_only": False,
        "summary": {
            "subdomains_discovered": 12,
            "subdomains_live": 8,
            "deep_targets": 5,
            "shallow_targets": 3,
            "takeover_candidates": 0,
            "cloud_asset_hits": 1,
            "passive_dns_subdomains": 4,
        },
        "subdomain_enum": {
            "per_source": {"subfinder": 10},
            "all_unique": 12,
            "subdomains": ["api.example.com", "www.example.com"],
        },
        "subdomain_triage": [
            {"subdomain": "api.example.com", "ips_resolved": ["198.51.100.10"]},
        ],
        "deep_targets": ["https://api.example.com"],
        "shallow_targets": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Pure validator
# ---------------------------------------------------------------------------


def test_canonical_no_violations() -> None:
    assert validate_surface_map(_canonical_surface_map()) == []


def test_not_dict() -> None:
    out = validate_surface_map("not a dict")  # type: ignore[arg-type]
    assert any(v.code == "surface_map.not_dict" for v in out)


def test_missing_schema_version() -> None:
    sm = _canonical_surface_map()
    del sm["schema_version"]
    out = validate_surface_map(sm)
    assert any(v.code == "surface_map.missing.schema_version" for v in out)


def test_invalid_schema_version() -> None:
    out = validate_surface_map(_canonical_surface_map(schema_version=99))
    assert any(v.code == "surface_map.schema_version.invalid" for v in out)


def test_schema_version_wrong_type() -> None:
    out = validate_surface_map(_canonical_surface_map(schema_version="1"))
    assert any(v.code == "surface_map.schema_version.invalid" for v in out)


def test_missing_domain() -> None:
    sm = _canonical_surface_map()
    del sm["domain"]
    out = validate_surface_map(sm)
    assert any(v.code == "surface_map.missing.domain" for v in out)


def test_invalid_domain_type() -> None:
    out = validate_surface_map(_canonical_surface_map(domain=""))
    assert any(v.code == "surface_map.domain.invalid_type" for v in out)
    out = validate_surface_map(_canonical_surface_map(domain=123))
    assert any(v.code == "surface_map.domain.invalid_type" for v in out)


def test_missing_generated_at() -> None:
    sm = _canonical_surface_map()
    del sm["generated_at"]
    out = validate_surface_map(sm)
    assert any(v.code == "surface_map.missing.generated_at" for v in out)


def test_invalid_generated_at_type() -> None:
    out = validate_surface_map(_canonical_surface_map(generated_at="not-a-date"))
    assert any(v.code == "surface_map.generated_at.invalid_type" for v in out)


def test_generated_at_with_z_suffix() -> None:
    """Common Python output uses '...Z'; we accept it."""
    out = validate_surface_map(
        _canonical_surface_map(generated_at="2026-05-04T12:00:00Z")
    )
    assert not any(v.code == "surface_map.generated_at.invalid_type" for v in out)


def test_missing_summary() -> None:
    sm = _canonical_surface_map()
    del sm["summary"]
    out = validate_surface_map(sm)
    assert any(v.code == "surface_map.missing.summary" for v in out)


def test_summary_missing_counters_warns() -> None:
    out = validate_surface_map(_canonical_surface_map(summary={"subdomains_discovered": 0}))
    counter_warns = [v for v in out if v.code == "surface_map.summary.missing_counters"]
    assert len(counter_warns) == 1
    assert counter_warns[0].severity == "warn"


def test_subdomain_enum_invalid_shape() -> None:
    out = validate_surface_map(
        _canonical_surface_map(subdomain_enum="not-a-dict")
    )
    assert any(v.code == "surface_map.subdomain_enum.invalid_shape" for v in out)


def test_subdomain_enum_subdomains_must_be_list_of_str() -> None:
    out = validate_surface_map(
        _canonical_surface_map(
            subdomain_enum={"per_source": {}, "all_unique": 0, "subdomains": [1, 2, 3]}
        )
    )
    assert any(v.code == "surface_map.subdomain_enum.invalid_shape" for v in out)


def test_subdomain_triage_must_be_list() -> None:
    out = validate_surface_map(_canonical_surface_map(subdomain_triage="not-a-list"))
    assert any(v.code == "surface_map.subdomain_triage.invalid_entry" for v in out)


def test_subdomain_triage_entry_must_be_dict() -> None:
    out = validate_surface_map(_canonical_surface_map(subdomain_triage=["x"]))
    assert any(v.code == "surface_map.subdomain_triage.invalid_entry" for v in out)


def test_subdomain_triage_invalid_ips() -> None:
    out = validate_surface_map(
        _canonical_surface_map(subdomain_triage=[
            {"subdomain": "x", "ips_resolved": [1, 2, 3]},
        ])
    )
    assert any(v.code == "surface_map.subdomain_triage.invalid_entry" for v in out)


def test_has_canonical_errors_filters_warns() -> None:
    warn_only = [SurfaceMapViolation(
        code="x", field="x", message="x", severity="warn",
    )]
    err_present = warn_only + [
        SurfaceMapViolation(code="y", field="y", message="y", severity="error"),
    ]
    assert has_canonical_errors(warn_only) is False
    assert has_canonical_errors(err_present) is True


# ---------------------------------------------------------------------------
# load_surface_map
# ---------------------------------------------------------------------------


def test_load_surface_map_canonical(tmp_path) -> None:
    p = tmp_path / "surface_map.json"
    p.write_text(json.dumps(_canonical_surface_map()))
    data, violations = load_surface_map(p)
    assert data is not None
    assert violations == []


def test_load_surface_map_missing_file(tmp_path) -> None:
    data, violations = load_surface_map(tmp_path / "absent.json")
    assert data is None
    assert any(v.code == "surface_map.not_dict" for v in violations)


def test_load_surface_map_malformed_json(tmp_path) -> None:
    p = tmp_path / "broken.json"
    p.write_text("not json {")
    data, violations = load_surface_map(p)
    assert data is None
    assert any(v.code == "surface_map.not_dict" for v in violations)


def test_load_surface_map_with_warns_returns_data(tmp_path) -> None:
    """Warns don't block loading — data is still returned."""
    sm = _canonical_surface_map(summary={"subdomains_discovered": 0})  # missing other counters
    p = tmp_path / "surface_map.json"
    p.write_text(json.dumps(sm))
    data, violations = load_surface_map(p)
    assert data is not None
    assert any(v.code == "surface_map.summary.missing_counters" for v in violations)


# ---------------------------------------------------------------------------
# Integration: producer-side hook in _write_surface_map
# ---------------------------------------------------------------------------


def test_producer_emits_violation_event_on_bad_shape(tmp_path) -> None:
    """When _write_surface_map is given a non-canonical shape, a
    handoff.shape_violation event is emitted to events.jsonl."""
    from strix.tools.recon.domain_pipeline import _write_surface_map

    tracer = Tracer("producer-bad-shape")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})

    bad_sm = {  # missing schema_version + domain + generated_at + summary
        "subdomain_enum": {"subdomains": ["a.example.com"]},
    }
    _write_surface_map("example.com", bad_sm)

    # File was still written (we don't block on contract errors).
    run_dir = tracer.get_run_dir()
    assert (run_dir / "surface_map.json").exists()

    # Event was emitted.
    events_file = run_dir / "events.jsonl"
    events = [
        json.loads(line) for line in events_file.read_text().splitlines() if line.strip()
    ]
    handoff_events = [
        e for e in events
        if (e.get("event_type") or e.get("event")) == "handoff.shape_violation"
    ]
    assert len(handoff_events) == 1
    payload = handoff_events[0].get("payload") or {}
    codes = {v["code"] for v in payload.get("violations") or []}
    assert "surface_map.missing.schema_version" in codes
    assert payload["is_canonical"] is False


def test_producer_no_event_on_canonical_shape(tmp_path) -> None:
    """Canonical surface_map → no handoff.shape_violation event."""
    from strix.tools.recon.domain_pipeline import _write_surface_map

    tracer = Tracer("producer-clean")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})

    _write_surface_map("example.com", _canonical_surface_map())

    run_dir = tracer.get_run_dir()
    events_file = run_dir / "events.jsonl"
    if events_file.exists():
        events = [
            json.loads(line) for line in events_file.read_text().splitlines() if line.strip()
        ]
        handoff_events = [
            e for e in events
            if (e.get("event_type") or e.get("event")) == "handoff.shape_violation"
        ]
        assert handoff_events == []


# ---------------------------------------------------------------------------
# Integration: consumer-side hook in cross_target_correlate
# ---------------------------------------------------------------------------


def test_consumer_loads_via_validator(tmp_path) -> None:
    """cross_target_correlate auto-loads surface_map via the
    handoff validator and still emits its correlations correctly."""
    import sys

    import strix.tools.cross_target.cross_target_correlate  # noqa: F401

    cross_target_correlate = sys.modules[
        "strix.tools.cross_target.cross_target_correlate"
    ].cross_target_correlate

    tracer = Tracer("consumer-via-validator")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})

    # Write a canonical surface_map with a flagged IP pair.
    sm_path = tmp_path / "surface_map.json"
    sm_path.write_text(json.dumps(_canonical_surface_map(
        subdomain_triage=[{"subdomain": "api.example.com", "ips_resolved": ["198.51.100.10"]}],
    )))

    def lookup(ip: str) -> dict[str, Any]:
        if ip == "198.51.100.10":
            return {
                "flags": ["vt_malicious=10"],
                "sources": ["virustotal"],
                "max_severity": "high",
            }
        return {"flags": [], "sources": [], "max_severity": "none"}

    out = cross_target_correlate(
        findings=[],
        surface_map_path=str(sm_path),
        ip_reputation_lookup=lookup,
    )
    assert out["findings_emitted"] >= 1
