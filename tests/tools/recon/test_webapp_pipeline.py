"""Tests for webapp_recon_pipeline (roadmap §8.2).

Hermetic — every underlying tool is mocked. We're testing the
orchestration shape (phase events, webapp_surface_map.json, summary
counters, error tracking, next_steps), not the underlying tool
behaviour (those have their own test modules).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.recon import webapp_pipeline as wp


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
    tracer = Tracer("wp-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://app.example.com"}]}
    )
    yield


def _stub_all_tools(monkeypatch, **overrides: Any) -> None:
    """Patch every underlying tool with a fake that returns a
    well-shaped dict. Tests that want different behaviour pass
    overrides keyed by tool name.

    Note: each tool's `__init__.py` re-exports the function with the
    same name as the submodule (e.g. `strix.tools.tls_audit.tls_audit`
    is the FUNCTION after import, not the module). We patch via
    `sys.modules[<module>]` so monkeypatch sees the module object,
    not the re-exported function."""
    import sys

    # Force-import each module so sys.modules has it.
    import strix.tools.recon.fingerprint  # noqa: F401
    import strix.tools.web_crawler.crawler  # noqa: F401
    import strix.tools.http_headers.http_headers  # noqa: F401
    import strix.tools.tls_audit.tls_audit  # noqa: F401
    import strix.tools.well_known.well_known  # noqa: F401

    def fake_fingerprint(agent_state, target, deep=False):
        if "fingerprint" in overrides:
            return overrides["fingerprint"]
        return {
            "success": True, "target": target,
            "detections": [{"name": "react", "version": "18.2"}],
            "skills_loaded": ["xss", "sql_injection"],
        }

    def fake_bfs_crawl(target, max_pages=200, max_depth=3, seed_urls=None, openapi_url=None):
        if "bfs_crawl" in overrides:
            return overrides["bfs_crawl"]
        return {
            "success": True, "target": target,
            "endpoints": [
                "https://app.example.com/", "https://app.example.com/login",
                "https://app.example.com/api/users",
            ],
            "js_bundles": ["https://app.example.com/main.js"],
            "openapi": {"url": "https://app.example.com/openapi.json"},
        }

    def fake_http_security_headers_audit(target_url):
        if "http_security_headers_audit" in overrides:
            return overrides["http_security_headers_audit"]
        return {
            "success": True, "target_url": target_url,
            "issues": [{"header": "Content-Security-Policy", "issue": "missing"}],
            "findings_emitted": 1,
        }

    def fake_tls_audit(target, timeout=6.0):
        if "tls_audit" in overrides:
            return overrides["tls_audit"]
        return {
            "success": True, "target": target, "host": "app.example.com",
            "protocols": {"TLS 1.3": {"accepted": True}},
            "weak_ciphers": {},
            "certificate": {"present": True, "expired": False},
            "findings_emitted": 0,
        }

    def fake_well_known_harvest(target, include_legacy=True):
        if "well_known_harvest" in overrides:
            return overrides["well_known_harvest"]
        return {
            "success": True, "target": target,
            "probed": 13,
            "hits": [{"path": "/.well-known/security.txt", "status": 200}],
            "errors": [],
            "stats": {"hits": 1, "errors_count": 0},
        }

    monkeypatch.setattr(
        sys.modules["strix.tools.recon.fingerprint"],
        "fingerprint_tech_stack", fake_fingerprint,
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.web_crawler.crawler"],
        "bfs_crawl", fake_bfs_crawl,
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.http_headers.http_headers"],
        "http_security_headers_audit", fake_http_security_headers_audit,
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.tls_audit.tls_audit"],
        "tls_audit", fake_tls_audit,
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.well_known.well_known"],
        "well_known_harvest", fake_well_known_harvest,
    )


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------


def test_invalid_url_rejected() -> None:
    out = wp.webapp_recon_pipeline(agent_state=None, target_url="")
    assert out["success"] is False

    out = wp.webapp_recon_pipeline(agent_state=None, target_url="ftp://x.com/")
    assert out["success"] is False


def test_bare_hostname_normalised(monkeypatch) -> None:
    _stub_all_tools(monkeypatch)
    out = wp.webapp_recon_pipeline(
        agent_state=None, target_url="app.example.com",
    )
    assert out["success"] is True
    assert out["target_url"].startswith("https://")
    assert out["target_host"] == "app.example.com"


# ---------------------------------------------------------------------------
# Happy path — surface map shape
# ---------------------------------------------------------------------------


def test_surface_map_shape(monkeypatch, tmp_path) -> None:
    _stub_all_tools(monkeypatch)
    out = wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
    )
    assert out["success"] is True
    sm = out["surface_map"]
    assert sm["schema_version"] == 1
    assert sm["target_url"] == "https://app.example.com"
    assert sm["target_host"] == "app.example.com"
    assert "generated_at" in sm
    assert "summary" in sm
    summary = sm["summary"]
    assert summary["endpoints_discovered"] == 3
    assert summary["javascript_bundles"] == 1
    assert summary["openapi_specs_found"] == 1
    assert summary["skills_auto_loaded"] == 2
    assert summary["security_header_issues"] == 1
    assert summary["well_known_hits"] == 1


def test_surface_map_persisted_to_disk(monkeypatch, tmp_path) -> None:
    _stub_all_tools(monkeypatch)
    out = wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
    )
    path = (tmp_path / "strix_runs" / "wp-test" / "webapp_surface_map.json")
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["target_host"] == "app.example.com"
    assert data["schema_version"] == 1


def test_phase_events_emitted(monkeypatch, tmp_path) -> None:
    _stub_all_tools(monkeypatch)
    wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
    )
    events_path = tmp_path / "strix_runs" / "wp-test" / "events.jsonl"
    events = [json.loads(l) for l in events_path.read_text().splitlines() if l]
    phases_entered = [
        e for e in events if (e.get("event_type") or e.get("event")) == "phase.entered"
    ]
    phases_completed = [
        e for e in events if (e.get("event_type") or e.get("event")) == "phase.completed"
    ]
    assert len(phases_entered) == 1
    assert len(phases_completed) == 1
    assert (phases_entered[0].get("payload") or {}).get("phase") == "recon"


# ---------------------------------------------------------------------------
# Step toggles
# ---------------------------------------------------------------------------


def test_disable_well_known(monkeypatch, tmp_path) -> None:
    """When enable_well_known=False, the well_known step is skipped."""
    _stub_all_tools(monkeypatch)
    import sys
    called = {"well_known": False}

    def fake_well_known(target, include_legacy=True):
        called["well_known"] = True
        return {"success": True}

    monkeypatch.setattr(
        sys.modules["strix.tools.well_known.well_known"],
        "well_known_harvest", fake_well_known,
    )

    out = wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
        enable_well_known=False,
    )
    assert out["surface_map"]["well_known"] is None
    # The well_known fake should NOT have been called.
    assert called["well_known"] is False


def test_disable_tls(monkeypatch) -> None:
    _stub_all_tools(monkeypatch)
    import sys
    called = {"tls": False}

    def fake_tls(target, timeout=6.0):
        called["tls"] = True
        return {"success": True}

    monkeypatch.setattr(
        sys.modules["strix.tools.tls_audit.tls_audit"],
        "tls_audit", fake_tls,
    )

    out = wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
        enable_tls=False,
    )
    assert out["surface_map"]["tls"] is None
    assert called["tls"] is False


def test_disable_security_headers(monkeypatch) -> None:
    _stub_all_tools(monkeypatch)
    import sys
    called = {"hdr": False}

    def fake_hdr(target_url):
        called["hdr"] = True
        return {"success": True}

    monkeypatch.setattr(
        sys.modules["strix.tools.http_headers.http_headers"],
        "http_security_headers_audit", fake_hdr,
    )

    out = wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
        enable_security_headers=False,
    )
    assert out["surface_map"]["security_headers"] is None
    assert called["hdr"] is False


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------


def test_underlying_failure_recorded_in_errors(monkeypatch) -> None:
    _stub_all_tools(monkeypatch)
    import sys

    def boom_crawl(target, **kw):
        raise RuntimeError("crawl exploded")

    monkeypatch.setattr(
        sys.modules["strix.tools.web_crawler.crawler"],
        "bfs_crawl", boom_crawl,
    )

    out = wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
    )
    # Pipeline still returns success — errors recorded in the surface map.
    assert out["success"] is True
    sm = out["surface_map"]
    assert sm["crawl"] is None
    errors = [e for e in sm["errors"] if e.get("step") == "bfs_crawl"]
    assert len(errors) == 1
    assert "crawl exploded" in errors[0]["error"]


def test_total_failure_still_emits_phase_close(monkeypatch, tmp_path) -> None:
    """Every step fails → pipeline still closes the phase + writes
    a (degenerate) surface map."""
    import sys

    # Force-import each module first.
    import strix.tools.recon.fingerprint  # noqa: F401
    import strix.tools.web_crawler.crawler  # noqa: F401
    import strix.tools.http_headers.http_headers  # noqa: F401
    import strix.tools.tls_audit.tls_audit  # noqa: F401
    import strix.tools.well_known.well_known  # noqa: F401

    def boom(*args, **kwargs):
        raise RuntimeError("everything broken")

    monkeypatch.setattr(
        sys.modules["strix.tools.recon.fingerprint"],
        "fingerprint_tech_stack", boom,
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.web_crawler.crawler"],
        "bfs_crawl", boom,
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.http_headers.http_headers"],
        "http_security_headers_audit", boom,
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.tls_audit.tls_audit"],
        "tls_audit", boom,
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.well_known.well_known"],
        "well_known_harvest", boom,
    )

    out = wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
    )
    assert out["success"] is True
    assert len(out["surface_map"]["errors"]) >= 4
    # Phase still closed.
    events_path = tmp_path / "strix_runs" / "wp-test" / "events.jsonl"
    events = [json.loads(l) for l in events_path.read_text().splitlines() if l]
    phase_completed = [
        e for e in events if (e.get("event_type") or e.get("event")) == "phase.completed"
    ]
    assert len(phase_completed) == 1


# ---------------------------------------------------------------------------
# Handoff schema integration
# ---------------------------------------------------------------------------


def test_handoff_schema_validates_clean(monkeypatch, tmp_path) -> None:
    """A successful pipeline run produces a canonical surface map
    that passes the handoff validator."""
    _stub_all_tools(monkeypatch)
    wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
    )
    path = tmp_path / "strix_runs" / "wp-test" / "webapp_surface_map.json"
    data = json.loads(path.read_text())

    from strix.agents.handoffs.webapp_surface_map import validate_webapp_surface_map
    violations = validate_webapp_surface_map(data)
    errors = [v for v in violations if v.severity == "error"]
    assert errors == [], f"unexpected canonical-contract errors: {errors}"


def test_handoff_event_NOT_emitted_on_clean_run(monkeypatch, tmp_path) -> None:
    _stub_all_tools(monkeypatch)
    wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
    )
    events_path = tmp_path / "strix_runs" / "wp-test" / "events.jsonl"
    events = [json.loads(l) for l in events_path.read_text().splitlines() if l]
    handoff_events = [
        e for e in events
        if (e.get("event_type") or e.get("event")) == "handoff.shape_violation"
    ]
    assert handoff_events == []


# ---------------------------------------------------------------------------
# next_steps surfacing
# ---------------------------------------------------------------------------


def test_next_steps_zero_endpoints_warns(monkeypatch) -> None:
    _stub_all_tools(monkeypatch, bfs_crawl={
        "success": True, "endpoints": [], "js_bundles": [], "openapi": {},
    })
    out = wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
    )
    next_steps = out["next_steps"]
    assert any("0 endpoints" in s for s in next_steps)


def test_next_steps_recommends_specialist_team(monkeypatch) -> None:
    _stub_all_tools(monkeypatch)
    out = wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
    )
    next_steps = out["next_steps"]
    assert any("specialist" in s.lower() or "spawn" in s.lower() for s in next_steps)


def test_next_steps_mentions_openapi(monkeypatch) -> None:
    _stub_all_tools(monkeypatch)
    out = wp.webapp_recon_pipeline(
        agent_state=None, target_url="https://app.example.com",
    )
    next_steps = out["next_steps"]
    assert any("openapi" in s.lower() for s in next_steps)


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def test_mitre_techniques_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    techniques = get_tool_mitre_techniques("webapp_recon_pipeline")
    assert "T1595" in techniques
    assert "T1592" in techniques
