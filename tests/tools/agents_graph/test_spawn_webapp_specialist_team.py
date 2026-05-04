"""Tests for spawn_webapp_specialist_team (roadmap §8.2 row 2).

Hermetic — `create_agent` and the surface-map loader are mocked.
We're testing the orchestration shape (which specialists are
spawned, surface-map auto-load, dedup, cap, skip-on-error,
inherit_context defaults), not the underlying agent loop.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

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
    tracer = Tracer("st-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://app.example.com"}]}
    )
    yield


def _stub_create_agent(monkeypatch) -> dict[str, list[dict[str, Any]]]:
    """Replace `create_agent` with a stub that records every call.
    Returns a dict whose `calls` key is the in-order list of call kwargs."""
    captured = {"calls": []}
    counter = {"i": 0}

    def fake_create(**kwargs):
        counter["i"] += 1
        captured["calls"].append(kwargs)
        return {
            "success": True,
            "agent_id": f"agent_{counter['i']:03d}",
            "agent_info": {"category": kwargs.get("category")},
        }

    import strix.tools.agents_graph.agents_graph_actions as ga
    monkeypatch.setattr(
        sys.modules["strix.tools.agents_graph.agents_graph_actions"],
        "create_agent", fake_create,
    )
    return captured


def _make_agent_state(agent_id: str = "lead_001") -> Any:
    class _S:
        def __init__(self) -> None:
            self.agent_id = agent_id
        def get_conversation_history(self) -> list:
            return []
    return _S()


def _write_canonical_surface_map(run_dir, **overrides) -> None:
    base = {
        "schema_version": 1,
        "target_url": "https://app.example.com",
        "target_host": "app.example.com",
        "generated_at": "2026-05-04T12:00:00+00:00",
        "summary": {
            "endpoints_discovered": 12,
            "javascript_bundles": 3,
            "openapi_specs_found": 1,
            "tech_stack_detections": 5,
            "skills_auto_loaded": 4,
            "security_header_issues": 1,
            "well_known_hits": 1,
            "tls_audit_findings": 0,
        },
    }
    base.update(overrides)
    path = run_dir / "webapp_surface_map.json"
    path.write_text(json.dumps(base))


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------


def _spawn():
    """Return the function under test, importing freshly so any
    module-level patches landed first."""
    from strix.tools.agents_graph.agents_graph_actions import (
        spawn_webapp_specialist_team,
    )
    return spawn_webapp_specialist_team


# ---------------------------------------------------------------------------
# URL normalisation / arg validation
# ---------------------------------------------------------------------------


def test_empty_target_url_rejected() -> None:
    out = _spawn()(agent_state=_make_agent_state(), target_url="")
    assert out["success"] is False


def test_invalid_scheme_rejected() -> None:
    out = _spawn()(agent_state=_make_agent_state(), target_url="ftp://x.com/")
    assert out["success"] is False


def test_bare_host_normalised(monkeypatch) -> None:
    _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="app.example.com",
        specialists="csrf-specialist",
    )
    assert out["success"] is True
    assert out["target_url"].startswith("https://")
    assert out["target_host"] == "app.example.com"


# ---------------------------------------------------------------------------
# Default specialist set
# ---------------------------------------------------------------------------


def test_default_spawns_eight_specialists(monkeypatch) -> None:
    captured = _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
    )
    assert out["success"] is True
    assert out["total_spawned"] == 8
    categories = [c["category"] for c in captured["calls"]]
    assert "authz-matrix-specialist" in categories
    assert "injection-specialist" in categories
    assert "xss-specialist" in categories
    assert "ssrf-scanner" in categories
    assert "idor-specialist" in categories
    assert "csrf-specialist" in categories
    assert "graphql-specialist" in categories
    assert "auth-attacker" in categories


def test_explicit_subset_spawned(monkeypatch) -> None:
    captured = _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        specialists="csrf-specialist,xss-specialist",
    )
    assert out["total_spawned"] == 2
    categories = [c["category"] for c in captured["calls"]]
    assert categories == ["csrf-specialist", "xss-specialist"]


def test_unknown_category_skipped(monkeypatch) -> None:
    _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        specialists="csrf-specialist,bogus-specialist,xss-specialist",
    )
    assert out["total_spawned"] == 2
    assert any(s["category"] == "bogus-specialist" for s in out["skipped"])


def test_duplicate_categories_deduped(monkeypatch) -> None:
    _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        specialists="csrf-specialist,csrf-specialist,csrf-specialist",
    )
    assert out["total_spawned"] == 1
    duplicates = [s for s in out["skipped"] if s["reason"] == "duplicate"]
    assert len(duplicates) == 2


def test_max_specialists_cap(monkeypatch) -> None:
    _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        max_specialists=3,
    )
    assert out["total_spawned"] == 3
    capped = [s for s in out["skipped"] if s["reason"] == "max_specialists cap"]
    assert len(capped) == 5  # 8 default - 3 spawned


# ---------------------------------------------------------------------------
# Surface-map auto-load
# ---------------------------------------------------------------------------


def test_surface_map_auto_loaded(monkeypatch, tmp_path) -> None:
    captured = _stub_create_agent(monkeypatch)
    tracer = tracer_module.get_global_tracer()
    run_dir = tracer.get_run_dir()
    _write_canonical_surface_map(run_dir)

    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        specialists="csrf-specialist",
    )
    assert out["surface_map_path"] is not None
    assert "webapp_surface_map.json" in out["surface_map_path"]

    # The summary block should be embedded in the spawned task.
    spawn_task = captured["calls"][0]["task"]
    assert "12" in spawn_task  # endpoints_discovered
    assert "OpenAPI" in spawn_task or "openapi" in spawn_task


def test_no_surface_map_still_spawns(monkeypatch, tmp_path) -> None:
    """Surface map missing → spawn proceeds with a (no map available)
    note."""
    captured = _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        specialists="csrf-specialist",
    )
    assert out["success"] is True
    assert out["surface_map_path"] is None
    spawn_task = captured["calls"][0]["task"]
    assert "no surface map" in spawn_task.lower() or "webapp_recon_pipeline" in spawn_task


# ---------------------------------------------------------------------------
# Spawn-failure resilience
# ---------------------------------------------------------------------------


def test_spawn_exception_swallowed(monkeypatch) -> None:
    """create_agent raising for one specialist doesn't break the others."""
    captured = {"calls": [], "fail_on": "csrf-specialist"}
    counter = {"i": 0}

    def fake_create(**kwargs):
        counter["i"] += 1
        captured["calls"].append(kwargs)
        if kwargs.get("category") == captured["fail_on"]:
            raise RuntimeError("simulated spawn failure")
        return {
            "success": True,
            "agent_id": f"agent_{counter['i']}",
            "agent_info": {"category": kwargs.get("category")},
        }

    monkeypatch.setattr(
        sys.modules["strix.tools.agents_graph.agents_graph_actions"],
        "create_agent", fake_create,
    )

    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        specialists="csrf-specialist,xss-specialist",
    )
    assert out["success"] is True
    assert out["total_spawned"] == 1
    assert any(
        s["category"] == "csrf-specialist" and "spawn_failed" in s["reason"]
        for s in out["skipped"]
    )


def test_spawn_returns_failure_recorded_in_skipped(monkeypatch) -> None:
    """create_agent returning success=False → recorded but doesn't break."""
    counter = {"i": 0}

    def fake_create(**kwargs):
        counter["i"] += 1
        if kwargs.get("category") == "csrf-specialist":
            return {"success": False, "error": "Invalid skills"}
        return {
            "success": True,
            "agent_id": f"agent_{counter['i']}",
            "agent_info": {"category": kwargs.get("category")},
        }

    monkeypatch.setattr(
        sys.modules["strix.tools.agents_graph.agents_graph_actions"],
        "create_agent", fake_create,
    )

    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        specialists="csrf-specialist,xss-specialist",
    )
    assert out["total_spawned"] == 1
    csrf_skip = [s for s in out["skipped"] if s["category"] == "csrf-specialist"]
    assert len(csrf_skip) == 1
    assert "Invalid skills" in csrf_skip[0]["reason"]


# ---------------------------------------------------------------------------
# inherit_context default
# ---------------------------------------------------------------------------


def test_inherit_context_defaults_false(monkeypatch) -> None:
    """Default inherit_context=False — specialists reason from the
    surface map, not the lead's chain-of-thought."""
    captured = _stub_create_agent(monkeypatch)
    _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        specialists="csrf-specialist",
    )
    assert captured["calls"][0]["inherit_context"] is False


def test_inherit_context_override(monkeypatch) -> None:
    captured = _stub_create_agent(monkeypatch)
    _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        specialists="csrf-specialist",
        inherit_context=True,
    )
    assert captured["calls"][0]["inherit_context"] is True


# ---------------------------------------------------------------------------
# Specialist registry — new categories
# ---------------------------------------------------------------------------


def test_new_specialist_categories_registered() -> None:
    """The §8.2 additions to the registry are present."""
    from strix.agents.specialists import get_specialist_profile

    for cat in [
        "authz-matrix-specialist",
        "injection-specialist",
        "graphql-specialist",
        "business-logic-specialist",
        "webapp-recon-lead",
    ]:
        p = get_specialist_profile(cat)
        assert p is not None, cat
        assert p.recommended_skills, cat
        assert p.scope_addendum, cat
        assert p.default_budget, cat


def test_authz_matrix_specialist_uses_authz_skills() -> None:
    from strix.agents.specialists import get_specialist_profile

    p = get_specialist_profile("authz-matrix-specialist")
    assert p is not None
    assert "broken_function_level_authorization" in p.recommended_skills


def test_injection_specialist_covers_multiple_classes() -> None:
    from strix.agents.specialists import get_specialist_profile

    p = get_specialist_profile("injection-specialist")
    assert p is not None
    skills = p.recommended_skills
    # Broader than sqli-specialist
    assert "sql_injection" in skills
    assert "rce" in skills
    assert "path_traversal_lfi_rfi" in skills


def test_graphql_specialist_uses_graphql_skill() -> None:
    from strix.agents.specialists import get_specialist_profile

    p = get_specialist_profile("graphql-specialist")
    assert p is not None
    assert p.recommended_skills == "graphql"


def test_business_logic_specialist_includes_race() -> None:
    from strix.agents.specialists import get_specialist_profile

    p = get_specialist_profile("business-logic-specialist")
    assert p is not None
    assert "business_logic" in p.recommended_skills
    assert "race_conditions" in p.recommended_skills


def test_webapp_recon_lead_doesnt_have_exploit_skills() -> None:
    """Recon lead doesn't probe vulnerabilities — its scope is
    Decide-stage routing only."""
    from strix.agents.specialists import get_specialist_profile

    p = get_specialist_profile("webapp-recon-lead")
    assert p is not None
    skills = p.recommended_skills
    # No exploit skills
    for forbidden in ("sql_injection", "xss", "ssrf", "csrf", "idor"):
        assert forbidden not in skills, f"recon lead has {forbidden}"


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        specialists="csrf-specialist",
    )
    assert set(out.keys()) >= {
        "success", "target_url", "target_host", "surface_map_path",
        "spawned", "skipped", "total_spawned", "max_specialists", "message",
    }


def test_each_spawn_record_has_agent_id(monkeypatch) -> None:
    _stub_create_agent(monkeypatch)
    out = _spawn()(
        agent_state=_make_agent_state(),
        target_url="https://app.example.com",
        specialists="csrf-specialist,xss-specialist",
    )
    for record in out["spawned"]:
        assert record["agent_id"]
        assert record["category"]
        assert record["name"]
