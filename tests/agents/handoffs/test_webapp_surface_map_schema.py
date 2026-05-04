"""Tests for the webapp_surface_map.json handoff schema (§8.2 / §8.0).

Mirrors the surface_map.json test pattern from #87.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.agents.handoffs.webapp_surface_map import (
    WebappSurfaceMapViolation,
    has_canonical_errors,
    load_webapp_surface_map,
    validate_webapp_surface_map,
)


def _canonical(**overrides: Any) -> dict[str, Any]:
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
        },
        "endpoints": ["https://app.example.com/login", "https://app.example.com/api"],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Pure validator
# ---------------------------------------------------------------------------


def test_canonical_no_violations() -> None:
    assert validate_webapp_surface_map(_canonical()) == []


def test_not_dict() -> None:
    out = validate_webapp_surface_map("not a dict")  # type: ignore[arg-type]
    assert any(v.code == "webapp_surface_map.not_dict" for v in out)


def test_missing_schema_version() -> None:
    sm = _canonical()
    del sm["schema_version"]
    out = validate_webapp_surface_map(sm)
    assert any(v.code == "webapp_surface_map.missing.schema_version" for v in out)


def test_invalid_schema_version() -> None:
    out = validate_webapp_surface_map(_canonical(schema_version=99))
    assert any(v.code == "webapp_surface_map.schema_version.invalid" for v in out)


def test_schema_version_wrong_type() -> None:
    out = validate_webapp_surface_map(_canonical(schema_version="1"))
    assert any(v.code == "webapp_surface_map.schema_version.invalid" for v in out)


def test_missing_target_url() -> None:
    sm = _canonical()
    del sm["target_url"]
    out = validate_webapp_surface_map(sm)
    assert any(v.code == "webapp_surface_map.missing.target_url" for v in out)


def test_invalid_target_url() -> None:
    out = validate_webapp_surface_map(_canonical(target_url=""))
    assert any(v.code == "webapp_surface_map.target_url.invalid_type" for v in out)
    out = validate_webapp_surface_map(_canonical(target_url=123))
    assert any(v.code == "webapp_surface_map.target_url.invalid_type" for v in out)


def test_missing_target_host() -> None:
    sm = _canonical()
    del sm["target_host"]
    out = validate_webapp_surface_map(sm)
    assert any(v.code == "webapp_surface_map.missing.target_host" for v in out)


def test_missing_generated_at() -> None:
    sm = _canonical()
    del sm["generated_at"]
    out = validate_webapp_surface_map(sm)
    assert any(v.code == "webapp_surface_map.missing.generated_at" for v in out)


def test_invalid_generated_at_type() -> None:
    out = validate_webapp_surface_map(_canonical(generated_at="not-a-date"))
    assert any(v.code == "webapp_surface_map.generated_at.invalid_type" for v in out)


def test_z_suffix_accepted() -> None:
    out = validate_webapp_surface_map(_canonical(generated_at="2026-05-04T12:00:00Z"))
    assert not any(v.code == "webapp_surface_map.generated_at.invalid_type" for v in out)


def test_missing_summary() -> None:
    sm = _canonical()
    del sm["summary"]
    out = validate_webapp_surface_map(sm)
    assert any(v.code == "webapp_surface_map.missing.summary" for v in out)


def test_summary_missing_counters_warns() -> None:
    out = validate_webapp_surface_map(_canonical(summary={"endpoints_discovered": 0}))
    counter_warns = [v for v in out if v.code == "webapp_surface_map.summary.missing_counters"]
    assert len(counter_warns) == 1
    assert counter_warns[0].severity == "warn"


def test_endpoints_invalid_shape() -> None:
    out = validate_webapp_surface_map(_canonical(endpoints=[1, 2, 3]))
    assert any(v.code == "webapp_surface_map.endpoints.invalid_shape" for v in out)


def test_has_canonical_errors_filters_warns() -> None:
    warn_only = [WebappSurfaceMapViolation(
        code="x", field="x", message="x", severity="warn",
    )]
    err = warn_only + [
        WebappSurfaceMapViolation(code="y", field="y", message="y", severity="error"),
    ]
    assert has_canonical_errors(warn_only) is False
    assert has_canonical_errors(err) is True


# ---------------------------------------------------------------------------
# load_webapp_surface_map
# ---------------------------------------------------------------------------


def test_load_canonical(tmp_path) -> None:
    p = tmp_path / "webapp_surface_map.json"
    p.write_text(json.dumps(_canonical()))
    data, violations = load_webapp_surface_map(p)
    assert data is not None
    assert violations == []


def test_load_missing_file(tmp_path) -> None:
    data, violations = load_webapp_surface_map(tmp_path / "absent.json")
    assert data is None
    assert any(v.code == "webapp_surface_map.not_dict" for v in violations)


def test_load_malformed_json(tmp_path) -> None:
    p = tmp_path / "broken.json"
    p.write_text("not json {")
    data, violations = load_webapp_surface_map(p)
    assert data is None
    assert any(v.code == "webapp_surface_map.not_dict" for v in violations)
