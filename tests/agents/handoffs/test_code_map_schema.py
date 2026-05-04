"""Tests for the code_map.json handoff schema (§8.1 / §8.0).

Mirrors the surface_map.json + webapp_surface_map.json patterns.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.agents.handoffs.code_map import (
    CodeMapViolation,
    has_canonical_errors,
    load_code_map,
    validate_code_map,
)


def _canonical(**overrides: Any) -> dict[str, Any]:
    base = {
        "schema_version": 1,
        "repo_path": "/path/to/repo",
        "repo_name": "repo",
        "generated_at": "2026-05-04T12:00:00+00:00",
        "summary": {
            "files_scanned": 100,
            "routes_discovered": 12,
            "models_discovered": 5,
            "db_queries_discovered": 30,
            "external_http_calls_discovered": 8,
            "auth_boundaries_discovered": 3,
        },
        "routes": [
            {"framework": "flask", "path": "/api/users", "file": "app.py", "line": 42},
        ],
        "models": [
            {"name": "User", "framework": "sqlalchemy", "file": "models.py", "line": 10},
        ],
        "db_queries": [
            {"kind": "raw_sql", "file": "service.py", "line": 50},
        ],
        "external_http_calls": [
            {"library": "python_requests", "file": "client.py", "line": 80},
        ],
        "auth_boundaries": [
            {"kind": "python_decorator", "file": "views.py", "line": 30},
        ],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Pure validator
# ---------------------------------------------------------------------------


def test_canonical_no_violations() -> None:
    assert validate_code_map(_canonical()) == []


def test_not_dict() -> None:
    out = validate_code_map("not a dict")  # type: ignore[arg-type]
    assert any(v.code == "code_map.not_dict" for v in out)


def test_missing_schema_version() -> None:
    sm = _canonical()
    del sm["schema_version"]
    out = validate_code_map(sm)
    assert any(v.code == "code_map.missing.schema_version" for v in out)


def test_invalid_schema_version() -> None:
    out = validate_code_map(_canonical(schema_version=99))
    assert any(v.code == "code_map.schema_version.invalid" for v in out)


def test_schema_version_wrong_type() -> None:
    out = validate_code_map(_canonical(schema_version="1"))
    assert any(v.code == "code_map.schema_version.invalid" for v in out)


def test_missing_repo_path() -> None:
    sm = _canonical()
    del sm["repo_path"]
    out = validate_code_map(sm)
    assert any(v.code == "code_map.missing.repo_path" for v in out)


def test_invalid_repo_path() -> None:
    out = validate_code_map(_canonical(repo_path=""))
    assert any(v.code == "code_map.repo_path.invalid_type" for v in out)
    out = validate_code_map(_canonical(repo_path=123))
    assert any(v.code == "code_map.repo_path.invalid_type" for v in out)


def test_missing_generated_at() -> None:
    sm = _canonical()
    del sm["generated_at"]
    out = validate_code_map(sm)
    assert any(v.code == "code_map.missing.generated_at" for v in out)


def test_invalid_generated_at_type() -> None:
    out = validate_code_map(_canonical(generated_at="not-a-date"))
    assert any(v.code == "code_map.generated_at.invalid_type" for v in out)


def test_z_suffix_accepted() -> None:
    out = validate_code_map(_canonical(generated_at="2026-05-04T12:00:00Z"))
    assert not any(v.code == "code_map.generated_at.invalid_type" for v in out)


def test_missing_summary() -> None:
    sm = _canonical()
    del sm["summary"]
    out = validate_code_map(sm)
    assert any(v.code == "code_map.missing.summary" for v in out)


def test_summary_missing_counters_warns() -> None:
    out = validate_code_map(_canonical(summary={"files_scanned": 0}))
    counter_warns = [v for v in out if v.code == "code_map.summary.missing_counters"]
    assert len(counter_warns) == 1
    assert counter_warns[0].severity == "warn"


# ---------------------------------------------------------------------------
# Per-array record shape
# ---------------------------------------------------------------------------


def test_routes_invalid_shape_not_list() -> None:
    out = validate_code_map(_canonical(routes="not-a-list"))
    assert any(v.code == "code_map.routes.invalid_shape" for v in out)


def test_routes_invalid_shape_missing_keys() -> None:
    out = validate_code_map(_canonical(routes=[{"framework": "flask"}]))
    assert any(v.code == "code_map.routes.invalid_shape" for v in out)


def test_models_invalid_shape() -> None:
    out = validate_code_map(_canonical(models=[{"name": "User"}]))
    assert any(v.code == "code_map.models.invalid_shape" for v in out)


def test_db_queries_invalid_shape() -> None:
    out = validate_code_map(_canonical(db_queries=[{"file": "x"}]))
    assert any(v.code == "code_map.db_queries.invalid_shape" for v in out)


def test_external_http_calls_invalid_shape() -> None:
    out = validate_code_map(_canonical(external_http_calls=[{"foo": "bar"}]))
    assert any(v.code == "code_map.external_http_calls.invalid_shape" for v in out)


def test_auth_boundaries_invalid_shape() -> None:
    out = validate_code_map(_canonical(auth_boundaries=["not-a-dict"]))
    assert any(v.code == "code_map.auth_boundaries.invalid_shape" for v in out)


def test_empty_arrays_accepted() -> None:
    """All arrays empty → still canonical (e.g. for a brand-new repo)."""
    out = validate_code_map(_canonical(
        routes=[], models=[], db_queries=[],
        external_http_calls=[], auth_boundaries=[],
    ))
    errors = [v for v in out if v.severity == "error"]
    assert errors == []


# ---------------------------------------------------------------------------
# has_canonical_errors
# ---------------------------------------------------------------------------


def test_has_canonical_errors_filters_warns() -> None:
    warn_only = [CodeMapViolation(code="x", field="x", message="x", severity="warn")]
    err = warn_only + [
        CodeMapViolation(code="y", field="y", message="y", severity="error"),
    ]
    assert has_canonical_errors(warn_only) is False
    assert has_canonical_errors(err) is True


# ---------------------------------------------------------------------------
# load_code_map
# ---------------------------------------------------------------------------


def test_load_canonical(tmp_path) -> None:
    p = tmp_path / "code_map.json"
    p.write_text(json.dumps(_canonical()))
    data, violations = load_code_map(p)
    assert data is not None
    assert violations == []


def test_load_missing_file(tmp_path) -> None:
    data, violations = load_code_map(tmp_path / "absent.json")
    assert data is None
    assert any(v.code == "code_map.not_dict" for v in violations)


def test_load_malformed_json(tmp_path) -> None:
    p = tmp_path / "broken.json"
    p.write_text("not json {")
    data, violations = load_code_map(p)
    assert data is None
    assert any(v.code == "code_map.not_dict" for v in violations)
