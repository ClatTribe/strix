"""Tests for score_reachability (roadmap §7.1).

Hermetic — uses tmp_path with synthetic repos + code_map.json
fixtures. Tests cover:

- Dead-code findings (test-only files, isolated files) → score=0,
  severity demoted to info
- Route-reachable findings → score=1.0, severity unchanged
- Auth-path adjacent findings → severity bumped one notch
- Non-test referrer (transitive reachability) → score=0.5
- Distance decay (route → imported → imported again)
- code_map.json missing → graceful failure
- Findings without code_locations → skipped with reason
- finding.reachability_scored event emitted
- Helpers: _score_for_file ladder, severity adjustment
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.reachability.reachability import (
    _adjust_finding_severity,
    _is_test_file,
    _score_for_file,
    score_reachability,
)


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
    tracer = Tracer("rs-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "repository", "value": str(tmp_path)}]}
    )
    yield


def _emit_taint_finding(
    tracer: Tracer, *, file: str, line: int = 42, severity: str = "high",
) -> str:
    return tracer.add_vulnerability_report(
        title=f"Taint flow at {file}:{line}",
        severity=severity,
        category="taint_flow",
        cwe="CWE-20",
        endpoint=f"{file}:{line}",
        verification_status="pattern_match",
        description_plain="p", recommended_action="a",
        code_locations=[{"file": file, "line": line}],
    )


def _make_repo_with_code_map(
    tmp_path: Path,
    files: dict[str, str],
    code_map_overrides: dict[str, Any] | None = None,
) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    for rel, content in files.items():
        full = repo / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content)

    base_cm: dict[str, Any] = {
        "schema_version": 1,
        "repo_path": str(repo),
        "repo_name": "repo",
        "generated_at": "2026-05-04T12:00:00+00:00",
        "summary": {
            "files_scanned": len(files),
            "routes_discovered": 0,
            "models_discovered": 0,
            "db_queries_discovered": 0,
            "external_http_calls_discovered": 0,
            "auth_boundaries_discovered": 0,
        },
        "routes": [],
        "models": [],
        "db_queries": [],
        "external_http_calls": [],
        "auth_boundaries": [],
    }
    if code_map_overrides:
        base_cm.update(code_map_overrides)

    cm_path = tmp_path / "strix_runs" / "rs-test" / "code_map.json"
    cm_path.parent.mkdir(parents=True, exist_ok=True)
    cm_path.write_text(json.dumps(base_cm))
    return repo


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_is_test_file_canonical_paths() -> None:
    assert _is_test_file("tests/test_foo.py") is True
    assert _is_test_file("test/foo.py") is True
    assert _is_test_file("__tests__/Component.test.tsx") is True
    assert _is_test_file("spec/models_spec.rb") is True
    assert _is_test_file("foo/bar/test_baz.py") is True


def test_is_test_file_non_test_paths() -> None:
    assert _is_test_file("src/app.py") is False
    assert _is_test_file("lib/util.js") is False
    assert _is_test_file("models/user.py") is False


def test_score_route_reachable_direct() -> None:
    score, evidence = _score_for_file(
        "src/auth.py",
        route_reachable_distance=0,
        non_test_referrers=set(),
        auth_path_files=set(),
    )
    assert score == 1.0
    assert evidence["route_distance"] == 0


def test_score_dead_code_zero() -> None:
    score, _ = _score_for_file(
        "src/dead.py",
        route_reachable_distance=None,
        non_test_referrers=set(),
        auth_path_files=set(),
    )
    assert score == 0.0


def test_score_test_file_zero() -> None:
    score, evidence = _score_for_file(
        "tests/test_app.py",
        route_reachable_distance=None,
        non_test_referrers={"src/app.py"},
        auth_path_files=set(),
    )
    assert score == 0.0
    assert evidence["in_test_path"] is True


def test_score_non_test_referrer_only_half() -> None:
    score, _ = _score_for_file(
        "src/util.py",
        route_reachable_distance=None,
        non_test_referrers={"src/app.py"},
        auth_path_files=set(),
    )
    assert score == 0.5


def test_score_distance_decay() -> None:
    s0, _ = _score_for_file("a.py", route_reachable_distance=0, non_test_referrers=set(), auth_path_files=set())
    s1, _ = _score_for_file("a.py", route_reachable_distance=1, non_test_referrers=set(), auth_path_files=set())
    s2, _ = _score_for_file("a.py", route_reachable_distance=2, non_test_referrers=set(), auth_path_files=set())
    assert s0 > s1 > s2


def test_score_auth_adjacency_clamps_to_one() -> None:
    score, evidence = _score_for_file(
        "src/auth.py",
        route_reachable_distance=2,  # would normally be 0.7
        non_test_referrers=set(),
        auth_path_files={"src/auth.py"},
    )
    assert score == 1.0
    assert evidence["auth_path_adjacent"] is True


def test_severity_demote_on_dead_code() -> None:
    finding = {"severity": "medium"}
    new_sev, field = _adjust_finding_severity(finding, score=0.0, auth_adjacent=False)
    assert new_sev == "info"
    assert field == "severity_demoted_from"


def test_severity_promote_on_auth_path() -> None:
    finding = {"severity": "medium"}
    new_sev, field = _adjust_finding_severity(finding, score=1.0, auth_adjacent=True)
    assert new_sev == "high"
    assert field == "severity_promoted_from_reachability"


def test_severity_no_change_route_reachable_normal() -> None:
    finding = {"severity": "medium"}
    new_sev, field = _adjust_finding_severity(finding, score=1.0, auth_adjacent=False)
    assert new_sev is None
    assert field is None


# ---------------------------------------------------------------------------
# End-to-end: dead code finding → demoted
# ---------------------------------------------------------------------------


def test_dead_code_finding_demoted_to_info(tmp_path) -> None:
    repo = _make_repo_with_code_map(
        tmp_path,
        files={
            "src/app.py": (
                "from flask import Flask\n"
                "from src.dead import unused\n"  # imports dead.py
                "@app.route('/api')\n"
                "def handler(): return 'ok'\n"
            ),
            "src/dead.py": "def unused(): pass\n# Has SQLi here\n",
            "src/totally_isolated.py": "def really_dead(): pass\n",
        },
        code_map_overrides={
            "routes": [{"framework": "flask", "method": "GET", "path": "/api",
                        "file": "src/app.py", "line": 3}],
            "summary": {
                "files_scanned": 3, "routes_discovered": 1, "models_discovered": 0,
                "db_queries_discovered": 0, "external_http_calls_discovered": 0,
                "auth_boundaries_discovered": 0,
            },
        },
    )

    tracer = tracer_module.get_global_tracer()
    rid = _emit_taint_finding(
        tracer, file="src/totally_isolated.py", severity="high",
    )

    out = score_reachability(repo_path=str(repo))
    assert out["success"] is True
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["severity"] == "info"
    assert findings[0]["severity_demoted_from"] == "high"
    assert findings[0]["reachability_score"] == 0.0


def test_route_reachable_finding_keeps_severity(tmp_path) -> None:
    repo = _make_repo_with_code_map(
        tmp_path,
        files={
            "src/app.py": (
                "@app.route('/api/users')\n"
                "def list_users():\n"
                "    return query_users()\n"
            ),
        },
        code_map_overrides={
            "routes": [{"framework": "flask", "method": "GET", "path": "/api/users",
                        "file": "src/app.py", "line": 1}],
            "summary": {
                "files_scanned": 1, "routes_discovered": 1, "models_discovered": 0,
                "db_queries_discovered": 0, "external_http_calls_discovered": 0,
                "auth_boundaries_discovered": 0,
            },
        },
    )

    tracer = tracer_module.get_global_tracer()
    rid = _emit_taint_finding(tracer, file="src/app.py", severity="high")

    out = score_reachability(repo_path=str(repo))
    assert out["success"] is True
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["severity"] == "high"  # unchanged
    assert findings[0]["reachability_score"] == 1.0


def test_auth_path_finding_promoted(tmp_path) -> None:
    repo = _make_repo_with_code_map(
        tmp_path,
        files={
            "src/auth.py": (
                "@login_required\n"
                "def authenticated_endpoint():\n"
                "    pass\n"
            ),
        },
        code_map_overrides={
            "routes": [{"framework": "flask", "method": "GET", "path": "/x",
                        "file": "src/auth.py", "line": 2}],
            "auth_boundaries": [{
                "kind": "python_decorator", "marker": "login_required",
                "file": "src/auth.py", "line": 1,
            }],
            "summary": {
                "files_scanned": 1, "routes_discovered": 1, "models_discovered": 0,
                "db_queries_discovered": 0, "external_http_calls_discovered": 0,
                "auth_boundaries_discovered": 1,
            },
        },
    )

    tracer = tracer_module.get_global_tracer()
    _emit_taint_finding(tracer, file="src/auth.py", severity="medium")

    score_reachability(repo_path=str(repo))
    findings = tracer.get_existing_vulnerabilities()
    # medium → high (auth-path bump)
    assert findings[0]["severity"] == "high"
    assert findings[0]["severity_promoted_from_reachability"] == "medium"


def test_test_file_finding_demoted(tmp_path) -> None:
    """A finding in tests/ → reachability=0 → severity=info."""
    repo = _make_repo_with_code_map(
        tmp_path,
        files={
            "src/app.py": "@app.route('/api')\ndef h(): pass\n",
            "tests/test_evil.py": "import os\nos.system('rm -rf /')  # evil but in tests\n",
        },
        code_map_overrides={
            "routes": [{"framework": "flask", "method": "GET", "path": "/api",
                        "file": "src/app.py", "line": 1}],
            "summary": {
                "files_scanned": 2, "routes_discovered": 1, "models_discovered": 0,
                "db_queries_discovered": 0, "external_http_calls_discovered": 0,
                "auth_boundaries_discovered": 0,
            },
        },
    )

    tracer = tracer_module.get_global_tracer()
    _emit_taint_finding(
        tracer, file="tests/test_evil.py", severity="critical",
    )

    score_reachability(repo_path=str(repo))
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["severity"] == "info"
    assert findings[0]["severity_demoted_from"] == "critical"


# ---------------------------------------------------------------------------
# Skip cases
# ---------------------------------------------------------------------------


def test_finding_without_code_locations_skipped(tmp_path) -> None:
    repo = _make_repo_with_code_map(tmp_path, {"app.py": "x = 1\n"})

    tracer = tracer_module.get_global_tracer()
    tracer.add_vulnerability_report(
        title="No code locations",
        severity="medium",
        category="taint_flow",
        cwe="CWE-20",
        endpoint="https://app.example.com",  # web finding, no file
        verification_status="pattern_match",
        description_plain="p", recommended_action="a",
    )

    out = score_reachability(repo_path=str(repo))
    assert any(s["reason"] == "no_code_locations" for s in out["skipped"])


def test_missing_code_map_returns_error(tmp_path, monkeypatch) -> None:
    """No code_map.json in run dir → success=False."""
    out = score_reachability(repo_path=str(tmp_path))
    assert out["success"] is False
    assert "code_map.json" in out["error"]


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------


def test_reachability_scored_event_emitted(tmp_path) -> None:
    repo = _make_repo_with_code_map(
        tmp_path,
        files={"src/app.py": "@app.route('/x')\ndef h(): pass\n"},
        code_map_overrides={
            "routes": [{"framework": "flask", "method": "GET", "path": "/x",
                        "file": "src/app.py", "line": 1}],
            "summary": {
                "files_scanned": 1, "routes_discovered": 1, "models_discovered": 0,
                "db_queries_discovered": 0, "external_http_calls_discovered": 0,
                "auth_boundaries_discovered": 0,
            },
        },
    )
    tracer = tracer_module.get_global_tracer()
    _emit_taint_finding(tracer, file="src/app.py")

    score_reachability(repo_path=str(repo))

    events_file = tmp_path / "strix_runs" / "rs-test" / "events.jsonl"
    events = [
        json.loads(l) for l in events_file.read_text().splitlines() if l.strip()
    ]
    rs_events = [
        e for e in events
        if (e.get("event_type") or e.get("event")) == "finding.reachability_scored"
    ]
    assert len(rs_events) == 1


# ---------------------------------------------------------------------------
# finding_ids filter
# ---------------------------------------------------------------------------


def test_finding_ids_filter(tmp_path) -> None:
    repo = _make_repo_with_code_map(
        tmp_path,
        files={"src/app.py": "@app.route('/x')\ndef h(): pass\n"},
        code_map_overrides={
            "routes": [{"framework": "flask", "method": "GET", "path": "/x",
                        "file": "src/app.py", "line": 1}],
            "summary": {
                "files_scanned": 1, "routes_discovered": 1, "models_discovered": 0,
                "db_queries_discovered": 0, "external_http_calls_discovered": 0,
                "auth_boundaries_discovered": 0,
            },
        },
    )
    tracer = tracer_module.get_global_tracer()
    rid_a = _emit_taint_finding(tracer, file="src/app.py", line=1)
    rid_b = _emit_taint_finding(tracer, file="src/app.py", line=2)

    out = score_reachability(repo_path=str(repo), finding_ids=rid_a)
    assert out["processed_count"] == 1
    assert out["scored"][0]["report_id"] == rid_a


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def test_mitre_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    techniques = get_tool_mitre_techniques("score_reachability")
    assert "T1592" in techniques
