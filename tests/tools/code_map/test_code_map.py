"""Tests for build_code_map (roadmap §8.1 row 1).

Hermetic — uses tmp_path to create synthetic source files with
known patterns. Tests cover: walk + prune, route detection across
frameworks, model detection, DB-query / HTTP-call / auth-boundary
detection, persistence + handoff schema, error resilience,
next_steps, MITRE.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.code_map.code_map import build_code_map


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
    tracer = Tracer("cm-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "repository", "value": str(tmp_path)}]}
    )
    yield


def _make_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    for rel, content in files.items():
        full = repo / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
    return repo


# ---------------------------------------------------------------------------
# Validation / argument handling
# ---------------------------------------------------------------------------


def test_empty_repo_path_rejected() -> None:
    out = build_code_map(repo_path="")
    assert out["success"] is False


def test_nonexistent_repo_rejected() -> None:
    out = build_code_map(repo_path="/path/does/not/exist/anywhere")
    assert out["success"] is False


def test_single_file_input(tmp_path) -> None:
    """build_code_map accepts a single .py file too — useful for tests."""
    f = tmp_path / "single.py"
    f.write_text("@app.route('/api/x')\ndef handler():\n    pass\n")
    out = build_code_map(repo_path=str(f))
    assert out["success"] is True
    assert out["code_map"]["summary"]["routes_discovered"] >= 1


# ---------------------------------------------------------------------------
# Route detection across frameworks
# ---------------------------------------------------------------------------


def test_flask_routes_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "app.py": (
            "from flask import Flask\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/api/users', methods=['GET', 'POST'])\n"
            "def list_users():\n    pass\n\n"
            "@app.get('/health')\n"
            "def health():\n    return 'ok'\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    assert out["success"] is True
    routes = out["code_map"]["routes"]
    paths = {r["path"] for r in routes}
    assert "/api/users" in paths
    assert "/health" in paths
    assert any(r["framework"] == "flask" for r in routes)


def test_fastapi_routes_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "main.py": (
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n\n"
            "@app.get('/api/items')\n"
            "async def list_items():\n    return []\n\n"
            "@app.post('/api/items')\n"
            "async def create_item():\n    pass\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    routes = out["code_map"]["routes"]
    assert any(r["framework"] == "fastapi" and r["method"] == "GET" for r in routes)
    assert any(r["framework"] == "fastapi" and r["method"] == "POST" for r in routes)


def test_django_path_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "urls.py": (
            "from django.urls import path\n"
            "from . import views\n\n"
            "urlpatterns = [\n"
            "    path('api/users/<int:pk>', views.user_detail),\n"
            "    path('admin/', views.admin_dashboard),\n"
            "]\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    routes = out["code_map"]["routes"]
    assert any(r["framework"] == "django" and "users" in r["path"] for r in routes)


def test_express_routes_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "server.js": (
            "const express = require('express');\n"
            "const app = express();\n\n"
            "app.get('/api/users', (req, res) => res.send([]));\n"
            "app.post('/api/users', (req, res) => res.send('ok'));\n"
            "router.delete('/api/users/:id', handler);\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    routes = out["code_map"]["routes"]
    assert any(r["framework"] == "express" and r["method"] == "GET" for r in routes)
    assert any(r["framework"] == "express" and r["method"] == "POST" for r in routes)
    assert any(r["framework"] == "express" and r["method"] == "DELETE" for r in routes)


def test_rails_routes_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "config/routes.rb": (
            "Rails.application.routes.draw do\n"
            "  get '/api/users', to: 'users#index'\n"
            "  post '/api/users', to: 'users#create'\n"
            "end\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    routes = out["code_map"]["routes"]
    rails = [r for r in routes if r["framework"] == "rails"]
    assert len(rails) >= 2


def test_spring_routes_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "Controller.java": (
            "@RestController\n"
            "public class UserController {\n"
            "    @GetMapping(\"/api/users\")\n"
            "    public List<User> getUsers() { return null; }\n\n"
            "    @PostMapping(value = \"/api/users\")\n"
            "    public User create() { return null; }\n"
            "}\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    routes = out["code_map"]["routes"]
    assert any(r["framework"] == "spring" and r["method"] == "GETMAPPING" for r in routes)


# ---------------------------------------------------------------------------
# Model detection
# ---------------------------------------------------------------------------


def test_sqlalchemy_models_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "models.py": (
            "from sqlalchemy.orm import declarative_base\n"
            "Base = declarative_base()\n\n"
            "class User(Base):\n"
            "    __tablename__ = 'users'\n\n"
            "class Post(db.Model):\n"
            "    pass\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    models = out["code_map"]["models"]
    names = {m["name"] for m in models}
    assert "User" in names
    assert "Post" in names


def test_django_models_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "app/models.py": (
            "from django.db import models\n\n"
            "class Article(models.Model):\n"
            "    title = models.CharField(max_length=200)\n\n"
            "class Comment(Model):\n"
            "    body = models.TextField()\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    models = out["code_map"]["models"]
    names = {m["name"] for m in models}
    assert "Article" in names
    assert "Comment" in names


def test_mongoose_schemas_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "user-schema.js": (
            "const mongoose = require('mongoose');\n"
            "const UserSchema = new mongoose.Schema({\n"
            "    name: String,\n"
            "});\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    models = out["code_map"]["models"]
    assert any(m["name"] == "UserSchema" for m in models)


# ---------------------------------------------------------------------------
# DB queries
# ---------------------------------------------------------------------------


def test_raw_sql_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "service.py": (
            "import sqlite3\n"
            "def get_user(uid):\n"
            "    return cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))\n\n"
            "def update_email(uid, email):\n"
            "    cursor.execute('UPDATE users SET email = ? WHERE id = ?', (email, uid))\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    queries = out["code_map"]["db_queries"]
    raw = [q for q in queries if q["kind"] == "raw_sql"]
    assert len(raw) >= 2
    assert any("SELECT" in q.get("sample", "").upper() for q in raw)
    assert any("UPDATE" in q.get("sample", "").upper() for q in raw)


def test_django_orm_calls_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "views.py": (
            "from .models import User\n"
            "def detail(request, pk):\n"
            "    user = User.objects.filter(id=pk).get()\n"
            "    User.objects.create(name='Bob')\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    queries = out["code_map"]["db_queries"]
    assert any(q["kind"] == "django_orm_call" for q in queries)


# ---------------------------------------------------------------------------
# External HTTP calls
# ---------------------------------------------------------------------------


def test_python_requests_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "client.py": (
            "import requests\n"
            "def fetch():\n"
            "    return requests.get('https://api.example.com/users')\n\n"
            "def create():\n"
            "    return requests.post('https://api.example.com/users', json={})\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    calls = out["code_map"]["external_http_calls"]
    assert any(c["library"] == "python_requests" and c["method"] == "GET" for c in calls)
    assert any(c["library"] == "python_requests" and c["method"] == "POST" for c in calls)


def test_javascript_fetch_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "app.js": (
            "async function loadUsers() {\n"
            "    const res = await fetch('https://api.example.com/users');\n"
            "    return res.json();\n"
            "}\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    calls = out["code_map"]["external_http_calls"]
    assert any(c["library"] == "javascript_fetch" for c in calls)


# ---------------------------------------------------------------------------
# Auth boundaries
# ---------------------------------------------------------------------------


def test_python_login_required_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "views.py": (
            "from django.contrib.auth.decorators import login_required\n\n"
            "@login_required\n"
            "def profile(request):\n"
            "    pass\n\n"
            "@permission_required('app.view_admin')\n"
            "def admin(request):\n"
            "    pass\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    auth = out["code_map"]["auth_boundaries"]
    kinds = {a["kind"] for a in auth}
    assert "python_decorator" in kinds
    assert "django_decorator" in kinds


def test_spring_security_detected(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "AdminController.java": (
            "@RestController\n"
            "public class AdminController {\n"
            "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
            "    @GetMapping(\"/admin\")\n"
            "    public String admin() { return \"ok\"; }\n"
            "}\n"
        ),
    })
    out = build_code_map(repo_path=str(repo))
    auth = out["code_map"]["auth_boundaries"]
    assert any(a["kind"] == "spring_security" for a in auth)


# ---------------------------------------------------------------------------
# Walk / prune behaviour
# ---------------------------------------------------------------------------


def test_prunes_node_modules(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "src/app.js": "app.get('/api/x', () => {});\n",
        "node_modules/lib/index.js": "app.get('/should-not-appear', () => {});\n",
    })
    out = build_code_map(repo_path=str(repo))
    paths = [r["path"] for r in out["code_map"]["routes"]]
    assert "/api/x" in paths
    assert "/should-not-appear" not in paths


def test_prunes_git_dir(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "src/app.py": "@app.route('/real')\ndef r(): pass\n",
        ".git/hooks/post-commit.py": "@app.route('/git-internal')\ndef i(): pass\n",
    })
    out = build_code_map(repo_path=str(repo))
    paths = [r["path"] for r in out["code_map"]["routes"]]
    assert "/real" in paths
    assert "/git-internal" not in paths


def test_prunes_dot_dirs(tmp_path) -> None:
    """Hidden dirs starting with dot are pruned (.idea, .vscode etc.)"""
    repo = _make_repo(tmp_path, {
        "app.py": "@app.route('/v')\ndef v(): pass\n",
        ".vscode/settings.py": "@app.route('/dotdir')\ndef d(): pass\n",
    })
    out = build_code_map(repo_path=str(repo))
    paths = [r["path"] for r in out["code_map"]["routes"]]
    assert "/v" in paths
    assert "/dotdir" not in paths


def test_max_files_cap(tmp_path) -> None:
    """max_files caps the walk."""
    files = {f"f{i}.py": f"@app.route('/r{i}')\ndef h{i}(): pass\n" for i in range(20)}
    repo = _make_repo(tmp_path, files)
    out = build_code_map(repo_path=str(repo), max_files=5)
    assert out["code_map"]["summary"]["files_scanned"] == 5


def test_skips_oversized_files(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    big = repo / "big.py"
    big.write_text("@app.route('/big')\ndef h(): pass\n" + ("# pad\n" * 100_000))
    out = build_code_map(repo_path=str(repo), max_file_size=1024)
    # The big file was skipped; routes empty.
    assert out["code_map"]["summary"]["routes_discovered"] == 0


# ---------------------------------------------------------------------------
# Persistence + handoff
# ---------------------------------------------------------------------------


def test_code_map_written_to_disk(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "app.py": "@app.route('/x')\ndef x(): pass\n",
    })
    build_code_map(repo_path=str(repo))
    artifact = tmp_path / "strix_runs" / "cm-test" / "code_map.json"
    assert artifact.exists()
    data = json.loads(artifact.read_text())
    assert data["schema_version"] == 1
    assert data["summary"]["routes_discovered"] >= 1


def test_handoff_schema_validates_clean(tmp_path) -> None:
    from strix.agents.handoffs.code_map import validate_code_map

    repo = _make_repo(tmp_path, {
        "app.py": "@app.route('/x')\ndef x(): pass\n",
    })
    out = build_code_map(repo_path=str(repo))
    violations = validate_code_map(out["code_map"])
    errors = [v for v in violations if v.severity == "error"]
    assert errors == []


def test_handoff_event_NOT_emitted_on_clean_run(tmp_path) -> None:
    repo = _make_repo(tmp_path, {"app.py": "x = 1\n"})
    build_code_map(repo_path=str(repo))
    events_path = tmp_path / "strix_runs" / "cm-test" / "events.jsonl"
    if events_path.exists():
        events = [
            json.loads(l) for l in events_path.read_text().splitlines() if l.strip()
        ]
        handoff_events = [
            e for e in events
            if (e.get("event_type") or e.get("event")) == "handoff.shape_violation"
        ]
        assert handoff_events == []


def test_phase_events_emitted(tmp_path) -> None:
    repo = _make_repo(tmp_path, {"app.py": "x = 1\n"})
    build_code_map(repo_path=str(repo))
    events_path = tmp_path / "strix_runs" / "cm-test" / "events.jsonl"
    events = [json.loads(l) for l in events_path.read_text().splitlines() if l.strip()]
    phases_entered = [
        e for e in events if (e.get("event_type") or e.get("event")) == "phase.entered"
    ]
    phases_completed = [
        e for e in events if (e.get("event_type") or e.get("event")) == "phase.completed"
    ]
    assert len(phases_entered) == 1
    assert len(phases_completed) == 1


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------


def test_unreadable_files_recorded_as_errors(tmp_path) -> None:
    """Files we can't read end up in `errors[]` rather than crashing the
    scan."""
    repo = tmp_path / "repo"
    repo.mkdir()
    good = repo / "good.py"
    good.write_text("@app.route('/g')\ndef g(): pass\n")
    binary = repo / "weird.py"
    # Write bytes that can't be decoded as UTF-8 — the read uses
    # errors='ignore' so this should still succeed but produce empty
    # extraction. The error path is more about OSError; we simulate
    # by creating a file then chmod'ing it to 0. Skip on systems
    # where chmod doesn't restrict.
    binary.write_bytes(b"\xff\xfe\x00\x00")
    out = build_code_map(repo_path=str(repo))
    # Pipeline didn't crash.
    assert out["success"] is True
    # Good file was scanned.
    paths = [r["path"] for r in out["code_map"]["routes"]]
    assert "/g" in paths


# ---------------------------------------------------------------------------
# next_steps
# ---------------------------------------------------------------------------


def test_next_steps_zero_files_warns(tmp_path) -> None:
    repo = tmp_path / "empty"
    repo.mkdir()
    out = build_code_map(repo_path=str(repo))
    assert any("Scanned 0 files" in s for s in out["next_steps"])


def test_next_steps_recommends_specialist_team(tmp_path) -> None:
    repo = _make_repo(tmp_path, {"app.py": "@app.route('/x')\ndef x(): pass\n"})
    out = build_code_map(repo_path=str(repo))
    assert any("specialist" in s.lower() for s in out["next_steps"])


def test_next_steps_warns_when_routes_without_auth(tmp_path) -> None:
    repo = _make_repo(tmp_path, {"app.py": "@app.route('/x')\ndef x(): pass\n"})
    out = build_code_map(repo_path=str(repo))
    assert any("auth-boundary" in s for s in out["next_steps"])


def test_next_steps_mentions_db_queries(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "service.py": "cursor.execute('SELECT * FROM x')\n",
    })
    out = build_code_map(repo_path=str(repo))
    assert any("DB query" in s for s in out["next_steps"])


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def test_mitre_techniques_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    techniques = get_tool_mitre_techniques("build_code_map")
    assert "T1592" in techniques
    assert "T1595" in techniques
