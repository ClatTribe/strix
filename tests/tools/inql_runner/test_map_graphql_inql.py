"""Tests for iter-23.3 `map_graphql_inql` wrapper."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest


import strix.tools.inql_runner.map_graphql_inql  # noqa: F401
mgi_mod = sys.modules["strix.tools.inql_runner.map_graphql_inql"]
map_graphql_inql = mgi_mod.map_graphql_inql


_SAMPLE_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [
                {
                    "name": "Query",
                    "fields": [
                        {
                            "name": "user",
                            "args": [
                                {"name": "id", "type": {"name": "ID"}},
                            ],
                        },
                        {
                            "name": "listOrders",
                            "args": [
                                {"name": "limit",
                                 "type": {"name": None,
                                           "ofType": {"name": "Int"}}},
                            ],
                        },
                    ],
                },
                {
                    "name": "Mutation",
                    "fields": [
                        {
                            "name": "createUser",
                            "args": [
                                {"name": "input",
                                 "type": {"name": "UserInput"}},
                            ],
                        },
                    ],
                },
            ],
        }
    }
}


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_INQL_DISABLED", raising=False)


def test_error_when_empty():
    out = map_graphql_inql("")
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = map_graphql_inql("https://api.example.com/graphql")
    assert out["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_INQL_DISABLED", "1")
    out = map_graphql_inql("https://api.example.com/graphql")
    assert out["status"] == "partial"


def test_parses_schema_into_operations(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/inql" if b == "inql" else None,
    )

    def _fake_run(cmd, **kw):
        # Find -o argument; write schema.json into that dir.
        o_idx = cmd.index("-o")
        outdir = Path(cmd[o_idx + 1])
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "schema.json").write_text(json.dumps(_SAMPLE_SCHEMA))
        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        m.stderr = ""
        return m

    monkeypatch.setattr(subprocess, "run", _fake_run)
    out = map_graphql_inql("https://api.example.com/graphql")
    assert out["status"] == "ok"
    # 2 queries + 1 mutation = 3 operations
    assert out["total_operations"] == 3
    names = {(o["kind"], o["name"]) for o in out["operations"]}
    assert ("query", "user") in names
    assert ("query", "listOrders") in names
    assert ("mutation", "createUser") in names
    # ofType unwrapping works
    list_orders = next(o for o in out["operations"] if o["name"] == "listOrders")
    assert list_orders["args"][0]["type"] == "Int"


def test_partial_when_introspection_disabled(monkeypatch):
    """inql ran but found no schema.json (introspection blocked)."""
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/inql" if b == "inql" else None,
    )
    # Do not write any schema.json
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = ""
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = map_graphql_inql("https://api.example.com/graphql")
    assert out["status"] == "partial"
    assert "introspection" in out["reason"].lower()


def test_headers_passed_through(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/inql" if b == "inql" else None,
    )
    captured = {}

    def _capture(cmd, **kw):
        captured["cmd"] = cmd
        m = MagicMock()
        m.returncode = 0
        m.stdout = ""
        m.stderr = ""
        return m

    monkeypatch.setattr(subprocess, "run", _capture)
    map_graphql_inql(
        "https://api.example.com/graphql",
        headers={"Authorization": "Bearer xyz", "X-Custom": "v"},
    )
    flat = " ".join(captured["cmd"])
    assert "Authorization: Bearer xyz" in flat
    assert "X-Custom: v" in flat


def test_timeout(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/inql" if b == "inql" else None,
    )

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="inql", timeout=120)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = map_graphql_inql("https://api.example.com/graphql")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("map_graphql_inql"))
