"""Tests for iter-Q5.14 — `get_recon_artifact(kind, name)`.

Pure READ STATE primitive that reads prepass-persisted artifacts
from `<run_dir>/recon/`. Closes Gap 2 from the consolidated Q5 §7.
"""

from __future__ import annotations

import json

import pytest

from strix.tools.recon_artifact.get_recon_artifact import (
    _KIND_FILENAMES,
    get_recon_artifact,
)


@pytest.fixture
def recon_dir(monkeypatch, tmp_path):
    """Set up an isolated recon dir for the test."""
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    d = tmp_path / "recon"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["", "   ", None, 42])
def test_rejects_invalid_kind(bad) -> None:
    out = get_recon_artifact(bad)
    assert out["success"] is False
    assert out["status"] == "error"


def test_rejects_unknown_kind() -> None:
    out = get_recon_artifact("not_a_real_kind")
    assert out["success"] is False
    assert "unknown kind" in out["reason"]
    # Includes all supported kinds in the diagnostic.
    for k in _KIND_FILENAMES:
        assert k in out["reason"]


# ---------------------------------------------------------------------------
# Happy path — read existing artifact
# ---------------------------------------------------------------------------


def test_reads_endpoints_artifact(recon_dir) -> None:
    payload = {"endpoints": ["https://x/a", "https://x/b"], "count": 2}
    (recon_dir / "endpoints.json").write_text(json.dumps(payload))

    out = get_recon_artifact("endpoints")
    assert out["success"] is True
    assert out["status"] == "ok"
    assert out["kind"] == "endpoints"
    assert out["artifact"] == payload
    assert out["artifact_size_chars"] > 0


def test_reads_openapi_spec_artifact(recon_dir) -> None:
    spec = {"openapi": "3.0.0", "paths": {"/users": {}}}
    (recon_dir / "openapi_spec.json").write_text(json.dumps(spec))

    out = get_recon_artifact("openapi_spec")
    assert out["status"] == "ok"
    assert out["artifact"]["openapi"] == "3.0.0"


def test_kind_normalized_lowercase(recon_dir) -> None:
    (recon_dir / "tech_stack.json").write_text('{"server": "nginx"}')

    out = get_recon_artifact("  TECH_STACK  ")
    assert out["status"] == "ok"
    assert out["kind"] == "tech_stack"


# ---------------------------------------------------------------------------
# name= qualifier for multi-instance artifacts
# ---------------------------------------------------------------------------


def test_reads_name_qualified_artifact(recon_dir) -> None:
    """Multiple GraphQL endpoints could exist; the name lets the lead
    pick one."""
    subdir = recon_dir / "graphql_schema"
    subdir.mkdir()
    (subdir / "api-gateway.json").write_text('{"types": ["Query"]}')
    (subdir / "admin-portal.json").write_text('{"types": ["Mutation"]}')

    out_a = get_recon_artifact("graphql_schema", name="api-gateway")
    out_b = get_recon_artifact("graphql_schema", name="admin-portal")
    assert out_a["status"] == "ok"
    assert out_b["status"] == "ok"
    assert out_a["artifact"]["types"] == ["Query"]
    assert out_b["artifact"]["types"] == ["Mutation"]


def test_blank_name_falls_through_to_top_level(recon_dir) -> None:
    (recon_dir / "subdomains.json").write_text(
        '{"subdomains": ["a.example.com"]}'
    )

    for name in ("", "   ", None):
        out = get_recon_artifact("subdomains", name=name)
        assert out["status"] == "ok"
        assert "subdomains" in out["artifact"]


# ---------------------------------------------------------------------------
# Not-found path
# ---------------------------------------------------------------------------


def test_returns_not_found_when_artifact_missing(recon_dir) -> None:
    out = get_recon_artifact("endpoints")
    assert out["success"] is True
    assert out["status"] == "not_found"
    assert "endpoints" in out["reason"]


def test_returns_not_found_when_run_dir_unset(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_RUN_DIR", raising=False)
    out = get_recon_artifact("endpoints")
    assert out["success"] is True
    assert out["status"] == "not_found"
    assert "STRIX_RUN_DIR not set" in out["reason"]


# ---------------------------------------------------------------------------
# Defensive — disk errors
# ---------------------------------------------------------------------------


def test_invalid_json_returns_error_dict(recon_dir) -> None:
    """Best-effort read — invalid JSON returns structured error,
    never raises."""
    (recon_dir / "endpoints.json").write_text("{ not valid json }")

    out = get_recon_artifact("endpoints")
    assert out["success"] is False
    assert out["status"] == "error"
    assert "failed to read" in out["reason"]


# ---------------------------------------------------------------------------
# Tool registration + catalog membership
# ---------------------------------------------------------------------------


def test_get_recon_artifact_is_registered() -> None:
    from strix.tools.registry import get_tool_by_name, get_tool_names
    assert "get_recon_artifact" in get_tool_names()
    assert get_tool_by_name("get_recon_artifact") is not None


def test_in_minimal_core() -> None:
    from strix.agents.lead_agent.tool_catalog import _MINIMAL_CORE_TOOLS
    assert "get_recon_artifact" in _MINIMAL_CORE_TOOLS


def test_in_legacy_core() -> None:
    from strix.agents.lead_agent.tool_catalog import _CORE_TOOLS
    assert "get_recon_artifact" in _CORE_TOOLS


def test_reaches_every_asset_type() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog
    for asset in (
        "web_application", "api", "repository", "local_code",
        "container_image", "ip_address", "domain",
    ):
        catalog = get_lead_tool_catalog(target_types=[asset])
        assert "get_recon_artifact" in catalog, (
            f"get_recon_artifact must be visible to {asset} lead"
        )


# ---------------------------------------------------------------------------
# All supported kinds round-trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(_KIND_FILENAMES))
def test_every_supported_kind_round_trips(recon_dir, kind) -> None:
    """Each kind has a canonical filename and the read works."""
    filename = _KIND_FILENAMES[kind]
    payload = {"_test_marker": kind, "value": 42}
    (recon_dir / filename).write_text(json.dumps(payload))

    out = get_recon_artifact(kind)
    assert out["status"] == "ok"
    assert out["artifact"]["_test_marker"] == kind
