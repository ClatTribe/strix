"""Tests for V3-4 — batched recon interpretation.

Pins:
  * Endpoint shape classification is deterministic + correct for
    the canonical paths (api / auth / file / id_in_path / search).
  * `interpret_recon_and_plan_probes` returns all four sections
    (endpoints / tech_stack / security_posture_flags /
    prioritized_probes).
  * LLM path used when inner_call_fn provided + parseable response.
  * Falls back to deterministic plan on malformed LLM response.
  * Kill switch (`STRIX_BATCHED_RECON_INTERP_DISABLED=1`) forces
    deterministic-only path.
  * Tolerant to multiple surface_map endpoint shapes (legacy
    list-of-strings + newer list-of-dicts).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.tools.recon.interpret_recon import (
    classify_endpoint_shape,
    interpret_recon_and_plan_probes,
    is_disabled,
    suspected_categories_for_shape,
    _build_deterministic_probe_plan,
    _parse_llm_probe_plan,
)


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_BATCHED_RECON_INTERP_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# classify_endpoint_shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint,expected_tags", [
    ("/api/users/42", {"api", "id_in_path", "numeric_id"}),
    ("/api/orders/550e8400-e29b-41d4-a716-446655440000",
     {"api", "id_in_path", "uuid_id"}),
    ("/login", {"auth"}),
    ("/auth/oauth/callback", {"auth"}),
    ("/upload/file", {"file"}),
    ("/search?q=foo", {"search"}),
    ("/api/v1/products/123", {"api", "id_in_path", "numeric_id"}),
    ("/static/index.html", set()),
    ("https://x.com/api/admin/users/42",
     {"api", "id_in_path", "numeric_id"}),
])
def test_classify_endpoint_shape(endpoint: str, expected_tags: set[str]) -> None:
    got = set(classify_endpoint_shape(endpoint))
    assert expected_tags.issubset(got), (
        f"expected {expected_tags} ⊆ got, but got {got}"
    )


def test_classify_endpoint_handles_empty() -> None:
    assert classify_endpoint_shape("") == []
    assert classify_endpoint_shape(None) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# suspected_categories_for_shape
# ---------------------------------------------------------------------------


def test_auth_shape_suggests_auth_categories() -> None:
    cats = suspected_categories_for_shape(["auth"])
    assert "auth_flow" in cats
    assert "csrf" in cats
    assert "jwt" in cats


def test_id_in_path_suggests_idor() -> None:
    cats = suspected_categories_for_shape(["api", "id_in_path", "numeric_id"])
    assert "idor" in cats
    assert "sqli" in cats


def test_file_shape_suggests_path_traversal() -> None:
    cats = suspected_categories_for_shape(["file"])
    assert "path_traversal" in cats


# ---------------------------------------------------------------------------
# Deterministic probe plan
# ---------------------------------------------------------------------------


def test_deterministic_plan_ranks_auth_endpoints_high() -> None:
    endpoints = [
        {"path": "/static/img.png", "shape": []},
        {"path": "/api/users", "shape": ["api"]},
        {"path": "/login", "shape": ["auth"]},
    ]
    plan = _build_deterministic_probe_plan(endpoints)
    # Static page has no shape → dropped from plan
    paths_in_plan = [p["endpoint"] for p in plan]
    assert "/static/img.png" not in paths_in_plan
    # /login (auth, weight=5) ranks above /api/users (api, weight=2)
    assert paths_in_plan.index("/login") < paths_in_plan.index("/api/users")


def test_deterministic_plan_skips_unclassified_endpoints() -> None:
    endpoints = [{"path": "/random", "shape": []}]
    plan = _build_deterministic_probe_plan(endpoints)
    assert plan == []


# ---------------------------------------------------------------------------
# _parse_llm_probe_plan — tolerant to many response shapes
# ---------------------------------------------------------------------------


def test_parse_llm_accepts_list_directly() -> None:
    raw = [{"endpoint": "/x", "suspected_categories": ["sqli"], "why": "ok"}]
    parsed = _parse_llm_probe_plan(raw)
    assert parsed is not None
    assert parsed[0]["endpoint"] == "/x"


def test_parse_llm_accepts_json_string() -> None:
    raw = '[{"endpoint": "/x", "suspected_categories": ["xss"], "why": ""}]'
    parsed = _parse_llm_probe_plan(raw)
    assert parsed is not None
    assert parsed[0]["endpoint"] == "/x"


def test_parse_llm_strips_markdown_fence() -> None:
    raw = '```json\n[{"endpoint": "/x", "suspected_categories": ["sqli"]}]\n```'
    parsed = _parse_llm_probe_plan(raw)
    assert parsed is not None
    assert parsed[0]["endpoint"] == "/x"


def test_parse_llm_returns_none_on_garbage() -> None:
    assert _parse_llm_probe_plan("not json at all") is None
    assert _parse_llm_probe_plan({"not": "a list"}) is None
    assert _parse_llm_probe_plan(None) is None
    assert _parse_llm_probe_plan(42) is None


def test_parse_llm_drops_malformed_entries() -> None:
    raw = [
        {"endpoint": "/x", "suspected_categories": ["sqli"]},  # ok
        "string-not-dict",                                      # dropped
        {"no_endpoint": "x"},                                   # dropped
        {"endpoint": "/y", "suspected_categories": "not-a-list"},  # dropped
    ]
    parsed = _parse_llm_probe_plan(raw)
    assert parsed is not None
    assert len(parsed) == 1
    assert parsed[0]["endpoint"] == "/x"


# ---------------------------------------------------------------------------
# interpret_recon_and_plan_probes — end-to-end on a synthetic
# surface_map
# ---------------------------------------------------------------------------


def _write_surface_map(tmp_path: Path, body: dict[str, Any]) -> Path:
    p = tmp_path / "webapp_surface_map.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    return p


def _sample_surface_map() -> dict[str, Any]:
    return {
        "endpoints": [
            "/api/users/42",
            "/login",
            "/search",
            "/static/index.html",
            "/upload",
        ],
        "fingerprint": {
            "detections": [
                {"name": "nginx", "version": "1.18.0"},
                {"name": "PHP", "version": "7.4"},
            ],
        },
        "security_headers": {
            "issues": [
                {"kind": "missing CSP"},
                {"kind": "missing HSTS"},
            ],
        },
        "tls": {
            "findings": [{"kind": "TLS 1.0 enabled"}],
        },
    }


def test_returns_all_four_sections(tmp_path: Path) -> None:
    p = _write_surface_map(tmp_path, _sample_surface_map())
    out = interpret_recon_and_plan_probes(str(p))
    assert out["success"] is True
    assert "endpoints" in out
    assert "tech_stack" in out
    assert "security_posture_flags" in out
    assert "prioritized_probes" in out


def test_tech_stack_summary_includes_detections(tmp_path: Path) -> None:
    p = _write_surface_map(tmp_path, _sample_surface_map())
    out = interpret_recon_and_plan_probes(str(p))
    assert "nginx" in out["tech_stack"]


def test_security_flags_pulled_from_headers_and_tls(
    tmp_path: Path,
) -> None:
    p = _write_surface_map(tmp_path, _sample_surface_map())
    out = interpret_recon_and_plan_probes(str(p))
    flags = out["security_posture_flags"]
    assert "missing CSP" in flags
    assert "TLS 1.0 enabled" in flags


def test_deterministic_path_when_no_llm_provided(tmp_path: Path) -> None:
    p = _write_surface_map(tmp_path, _sample_surface_map())
    out = interpret_recon_and_plan_probes(str(p))
    assert out["interpretation_source"] == "deterministic_fallback"


def test_llm_path_when_inner_call_returns_valid_plan(
    tmp_path: Path,
) -> None:
    p = _write_surface_map(tmp_path, _sample_surface_map())

    def fake_llm(prompt: str) -> list[dict[str, Any]]:
        # Return a probe plan in priority order
        return [
            {"endpoint": "/login", "suspected_categories": ["auth_flow"], "why": "auth entry"},
            {"endpoint": "/api/users/42", "suspected_categories": ["idor"], "why": "id_in_path"},
        ]

    out = interpret_recon_and_plan_probes(str(p), inner_call_fn=fake_llm)
    assert out["interpretation_source"] == "llm"
    assert len(out["prioritized_probes"]) == 2
    assert out["prioritized_probes"][0]["endpoint"] == "/login"


def test_llm_failure_falls_back_to_deterministic(tmp_path: Path) -> None:
    """Recall canary — if the LLM call returns garbage, the tool
    must NOT crash and must NOT return an empty plan. Fall through
    to the deterministic ranking so the lead still has something
    to act on."""
    p = _write_surface_map(tmp_path, _sample_surface_map())

    def garbage_llm(prompt: str) -> str:
        return "this is not valid json"

    out = interpret_recon_and_plan_probes(str(p), inner_call_fn=garbage_llm)
    assert out["interpretation_source"] == "deterministic_fallback"
    # Plan is non-empty (deterministic fallback ranked the
    # shaped endpoints)
    assert len(out["prioritized_probes"]) > 0


def test_kill_switch_forces_deterministic_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = _write_surface_map(tmp_path, _sample_surface_map())
    monkeypatch.setenv("STRIX_BATCHED_RECON_INTERP_DISABLED", "1")

    def fake_llm(prompt: str) -> list[dict[str, Any]]:
        return [{"endpoint": "/login", "suspected_categories": ["auth_flow"]}]

    out = interpret_recon_and_plan_probes(str(p), inner_call_fn=fake_llm)
    # LLM is NOT called even though inner_call_fn was provided
    assert out["interpretation_source"] == "deterministic_fallback"


def test_missing_surface_map_returns_error(tmp_path: Path) -> None:
    out = interpret_recon_and_plan_probes(str(tmp_path / "nope.json"))
    assert out["success"] is False
    assert "error" in out


def test_corrupt_surface_map_returns_error(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("not valid json", encoding="utf-8")
    out = interpret_recon_and_plan_probes(str(p))
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Tolerance to multiple surface_map endpoint shapes
# ---------------------------------------------------------------------------


def test_endpoints_as_list_of_dicts(tmp_path: Path) -> None:
    """Newer surface_maps may pass {path, method} dicts instead
    of bare strings. The tool tolerates both."""
    p = _write_surface_map(tmp_path, {
        "endpoints": [
            {"path": "/api/users/42", "method": "GET"},
            {"path": "/login", "method": "POST"},
        ],
        "fingerprint": {},
    })
    out = interpret_recon_and_plan_probes(str(p))
    paths = {e["path"] for e in out["endpoints"]}
    assert paths == {"/api/users/42", "/login"}


def test_empty_surface_map_handled(tmp_path: Path) -> None:
    p = _write_surface_map(tmp_path, {})
    out = interpret_recon_and_plan_probes(str(p))
    assert out["success"] is True
    assert out["endpoints"] == []
    assert out["prioritized_probes"] == []


# ---------------------------------------------------------------------------
# Recall canary
# ---------------------------------------------------------------------------


def test_recall_canary_auth_endpoint_always_in_plan(tmp_path: Path) -> None:
    """The tool MUST surface auth endpoints — missing one would
    cascade into missed auth-flow findings. If a future change
    drops auth-shape endpoints, this canary breaks."""
    p = _write_surface_map(tmp_path, {
        "endpoints": ["/login", "/logout", "/api/data"],
        "fingerprint": {},
    })
    out = interpret_recon_and_plan_probes(str(p))
    paths_in_plan = [p["endpoint"] for p in out["prioritized_probes"]]
    assert "/login" in paths_in_plan, (
        "recall canary: /login must appear in the probe plan"
    )
    assert "/logout" in paths_in_plan
