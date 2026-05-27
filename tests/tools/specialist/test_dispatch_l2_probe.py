"""Tests for iter-Q5.10 — `dispatch_l2_probe(kind, **kwargs)`.

Umbrella tool that collapses 3 L2-native session-aware probes
(scan_idor, scan_auth_flow, scan_business_logic) under one catalog
slot. Per CLAUDE.md §1.5.7 (RE-DISPATCH bucket) + the consolidated
Q5 proposal §4.

The test surface is intentionally narrow — `dispatch_l2_probe` is
a thin router. Per-probe semantics are tested in their own files
(`tests/tools/specialist/test_scan_idor.py`, etc.). This file only
verifies:

  * Kind validation + error shape
  * Each kind routes to the correct underlying probe
  * Errors from the underlying probe are surfaced cleanly
  * Tool is registered + in the right catalogs
"""

from __future__ import annotations

from unittest import mock

import pytest

from strix.tools.specialist.dispatch_l2_probe import (
    _VALID_KINDS,
    dispatch_l2_probe,
)


# ---------------------------------------------------------------------------
# Kind validation
# ---------------------------------------------------------------------------


def test_valid_kinds_match_documented_set() -> None:
    """The 3 probes the docstring promises must be in _VALID_KINDS."""
    assert _VALID_KINDS == {"idor", "auth_flow", "business_logic"}


@pytest.mark.parametrize("kind", ["", None, 42, [], {}])
def test_rejects_invalid_kind_type(kind) -> None:
    out = dispatch_l2_probe(kind=kind)
    assert out["status"] == "error"
    assert out["success"] is False
    assert "kind is required" in out["reason"]


def test_rejects_whitespace_only_kind() -> None:
    out = dispatch_l2_probe(kind="   ")
    assert out["status"] == "error"
    assert "kind is required" in out["reason"]


@pytest.mark.parametrize("bad_kind", [
    "unknown", "sqlmap", "scan_idor", "xss", "csrf",
])
def test_rejects_unknown_kind_string(bad_kind) -> None:
    out = dispatch_l2_probe(kind=bad_kind)
    assert out["status"] == "error"
    assert "unknown kind" in out["reason"]
    assert "idor" in out["reason"]
    assert "auth_flow" in out["reason"]
    assert "business_logic" in out["reason"]


def test_kind_is_normalized_lowercase_and_stripped() -> None:
    """`kind="  IDOR  "` should route to the idor probe."""
    with mock.patch(
        "strix.tools.specialist.scan_idor.scan_idor",
        return_value={"status": "ok", "findings": []},
    ) as mock_idor:
        out = dispatch_l2_probe(kind="  IDOR  ", urls=["http://x/a/1"])
    mock_idor.assert_called_once()
    assert out["status"] == "ok"


# ---------------------------------------------------------------------------
# Routing — each kind dispatches to the correct probe
# ---------------------------------------------------------------------------


def test_idor_routes_to_scan_idor() -> None:
    sentinel = {"status": "ok", "kind_reached": "idor"}
    with mock.patch(
        "strix.tools.specialist.scan_idor.scan_idor",
        return_value=sentinel,
    ) as mock_idor:
        out = dispatch_l2_probe(
            kind="idor",
            urls=["http://example.com/users/1"],
            owner_label="user-a",
            accessor_label="user-b",
        )
    mock_idor.assert_called_once_with(
        urls=["http://example.com/users/1"],
        owner_label="user-a",
        accessor_label="user-b",
    )
    assert out == sentinel


def test_auth_flow_routes_to_scan_auth_flow() -> None:
    sentinel = {"status": "ok", "kind_reached": "auth_flow"}
    with mock.patch(
        "strix.tools.specialist.scan_auth_flow.scan_auth_flow",
        return_value=sentinel,
    ) as mock_auth:
        out = dispatch_l2_probe(
            kind="auth_flow",
            login_url="http://example.com/login",
            method="POST",
        )
    mock_auth.assert_called_once_with(
        login_url="http://example.com/login",
        method="POST",
    )
    assert out == sentinel


def test_business_logic_routes_to_scan_business_logic() -> None:
    sentinel = {"status": "ok", "kind_reached": "business_logic"}
    with mock.patch(
        "strix.tools.specialist.scan_business_logic.scan_business_logic",
        return_value=sentinel,
    ) as mock_biz:
        out = dispatch_l2_probe(
            kind="business_logic",
            url="http://example.com/checkout",
            body_template={"price": 100, "quantity": 1},
        )
    mock_biz.assert_called_once_with(
        url="http://example.com/checkout",
        body_template={"price": 100, "quantity": 1},
    )
    assert out == sentinel


# ---------------------------------------------------------------------------
# Underlying-probe errors surface cleanly
# ---------------------------------------------------------------------------


def test_wrong_kwargs_returns_structured_error() -> None:
    """TypeError from the underlying probe (e.g. missing required
    kwarg) gets re-shaped as an error dict — never raises."""
    # scan_idor requires `urls` or `url` — passing neither should TypeError
    # internally, but the umbrella catches and reshapes.
    with mock.patch(
        "strix.tools.specialist.scan_idor.scan_idor",
        side_effect=TypeError(
            "scan_idor() missing 1 required keyword-only argument: 'urls'",
        ),
    ):
        out = dispatch_l2_probe(kind="idor")  # no urls kwarg
    assert out["status"] == "error"
    assert out["success"] is False
    assert "bad kwargs" in out["reason"]
    assert "TypeError" in out["reason"]
    assert "kind=idor" in out["reason"]


def test_probe_raising_general_exception_returns_error_dict() -> None:
    """Any non-TypeError exception from the probe surfaces as an
    error dict (never propagates)."""
    with mock.patch(
        "strix.tools.specialist.scan_idor.scan_idor",
        side_effect=RuntimeError("network is on fire"),
    ):
        out = dispatch_l2_probe(kind="idor", urls=["http://x/a/1"])
    assert out["status"] == "error"
    assert "RuntimeError" in out["reason"]
    assert "network is on fire" in out["reason"]


# ---------------------------------------------------------------------------
# Tool registration + catalog membership
# ---------------------------------------------------------------------------


def test_dispatch_l2_probe_is_registered() -> None:
    from strix.tools.registry import get_tool_by_name, get_tool_names
    assert "dispatch_l2_probe" in get_tool_names()
    fn = get_tool_by_name("dispatch_l2_probe")
    assert fn is not None
    assert callable(fn)


def test_dispatch_l2_probe_in_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import _MINIMAL_TOOLS_BY_TARGET_TYPE
    assert "dispatch_l2_probe" in _MINIMAL_TOOLS_BY_TARGET_TYPE["web_application"]


def test_dispatch_l2_probe_in_api_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import _MINIMAL_TOOLS_BY_TARGET_TYPE
    assert "dispatch_l2_probe" in _MINIMAL_TOOLS_BY_TARGET_TYPE["api"]


def test_underlying_probes_removed_from_minimal_catalogs() -> None:
    """The collapse target: scan_idor / scan_auth_flow / scan_business_logic
    must NOT appear in the LLM-visible minimal catalogs — they're
    reachable only through dispatch_l2_probe."""
    from strix.agents.lead_agent.tool_catalog import _MINIMAL_TOOLS_BY_TARGET_TYPE
    for asset in ("web_application", "api"):
        catalog = _MINIMAL_TOOLS_BY_TARGET_TYPE[asset]
        for collapsed_tool in ("scan_idor", "scan_auth_flow", "scan_business_logic"):
            assert collapsed_tool not in catalog, (
                f"{asset}: {collapsed_tool} is still in the minimal "
                f"catalog after Q5.10. The collapse target failed."
            )


def test_underlying_probes_still_registered_for_orchestrator_mode() -> None:
    """Even though hidden from the LLM-visible catalog, the underlying
    probes stay registered. Orchestrator mode + direct test callers
    reach them by name."""
    from strix.tools.registry import get_tool_names
    names = get_tool_names()
    for name in ("scan_idor", "scan_auth_flow", "scan_business_logic"):
        assert name in names, f"{name} unregistered — broke orchestrator mode"
