"""Tests for §8.5 Phase 3 / B.9 — per-target-type tool catalog filtering.

Pins the architectural commitment: `create_agent` and the spawn
helpers are NEVER in the lead's catalog regardless of target type.
The lead literally cannot spawn sub-agents.
"""

from __future__ import annotations

import pytest

from strix.agents.lead_agent.tool_catalog import (
    get_lead_tool_catalog,
    is_tool_allowed_for_lead,
    list_blocked_tools,
    list_core_tools,
    list_target_types,
)


# ---------------------------------------------------------------------------
# Architectural commitment: spawn-helpers always blocked
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spawn_tool",
    [
        "create_agent",
        "spawn_webapp_specialist_team",
        "spawn_code_specialist_team",
        "spawn_webapp_subteam",
        "wait_for_message",
        "send_message_to_agent",
        "stop_agent",
        "view_agent_graph",
    ],
)
@pytest.mark.parametrize(
    "target_types",
    [
        ["web_application"],
        ["repository"],
        ["local_code"],
        ["domain"],
        ["ip_address"],
        ["web_application", "repository", "domain"],
    ],
)
def test_spawn_helpers_never_in_lead_catalog(
    spawn_tool: str, target_types: list[str],
) -> None:
    """The architectural commitment: regardless of target type, the
    lead's catalog NEVER includes `create_agent` or its sibling
    spawn helpers. Removing from the catalog is the simplest gate
    against accidental sub-agent spawning."""
    catalog = get_lead_tool_catalog(target_types=target_types)
    assert spawn_tool not in catalog, (
        f"spawn helper {spawn_tool!r} leaked into lead catalog for "
        f"target_types={target_types!r} — architectural commitment broken"
    )


def test_blocked_set_includes_create_agent() -> None:
    blocked = list_blocked_tools()
    assert "create_agent" in blocked


# ---------------------------------------------------------------------------
# Core tools always present
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "core_tool",
    [
        "open_hypothesis", "confirm_hypothesis", "dismiss_hypothesis",
        "list_active_hypotheses", "is_surface_under_investigation",
        "agent_self_audit",
        "create_vulnerability_report", "update_finding", "check_budget",
        "cve_lookup", "nvd_lookup",
        "think", "finish_scan",
    ],
)
@pytest.mark.parametrize(
    "target_types",
    [
        ["web_application"],
        ["repository"],
        ["domain"],
        ["ip_address"],
    ],
)
def test_core_tools_in_every_target_type_catalog(
    core_tool: str, target_types: list[str],
) -> None:
    """Coordination tools (hypothesis primitives, finding tools, threat
    intel, finish_scan) appear in every target type's catalog."""
    catalog = get_lead_tool_catalog(target_types=target_types)
    assert core_tool in catalog


# ---------------------------------------------------------------------------
# Per-target-type specialisation
# ---------------------------------------------------------------------------


def test_web_application_includes_browser_action() -> None:
    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "browser_action" in catalog
    assert "send_request" in catalog


def test_repository_does_not_include_browser_tools() -> None:
    catalog = get_lead_tool_catalog(target_types=["repository"])
    assert "browser_action" not in catalog
    assert "build_code_map" in catalog


def test_domain_includes_subdomain_enum_but_not_browser() -> None:
    catalog = get_lead_tool_catalog(target_types=["domain"])
    assert "subdomain_enum_tool" in catalog
    assert "browser_action" not in catalog


def test_ip_address_does_not_include_web_specific_tools() -> None:
    catalog = get_lead_tool_catalog(target_types=["ip_address"])
    assert "csrf_check" not in catalog
    assert "send_request" in catalog  # may probe HTTP on IP


def test_multi_target_type_catalog_is_union() -> None:
    """When the run targets multiple types, the catalog is the union."""
    web = get_lead_tool_catalog(target_types=["web_application"])
    repo = get_lead_tool_catalog(target_types=["repository"])
    multi = get_lead_tool_catalog(
        target_types=["web_application", "repository"],
    )
    assert web.issubset(multi)
    assert repo.issubset(multi)


# ---------------------------------------------------------------------------
# Predicate variant
# ---------------------------------------------------------------------------


def test_is_tool_allowed_predicate() -> None:
    assert is_tool_allowed_for_lead(
        "browser_action", target_types=["web_application"],
    )
    assert not is_tool_allowed_for_lead(
        "create_agent", target_types=["web_application"],
    )
    assert not is_tool_allowed_for_lead(
        "create_agent", target_types=["repository"],
    )


def test_is_tool_allowed_handles_invalid_input() -> None:
    """Defensive — non-string tool name returns False without raising."""
    assert not is_tool_allowed_for_lead(
        None, target_types=["web_application"],  # type: ignore[arg-type]
    )
    assert not is_tool_allowed_for_lead(
        "", target_types=["web_application"],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_list_target_types_returns_known_set() -> None:
    types = list_target_types()
    for required in ("web_application", "repository", "domain", "ip_address"):
        assert required in types


def test_list_core_tools_returns_non_empty() -> None:
    core = list_core_tools()
    assert len(core) > 0
    assert "create_agent" not in core  # core ≠ blocked


def test_unknown_target_type_falls_back_to_core_only() -> None:
    """Unknown target types contribute zero — the lead still gets
    the core tools but no specialist tools."""
    catalog = get_lead_tool_catalog(target_types=["unknown_target"])
    assert catalog == list_core_tools() - list_blocked_tools()


def test_empty_target_types_returns_core_minus_blocked() -> None:
    catalog = get_lead_tool_catalog(target_types=[])
    assert catalog == list_core_tools() - list_blocked_tools()


# ---------------------------------------------------------------------------
# Catalog size — Phase 3 cost-pricing assumption (~30-50 tools)
# ---------------------------------------------------------------------------


def test_per_target_catalog_under_60_tools() -> None:
    """`single-agent.md §2.8` says ~30-50 tools per catalog instead
    of ~130. Pin a slightly looser cap (60) to avoid flakiness from
    minor catalog additions while still catching catalog blow-up."""
    for tt in ["web_application", "repository", "domain", "ip_address"]:
        catalog = get_lead_tool_catalog(target_types=[tt])
        assert len(catalog) <= 60, (
            f"target_type={tt!r} catalog has {len(catalog)} tools — "
            f"exceeds the §2.8 ~30-50 budget"
        )
