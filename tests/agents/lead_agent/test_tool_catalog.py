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
        # iter-22.9: `cve_lookup` + `nvd_lookup` (plus three other
        # CVE-shaped lookup tools) consolidated into the single
        # `query_threat_intel` per
        # `docs/l2-architecture-evaluation.md §5.1`.
        "query_threat_intel",
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


# ---------------------------------------------------------------------------
# Phase 6 — SCA specialist routing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target_types",
    [
        ["repository"],
        ["local_code"],
        # iter-22.9 dropped bare `["web_application"]` per
        # `docs/l2-architecture-evaluation.md §5.4` — a deployed
        # live URL does NOT natively expose lockfiles. The paired
        # cases below cover the vibe-app pattern via catalog
        # union, which IS preserved.
        ["web_application", "repository"],   # paired DAST + SCA
        ["web_application", "local_code"],   # paired DAST + SCA (local clone)
    ],
)
def test_scan_sca_lockfiles_in_catalog_for_repo_capable_targets(
    target_types: list[str],
) -> None:
    """`scan_sca_lockfiles` must be available whenever a repo-shaped
    asset is in scope. For vibe-app patterns (deployed URL + source
    checkout), the catalog UNION restores SCA via the repository
    entry — iter-22.9 stopped putting it in the bare
    web_application catalog."""
    catalog = get_lead_tool_catalog(target_types=target_types)
    assert "scan_sca_lockfiles" in catalog


def test_scan_sca_lockfiles_not_in_pure_network_catalogs() -> None:
    """Pure network targets (domain / ip_address) should not pull in
    SCA — there's no checkout to walk."""
    for tt in ("domain", "ip_address"):
        catalog = get_lead_tool_catalog(target_types=[tt])
        assert "scan_sca_lockfiles" not in catalog, tt


def test_threat_intel_lookup_in_core_for_dast_sca_correlation() -> None:
    """Cross-asset correlation needs the threat-intel lookup tool
    always available — DAST may fingerprint a tech stack and pivot
    to 'what known CVEs apply?' regardless of target type.

    iter-22.9: `lookup_known_cves` + `lookup_cve_by_id` (+ three
    other CVE-lookup variants) consolidated into the single
    `query_threat_intel` per
    `docs/l2-architecture-evaluation.md §5.1`. This test pins
    that the unified tool stays in `_CORE_TOOLS`.
    """
    core = list_core_tools()
    assert "query_threat_intel" in core
    # And pin the removed variants stay removed (so a future
    # eager refactor doesn't re-add them and bloat the catalog).
    assert "lookup_known_cves" not in core
    assert "lookup_cve_by_id" not in core
    assert "list_actively_exploited_cves" not in core
    assert "cve_lookup" not in core
    assert "nvd_lookup" not in core


def test_dast_and_sca_coexist_in_paired_catalog() -> None:
    """The paired (web + repo) catalog must contain both DAST anchor
    tools (specialists, browser, HTTP) and SCA tools — neither side
    is silently dropped when the other is in scope."""
    catalog = get_lead_tool_catalog(
        target_types=["web_application", "repository"],
    )
    # DAST anchors
    assert "scan_sqli" in catalog
    assert "scan_xss" in catalog
    assert "browser_action" in catalog
    assert "send_request" in catalog
    # SCA anchors
    assert "scan_sca_lockfiles" in catalog
    assert "build_code_map" in catalog
    assert "taint_analysis" in catalog


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


def test_per_target_catalog_under_90_tools() -> None:
    """`single-agent.md §2.8` says ~30-50 tools per catalog instead
    of ~130. Cap was 60 pre-Phase-2; raised to 90 after PRs #193-#215
    landed 17 new specialists + the multi-role / replay-mutation
    orchestrators. Still catches catalog blow-up (130-tool baseline)
    while accommodating the deterministic-specialist library.

    Future tuning: when active-learning lands (Phase 6.1), the lead
    will subset the catalog per-scan and this cap can drop again."""
    for tt in ["web_application", "repository", "domain", "ip_address"]:
        catalog = get_lead_tool_catalog(target_types=[tt])
        assert len(catalog) <= 90, (
            f"target_type={tt!r} catalog has {len(catalog)} tools — "
            f"exceeds the §2.8 ~30-50 budget (post-Phase-5 cap: 90)"
        )


# ---------------------------------------------------------------------------
# iter-22.9 catalog-bloat consolidation pins
# ---------------------------------------------------------------------------


def test_iter_22_9_replay_mutation_consolidated() -> None:
    """3 source-specific replay tools → 1 unified per
    `docs/l2-architecture-evaluation.md §5.2`."""
    for tt in ["web_application", "api"]:
        catalog = get_lead_tool_catalog(target_types=[tt])
        assert "replay_mutation" in catalog, tt
        # Pin the removed variants stay removed
        assert "replay_mutation_on_endpoints" not in catalog, tt
        assert "replay_mutation_from_har_file" not in catalog, tt
        assert "replay_mutation_from_burp_file" not in catalog, tt


def test_iter_22_9_web_application_no_sast_sca() -> None:
    """Per `docs/l2-architecture-evaluation.md §5.4`: web_application
    is by-definition a deployed live URL — SAST / SCA belong to the
    `repository` catalog (the union path covers paired vibe-app
    runs)."""
    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_sast" not in catalog
    assert "scan_sca_lockfiles" not in catalog


def test_iter_22_9_repository_still_has_sast_sca() -> None:
    """The reverse pin — repository keeps both."""
    catalog = get_lead_tool_catalog(target_types=["repository"])
    assert "scan_sast" in catalog
    assert "scan_sca_lockfiles" in catalog


def test_iter_22_9_paired_web_plus_repo_has_sast_sca() -> None:
    """Paired vibe-app pattern (web_application + repository) must
    still see SAST/SCA via the catalog union — this is the whole
    reason we trusted the §5.4 removal."""
    catalog = get_lead_tool_catalog(
        target_types=["web_application", "repository"],
    )
    assert "scan_sast" in catalog
    assert "scan_sca_lockfiles" in catalog


def test_iter_22_9_webapp_recon_pipeline_dropped_from_catalog() -> None:
    """Per `docs/l2-architecture-evaluation.md §5.3`: composite
    `webapp_recon_pipeline` removed from the lead catalog —
    `fingerprint_tech_stack` + `bfs_crawl` + `well_known_harvest`
    are orchestrated explicitly. The tool STAYS registered (anchor
    prepass phase-2 calls it directly) but the lead doesn't see
    its schema."""
    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "webapp_recon_pipeline" not in catalog
    # The decomposed primitives stay
    assert "fingerprint_tech_stack" in catalog
    assert "bfs_crawl" in catalog
    assert "well_known_harvest" in catalog

    # And the tool stays in the global registry for direct
    # anchor_prepass invocation
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("webapp_recon_pipeline"))


# ---------------------------------------------------------------------------
# iter-22.10 — L2 cognitive gaps: kg_query_* promoted from
# patcher-only to Lead Orchestrator catalog
# ---------------------------------------------------------------------------


def test_iter_22_10_kg_query_in_lead_core_tools() -> None:
    """Per `docs/l2-architecture-evaluation.md §4`: kg_query_nodes
    + kg_query_paths previously lived ONLY in the patcher
    specialist's catalog. Promoted to `_CORE_TOOLS` so the lead
    orchestrator can answer "which Assets is this finding
    attached to?" / "is there a path from Surface X to Vuln Y?"
    without spawning a patcher dispatch just to query the KG."""
    core = list_core_tools()
    assert "kg_query_nodes" in core
    assert "kg_query_paths" in core


def test_iter_22_10_kg_query_visible_per_target() -> None:
    """Verify the promotion actually flows through to per-target
    catalogs via the _CORE_TOOLS union."""
    for tt in ("web_application", "repository", "api",
               "container_image", "domain", "ip_address"):
        catalog = get_lead_tool_catalog(target_types=[tt])
        assert "kg_query_nodes" in catalog, tt
        assert "kg_query_paths" in catalog, tt
