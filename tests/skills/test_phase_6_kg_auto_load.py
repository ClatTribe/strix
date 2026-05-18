"""Phase 6 — KG-driven + discovered-asset-driven skill auto-load.

Pins the mapping tables + the helper functions that compose them
into a single pre-load list. The actual integration into the lead
agent boot is wiring (callers pass the output of `get_auto_load_skills`
into `load_skills`); the contract pinned here is the mapping data
and the composition rules.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Direct mappings
# ---------------------------------------------------------------------------


def test_kg_node_kind_to_skill_covers_main_node_types() -> None:
    """Every shipped KG node kind (from agents/knowledge_graph.py)
    must have at least one default skill mapping."""
    from strix.skills import KG_NODE_KIND_TO_SKILL

    expected_kinds = [
        "CloudResource", "CloudIdentity", "Surface", "Asset",
        "Vuln", "Credential", "Secret", "Dependency", "Role",
    ]
    for kind in expected_kinds:
        assert kind in KG_NODE_KIND_TO_SKILL, (
            f"KG node kind {kind!r} missing from KG_NODE_KIND_TO_SKILL"
        )
        assert KG_NODE_KIND_TO_SKILL[kind], (
            f"KG node kind {kind!r} has empty skill list"
        )


def test_kg_subtype_mapping_resolves_to_real_skills() -> None:
    """Every subtype-mapped skill must be in the registry."""
    from strix.skills import (
        KG_NODE_SUBTYPE_TO_SKILL,
        get_all_skill_names,
    )

    available = get_all_skill_names()
    broken: list[tuple[str, str]] = []
    for subtype, skill_list in KG_NODE_SUBTYPE_TO_SKILL.items():
        for skill in skill_list:
            if skill not in available:
                broken.append((subtype, skill))
    assert not broken, (
        f"KG subtype mappings reference missing skills: {broken}"
    )


def test_discovered_asset_mapping_resolves_to_real_skills() -> None:
    from strix.skills import (
        DISCOVERED_ASSET_TYPE_TO_SKILL,
        get_all_skill_names,
    )

    available = get_all_skill_names()
    broken: list[tuple[str, str]] = []
    for asset_type, skill_list in DISCOVERED_ASSET_TYPE_TO_SKILL.items():
        for skill in skill_list:
            if skill not in available:
                broken.append((asset_type, skill))
    assert not broken, (
        f"discovered-asset mappings reference missing skills: {broken}"
    )


def test_target_type_mapping_resolves_to_real_skills() -> None:
    from strix.skills import (
        TARGET_TYPE_TO_SKILL,
        get_all_skill_names,
    )

    available = get_all_skill_names()
    broken: list[tuple[str, str]] = []
    for target_type, skill_list in TARGET_TYPE_TO_SKILL.items():
        for skill in skill_list:
            if skill not in available:
                broken.append((target_type, skill))
    assert not broken, (
        f"target-type mappings reference missing skills: {broken}"
    )


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def test_get_skills_for_kg_node_basic() -> None:
    from strix.skills import get_skills_for_kg_node

    # Generic kind only
    skills = get_skills_for_kg_node("CloudResource", attrs=None)
    assert "cloud_attack_path_traversal" in skills

    # Kind + subtype refinement
    skills = get_skills_for_kg_node("CloudResource", attrs={"service": "aws_lambda"})
    assert "aws_lambda_attack_surface" in skills


def test_get_skills_for_kg_node_unknown_kind_returns_empty() -> None:
    from strix.skills import get_skills_for_kg_node

    skills = get_skills_for_kg_node("NotARealKind")
    assert skills == []


def test_get_skills_for_kg_node_subtype_alternates() -> None:
    """attrs.kind / attrs.subtype work as alternates to attrs.service."""
    from strix.skills import get_skills_for_kg_node

    # via .kind
    skills = get_skills_for_kg_node("CloudResource", attrs={"kind": "aws_s3"})
    assert "aws_s3_attack_surface" in skills

    # via .subtype
    skills = get_skills_for_kg_node("Surface", attrs={"subtype": "graphql_endpoint"})
    assert "graphql" in skills


def test_get_skills_for_discovered_asset() -> None:
    from strix.skills import get_skills_for_discovered_asset

    assert "subdomain_strategy" in get_skills_for_discovered_asset("domain")
    assert "cloud_attack_path_traversal" in get_skills_for_discovered_asset("cloud_account")
    assert get_skills_for_discovered_asset("not_a_real_type") == []


def test_get_skills_for_target_type() -> None:
    from strix.skills import get_skills_for_target_type

    web = get_skills_for_target_type("web_application")
    assert "asset_discovery_pipeline" in web

    cloud = get_skills_for_target_type("cloud_account")
    assert "cloud_attack_path_traversal" in cloud


# ---------------------------------------------------------------------------
# Composition: get_auto_load_skills
# ---------------------------------------------------------------------------


def test_auto_load_dedups_across_sources() -> None:
    """If multiple sources suggest the same skill, it appears once."""
    from strix.skills import get_auto_load_skills

    skills = get_auto_load_skills(
        target_types=["web_application"],
        discovered_asset_types=["web_application"],
        kg_node_kinds=[],
    )
    # Both sources suggest asset_discovery_pipeline; should appear once
    assert skills.count("asset_discovery_pipeline") == 1


def test_auto_load_orders_discovered_first() -> None:
    """Discovered assets (operator-curated) outrank target-type baselines."""
    from strix.skills import get_auto_load_skills

    skills = get_auto_load_skills(
        target_types=["cloud_account"],
        discovered_asset_types=["api"],
        kg_node_kinds=[],
    )
    # `openapi_recon` (from api discovered-asset) should come before
    # `cloud_attack_path_traversal` (from cloud_account target type)
    assert "openapi_recon" in skills
    assert "cloud_attack_path_traversal" in skills
    assert skills.index("openapi_recon") < skills.index("cloud_attack_path_traversal")


def test_auto_load_honours_cap(monkeypatch) -> None:
    """The cap from get_max_skills_per_agent caps the output list."""
    monkeypatch.setenv("STRIX_SKILLS_MAX_PER_AGENT", "3")

    from strix.skills import get_auto_load_skills

    skills = get_auto_load_skills(
        target_types=["web_application", "cloud_account", "domain"],
        kg_node_kinds=[
            ("CloudResource", {"service": "aws_lambda"}),
            ("CloudResource", {"service": "aws_rds"}),
        ],
    )
    assert len(skills) <= 3


def test_auto_load_kg_node_refinement_overrides() -> None:
    """A CloudResource with service=aws_lambda includes the lambda
    skill in addition to the generic CloudResource defaults."""
    from strix.skills import get_auto_load_skills

    skills = get_auto_load_skills(
        target_types=["cloud_account"],
        kg_node_kinds=[("CloudResource", {"service": "aws_lambda"})],
    )
    assert "aws_lambda_attack_surface" in skills
    assert "cloud_attack_path_traversal" in skills


def test_auto_load_empty_inputs_returns_empty() -> None:
    from strix.skills import get_auto_load_skills

    skills = get_auto_load_skills(
        target_types=[],
        kg_node_kinds=[],
        discovered_asset_types=[],
    )
    assert skills == []


def test_auto_load_filters_missing_skill_references() -> None:
    """If a mapping references a deleted skill, it's silently dropped
    (the parity test catches the broken mapping; auto-load doesn't crash)."""
    from strix.skills import get_skills_for_kg_node

    # All produced skills must exist in the registry
    from strix.skills import get_all_skill_names

    available = get_all_skill_names()
    for kind in ["CloudResource", "CloudIdentity", "Vuln", "Credential"]:
        skills = get_skills_for_kg_node(kind)
        for s in skills:
            assert s in available, (
                f"get_skills_for_kg_node({kind!r}) returned missing skill {s!r}"
            )


# ---------------------------------------------------------------------------
# Phase 7 cleanup — boot-time integration into LeadAgent
# ---------------------------------------------------------------------------


def test_lead_agent_source_wires_auto_load() -> None:
    """The LeadAgent boot path includes the Phase 6 auto-load wiring.

    A full hermetic LeadAgent boot is hard to fixture without a real
    LLM provider + sandbox; this test pins the contract at the source
    level so the wiring can't silently drop out in future refactors.
    """
    from strix.utils.resource_paths import get_strix_resource_path

    lead_src = (
        get_strix_resource_path("agents")
        / "lead_agent" / "lead_agent.py"
    ).read_text(encoding="utf-8")

    # The auto-load wiring imports + calls + add_skills handoff
    assert "from strix.skills import get_auto_load_skills" in lead_src, (
        "LeadAgent missing get_auto_load_skills import"
    )
    assert "self.llm.add_skills(auto)" in lead_src, (
        "LeadAgent missing llm.add_skills handoff after auto-load"
    )
    # Reference to target_types_list (the post-Phase-7 gating)
    assert "target_types=target_types_list" in lead_src, (
        "LeadAgent does not pass target_types to auto-load"
    )
    # Phase 7: should skip the fallback-all-types case so unit-test
    # instantiations don't inflate prompt with N-target-type baselines
    assert "is_fallback_default" in lead_src, (
        "LeadAgent auto-load missing the all-types-fallback gate"
    )


def test_auto_load_at_boot_produces_target_type_baseline() -> None:
    """Smoke: with a web_application target type and no KG state, the
    auto-load returns the web_application baseline skills the LeadAgent
    boot integration relies on."""
    from strix.skills import get_auto_load_skills

    skills = get_auto_load_skills(target_types=["web_application"])
    assert "asset_discovery_pipeline" in skills, (
        f"expected asset_discovery_pipeline in web_application baseline; got {skills}"
    )
