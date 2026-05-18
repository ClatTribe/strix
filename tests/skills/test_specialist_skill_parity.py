"""Parity test: every shipped specialist has a paired skill.

Phase 1A of the skills-system upgrade (per the `Skills system audit`
discussion). The two-level disclosure menu (`strix/skills/menu.py`) +
the fingerprint auto-loader (`strix/tools/recon/fingerprint.py`) both
assume the lead can reach a skill body for any specialist it dispatches.
When a specialist has no paired skill, the lead either skips loading
(missing reasoning context) or loads the wrong one (mismatch).

This test pins the contract: each `scan_<vuln>` specialist in
`strix/tools/specialist/` either has its own skill at
`strix/skills/vulnerabilities/<vuln>.md`, or is allow-listed below
because an *equivalent* skill exists under a different name (e.g.
`scan_secrets_in_response` → `information_disclosure.md`).

Adding a new specialist? Either drop a matching skill in
`strix/skills/vulnerabilities/` or extend `_EQUIVALENT_SKILLS` with
the cross-reference + a one-line comment explaining why.
"""

from __future__ import annotations

from pathlib import Path

from strix.utils.resource_paths import get_strix_resource_path


# Cross-reference: specialist name → skill filename when names diverge.
# Each entry is a deliberate mapping, not a TODO.
_EQUIVALENT_SKILLS: dict[str, str] = {
    # scan_secrets_in_response is the active probe for the
    # information-disclosure class; the skill body covers the same
    # surface under the broader class name.
    "scan_secrets_in_response": "information_disclosure",
    # scan_blind_cmd_injection / scan_cmd_injection share the rce skill;
    # the skill body covers in-band + OOB + blind variants.
    "scan_blind_cmd_injection": "rce",
    "scan_cmd_injection": "rce",
    # scan_blind_ssrf shares the ssrf skill (covers OAST oracle).
    "scan_blind_ssrf": "ssrf",
    # scan_oob_xxe shares the xxe skill (covers OOB section).
    "scan_oob_xxe": "xxe",
    # scan_request_smuggling_active maps to request_smuggling.
    "scan_request_smuggling_active": "request_smuggling",
    # scan_subdomain_takeover_active maps to subdomain_takeover.
    "scan_subdomain_takeover_active": "subdomain_takeover",
    # scan_path_traversal maps to the lfi-rfi skill (canonical name on disk).
    "scan_path_traversal": "path_traversal_lfi_rfi",
    # API-specific specialists map to consolidated API skills.
    "scan_api_bola": "idor",  # BOLA = OWASP API1, IDOR-equivalent on objects
    "scan_api_bfla": "broken_function_level_authorization",
    "scan_api_mass_assignment": "mass_assignment",
    "scan_api_rate_limit": "api_resource_consumption",
    "scan_api_grpc_reflection": "api_inventory",
    "graphql_introspection_deep": "api_inventory",
    # Multi-role auth orchestrator — captured by the auth + authz skills.
    "scan_multi_role_auth": "broken_function_level_authorization",
    # Auth-flow specialist covers default-creds + session capture; closest skill
    # is JWT (overlap on session handling). Allow-listed; revisit when an
    # `authentication_default_creds.md` skill lands.
    "scan_auth_flow": "authentication_jwt",
    # misconfig specialist runs across a broad surface; covered by
    # information_disclosure for the most common output (exposed configs).
    "scan_misconfig": "information_disclosure",
    # OAuth: dedicated skill exists.
    "scan_oauth": "oauth_oidc",
    # IDOR: dedicated skill.
    "scan_idor": "idor",
    # Naming-mismatch mappings (filename stem differs from specialist stem).
    "scan_sqli": "sql_injection",
    "scan_race_condition": "race_conditions",
}

# Specialists that don't get a skill — meta / coordination tools or
# pure-recon helpers that produce no findings on their own.
_SKILL_EXEMPT: frozenset[str] = frozenset({
    # not a specialist — file is the result schema / shared helper
    "result",
    "registry",
    "_request_builders",
    "async_dispatch",
    "llm_orchestrator",
    "ssrf_probes",
    "xss_contexts",
})


def _specialist_modules() -> list[str]:
    """List every `scan_*` / specialist-class module name in
    `strix/tools/specialist/`. Excludes private helpers."""
    base = (
        get_strix_resource_path("tools").parent / "tools" / "specialist"
    )
    return [
        p.stem
        for p in base.glob("*.py")
        if not p.stem.startswith("__")
        and p.stem not in _SKILL_EXEMPT
    ]


def _skill_names() -> set[str]:
    """All skill filenames (stems) in `strix/skills/vulnerabilities/`."""
    base = get_strix_resource_path("skills") / "vulnerabilities"
    return {p.stem for p in base.glob("*.md")}


def test_every_specialist_has_a_paired_skill() -> None:
    """Every specialist module must resolve to a known skill, either
    by direct name match or via `_EQUIVALENT_SKILLS`."""
    specialists = _specialist_modules()
    skills = _skill_names()

    unmatched: list[str] = []
    for specialist in specialists:
        # Direct match: scan_xss → xss.md
        canonical = specialist.replace("scan_", "", 1)
        if canonical in skills:
            continue
        # Equivalence map
        mapped = _EQUIVALENT_SKILLS.get(specialist)
        if mapped and mapped in skills:
            continue
        unmatched.append(specialist)

    assert not unmatched, (
        f"Specialists without a paired skill: {unmatched}. "
        f"Either add `strix/skills/vulnerabilities/<name>.md` or "
        f"extend `_EQUIVALENT_SKILLS` in this test."
    )


def test_new_phase_1a_skills_present() -> None:
    """Pin that the 11 Phase-1A skills landed and are parseable."""
    base = get_strix_resource_path("skills") / "vulnerabilities"
    expected = [
        "saml_xsw",
        "deserialization",
        "ssti",
        "nosql_injection",
        "prototype_pollution",
        "cache_deception",
        "request_smuggling",
        "websocket_auth",
        "ldap_injection",
        "xpath_injection",
        "oauth_oidc",
    ]
    for skill in expected:
        path: Path = base / f"{skill}.md"
        assert path.exists(), f"missing skill: {path}"
        content = path.read_text(encoding="utf-8")
        # Must have frontmatter
        assert content.startswith("---\n"), f"{skill}: missing frontmatter"
        # Must declare a name + description
        assert "\nname:" in content, f"{skill}: missing `name:` field"
        assert "\ndescription:" in content, (
            f"{skill}: missing `description:` field"
        )
        # Must declare triggers (Phase-1A standard)
        assert "\ntriggers:" in content, (
            f"{skill}: Phase-1A skills must declare `triggers:` for "
            f"menu keyword-matching"
        )


def test_phase_1a_skills_appear_in_menu() -> None:
    """The Decepticon two-level menu must pick up the new skills."""
    from strix.skills.menu import generate_skills_menu

    menu = generate_skills_menu()
    expected = [
        "saml_xsw",
        "deserialization",
        "ssti",
        "nosql_injection",
        "prototype_pollution",
        "cache_deception",
        "request_smuggling",
        "websocket_auth",
        "ldap_injection",
        "xpath_injection",
        "oauth_oidc",
    ]
    missing = [s for s in expected if s not in menu]
    assert not missing, f"skills missing from generated menu: {missing}"


def test_phase_1b_reconnaissance_skills_present() -> None:
    """Pin that the 7 Phase-1B reconnaissance skills landed and parse."""
    base = get_strix_resource_path("skills") / "reconnaissance"
    expected = [
        "subdomain_strategy",
        "dns_hygiene_attacks",
        "asset_discovery_pipeline",
        "threat_intel_pivoting",
        "kev_diff_workflow",
        "har_burp_ingestion",
        "openapi_recon",
    ]
    for skill in expected:
        path: Path = base / f"{skill}.md"
        assert path.exists(), f"missing reconnaissance skill: {path}"
        content = path.read_text(encoding="utf-8")
        assert content.startswith("---\n"), f"{skill}: missing frontmatter"
        assert "\nname:" in content, f"{skill}: missing `name:` field"
        assert "\ndescription:" in content, (
            f"{skill}: missing `description:` field"
        )
        assert "\ntriggers:" in content, f"{skill}: missing `triggers:` field"


def test_reconnaissance_category_no_longer_empty() -> None:
    """Phase 1B closes the empty reconnaissance/ category."""
    from strix.skills import get_available_skills

    available = get_available_skills()
    assert "reconnaissance" in available, (
        "reconnaissance category should appear in available skills"
    )
    assert len(available["reconnaissance"]) >= 7, (
        f"expected ≥7 reconnaissance skills; got "
        f"{len(available['reconnaissance'])}: {available['reconnaissance']}"
    )


def test_phase_1b_skills_appear_in_menu() -> None:
    """Reconnaissance category renders in the menu."""
    from strix.skills.menu import generate_skills_menu

    menu = generate_skills_menu()
    assert "RECONNAISSANCE" in menu, (
        "RECONNAISSANCE category header missing from menu"
    )
    expected = [
        "subdomain_strategy",
        "dns_hygiene_attacks",
        "asset_discovery_pipeline",
        "threat_intel_pivoting",
        "kev_diff_workflow",
        "har_burp_ingestion",
        "openapi_recon",
    ]
    missing = [s for s in expected if s not in menu]
    assert not missing, f"reconnaissance skills missing from menu: {missing}"


def test_phase_2_cloud_skills_present() -> None:
    """Pin that the 13 Phase-2 cloud skills landed and are parseable."""
    base = get_strix_resource_path("skills") / "cloud"
    expected = [
        "aws_iam_chains",
        "aws_s3_attack_surface",
        "aws_lambda_attack_surface",
        "aws_rds_attack_surface",
        "aws_secrets_manager",
        "azure_rbac_chains",
        "azure_blob_attack_surface",
        "gcp_iam_chains",
        "gcp_bigquery_attack_surface",
        "gcp_cloud_run_attack_surface",
        "cloudtrail_anomaly_patterns",
        "cloud_attack_path_traversal",
        "dspm_pii_classification",
    ]
    for skill in expected:
        path: Path = base / f"{skill}.md"
        assert path.exists(), f"missing cloud skill: {path}"
        content = path.read_text(encoding="utf-8")
        assert content.startswith("---\n"), f"{skill}: missing frontmatter"
        assert "\nname:" in content, f"{skill}: missing `name:` field"
        assert "\ndescription:" in content, (
            f"{skill}: missing `description:` field"
        )
        assert "\ntriggers:" in content, (
            f"{skill}: Phase-2 cloud skills must declare `triggers:`"
        )


def test_phase_2_cloud_category_grows() -> None:
    """Pre-Phase-2 the cloud category had only kubernetes.md (1 skill).
    Phase 2 adds 13 → ≥14 total."""
    from strix.skills import get_available_skills

    available = get_available_skills()
    assert "cloud" in available, "cloud category missing"
    assert len(available["cloud"]) >= 14, (
        f"expected ≥14 cloud skills after Phase 2; got "
        f"{len(available['cloud'])}: {available['cloud']}"
    )


def test_phase_2_cloud_skills_appear_in_menu() -> None:
    """The Decepticon menu picks up the new cloud skills."""
    from strix.skills.menu import generate_skills_menu

    menu = generate_skills_menu()
    assert "CLOUD" in menu, "CLOUD category header missing from menu"
    expected = [
        "aws_iam_chains",
        "aws_s3_attack_surface",
        "aws_lambda_attack_surface",
        "aws_rds_attack_surface",
        "aws_secrets_manager",
        "azure_rbac_chains",
        "azure_blob_attack_surface",
        "gcp_iam_chains",
        "gcp_bigquery_attack_surface",
        "gcp_cloud_run_attack_surface",
        "cloudtrail_anomaly_patterns",
        "cloud_attack_path_traversal",
        "dspm_pii_classification",
    ]
    missing = [s for s in expected if s not in menu]
    assert not missing, f"cloud skills missing from menu: {missing}"
