"""Tests for iter-37.2 — minimal OSS-anchored catalog (default ON).

Per docs/tool-catalog-rationalization.md: the L2 Lead's tool catalog
is reduced from ~99 tools per web target to ~42 (33 core + 9 minimal
per-asset, all OSS-backed). The remaining in-house duplicates are
DEPRECATED in iter-37.3 (warn-on-call) and DELETED in iter-37.5.

Default: minimal catalog ON. Set STRIX_LEGACY_CATALOG=1 to restore
pre-iter-37.2 behavior for backwards-compat.
"""

from __future__ import annotations

import os

import pytest

from strix.agents.lead_agent.tool_catalog import (
    _MINIMAL_TOOLS_BY_TARGET_TYPE,
    _TOOLS_BY_TARGET_TYPE,
    get_lead_tool_catalog,
    is_legacy_catalog_enabled,
)


@pytest.fixture(autouse=True)
def _clean_env():
    """Each test starts with STRIX_LEGACY_CATALOG unset. Restore the
    pre-test value after, regardless of what the test did."""
    saved = os.environ.pop("STRIX_LEGACY_CATALOG", None)
    try:
        yield
    finally:
        # ALWAYS clean up — if the test set the var, pop it; then
        # restore whatever was set before.
        os.environ.pop("STRIX_LEGACY_CATALOG", None)
        if saved is not None:
            os.environ["STRIX_LEGACY_CATALOG"] = saved


# ---------------------------------------------------------------------------
# Env-gate
# ---------------------------------------------------------------------------

def test_legacy_catalog_disabled_by_default():
    """Minimal catalog is the new default; legacy is opt-in."""
    assert is_legacy_catalog_enabled() is False


def test_legacy_catalog_enabled_via_env():
    for v in ("1", "true", "TRUE", "yes", "on", "On"):
        os.environ["STRIX_LEGACY_CATALOG"] = v
        assert is_legacy_catalog_enabled() is True, f"failed for {v!r}"


def test_legacy_catalog_disabled_for_falsy():
    for v in ("0", "false", "no", "off", ""):
        os.environ["STRIX_LEGACY_CATALOG"] = v
        assert is_legacy_catalog_enabled() is False, f"failed for {v!r}"


# ---------------------------------------------------------------------------
# Catalog size reduction — the headline win
# ---------------------------------------------------------------------------

def test_web_catalog_dramatically_smaller_under_minimal():
    minimal = get_lead_tool_catalog(target_types=["web_application"])
    os.environ["STRIX_LEGACY_CATALOG"] = "1"
    legacy = get_lead_tool_catalog(target_types=["web_application"])
    # iter-37.2 — minimal must be at least 30% smaller than legacy
    assert len(minimal) < len(legacy) * 0.7, (
        f"iter-37.2 minimal catalog ({len(minimal)} tools) should be "
        f"meaningfully smaller than legacy ({len(legacy)} tools). "
        f"If they're close, the migration didn't take effect."
    )


def test_api_catalog_dramatically_smaller_under_minimal():
    minimal = get_lead_tool_catalog(target_types=["api"])
    os.environ["STRIX_LEGACY_CATALOG"] = "1"
    legacy = get_lead_tool_catalog(target_types=["api"])
    assert len(minimal) < len(legacy) * 0.7


# ---------------------------------------------------------------------------
# OSS-anchored tools are present per asset type
# ---------------------------------------------------------------------------

def test_web_minimal_catalog_includes_oss_recon():
    """iter-37.11 superseded the iter-37.2 contract: katana fires in
    the anchor prepass (_ANCHORS_WEB), not in the LLM catalog. Verify
    the prepass coverage instead."""
    from strix.agents.lead_agent.anchor_prepass import (
        _ANCHORS_BY_TARGET_TYPE,
    )
    anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE["web_application"]}
    assert "crawl_with_katana" in anchors


def test_web_minimal_catalog_includes_oss_generic_detection():
    """iter-37.11 superseded: nuclei fires in the prepass, not catalog."""
    from strix.agents.lead_agent.anchor_prepass import (
        _ANCHORS_BY_TARGET_TYPE,
    )
    anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE["web_application"]}
    assert "scan_nuclei_templates" in anchors


def test_web_minimal_catalog_includes_oss_sqli_xss():
    tools = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_sqli_sqlmap" in tools
    assert "scan_xss_dalfox" in tools


def test_web_minimal_catalog_includes_oss_tls():
    """iter-37.11 superseded: tls_audit fires in the prepass."""
    from strix.agents.lead_agent.anchor_prepass import (
        _ANCHORS_BY_TARGET_TYPE,
    )
    anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE["web_application"]}
    assert "tls_audit" in anchors


def test_api_minimal_catalog_anchors_on_openapi():
    """iter-37.11 superseded: openapi_spec_ingest fires in the prepass."""
    from strix.agents.lead_agent.anchor_prepass import (
        _ANCHORS_BY_TARGET_TYPE,
    )
    anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE["api"]}
    assert "openapi_spec_ingest" in anchors


def test_api_minimal_catalog_includes_graphql_inql():
    """GraphQL endpoints are common on API targets. InQL stays in
    catalog — no comparable OSS substitute for fine-grained schema
    mutation testing."""
    tools = get_lead_tool_catalog(target_types=["api"])
    assert "map_graphql_inql" in tools


def test_code_minimal_catalog_anchors_on_semgrep_trivy():
    """iter-37.11 superseded: SAST + SCA + secrets fire in the
    prepass, not in catalog."""
    from strix.agents.lead_agent.anchor_prepass import (
        _ANCHORS_BY_TARGET_TYPE,
    )
    for asset in ("repository", "local_code"):
        anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE[asset]}
        assert "scan_sast" in anchors, f"{asset} missing semgrep in prepass"
        assert "scan_sca_lockfiles" in anchors, (
            f"{asset} missing trivy fs in prepass"
        )
        assert "secrets_scan" in anchors, (
            f"{asset} missing gitleaks in prepass"
        )


def test_container_minimal_catalog_anchors_on_trivy():
    """iter-37.11 superseded: trivy (scan_container_image) fires in
    the prepass. dockle stays in catalog (not prepass-covered)."""
    from strix.agents.lead_agent.anchor_prepass import (
        _ANCHORS_BY_TARGET_TYPE,
    )
    anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE["container_image"]}
    assert "scan_container_image" in anchors  # trivy — prepass
    tools = get_lead_tool_catalog(target_types=["container_image"])
    assert "scan_image_dockle" in tools  # dockle — still in catalog


def test_ip_minimal_catalog_anchors_on_nmap_nuclei():
    tools = get_lead_tool_catalog(target_types=["ip_address"])
    assert "fingerprint_services_nmap" in tools  # nmap
    assert "scan_nuclei_templates" in tools  # nuclei templates


def test_domain_minimal_catalog_anchors_on_subfinder_bbot():
    tools = get_lead_tool_catalog(target_types=["domain"])
    assert "domain_recon_pipeline" in tools or "enumerate_subdomains_subfinder" in tools


# ---------------------------------------------------------------------------
# Deprecated in-house duplicates are HIDDEN from minimal catalog
# ---------------------------------------------------------------------------

def test_web_minimal_hides_in_house_sqli():
    """In-house scan_sqli is hidden — LLM should use scan_sqli_sqlmap (OSS)."""
    tools = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_sqli" not in tools, (
        "scan_sqli (in-house) leaked into minimal catalog. The minimal "
        "catalog should expose scan_sqli_sqlmap (OSS-anchored)."
    )


def test_web_minimal_hides_in_house_xss():
    tools = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_xss" not in tools


def test_web_minimal_hides_in_house_ssrf():
    """In-house SSRF scanners hidden — use nuclei SSRF templates."""
    tools = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_ssrf" not in tools
    assert "scan_blind_ssrf" not in tools


def test_web_minimal_hides_other_duplicates():
    """Various in-house duplicates that route through nuclei templates."""
    tools = get_lead_tool_catalog(target_types=["web_application"])
    for forbidden in (
        "scan_xxe", "scan_oob_xxe",
        "scan_cmd_injection", "scan_blind_cmd_injection",
        "scan_path_traversal", "scan_ldap_injection",
        "scan_xpath_injection", "scan_ssti", "scan_nosql_injection",
        "scan_deserialization", "scan_misconfig",
        "scan_cache_deception", "scan_prototype_pollution",
        "scan_websocket_auth", "scan_race_condition",
        "scan_authn_metadata", "scan_saml_xsw", "scan_oauth",
        "scan_secrets_in_response", "scan_request_smuggling_active",
        "cors_deep_check", "csrf_check", "open_redirect_check",
        "host_header_check", "method_tamper_check",
        "debug_endpoint_check", "file_upload_abuse_check",
        "scan_response_anomaly", "scan_timing_oracle",
    ):
        assert forbidden not in tools, (
            f"iter-37.2 minimal catalog leaked deprecated in-house "
            f"tool: {forbidden!r}. Route through nuclei templates."
        )


def test_api_minimal_hides_api_specific_duplicates():
    """API-shaped in-house duplicates merged into scan_idor."""
    tools = get_lead_tool_catalog(target_types=["api"])
    for forbidden in (
        "scan_api_bola", "scan_api_bfla",
        "scan_multi_role_auth",
    ):
        assert forbidden not in tools, (
            f"iter-37.2: {forbidden!r} should be merged into scan_idor "
            f"(session-aware authz)."
        )


# ---------------------------------------------------------------------------
# Backwards-compat — legacy catalog still works under env-flag
# ---------------------------------------------------------------------------

def test_legacy_catalog_restores_full_set():
    """Setting STRIX_LEGACY_CATALOG=1 returns the pre-iter-37.2 catalog."""
    os.environ["STRIX_LEGACY_CATALOG"] = "1"
    tools = get_lead_tool_catalog(target_types=["web_application"])
    # The in-house scanners come back when legacy mode is on
    assert "scan_sqli" in tools
    assert "scan_xss" in tools
    assert "scan_ssrf" in tools


def test_minimal_table_no_duplicate_within_asset():
    """Each minimal per-asset set must have unique tools."""
    for asset, tools in _MINIMAL_TOOLS_BY_TARGET_TYPE.items():
        # frozenset enforces this, but assert anyway
        assert len(tools) == len(set(tools))


# ---------------------------------------------------------------------------
# LLM choice space — quantitative check
# ---------------------------------------------------------------------------

def test_minimal_catalog_under_50_tools_per_asset():
    """The LLM decision space per asset type must stay under 50 tools.
    Above that, decision paralysis sets in (v3/v4/v5 bench evidence)."""
    for asset in _MINIMAL_TOOLS_BY_TARGET_TYPE:
        tools = get_lead_tool_catalog(target_types=[asset])
        assert len(tools) < 50, (
            f"{asset} catalog has {len(tools)} tools — over the 50-tool "
            f"decision-paralysis threshold. Per docs/tool-catalog-"
            f"rationalization.md, target is ~8-15 per asset (the rest "
            f"is core framework tools)."
        )


def test_minimal_per_asset_specialist_set_is_compact():
    """The PER-ASSET specialist set (excluding shared core) should be
    ≤15 tools — matches the audit doc's target."""
    for asset, specialists in _MINIMAL_TOOLS_BY_TARGET_TYPE.items():
        assert len(specialists) <= 15, (
            f"Minimal specialist set for {asset} has {len(specialists)} "
            f"tools — should be ≤15 per docs/tool-catalog-rationalization.md"
        )


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_no_in_house_duplicates_of_oss_tools():
    """Verify the minimal sets don't accidentally re-include both the
    OSS wrapper AND its in-house duplicate."""
    for asset, tools in _MINIMAL_TOOLS_BY_TARGET_TYPE.items():
        # SQLi: only sqlmap, never scan_sqli
        if "scan_sqli_sqlmap" in tools:
            assert "scan_sqli" not in tools, f"{asset}: both sqlmap + in-house SQLi"
        # XSS: only dalfox + nuclei, never in-house scan_xss
        if "scan_xss_dalfox" in tools:
            assert "scan_xss" not in tools, f"{asset}: both dalfox + in-house XSS"
