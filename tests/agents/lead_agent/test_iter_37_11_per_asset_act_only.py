"""Tests for iter-37.11 — per-asset minimal catalogs trimmed to ACT-only.

iter-37.2 trimmed per-asset catalogs from ~85 (legacy) to 10
(minimal). iter-37.11 takes the next cut: drop tools whose result is
already produced by the OSS anchor prepass (`anchor_prepass.py`).
The principle is OODA: OBSERVE + ORIENT are the harness's job
(deterministic prepass); the LLM only needs ACT tools in catalog.

Two assets stay unchanged because they have NO comprehensive prepass:
  * `ip_address` — only `probe_open_tcp_ports` + per-port banners
  * `domain`     — no prepass at all
"""

from __future__ import annotations

import os

import pytest

from strix.agents.lead_agent.tool_catalog import (
    _MINIMAL_TOOLS_BY_TARGET_TYPE,
    get_lead_tool_catalog,
)


@pytest.fixture(autouse=True)
def _clean_env():
    saved = os.environ.pop("STRIX_LEGACY_CATALOG", None)
    try:
        yield
    finally:
        os.environ.pop("STRIX_LEGACY_CATALOG", None)
        if saved is not None:
            os.environ["STRIX_LEGACY_CATALOG"] = saved


# ---------------------------------------------------------------------------
# web_application: 10 → 5 (ACT-only)
# ---------------------------------------------------------------------------


def test_web_specialist_set_has_3_tools():
    """iter-37.11 trimmed to 5 ACT-only. iter-37.14 promoted 3 OSS
    wrappers to 8. iter-Q5.3 dropped the deep-exploit OSS wrappers
    (sqlmap, dalfox, smuggler, hydra, ffuf) to `anchor_prepass` per
    CLAUDE.md §1.5 (tools are LLM's hands, not its brain) → 3
    specialists (scan_idor, scan_auth_flow, send_request).

    Maintenance note for future iter-Q5.10: scan_idor + scan_auth_flow
    collapse under `dispatch_l2_probe(kind, **kwargs)` → 2 specialists
    after that lands. Update this assertion when Q5.10 ships."""
    web = _MINIMAL_TOOLS_BY_TARGET_TYPE["web_application"]
    assert len(web) == 3, (
        f"web_application should have 3 ACT-only specialists post "
        f"iter-Q5.3; got {len(web)}: {sorted(web)}"
    )


def test_web_specialist_set_drops_deep_exploit_tools_to_prepass():
    """iter-Q5.3: sqlmap, dalfox, smuggler are now in anchor_prepass,
    not in the L2 catalog. The lead re-fires on candidates via the
    future `rescan(tool_name, target, captured_state)` (iter-Q5.9)."""
    web = _MINIMAL_TOOLS_BY_TARGET_TYPE["web_application"]
    for prepass_tool in (
        "scan_sqli_sqlmap",
        "scan_xss_dalfox",
        "scan_smuggling_smuggler",
        "probe_default_creds_hydra",
        "scan_fuzz_ffuf",
    ):
        assert prepass_tool not in web, (
            f"{prepass_tool} was moved to anchor_prepass by iter-Q5.3; "
            f"must not appear in the L2 catalog. The lead re-fires it "
            f"via rescan(...) (Q5.9) when new state is captured."
        )


def test_web_specialist_set_keeps_llm_orchestrated():
    """scan_idor + scan_auth_flow are LLM-orchestrated (no OSS
    substitute for session-aware authz / multi-step auth)."""
    web = _MINIMAL_TOOLS_BY_TARGET_TYPE["web_application"]
    assert "scan_idor" in web
    assert "scan_auth_flow" in web


def test_web_specialist_set_keeps_http_primitive():
    """send_request is the LLM-driven HTTP fallback for cases the
    prepass dispatcher didn't cover."""
    web = _MINIMAL_TOOLS_BY_TARGET_TYPE["web_application"]
    assert "send_request" in web


def test_web_specialist_set_drops_prepass_duplicates():
    """Recon (katana) + broad-orient (nuclei) + auth-seed (seed_auth)
    + TLS hygiene (tls_audit) all fire in the prepass. The LLM
    doesn't need them in catalog — re-firing wastes tokens."""
    web = _MINIMAL_TOOLS_BY_TARGET_TYPE["web_application"]
    for prepass_tool in (
        "crawl_with_katana",
        "scan_nuclei_templates",
        "seed_auth",
        "tls_audit",
        "browser_action",
    ):
        assert prepass_tool not in web, (
            f"{prepass_tool} was dropped by iter-37.11 — it fires "
            f"in the prepass (or is rarely the right LLM call)."
        )


# ---------------------------------------------------------------------------
# api: 10 → 5
# ---------------------------------------------------------------------------


def test_api_specialist_set_has_4_tools():
    """iter-37.14 had 9 specialists. iter-Q5.3 dropped 5 OSS wrappers
    (sqlmap, smuggler, hydra, ffuf, schemathesis) to anchor_prepass
    per CLAUDE.md §1.5 → 4 specialists (scan_idor, scan_auth_flow,
    map_graphql_inql, send_request).

    Maintenance note for future Q5.5: map_graphql_inql is an OSS
    wrapper too and moves to prepass in Q5.5 → 3 specialists. And
    Q5.10 collapses scan_idor + scan_auth_flow → 2 specialists."""
    api = _MINIMAL_TOOLS_BY_TARGET_TYPE["api"]
    assert len(api) == 4, (
        f"api should have 4 ACT-only specialists post iter-Q5.3; "
        f"got {len(api)}: {sorted(api)}"
    )


def test_api_specialist_drops_deep_exploit_tools_to_prepass():
    """iter-Q5.3: same migration as web — sqlmap / smuggler / hydra /
    ffuf / schemathesis fire in anchor_prepass, not in the L2 catalog."""
    api = _MINIMAL_TOOLS_BY_TARGET_TYPE["api"]
    for prepass_tool in (
        "scan_sqli_sqlmap",
        "scan_smuggling_smuggler",
        "probe_default_creds_hydra",
        "scan_fuzz_ffuf",
        "scan_api_schemathesis",
    ):
        assert prepass_tool not in api, (
            f"{prepass_tool} was moved to anchor_prepass by iter-Q5.3; "
            f"must not appear in the L2 catalog."
        )


def test_api_specialist_keeps_graphql_specific():
    """GraphQL deep work (InQL) has no OSS substitute for fine-
    grained schema mutation testing."""
    api = _MINIMAL_TOOLS_BY_TARGET_TYPE["api"]
    assert "map_graphql_inql" in api


def test_api_specialist_drops_prepass_duplicates():
    api = _MINIMAL_TOOLS_BY_TARGET_TYPE["api"]
    for prepass_tool in (
        "openapi_spec_ingest",
        "crawl_with_katana",
        "scan_nuclei_templates",
        "seed_auth",
        "tls_audit",
    ):
        assert prepass_tool not in api, (
            f"{prepass_tool} in api specialist set — should be dropped "
            f"per iter-37.11 (covered by anchor prepass)."
        )


# ---------------------------------------------------------------------------
# repository / local_code: 8 → 4
# ---------------------------------------------------------------------------


def test_code_specialist_set_has_5_tools():
    """iter-37.14: + scan_mobile_mobsfscan (MobSF mobile SAST) →
    5 specialists per code asset."""
    for asset in ("repository", "local_code"):
        tools = _MINIMAL_TOOLS_BY_TARGET_TYPE[asset]
        assert len(tools) == 5, (
            f"{asset} should have 5 ACT-only specialists post "
            f"iter-37.14; got {len(tools)}: {sorted(tools)}"
        )


def test_code_specialist_keeps_llm_orchestrated():
    """build_code_map + taint_analysis are LLM-orchestrated and have
    no OSS substitute."""
    for asset in ("repository", "local_code"):
        tools = _MINIMAL_TOOLS_BY_TARGET_TYPE[asset]
        assert "build_code_map" in tools
        assert "taint_analysis" in tools


def test_code_specialist_drops_prepass_orient_tools():
    """semgrep/gitleaks/trivy fs/trivy IaC fire in the prepass."""
    for asset in ("repository", "local_code"):
        tools = _MINIMAL_TOOLS_BY_TARGET_TYPE[asset]
        for prepass_tool in (
            "scan_sast",                # semgrep
            "secrets_scan",             # gitleaks
            "scan_sca_lockfiles",       # trivy fs
            "scan_iac",                 # IaC misconfig
        ):
            assert prepass_tool not in tools, (
                f"{asset}: {prepass_tool} in specialist set — covered "
                f"by code prepass."
            )


# ---------------------------------------------------------------------------
# container_image: 4 → 2
# ---------------------------------------------------------------------------


def test_container_specialist_set_has_2_tools():
    tools = _MINIMAL_TOOLS_BY_TARGET_TYPE["container_image"]
    assert len(tools) == 2, (
        f"container_image should have 2 ACT-only specialists; got "
        f"{len(tools)}: {sorted(tools)}"
    )


def test_container_specialist_keeps_dockle_and_terminal():
    """dockle isn't in prepass; terminal for image inspection."""
    tools = _MINIMAL_TOOLS_BY_TARGET_TYPE["container_image"]
    assert "scan_image_dockle" in tools
    assert "terminal_execute" in tools


def test_container_specialist_drops_trivy_in_catalog():
    """trivy (scan_container_image) fires in the container prepass."""
    tools = _MINIMAL_TOOLS_BY_TARGET_TYPE["container_image"]
    assert "scan_container_image" not in tools


# ---------------------------------------------------------------------------
# Unchanged assets (no comprehensive prepass)
# ---------------------------------------------------------------------------


def test_ip_address_keeps_recon_in_catalog():
    """ip_address has only thin prepass (port discovery + banner
    probes) — LLM still needs nmap/httpx/nuclei in catalog."""
    tools = _MINIMAL_TOOLS_BY_TARGET_TYPE["ip_address"]
    assert "fingerprint_services_nmap" in tools
    assert "probe_hosts_httpx" in tools
    assert "scan_nuclei_templates" in tools


def test_domain_keeps_recon_in_catalog():
    """domain has no prepass — LLM drives all recon."""
    tools = _MINIMAL_TOOLS_BY_TARGET_TYPE["domain"]
    assert "domain_recon_pipeline" in tools or "enumerate_subdomains_subfinder" in tools
    assert "scan_nuclei_templates" in tools


# ---------------------------------------------------------------------------
# Total catalog sizes — the headline win
# ---------------------------------------------------------------------------


def test_web_total_catalog_at_or_under_13_tools():
    """iter-37.11: 5 core + 5 specialist = 10.
    iter-37.14: + 3 OSS wrappers (hydra/ffuf/smuggler) = 13. Still
    well under the 50-tool decision-paralysis threshold + matches
    the audit doc's ~8-15 band."""
    tools = get_lead_tool_catalog(target_types=["web_application"])
    assert len(tools) <= 13, (
        f"web_application catalog is {len(tools)} tools — iter-37.14 "
        f"target is ≤13 (5 core + 8 specialist)."
    )


def test_api_total_catalog_at_or_under_14_tools():
    """iter-37.14: 5 core + 9 specialist (added hydra, ffuf,
    schemathesis, smuggler) = 14."""
    tools = get_lead_tool_catalog(target_types=["api"])
    assert len(tools) <= 14


def test_code_total_catalog_at_or_under_10_tools():
    """iter-37.14: 5 core + 5 specialist (added mobsfscan) = 10."""
    for asset in ("repository", "local_code"):
        tools = get_lead_tool_catalog(target_types=[asset])
        assert len(tools) <= 10, f"{asset} has {len(tools)} tools"


def test_container_total_catalog_at_or_under_7_tools():
    """5 core + 2 specialist = 7."""
    tools = get_lead_tool_catalog(target_types=["container_image"])
    assert len(tools) <= 7


# ---------------------------------------------------------------------------
# Reduction from legacy
# ---------------------------------------------------------------------------


def test_web_catalog_dramatically_smaller_under_minimal():
    """Headline test: minimal catalog must be ≥80% smaller than legacy.
    Legacy ~99 → minimal ~10 = 90% reduction. This is the iter-37
    thesis in one assertion."""
    minimal = get_lead_tool_catalog(target_types=["web_application"])
    os.environ["STRIX_LEGACY_CATALOG"] = "1"
    legacy = get_lead_tool_catalog(target_types=["web_application"])
    assert len(minimal) < len(legacy) * 0.2, (
        f"iter-37.11 web catalog is {len(minimal)} tools vs legacy "
        f"{len(legacy)} ({100 * len(minimal) / len(legacy):.0f}%). "
        f"Target: <20% of legacy (90%+ reduction)."
    )


# ---------------------------------------------------------------------------
# Dropped tools still registered + executable
# ---------------------------------------------------------------------------


def test_dropped_prepass_tools_still_registered():
    """Dropped tools must remain callable via the registry — sandbox
    tool-server, prepass itself, and orchestrator-mode dispatch all
    still need them."""
    from strix.tools.registry import get_tool_names

    registered = set(get_tool_names())
    for tool in (
        "crawl_with_katana",
        "scan_nuclei_templates",
        "seed_auth",
        "tls_audit",
        "openapi_spec_ingest",
        "scan_sast",
        "secrets_scan",
        "scan_sca_lockfiles",
        "scan_iac",
        "scan_container_image",
    ):
        assert tool in registered, (
            f"{tool} should still be REGISTERED — only catalog "
            f"visibility changes per iter-37.11."
        )


# ---------------------------------------------------------------------------
# Legacy mode brings everything back
# ---------------------------------------------------------------------------


def test_legacy_mode_restores_full_per_asset_catalog():
    os.environ["STRIX_LEGACY_CATALOG"] = "1"
    web = get_lead_tool_catalog(target_types=["web_application"])
    # Tools that iter-37.11 dropped come back via _TOOLS_BY_TARGET_TYPE
    assert "crawl_with_katana" in web
    assert "scan_nuclei_templates" in web
    assert "seed_auth" in web
    assert "tls_audit" in web
