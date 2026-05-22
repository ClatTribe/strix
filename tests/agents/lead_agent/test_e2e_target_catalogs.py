"""E2E Phase D — per-target Lead-catalog membership.

Per `docs/E2E-test-proposal.md` §3.5. Each test asserts that
`get_lead_tool_catalog(["<target_type>"])` returns a set including the
asset-specific anchor tools PLUS the L1.5-aware core tools added in
iter-26 (`list_pending_findings`, `drain_amplify_queue`,
`execute_adaptive_probe`).

Pure registry inspection — no Tracer, no subprocess, no mocks needed.
"""

from __future__ import annotations

import pytest

from strix.agents.lead_agent.tool_catalog import (
    get_lead_tool_catalog,
    list_target_types,
)


# iter-26 added these to _CORE_TOOLS; every target_type catalog must
# include them.
_L15_CORE_TOOLS = {
    "list_pending_findings",
    "drain_amplify_queue",
    "execute_adaptive_probe",
}


def _assert_l15_core(catalog: set[str]) -> None:
    missing = _L15_CORE_TOOLS - catalog
    assert not missing, (
        f"L1.5-aware core tools missing from catalog: {missing}"
    )


# =========================================================================
# E2E-L2-web-1 — web_application catalog
# =========================================================================

def test_web_application_catalog():
    catalog = get_lead_tool_catalog(target_types={"web_application"})
    _assert_l15_core(catalog)
    # Web-anchor recon + active specialists. crawl_with_katana
    # supersedes bfs_crawl; probe_hosts_httpx with -tech-detect
    # supersedes fingerprint_tech_stack (per docs/L2-optimization.md
    # §5.3) — those legacy tools intentionally dropped from the web
    # catalog to keep under the 90-tool prompt-token budget.
    required_web = {
        "crawl_with_katana",
        "probe_hosts_httpx",
        "discover_paths_feroxbuster",
        "scan_xss",
        "scan_sqli",
        "scan_xss_dalfox",
        "scan_sqli_sqlmap",
        "scan_xxe",
        "scan_nuclei_templates",
        "http_security_headers_audit",
        "tls_audit",
        "cors_deep_check",
        "csrf_check",
    }
    missing = required_web - catalog
    assert not missing, (
        f"web_application catalog missing essential tools: {missing}"
    )


# =========================================================================
# E2E-L2-api-1 — api catalog
# =========================================================================

def test_api_catalog():
    catalog = get_lead_tool_catalog(target_types={"api"})
    _assert_l15_core(catalog)
    # API-specific anchors
    required_api = {
        "openapi_spec_ingest",
        "scan_api_bola",
        "scan_api_bfla",
        "scan_api_mass_assignment",
        "scan_api_rate_limit",
        "jwt_audit",
        "scan_sqli",
        "scan_idor",
    }
    missing = required_api - catalog
    assert not missing, (
        f"api catalog missing essential tools: {missing}"
    )


# =========================================================================
# E2E-L2-repo-1 — repository catalog
# =========================================================================

def test_repository_catalog():
    catalog = get_lead_tool_catalog(target_types={"repository"})
    _assert_l15_core(catalog)
    # Repository / local_code anchors
    required_repo = {
        "scan_sast",
        "scan_sca_lockfiles",
        "secrets_scan",
        "scan_iac",
        "sbom_extract",
    }
    missing = required_repo - catalog
    assert not missing, (
        f"repository catalog missing essential tools: {missing}"
    )
    # iter-22.9 §5.4 guardrail — SAST/SCA must NOT leak into the
    # web_application catalog
    web_catalog = get_lead_tool_catalog(target_types={"web_application"})
    leaked = {"scan_sca_lockfiles", "scan_sast"} & web_catalog
    assert not leaked, (
        f"iter-22.9 §5.4 regression: SAST/SCA leaked into web "
        f"catalog: {leaked}"
    )


# =========================================================================
# E2E-L2-host-1 — ip_address catalog
# =========================================================================

def test_ip_address_catalog():
    catalog = get_lead_tool_catalog(target_types={"ip_address"})
    _assert_l15_core(catalog)
    # IP / host anchors — nmap is the primary IP-target tool from
    # iter-23.1; tls_audit_testssl is the TLS auditor; httpx for HTTP
    # ports.
    required_ip = {
        "fingerprint_services_nmap",
        "tls_audit_testssl",
        "probe_hosts_httpx",
    }
    missing = required_ip - catalog
    assert not missing, (
        f"ip_address catalog missing essential tools: {missing}"
    )


# =========================================================================
# E2E-L2-container-1 — container_image catalog
# =========================================================================

def test_container_image_catalog():
    catalog = get_lead_tool_catalog(target_types={"container_image"})
    _assert_l15_core(catalog)
    # Container anchors
    required_container = {
        "scan_container_image",
        "scan_image_dockle",
    }
    missing = required_container - catalog
    assert not missing, (
        f"container_image catalog missing essential tools: {missing}"
    )


# =========================================================================
# E2E-L2-cross-1 — every known target_type gets L1.5 core
# =========================================================================

def test_every_target_type_gets_l15_core_tools():
    """Cross-cutting: every target_type listed by `list_target_types()`
    must include the L1.5-aware core tools. iter-26 wired them via
    _CORE_TOOLS which is unioned with every per-type set in
    `get_lead_tool_catalog`. This test guards against a future
    refactor that accidentally drops _CORE_TOOLS from a specific
    target_type."""
    for tt in list_target_types():
        catalog = get_lead_tool_catalog(target_types={tt})
        missing = _L15_CORE_TOOLS - catalog
        assert not missing, (
            f"target_type {tt!r} missing L1.5 core: {missing}"
        )
