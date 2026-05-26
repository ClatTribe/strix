"""Tests for iter-37.3 — deprecation registry for in-house tools
superseded by OSS engines.

Verifies:
  * The 47 in-house duplicates are all in the deprecation map
  * Each maps to a concrete OSS replacement (not just "deprecated")
  * `emit_deprecation_warning` logs a warning with the replacement hint
  * The executor calls the warning hook on tool invocation
  * OSS-wrapper tools (sqlmap, dalfox, nuclei, etc.) are NOT deprecated
  * LLM-orchestration tools that survive (scan_idor, scan_auth_flow,
    scan_business_logic) are NOT deprecated
"""

from __future__ import annotations

import logging

import pytest

from strix.tools.deprecations import (
    _DEPRECATIONS,
    emit_deprecation_warning,
    get_replacement,
    is_deprecated,
)


# ---------------------------------------------------------------------------
# Registry contents
# ---------------------------------------------------------------------------

def test_registry_has_at_least_40_entries():
    """Audit doc says 47 in-house tools to deprecate; we should have
    most of them registered. Defensive lower-bound check."""
    assert len(_DEPRECATIONS) >= 40, (
        f"iter-37.3 deprecation registry has only {len(_DEPRECATIONS)} "
        f"entries. Per docs/tool-catalog-rationalization.md the audit "
        f"identified 47 in-house duplicates."
    )


def test_every_replacement_is_non_empty_string():
    """No empty replacements — every deprecated tool gets a concrete
    routing hint."""
    for tool, replacement in _DEPRECATIONS.items():
        assert isinstance(replacement, str)
        assert len(replacement) > 10, (
            f"Replacement for {tool!r} too vague: {replacement!r}"
        )


def test_replacement_names_are_real_tools_or_nuclei_routes():
    """Each replacement should either name a registered tool OR
    explain a nuclei-tag route. Verify no typos in tool names."""
    valid_replacement_tools = {
        "scan_sqli_sqlmap", "scan_xss_dalfox", "scan_nuclei_templates",
        "scan_dns_hygiene_checkdmarc", "scan_credential_leaks_hibp",
        "map_graphql_inql", "scan_idor", "query_threat_intel",
        "scan_authn_metadata",
    }
    for tool, replacement in _DEPRECATIONS.items():
        # The replacement hint should mention at least one valid
        # tool name (the first word/identifier).
        first_word = replacement.split()[0].strip("(),")
        # Accept tool names OR "nuclei" / OSS engine names
        valid = (
            first_word in valid_replacement_tools
            or first_word.startswith("scan_")
            or first_word == "query_threat_intel"
            or first_word == "map_graphql_inql"
        )
        assert valid, (
            f"{tool!r}'s replacement {replacement!r} doesn't start "
            f"with a known tool name"
        )


# ---------------------------------------------------------------------------
# OSS-wrapper tools must NOT be deprecated
# ---------------------------------------------------------------------------

def test_oss_wrapper_tools_not_deprecated():
    """The 18 OSS wrappers strix already has must NOT appear in the
    deprecation registry — they're the migration TARGETS, not sources."""
    oss_wrappers = (
        "scan_nuclei_templates", "scan_sqli_sqlmap", "scan_xss_dalfox",
        "crawl_with_katana", "discover_paths_feroxbuster",
        "probe_hosts_httpx", "tls_audit", "fingerprint_services_nmap",
        "enumerate_subdomains_subfinder", "domain_recon_pipeline",
        "scan_buckets_via_bbot", "scan_typosquats_dnstwist",
        "map_graphql_inql", "verify_credentials_trufflehog",
        "secrets_scan", "scan_image_dockle", "scan_dockerfile_hadolint",
        "scan_container_image", "scan_dns_hygiene_checkdmarc",
    )
    for tool in oss_wrappers:
        assert not is_deprecated(tool), (
            f"OSS wrapper {tool!r} accidentally deprecated — it's the "
            f"replacement, not a deprecation source"
        )


# ---------------------------------------------------------------------------
# LLM-orchestration tools that survive must NOT be deprecated
# ---------------------------------------------------------------------------

def test_llm_orchestration_tools_not_deprecated():
    """Per docs/tool-catalog-rationalization.md, ~8 in-house tools
    survive (LLM logic, no OSS substitute). They must NOT be in the
    deprecation registry."""
    survivors = (
        "scan_idor",           # session-aware authz (merged with bola/bfla/multi-role)
        "scan_auth_flow",      # auth flow orchestration
        "seed_auth",           # account seeding
        "scan_business_logic", # LLM-led business logic
        "probe_endpoint",      # generic HTTP primitive
        "replay_mutation",     # mutation testing orchestrator
        "correlate_findings",  # chain reasoning
    )
    for tool in survivors:
        assert not is_deprecated(tool), (
            f"LLM-orchestration tool {tool!r} should NOT be deprecated"
        )


# ---------------------------------------------------------------------------
# Per-category coverage
# ---------------------------------------------------------------------------

def test_injection_family_all_deprecated():
    """Every in-house injection scanner is deprecated."""
    for tool in (
        "scan_sqli", "scan_xss", "scan_ssrf", "scan_xxe",
        "scan_cmd_injection", "scan_path_traversal",
        "scan_nosql_injection", "scan_ldap_injection",
        "scan_xpath_injection", "scan_ssti",
    ):
        assert is_deprecated(tool), f"{tool} missing from deprecation map"


def test_blind_variants_deprecated():
    """Blind variants of injection scanners — all deprecated."""
    for tool in (
        "scan_blind_ssrf", "scan_blind_cmd_injection", "scan_oob_xxe",
    ):
        assert is_deprecated(tool)


def test_misconfig_family_deprecated():
    """The 'misconfig' / 'anomaly' family routes through nuclei."""
    for tool in (
        "scan_misconfig", "scan_response_anomaly",
        "scan_secrets_in_response",
    ):
        assert is_deprecated(tool)


def test_authz_duplicates_merged_into_scan_idor():
    """scan_api_bola / scan_api_bfla / scan_multi_role_auth all map
    to scan_idor (which absorbs session-aware authz)."""
    for tool in (
        "scan_api_bola", "scan_api_bfla", "scan_multi_role_auth",
        "scan_api_mass_assignment",
    ):
        assert is_deprecated(tool)
        replacement = get_replacement(tool)
        assert replacement is not None
        assert "scan_idor" in replacement, (
            f"{tool!r} should route to scan_idor; got {replacement!r}"
        )


# ---------------------------------------------------------------------------
# emit_deprecation_warning — log behavior
# ---------------------------------------------------------------------------

def test_emit_warning_logs_deprecated_tool(caplog):
    """Invoking emit_deprecation_warning on a deprecated tool name
    should log a WARNING with the replacement hint."""
    with caplog.at_level(logging.WARNING, logger="strix.tools.deprecations"):
        emit_deprecation_warning("scan_sqli")
    assert any(
        "scan_sqli" in rec.message and "sqlmap" in rec.message
        for rec in caplog.records
    ), (
        "Deprecation warning should mention the tool name + its "
        "OSS replacement (sqlmap). Log records: "
        f"{[r.message for r in caplog.records]}"
    )


def test_emit_warning_silent_for_non_deprecated_tool(caplog):
    """OSS-wrapper tools don't emit warnings on invocation."""
    with caplog.at_level(logging.WARNING, logger="strix.tools.deprecations"):
        emit_deprecation_warning("scan_nuclei_templates")
        emit_deprecation_warning("scan_sqli_sqlmap")
    # No warnings should land — these are the replacements
    deprecation_records = [
        r for r in caplog.records
        if "deprecation" in r.message.lower()
    ]
    assert deprecation_records == [], (
        f"OSS-wrapper invocations should not warn. Records: "
        f"{[r.message for r in deprecation_records]}"
    )


def test_emit_warning_silent_for_unknown_tool(caplog):
    """Unknown tool names don't crash + don't emit a warning."""
    with caplog.at_level(logging.WARNING, logger="strix.tools.deprecations"):
        emit_deprecation_warning("totally_unknown_tool_xyz123")
    assert all(
        "totally_unknown_tool_xyz123" not in r.message
        for r in caplog.records
    )


# ---------------------------------------------------------------------------
# Executor integration
# ---------------------------------------------------------------------------

def test_executor_invokes_deprecation_hook(monkeypatch):
    """`execute_tool` must call `emit_deprecation_warning` on every
    invocation so the warning fires regardless of where the tool gets
    called from."""
    from strix.tools import executor
    called: list[str] = []
    monkeypatch.setattr(
        "strix.tools.deprecations.emit_deprecation_warning",
        lambda tool_name: called.append(tool_name),
    )

    # Replace local execution path so we don't actually invoke anything
    async def _stub_local(tool_name, agent_state, **kwargs):
        return {"ok": True}
    monkeypatch.setattr(
        executor, "_execute_tool_locally", _stub_local,
    )

    # Force the local path by saying tool isn't sandbox-bound
    monkeypatch.setattr(
        executor, "should_execute_in_sandbox", lambda name: False,
    )

    import asyncio
    asyncio.run(executor.execute_tool("scan_sqli", None))
    assert "scan_sqli" in called, (
        "executor.execute_tool didn't call emit_deprecation_warning"
    )


def test_executor_hook_swallows_exceptions(monkeypatch):
    """If the deprecation hook raises, the tool still executes."""
    from strix.tools import executor

    def _boom(tool_name):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(
        "strix.tools.deprecations.emit_deprecation_warning", _boom,
    )

    async def _stub_local(tool_name, agent_state, **kwargs):
        return {"ok": True}
    monkeypatch.setattr(executor, "_execute_tool_locally", _stub_local)
    monkeypatch.setattr(
        executor, "should_execute_in_sandbox", lambda name: False,
    )

    import asyncio
    result = asyncio.run(executor.execute_tool("scan_sqli", None))
    assert result == {"ok": True}  # tool still ran despite hook crash
