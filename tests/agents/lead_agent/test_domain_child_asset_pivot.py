"""Tests for iter-Q5.44 — domain → child-asset pivoting.

The domain prepass surfaces discovered subdomains via a stable
`PrepassSummary.child_assets_discovered` sidecar so downstream
orchestrators (webappsec wrapper, L2 lead system prompt, asset graph
emitter) can pivot to per-child scans without re-parsing tool-specific
output shapes.

Coverage:
  * `_normalise_host` strips scheme / path / port
  * Extractor reads from `domain_recon_pipeline.raw_result.surface_map`:
    - `subdomain_triage` (preferred — carries IP + scheme + status)
    - `subdomain_enum.subdomains` (fallback — bare host list)
  * Extractor reads from `enumerate_subdomains_subfinder.raw_result.findings`
  * Apex is excluded from the child list
  * `triage=skip` entries are dropped
  * Dedup by host across sources, with pipeline winning over subfinder
  * `asset_type` classification: scheme present → web_application;
    no scheme → ip_address
  * Empty / malformed raw_results don't crash
  * `to_dict` serializes the sidecar
  * Non-domain target types leave the sidecar empty (no false-pivots)
"""

from __future__ import annotations

import pytest

from strix.agents.lead_agent.anchor_prepass import (
    PrepassSummary,
    ToolResult,
    _extract_child_assets_from_domain_prepass,
    _normalise_host,
)


# ----------------------------------------------------------------------
# _normalise_host
# ----------------------------------------------------------------------

class TestNormaliseHost:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("Example.COM", "example.com"),
            ("https://api.example.com/", "api.example.com"),
            ("http://api.example.com:8443/path", "api.example.com"),
            ("api.example.com:443", "api.example.com"),
            ("api.example.com.", "api.example.com"),
            ("  api.example.com  ", "api.example.com"),
            ("https://api.example.com/v1/users", "api.example.com"),
            ("", ""),
        ],
    )
    def test_normalises(self, raw: str, expected: str) -> None:
        assert _normalise_host(raw) == expected

    def test_ipv6_bracket_preserved(self) -> None:
        # IPv6 hosts come bracketed; the ":" inside brackets must not
        # trigger port-strip.
        assert _normalise_host("[2001:db8::1]") == "[2001:db8::1]"


# ----------------------------------------------------------------------
# Helpers to build PrepassSummary fixtures
# ----------------------------------------------------------------------

def _summary_with_pipeline_triage(
    *, apex: str, entries: list[dict],
) -> PrepassSummary:
    summary = PrepassSummary(target_type="domain", target_value=apex)
    summary.tool_results.append(ToolResult(
        tool_name="domain_recon_pipeline",
        status="ok",
        findings_count=0,
        raw_result={
            "success": True,
            "domain": apex,
            "surface_map": {"subdomain_triage": entries},
        },
    ))
    return summary


def _summary_with_pipeline_enum(
    *, apex: str, subdomains: list[str],
) -> PrepassSummary:
    summary = PrepassSummary(target_type="domain", target_value=apex)
    summary.tool_results.append(ToolResult(
        tool_name="domain_recon_pipeline",
        status="ok",
        findings_count=0,
        raw_result={
            "surface_map": {
                "subdomain_enum": {"subdomains": subdomains},
            },
        },
    ))
    return summary


def _summary_with_subfinder(
    *, apex: str, findings: list[dict],
) -> PrepassSummary:
    summary = PrepassSummary(target_type="domain", target_value=apex)
    summary.tool_results.append(ToolResult(
        tool_name="enumerate_subdomains_subfinder",
        status="ok",
        findings_count=len(findings),
        raw_result={"status": "ok", "findings": findings},
    ))
    return summary


# ----------------------------------------------------------------------
# Triage extraction (preferred path)
# ----------------------------------------------------------------------

class TestExtractorPipelineTriage:
    def test_emits_single_entry_with_full_shape(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[
                {
                    "host": "api.example.com",
                    "ip": "1.2.3.4",
                    "triage": "deep",
                    "scheme": "https",
                    "status": 200,
                },
            ],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, apex_domain="example.com",
        )
        assert len(children) == 1
        c = children[0]
        assert c == {
            "host": "api.example.com",
            "ip": "1.2.3.4",
            "asset_type": "web_application",
            "scheme": "https",
            "triage": "deep",
            "source": "domain_recon_pipeline",
        }

    def test_https_scheme_classifies_as_web_application(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[{"host": "api.example.com", "scheme": "https"}],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert children[0]["asset_type"] == "web_application"

    def test_http_scheme_classifies_as_web_application(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[{"host": "api.example.com", "scheme": "http"}],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert children[0]["asset_type"] == "web_application"

    def test_no_scheme_classifies_as_ip_address(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[{"host": "mx.example.com", "ip": "5.6.7.8"}],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert children[0]["asset_type"] == "ip_address"

    def test_unknown_scheme_classifies_as_ip_address(self) -> None:
        # Scheme like "ftp" / "smb" — not web; route to ip_address so
        # the wrapper can run network tooling.
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[{"host": "ftp.example.com", "scheme": "ftp"}],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert children[0]["asset_type"] == "ip_address"
        # Unknown scheme is dropped — we only report http/https
        assert children[0]["scheme"] is None

    def test_apex_excluded(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[
                {"host": "example.com", "scheme": "https"},  # apex itself
                {"host": "api.example.com", "scheme": "https"},
            ],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert [c["host"] for c in children] == ["api.example.com"]

    def test_apex_excluded_case_insensitive(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="Example.COM",
            entries=[{"host": "EXAMPLE.com", "scheme": "https"}],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "Example.COM",
        )
        assert children == []

    def test_triage_skip_entries_dropped(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[
                {"host": "live.example.com", "triage": "deep", "scheme": "https"},
                {"host": "dead.example.com", "triage": "skip"},
            ],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert [c["host"] for c in children] == ["live.example.com"]

    def test_host_normalised_in_output(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[{"host": "  API.EXAMPLE.COM  ", "scheme": "https"}],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert children[0]["host"] == "api.example.com"


# ----------------------------------------------------------------------
# Bare enum list (fallback)
# ----------------------------------------------------------------------

class TestExtractorPipelineEnumFallback:
    def test_bare_list_promoted_as_ip_address(self) -> None:
        summary = _summary_with_pipeline_enum(
            apex="example.com",
            subdomains=["api.example.com", "mx.example.com"],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        hosts = sorted(c["host"] for c in children)
        assert hosts == ["api.example.com", "mx.example.com"]
        for c in children:
            assert c["asset_type"] == "ip_address"
            assert c["scheme"] is None
            assert c["triage"] is None

    def test_apex_excluded_from_bare_list(self) -> None:
        summary = _summary_with_pipeline_enum(
            apex="example.com",
            subdomains=["example.com", "api.example.com"],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert [c["host"] for c in children] == ["api.example.com"]


# ----------------------------------------------------------------------
# Triage + enum dedup (triage data wins)
# ----------------------------------------------------------------------

class TestExtractorTriageWinsOverBareEnum:
    def test_triage_data_preferred_when_host_appears_in_both(self) -> None:
        summary = PrepassSummary(target_type="domain", target_value="example.com")
        summary.tool_results.append(ToolResult(
            tool_name="domain_recon_pipeline",
            status="ok",
            findings_count=0,
            raw_result={
                "surface_map": {
                    "subdomain_triage": [
                        {
                            "host": "api.example.com",
                            "ip": "1.2.3.4",
                            "scheme": "https",
                            "triage": "deep",
                        },
                    ],
                    "subdomain_enum": {
                        "subdomains": ["api.example.com", "other.example.com"],
                    },
                },
            },
        ))
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        # api.example.com should carry triage data (web_application);
        # other.example.com is enum-only (ip_address fallback).
        by_host = {c["host"]: c for c in children}
        assert by_host["api.example.com"]["asset_type"] == "web_application"
        assert by_host["api.example.com"]["ip"] == "1.2.3.4"
        assert by_host["other.example.com"]["asset_type"] == "ip_address"


# ----------------------------------------------------------------------
# Subfinder fallback
# ----------------------------------------------------------------------

class TestExtractorSubfinderFallback:
    def test_subfinder_findings_extracted_when_no_pipeline(self) -> None:
        summary = _summary_with_subfinder(
            apex="example.com",
            findings=[
                {"subdomain": "api.example.com", "ip": "1.2.3.4"},
                {"subdomain": "mx.example.com"},
            ],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert len(children) == 2
        by_host = {c["host"]: c for c in children}
        assert by_host["api.example.com"]["ip"] == "1.2.3.4"
        assert by_host["api.example.com"]["source"] == "enumerate_subdomains_subfinder"

    def test_subfinder_only_fills_gaps_pipeline_wins(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[
                {"host": "api.example.com", "scheme": "https", "triage": "deep"},
            ],
        )
        # Subfinder reports the SAME host + an extra. Pipeline entry
        # for api.example.com must NOT be overwritten by the
        # subfinder entry.
        summary.tool_results.append(ToolResult(
            tool_name="enumerate_subdomains_subfinder",
            status="ok",
            findings_count=2,
            raw_result={
                "findings": [
                    {"subdomain": "api.example.com"},  # already from pipeline
                    {"subdomain": "extra.example.com"},
                ],
            },
        ))
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        by_host = {c["host"]: c for c in children}
        assert by_host["api.example.com"]["source"] == "domain_recon_pipeline"
        assert by_host["api.example.com"]["asset_type"] == "web_application"
        assert by_host["extra.example.com"]["source"] == "enumerate_subdomains_subfinder"
        assert by_host["extra.example.com"]["asset_type"] == "ip_address"

    def test_subfinder_handles_host_key_alias(self) -> None:
        """Some subfinder wrapper variants use `host` instead of `subdomain`."""
        summary = _summary_with_subfinder(
            apex="example.com",
            findings=[{"host": "api.example.com"}],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert children[0]["host"] == "api.example.com"


# ----------------------------------------------------------------------
# Robustness / malformed data
# ----------------------------------------------------------------------

class TestExtractorRobustness:
    def test_empty_summary_returns_empty_list(self) -> None:
        summary = PrepassSummary(target_type="domain", target_value="example.com")
        assert _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        ) == []

    def test_missing_raw_result_skipped(self) -> None:
        summary = PrepassSummary(target_type="domain", target_value="example.com")
        summary.tool_results.append(ToolResult(
            tool_name="domain_recon_pipeline",
            status="error",
            findings_count=0,
            raw_result=None,
        ))
        assert _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        ) == []

    def test_non_dict_raw_result_skipped(self) -> None:
        summary = PrepassSummary(target_type="domain", target_value="example.com")
        summary.tool_results.append(ToolResult(
            tool_name="domain_recon_pipeline",
            status="ok",
            findings_count=0,
            raw_result="not a dict",  # type: ignore[arg-type]
        ))
        assert _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        ) == []

    def test_missing_surface_map_skipped(self) -> None:
        summary = PrepassSummary(target_type="domain", target_value="example.com")
        summary.tool_results.append(ToolResult(
            tool_name="domain_recon_pipeline",
            status="ok",
            findings_count=0,
            raw_result={"success": True},
        ))
        assert _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        ) == []

    def test_non_list_triage_skipped(self) -> None:
        summary = _summary_with_pipeline_triage(apex="example.com", entries=[])
        # Replace the empty list with a non-list to confirm robustness.
        summary.tool_results[0].raw_result["surface_map"]["subdomain_triage"] = (
            "garbage"
        )
        assert _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        ) == []

    def test_non_dict_entries_skipped(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[
                "garbage",  # type: ignore[list-item]
                {"host": "api.example.com", "scheme": "https"},
                42,  # type: ignore[list-item]
            ],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert [c["host"] for c in children] == ["api.example.com"]

    def test_empty_host_skipped(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[
                {"host": "", "scheme": "https"},
                {"host": "   ", "scheme": "https"},
                {"host": "api.example.com", "scheme": "https"},
            ],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert [c["host"] for c in children] == ["api.example.com"]

    def test_unrelated_tool_results_ignored(self) -> None:
        summary = PrepassSummary(target_type="domain", target_value="example.com")
        # checkdmarc + dnstwist + nuclei all run in domain prepass but
        # don't carry subdomain enumeration data.
        for tool in (
            "scan_dns_hygiene_checkdmarc",
            "scan_typosquats_dnstwist",
            "scan_nuclei_templates",
        ):
            summary.tool_results.append(ToolResult(
                tool_name=tool,
                status="ok",
                findings_count=0,
                raw_result={"findings": [{"some": "finding"}]},
            ))
        assert _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        ) == []


# ----------------------------------------------------------------------
# Ordering — stable for downstream snapshot comparisons
# ----------------------------------------------------------------------

class TestExtractorOrderingDeterminism:
    def test_alphabetical_host_order(self) -> None:
        summary = _summary_with_pipeline_triage(
            apex="example.com",
            entries=[
                {"host": "zzz.example.com", "scheme": "https"},
                {"host": "aaa.example.com", "scheme": "https"},
                {"host": "mmm.example.com", "scheme": "https"},
            ],
        )
        children = _extract_child_assets_from_domain_prepass(
            summary, "example.com",
        )
        assert [c["host"] for c in children] == [
            "aaa.example.com", "mmm.example.com", "zzz.example.com",
        ]


# ----------------------------------------------------------------------
# PrepassSummary.to_dict serialization
# ----------------------------------------------------------------------

class TestToDictSerialization:
    def test_to_dict_includes_child_assets_key(self) -> None:
        summary = PrepassSummary(target_type="domain", target_value="example.com")
        d = summary.to_dict()
        assert "child_assets_discovered" in d
        assert d["child_assets_discovered"] == []

    def test_to_dict_carries_extracted_children(self) -> None:
        summary = PrepassSummary(target_type="domain", target_value="example.com")
        summary.child_assets_discovered = [
            {
                "host": "api.example.com",
                "ip": "1.2.3.4",
                "asset_type": "web_application",
                "scheme": "https",
                "triage": "deep",
                "source": "domain_recon_pipeline",
            },
        ]
        d = summary.to_dict()
        assert len(d["child_assets_discovered"]) == 1
        assert d["child_assets_discovered"][0]["host"] == "api.example.com"

    def test_to_dict_returns_list_copy_not_reference(self) -> None:
        summary = PrepassSummary(target_type="domain", target_value="example.com")
        summary.child_assets_discovered = [{"host": "a.example.com"}]
        d = summary.to_dict()
        d["child_assets_discovered"].append({"host": "b.example.com"})
        # Original list not mutated by downstream consumer.
        assert len(summary.child_assets_discovered) == 1


# ----------------------------------------------------------------------
# Anti-overfit: no fixture identifiers in implementation
# ----------------------------------------------------------------------

def test_no_fixture_identifiers_in_q5_44_impl() -> None:
    """Source-grep: extractor must not reference SUT-specific hosts."""
    import inspect

    import strix.agents.lead_agent.anchor_prepass as ap_mod

    fn_src = inspect.getsource(_extract_child_assets_from_domain_prepass)
    banned = {
        "juice-shop", "bkimminich", "vampi", "crapi", "wavsep",
        "erev0s", "getedunext",
    }
    for ident in banned:
        assert ident not in fn_src.lower(), (
            f"_extract_child_assets_from_domain_prepass references "
            f"SUT identifier {ident!r}"
        )
    # Also check _normalise_host.
    norm_src = inspect.getsource(ap_mod._normalise_host)
    for ident in banned:
        assert ident not in norm_src.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
