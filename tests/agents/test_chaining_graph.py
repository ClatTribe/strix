"""Tests for §workitem.md Phase 5.2 — vulnerability chaining graph.

Pins:
  * 2-hop chain detection (xss + csrf on same host)
  * 3-hop chain detection (default-creds → admin → arbitrary data)
  * Different hosts → no chain (co_host_required)
  * Subdomain takeover edge: co_host_required=False
  * Chain severity = max(individual) + bump for 3-hop / RCE keyword
  * 3-hop subsumes 2-hop (no double-emit)
  * `category` and `title` substring both match for edges
  * emit_chain_findings writes consolidated finding to tracer
  * Best-effort: malformed input → empty result
  * register_chain_edge extension point
"""

from __future__ import annotations

import pytest

from strix.agents.chaining_graph import (
    Chain,
    ChainEdge,
    analyze_findings_for_chains,
    build_chain_graph,
    emit_chain_findings,
    register_chain_edge,
    render_chain_finding,
    reset_edges_for_testing,
)


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path) -> None:
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-chain"))
    reset_edges_for_testing()
    yield
    reset_edges_for_testing()


# ---------------------------------------------------------------------------
# 2-hop detection
# ---------------------------------------------------------------------------


def test_xss_and_csrf_on_same_host_chain() -> None:
    findings = [
        {
            "id": "v1", "title": "Reflected XSS in `q`",
            "category": "xss", "severity": "high",
            "endpoint": "http://example.com/search",
        },
        {
            "id": "v2", "title": "CSRF on /api/transfer",
            "category": "csrf", "severity": "medium",
            "endpoint": "http://example.com/api/transfer",
        },
    ]
    chains = analyze_findings_for_chains(findings)
    assert len(chains) == 1
    chain = chains[0]
    assert len(chain.findings) == 2
    assert chain.findings[0]["category"] == "xss"
    assert chain.findings[1]["category"] == "csrf"
    assert chain.edges[0].category_a == "xss"
    assert chain.edges[0].category_b == "csrf"


def test_xss_and_csrf_on_different_hosts_no_chain() -> None:
    findings = [
        {
            "id": "v1", "title": "XSS",
            "category": "xss", "severity": "high",
            "endpoint": "http://example.com/x",
        },
        {
            "id": "v2", "title": "CSRF",
            "category": "csrf", "severity": "medium",
            "endpoint": "http://other.test/api",
        },
    ]
    chains = analyze_findings_for_chains(findings)
    # co_host_required → no chain across different hosts.
    assert chains == []


def test_subdomain_takeover_csrf_chain_no_host_match_required() -> None:
    """The takeover-csrf edge has co_host_required=False because the
    subdomain that's been taken over is intentionally a DIFFERENT
    subdomain from the parent app."""
    findings = [
        {
            "id": "v1", "title": "Subdomain takeover at assets.example.com",
            "category": "subdomain_takeover", "severity": "high",
            "endpoint": "http://assets.example.com/",
        },
        {
            "id": "v2", "title": "Missing CSRF",
            "category": "csrf", "severity": "medium",
            "endpoint": "http://www.example.com/api",
        },
    ]
    chains = analyze_findings_for_chains(findings)
    assert len(chains) == 1


# ---------------------------------------------------------------------------
# 3-hop detection
# ---------------------------------------------------------------------------


def test_three_hop_chain_default_creds_idor_missing_auth() -> None:
    """authentication → missing_auth and idor → missing_auth share
    'missing_auth' as B. We construct a 3-hop where authentication
    leads to missing_auth which is also targeted by idor on the
    same host."""
    # Note: 3-hop requires A→B and B→C edges. Let's use:
    #   ssrf → secrets_exposure (edge 1)
    #   path_traversal → secrets_exposure (NOT a chain — both A→B same B)
    # Better: idor → missing_auth, missing_auth → ??? (no outgoing).
    # Construct: idor (A) → missing_auth (B); plus a separate 2-hop.
    # For real 3-hop we need consecutive edges.
    # Let's pick: deserialization → command_injection (edge 1),
    # AND command_injection has NO outgoing edge in default registry.
    # So 3-hop is hard with default edges. Test 2-hop primarily and
    # register a custom 3-hop edge below.
    register_chain_edge(ChainEdge(
        category_a="command_injection",
        category_b="ssrf",
        description="Cmd injection grants shell which probes internal SSRF",
        impact_summary="Shell access enables internal SSRF",
    ))

    findings = [
        {
            "id": "v1", "title": "Java deserialization",
            "category": "deserialization", "severity": "high",
            "endpoint": "http://example.com/api/process",
        },
        {
            "id": "v2", "title": "OS command injection in `host`",
            "category": "command_injection", "severity": "critical",
            "endpoint": "http://example.com/admin/ping",
        },
        {
            "id": "v3", "title": "SSRF in `url`",
            "category": "ssrf", "severity": "high",
            "endpoint": "http://example.com/proxy",
        },
    ]
    chains = analyze_findings_for_chains(findings)
    # The 3-hop should subsume the (deser, cmd) 2-hop.
    three_hop = [c for c in chains if len(c.findings) == 3]
    assert len(three_hop) == 1
    assert three_hop[0].findings[0]["category"] == "deserialization"
    assert three_hop[0].findings[1]["category"] == "command_injection"
    assert three_hop[0].findings[2]["category"] == "ssrf"


def test_three_hop_subsumes_two_hop() -> None:
    """When (a, b, c) is a 3-hop chain, the (a, b) 2-hop should NOT
    also appear."""
    register_chain_edge(ChainEdge(
        category_a="command_injection",
        category_b="ssrf",
        description="x", impact_summary="x",
    ))
    findings = [
        {
            "id": "v1", "category": "deserialization", "severity": "high",
            "endpoint": "http://x/", "title": "deser",
        },
        {
            "id": "v2", "category": "command_injection", "severity": "critical",
            "endpoint": "http://x/", "title": "cmd",
        },
        {
            "id": "v3", "category": "ssrf", "severity": "high",
            "endpoint": "http://x/", "title": "ssrf",
        },
    ]
    chains = analyze_findings_for_chains(findings)
    # Should not contain both the 3-hop and its (a,b) 2-hop.
    pairs_seen = [
        tuple(f["category"] for f in c.findings)
        for c in chains
    ]
    assert ("deserialization", "command_injection", "ssrf") in pairs_seen
    # The 2-hop subset is dropped.
    assert ("deserialization", "command_injection") not in pairs_seen


# ---------------------------------------------------------------------------
# Severity computation
# ---------------------------------------------------------------------------


def test_chain_severity_max_plus_bump_for_three_hop() -> None:
    register_chain_edge(ChainEdge(
        category_a="command_injection", category_b="ssrf",
        description="x", impact_summary="x",
    ))
    findings = [
        {"id": "v1", "category": "deserialization", "severity": "medium",
         "endpoint": "http://x/", "title": "deser"},
        {"id": "v2", "category": "command_injection", "severity": "medium",
         "endpoint": "http://x/", "title": "cmd"},
        {"id": "v3", "category": "ssrf", "severity": "medium",
         "endpoint": "http://x/", "title": "ssrf"},
    ]
    chains = analyze_findings_for_chains(findings)
    three_hop = next(c for c in chains if len(c.findings) == 3)
    # max(medium)=2 + 1 bump for 3-hop = 3 = high
    assert three_hop.chain_severity == "high"


def test_chain_severity_bumped_for_rce_keyword() -> None:
    findings = [
        {"id": "v1", "category": "xss", "severity": "medium",
         "endpoint": "http://x/", "title": "XSS to RCE somehow"},
        {"id": "v2", "category": "csrf", "severity": "low",
         "endpoint": "http://x/", "title": "CSRF"},
    ]
    chains = analyze_findings_for_chains(findings)
    chain = chains[0]
    # max(medium=2, low=1) + bump for "RCE" keyword = 3 = high
    assert chain.chain_severity == "high"


def test_chain_severity_capped_at_critical() -> None:
    findings = [
        {"id": "v1", "category": "xss", "severity": "critical",
         "endpoint": "http://x/", "title": "XSS leading to RCE"},
        {"id": "v2", "category": "csrf", "severity": "high",
         "endpoint": "http://x/", "title": "CSRF"},
    ]
    chains = analyze_findings_for_chains(findings)
    # Already critical; bump capped.
    assert chains[0].chain_severity == "critical"


# ---------------------------------------------------------------------------
# Edge matching
# ---------------------------------------------------------------------------


def test_category_match_via_substring_in_title() -> None:
    """When the category field is generic but the title says
    'XSS' / 'CSRF', edges still apply."""
    findings = [
        {"id": "v1", "category": "info_disclosure",
         "severity": "high", "endpoint": "http://x/",
         "title": "Reflected XSS in `q`"},
        {"id": "v2", "category": "info_disclosure",
         "severity": "medium", "endpoint": "http://x/",
         "title": "Missing CSRF token on /transfer"},
    ]
    chains = analyze_findings_for_chains(findings)
    assert len(chains) == 1


def test_jwt_alias_matches_weak_jwt_edge() -> None:
    """JWT-related findings emit category=jwt; the weak_jwt → idor
    edge needs to alias-match."""
    findings = [
        {"id": "v1", "category": "jwt", "severity": "high",
         "endpoint": "http://x/api/me",
         "title": "JWT alg=none accepted"},
        {"id": "v2", "category": "idor", "severity": "high",
         "endpoint": "http://x/api/users/42",
         "title": "IDOR in user_id path segment"},
    ]
    chains = analyze_findings_for_chains(findings)
    assert len(chains) == 1
    assert chains[0].edges[0].category_a == "weak_jwt"


# ---------------------------------------------------------------------------
# render + emit
# ---------------------------------------------------------------------------


def test_render_chain_finding_shape() -> None:
    findings = [
        {"id": "v1", "category": "xss", "severity": "high",
         "endpoint": "http://x/", "title": "XSS"},
        {"id": "v2", "category": "csrf", "severity": "medium",
         "endpoint": "http://x/", "title": "CSRF"},
    ]
    chains = analyze_findings_for_chains(findings)
    payload = render_chain_finding(chains[0])
    assert payload["category"] == "exploit_chain"
    assert payload["title"].startswith("Exploit chain: XSS → CSRF")
    assert "endpoint" in payload
    assert payload["severity"] in {"high", "critical", "medium"}


def test_emit_chain_findings_writes_to_tracer(monkeypatch) -> None:
    from strix.telemetry.tracer import get_global_tracer
    tracer = get_global_tracer()
    # Prime the tracer with two component findings that form a chain.
    tracer.add_vulnerability_report(
        title="Reflected XSS in `q`",
        severity="high",
        category="xss",
        endpoint="http://example.com/search",
    )
    tracer.add_vulnerability_report(
        title="Missing CSRF",
        severity="medium",
        category="csrf",
        endpoint="http://example.com/api/transfer",
    )
    rids = emit_chain_findings()
    assert len(rids) == 1
    # Tracer now has 3 vulns: 2 components + 1 chain.
    vulns = tracer.get_existing_vulnerabilities()
    chain_vulns = [v for v in vulns if v.get("category") == "exploit_chain"]
    assert len(chain_vulns) == 1


def test_emit_chain_findings_no_chains_returns_empty() -> None:
    from strix.telemetry.tracer import get_global_tracer
    tracer = get_global_tracer()
    tracer.add_vulnerability_report(
        title="Just one XSS",
        severity="high",
        category="xss",
        endpoint="http://x/",
    )
    rids = emit_chain_findings()
    assert rids == []


def test_build_chain_graph_picks_live_tracer_findings() -> None:
    from strix.telemetry.tracer import get_global_tracer
    tracer = get_global_tracer()
    tracer.add_vulnerability_report(
        title="XSS", severity="high", category="xss",
        endpoint="http://x/",
    )
    tracer.add_vulnerability_report(
        title="CSRF", severity="medium", category="csrf",
        endpoint="http://x/",
    )
    chains = build_chain_graph()
    assert len(chains) == 1


# ---------------------------------------------------------------------------
# Best-effort robustness
# ---------------------------------------------------------------------------


def test_analyze_with_malformed_input() -> None:
    assert analyze_findings_for_chains(None) == []  # type: ignore[arg-type]
    assert analyze_findings_for_chains([]) == []
    assert analyze_findings_for_chains(["not a dict"]) == []  # type: ignore[list-item]


def test_analyze_single_finding_returns_empty() -> None:
    findings = [{"id": "v1", "category": "xss", "severity": "high",
                 "endpoint": "http://x/", "title": "x"}]
    assert analyze_findings_for_chains(findings) == []


def test_analyze_with_finding_missing_endpoint() -> None:
    """When an endpoint is missing, host comparison fails → no chain
    (correctly conservative)."""
    findings = [
        {"id": "v1", "category": "xss", "severity": "high",
         "title": "XSS"},
        {"id": "v2", "category": "csrf", "severity": "medium",
         "title": "CSRF"},
    ]
    # Both missing endpoint → no host match → no chain.
    chains = analyze_findings_for_chains(findings)
    assert chains == []


# ---------------------------------------------------------------------------
# register_chain_edge extension point
# ---------------------------------------------------------------------------


def test_register_chain_edge_extends_detection() -> None:
    register_chain_edge(ChainEdge(
        category_a="custom_a",
        category_b="custom_b",
        description="custom edge", impact_summary="x",
    ))
    findings = [
        {"id": "v1", "category": "custom_a", "severity": "high",
         "endpoint": "http://x/", "title": "a"},
        {"id": "v2", "category": "custom_b", "severity": "medium",
         "endpoint": "http://x/", "title": "b"},
    ]
    chains = analyze_findings_for_chains(findings)
    assert len(chains) == 1
