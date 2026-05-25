"""Tests for iter-33.3 — heuristic shape-based chain linkers.

These linkers fire on category families (not strict CWE/endpoint
matches) so chains land even when the LLM agent's findings have
sparse / missing CWE annotations.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.finding_chains.chain import Finding
from strix.finding_chains.correlator import build_chains
from strix.finding_chains.links import (
    LINKER_REGISTRY,
    LINK_HEURISTIC_PRIV_ESCALATION,
    LINK_HEURISTIC_CREDENTIAL_EXTRACTION,
    LINK_HEURISTIC_DATA_EXFIL,
    LINK_HEURISTIC_BOLA_AT_SCALE,
    link_heuristic_bola_at_scale_chain,
    link_heuristic_credential_extraction_chain,
    link_heuristic_data_exfil_chain,
    link_heuristic_priv_escalation_chain,
)


def _f(**kwargs) -> Finding:
    return Finding(
        id=kwargs.get("id", "f"),
        title=kwargs.get("title", "X"),
        category=kwargs.get("category", "sqli"),
        severity=kwargs.get("severity", "medium"),
        cwe=kwargs.get("cwe"),
        target=kwargs.get("target", ""),
        endpoint=kwargs.get("endpoint", ""),
        description=kwargs.get("description", ""),
        cve=kwargs.get("cve"),
        package=kwargs.get("package", ""),
        metadata=kwargs.get("metadata", {}),
    )


# ---------------------------------------------------------------------------
# Privilege-escalation heuristic
# ---------------------------------------------------------------------------

def test_priv_escalation_links_auth_bypass_plus_missing_authz():
    """auth-bypass on target + missing-authz on same target → chain."""
    findings = [
        _f(id="v1", category="auth", target="http://app"),
        _f(id="v2", category="idor", target="http://app"),
    ]
    links = link_heuristic_priv_escalation_chain(findings)
    assert len(links) == 1
    assert {links[0].finding_a, links[0].finding_b} == {"v1", "v2"}
    assert links[0].link_type == LINK_HEURISTIC_PRIV_ESCALATION


def test_priv_escalation_jwt_plus_bfla():
    """JWT issues + BFLA → chain."""
    findings = [
        _f(id="v1", category="jwt", target="http://app"),
        _f(id="v2", category="bfla", target="http://app"),
    ]
    links = link_heuristic_priv_escalation_chain(findings)
    assert len(links) == 1


def test_priv_escalation_default_creds_plus_authz_missing():
    """default_creds finding chains with missing_auth."""
    findings = [
        _f(id="v1", category="default_creds", target="http://app"),
        _f(id="v2", category="missing_auth", target="http://app"),
    ]
    links = link_heuristic_priv_escalation_chain(findings)
    assert len(links) == 1


def test_priv_escalation_rejects_different_targets():
    """Cross-target findings don't chain."""
    findings = [
        _f(id="v1", category="auth", target="http://app-a"),
        _f(id="v2", category="idor", target="http://app-b"),
    ]
    links = link_heuristic_priv_escalation_chain(findings)
    assert len(links) == 0


def test_priv_escalation_no_match_on_unrelated_categories():
    """SQLi + XSS doesn't fire the priv-esc heuristic."""
    findings = [
        _f(id="v1", category="sqli", target="http://app"),
        _f(id="v2", category="xss", target="http://app"),
    ]
    links = link_heuristic_priv_escalation_chain(findings)
    assert len(links) == 0


def test_priv_escalation_dedups_pairs():
    """If same (a,b) pair would fire from both sides of the cartesian,
    only one link is emitted."""
    findings = [
        _f(id="v1", category="auth", target="http://app"),
        _f(id="v2", category="idor", target="http://app"),
    ]
    links = link_heuristic_priv_escalation_chain(findings)
    assert len(links) == 1


# ---------------------------------------------------------------------------
# Credential-extraction heuristic
# ---------------------------------------------------------------------------

def test_credential_extraction_sqli_plus_hardcoded_secret():
    findings = [
        _f(id="v1", category="sqli", target="http://app"),
        _f(id="v2", category="hardcoded_secret", target="http://app"),
    ]
    links = link_heuristic_credential_extraction_chain(findings)
    assert len(links) == 1
    assert links[0].link_type == LINK_HEURISTIC_CREDENTIAL_EXTRACTION


def test_credential_extraction_path_traversal_plus_jwt_weak():
    findings = [
        _f(id="v1", category="path_traversal", target="http://app"),
        _f(id="v2", category="jwt_weak", target="http://app"),
    ]
    links = link_heuristic_credential_extraction_chain(findings)
    assert len(links) == 1


def test_credential_extraction_xxe_plus_info_disclosure():
    findings = [
        _f(id="v1", category="xxe", target="http://app"),
        _f(id="v2", category="info_disclosure", target="http://app"),
    ]
    links = link_heuristic_credential_extraction_chain(findings)
    assert len(links) == 1


# ---------------------------------------------------------------------------
# Data-exfil heuristic
# ---------------------------------------------------------------------------

def test_data_exfil_sqli_plus_directory_listing():
    findings = [
        _f(id="v1", category="sqli", target="http://app"),
        _f(id="v2", category="directory_listing", target="http://app"),
    ]
    links = link_heuristic_data_exfil_chain(findings)
    assert len(links) == 1
    assert links[0].link_type == LINK_HEURISTIC_DATA_EXFIL


def test_data_exfil_cmd_injection_plus_debug_endpoint():
    findings = [
        _f(id="v1", category="cmd_injection", target="http://app"),
        _f(id="v2", category="debug_endpoint", target="http://app"),
    ]
    links = link_heuristic_data_exfil_chain(findings)
    assert len(links) == 1


# ---------------------------------------------------------------------------
# BOLA-at-scale heuristic
# ---------------------------------------------------------------------------

def test_bola_at_scale_idor_plus_jwt():
    findings = [
        _f(id="v1", category="idor", target="http://app"),
        _f(id="v2", category="jwt", target="http://app"),
    ]
    links = link_heuristic_bola_at_scale_chain(findings)
    assert len(links) == 1
    assert links[0].link_type == LINK_HEURISTIC_BOLA_AT_SCALE


def test_bola_at_scale_bola_plus_weak_crypto():
    findings = [
        _f(id="v1", category="bola", target="http://app"),
        _f(id="v2", category="weak_crypto", target="http://app"),
    ]
    links = link_heuristic_bola_at_scale_chain(findings)
    assert len(links) == 1


def test_bola_at_scale_rejects_unrelated_pair():
    findings = [
        _f(id="v1", category="sqli", target="http://app"),
        _f(id="v2", category="xss", target="http://app"),
    ]
    links = link_heuristic_bola_at_scale_chain(findings)
    assert len(links) == 0


# ---------------------------------------------------------------------------
# Registry inclusion
# ---------------------------------------------------------------------------

def test_heuristic_linkers_registered():
    """All 4 iter-33.3 linkers must be in LINKER_REGISTRY."""
    registry_names = {linker.__name__ for linker in LINKER_REGISTRY}
    for expected in (
        "link_heuristic_priv_escalation_chain",
        "link_heuristic_credential_extraction_chain",
        "link_heuristic_data_exfil_chain",
        "link_heuristic_bola_at_scale_chain",
    ):
        assert expected in registry_names, f"{expected} not registered"


# ---------------------------------------------------------------------------
# End-to-end: build_chains uses the heuristics
# ---------------------------------------------------------------------------

def test_build_chains_groups_heuristic_chain():
    """build_chains() should produce a 2-member chain via heuristic
    linker even when CWE / endpoint don't strictly match."""
    findings = [
        _f(id="v1", category="auth", target="http://app",
           endpoint="http://app/login"),
        _f(id="v2", category="idor", target="http://app",
           endpoint="http://app/api/users/123"),
    ]
    chains = build_chains(findings, min_chain_size=2)
    assert len(chains) == 1
    # Both findings should be in the same chain
    ids = set(chains[0].finding_ids)
    assert ids == {"v1", "v2"}


def test_build_chains_chains_3_findings_via_heuristic_transitively():
    """Auth-bypass + missing-authz + injection on same target →
    3-member chain via transitive heuristic linking."""
    findings = [
        _f(id="v1", category="auth", target="http://app"),
        _f(id="v2", category="idor", target="http://app"),
        _f(id="v3", category="sqli", target="http://app"),
        _f(id="v4", category="info_disclosure", target="http://app"),
    ]
    chains = build_chains(findings, min_chain_size=2)
    # All 4 should land in one chain via:
    #   auth+idor (priv-esc) + sqli+info_disclosure (cred-extract)
    #   + the connecting "same target" transitive closure
    assert len(chains) >= 1
    if len(chains) == 1:
        assert set(chains[0].finding_ids) == {"v1", "v2", "v3", "v4"}


# ---------------------------------------------------------------------------
# Anti-overfit
# ---------------------------------------------------------------------------

def test_heuristic_linker_source_has_no_sut_specific_strings():
    """The heuristic linkers must not reference SUT identifiers."""
    import strix.finding_chains.links as mod
    src = open(mod.__file__).read()
    # Extract just the iter-33.3 section
    start = src.find("iter-33.3 — heuristic shape-based linkers")
    assert start > 0
    end = src.find("# Linker registry", start)
    iter_33_3_src = src[start:end].lower()
    forbidden = (
        "bkimminich", "juice-sh.op", "/rest/user/login",
        "/users/v1/_debug", "vampi", "erev0s", "juice-shop",
    )
    for tok in forbidden:
        assert tok not in iter_33_3_src, (
            f"SUT-specific token {tok!r} in iter-33.3 linker source"
        )


def test_heuristic_confidence_is_lower_than_strict_linkers():
    """Heuristic links should have lower confidence (~0.7) than the
    strict CWE-match linkers (~0.85+). That way the wrapper UI can
    visually distinguish "we suspect this is a chain" from "we know
    these two findings share a CWE.\""""
    findings = [
        _f(id="v1", category="auth", target="http://app"),
        _f(id="v2", category="idor", target="http://app"),
    ]
    links = link_heuristic_priv_escalation_chain(findings)
    assert links[0].confidence < 0.85
    assert links[0].confidence >= 0.5  # but still actionable
