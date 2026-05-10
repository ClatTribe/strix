"""Unit tests for the cross-category linkers."""

from __future__ import annotations

import pytest

from strix.finding_chains.chain import Finding
from strix.finding_chains.links import (
    LINK_ANOMALY_DAST_ENDPOINT,
    LINK_IAC_DAST_CATEGORY,
    LINK_SAST_DAST_CWE_ENDPOINT,
    LINK_SCA_DAST_CWE,
    LINK_SCA_SAST_PACKAGE,
    link_anomaly_to_specialist,
    link_iac_to_dast_by_category,
    link_sast_to_dast_by_cwe_endpoint,
    link_sca_to_dast_by_cwe,
    link_sca_to_sast_by_package,
)


def _f(**kwargs) -> Finding:
    """Tiny helper — defaults that keep tests readable."""
    return Finding(
        id=kwargs.get("id", "f"),
        title=kwargs.get("title", "X"),
        category=kwargs.get("category", "sqli"),
        severity=kwargs.get("severity", "high"),
        cwe=kwargs.get("cwe"),
        target=kwargs.get("target", ""),
        endpoint=kwargs.get("endpoint", ""),
        description=kwargs.get("description", ""),
        cve=kwargs.get("cve"),
        package=kwargs.get("package", ""),
        metadata=kwargs.get("metadata", {}),
    )


# ---------------------------------------------------------------------------
# SCA → DAST
# ---------------------------------------------------------------------------


def test_sca_to_dast_links_when_cwe_family_matches_on_same_target() -> None:
    sca = _f(
        id="sca-1",
        title="Vulnerable dependency `npm:lodash@4.17.20`",
        category="vulnerable_dependency",
        cwe="CWE-1321",  # prototype pollution → 'deserialization' family
        target="https://app.example.com",
    )
    dast = _f(
        id="dast-1",
        title="Prototype pollution at /api/merge",
        category="deserialization",
        cwe="CWE-502",
        target="https://app.example.com",
        endpoint="/api/merge",
    )
    links = link_sca_to_dast_by_cwe([sca, dast])
    assert len(links) == 1
    assert links[0].link_type == LINK_SCA_DAST_CWE
    assert {links[0].finding_a, links[0].finding_b} == {"sca-1", "dast-1"}


def test_sca_to_dast_no_link_when_target_differs() -> None:
    sca = _f(
        id="sca-1", category="vulnerable_dependency",
        cwe="CWE-89", target="https://a.example.com",
    )
    dast = _f(
        id="dast-1", category="sqli",
        cwe="CWE-89", target="https://b.example.com",
    )
    assert link_sca_to_dast_by_cwe([sca, dast]) == []


def test_sca_to_dast_no_link_when_cwe_family_differs() -> None:
    sca = _f(
        id="sca-1", category="vulnerable_dependency",
        cwe="CWE-89", target="https://x.com",
    )
    dast = _f(
        id="dast-1", category="xss",
        cwe="CWE-79", target="https://x.com",
    )
    assert link_sca_to_dast_by_cwe([sca, dast]) == []


# ---------------------------------------------------------------------------
# SAST → DAST
# ---------------------------------------------------------------------------


def test_sast_to_dast_links_on_cwe_family_and_target() -> None:
    sast = _f(
        id="sast-1", category="sast", cwe="CWE-94",
        target="/repo/src", endpoint="app.js:35",
    )
    dast = _f(
        id="dast-1", category="cmd_injection", cwe="CWE-94",
        target="/repo/src", endpoint="/api/calc",
    )
    links = link_sast_to_dast_by_cwe_endpoint([sast, dast])
    assert len(links) == 1
    assert links[0].link_type == LINK_SAST_DAST_CWE_ENDPOINT


def test_sast_to_dast_no_link_when_cwe_family_differs() -> None:
    sast = _f(id="sast-1", category="sast", cwe="CWE-89",
              target="/repo/src")
    dast = _f(id="dast-1", category="xss", cwe="CWE-79",
              target="/repo/src")
    assert link_sast_to_dast_by_cwe_endpoint([sast, dast]) == []


# ---------------------------------------------------------------------------
# IaC → DAST
# ---------------------------------------------------------------------------


def test_iac_to_dast_links_on_misconfig_with_cors_keywords() -> None:
    iac = _f(
        id="iac-1",
        title="[iac:vercel] vercel-cors-wildcard-with-credentials",
        category="misconfig",
        target="https://app.com",
    )
    dast = _f(
        id="dast-1",
        title="cors_deep_check fired",
        category="misconfig",
        target="https://app.com",
    )
    links = link_iac_to_dast_by_category([iac, dast])
    assert len(links) == 1
    assert links[0].link_type == LINK_IAC_DAST_CATEGORY


def test_iac_to_dast_links_open_redirect_pair() -> None:
    iac = _f(
        id="iac-1",
        title="[iac:vercel] vercel-redirect-external-host",
        category="open_redirect",
        target="https://app.com",
    )
    dast = _f(
        id="dast-1",
        title="open_redirect_check fired on /go",
        category="open_redirect",
        target="https://app.com",
    )
    links = link_iac_to_dast_by_category([iac, dast])
    assert len(links) == 1


def test_iac_to_dast_no_link_when_target_differs() -> None:
    iac = _f(id="iac-1", title="[iac:vercel] cors", category="misconfig",
             target="https://a.com")
    dast = _f(id="dast-1", title="cors fired", category="misconfig",
              target="https://b.com")
    assert link_iac_to_dast_by_category([iac, dast]) == []


# ---------------------------------------------------------------------------
# Anomaly → DAST specialist
# ---------------------------------------------------------------------------


def test_anomaly_to_dast_links_on_same_endpoint() -> None:
    anom = _f(
        id="anom-1", category="anomaly",
        title="Anomaly: error_string_present",
        target="https://x.com", endpoint="/api/users",
    )
    dast = _f(
        id="dast-1", category="sqli",
        target="https://x.com", endpoint="/api/users",
    )
    links = link_anomaly_to_specialist([anom, dast])
    assert len(links) == 1
    assert links[0].link_type == LINK_ANOMALY_DAST_ENDPOINT


def test_anomaly_to_dast_partial_endpoint_match_links() -> None:
    """`/api/users` (anomaly) ↔ `/api/users/:id` (DAST) →
    partial match should still link."""
    anom = _f(id="anom-1", category="anomaly",
              target="https://x.com", endpoint="/api/users")
    dast = _f(id="dast-1", category="sqli",
              target="https://x.com", endpoint="/api/users/:id")
    links = link_anomaly_to_specialist([anom, dast])
    assert len(links) == 1


def test_anomaly_to_dast_no_link_when_neither_endpoint_nor_target_match() -> None:
    anom = _f(id="anom-1", category="anomaly",
              target="https://a.com", endpoint="/api/x")
    dast = _f(id="dast-1", category="sqli",
              target="https://b.com", endpoint="/api/y")
    assert link_anomaly_to_specialist([anom, dast]) == []


# ---------------------------------------------------------------------------
# SCA → SAST (package match)
# ---------------------------------------------------------------------------


def test_sca_to_sast_links_when_sast_text_mentions_package() -> None:
    sca = _f(
        id="sca-1",
        title="Vulnerable dependency `npm:lodash@4.17.20`",
        category="vulnerable_dependency",
        package="npm:lodash",
    )
    sast = _f(
        id="sast-1",
        title="strix-react-dangerously-set-innerhtml",
        category="sast",
        description="dangerouslySetInnerHTML reads from request body; "
                    "uses lodash.merge upstream",
    )
    links = link_sca_to_sast_by_package([sca, sast])
    assert len(links) == 1
    assert links[0].link_type == LINK_SCA_SAST_PACKAGE


def test_sca_to_sast_no_link_when_package_not_referenced() -> None:
    sca = _f(id="sca-1", category="vulnerable_dependency",
             package="npm:lodash")
    sast = _f(id="sast-1", category="sast",
              description="some unrelated SAST hit on express")
    assert link_sca_to_sast_by_package([sca, sast]) == []


def test_sca_to_sast_skips_short_package_names() -> None:
    """Package names < 4 chars produce too many false-positive
    string matches in the SAST text. Skipped."""
    sca = _f(id="sca-1", category="vulnerable_dependency",
             package="npm:ws")  # 'ws' = 2 chars
    sast = _f(id="sast-1", category="sast",
              description="awssdk has ws inside")
    assert link_sca_to_sast_by_package([sca, sast]) == []
