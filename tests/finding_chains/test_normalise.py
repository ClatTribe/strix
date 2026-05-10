"""Unit tests for `strix.finding_chains.normalise`."""

from __future__ import annotations

import pytest

from strix.finding_chains.normalise import (
    _extract_cve,
    _extract_package,
    _normalise_cwe,
    normalise_finding,
    normalise_findings,
)


# ---------------------------------------------------------------------------
# CWE extraction
# ---------------------------------------------------------------------------


def test_normalise_cwe_with_string_form() -> None:
    assert _normalise_cwe("CWE-89") == "CWE-89"
    assert _normalise_cwe("cwe-89") == "CWE-89"
    assert _normalise_cwe("CWE-89: SQL Injection") == "CWE-89"


def test_normalise_cwe_with_bare_number() -> None:
    assert _normalise_cwe("89") == "CWE-89"


def test_normalise_cwe_with_list() -> None:
    assert _normalise_cwe(["CWE-79", "CWE-89"]) == "CWE-79"


def test_normalise_cwe_invalid_returns_none() -> None:
    assert _normalise_cwe(None) is None
    assert _normalise_cwe("") is None
    assert _normalise_cwe([]) is None


# ---------------------------------------------------------------------------
# Package + CVE extraction
# ---------------------------------------------------------------------------


def test_extract_package_from_sca_title() -> None:
    title = "Vulnerable dependency `npm:lodash@4.17.20` (3 CVEs)"
    assert _extract_package(title) == "npm:lodash"


def test_extract_package_pypi_form() -> None:
    title = "Vulnerable dependency `pypi:django@4.2.0` (1 CVE) [KEV — actively exploited]"
    assert _extract_package(title) == "pypi:django"


def test_extract_package_returns_empty_when_not_present() -> None:
    title = "[chain:sast_dast] eval(req.body) — cmd_injection"
    assert _extract_package(title) == ""


def test_extract_cve_from_explicit_field() -> None:
    assert _extract_cve("", "", "cve-2024-9999") == "CVE-2024-9999"


def test_extract_cve_from_title() -> None:
    title = "SQL injection (CVE-2024-9999)"
    assert _extract_cve(title) == "CVE-2024-9999"


def test_extract_cve_ghsa_form() -> None:
    title = "Lodash advisory (GHSA-aaaa-bbbb-cccc)"
    assert _extract_cve(title) == "GHSA-AAAA-BBBB-CCCC"


def test_extract_cve_returns_none_when_absent() -> None:
    assert _extract_cve("Plain title", "no IDs here") is None


# ---------------------------------------------------------------------------
# normalise_finding — full pipeline
# ---------------------------------------------------------------------------


def test_normalise_finding_basic_dict() -> None:
    raw = {
        "id": "f1",
        "title": "SQL Injection at /api/users",
        "category": "sqli",
        "severity": "high",
        "cwe": "CWE-89",
        "target": "https://example.com",
        "endpoint": "/api/users",
        "description": "string concat in DB query",
    }
    f = normalise_finding(raw)
    assert f is not None
    assert f.id == "f1"
    assert f.title == "SQL Injection at /api/users"
    assert f.category == "sqli"
    assert f.cwe == "CWE-89"
    assert f.severity == "high"


def test_normalise_finding_extracts_sca_package() -> None:
    """SCA findings should auto-extract the package name from
    the title format the SCA emit path uses."""
    raw = {
        "title": "Vulnerable dependency `npm:lodash@4.17.20` (1 CVE)",
        "category": "vulnerable_dependency",
        "severity": "high",
    }
    f = normalise_finding(raw)
    assert f is not None
    assert f.package == "npm:lodash"


def test_normalise_finding_synthesises_id_when_missing() -> None:
    """Findings without explicit IDs should get a stable
    synthesised one (so two normalisations of the same finding
    produce the same id)."""
    raw = {
        "title": "X",
        "category": "sast",
        "cwe": "CWE-89",
        "endpoint": "app.js:42",
    }
    f1 = normalise_finding(raw)
    f2 = normalise_finding(raw)
    assert f1 is not None and f2 is not None
    assert f1.id == f2.id
    assert f1.id.startswith("f-")


def test_normalise_finding_rejects_input_without_title() -> None:
    raw = {"category": "sqli"}
    assert normalise_finding(raw) is None


def test_normalise_finding_rejects_input_without_category_or_cwe() -> None:
    """A finding with neither a category nor a CWE has nothing
    for linkers to match on — reject."""
    raw = {"title": "weird"}
    assert normalise_finding(raw) is None


def test_normalise_finding_handles_pydantic_model() -> None:
    """`FindingDraft` instances expose `.model_dump()` — accept
    that path so the lead can call the correlator with
    in-memory drafts."""

    class FakeDraft:
        def model_dump(self):
            return {
                "title": "X", "category": "sqli", "cwe": "CWE-89",
                "severity": "high",
            }

    f = normalise_finding(FakeDraft())
    assert f is not None
    assert f.category == "sqli"


def test_normalise_findings_skips_invalid_inputs() -> None:
    """One bad row shouldn't poison the bulk normaliser."""
    inputs = [
        {"title": "Good", "category": "sqli"},
        None,
        {"category": "no title"},
        "not a dict",
        {"title": "Also good", "cwe": "CWE-79"},
    ]
    out = normalise_findings(inputs)
    assert len(out) == 2
