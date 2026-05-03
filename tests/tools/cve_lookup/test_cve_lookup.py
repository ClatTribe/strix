"""Tests for cve_lookup.

Hermetic — `_query_osv` is monkeypatched. Tests cover:

- Input validation (empty name / version)
- CVE alias extraction (canonical CVE-* in aliases / fallback to id)
- Severity derivation: GHSA enum, CVSS numeric, CVSS vector, default
- Fix-version extraction from `affected[].ranges[].events[].fixed`
- Reference extraction (caps to 5)
- Summary text fallback (summary → details)
- Fresh response → finding emitted (severity tied to source)
- Empty vulns → no findings, no error
- KEV auto-enrichment via tracer (no manual KEV plumbing)
- Cache hit returns from_cache=True without querying OSV
- Stale cache served on OSV failure (fail-open)
- OSV failure with no cache returns success=False with error
- Cache disabled by STRIX_CVE_LOOKUP_NO_CACHE=1
- Per-finding description_plain + recommended_action populated
- check.completed event emitted with category=cve_lookup
- _MAX_CVES_PER_LOOKUP cap
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.cve_lookup.cve_lookup  # noqa: F401

cl_module = sys.modules["strix.tools.cve_lookup.cve_lookup"]
cve_lookup = cl_module.cve_lookup


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    # Redirect HOME so the cache writes go into tmp_path, not user's real
    # ~/.strix dir. Must be set BEFORE any cve_lookup call.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    monkeypatch.delenv("STRIX_CVE_LOOKUP_NO_CACHE", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("cve-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://app.example.com/"}]})
    yield


def _patch_osv(monkeypatch, responder):
    """Install a fake `_query_osv`. responder(name, version, ecosystem) → dict."""
    log: list[dict[str, Any]] = []

    def fake(name, version, ecosystem, timeout):
        log.append({"name": name, "version": version, "ecosystem": ecosystem})
        return responder(name, version, ecosystem)

    monkeypatch.setattr(cl_module, "_query_osv", fake)
    return log


def _vuln(
    *,
    osv_id: str = "GHSA-xxxx-yyyy-zzzz",
    aliases: list[str] | None = None,
    summary: str = "Test summary",
    severity_enum: str | None = "HIGH",
    cvss_score: float | None = None,
    cvss_vector: str | None = None,
    fix_versions: list[str] | None = None,
    name: str = "test-pkg",
    ecosystem: str = "npm",
    references: list[str] | None = None,
) -> dict[str, Any]:
    db_spec: dict[str, Any] = {}
    if severity_enum:
        db_spec["severity"] = severity_enum
    if cvss_score is not None:
        db_spec["cvss"] = {"score": cvss_score}

    severity_arr: list[dict[str, str]] = []
    if cvss_vector:
        severity_arr.append({"type": "CVSS_V3", "score": cvss_vector})

    affected = [{
        "package": {"name": name, "ecosystem": ecosystem},
        "ranges": [{
            "events": [
                {"introduced": "0"},
                *([{"fixed": fv} for fv in (fix_versions or [])])
            ],
        }],
    }]

    return {
        "id": osv_id,
        "aliases": aliases or [],
        "summary": summary,
        "severity": severity_arr,
        "affected": affected,
        "references": [{"type": "ADVISORY", "url": u} for u in (references or [])],
        "database_specific": db_spec,
    }


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_missing_name_rejected(monkeypatch) -> None:
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": []})
    out = cve_lookup("", "1.0.0", "npm")
    assert out["success"] is False


def test_missing_version_rejected(monkeypatch) -> None:
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": []})
    out = cve_lookup("express", "", "npm")
    assert out["success"] is False


def test_empty_ecosystem_allowed(monkeypatch) -> None:
    log = _patch_osv(monkeypatch, lambda n, v, e: {"vulns": []})
    out = cve_lookup("some-pkg", "1.2.3", "")
    assert out["success"] is True
    assert log[0]["ecosystem"] == ""


# ---------------------------------------------------------------------------
# CVE alias extraction
# ---------------------------------------------------------------------------


def test_extract_cve_from_aliases() -> None:
    cve = cl_module._extract_cve_id({"aliases": ["GHSA-x", "CVE-2022-12345"]})
    assert cve == "CVE-2022-12345"


def test_extract_cve_returns_none_when_no_alias() -> None:
    cve = cl_module._extract_cve_id({"aliases": ["GHSA-x"]})
    assert cve is None


def test_extract_cve_falls_back_to_top_level_id() -> None:
    """Some advisories put the CVE in `id` directly."""
    cve = cl_module._extract_cve_id({"id": "CVE-2022-99999", "aliases": []})
    assert cve == "CVE-2022-99999"


def test_extract_cve_uppercases() -> None:
    assert cl_module._extract_cve_id({"aliases": ["cve-2022-12345"]}) == "CVE-2022-12345"


# ---------------------------------------------------------------------------
# Severity derivation
# ---------------------------------------------------------------------------


def test_severity_ghsa_enum_critical() -> None:
    sev, _ = cl_module._derive_severity({"database_specific": {"severity": "CRITICAL"}})
    assert sev == "critical"


def test_severity_ghsa_enum_moderate_to_medium() -> None:
    sev, _ = cl_module._derive_severity({"database_specific": {"severity": "MODERATE"}})
    assert sev == "medium"


def test_severity_cvss_score_high_band() -> None:
    sev, _ = cl_module._derive_severity({"database_specific": {"cvss": {"score": 8.1}}})
    assert sev == "high"


def test_severity_cvss_score_low_band() -> None:
    sev, _ = cl_module._derive_severity({"database_specific": {"cvss": {"score": 3.1}}})
    assert sev == "low"


def test_severity_severity_array_numeric() -> None:
    sev, meta = cl_module._derive_severity({
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
    })
    assert sev == "critical"
    assert meta["source"] == "severity[].score"


def test_severity_severity_array_vector_high() -> None:
    sev, _ = cl_module._derive_severity({
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    })
    assert sev == "high"


def test_severity_severity_array_vector_medium_when_local() -> None:
    sev, _ = cl_module._derive_severity({
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    })
    assert sev == "medium"


def test_severity_default_medium() -> None:
    sev, meta = cl_module._derive_severity({})
    assert sev == "medium"
    assert meta["source"] == "default"


def test_cvss_score_to_severity_bands() -> None:
    assert cl_module._cvss_score_to_severity(9.8) == "critical"
    assert cl_module._cvss_score_to_severity(7.5) == "high"
    assert cl_module._cvss_score_to_severity(4.0) == "medium"
    assert cl_module._cvss_score_to_severity(3.9) == "low"


# ---------------------------------------------------------------------------
# Fix-version extraction
# ---------------------------------------------------------------------------


def test_fix_versions_extracted() -> None:
    vuln = _vuln(fix_versions=["1.2.3", "2.0.0"], name="lib", ecosystem="npm")
    fixes = cl_module._extract_fix_versions(vuln, "lib", "npm")
    assert fixes == ["1.2.3", "2.0.0"]


def test_fix_versions_filters_by_ecosystem() -> None:
    vuln = {
        "affected": [
            {"package": {"name": "lib", "ecosystem": "npm"}, "ranges": [{"events": [{"fixed": "1.2.3"}]}]},
            {"package": {"name": "lib", "ecosystem": "PyPI"}, "ranges": [{"events": [{"fixed": "0.0.9"}]}]},
        ]
    }
    npm_fixes = cl_module._extract_fix_versions(vuln, "lib", "npm")
    pypi_fixes = cl_module._extract_fix_versions(vuln, "lib", "PyPI")
    assert npm_fixes == ["1.2.3"]
    assert pypi_fixes == ["0.0.9"]


def test_fix_versions_dedup() -> None:
    vuln = {
        "affected": [
            {"package": {"name": "lib", "ecosystem": "npm"},
             "ranges": [{"events": [{"fixed": "1.2.3"}, {"fixed": "1.2.3"}]}]},
        ]
    }
    fixes = cl_module._extract_fix_versions(vuln, "lib", "npm")
    assert fixes == ["1.2.3"]


# ---------------------------------------------------------------------------
# References extraction
# ---------------------------------------------------------------------------


def test_references_extracted_capped() -> None:
    refs = [f"https://example.com/{i}" for i in range(10)]
    vuln = _vuln(references=refs)
    out = cl_module._extract_references(vuln, cap=5)
    assert len(out) == 5
    assert out == refs[:5]


def test_references_filters_non_http() -> None:
    vuln = {"references": [
        {"url": "https://x.com/a"}, {"url": "ftp://nope"},
        {"url": "javascript:alert(1)"}, {"url": "http://y.com/b"},
    ]}
    out = cl_module._extract_references(vuln, cap=5)
    assert out == ["https://x.com/a", "http://y.com/b"]


# ---------------------------------------------------------------------------
# Summary text
# ---------------------------------------------------------------------------


def test_summary_uses_summary_field() -> None:
    assert cl_module._summary_text({"summary": "Short summary text"}) == "Short summary text"


def test_summary_falls_back_to_details_first_line() -> None:
    out = cl_module._summary_text({"details": "First line.\nMore lines.\nEven more."})
    assert out == "First line."


def test_summary_caps_at_500_chars() -> None:
    long_text = "a" * 1000
    out = cl_module._summary_text({"summary": long_text})
    assert len(out) == 500


# ---------------------------------------------------------------------------
# Fresh response → emit findings
# ---------------------------------------------------------------------------


def test_single_vuln_emits_finding(monkeypatch) -> None:
    vuln = _vuln(
        osv_id="GHSA-xxxx",
        aliases=["CVE-2022-12345"],
        summary="Prototype pollution in lodash",
        severity_enum="HIGH",
        fix_versions=["4.17.21"],
        name="lodash",
        ecosystem="npm",
        references=["https://github.com/advisories/GHSA-xxxx"],
    )
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": [vuln]})
    out = cve_lookup("lodash", "4.17.10", "npm")

    assert out["success"] is True
    assert out["cve_count"] == 1
    assert out["findings_emitted"] == 1
    assert out["from_cache"] is False
    assert out["vulnerabilities"][0]["cve"] == "CVE-2022-12345"
    assert out["vulnerabilities"][0]["severity"] == "high"
    assert out["vulnerabilities"][0]["fix_versions"] == ["4.17.21"]

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    r = reports[0]
    assert r["category"] == "vulnerable_dependency"
    assert r["cwe"] == "CWE-1104"
    assert r["cve"] == "CVE-2022-12345"
    assert r["severity"] == "high"
    assert r.get("description_plain")
    assert r.get("recommended_action")
    assert "4.17.21" in r["recommended_action"]


def test_multiple_vulns_emit_multiple_findings(monkeypatch) -> None:
    vulns = [
        _vuln(osv_id="GHSA-a", aliases=["CVE-2022-1"], severity_enum="CRITICAL"),
        _vuln(osv_id="GHSA-b", aliases=["CVE-2022-2"], severity_enum="HIGH"),
        _vuln(osv_id="GHSA-c", aliases=["CVE-2022-3"], severity_enum="LOW"),
    ]
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": vulns})
    out = cve_lookup("test-pkg", "1.0.0", "npm")
    assert out["findings_emitted"] == 3
    severities = {r["severity"] for r in tracer_module.get_global_tracer().get_existing_vulnerabilities()}
    assert "critical" in severities
    assert "high" in severities
    assert "low" in severities


def test_empty_vulns_no_findings(monkeypatch) -> None:
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": []})
    out = cve_lookup("clean-pkg", "1.0.0", "npm")
    assert out["success"] is True
    assert out["cve_count"] == 0
    assert out["findings_emitted"] == 0
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_vuln_without_cve_alias_uses_osv_id(monkeypatch) -> None:
    vuln = _vuln(osv_id="GHSA-xxxx", aliases=[], summary="No CVE assigned yet")
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": [vuln]})
    out = cve_lookup("x", "1.0.0", "npm")
    assert out["vulnerabilities"][0]["cve"] is None
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    # The tracer omits the `cve` key when None (see add_vulnerability_report).
    assert reports[0].get("cve") is None
    assert "GHSA-xxxx" in reports[0]["title"]


def test_no_fix_version_uses_monitor_action(monkeypatch) -> None:
    vuln = _vuln(fix_versions=[], aliases=["CVE-2099-9999"])
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": [vuln]})
    cve_lookup("test-pkg", "1.0.0", "npm")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert "monitor" in reports[0]["recommended_action"].lower()


# ---------------------------------------------------------------------------
# Cache behaviour
# ---------------------------------------------------------------------------


def test_cache_hit_returns_from_cache(monkeypatch, tmp_path) -> None:
    """Second call with same triple within TTL → hits cache, no fresh OSV query."""
    vuln = _vuln(aliases=["CVE-2022-1"])
    log = _patch_osv(monkeypatch, lambda n, v, e: {"vulns": [vuln]})

    out1 = cve_lookup("test-pkg", "1.0.0", "npm")
    assert out1["from_cache"] is False
    assert len(log) == 1

    out2 = cve_lookup("test-pkg", "1.0.0", "npm")
    assert out2["from_cache"] is True
    # Second call should NOT re-hit OSV.
    assert len(log) == 1


def test_cache_disabled_via_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_CVE_LOOKUP_NO_CACHE", "1")
    log = _patch_osv(monkeypatch, lambda n, v, e: {"vulns": []})
    cve_lookup("x", "1.0.0", "npm")
    cve_lookup("x", "1.0.0", "npm")
    # Both should hit OSV directly.
    assert len(log) == 2


def test_stale_cache_served_on_osv_failure(monkeypatch) -> None:
    """OSV fails → return stale cache with `error` populated."""
    # First call: populate cache.
    vuln = _vuln(aliases=["CVE-2022-1"])
    call_count = [0]

    def responder(n, v, e):
        call_count[0] += 1
        if call_count[0] == 1:
            return {"vulns": [vuln]}
        return {"error": "network unreachable"}

    _patch_osv(monkeypatch, responder)
    cve_lookup("test-pkg", "1.0.0", "npm")  # populates cache

    # Now make the cache stale and force a fresh query that fails.
    cache_path = cl_module._cache_path("test-pkg", "1.0.0", "npm")
    old_mtime = time.time() - 10 * 3600  # > TTL
    import os as _os
    _os.utime(cache_path, (old_mtime, old_mtime))

    out = cve_lookup("test-pkg", "1.0.0", "npm")
    assert out["from_cache"] is True
    assert out["success"] is True
    assert "stale cache" in (out.get("error") or "")
    # Findings are re-emitted from the stale cache.
    assert out["findings_emitted"] == 1


def test_osv_failure_no_cache_returns_error(monkeypatch) -> None:
    _patch_osv(monkeypatch, lambda n, v, e: {"error": "DNS resolution failed"})
    out = cve_lookup("never-cached-pkg", "9.9.9", "npm")
    assert out["success"] is False
    assert "DNS resolution failed" in out["error"]
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Cap on findings
# ---------------------------------------------------------------------------


def test_max_cves_per_lookup_cap(monkeypatch) -> None:
    """Don't flood findings — cap at _MAX_CVES_PER_LOOKUP (200)."""
    huge = [_vuln(osv_id=f"GHSA-{i:04d}", aliases=[f"CVE-2022-{i:04d}"]) for i in range(250)]
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": huge})
    out = cve_lookup("noisy-pkg", "1.0.0", "npm")
    assert out["cve_count"] == 200  # cap honoured
    assert out["findings_emitted"] == 200


# ---------------------------------------------------------------------------
# §11 UX baseline
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    vulns = [
        _vuln(osv_id="GHSA-a", aliases=["CVE-2022-1"], severity_enum="CRITICAL", fix_versions=["2.0.0"]),
        _vuln(osv_id="GHSA-b", aliases=[], severity_enum="MODERATE", fix_versions=[]),
    ]
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": vulns})
    cve_lookup("test-pkg", "1.0.0", "npm")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain on: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action on: {r['title']}"
        assert r["category"] == "vulnerable_dependency"
        assert r["cwe"] == "CWE-1104"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": []})
    cve_lookup("clean-pkg", "1.0.0", "npm")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "cve_lookup" in summary["by_category"]
    assert summary["by_category"]["cve_lookup"]["not_vulnerable"] == 1


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": [_vuln(aliases=["CVE-2022-1"])]})
    cve_lookup("vuln-pkg", "1.0.0", "npm")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["cve_lookup"]
    assert cat["vulnerable"] == 1


def test_check_event_inconclusive_on_osv_failure(monkeypatch) -> None:
    _patch_osv(monkeypatch, lambda n, v, e: {"error": "boom"})
    cve_lookup("never-cached", "1.0.0", "npm")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["cve_lookup"]
    assert cat.get("inconclusive", 0) == 1


# ---------------------------------------------------------------------------
# Cache-key collision-resistance
# ---------------------------------------------------------------------------


def test_cache_key_distinct_per_triple() -> None:
    a = cl_module._cache_key("express", "4.16.0", "npm")
    b = cl_module._cache_key("express", "4.17.0", "npm")
    c = cl_module._cache_key("Express", "4.16.0", "npm")  # same up to case
    d = cl_module._cache_key("express", "4.16.0", "PyPI")
    assert a != b
    assert a == c  # case-insensitive on name + ecosystem
    assert a != d


# ---------------------------------------------------------------------------
# Result schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    _patch_osv(monkeypatch, lambda n, v, e: {"vulns": [_vuln(aliases=["CVE-2022-1"])]})
    out = cve_lookup("test-pkg", "1.0.0", "npm")
    for k in ("success", "name", "version", "ecosystem", "osv_url",
              "queried_at", "cve_count", "from_cache", "vulnerabilities",
              "findings_emitted"):
        assert k in out
    for v in out["vulnerabilities"]:
        for k in ("id", "cve", "severity", "severity_source", "summary",
                  "fix_versions", "references", "ghsa_id", "alias_count"):
            assert k in v
