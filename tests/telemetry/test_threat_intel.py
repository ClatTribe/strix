"""Tests for threat_intel.py and the enrichment hook in tracer.add_vulnerability_report."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import threat_intel
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


# ---------------------------------------------------------------------------
# Static mappings
# ---------------------------------------------------------------------------


def test_owasp_top_10_for_sqli() -> None:
    assert threat_intel.lookup_owasp_top_10("CWE-89") == "A03:2021"


def test_owasp_top_10_for_ssrf() -> None:
    assert threat_intel.lookup_owasp_top_10("CWE-918") == "A10:2021"


def test_owasp_top_10_normalizes_input() -> None:
    assert threat_intel.lookup_owasp_top_10("89") == "A03:2021"
    assert threat_intel.lookup_owasp_top_10("cwe-89") == "A03:2021"


def test_owasp_top_10_unknown_returns_none() -> None:
    assert threat_intel.lookup_owasp_top_10("CWE-99999") is None
    assert threat_intel.lookup_owasp_top_10(None) is None
    assert threat_intel.lookup_owasp_top_10("") is None


def test_owasp_api_top_10_for_idor() -> None:
    assert threat_intel.lookup_owasp_api_top_10("CWE-639") == "API1:2023"


def test_owasp_api_top_10_for_ssrf() -> None:
    assert threat_intel.lookup_owasp_api_top_10("CWE-918") == "API7:2023"


def test_mitre_attack_for_cmd_injection() -> None:
    assert threat_intel.lookup_mitre_attack("CWE-78") == ["T1059"]


def test_mitre_attack_for_ssrf_returns_multiple() -> None:
    techniques = threat_intel.lookup_mitre_attack("CWE-918")
    assert "T1071.001" in techniques
    assert "T1090" in techniques


def test_mitre_attack_unknown_returns_empty() -> None:
    assert threat_intel.lookup_mitre_attack("CWE-99999") == []
    assert threat_intel.lookup_mitre_attack(None) == []


# ---------------------------------------------------------------------------
# KEV catalog
# ---------------------------------------------------------------------------


_KEV_FAKE_PAYLOAD = {
    "title": "CISA KEV (test fixture)",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 RCE",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "requiredAction": "Apply updates",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2024-1234",
            "vendorProject": "ExampleCo",
            "product": "ExampleProduct",
            "vulnerabilityName": "Example RCE",
            "dateAdded": "2024-01-15",
            "dueDate": "2024-02-05",
            "requiredAction": "Update",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


@pytest.fixture
def kev_catalog_with_cache(tmp_path) -> threat_intel.KevCatalog:
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(_KEV_FAKE_PAYLOAD))
    return threat_intel.KevCatalog(
        url="http://invalid.example/never-fetched",
        cache_path=cache,
    )


def test_kev_lookup_known_cve(kev_catalog_with_cache) -> None:
    catalog = kev_catalog_with_cache
    assert catalog.is_known("CVE-2021-44228") is True
    entry = catalog.entry("CVE-2021-44228")
    assert entry is not None
    assert entry["vendor"] == "Apache"
    assert entry["added_at"] == "2021-12-10"


def test_kev_lookup_unknown_cve(kev_catalog_with_cache) -> None:
    catalog = kev_catalog_with_cache
    assert catalog.is_known("CVE-1999-0001") is False


def test_kev_lookup_invalid_input_returns_none(kev_catalog_with_cache) -> None:
    catalog = kev_catalog_with_cache
    assert catalog.is_known("not-a-cve") is None
    assert catalog.is_known(None) is None
    assert catalog.is_known("") is None


def test_kev_disabled_env_skips_load(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(_KEV_FAKE_PAYLOAD))
    catalog = threat_intel.KevCatalog(
        url="http://invalid.example/never-fetched", cache_path=cache
    )
    # With disabled, even a fresh cache shouldn't load.
    assert catalog.is_known("CVE-2021-44228") is None
    assert catalog.loaded() is False


def test_kev_no_cache_no_network_returns_none(monkeypatch, tmp_path) -> None:
    """When no cache exists and remote fetch fails, lookups return None."""
    def fake_fetch(*_args, **_kwargs):
        raise OSError("simulated network failure")

    monkeypatch.setattr(threat_intel, "_fetch_json", fake_fetch)
    catalog = threat_intel.KevCatalog(
        url="http://invalid.example/never-fetched",
        cache_path=tmp_path / "nonexistent.json",
    )
    assert catalog.is_known("CVE-2021-44228") is None


def test_kev_falls_back_to_stale_cache(monkeypatch, tmp_path) -> None:
    """Stale cache should still serve when remote fetch fails."""
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(_KEV_FAKE_PAYLOAD))
    # Make the cache appear ancient
    import os
    old = 1000  # 1970-ish
    os.utime(cache, (old, old))

    def fake_fetch(*_args, **_kwargs):
        raise OSError("simulated network failure")

    monkeypatch.setattr(threat_intel, "_fetch_json", fake_fetch)
    catalog = threat_intel.KevCatalog(
        url="http://invalid.example/never-fetched", cache_path=cache
    )
    # Stale cache used as fallback after fetch fails.
    assert catalog.is_known("CVE-2021-44228") is True


# ---------------------------------------------------------------------------
# enrich() — single-shot helper
# ---------------------------------------------------------------------------


def test_enrich_merges_owasp_and_mitre(monkeypatch) -> None:
    # Disable KEV to keep the test hermetic.
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    threat_intel.set_default_catalog(None)

    out = threat_intel.enrich(cwe="CWE-89", cve=None)
    assert out["owasp_top_10"] == "A03:2021"
    assert out["mitre_attack"] == ["T1190"]
    assert "is_kev" not in out  # No CVE → no KEV check.
    assert "owasp_api_top_10" not in out  # CWE-89 not in API map.


def test_enrich_with_kev_known_cve(monkeypatch, tmp_path) -> None:
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(_KEV_FAKE_PAYLOAD))
    threat_intel.set_default_catalog(
        threat_intel.KevCatalog(url="http://invalid", cache_path=cache)
    )

    out = threat_intel.enrich(cwe=None, cve="CVE-2021-44228")
    assert out["is_kev"] is True
    assert out["kev_added_at"] == "2021-12-10"
    assert "cisa_kev_url" in out
    threat_intel.set_default_catalog(None)


def test_enrich_with_kev_unknown_cve(monkeypatch, tmp_path) -> None:
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(_KEV_FAKE_PAYLOAD))
    threat_intel.set_default_catalog(
        threat_intel.KevCatalog(url="http://invalid", cache_path=cache)
    )

    out = threat_intel.enrich(cwe=None, cve="CVE-9999-9999")
    assert out["is_kev"] is False
    assert "kev_added_at" not in out
    threat_intel.set_default_catalog(None)


def test_enrich_no_cwe_no_cve_empty(monkeypatch) -> None:
    threat_intel.set_default_catalog(None)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    assert threat_intel.enrich(cwe=None, cve=None) == {}


# ---------------------------------------------------------------------------
# Integration: tracer.add_vulnerability_report uses the enrichment
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_tracer_for_integration(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    threat_intel.set_default_catalog(None)
    yield
    threat_intel.set_default_catalog(None)


def test_tracer_enriches_with_owasp_and_mitre(monkeypatch, tmp_path) -> None:
    # Disable KEV (no CVE in this finding anyway, but be safe).
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")

    tracer = Tracer("ti-integration")
    set_global_tracer(tracer)
    tracer.add_vulnerability_report(
        title="SQLi in /search", severity="high", cwe="CWE-89"
    )

    reports = tracer.get_existing_vulnerabilities()
    assert reports[0]["owasp_top_10"] == "A03:2021"
    assert reports[0]["mitre_attack"] == ["T1190"]
    assert reports[0]["category"] == "sqli"


def test_tracer_enriches_with_kev_when_cve_present(monkeypatch, tmp_path) -> None:
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(_KEV_FAKE_PAYLOAD))
    threat_intel.set_default_catalog(
        threat_intel.KevCatalog(url="http://invalid", cache_path=cache)
    )

    tracer = Tracer("ti-kev")
    set_global_tracer(tracer)
    tracer.add_vulnerability_report(
        title="Log4Shell exploit",
        severity="critical",
        cwe="CWE-502",
        cve="CVE-2021-44228",
    )

    report = tracer.get_existing_vulnerabilities()[0]
    assert report["is_kev"] is True
    assert report["kev_added_at"] == "2021-12-10"
    assert report["mitre_attack"] == ["T1190"]
    assert report["owasp_top_10"] == "A08:2021"


def test_vulnerabilities_json_includes_threat_intel_fields(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("ti-json")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["example.com"]})
    tracer.add_vulnerability_report(
        title="Open redirect", severity="medium", cwe="CWE-601"
    )

    json_path = tmp_path / "strix_runs" / "ti-json" / "vulnerabilities.json"
    data = json.loads(json_path.read_text())
    finding = data["findings"][0]
    assert finding["owasp_top_10"] == "A01:2021"
    assert finding["mitre_attack"] == ["T1204.001"]


def test_enrichment_does_not_break_on_unknown_cwe(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("ti-unknown-cwe")
    set_global_tracer(tracer)
    tracer.add_vulnerability_report(
        title="Some weird finding", severity="low", cwe="CWE-99999"
    )
    report = tracer.get_existing_vulnerabilities()[0]
    # No threat-intel fields should be set when CWE is unknown.
    assert "owasp_top_10" not in report
    assert "mitre_attack" not in report
    assert "is_kev" not in report
