"""Tests for dns_hygiene_check.

We mock the `dig` helper so the test suite is hermetic — no actual DNS
queries are made. Each test pins one check's behaviour independently.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.tools.recon import dns_hygiene


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    tracer = Tracer("dns-hygiene-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["example.com"]})
    yield


def _patch_dig(monkeypatch, responses: dict[str, str]) -> None:
    def fake_dig(query: str, record_type: str = "A", **_: Any) -> str:
        return responses.get(f"{query}|{record_type}", responses.get(query, ""))

    monkeypatch.setattr(dns_hygiene, "dig", fake_dig)


def test_invalid_domain_rejected() -> None:
    out = dns_hygiene.dns_hygiene_check("not a domain")
    assert out["success"] is False
    assert "invalid" in out["error"].lower()


def test_unknown_check_rejected(monkeypatch) -> None:
    _patch_dig(monkeypatch, {})
    out = dns_hygiene.dns_hygiene_check("example.com", checks="spf,nonexistent")
    assert out["success"] is False
    assert "unknown checks" in out["error"]


def test_missing_spf_emits_finding(monkeypatch) -> None:
    _patch_dig(monkeypatch, {"example.com|TXT": '"some-other-record"'})
    out = dns_hygiene.dns_hygiene_check("example.com", checks="spf")
    assert out["success"] is True
    assert out["results"][0] == {"check": "spf", "present": False, "value": None}

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["category"] == "email_security"
    assert "spf" in reports[0]["title"].lower()


def test_present_spf_no_finding(monkeypatch) -> None:
    _patch_dig(monkeypatch, {"example.com|TXT": '"v=spf1 include:_spf.google.com -all"'})
    out = dns_hygiene.dns_hygiene_check("example.com", checks="spf")
    assert out["results"][0]["present"] is True
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_dmarc_p_none_emits_lower_severity(monkeypatch) -> None:
    _patch_dig(
        monkeypatch,
        {"_dmarc.example.com|TXT": '"v=DMARC1; p=none; rua=mailto:dm@example.com"'},
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dmarc")
    assert out["results"][0]["policy"] == "none"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "low"


def test_dmarc_quarantine_no_finding(monkeypatch) -> None:
    _patch_dig(
        monkeypatch,
        {"_dmarc.example.com|TXT": '"v=DMARC1; p=quarantine; rua=mailto:dm@example.com"'},
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dmarc")
    assert out["results"][0]["policy"] == "quarantine"
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_dnssec_unsigned_emits_finding(monkeypatch) -> None:
    _patch_dig(monkeypatch, {})  # no DNSKEY
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dnssec")
    assert out["results"][0]["signed"] is False
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["category"] == "dns_security"


def test_axfr_exposure_emits_high_severity(monkeypatch) -> None:
    long_zone = "\n".join(
        ["example.com. 3600 IN A 1.2.3.4"] * 30
    )
    responses = {
        "example.com|NS": "ns1.example.com.\nns2.example.com.",
        "example.com|AXFR": long_zone,
    }
    _patch_dig(monkeypatch, responses)
    out = dns_hygiene.dns_hygiene_check("example.com", checks="axfr")
    assert out["results"][0]["exposed_nameservers"]
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "high" and r["category"] == "dns_security" for r in reports)


def test_all_checks_run_when_default(monkeypatch) -> None:
    _patch_dig(monkeypatch, {})  # everything missing → many findings
    out = dns_hygiene.dns_hygiene_check("example.com")
    assert out["success"] is True
    # 8 default checks, but axfr returns "no NS records" early so it doesn't
    # emit; and dkim doesn't emit when selectors are absent.
    assert len(out["checks_run"]) == 8
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    # spf, dmarc, mta_sts, caa, dnssec all missing → 5 findings.
    assert len(reports) == 5
