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
    # 15 checks total. The deeper checks (dane / bimi / dmarc_rua / spf_lookups /
    # dkim_keys / open_resolver / dangling_ns) all early-out as inconclusive
    # when the underlying records or NS list aren't present, so they don't add
    # findings on a blank target.
    assert len(out["checks_run"]) == 15
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    # spf, dmarc, mta_sts, caa, dnssec all missing → 5 findings.
    assert len(reports) == 5


# ---------------------------------------------------------------------------
# DANE / BIMI — informational checks (no findings either way)
# ---------------------------------------------------------------------------


def test_dane_present_no_finding(monkeypatch) -> None:
    _patch_dig(
        monkeypatch,
        {"_25._tcp.example.com|TLSA": "3 1 1 abc123def456"},
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dane")
    assert out["results"][0]["present"] is True
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_dane_absent_no_finding(monkeypatch) -> None:
    _patch_dig(monkeypatch, {})
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dane")
    assert out["results"][0]["present"] is False
    # DANE absence is informational, not a finding.
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_bimi_present_no_finding(monkeypatch) -> None:
    _patch_dig(
        monkeypatch,
        {"default._bimi.example.com|TXT": '"v=BIMI1; l=https://example.com/logo.svg"'},
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="bimi")
    assert out["results"][0]["present"] is True
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


# ---------------------------------------------------------------------------
# DMARC RUA reachability
# ---------------------------------------------------------------------------


def test_dmarc_rua_unreachable_emits_finding(monkeypatch) -> None:
    _patch_dig(
        monkeypatch,
        {
            "_dmarc.example.com|TXT": '"v=DMARC1; p=quarantine; rua=mailto:reports@offline.example;"',
            "offline.example|MX": "",  # no MX → unreachable
        },
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dmarc_rua")
    assert out["results"][0]["mx_present"] is False
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["category"] == "email_security"
    assert "rua" in reports[0]["title"].lower()


def test_dmarc_rua_reachable_no_finding(monkeypatch) -> None:
    _patch_dig(
        monkeypatch,
        {
            "_dmarc.example.com|TXT": '"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com;"',
            "example.com|MX": "10 mx.example.com.",  # has MX
        },
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dmarc_rua")
    assert out["results"][0]["mx_present"] is True
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_dmarc_rua_no_dmarc_inconclusive(monkeypatch) -> None:
    _patch_dig(monkeypatch, {})
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dmarc_rua")
    assert out["results"][0]["rua_present"] is False
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


# ---------------------------------------------------------------------------
# SPF lookup-count audit
# ---------------------------------------------------------------------------


def test_spf_lookups_within_limit_no_finding(monkeypatch) -> None:
    _patch_dig(
        monkeypatch,
        {"example.com|TXT": '"v=spf1 include:_spf.google.com include:mailgun.org -all"'},
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="spf_lookups")
    assert out["results"][0]["apex_lookup_count"] == 2
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_spf_lookups_over_limit_emits_finding(monkeypatch) -> None:
    # 11 includes — over the 10-lookup limit
    spf = "v=spf1 " + " ".join(f"include:p{i}.example.com" for i in range(11)) + " -all"
    _patch_dig(monkeypatch, {"example.com|TXT": f'"{spf}"'})
    out = dns_hygiene.dns_hygiene_check("example.com", checks="spf_lookups")
    assert out["results"][0]["apex_lookup_count"] == 11
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "medium"
    assert "spf" in reports[0]["title"].lower()


def test_spf_lookups_no_spf_inconclusive(monkeypatch) -> None:
    _patch_dig(monkeypatch, {})
    out = dns_hygiene.dns_hygiene_check("example.com", checks="spf_lookups")
    assert out["results"][0]["spf_present"] is False


# ---------------------------------------------------------------------------
# DKIM key-strength audit
# ---------------------------------------------------------------------------


def test_dkim_weak_key_emits_finding(monkeypatch) -> None:
    """A short SPKI body simulates an RSA-1024 key (~162 bytes decoded).
    SPKI of 100 base64 chars decodes to ~75 bytes — clearly under the 250 threshold."""
    short_p = "A" * 100  # base64 padding-friendly
    _patch_dig(
        monkeypatch,
        {f"default._domainkey.example.com|TXT": f'"v=DKIM1; k=rsa; p={short_p}"'},
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dkim_keys")
    assert "default" in out["results"][0]["weak_selectors"]
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["category"] == "email_security"
    assert reports[0]["cwe"] == "CWE-326"


def test_dkim_strong_key_no_finding(monkeypatch) -> None:
    """Long base64 simulates an RSA-2048 key (~294 bytes decoded; 392 base64 chars)."""
    long_p = "A" * 400
    _patch_dig(
        monkeypatch,
        {f"google._domainkey.example.com|TXT": f'"v=DKIM1; k=rsa; p={long_p}"'},
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dkim_keys")
    assert out["results"][0]["weak_selectors"] == []
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_dkim_no_selectors_inconclusive(monkeypatch) -> None:
    _patch_dig(monkeypatch, {})
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dkim_keys")
    assert out["results"][0]["audited"] == []


# ---------------------------------------------------------------------------
# Open recursive resolver
# ---------------------------------------------------------------------------


def test_open_recursive_resolver_emits_finding(monkeypatch) -> None:
    _patch_dig(
        monkeypatch,
        {
            "example.com|NS": "ns1.example.com.\nns2.example.com.",
            # A query against an unrelated zone returns an answer → recursing.
            "a.iana-servers.net|A": "199.43.135.53",
        },
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="open_resolver")
    assert len(out["results"][0]["open_nameservers"]) > 0
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["category"] == "dns_security" and "recursive" in r["title"].lower() for r in reports)


def test_open_resolver_no_recursion_no_finding(monkeypatch) -> None:
    _patch_dig(
        monkeypatch,
        {"example.com|NS": "ns1.example.com.\nns2.example.com."},
        # No fake A response for a.iana-servers.net → NS doesn't recurse.
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="open_resolver")
    assert out["results"][0]["open_nameservers"] == []
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_open_resolver_no_ns_inconclusive(monkeypatch) -> None:
    _patch_dig(monkeypatch, {})
    out = dns_hygiene.dns_hygiene_check("example.com", checks="open_resolver")
    assert out["results"][0]["tested"] is False


# ---------------------------------------------------------------------------
# Dangling NS
# ---------------------------------------------------------------------------


def test_dangling_ns_emits_high_severity_finding(monkeypatch) -> None:
    _patch_dig(
        monkeypatch,
        {
            "example.com|NS": "ns1.example.com.\nns-decommissioned.example.com.",
            "ns1.example.com|A": "1.2.3.4",
            # ns-decommissioned doesn't resolve → dangling
        },
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dangling_ns")
    assert "ns-decommissioned.example.com" in out["results"][0]["dangling"]
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "high" and "dangling" in r["title"].lower() for r in reports)


def test_dangling_ns_all_resolve_no_finding(monkeypatch) -> None:
    _patch_dig(
        monkeypatch,
        {
            "example.com|NS": "ns1.example.com.\nns2.example.com.",
            "ns1.example.com|A": "1.2.3.4",
            "ns2.example.com|A": "5.6.7.8",
        },
    )
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dangling_ns")
    assert out["results"][0]["dangling"] == []
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []
