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
    # 17 checks total (after PR #120 added svcb_https + PR #122
    # added dns_rebinding). The deeper checks (dane / bimi /
    # dmarc_rua / spf_lookups / dkim_keys / open_resolver /
    # dangling_ns / svcb_https / dns_rebinding) all early-out
    # as inconclusive when the underlying records or NS list aren't
    # present, so they don't add findings on a blank target.
    assert len(out["checks_run"]) == 17
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



# ---------------------------------------------------------------------------
# DNSSEC algorithm strength + signature hygiene (PR #119)
# ---------------------------------------------------------------------------


def test_dnssec_weak_algorithm_rsasha1_emits_medium(monkeypatch) -> None:
    """Algorithm 5 (RSASHA1) — SHA-1 broken; deprecated → medium."""
    # DNSKEY rdata: <flags> <protocol> <algorithm> <key>
    _patch_dig(monkeypatch, {
        "example.com|DNSKEY": "257 3 5 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=",
        "example.com|RRSIG": "",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dnssec")
    assert out["results"][0]["signed"] is True
    assert "RSASHA1" in out["results"][0]["weak_algorithms"]
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    weak = [r for r in reports if "Weak DNSSEC algorithm" in r["title"]]
    assert len(weak) == 1
    assert weak[0]["severity"] == "medium"
    assert weak[0]["cwe"] == "CWE-326"


def test_dnssec_broken_algorithm_rsamd5_emits_high(monkeypatch) -> None:
    """Algorithm 1 (RSAMD5) — MUST NOT use → high."""
    _patch_dig(monkeypatch, {
        "example.com|DNSKEY": "257 3 1 AwEAAagFAKE",
        "example.com|RRSIG": "",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dnssec")
    assert "RSAMD5" in out["results"][0]["weak_algorithms"]
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    weak = [r for r in reports if "Weak DNSSEC algorithm" in r["title"]]
    assert len(weak) == 1
    assert weak[0]["severity"] == "high"


def test_dnssec_modern_algorithm_no_finding(monkeypatch) -> None:
    """Algorithm 13 (ECDSAP256SHA256) — modern → no weak finding."""
    _patch_dig(monkeypatch, {
        "example.com|DNSKEY": "257 3 13 AwEAAagFAKE",
        "example.com|RRSIG": "",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dnssec")
    assert out["results"][0]["weak_algorithms"] == []
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    weak = [r for r in reports if "Weak DNSSEC algorithm" in r["title"]]
    assert len(weak) == 0


def test_dnssec_ed25519_no_finding(monkeypatch) -> None:
    """Algorithm 15 (ED25519) — modern → no finding."""
    _patch_dig(monkeypatch, {
        "example.com|DNSKEY": "257 3 15 AwEAAagFAKE",
        "example.com|RRSIG": "",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dnssec")
    assert out["results"][0]["weak_algorithms"] == []


def test_dnssec_unrecognised_algorithm_emits_medium(monkeypatch) -> None:
    """Algorithm 99 (not in IANA registry) → medium (review needed)."""
    _patch_dig(monkeypatch, {
        "example.com|DNSKEY": "257 3 99 AwEAAagFAKE",
        "example.com|RRSIG": "",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dnssec")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    unrec = [r for r in reports if "Unrecognised DNSSEC algorithm" in r["title"]]
    assert len(unrec) == 1
    assert unrec[0]["severity"] == "medium"


def test_dnssec_rrsig_expiring_soon_emits_medium(monkeypatch) -> None:
    """RRSIG signature expiring within 7 days → medium."""
    from datetime import datetime, timedelta, timezone
    expiring = (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y%m%d%H%M%S")
    inception = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y%m%d%H%M%S")
    rrsig_line = f"A 13 2 3600 {expiring} {inception} 12345 example.com. AAAA"
    _patch_dig(monkeypatch, {
        "example.com|DNSKEY": "257 3 13 AwEAAagFAKE",  # modern algo
        "example.com|RRSIG": rrsig_line,
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dnssec")
    assert out["results"][0]["rrsig_expiring_soon"] is True
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    expiring_findings = [r for r in reports if "expiring soon" in r["title"]]
    assert len(expiring_findings) == 1
    assert expiring_findings[0]["severity"] == "medium"


def test_dnssec_rrsig_already_expired_emits_high(monkeypatch) -> None:
    """RRSIG signature already past expiration → high (resolvers SERVFAIL)."""
    from datetime import datetime, timedelta, timezone
    expired = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y%m%d%H%M%S")
    inception = (datetime.now(timezone.utc) - timedelta(days=20)).strftime("%Y%m%d%H%M%S")
    rrsig_line = f"A 13 2 3600 {expired} {inception} 12345 example.com. AAAA"
    _patch_dig(monkeypatch, {
        "example.com|DNSKEY": "257 3 13 AwEAAagFAKE",
        "example.com|RRSIG": rrsig_line,
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dnssec")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    expiring_findings = [r for r in reports if "expiring soon" in r["title"]]
    assert len(expiring_findings) == 1
    assert expiring_findings[0]["severity"] == "high"


def test_dnssec_rrsig_far_future_no_finding(monkeypatch) -> None:
    """RRSIG signature 30+ days out → no finding."""
    from datetime import datetime, timedelta, timezone
    far_out = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y%m%d%H%M%S")
    inception = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y%m%d%H%M%S")
    rrsig_line = f"A 13 2 3600 {far_out} {inception} 12345 example.com. AAAA"
    _patch_dig(monkeypatch, {
        "example.com|DNSKEY": "257 3 13 AwEAAagFAKE",
        "example.com|RRSIG": rrsig_line,
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dnssec")
    assert out["results"][0]["rrsig_expiring_soon"] is False


def test_dnssec_no_rrsig_no_expiry_check(monkeypatch) -> None:
    """No RRSIG records → no expiry analysis (signed_with_no_rrsig is itself a finding,
    but already pre-existing pre-#119 — we don't add new findings here)."""
    _patch_dig(monkeypatch, {
        "example.com|DNSKEY": "257 3 13 AwEAAagFAKE",
        "example.com|RRSIG": "",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dnssec")
    assert out["results"][0]["rrsig_expiring_soon"] is False


def test_dnssec_malformed_dnskey_does_not_crash(monkeypatch) -> None:
    """Garbage DNSKEY rdata → safe skip; no findings, no crash."""
    _patch_dig(monkeypatch, {
        "example.com|DNSKEY": "garbage line\nanother",
        "example.com|RRSIG": "",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dnssec")
    # No weak_algorithms because the malformed lines were skipped.
    assert out["results"][0]["weak_algorithms"] == []


# ---------------------------------------------------------------------------
# SVCB / HTTPS DNS records (RFC 9460) — PR #120
# ---------------------------------------------------------------------------


def test_svcb_https_no_records_no_finding(monkeypatch) -> None:
    _patch_dig(monkeypatch, {})
    out = dns_hygiene.dns_hygiene_check("example.com", checks="svcb_https")
    assert out["results"][0]["present"] is False
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 0


def test_svcb_https_record_emits_info(monkeypatch) -> None:
    """Cloudflare-style HTTPS record with ALPN h2 + h3."""
    _patch_dig(monkeypatch, {
        "example.com|HTTPS": '1 . alpn="h3,h2" ipv4hint=104.16.1.1',
        "example.com|SVCB": "",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="svcb_https")
    result = out["results"][0]
    assert result["present"] is True
    assert "h3" in result["alpn"]
    assert "h2" in result["alpn"]
    assert "104.16.1.1" in result["ipv4hints"]

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    info = [r for r in reports if r["severity"] == "info"]
    assert len(info) == 1
    assert "SVCB/HTTPS" in info[0]["title"]


def test_svcb_https_ech_configured(monkeypatch) -> None:
    """ECH (Encrypted ClientHello) is a modern privacy feature."""
    _patch_dig(monkeypatch, {
        "example.com|HTTPS": '1 . alpn="h3" ech="AEf+DQBDAAAAAAAA"',
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="svcb_https")
    assert out["results"][0]["ech_configured"] is True


def test_svcb_https_aliasform_record(monkeypatch) -> None:
    """AliasForm (priority 0) HTTPS record points at a target."""
    _patch_dig(monkeypatch, {
        "example.com|HTTPS": "0 svc.cdn.example.net.",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="svcb_https")
    result = out["results"][0]
    assert result["present"] is True
    assert "svc.cdn.example.net." in result["targets"]


def test_svcb_https_malformed_lines_skipped(monkeypatch) -> None:
    """Garbage lines mixed with valid records → only valid parsed."""
    _patch_dig(monkeypatch, {
        "example.com|HTTPS": (
            "garbage line not a record\n"
            "; comment line\n"
            '1 . alpn="h2"\n'
        ),
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="svcb_https")
    assert out["results"][0]["present"] is True
    assert out["results"][0]["alpn"] == ["h2"]


def test_svcb_https_both_record_types(monkeypatch) -> None:
    """Domain may have both SVCB and HTTPS records — count separately."""
    _patch_dig(monkeypatch, {
        "example.com|HTTPS": '1 . alpn="h3"',
        "example.com|SVCB": "1 svc.example.net. port=8443",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="svcb_https")
    result = out["results"][0]
    assert len(result["https_records"]) == 1
    assert len(result["svcb_records"]) == 1


# ---------------------------------------------------------------------------
# DNS rebinding feasibility (PR #122)
# ---------------------------------------------------------------------------


def test_dns_rebinding_short_ttl_emits_low(monkeypatch) -> None:
    """TTL < 60s → low CWE-345."""
    _patch_dig(monkeypatch, {
        "example.com|A": "example.com.\t30\tIN\tA\t1.2.3.4",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dns_rebinding")
    assert out["results"][0]["min_ttl"] == 30
    assert out["results"][0]["feasibility"] == "high"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    rebind = [r for r in reports if "rebinding" in r["title"].lower()]
    assert len(rebind) == 1
    assert rebind[0]["severity"] == "low"


def test_dns_rebinding_medium_ttl_emits_info(monkeypatch) -> None:
    """60 ≤ TTL < 300s → info."""
    _patch_dig(monkeypatch, {
        "example.com|A": "example.com.\t180\tIN\tA\t1.2.3.4",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dns_rebinding")
    assert out["results"][0]["min_ttl"] == 180
    assert out["results"][0]["feasibility"] == "medium"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    info = [r for r in reports if "rebinding" in r["title"].lower()]
    assert len(info) == 1
    assert info[0]["severity"] == "info"


def test_dns_rebinding_long_ttl_no_finding(monkeypatch) -> None:
    """TTL ≥ 300s → no finding (standard config)."""
    _patch_dig(monkeypatch, {
        "example.com|A": "example.com.\t3600\tIN\tA\t1.2.3.4",
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dns_rebinding")
    assert out["results"][0]["feasibility"] == "low"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len([r for r in reports if "rebinding" in r["title"].lower()]) == 0


def test_dns_rebinding_no_records(monkeypatch) -> None:
    """No A records → safe early-out, no finding."""
    _patch_dig(monkeypatch, {})
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dns_rebinding")
    assert out["results"][0]["ttls"] == []
    assert out["results"][0]["feasibility"] is None


def test_dns_rebinding_min_of_multiple_ttls(monkeypatch) -> None:
    """When multiple A records have different TTLs, the MIN is used."""
    _patch_dig(monkeypatch, {
        "example.com|A": (
            "example.com.\t3600\tIN\tA\t1.2.3.4\n"
            "example.com.\t30\tIN\tA\t5.6.7.8"
        ),
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dns_rebinding")
    assert out["results"][0]["min_ttl"] == 30


def test_dns_rebinding_malformed_lines_skipped(monkeypatch) -> None:
    """Garbage lines are skipped silently."""
    _patch_dig(monkeypatch, {
        "example.com|A": (
            "; comment line\n"
            "garbage\n"
            "example.com.\t60\tIN\tA\t1.2.3.4"
        ),
    })
    out = dns_hygiene.dns_hygiene_check("example.com", checks="dns_rebinding")
    assert out["results"][0]["min_ttl"] == 60
