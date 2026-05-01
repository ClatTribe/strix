"""Tests for org_fingerprint."""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
import strix.tools.recon.org_recon as ofp


_WHOIS_FIXTURE = """\
Domain Name: EXAMPLE.COM
Registrar: GoDaddy.com, LLC
Creation Date: 2010-04-15T18:42:53Z
Registry Expiry Date: 2026-04-15T18:42:53Z
Registrant Organization: Domains By Proxy, LLC
Registrant Country: US
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: unsigned
"""


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
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("ofp-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


# ---------------------------------------------------------------------------
# WHOIS parser
# ---------------------------------------------------------------------------


def test_parse_whois_extracts_canonical_fields() -> None:
    parsed = ofp._parse_whois(_WHOIS_FIXTURE)
    assert parsed["registrar"] == "GoDaddy.com, LLC"
    assert parsed["creation_date"] == "2010-04-15T18:42:53Z"
    assert parsed["expiry_date"] == "2026-04-15T18:42:53Z"
    assert parsed["name_servers"] == ["ns1.example.com", "ns2.example.com"]
    assert parsed["dnssec"] == "unsigned"
    assert parsed["privacy_protected"] is True


def test_parse_whois_no_privacy_marker_doesnt_set_flag() -> None:
    text = "Registrant Organization: Acme Corp\nRegistrant Country: US"
    parsed = ofp._parse_whois(text)
    assert "privacy_protected" not in parsed


def test_parse_whois_empty_returns_empty() -> None:
    assert ofp._parse_whois("") == {}


# ---------------------------------------------------------------------------
# Typosquat candidate generation
# ---------------------------------------------------------------------------


def test_typosquat_candidates_are_bounded_and_distinct() -> None:
    candidates = ofp._typosquat_candidates("example.com", max_candidates=20)
    assert len(candidates) <= 20
    assert len(set(candidates)) == len(candidates)
    assert "example.com" not in candidates  # don't include self
    # Should include common transformations.
    # "example" → "exarnple" (m→rn homoglyph) and "example.{net,org,io,...}" (alt TLDs).
    has_homoglyph = any("exarnple" in c or "examp1e" in c or "exampie" in c for c in candidates)
    has_alt_tld = any(
        c.startswith("example.") and c != "example.com" for c in candidates
    )
    assert has_homoglyph
    assert has_alt_tld


def test_typosquat_candidates_short_label() -> None:
    candidates = ofp._typosquat_candidates("ab.com")
    # Even short labels should produce a few.
    assert len(candidates) > 0


def test_typosquat_candidates_invalid_input_returns_empty() -> None:
    assert ofp._typosquat_candidates("not-a-domain") == []


# ---------------------------------------------------------------------------
# Tool integration — mocked subprocess + dig + http
# ---------------------------------------------------------------------------


def _patch_all(monkeypatch, *, whois_text: str = "", dig_responses: dict[str, str] | None = None,
               head_status: int = 404) -> None:
    monkeypatch.setattr(ofp, "_run_whois", lambda d: whois_text)
    responses = dict(dig_responses or {})

    def fake_dig(query: str, record_type: str = "A", **_: Any) -> str:
        return responses.get(f"{query}|{record_type}", responses.get(query, ""))

    monkeypatch.setattr(ofp, "dig", fake_dig)
    monkeypatch.setattr(ofp, "http_head", lambda url, **_: (head_status, {}))


def test_invalid_domain_rejected() -> None:
    out = ofp.org_fingerprint("not a domain")
    assert out["success"] is False


def test_full_run_with_no_typosquats_resolving(monkeypatch) -> None:
    _patch_all(
        monkeypatch,
        whois_text=_WHOIS_FIXTURE,
        dig_responses={
            "example.com|A": "93.184.216.34",
            # Cymru-formatted ASN response
            "34.216.184.93.origin.asn.cymru.com|TXT": (
                '"15169 | 93.184.216.0/24 | US | arin | 2008-06-02"'
            ),
        },
        head_status=404,  # no GitHub orgs found, no live typosquat sites
    )
    out = ofp.org_fingerprint("example.com")
    assert out["success"] is True
    assert out["whois"]["registrar"] == "GoDaddy.com, LLC"
    assert out["asn"]["asn"] == "AS15169"
    assert out["typosquats_resolved"] == []
    # No findings emitted because no typosquats resolved.
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


def test_resolved_typosquat_emits_finding(monkeypatch) -> None:
    # Make ONE specific typosquat candidate resolve.
    _patch_all(
        monkeypatch,
        whois_text="",
        dig_responses={
            "example.com|A": "1.2.3.4",
            "example.net|A": "5.6.7.8",  # alt-TLD candidate resolves
        },
        head_status=200,
    )
    out = ofp.org_fingerprint("example.com")
    assert out["success"] is True
    assert "example.net" in out["typosquats_resolved"]
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    typosquat_findings = [
        r for r in reports if "typosquat" in r["title"].lower() and "example.net" in r["title"]
    ]
    assert len(typosquat_findings) == 1
    f = typosquat_findings[0]
    assert f["severity"] == "low"  # had live web (status 200)
    assert f["category"] == "info_disclosure"


def test_skip_typosquats_skips_dns_sweep(monkeypatch) -> None:
    dig_calls: list[str] = []

    def fake_dig(query: str, record_type: str = "A", **_: Any) -> str:
        dig_calls.append(f"{query}|{record_type}")
        return "1.2.3.4" if query == "example.com" else ""

    monkeypatch.setattr(ofp, "_run_whois", lambda d: "")
    monkeypatch.setattr(ofp, "dig", fake_dig)
    monkeypatch.setattr(ofp, "http_head", lambda url, **_: (404, {}))

    out = ofp.org_fingerprint("example.com", skip_typosquats=True)
    assert out["success"] is True
    assert out["typosquats_probed"] == 0
    # Only the apex A lookup + the Cymru ASN query should have happened —
    # NOT 25 typosquat A lookups.
    assert len(dig_calls) <= 5  # apex A + ASN TXT and a couple of WAF-style probes max


def test_check_events_emitted(monkeypatch) -> None:
    _patch_all(
        monkeypatch,
        whois_text=_WHOIS_FIXTURE,
        dig_responses={"example.com|A": "1.2.3.4"},
        head_status=404,
    )
    ofp.org_fingerprint("example.com", skip_typosquats=True)
    summary = tracer_module.get_global_tracer().get_check_summary()
    # Three checks emitted when typosquats skipped: org_fingerprint, asn_ownership,
    # github_org_presence. Plus typosquat would be the 4th when not skipped.
    assert summary["total"] == 3
    assert "org_fingerprint" in summary["by_category"]
    assert "asn_ownership" in summary["by_category"]
    assert "github_org_presence" in summary["by_category"]


def test_github_candidate_names_strip_dashes() -> None:
    names = ofp._candidate_org_names("acme-corp.com")
    assert "acme-corp" in names
    assert "acmecorp" in names
    # Bounded to <= 3.
    assert len(names) <= 3


def test_asn_lookup_handles_no_response(monkeypatch) -> None:
    monkeypatch.setattr(ofp, "dig", lambda *a, **k: "")
    out = ofp._asn_lookup("1.2.3.4")
    assert out["lookup_status"] == "no_response"
