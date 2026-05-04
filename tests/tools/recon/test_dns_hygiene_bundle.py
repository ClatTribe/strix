"""Tests for the DNS hygiene bundle (PR #110).

Covers four roadmap rows shipped together:

* §7.3 row "DKIM selector wordlist expansion"
  → expanded `_DKIM_SELECTORS` to ~40 entries covering vendor-specific
    naming (Microsoft 365, SendGrid, Mailgun, Postmark, AWS SES, Zoho,
    Apple iCloud, Salesforce, …).

* §7.3 row "Punycode / IDN homograph subdomains"
  → new `_IDN_HOMOGLYPHS` map (Cyrillic / Greek look-alikes) wired
    into the typosquat generator. Output is punycode-encoded so DNS
    queries don't require IDNA support upstream.

* §7.3 row "HTTP / HTTPS asymmetry per subdomain"
  → `_triage_subdomain` now probes BOTH schemes; emits a low CWE-319
    finding when only HTTP responds.

* §7.3 row "AAAA / IPv6 reachability"
  → new `_resolve_subdomain_v6` AAAA query; `ipv6` field surfaced on
    every triage result; IPv6-only hosts don't get classified as
    skip.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.recon import dns_hygiene as dh
from strix.tools.recon import domain_pipeline as dp
from strix.tools.recon import org_recon as orc


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
    tracer = Tracer("dns-bundle-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _findings() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


# ---------------------------------------------------------------------------
# DKIM selector wordlist expansion (#360)
# ---------------------------------------------------------------------------


def test_dkim_selector_list_expanded() -> None:
    """The wordlist now covers ~40 selectors including vendor-specific."""
    selectors = dh._DKIM_SELECTORS
    # Length sanity — original was 12; expanded should be at least 30.
    assert len(selectors) >= 30, (
        f"expected expanded DKIM wordlist (≥30 entries); got {len(selectors)}"
    )

    # Vendor-specific selectors are now present.
    expected_vendors = {
        # Microsoft / Exchange
        "selector1-azurecomm-prod-net",
        # SendGrid
        "smtpapi",
        # Mailchimp / Mandrill
        "mandrill",
        # Mailgun
        "mxvault",
        "mg",
        # Postmark
        "postmark",
        "pm",
        # Amazon SES
        "amazonses",
        "ses",
        # ProtonMail
        "protonmail",
        # Zoho
        "zoho",
        # Mimecast
        "mimecast",
        # Apple iCloud
        "sig1",
        # Salesforce
        "pf2014",
    }
    missing = expected_vendors - set(selectors)
    assert not missing, f"DKIM wordlist missing expected vendor selectors: {missing}"

    # Original canonical selectors retained.
    assert {"default", "google", "k1", "selector1", "selector2"} <= set(selectors)


def test_dkim_selector_list_no_duplicates() -> None:
    """Sanity: no duplicate entries."""
    selectors = dh._DKIM_SELECTORS
    assert len(selectors) == len(set(selectors))


# ---------------------------------------------------------------------------
# IDN homograph subdomains (#365)
# ---------------------------------------------------------------------------


def test_idn_homoglyph_map_present() -> None:
    """Cyrillic / Greek look-alikes are registered."""
    assert "a" in orc._IDN_HOMOGLYPHS  # CYRILLIC SMALL LETTER A
    assert "е".encode("utf-8") != "e".encode("utf-8")  # sanity: actually distinct
    # Cyrillic 'а' is in the map for ASCII 'a'.
    assert any(
        c.encode("utf-8") != b"a" for c in orc._IDN_HOMOGLYPHS["a"]
    )


def test_typosquat_includes_idn_punycode_candidates() -> None:
    """Generator emits at least one `xn--…` candidate when the label
    contains an IDN-eligible character."""
    candidates = orc._typosquat_candidates("example.com", max_candidates=80)

    punycode_hits = [c for c in candidates if c.startswith("xn--")]
    assert punycode_hits, (
        "expected ≥1 punycode IDN-homograph candidate in typosquat output"
    )
    # Each should still end with the original TLD.
    for p in punycode_hits:
        assert p.endswith(".com")


def test_typosquat_idn_candidates_decode_to_distinct_unicode() -> None:
    """Each punycode candidate decodes to a Unicode label visually
    similar to the original — sanity that the encoding round-trips."""
    candidates = orc._typosquat_candidates("example.com", max_candidates=80)
    punycode_hits = [c for c in candidates if c.startswith("xn--")]
    assert punycode_hits

    # Decode each to verify it's a real IDNA label.
    for p in punycode_hits:
        label = p.split(".", 1)[0]
        try:
            decoded = label.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            pytest.fail(f"punycode candidate {p!r} doesn't decode")
        assert decoded != "example", (
            f"decoded {decoded!r} should differ from original 'example'"
        )


def test_typosquat_short_label_no_crash() -> None:
    """Pathological short labels shouldn't crash the IDN path."""
    out = orc._typosquat_candidates("ab.com", max_candidates=20)
    # No assertion on content — just that it doesn't raise.
    assert isinstance(out, list)


# ---------------------------------------------------------------------------
# HTTP / HTTPS asymmetry (#362)
# ---------------------------------------------------------------------------


def test_triage_http_only_emits_low_finding(monkeypatch) -> None:
    """HTTPS probe returns 0 (no response), HTTP returns 200 → low CWE-319."""
    monkeypatch.setattr(dp, "dig", lambda *a, **kw: "1.2.3.4")

    def fake_head(url, **_kw):
        if url.startswith("https://"):
            return 0, {}
        return 200, {"content-type": "text/html"}

    monkeypatch.setattr(dp, "http_head", fake_head)

    result = dp._triage_subdomain("legacy.example.com")

    assert result["live"] is True
    assert result["scheme"] == "http"
    assert result["scheme_asymmetry"] == "http_only"

    findings = _findings()
    cleartext = [f for f in findings if f["category"] == "cleartext_transmission"]
    assert len(cleartext) == 1
    assert cleartext[0]["severity"] == "low"
    assert cleartext[0]["cwe"] == "CWE-319"
    assert "legacy.example.com" in cleartext[0]["title"]


def test_triage_both_schemes_no_asymmetry_finding(monkeypatch) -> None:
    """When both HTTPS and HTTP respond, no finding (HTTP→HTTPS redirect is normal)."""
    monkeypatch.setattr(dp, "dig", lambda *a, **kw: "1.2.3.4")
    monkeypatch.setattr(
        dp, "http_head",
        lambda url, **_: (200, {"content-type": "text/html"}),
    )

    result = dp._triage_subdomain("api.example.com")

    assert result["scheme"] == "https"
    assert result["scheme_asymmetry"] == "both"
    findings = _findings()
    assert not any(f["category"] == "cleartext_transmission" for f in findings)


def test_triage_https_only_no_asymmetry_finding(monkeypatch) -> None:
    """HTTPS-only is the well-configured case — no finding."""
    monkeypatch.setattr(dp, "dig", lambda *a, **kw: "1.2.3.4")

    def fake_head(url, **_kw):
        if url.startswith("https://"):
            return 200, {"content-type": "text/html"}
        return 0, {}

    monkeypatch.setattr(dp, "http_head", fake_head)

    result = dp._triage_subdomain("api.example.com")

    assert result["scheme"] == "https"
    assert result["scheme_asymmetry"] == "https_only"
    findings = _findings()
    assert not any(f["category"] == "cleartext_transmission" for f in findings)


# ---------------------------------------------------------------------------
# IPv6 / AAAA reachability (#359)
# ---------------------------------------------------------------------------


def test_resolve_subdomain_v6_extracts_aaaa(monkeypatch) -> None:
    """`_resolve_subdomain_v6` returns the first AAAA record."""
    def fake_dig(host: str, rrtype: str) -> str:
        if rrtype == "AAAA":
            return "2606:4700:4700::1111\n2606:4700:4700::1001"
        return ""

    monkeypatch.setattr(dp, "dig", fake_dig)
    assert dp._resolve_subdomain_v6("ipv6.example.com") == "2606:4700:4700::1111"


def test_resolve_subdomain_v6_returns_none_when_absent(monkeypatch) -> None:
    monkeypatch.setattr(dp, "dig", lambda *a, **kw: "")
    assert dp._resolve_subdomain_v6("nope.example.com") is None


def test_resolve_subdomain_v6_rejects_garbage(monkeypatch) -> None:
    """Output that's not v6-shaped → None (not a crash)."""
    monkeypatch.setattr(dp, "dig", lambda *a, **kw: "garbage line\n;; some comment")
    assert dp._resolve_subdomain_v6("x.example.com") is None


def test_triage_surfaces_aaaa_when_dual_stack(monkeypatch) -> None:
    """When both A and AAAA resolve, both are surfaced on the result."""
    def fake_dig(host: str, rrtype: str) -> str:
        if rrtype == "A":
            return "1.2.3.4"
        if rrtype == "AAAA":
            return "2606:4700::1"
        return ""

    monkeypatch.setattr(dp, "dig", fake_dig)
    monkeypatch.setattr(
        dp, "http_head",
        lambda url, **_: (200, {"content-type": "text/html"}),
    )

    result = dp._triage_subdomain("dual.example.com")

    assert result["ip"] == "1.2.3.4"
    assert result["ipv6"] == "2606:4700::1"
    assert result["live"] is True


def test_triage_ipv6_only_marked_live_not_skip(monkeypatch) -> None:
    """IPv6-only host (no A record) gets `triage=shallow` not `skip`,
    and `scheme_asymmetry=ipv6_only` to flag it for the agent."""
    def fake_dig(host: str, rrtype: str) -> str:
        if rrtype == "A":
            return ""
        if rrtype == "AAAA":
            return "2606:4700::1"
        return ""

    monkeypatch.setattr(dp, "dig", fake_dig)
    # http_head won't be called since we skip on no A; just provide a stub.
    monkeypatch.setattr(dp, "http_head", lambda url, **_: (0, {}))

    result = dp._triage_subdomain("v6only.example.com")

    assert result["ip"] is None
    assert result["ipv6"] == "2606:4700::1"
    assert result["live"] is True
    assert result["triage"] == "shallow"
    assert result["scheme_asymmetry"] == "ipv6_only"


def test_triage_no_dns_at_all_returns_skip(monkeypatch) -> None:
    """Neither A nor AAAA → skip with the updated 'no A or AAAA' evidence."""
    monkeypatch.setattr(dp, "dig", lambda *a, **kw: "")
    monkeypatch.setattr(dp, "http_head", lambda url, **_: (0, {}))

    result = dp._triage_subdomain("nope.example.com")

    assert result["ip"] is None
    assert result["ipv6"] is None
    assert result["live"] is False
    assert result["triage"] == "skip"
    assert "no A or AAAA" in result["evidence"]
