"""Tests for masterroadmap §1 P0 — `scan_saml_xsw` (SAML XML Signature
Wrapping + SP configuration audit).

Coverage:
  * Defensive input handling
  * Phase 1: SP metadata discovery + config audit (WantAssertionsSigned,
    weak signing algs)
  * Phase 2: active ACS probes (unsigned, mangled signature)
  * Phase 3: XSW1-8 variant generation + classification
  * Auth header auto-injection from SecurityContext
  * decision_log + SecurityContext recording
  * Registry / catalog wiring
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_saml_xsw import (
    _NS_SAML,
    _NS_SAMLP,
    _build_unsigned_response,
    _build_xsw_variant,
    _classify_acs_response,
    _decode_donor,
    _parse_sp_metadata,
    scan_saml_xsw,
)


# ---------------------------------------------------------------------------
# Fixtures (mirror test_scan_oauth)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path) -> None:
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-saml-xsw"))


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


def _patch_proxy(monkeypatch, response_for_url):
    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=response_for_url)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: fake,
    )
    return fake


def _sp_metadata_xml(
    *,
    want_assertions_signed: str | None = "true",
    weak_alg: bool = False,
    acs_url: str = "https://sp.example.com/saml/acs",
) -> str:
    sig_method = (
        '<ds:SignatureMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
        'Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
        if weak_alg else ""
    )
    digest_method = (
        '<ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
        'Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
        if weak_alg else ""
    )
    sp_attrs = ""
    if want_assertions_signed is not None:
        sp_attrs = f' WantAssertionsSigned="{want_assertions_signed}"'
    return (
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        'entityID="https://sp.example.com">'
        f'<md:SPSSODescriptor protocolSupportEnumeration='
        f'"urn:oasis:names:tc:SAML:2.0:protocol"{sp_attrs}>'
        f'{sig_method}{digest_method}'
        f'<md:AssertionConsumerService '
        f'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{acs_url}" index="0"/>'
        '</md:SPSSODescriptor>'
        '</md:EntityDescriptor>'
    )


def _signed_donor_response(
    *,
    response_id: str = "_resp1",
    assertion_id: str = "_assert1",
    subject: str = "user@example.com",
) -> str:
    """A donor SAML Response with a signature block on the inner
    Assertion. The signature bytes are placeholders — we never verify
    them; the test asks whether the SP processed the right element."""
    return (
        f'<samlp:Response xmlns:samlp="{_NS_SAMLP}" '
        f'xmlns:saml="{_NS_SAML}" '
        f'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
        f'ID="{response_id}" Version="2.0" '
        f'IssueInstant="2025-01-01T00:00:00Z" '
        f'Destination="https://sp.example.com/saml/acs">'
        f'<saml:Issuer>https://idp.example.com</saml:Issuer>'
        f'<samlp:Status>'
        f'<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
        f'</samlp:Status>'
        f'<saml:Assertion ID="{assertion_id}" Version="2.0" '
        f'IssueInstant="2025-01-01T00:00:00Z">'
        f'<saml:Issuer>https://idp.example.com</saml:Issuer>'
        f'<ds:Signature>'
        f'<ds:SignedInfo>'
        f'<ds:Reference URI="#{assertion_id}">'
        f'<ds:DigestValue>placeholder-digest</ds:DigestValue>'
        f'</ds:Reference>'
        f'</ds:SignedInfo>'
        f'<ds:SignatureValue>placeholder-signature-value</ds:SignatureValue>'
        f'</ds:Signature>'
        f'<saml:Subject>'
        f'<saml:NameID>{subject}</saml:NameID>'
        f'</saml:Subject>'
        f'<saml:AttributeStatement>'
        f'<saml:Attribute Name="role">'
        f'<saml:AttributeValue>user</saml:AttributeValue>'
        f'</saml:Attribute>'
        f'</saml:AttributeStatement>'
        f'</saml:Assertion>'
        f'</samlp:Response>'
    )


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_saml_xsw(url="")
    assert out["status"] == "error"


def test_invalid_url_returns_error() -> None:
    out = scan_saml_xsw(url="not-a-url")
    assert out["status"] == "error"


def test_no_metadata_no_acs_returns_partial(monkeypatch) -> None:
    """No metadata found, no operator-supplied ACS → partial, Phase 2/3 skipped."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 404, "body": "not found", "headers": {},
    })
    out = scan_saml_xsw(url="https://sp.example.com/")
    assert out["status"] == "partial"
    assert out["tool_metadata"]["acs_url_probed"] is None


# ---------------------------------------------------------------------------
# Phase 1 — config audit
# ---------------------------------------------------------------------------


def test_want_assertions_signed_false_emits_high(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if any(p in url for p in ("/saml2/metadata", "/saml/metadata", "/Shibboleth")):
            return {
                "status_code": 200,
                "body": _sp_metadata_xml(want_assertions_signed="false"),
                "headers": {},
            }
        return {"status_code": 400, "body": "rejected", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_saml_xsw(url="https://sp.example.com/")
    titles = [f["title"] for f in out["findings"]]
    assert any("WantAssertionsSigned" in t for t in titles)


def test_want_assertions_signed_true_no_finding(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "metadata" in url.lower() or "Shibboleth" in url:
            return {
                "status_code": 200,
                "body": _sp_metadata_xml(want_assertions_signed="true"),
                "headers": {},
            }
        return {"status_code": 400, "body": "no", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_saml_xsw(url="https://sp.example.com/")
    titles = [f["title"] for f in out["findings"]]
    assert not any("WantAssertionsSigned" in t for t in titles)


def test_weak_signature_alg_emits_medium(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "metadata" in url.lower() or "Shibboleth" in url:
            return {
                "status_code": 200,
                "body": _sp_metadata_xml(weak_alg=True),
                "headers": {},
            }
        return {"status_code": 400, "body": "rejected", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_saml_xsw(url="https://sp.example.com/")
    titles = [f["title"] for f in out["findings"]]
    assert any("weak signature" in t.lower() or "digest" in t.lower() for t in titles)


def test_metadata_acs_url_used_for_active_probe(monkeypatch) -> None:
    """Discovered ACS endpoint gets POSTed to in Phase 2."""
    posted_urls: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        if method == "GET" and ("metadata" in url.lower() or "Shibboleth" in url):
            return {
                "status_code": 200,
                "body": _sp_metadata_xml(),
                "headers": {},
            }
        if method == "POST":
            posted_urls.append(url)
            return {"status_code": 400, "body": "rejected", "headers": {}}
        return {"status_code": 404, "body": "", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    scan_saml_xsw(url="https://sp.example.com/")
    assert any("https://sp.example.com/saml/acs" in u for u in posted_urls)


# ---------------------------------------------------------------------------
# Phase 2 — active ACS probes
# ---------------------------------------------------------------------------


def test_unsigned_response_accepted_emits_critical(monkeypatch) -> None:
    """ACS 302s to in-app path when given an unsigned Response → critical."""

    def fake_resp(method, url, headers, body, timeout):
        if method == "POST" and url.endswith("/acs"):
            return {
                "status_code": 302,
                "body": "",
                "headers": {"Location": "https://sp.example.com/dashboard"},
            }
        return {"status_code": 404, "body": "", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_saml_xsw(
        url="https://sp.example.com/",
        acs_url="https://sp.example.com/acs",
    )
    titles = [f["title"] for f in out["findings"]]
    severities = [f["severity"] for f in out["findings"]]
    assert any("unsigned Response" in t for t in titles)
    assert "critical" in severities


def test_unsigned_response_rejected_no_finding(monkeypatch) -> None:
    """ACS returns 401 with 'signature' in body → no finding."""

    def fake_resp(method, url, headers, body, timeout):
        if method == "POST":
            return {
                "status_code": 401,
                "body": "Invalid SAML signature",
                "headers": {},
            }
        return {"status_code": 404, "body": "", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_saml_xsw(
        url="https://sp.example.com/",
        acs_url="https://sp.example.com/acs",
    )
    titles = [f["title"] for f in out["findings"]]
    assert not any("unsigned Response" in t for t in titles)


def test_unsigned_response_session_cookie_emits_critical(monkeypatch) -> None:
    """ACS returns 200 with a session-shaped Set-Cookie → critical."""

    def fake_resp(method, url, headers, body, timeout):
        if method == "POST":
            return {
                "status_code": 200,
                "body": "<html>Welcome</html>",
                "headers": {
                    "Set-Cookie": "JSESSIONID=abc123; HttpOnly; Path=/",
                },
            }
        return {"status_code": 404, "body": "", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_saml_xsw(
        url="https://sp.example.com/",
        acs_url="https://sp.example.com/acs",
    )
    severities = [f["severity"] for f in out["findings"]]
    assert "critical" in severities


def test_mangled_signature_accepted_emits_critical(monkeypatch) -> None:
    """First POST (unsigned) is rejected; second POST (mangled-sig) accepted."""
    post_count = {"n": 0}

    def fake_resp(method, url, headers, body, timeout):
        if method == "POST":
            post_count["n"] += 1
            if post_count["n"] == 1:
                # Unsigned probe → server rejects.
                return {
                    "status_code": 400,
                    "body": "Missing signature",
                    "headers": {},
                }
            # Mangled signature → server accepts.
            return {
                "status_code": 302,
                "body": "",
                "headers": {"Location": "https://sp.example.com/dashboard"},
            }
        return {"status_code": 404, "body": "", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_saml_xsw(
        url="https://sp.example.com/",
        acs_url="https://sp.example.com/acs",
    )
    titles = [f["title"] for f in out["findings"]]
    assert any("mangled-signature" in t.lower() or "invalid signature" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# Phase 3 — XSW variant probes
# ---------------------------------------------------------------------------


def test_donor_assertion_runs_8_xsw_probes(monkeypatch) -> None:
    """When donor is supplied, 8 distinct XSW POSTs hit the ACS."""
    post_bodies: list[str] = []

    def fake_resp(method, url, headers, body, timeout):
        if method == "POST":
            post_bodies.append(body)
            return {"status_code": 400, "body": "Signature mismatch", "headers": {}}
        return {"status_code": 404, "body": "", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_saml_xsw(
        url="https://sp.example.com/",
        acs_url="https://sp.example.com/acs",
        donor_assertion=_signed_donor_response(),
    )
    # 2 (unsigned + mangled) + 8 (XSW1-8) = 10 POSTs.
    assert len(post_bodies) == 10, f"expected 10 POSTs, got {len(post_bodies)}"
    assert out["status"] == "ok" or out["status"] == "partial"


def test_xsw_variant_accepted_emits_critical(monkeypatch) -> None:
    """When the ACS accepts XSW3 (say), we emit one critical finding."""
    post_count = {"n": 0}

    def fake_resp(method, url, headers, body, timeout):
        if method == "POST":
            post_count["n"] += 1
            # Posts 1 and 2 are unsigned + mangled. Posts 3-10 are
            # XSW1-8. Accept the 5th post (XSW3 — third XSW variant).
            if post_count["n"] == 5:
                return {
                    "status_code": 302,
                    "body": "",
                    "headers": {"Location": "https://sp.example.com/inbox"},
                }
            return {"status_code": 401, "body": "Invalid signature", "headers": {}}
        return {"status_code": 404, "body": "", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_saml_xsw(
        url="https://sp.example.com/",
        acs_url="https://sp.example.com/acs",
        donor_assertion=_signed_donor_response(),
    )
    titles = [f["title"] for f in out["findings"]]
    severities = [f["severity"] for f in out["findings"]]
    assert any("XSW" in t and "accepted" in t for t in titles)
    assert "critical" in severities
    accepted = out["tool_metadata"]["accepted_xsw_variants"]
    assert isinstance(accepted, list) and accepted, accepted


def test_donor_unusable_skips_phase3(monkeypatch) -> None:
    """Garbage donor → Phase 3 skipped, evidence records the skip."""

    def fake_resp(method, url, headers, body, timeout):
        if method == "POST":
            return {"status_code": 400, "body": "rejected", "headers": {}}
        return {"status_code": 404, "body": "", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_saml_xsw(
        url="https://sp.example.com/",
        acs_url="https://sp.example.com/acs",
        donor_assertion="not-actually-xml-or-base64-of-xml",
    )
    ev_text = " ".join(out["evidence"])
    assert "donor_assertion_unusable" in ev_text


# ---------------------------------------------------------------------------
# Auth header auto-injection
# ---------------------------------------------------------------------------


def test_auth_bearer_auto_forwarded(monkeypatch) -> None:
    captured: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured.append(dict(headers or {}))
        return {"status_code": 404, "body": "", "headers": {}}

    _patch_proxy(monkeypatch, fake_resp)
    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="tok123")

    scan_saml_xsw(url="https://sp.example.com/")
    assert any(
        h.get("Authorization") == "Bearer tok123"
        for h in captured
    )


# ---------------------------------------------------------------------------
# Decision log
# ---------------------------------------------------------------------------


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions,
        reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda method, url, headers, body, timeout: (
        {"status_code": 200, "body": _sp_metadata_xml(), "headers": {}}
        if method == "GET" and "metadata" in url.lower()
        else {"status_code": 400, "body": "rejected", "headers": {}}
    ))
    scan_saml_xsw(url="https://sp.example.com/")
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_saml_xsw"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_saml_xsw_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_saml_xsw")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "saml-xsw-specialist"


def test_scan_saml_xsw_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_saml_xsw" in catalog


def test_scan_saml_xsw_in_lead_api_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["api"])
    assert "scan_saml_xsw" in catalog


# ---------------------------------------------------------------------------
# Unit tests for the XSW helper functions
# ---------------------------------------------------------------------------


def test_build_unsigned_response_has_no_signature() -> None:
    """The unsigned-response builder produces XML with no Signature."""
    xml_text = _build_unsigned_response(acs_url="https://sp.example.com/acs")
    assert "<ds:Signature" not in xml_text and "<Signature" not in xml_text
    assert "Assertion" in xml_text
    assert "https://sp.example.com/acs" in xml_text


def test_build_xsw_variant_returns_distinct_output() -> None:
    """Each variant produces a structurally different string."""
    donor = _signed_donor_response()
    variants = {}
    for v in range(1, 9):
        out = _build_xsw_variant(donor_xml=donor, variant=v)
        assert out is not None, f"variant {v} returned None"
        variants[v] = out
    # All 8 should be distinct (each represents a different mutation).
    assert len(set(variants.values())) == 8, "XSW variants should be distinct"


def test_build_xsw_variant_preserves_signature_value() -> None:
    """The donor's SignatureValue must appear verbatim in every variant.
    XSW's whole point is preserving the signature bytes."""
    donor = _signed_donor_response()
    sig_marker = "placeholder-signature-value"
    for v in range(1, 9):
        out = _build_xsw_variant(donor_xml=donor, variant=v)
        assert out is not None
        assert sig_marker in out, f"variant {v} dropped the signature"


def test_build_xsw_variant_rejects_non_response_donor() -> None:
    """A donor that isn't a samlp:Response returns None — the caller
    surfaces this as `donor_assertion_unusable`."""
    bad = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>'
    assert _build_xsw_variant(donor_xml=bad, variant=1) is None


def test_build_xsw_variant_out_of_range_returns_none() -> None:
    donor = _signed_donor_response()
    assert _build_xsw_variant(donor_xml=donor, variant=0) is None
    assert _build_xsw_variant(donor_xml=donor, variant=9) is None


def test_decode_donor_accepts_raw_xml() -> None:
    xml_text = "<samlp:Response xmlns:samlp='x'/>"
    assert _decode_donor(xml_text).startswith("<samlp:Response")


def test_decode_donor_accepts_base64() -> None:
    donor = _signed_donor_response()
    encoded = base64.b64encode(donor.encode("utf-8")).decode("ascii")
    decoded = _decode_donor(encoded)
    assert decoded.startswith("<samlp:Response")
    assert "placeholder-signature-value" in decoded


def test_parse_sp_metadata_extracts_want_assertions_signed() -> None:
    md = _sp_metadata_xml(want_assertions_signed="false")
    info = _parse_sp_metadata(md)
    assert info["want_assertions_signed"] is False
    assert info["acs_endpoints"] == ["https://sp.example.com/saml/acs"]


def test_parse_sp_metadata_extracts_weak_alg() -> None:
    md = _sp_metadata_xml(weak_alg=True)
    info = _parse_sp_metadata(md)
    assert any("sha1" in a for a in info["signing_algs"])
    assert any("sha1" in a for a in info["digest_algs"])


def test_classify_acs_response_rejection_signal() -> None:
    verdict, _reason = _classify_acs_response(
        resp={"status_code": 401, "body": "Invalid signature", "headers": {}},
        acs_url="https://sp.example.com/acs",
    )
    assert verdict == "rejected"


def test_classify_acs_response_session_cookie_signal() -> None:
    verdict, _reason = _classify_acs_response(
        resp={
            "status_code": 200, "body": "ok",
            "headers": {"Set-Cookie": "auth_session=xyz; HttpOnly"},
        },
        acs_url="https://sp.example.com/acs",
    )
    assert verdict == "accepted"


def test_classify_acs_response_302_to_login_not_accepted() -> None:
    """302 back to /login is NOT a successful auth — must not flag."""
    verdict, _reason = _classify_acs_response(
        resp={
            "status_code": 302, "body": "",
            "headers": {"Location": "https://sp.example.com/login?error=1"},
        },
        acs_url="https://sp.example.com/acs",
    )
    assert verdict != "accepted"


def test_classify_acs_response_302_to_dashboard_accepted() -> None:
    verdict, _reason = _classify_acs_response(
        resp={
            "status_code": 302, "body": "",
            "headers": {"Location": "https://sp.example.com/dashboard"},
        },
        acs_url="https://sp.example.com/acs",
    )
    assert verdict == "accepted"
