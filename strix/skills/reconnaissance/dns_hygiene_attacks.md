---
name: dns-hygiene-attacks
description: SPF / DMARC / DKIM / MTA-STS / DNSSEC / CAA / BIMI misconfigurations → email spoofing, takeover, MITM
triggers: [spf, dmarc, dkim, mta-sts, dnssec, caa, bimi, email spoofing, dns posture]
---

# DNS Hygiene Attacks

DNS records carry the security contract for email authentication, certificate issuance constraints, and (with DNSSEC) zone-integrity. Weak or missing records on any of these enable email spoofing, fraudulent certificate issuance, subdomain hijack, or DNS poisoning. Strix's `dns_hygiene_check` (PRs #8, #19) audits all of these; this skill explains *how each becomes exploitable*.

## Surface Inventory

| Record | Purpose | Common bugs |
|---|---|---|
| **SPF** (TXT `v=spf1`) | Authorise sending hosts for the domain | Missing, `+all`, `?all`, too many DNS lookups (>10), bypassable include chain |
| **DMARC** (`_dmarc.x.com` TXT) | Policy on SPF/DKIM failures + reporting | Missing, `p=none`, `pct<100`, no `rua`, weak alignment |
| **DKIM** (`<selector>._domainkey.x.com` TXT) | Cryptographic email signing | Missing, weak key (<2048 bit), unrotated, NXDOMAIN selector |
| **MTA-STS** (`_mta-sts.x.com` + HTTPS policy file) | Force TLS on inbound mail | Missing, `mode: testing` permanent, policy expired |
| **DANE TLSA** | Bind cert to DNS via DNSSEC | Rare; presence implies TLS-pinning ambition |
| **DNSSEC** (DS at parent + DNSKEY at zone) | Cryptographic chain-of-trust on DNS responses | Missing (most common), broken chain, key rollover stuck |
| **CAA** (CAA records) | Restrict which CAs may issue certs for the domain | Missing → any CA can issue; broad allow-list |
| **BIMI** (`_bimi.x.com` TXT + VMC) | Verified brand mark indicator in inbox | Mismatch with DMARC enforcement |

## Email Spoofing Attack Tree

```
1. SPF: weak / missing
   ├─ +all              → any source can claim From: x.com
   ├─ ~all + relaxed    → soft-fail; many providers accept
   ├─ >10 DNS lookups   → PermError; SPF treated as missing
   └─ include chain     → if any included domain is takeover-able, attacker
                          adds their IP to the SPF chain transitively

2. DMARC: weak / missing
   ├─ Missing           → no enforcement; recipient inboxes accept failures
   ├─ p=none            → reports only; spoofing still delivered
   ├─ pct<100           → partial enforcement; sampling-based bypass
   └─ alignment=relaxed → subdomain spoofs (mailbox.x.com vs x.com) pass

3. DKIM: weak / missing
   ├─ Missing selector  → can't even attempt signing
   ├─ Public-key <2048  → cryptographically feasible to forge
   └─ Unrotated         → if private key leaked once, forever-spoofable
```

Combined effect: **missing SPF + missing DMARC = inboxes accept any mail with From: ceo@x.com**. The classic CEO-fraud / BEC entry point.

## Detection Channels

### SPF audit
```bash
DOMAIN='<TARGET>'

# Pull the SPF record
dig +short TXT "$DOMAIN" | grep -i 'v=spf1'

# Count DNS lookups (must be ≤10)
spfquery -file "$DOMAIN"  # tool from spf-tools-perl
```

Red flags:
- No `v=spf1` record at all → no auth claim
- Ends with `+all` → any source authorised
- Ends with `?all` → neutral; recipient decides
- More than 10 `include:` / `a:` / `mx:` / `exists:` mechanisms → PermError

### DMARC audit
```bash
dig +short TXT "_dmarc.${DOMAIN}" | grep -i 'v=DMARC1'

# Parse policy
DMARC=$(dig +short TXT "_dmarc.${DOMAIN}")
echo "$DMARC" | grep -oE 'p=[^;]+'        # policy
echo "$DMARC" | grep -oE 'sp=[^;]+'       # subdomain policy
echo "$DMARC" | grep -oE 'pct=[^;]+'      # percentage
echo "$DMARC" | grep -oE 'rua=[^;]+'      # reporting URI
echo "$DMARC" | grep -oE 'aspf=[^;]+'     # SPF alignment
echo "$DMARC" | grep -oE 'adkim=[^;]+'    # DKIM alignment
```

Red flags:
- No record → no enforcement; **high severity**
- `p=none` → reports only; spoofing still delivered
- `pct=` < 100 → partial enforcement
- `sp=none` without `sp=` defaulting to `p=` → subdomain spoofing wins

### DKIM audit
```bash
# Common selectors (try each)
for selector in default selector1 selector2 google k1 mandrill mailchimp ses sendgrid; do
  RECORD=$(dig +short TXT "${selector}._domainkey.${DOMAIN}")
  if [[ -n "$RECORD" ]]; then
    echo "Selector '$selector': $RECORD"
    # Extract key size
    PUBKEY=$(echo "$RECORD" | grep -oE 'p=[A-Za-z0-9+/=]+' | cut -d= -f2-)
    KEYSIZE=$(echo "$PUBKEY" | base64 -d 2>/dev/null | openssl rsa -pubin -inform DER -text -noout 2>/dev/null | grep 'Public-Key' | grep -oE '[0-9]+')
    echo "  Key size: ${KEYSIZE} bits"
  fi
done
```

Red flag: key size < 2048 bits.

### MTA-STS audit
```bash
# Policy lookup
dig +short TXT "_mta-sts.${DOMAIN}" | grep -i 'v=STSv1'

# Fetch policy file
curl -s "https://mta-sts.${DOMAIN}/.well-known/mta-sts.txt"
```

Red flags:
- No record + no policy file → no TLS enforcement on inbound mail
- `mode: testing` permanently → effectively unenforced
- Policy `max_age` < 86400 → forced re-fetch loop

### DNSSEC audit
```bash
# Check parent zone for DS record
dig +short DS "$DOMAIN"

# Validate the chain
dig +dnssec "$DOMAIN" | grep -i 'flags.*ad'  # AD flag = authenticated
delv "$DOMAIN" 2>&1 | grep -i 'validated'
```

Red flag: no DS record → DNSSEC effectively disabled.

### CAA audit
```bash
dig +short CAA "$DOMAIN"
```

Red flags:
- No CAA records → any CA can issue
- Allow-list includes EVERY CA → effectively no restriction
- Old `issue` value pointing at decommissioned CA → still issuable by that CA

## Attack Vectors

### Sending spoofed mail (BEC pretexting)

```bash
# Test environment ONLY — confirm spoofing is feasible
# Use swaks or mailsend to forge a From: header
swaks --to victim@x.com \
      --from "ceo@${DOMAIN}" \
      --header "Subject: Wire request" \
      --body "Approve attached invoice — urgent." \
      --server <mail-server-from-MX>
```

If the message lands in the victim's inbox (not spam / quarantine), the DMARC posture is insufficient.

### SPF include chain takeover

```bash
# Walk the include: chain
dig +short TXT '<TARGET>' | grep -oE 'include:[^ "]+' | sed 's/include://'

# For each included domain, check whether it's a service the attacker could register
# (Heroku, SendGrid, Mailchimp, etc. — sometimes domains the org no longer uses)
for inc in $(dig +short TXT '<TARGET>' | grep -oE 'include:[^ "]+' | sed 's/include://'); do
  echo "Checking $inc..."
  dig +short A "$inc"  # NXDOMAIN → takeover candidate
done
```

If an `include:` resolves to NXDOMAIN OR points at a service the attacker can sign up for, they can add their IP to the SPF authorisation chain.

### Subdomain takeover via CAA-less + dangling CNAME

When CAA is missing AND a subdomain CNAMEs to a decommissioned service, the attacker:
1. Claims the dangling service name on the SaaS provider (Heroku, GitHub Pages, Netlify, etc.)
2. Requests a Let's Encrypt cert for that subdomain (since CAA doesn't restrict)
3. Serves attacker content under the org's brand

## Operational Runbook

### Step 1 — full hygiene sweep
```bash
strix dns_hygiene_check --domain '<TARGET>'
```

Returns structured findings per record. Triage:
- Missing/`+all` SPF: **high** (CWE-290 — improper authentication)
- Missing DMARC: **high** (CWE-290)
- `p=none` DMARC: **medium** (reports-only enforcement)
- Weak DKIM: **medium** (CWE-327 — broken crypto)
- Missing CAA: **low** to **medium** depending on PKI hygiene elsewhere
- Missing DNSSEC: **low** in 2026 (still rare; not a critical bar)

### Step 2 — spoofability test (in scope)
```bash
# Determine which spoofing variants the target's policy allows
# Use https://www.dmarcian.com/dmarc-inspector/ or hand-craft tests

# Variant A: spoof apex (From: ceo@TARGET)
# Variant B: spoof subdomain (From: ceo@notifications.TARGET)
# Variant C: lookalike (From: ceo@TARGET.com.attacker.com)
```

Send each from a controlled source to a mailbox you own; classify which variants land in inbox vs spam.

### Step 3 — escalate
- BEC pretexting against the org (only with explicit phishing-engagement authorisation)
- Subdomain takeover via CAA-less + dangling CNAME
- Fraudulent cert issuance via lax CAA when attacker has DNS control (extremely rare)

## Validation

1. SPF: lookup count via `spfquery`; confirm < 10 OR document the PermError.
2. DMARC: parse policy; record p / sp / pct / alignment values.
3. DKIM: probe common selectors; extract key size.
4. CAA: present or absent; document any unsafe broad allow-list.
5. Spoofing PoC (when authorised): forge a message that lands in inbox.

## False Positives

- Domain only used for serving HTTPS (no mail) → DMARC `p=reject` is correct but a `null MX` is required to be fully compliant; some auditors flag `null MX` as a positive.
- SPF with TempError due to upstream DNS issue at scan time — re-run.
- Internal-only mail infrastructure where DKIM is signed by the gateway, not the apex — the apex selector may be intentionally absent.

## Impact

- BEC fraud: spoofed `From: ceo@target` instructions to finance / HR / IT.
- Phishing pretext: legitimate-looking notifications from the target's brand.
- Subdomain takeover via CAA + dangling CNAME chain.
- Reputation damage if the target's domain is used at scale for spam.

## Remediation

1. SPF: `v=spf1` with explicit `include:` for legitimate senders, ending in `-all` (hard fail).
2. DMARC: start at `p=none` + `rua=mailto:dmarc@target` for monitoring; progress to `p=quarantine` then `p=reject` once forwarders are tamed.
3. DKIM: 2048-bit RSA minimum; rotate annually; publish selector aliases for clean cutover.
4. MTA-STS: `mode: enforce` once monitoring is comfortable.
5. CAA: explicit list of authorised CAs (typically just Let's Encrypt or DigiCert for most orgs).
6. DNSSEC: enable at the registrar if the registrar supports it cleanly.

## Pro Tips

1. The fastest single-shot DMARC audit: `dig +short TXT _dmarc.<TARGET>` — if no output, that's already a high-severity finding.
2. Subdomain spoofing (`From: ceo@news.target.com`) often works even when the apex is locked down. Check the `sp=` field explicitly.
3. SPF `+all` is exceedingly rare in 2026 but happens during cutover errors — always grep for it.
4. DKIM selector enumeration is annoying but high-yield — try all common SaaS selectors (`google`, `selector1`, `selector2`, `mandrill`, `mailchimp`, `ses`, `sendgrid`).
5. CAA's enforcement happens at cert issuance; only useful if your CAs respect it. All major CAs do; some obscure ones don't.

## Summary

DNS hygiene is the email-authentication contract for the domain. Missing or weak records make BEC, phishing, and lookalike-domain attacks materially easier. Audit per record; prioritise DMARC + SPF first, then DKIM rotation and CAA.
