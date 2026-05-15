---
name: subdomain-takeover
description: Subdomain takeover testing for dangling DNS records and unclaimed cloud resources
---

# Subdomain Takeover

Subdomain takeover lets an attacker serve content from a trusted subdomain by claiming resources referenced by dangling DNS (CNAME/A/ALIAS/NS) or mis-bound provider configurations. Consequences include phishing on a trusted origin, cookie and CORS pivot, OAuth redirect abuse, and CDN cache poisoning.

## Attack Surface

- Dangling CNAME/A/ALIAS to third-party services (hosting, storage, serverless, CDN)
- Orphaned NS delegations (child zones with abandoned/expired nameservers)
- Decommissioned SaaS integrations (support, docs, marketing, forms) referenced via CNAME
- CDN "alternate domain" mappings (CloudFront/Fastly/Azure CDN) lacking ownership verification
- Storage and static hosting endpoints (S3/Blob/GCS buckets, GitHub/GitLab Pages)

## Reconnaissance

### Enumeration Pipeline

- Subdomain inventory: combine CT (crt.sh APIs), passive DNS sources, in-house asset lists, IaC/terraform outputs
- Resolver sweep: use IPv4/IPv6-aware resolvers; track NXDOMAIN vs SERVFAIL vs provider-branded 4xx/5xx
- Record graph: build a CNAME graph and collapse chains to identify external endpoints

### DNS Indicators

- CNAME targets ending in provider domains: `github.io`, `amazonaws.com`, `cloudfront.net`, `azurewebsites.net`, `blob.core.windows.net`, `fastly.net`, `vercel.app`, `netlify.app`, `herokudns.com`, `trafficmanager.net`, `azureedge.net`, `akamaized.net`
- Orphaned NS: subzone delegated to nameservers on a domain that has expired or no longer hosts authoritative servers
- MX to third-party mail providers with decommissioned domains
- TXT/verification artifacts (`asuid`, `_dnsauth`, `_github-pages-challenge`) suggesting previous external bindings

### HTTP Fingerprints

Service-specific unclaimed messages (examples):
- **GitHub Pages**: "There isn't a GitHub Pages site here."
- **Fastly**: "Fastly error: unknown domain"
- **Heroku**: "No such app" or "There's nothing here, yet."
- **S3 static site**: "NoSuchBucket" / "The specified bucket does not exist"
- **CloudFront**: 403/400 with "The request could not be satisfied"
- **Azure App Service**: default 404 for azurewebsites.net unless custom-domain verified
- **Shopify**: "Sorry, this shop is currently unavailable"

TLS clues: certificate CN/SAN referencing provider default host instead of the custom subdomain

## Key Vulnerabilities

### Claim Third-Party Resource

- Create the resource with the exact required name:
  - Storage/hosting: S3 bucket "sub.example.com" (website endpoint)
  - Pages hosting: create repo/site and add the custom domain
  - Serverless/app hosting: create app/site matching the target hostname

### CDN Alternate Domains

- Add the victim subdomain as an alternate domain on your CDN distribution if the provider does not enforce domain ownership checks
- Upload a TLS cert or use managed cert issuance

### NS Delegation Takeover

- If a child zone is delegated to nameservers under an expired domain, register that domain and host authoritative NS
- Publish records to control all hosts under the delegated subzone

### Mail Surface

- If MX points to a decommissioned provider, takeover could enable email receipt for that subdomain

## Advanced Techniques

### Blind and Cache Channels

- CDN edge behavior: 404/421 vs 403 differentials reveal whether an alt name is partially configured
- Cache poisoning: once taken over, exploit cache keys to persist malicious responses

### CT and TLS

- Use CT logs to detect unexpected certificate issuance for your subdomain
- For PoC, issue a DV cert post-takeover (within scope) to produce verifiable evidence

### OAuth and Trust Chains

- If the subdomain is whitelisted as an OAuth redirect/callback or in CSP/script-src, takeover elevates to account takeover or script injection

### Verification Gaps

- Look for providers that accept domain binding prior to TXT verification
- Race windows: re-claim resource names immediately after victim deletion

### Wildcards and Fallbacks

- Wildcard CNAMEs to providers may expose unbounded subdomains
- Fallback origins: CDNs configured with multiple origins may expose unknown-domain responses

## Special Contexts

### Storage and Static

- S3/GCS/Azure Blob static sites: bucket naming constraints dictate whether a bucket can match hostname
- Website vs API endpoints differ in claimability and fingerprints

### Serverless and Hosting

- GitHub/GitLab Pages, Netlify, Vercel, Azure Static Web Apps: domain binding flows vary
- Most require TXT now, but historical projects may not

### CDN and Edge

- CloudFront/Fastly/Azure CDN/Akamai: alternate domain verification differs
- Some products historically allowed alt-domain claims without proof

### DNS Delegations

- Child-zone NS delegations outrank parent records
- Control of delegated NS yields full control of all hosts below that label

## Operational Runbook

Subdomain takeover requires careful enumeration → fingerprint identification → safe claim. Most engagements stop at "confirmed takeover possible" without actually claiming the resource (the claim itself is non-trivial to reverse).

### Step 1 — enumerate subdomains broadly

```bash
# Multi-source enumeration
subfinder -d <TARGET_DOMAIN> -all -recursive -o /tmp/subs.txt
amass enum -passive -d <TARGET_DOMAIN> -o /tmp/subs_amass.txt
assetfinder --subs-only <TARGET_DOMAIN> >> /tmp/subs.txt
findomain -t <TARGET_DOMAIN> -q >> /tmp/subs.txt

# Certificate transparency
curl -s "https://crt.sh/?q=%25.<TARGET_DOMAIN>&output=json" \
    | jq -r '.[].name_value' | tr ',' '\n' | sort -u >> /tmp/subs.txt

# Deduplicate
sort -u /tmp/subs.txt > /tmp/subs_unique.txt
wc -l /tmp/subs_unique.txt
```

### Step 2 — resolve all DNS record types

```bash
# Bulk resolve with dnsx
dnsx -l /tmp/subs_unique.txt -a -aaaa -cname -ns -mx -resp -silent > /tmp/dns_records.txt

# Focus on CNAMEs pointing to third-party services (highest takeover risk)
grep "CNAME" /tmp/dns_records.txt | tee /tmp/cnames.txt

# Also pull dangling NS delegations (rarer but high-impact)
grep "NS " /tmp/dns_records.txt | grep -v "<TARGET_DOMAIN>"
```

### Step 3 — fingerprint against known-takeoverable services

```bash
# Subjack — has the largest fingerprint database
subjack -w /tmp/subs_unique.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json \
    -v -o /tmp/subjack_results.json

# Nuclei has signed takeover templates
nuclei -l /tmp/subs_unique.txt -t http/takeovers/ -severity high,critical -o /tmp/nuclei_takeovers.txt

# Manual fingerprint check — fetch each candidate
for sub in $(grep -E "(s3|github|herokuapp|azure|cloudfront|fastly|shopify)" /tmp/cnames.txt | awk '{print $1}'); do
    body=$(curl -sL "https://$sub" -m 10 -o /dev/null -w '%{http_code}\n')
    echo "$sub → status=$body"
    if [ "$body" = "404" ]; then
        # Often the "unclaimed" status — fetch the body to confirm fingerprint
        curl -sL "https://$sub" -m 10 | head -5
    fi
done
```

### Step 4 — high-value provider fingerprints

| Service | CNAME pattern | Unclaimed response signature |
|---|---|---|
| AWS S3 (legacy) | `*.s3.amazonaws.com` | `<Code>NoSuchBucket</Code>` |
| AWS S3 (region) | `*.s3-website.<region>.amazonaws.com` | "The specified bucket does not exist" |
| AWS CloudFront | `*.cloudfront.net` | "ERROR: The request could not be satisfied" |
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" |
| Heroku | `*.herokuapp.com` | "No such app" |
| Azure | `*.azurewebsites.net` / `*.cloudapp.net` | "404 Web Site not found" |
| Shopify | `*.myshopify.com` | "Sorry, this shop is currently unavailable" |
| Fastly | `*.fastly.net` | "Fastly error: unknown domain" |
| Tumblr | `*.tumblr.com` | "Whatever you were looking for doesn't currently exist" |
| Surge | `*.surge.sh` | "project not found" |
| Pantheon | `*.pantheonsite.io` | "404 site not found" |
| Bitbucket | `*.bitbucket.io` | "Repository not found" |
| Webflow | `*.webflow.io` | "The page you are looking for doesn't exist" |
| Read the Docs | `*.readthedocs.io` | "unknown to Read the Docs" |

### Step 5 — confirm before claiming (DO NOT execute claim without scope authz)

```bash
# Confirmation checklist for a candidate "victim.example.com → unclaimed.s3.amazonaws.com":
# 1. dig CNAME the subdomain
dig +short victim.example.com
# 2. Verify the target resolves but is unclaimed
curl -sL https://victim.example.com -m 10
# 3. Search GitHub / DocSearch for references to the subdomain
# 4. Document the FQDN, the dangling target, the fingerprint match,
#    AND screenshot the unclaimed response.
```

**STOP HERE** unless the engagement scope explicitly authorizes the claim. The claim itself:

```bash
# (DO NOT do this without explicit scope auth)
# 1. Register the dangling resource (create new S3 bucket / GitHub Pages site / etc.)
# 2. Set a custom domain matching the target subdomain
# 3. Host benign content proving control
# 4. Document the cookie/CORS scope the takeover grants
# 5. Hand off to the customer to demonstrate impact

# Reversal: bucket deletion / Pages site delete should restore the dangling state,
# but DNS owner needs to update CNAME → cleanup is shared work.
```

### Step 6 — record evidence

Document:
- FQDN of vulnerable subdomain
- CNAME target (the dangling pointer)
- Fingerprint match (exact string from the unclaimed response)
- Cookie scope implications (`.example.com` cookies are reachable from any subdomain of example.com → takeover grants session theft)
- Severity: **high** for generic takeover; **critical** when the target subdomain is referenced in JS / OAuth callback URLs / CSP allow-lists / SAML metadata / cookie domains.

## Testing Methodology

1. **Enumerate subdomains** - Aggregate CT logs, passive DNS, and org inventory
2. **Resolve DNS** - All RR types: A/AAAA, CNAME, NS, MX, TXT; keep CNAME chains
3. **HTTP/TLS probe** - Capture status, body, error text, Server headers, certificate SANs
4. **Fingerprint providers** - Map known "unclaimed/missing resource" signatures
5. **Attempt claim** (with authorization) - Create missing resource with exact required name
6. **Validate control** - Serve minimal unique payload; confirm over HTTPS

## Validation

1. Before: record DNS chain, HTTP response (status/body length/fingerprint), and TLS details
2. After claim: serve unique content and verify over HTTPS at the target subdomain
3. Optional: issue a DV certificate (legal scope) and reference CT entry as evidence
4. Demonstrate impact chains (CSP/script-src trust, OAuth redirect acceptance, cookie Domain scoping)

## False Positives

- "Unknown domain" pages that are not claimable due to enforced TXT/ownership checks
- Provider-branded default pages for valid, owned resources (not a takeover)
- Soft 404s from your own infrastructure or catch-all vhosts

## Impact

- Content injection under trusted subdomain: phishing, malware delivery, brand damage
- Cookie and CORS pivot: if parent site sets Domain-scoped cookies or allows subdomain origins
- OAuth/SSO abuse via whitelisted redirect URIs
- Email delivery manipulation for subdomain

## Pro Tips

1. Build a pipeline: enumerate (subfinder/amass) → resolve (dnsx) → probe (httpx) → fingerprint (nuclei/custom) → verify claims
2. Maintain a current fingerprint corpus; provider messages change frequently
3. Prefer minimal PoCs: static "ownership proof" page and, where allowed, DV cert issuance
4. Monitor CT for unexpected certs on your subdomains
5. Eliminate dangling DNS in decommission workflows first
6. For NS delegations, treat any expired nameserver domain as critical
7. Use CAA to limit certificate issuance while you triage

## Summary

Subdomain safety is lifecycle safety: if DNS points at anything, you must own and verify the thing on every provider and product path. Remove or verify—there is no safe middle.
