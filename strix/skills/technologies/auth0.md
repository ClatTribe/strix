---
name: auth0
description: Auth0 — universal-login customisation, rules vs actions, M2M client misconfig, tenant-wide policies, JWT validation gaps
triggers: [auth0, oauth0, identity provider, rules, actions, tenant, m2m, machine to machine, universal login, custom database]
---

# Auth0 Security

Auth0 is the most-deployed third-party identity provider for B2B SaaS. The Auth0 *side* has its own bugs (tenant-wide policies, rule / action misconfiguration), but the more common surface is **how the customer app integrates with Auth0**: JWT validation, redirect handling, M2M tokens with broad scopes, custom-database connections with stored creds.

## Attack Surface

### JWT (`id_token` + `access_token`)
- Auth0 signs with RS256 by default; HS256 is opt-in (legacy / SDK examples)
- Bug: `jwt.verify(token, secret, {algorithms: ['HS256', 'RS256']})` → alg-confusion
- Bug: `jwt.decode()` for claims extraction without `verify()` — no signature check
- Bug: `aud` (audience) not validated → tokens issued for app A used at app B
- Bug: `iss` not validated → token from a different tenant accepted

### Redirect handling
- Allowed Callback URLs configured per Application
- Bug: wildcards (`https://*.example.com/callback`) accept attacker-owned subdomains
- Bug: developer added `https://localhost:3000/callback` "for testing" — left in prod
- Bug: callback handler doesn't validate `state` → CSRF on auth callback

### Universal Login customisation
- Tenant can customise the login page HTML / CSS / JS
- Bug: custom JS injection via tenant admin compromise → stored XSS on login page
- Bug: custom DB connection with bcrypt-less password storage

### Rules vs Actions
- Rules: legacy, JS code that runs in the login pipeline (deprecated, sunset 2024)
- Actions: new model; per-flow code (login, post-login, pre-registration, etc.)
- Bug: Rule / Action with hardcoded API keys in console
- Bug: Action modifying `id_token` / `access_token` adding unauthorized claims (e.g., `is_admin: true` always)

### M2M (Machine-to-Machine) clients
- Used for service-to-service auth via `client_credentials` grant
- Bug: M2M client with scopes `read:users` `update:users` etc. — token stored in app config, leaks via repo/log
- Bug: M2M client secret rotation never done

### Custom databases
- Auth0 can connect to your DB for authentication via custom scripts
- Bug: custom DB scripts written in the Auth0 console with hardcoded creds for the customer DB
- Bug: SQL injection in the custom DB script's query construction
- Bug: bcrypt downgrade — script returns plaintext password to Auth0 for hashing

### Tenant-wide policies
- Password policies, MFA, lockout — all tenant-level
- Bug: MFA off for non-admin users; only enforced for admins → most users still password-only
- Bug: Anomaly detection off → no detection of credential stuffing

## Detection Channels

### Fingerprint Auth0 integration
```bash
# Look for Auth0 SDK in the page
curl -s 'https://<TARGET>/' | grep -oE 'auth0|@auth0/auth0-react|@auth0/auth0-spa-js'

# Auth0 universal-login URL pattern
curl -s 'https://<TARGET>/' | grep -oE 'https://[a-z0-9-]+\.auth0\.com|https://[a-z0-9-]+\.eu\.auth0\.com|https://[a-z0-9-]+\.us\.auth0\.com'
```

The Auth0 tenant domain (`<tenant>.auth0.com`) is publicly fingerprint-able.

### JWT inspection
```bash
# Capture an access_token / id_token (from network tab / curl)
TOKEN='eyJhbGciOi...'

# Decode header
echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null
# alg, kid, typ

# Decode payload
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null
# iss, aud, sub, exp, iat, scope, custom claims
```

### Callback URL audit
```bash
# Auth0 publishes its OIDC discovery doc
curl -s 'https://<TENANT>.auth0.com/.well-known/openid-configuration' | jq .

# response_types_supported, scopes_supported, code_challenge_methods_supported
# Compare against your app's Auth0 client setup
```

### M2M token brute (when you have client_id only)
```bash
# Try common client_secret defaults / weak rotation
curl -X POST "https://<TENANT>.auth0.com/oauth/token" \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"client_credentials","client_id":"<APP_ID>","client_secret":"<GUESS>","audience":"https://api/"}'
```

## Operational Runbook

### Step 1 — fingerprint tenant + flows
```bash
TENANT='target-tenant.auth0.com'

# Pull OIDC discovery
curl -s "https://${TENANT}/.well-known/openid-configuration" > /tmp/oidc.json

# Allowed flows
jq '.grant_types_supported' /tmp/oidc.json

# Endpoints
jq '{authorization: .authorization_endpoint, token: .token_endpoint, userinfo: .userinfo_endpoint, jwks: .jwks_uri}' /tmp/oidc.json
```

### Step 2 — JWT validation audit (full sweep)
See oauth_oidc.md skill — same JWT-validation testing applies:
- alg=none probe
- alg=HS256 with public key as secret
- expired token replay
- missing `iss` / `aud` validation

### Step 3 — callback-URL loose match
```bash
# Per the OAuth/OIDC skill's redirect_uri probe
# Auth0-specific: try with `https://<TENANT>.auth0.com` as the redirect (some apps allow it for "logout" flows but accept on login)
```

### Step 4 — M2M scope enumeration
```bash
# If you have a token, decode the scope claim
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d | jq -r .scope

# Common over-broad M2M scopes:
# - read:users update:users delete:users → user-management RPC
# - read:roles update:roles → role management
# - read:rules update:rules → tenant code modification
```

### Step 5 — userinfo abuse
```bash
# Auth0's /userinfo accepts any valid access_token
# Tokens with `openid profile email` scope return full profile
curl -H "Authorization: Bearer $ACCESS_TOKEN" "https://${TENANT}/userinfo"

# Bug: tokens with `read:current_user` reach the Management API
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://${TENANT}/api/v2/users/$(echo $ACCESS_TOKEN | cut -d. -f2 | base64 -d | jq -r .sub)"
```

### Step 6 — Action / Rule auditing (post-tenant-admin compromise)
```bash
# Via Management API with a tenant-management token:
curl -H "Authorization: Bearer $MGMT_TOKEN" \
  "https://${TENANT}/api/v2/actions/actions" | jq '.actions[].name'

# Look for actions with suspicious code (key exfil, claim injection)
```

## Specific Vulnerability Classes

### Custom DB script SQL injection
- Auth0 console has a `getUser` / `login` script that queries the customer's DB
- Devs sometimes write: `SELECT * FROM users WHERE email = '${email}'` (string concat) — SQLi via attacker-chosen email
- Test by triggering login with crafted email; Auth0 runs the script

### Rule modifies tokens with bypassable conditions
- Rule: `if (context.connection.strategy === 'oauth2') { user.app_metadata.is_admin = true; }`
- Bug: the strategy comparison is permissive; OAuth2 connections from any social provider trigger the elevation

### Tenant-wide MFA off
- `Multifactor` policies in the dashboard
- Bug: "MFA required for users with the `admin` role" but role attribute set client-side; not enforced

### `id_token` validation skipped client-side
- SPAs sometimes call `auth0-react`'s `getIdTokenClaims()` and trust the result
- Token is signed; SDK validates; but the SPA's API server should re-validate the `aud` + `iss` independently

### Refresh-token rotation off
- Auth0 supports refresh-token rotation; default OFF for legacy SDKs
- Stolen refresh token = perpetual access until manually revoked

### Anonymous user signup → privilege escalation
- Some tenants enable signup on the management UI
- Bug: signup script auto-promotes new users with specific email domains to admin

## Bypass Techniques

- **`prompt=none` for silent re-auth** + open redirect on callback → token theft without user interaction
- **`response_type=token id_token`** (implicit flow) leaking tokens in URL fragment → log scrape
- **JWT in URL parameter** (e.g., `?token=`) → leak via Referer, logs, browser history
- **Cross-tenant ID confusion**: token issued by tenant A used against app validating against tenant B

## Validation

1. JWT alg-confusion: forged token with alg=none / alg=HS256 accepted.
2. Callback loose-match: redirect to attacker-controlled host succeeds.
3. M2M scope leak: token with broad scopes exfiltrated from repo / log.
4. Userinfo abuse: enumerate user details via captured token.
5. Custom DB SQLi: malformed email triggers SQL error in Auth0 logs (if accessible).

## False Positives

- `https://localhost:3000` in callback URLs for a dev app — confirm prod env.
- M2M token with broad scopes legitimately used for an internal service — confirm operator's intent.
- Auth0 staging tenant findings — confirm the affected tenant is prod.

## Impact

- Account takeover via JWT validation bypass.
- Tenant-wide compromise via Action / Rule modification.
- Mass user-data exfil via Management API token with `read:users` scope.
- Phishing-platform via Universal Login JS injection.

## Remediation

1. **Strict callback URLs**: explicit list, no wildcards, no localhost in prod.
2. **JWT validation server-side**: verify alg, iss, aud, exp — every time.
3. **MFA tenant-wide**: at minimum for admin, ideally for all users.
4. **M2M client secret rotation**: quarterly.
5. **Refresh token rotation enabled**: invalidates old refresh tokens on use.
6. **Actions / Rules code review**: same standard as application code; track in git.
7. **Anomaly detection on**: brute-force protection, suspicious-IP throttling.

## Pro Tips

1. The tenant domain is publicly known (Application Login URI in source). Pull `/.well-known/openid-configuration` first.
2. Auth0's `/v2/api-explorer` endpoint reveals the Management API surface — useful for M2M scope enumeration.
3. `is_admin` / `role` claims in `id_token` are GROUND TRUTH — modifying them via Rule / Action = persistent elevation.
4. The `app_metadata` field is writable by tenant admins + by Rules; check what flows there.
5. SSO Lock (Auth0's older Lock widget) has different XSS surface than the newer Universal Login Page — fingerprint which is used.

## Summary

Auth0 bugs split across (1) the customer's JWT validation, (2) callback URL configuration, (3) Auth0-side tenant policies, (4) custom DB scripts, and (5) M2M client scope creep. Audit each independently; the JWT validation half is the customer's responsibility.
