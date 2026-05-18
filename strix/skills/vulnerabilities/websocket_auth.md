---
name: websocket-auth
description: WebSocket + SSE authentication / authorization probing — origin checks, token rebind, cross-site WS hijacking
triggers: [websocket, ws, wss, sse, server sent events, cswsh, origin header, socket.io, channel auth]
---

# WebSocket / SSE Authentication

WebSockets and Server-Sent Events upgrade from HTTP but operate under different security primitives — origin checks rather than CORS, no per-message CSRF tokens, often a single auth-at-handshake that's trusted for the lifetime of the connection. Common bugs: missing `Origin` validation (CSWSH), token-in-URL leakage, channel-level authz bypass, and message-level injection.

Companion to `scan_websocket_auth`.

## Attack Surface

**Stacks**
- Native `WebSocket` API (browser) + Node `ws` / Go `gorilla/websocket` / Python `websockets` / Phoenix Channels / Spring WebSocket
- **Socket.IO** — fallback transport polling; auth differs per transport
- **GraphQL subscriptions over WebSocket** (`graphql-ws` / `subscriptions-transport-ws`)
- **MQTT over WebSocket** — IoT-flavoured; same channel-auth bugs
- **SSE (`EventSource`)** — HTTP-shaped; different but related class
- **WebTransport** (newer) — HTTP/3-based; QUIC streams

**Common endpoints**
- `/ws`, `/socket`, `/socket.io/`, `/realtime`, `/graphql` (with `Upgrade`), `/events` (SSE)
- `/sockjs-node`, `/sockjs/`
- `wss://api.<domain>/v1/stream`

**Where the auth lives**
- Cookie (browser-supplied automatically — CSWSH risk)
- Bearer token in handshake `Sec-WebSocket-Protocol` header (clever, less common)
- Token in URL query string (`wss://api/ws?token=...`) — leaks in logs, browser history, referer
- Auth message after connection: `{"type":"auth","token":"..."}`

## Detection Channels

### Origin validation (CSWSH)

```bash
# Connect with an attacker-controlled Origin header
wscat -c 'wss://<TARGET>/ws' -H 'Origin: https://attacker.com'

# If accepted: any attacker-hosted page can open a WS to <TARGET>/ws
# using the victim's cookies. That's CSWSH.
```

A correctly-configured server rejects with HTTP 403 / disconnects immediately on unauthorised origins.

### Cookie-only auth

```bash
# Connect with cookie + no other auth → if successful, auth is purely cookie-driven
wscat -c 'wss://<TARGET>/ws' -H 'Cookie: session=<victim>'

# Combined with bad origin check = CSWSH game over.
```

### Token-in-URL leakage

```bash
# Pull the actual app and look at handshake
curl -s 'https://<TARGET>/some-page-that-opens-ws' | grep -oE 'wss?://[^"]+token=[^"&]+'

# If token appears in URL: every proxy/load-balancer log along the way has it.
```

### Subprotocol bypass

```bash
# Some servers accept null subprotocols where they should require auth
wscat -c 'wss://<TARGET>/ws' -s ''   # empty subprotocol
wscat -c 'wss://<TARGET>/ws' -s 'admin-protocol'  # privileged subprotocol
```

### Per-message authz

```javascript
// Connect as low-priv user
const ws = new WebSocket('wss://<TARGET>/ws');
ws.onopen = () => {
  // Try to subscribe to a privileged channel
  ws.send(JSON.stringify({type: 'subscribe', channel: 'admin:audit'}));
};
ws.onmessage = (msg) => console.log(msg.data);
// If the server doesn't re-authz per message, you'll see admin channel data.
```

## Operational Runbook

### Step 1 — discover WebSocket endpoints

```bash
# Grep the live page for ws:// or wss:// URLs
curl -s 'https://<TARGET>/' | grep -oE 'wss?://[^"\\]+' | sort -u

# Check service-worker / app manifest
curl -s 'https://<TARGET>/sw.js' | grep -oE 'wss?://[^"\\]+'

# Common paths to brute
for path in /ws /socket /socket.io/ /realtime /graphql /events /api/ws /api/stream; do
  curl -s -i -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    -H 'Sec-WebSocket-Version: 13' \
    "https://<TARGET>${path}" -o /dev/null -w '%{http_code}\n'
done
# 101 → WebSocket endpoint present
```

### Step 2 — origin validation matrix

```bash
ORIGINS=(
  'https://<TARGET>'                   # legitimate
  'https://attacker.com'                # off-origin
  'null'                                # sandboxed iframe / data: URL
  'https://<TARGET>.attacker.com'       # subdomain confusion
  'https://attacker.com.<TARGET>'       # reverse confusion
  'http://<TARGET>'                     # protocol downgrade
  ''                                    # missing
)

for origin in "${ORIGINS[@]}"; do
  printf "%-50s " "$origin"
  wscat -c 'wss://<TARGET>/ws' -H "Origin: $origin" -x 'ping' 2>&1 | head -1
done
```

Any acceptance of off-origin / null / missing Origin → CSWSH high-severity finding.

### Step 3 — token-in-URL audit

```bash
# Pull traffic via browser DevTools or proxy → look at upgrade request
# In Burp / mitmproxy: filter by "websocket" + "GET" → check the URL

# If you see ?token=, ?auth=, ?api_key= in the WebSocket URL:
# - Server access logs likely contain the token
# - Browser history retains it
# - Any HTTP referer from this page leaks it
```

### Step 4 — channel authz probe

```bash
# Authenticate as user A (low priv)
TOKEN_A='...'

# Connect + try to subscribe to user B's channels
node -e "
const WebSocket = require('ws');
const ws = new WebSocket('wss://<TARGET>/ws?token=$TOKEN_A');
ws.on('open', () => {
  ws.send(JSON.stringify({type: 'subscribe', channel: 'user:42:private'}));
});
ws.on('message', (data) => console.log(data.toString()));
"
```

If you receive messages from user 42's private channel → channel-level authz bypass.

### Step 5 — Socket.IO-specific

```bash
# Socket.IO uses polling fallback; auth differs between polling and WS transport
curl -s 'https://<TARGET>/socket.io/?EIO=4&transport=polling'

# Probe namespace-level authz
curl -s 'https://<TARGET>/socket.io/?EIO=4&transport=polling&namespace=/admin'
```

Socket.IO namespaces (`/admin`, `/internal`) sometimes lack auth entirely.

### Step 6 — GraphQL-over-WS subscription authz

```javascript
const { createClient } = require('graphql-ws');
const client = createClient({
  url: 'wss://<TARGET>/graphql',
  connectionParams: { authToken: '<low_priv_token>' },
});

// Try a privileged subscription
client.subscribe(
  { query: 'subscription { adminAuditLog { actor action } }' },
  { next: (data) => console.log(data) },
);
```

If you get audit-log events with a low-priv token: subscription-level authz is broken.

## Bypass Techniques

- **Subprotocol smuggling**: `Sec-WebSocket-Protocol: bearer.eyJhbG...` — some servers accept the protocol name as the auth source.
- **Origin null tricks**: sandboxed iframes (`<iframe sandbox>`) send `Origin: null`. Servers that allow `null` for "local file" cases are CSWSH-vulnerable.
- **Cookie scoping abuse**: WebSocket auto-attaches cookies even from off-origin attacker pages — that's the whole CSWSH primitive.
- **Heartbeat / ping abuse**: long-lived connections rarely re-authenticate; if a token revokes mid-connection, server may keep sending.

## Validation

1. CSWSH: connect from `https://attacker.com` (Origin), demonstrate sending+receiving authenticated traffic with the victim's cookies.
2. Channel bypass: subscribe to channel X with credentials that should only access channel Y; receive X's messages.
3. Token leakage: produce server access log or proxy log entry containing the token.
4. Persistent-session bypass: revoke the user's session via the web UI; show the WebSocket connection still serving authenticated data.

## False Positives

- Server returns 200 to the handshake (not 101) — connection didn't upgrade. The body might be a redirect; not exploitable as WS.
- Wscat hangs after Origin probe — could be silent rejection. Confirm with `-s` flag for protocol prints or by reading server response codes.
- Server uses STOMP / SockJS over the WebSocket — different auth model; the WS layer is just transport.

## Impact

- CSWSH: attacker reads / writes user's authenticated WebSocket traffic via a phishing page.
- Channel-level data exfil: read other users' private channel messages.
- Persistent-session bypass: connections survive password reset / session revocation.
- Token leakage via URL: every proxy log + browser history exposes valid bearer tokens.

## Remediation

1. **Validate `Origin` strictly** at the upgrade handler: allow-list of exact origins; reject `null` unless explicitly required.
2. **Don't put tokens in URLs**: use the first message-after-connect for auth (`{"type":"auth","token":"..."}`) and require it within a short timeout.
3. **Re-authorise per channel subscription**: confirm the connected user has access to the channel they're subscribing to.
4. **Re-authorise on session revocation**: have an out-of-band channel-close mechanism when a user's session is revoked.
5. **Disable cookie auth on WebSocket upgrades**: require bearer token (in subprotocol header or first message). Cookies + WebSocket = CSWSH-vulnerable by default.
6. **Set short connection-idle timeouts** + require explicit re-auth on reconnect.

## Pro Tips

1. Use `wscat` (Node) or `websocat` (Rust) for hand-crafted probes; they're vastly easier than `nc` + manual upgrade frames.
2. Browser DevTools → Network tab → WS filter shows the full WebSocket message stream. Use it to capture legitimate traffic before crafting probes.
3. Socket.IO is often vulnerable on the polling transport even when WebSocket is locked down — always test both.
4. Server-Sent Events follow CORS (since they're HTTP), not the WebSocket origin model — different audit needed.
5. GraphQL subscriptions are the highest-yield surface in modern apps — most teams forget to re-authz per subscription.

## Summary

WebSocket security is HTTP security minus CORS. The standard bugs are origin-laxity (CSWSH), token-in-URL leakage, missing per-channel authz, and persistent sessions surviving revocation. Audit each at upgrade-time and message-time.
