"""iter-29.1 — Endpoint classifier (the foundation for shape-aware exploitation).

The prior iter surfaced the L1 gap: discovery primitives (auth seed,
GraphQL discovery, default-creds probe) produced expanded surfaces
but downstream specialists couldn't EXPLOIT them because they had no
idea what each endpoint **was** — they treated `/api/users/123`,
`/search?q=`, `/login`, and `/static/main.js` identically.

This module gives every discovered URL an `EndpointProfile`. Downstream
specialists (scan_sqli, scan_xss, scan_idor, ...) consume the profile
to pick the right payload bin, request shape, and confidence threshold.

**What it classifies:**

  * **shape** — how requests/responses are wire-formatted
    (form / json / graphql / multipart / xml / grpc / path / static)
  * **endpoint_class** — what attack class is plausible
    (search / upload / redirect / admin / api-list / api-detail
     / auth-login / auth-register / destructive / static-asset
     / generic)
  * **methods** — HTTP verbs observed
  * **auth_required** — does an unauthenticated probe return 401/403?
  * **idempotent** — safe to fire payloads multiple times?
  * **expected_status / response_size_baseline / response_time_ms** —
    diff baseline for payload-aware specialists
  * **framework_hints** — express / django / rails / spring / asp.net /
    wordpress / nginx etc. — from Server / X-Powered-By / cookies /
    HTML generators
  * **waf_detected** — cloudflare / akamai / aws / sucuri / f5 / imperva
    / azure (informs payload-bypass strategy)
  * **rate_limit_detected** — burst-probed; informs governor

**Anti-overfit guarantees:**

  * Class detection uses URL-substring conventions documented in REST
    style guides (search/upload/redirect/admin/login/register patterns
    are universal). NO per-SUT entries.
  * Framework detection from documented Server / X-Powered-By /
    Set-Cookie / HTML-generator-meta values published in each
    framework's docs.
  * WAF detection from public WAF-fingerprint corpora
    (wafw00f / public WAF-bypass research). Vendor signatures are
    deterministic; no SUT-coupling possible.
  * Regression test grep asserts no fixture-specific identifier
    appears in this module's source.

**Pure-python; no new docker tools required.**
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

import requests


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — class/shape/framework conventions
# ---------------------------------------------------------------------------

# Endpoint class → URL substring patterns (case-insensitive). Sourced
# from REST style guides + OWASP testing guide vocabulary. Each pattern
# is a substring matched against the URL path component.
#
# Order matters — earlier classes win when multiple match (e.g. an
# `/admin/login` is class=admin, not class=auth-login, because the
# admin scope is the more important attack surface).
_CLASS_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    ("destructive", ("delete", "remove", "purge", "drop", "truncate", "wipe")),
    ("admin", ("admin", "manage", "console", "dashboard", "superuser", "/staff/")),
    ("auth-register", ("/register", "/signup", "/sign-up", "/users/register",
                       "/auth/register", "/auth/signup")),
    ("auth-login", ("/login", "/signin", "/sign-in", "/auth/login",
                    "/auth/signin", "/oauth/token", "/oauth/authorize",
                    "/sso/login", "/saml/login")),
    ("upload", ("/upload", "/import", "/attach", "/media", "/file",
                "/photo", "/avatar", "/document")),
    ("redirect", ("/redirect", "/forward", "/goto", "/r/", "/go/", "/out/",
                  "/link/", "/url/")),
    ("search", ("/search", "/query", "/find", "/lookup", "/autocomplete",
                "/suggest", "/typeahead")),
]


# REST-detail vs REST-list — detail endpoints have a trailing ID
# component (numeric, UUID, hex). Used after the substring patterns
# above don't match. Anti-overfit: these patterns describe REST URL
# convention, not any specific SUT.
_REST_DETAIL_RE = re.compile(
    r"/[A-Za-z][A-Za-z0-9_-]*/"
    r"(?:[0-9]+|[a-f0-9]{8,}|[A-Za-z0-9_-]{20,}|[A-Za-z0-9-]{36})"
    r"/?$",
    re.IGNORECASE,
)
_REST_LIST_RE = re.compile(r"/(api|v[0-9]+)?/?[A-Za-z][A-Za-z0-9_-]*/?$", re.IGNORECASE)


# Static-asset extensions (industry standard, not SUT-specific)
_STATIC_EXTS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map",
    ".mp4", ".webm", ".ogg", ".mp3", ".wav", ".pdf", ".zip",
)

# GraphQL endpoint hints (industry convention)
_GRAPHQL_HINTS = ("/graphql", "/gql", "/v1/graphql", "/api/graphql", "/query")


# Framework fingerprints — from documented framework defaults.
# Each tuple: (framework_name, {header: regex, ...}, body_regex_or_None).
# Detection is best-effort; any single signal is sufficient.
_FRAMEWORK_FINGERPRINTS: list[tuple[str, dict[str, re.Pattern[str]], re.Pattern[str] | None]] = [
    # Server / X-Powered-By identification (RFC-conventional headers)
    ("express", {"x-powered-by": re.compile(r"Express", re.I)}, None),
    ("django", {"server": re.compile(r"gunicorn|wsgiref|WSGIServer", re.I)},
        re.compile(r"csrfmiddlewaretoken|django\.contrib", re.I)),
    ("rails", {"x-powered-by": re.compile(r"Phusion Passenger|Rails", re.I)}, None),
    ("rails-alt", {"x-runtime": re.compile(r".+")}, None),  # X-Runtime is Rails-specific
    ("spring", {"x-application-context": re.compile(r".+")}, None),
    ("tomcat", {"server": re.compile(r"Apache Tomcat|Coyote", re.I)}, None),
    ("nginx", {"server": re.compile(r"nginx", re.I)}, None),
    ("apache", {"server": re.compile(r"^Apache/", re.I)}, None),
    ("aspnet", {"x-aspnet-version": re.compile(r".+")},
        re.compile(r"__VIEWSTATE|__EVENTVALIDATION", re.I)),
    ("aspnet-core", {"x-powered-by": re.compile(r"ASP\.NET", re.I)}, None),
    ("php", {"x-powered-by": re.compile(r"PHP/", re.I)}, None),
    ("wordpress", {}, re.compile(r"wp-content|wp-includes|wp-json", re.I)),
    ("flask", {"server": re.compile(r"Werkzeug", re.I)}, None),
    ("fastapi", {}, re.compile(r"FastAPI|openapi", re.I)),  # weak — needs corroboration
    ("hasura", {"x-hasura-role": re.compile(r".+")}, None),
    ("nextjs", {"x-powered-by": re.compile(r"Next\.js", re.I)},
        re.compile(r"__NEXT_DATA__", re.I)),
    ("nuxt", {}, re.compile(r"__NUXT__", re.I)),
    ("angular", {}, re.compile(r"ng-version|<app-root", re.I)),
    ("react", {}, re.compile(r"data-react-helmet|<div\s+id=\"?(?:root|app)\"?>", re.I)),
    ("vue", {}, re.compile(r"data-v-[a-f0-9]+|__VUE_SSR_CONTEXT__", re.I)),
]


# WAF fingerprints — from public WAF-fingerprint corpora (wafw00f
# + per-vendor security advisory pages).
_WAF_FINGERPRINTS: list[tuple[str, dict[str, re.Pattern[str]], re.Pattern[str] | None]] = [
    ("cloudflare",
     {"server": re.compile(r"cloudflare", re.I),
      "cf-ray": re.compile(r".+"),
      "set-cookie": re.compile(r"__cf_bm|__cfduid", re.I)},
     None),
    ("akamai",
     {"x-akamai-transformed": re.compile(r".+"),
      "server": re.compile(r"AkamaiGHost", re.I)},
     None),
    ("aws-waf",
     {"x-amz-cf-id": re.compile(r".+"),
      "x-amzn-requestid": re.compile(r".+")},
     None),
    ("azure-frontdoor",
     {"x-azure-ref": re.compile(r".+"),
      "x-cache": re.compile(r"CONFIG_NOCACHE", re.I)},
     None),
    ("sucuri",
     {"x-sucuri-id": re.compile(r".+"),
      "server": re.compile(r"Sucuri", re.I)},
     None),
    ("f5-bigip",
     {"server": re.compile(r"BigIP", re.I),
      "set-cookie": re.compile(r"BIGipServer", re.I)},
     None),
    ("imperva",
     {"x-iinfo": re.compile(r".+"),
      "set-cookie": re.compile(r"incap_ses|visid_incap", re.I)},
     None),
    ("fortinet",
     {"server": re.compile(r"FortiWeb", re.I)}, None),
    ("barracuda",
     {"server": re.compile(r"Barracuda", re.I),
      "set-cookie": re.compile(r"barra_counter_session", re.I)},
     None),
]


# Error tokens worth capturing in the baseline so the diff verifier
# (iter-29.2) can spot a payload triggering a NEW error type.
_BASELINE_ERROR_TOKENS = (
    "SQLSTATE", "mysql_", "psql:", "ORA-", "sqlite_",
    "Traceback (most recent call last)",
    "java.lang.", "NullPointerException",
    "<title>Whitelabel Error",      # Spring default
    "<h1>Server Error",
    "Microsoft OLE DB",
    "ODBC SQL Server Driver",
)


# Default probe timeout (per request)
_PROBE_TIMEOUT_S = 6
# How many requests to issue when computing the baseline (avg of N)
_BASELINE_PROBE_COUNT = 1
# Burst probe count for rate-limit detection
_RATE_LIMIT_PROBE_COUNT = 5


# ---------------------------------------------------------------------------
# EndpointProfile dataclass
# ---------------------------------------------------------------------------

@dataclass
class EndpointProfile:
    """Structured profile of an HTTP endpoint, consumed by downstream
    payload-aware specialists.

    All fields are JSON-serializable via `to_dict()`. The profile is
    immutable in spirit — re-classify if the endpoint behavior changes
    mid-scan (e.g., post-auth re-classify of an admin URL).
    """
    url: str
    shape: str                              # form/json/graphql/multipart/xml/grpc/path/static/unknown
    endpoint_class: str                     # search/upload/admin/auth-login/.../generic
    methods: list[str] = field(default_factory=list)
    auth_required: bool | None = None       # True/False/None (unknown)
    idempotent: bool = True
    expected_status: int | None = None
    response_shape: str = "unknown"         # html/json/xml/binary/empty/redirect
    response_size_baseline: int = 0
    response_time_baseline_ms: int = 0
    rate_limit_detected: bool = False
    framework_hints: list[str] = field(default_factory=list)
    waf_detected: str | None = None
    headers_baseline: dict[str, str] = field(default_factory=dict)
    error_signals_baseline: list[str] = field(default_factory=list)
    classification_confidence: float = 0.5
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Shape detection
# ---------------------------------------------------------------------------

def _classify_static_extension(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXTS)


def _detect_shape(
    url: str, response: requests.Response | None,
    forms: list[dict[str, Any]] | None,
    has_openapi: bool,
) -> tuple[str, float]:
    """Return (shape, confidence)."""
    path_lower = urlparse(url).path.lower()

    # Static asset by extension is the most certain match
    if _classify_static_extension(url):
        return "static", 0.99

    # GraphQL by path convention is high confidence
    if any(h in path_lower for h in _GRAPHQL_HINTS):
        return "graphql", 0.9

    # Inspect response (if supplied)
    if response is not None:
        ctype = (response.headers.get("Content-Type") or "").lower()
        body_sample = (response.text or "")[:4000].lower()

        if "application/json" in ctype:
            return "json", 0.9
        if "application/graphql" in ctype:
            return "graphql", 0.95
        if "multipart/form-data" in ctype:
            return "multipart", 0.95
        if "application/grpc" in ctype:
            return "grpc", 0.99
        if "application/xml" in ctype or "text/xml" in ctype:
            return "xml", 0.9
        if "text/html" in ctype:
            # Form when the HTML contains a <form> the discovery layer
            # surfaced or the body shows it.
            if (forms and len(forms) > 0) or "<form" in body_sample:
                return "form", 0.85
            return "form", 0.4  # HTML without forms — could still POST, low conf
        if "text/plain" in ctype:
            # Plain text: weak — guess by body
            if body_sample.startswith("{") or body_sample.startswith("["):
                return "json", 0.5
            return "unknown", 0.3
        if ctype.startswith(("image/", "audio/", "video/", "font/")):
            return "static", 0.95

    # URL-pattern hints when no response is available
    if any(h in path_lower for h in ("/api/", "/v1/", "/v2/", "/rest/")):
        return "json", 0.5  # API-shaped URL likely returns JSON
    if has_openapi:
        return "json", 0.6

    # Forms surfaced by katana even without response
    if forms:
        for f in forms:
            if str(f.get("action") or "").rstrip("/") == url.rstrip("/"):
                return "form", 0.7

    return "unknown", 0.2


# ---------------------------------------------------------------------------
# Endpoint-class detection
# ---------------------------------------------------------------------------

def _detect_endpoint_class(url: str, shape: str) -> tuple[str, float]:
    """Return (class, confidence).

    Match priority:
      1. Static-asset shape → static-asset (terminal)
      2. URL-substring patterns (destructive > admin > auth > upload > ...)
      3. REST-detail / REST-list pattern (default for API URLs)
      4. generic (fallback)
    """
    if shape == "static":
        return "static-asset", 0.99

    path = urlparse(url).path.lower()

    # Substring rules (ordered — earlier wins)
    for cls, patterns in _CLASS_PATTERNS:
        if any(p in path for p in patterns):
            return cls, 0.8

    # REST conventions — detail-form (with ID) vs list-form
    if _REST_DETAIL_RE.search(path):
        return "api-detail", 0.7
    if _REST_LIST_RE.search(path) and (shape == "json" or "/api/" in path):
        return "api-list", 0.65

    return "generic", 0.4


# ---------------------------------------------------------------------------
# Framework + WAF fingerprinting
# ---------------------------------------------------------------------------

def _match_fingerprints(
    headers: dict[str, str], body: str,
    catalog: list[tuple[str, dict[str, re.Pattern[str]], re.Pattern[str] | None]],
) -> list[str]:
    """Return list of matched names from the catalog."""
    matched: list[str] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for name, hdr_pats, body_pat in catalog:
        hdr_hit = False
        for h_name, regex in hdr_pats.items():
            h_val = lower_headers.get(h_name.lower(), "")
            if h_val and regex.search(h_val):
                hdr_hit = True
                break
        body_hit = bool(body_pat and body and body_pat.search(body))
        if hdr_hit or body_hit:
            matched.append(name)
    return matched


def _detect_frameworks(response: requests.Response | None) -> list[str]:
    if response is None:
        return []
    return _match_fingerprints(
        dict(response.headers),
        (response.text or "")[:8000],
        _FRAMEWORK_FINGERPRINTS,
    )


def _detect_waf(response: requests.Response | None) -> str | None:
    if response is None:
        return None
    matches = _match_fingerprints(
        dict(response.headers),
        (response.text or "")[:4000],
        _WAF_FINGERPRINTS,
    )
    return matches[0] if matches else None


# ---------------------------------------------------------------------------
# Auth-required probe + baseline metrics
# ---------------------------------------------------------------------------

def _normalize_response_shape(response: requests.Response) -> str:
    ctype = (response.headers.get("Content-Type") or "").lower()
    if response.status_code in (301, 302, 303, 307, 308):
        return "redirect"
    if "application/json" in ctype:
        return "json"
    if "application/xml" in ctype or "text/xml" in ctype:
        return "xml"
    if "text/html" in ctype:
        return "html"
    if not response.content:
        return "empty"
    if ctype.startswith(("image/", "audio/", "video/", "font/", "application/octet-stream")):
        return "binary"
    return "unknown"


def _extract_error_signals(body: str) -> list[str]:
    found = []
    for token in _BASELINE_ERROR_TOKENS:
        if token in body:
            found.append(token)
    return found


def _probe_unauthenticated(
    url: str, timeout: int,
) -> requests.Response | None:
    """GET the URL with NO auth headers. Returns the response or None
    on connection error."""
    try:
        return requests.get(
            url, timeout=timeout, allow_redirects=False,
            headers={"User-Agent": "strix-classifier/1.0"},
        )
    except requests.RequestException:
        return None


def _probe_rate_limit(url: str, timeout: int) -> bool:
    """Fire N quick requests; return True if any returns 429/503 or
    a Retry-After header."""
    for _ in range(_RATE_LIMIT_PROBE_COUNT):
        try:
            r = requests.get(
                url, timeout=timeout, allow_redirects=False,
                headers={"User-Agent": "strix-classifier/1.0"},
            )
            if r.status_code in (429, 503):
                return True
            if r.headers.get("Retry-After"):
                return True
        except requests.RequestException:
            continue
    return False


def _headers_baseline_subset(response: requests.Response) -> dict[str, str]:
    """Capture a small, deterministic subset of response headers for
    the diff verifier to use. Avoid full headers — they include
    request-id / timestamps that change per request."""
    keep = (
        "content-type", "server", "x-powered-by", "x-frame-options",
        "x-content-type-options", "x-xss-protection", "strict-transport-security",
        "access-control-allow-origin", "set-cookie",
    )
    lower = {k.lower(): v for k, v in response.headers.items()}
    return {k: lower[k] for k in keep if k in lower}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_endpoint(
    url: str,
    *,
    response: requests.Response | None = None,
    forms: list[dict[str, Any]] | None = None,
    has_openapi: bool = False,
    methods: list[str] | None = None,
    probe_if_no_response: bool = True,
    probe_rate_limit: bool = False,
    timeout: int = _PROBE_TIMEOUT_S,
) -> EndpointProfile:
    """Build an EndpointProfile for `url`.

    Args:
        url: target URL (full http(s) URL).
        response: optional pre-fetched response. When supplied, used
            for shape / framework / WAF / baseline detection without
            a fresh request.
        forms: optional list of forms (from `crawl_with_katana`'s
            forms[] output) — used as a hint when no response is
            present.
        has_openapi: True if an OpenAPI/Swagger spec was discovered
            for the target.
        methods: HTTP methods observed for this endpoint (e.g. from
            crawl). Drives `idempotent` flag.
        probe_if_no_response: when True (default) and `response` is
            None, fire a single GET to populate baseline. Set False
            for offline / read-only analysis.
        probe_rate_limit: when True, additionally fire a 5-request
            burst to detect rate-limiting. Default False (skip — this
            doubles probe cost; do it only when called explicitly).
        timeout: per-request timeout seconds.

    Returns:
        `EndpointProfile`. Always non-None. `classification_confidence`
        is the rough average of the per-feature confidences.
    """
    if not url or not isinstance(url, str):
        return EndpointProfile(
            url=str(url or ""), shape="unknown", endpoint_class="generic",
            classification_confidence=0.0,
            notes=["empty url"],
        )

    notes: list[str] = []

    # Fetch response if not supplied
    if response is None and probe_if_no_response:
        t_start = time.monotonic()
        try:
            response = requests.get(
                url, timeout=timeout, allow_redirects=False,
                headers={"User-Agent": "strix-classifier/1.0"},
            )
            response_time_ms = int((time.monotonic() - t_start) * 1000)
        except requests.RequestException as e:
            notes.append(f"probe failed: {type(e).__name__}: {e}")
            response = None
            response_time_ms = 0
    else:
        response_time_ms = 0

    # ----- shape -----
    shape, shape_conf = _detect_shape(url, response, forms, has_openapi)

    # ----- class -----
    endpoint_class, class_conf = _detect_endpoint_class(url, shape)

    # ----- methods + idempotency -----
    methods = methods or []
    methods_normalized = sorted({m.upper() for m in methods}) or (["GET"] if response else [])
    unsafe_methods = {"POST", "PUT", "PATCH", "DELETE"}
    idempotent = not (set(methods_normalized) & unsafe_methods)

    # ----- auth, framework, WAF, baseline metrics -----
    auth_required: bool | None = None
    framework_hints: list[str] = []
    waf_detected: str | None = None
    expected_status = None
    response_shape = "unknown"
    response_size = 0
    headers_baseline: dict[str, str] = {}
    error_signals: list[str] = []

    if response is not None:
        expected_status = response.status_code
        response_shape = _normalize_response_shape(response)
        response_size = len(response.content or b"")
        framework_hints = _detect_frameworks(response)
        waf_detected = _detect_waf(response)
        headers_baseline = _headers_baseline_subset(response)
        body = (response.text or "")[:8000]
        error_signals = _extract_error_signals(body)

        if response.status_code in (401, 403):
            auth_required = True
        elif response.status_code in (200, 201, 204, 301, 302):
            auth_required = False

    # ----- rate-limit probe (optional, expensive) -----
    rate_limit_detected = False
    if probe_rate_limit:
        rate_limit_detected = _probe_rate_limit(url, timeout=timeout)
        if rate_limit_detected:
            notes.append("rate-limit detected during burst probe")

    # ----- overall confidence -----
    confidence = round((shape_conf + class_conf) / 2, 2)

    return EndpointProfile(
        url=url,
        shape=shape,
        endpoint_class=endpoint_class,
        methods=methods_normalized,
        auth_required=auth_required,
        idempotent=idempotent,
        expected_status=expected_status,
        response_shape=response_shape,
        response_size_baseline=response_size,
        response_time_baseline_ms=response_time_ms,
        rate_limit_detected=rate_limit_detected,
        framework_hints=framework_hints,
        waf_detected=waf_detected,
        headers_baseline=headers_baseline,
        error_signals_baseline=error_signals,
        classification_confidence=confidence,
        notes=notes,
    )


def classify_endpoints_batch(
    urls: list[str], **kwargs: Any,
) -> list[EndpointProfile]:
    """Convenience: classify many URLs sequentially. Order preserved.
    `kwargs` forwarded to `classify_endpoint`."""
    return [classify_endpoint(u, **kwargs) for u in urls]


__all__ = [
    "EndpointProfile",
    "classify_endpoint",
    "classify_endpoints_batch",
]
