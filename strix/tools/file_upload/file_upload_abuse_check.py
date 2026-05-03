"""File-upload abuse harness.

For a known multipart upload endpoint, iterates the classic
file-upload-bypass cohort and reports per-payload acceptance. This is
one of the highest-conversion finding types in real engagements:
extension-bypass / content-type-spoofing / magic-byte-spoofing
against upload endpoints that delegate validation to the wrong layer.

This tool is **invoked when the agent has already discovered an
upload endpoint**. It is not a crawler / discovery tool — the caller
provides the URL, the file form-field name, and any extra form
fields (CSRF token, document-type selector, etc.) needed for the
upload to validate.

Methodology (one HTTP request per probe, all bounded by `timeout`):

1. **Control upload** — `strix-<nonce>-control.jpg` (PNG magic bytes +
   tiny JFIF stub). Establishes the baseline: status, body length,
   body hash, response-body URL extraction. Lets every subsequent
   probe answer "did this look like the control was accepted?"
2. **Bypass cohort** — 13 deterministic payload mutations (see table
   below). Each carries the same `strix-<nonce>-` filename prefix so
   probe artifacts are auditable in target storage.
3. **Per-bypass verdict** — based on response status-class similarity
   to control + URL-extraction:
   - URL extracted matching `strix-<nonce>-` → fetch back, confirm
     content-match → **high** (CWE-434, unrestricted_upload).
   - Same status class as control + no URL extraction → **medium**
     CWE-434 (likely accepted, can't fetch-back-verify).
   - Different status class → no finding (server rejected).

Bypass cohort:

| Label | Filename | Body | Class |
|---|---|---|---|
| `php_extension`         | `<n>.php`              | PHP payload                    | extension switch |
| `phtml_extension`       | `<n>.phtml`            | PHP payload                    | extension switch |
| `jsp_extension`         | `<n>.jsp`              | JSP payload                    | extension switch |
| `aspx_extension`        | `<n>.aspx`             | ASP.NET payload                | extension switch |
| `php_with_image_magic`  | `<n>.php`              | PNG-magic + PHP payload        | magic-byte spoofing |
| `php_in_jpg_ext`        | `<n>.jpg`              | PHP payload (no magic)         | content-mismatch |
| `double_ext_php_jpg`    | `<n>.php.jpg`          | PHP payload                    | double extension |
| `double_ext_jpg_php`    | `<n>.jpg.php`          | PHP payload                    | double extension |
| `null_byte`             | `<n>.php\\x00.jpg`     | PHP payload                    | null-byte truncation |
| `alt_case_php`          | `<n>.PhP`              | PHP payload                    | case-sensitivity |
| `trailing_dot`          | `<n>.php.`             | PHP payload                    | filename normalization |
| `trailing_space`        | `<n>.php ` (trailing)  | PHP payload                    | filename normalization |
| `svg_with_script`       | `<n>.svg`              | SVG with `<script>`            | SVG XSS |
| `html_xss`              | `<n>.html`             | `<html>...<script>...</script>`| HTML XSS |
| `path_traversal`        | `../../../<n>.txt`     | benign text                    | filename injection |

Severity tuning:

- **High** (CWE-434, unrestricted_upload) — bypass payload accepted
  AND the uploaded artifact is fetchable AND its served Content-Type
  is dangerous (`application/x-php`, `application/x-httpd-php`,
  `text/html`, `text/x-php`, anything starting with `text/` for an
  `.svg` URL, etc.).
- **High** (CWE-434) — extension-switch bypass (`.php` / `.phtml` /
  `.jsp` / `.aspx`) accepted with same status as control even when
  fetch-back can't confirm (the extension is dangerous regardless of
  served content-type).
- **Medium** (CWE-434) — content-mismatch / double-extension /
  null-byte / case-variant accepted with same status as control but
  not fetch-back-confirmed.
- **Medium** (CWE-434) — SVG/HTML XSS payload accepted and served
  with `Content-Disposition: inline` or no disposition (XSS via
  same-origin asset).
- **Low** (CWE-434) — path-traversal filename accepted (weak
  filename validation; not directly exploitable but indicates poor
  hygiene).

Skip / soft-fail conditions:

- Control upload returns non-2xx — endpoint validation requires
  fields we don't have; tool exits gracefully with `inconclusive`.
- Cluster-A `--exclude-path` blocks the upload URL → skip with
  graceful no-op.
- Fetch-back URL extraction yields nothing → fall back to
  status-class comparison only.

Safety:

- Every uploaded artifact has a unique `strix-<nonce>-` filename
  prefix so probe traffic in target storage is auditable + cleanable.
- Payload bodies all start with a clear test-artifact marker (e.g.
  `<?php /* strix file-upload-abuse-check probe — safe to delete */ ?>`).
- Payload size hard-capped at 4 KiB per probe — no DoS, no
  decompression-bomb risk.
- Read-only verification fetch-back: GET the URL extracted from the
  upload response, never executes the artifact.
- Composes with cluster-A safety (auth-injection / exclude-path /
  rate-limit) — every fetch routes through `proxy_manager` /
  `http_safety` direct fallback.

Each finding carries `description_plain` + `recommended_action` (the
§11 non-tech UX fields) — recommends the universal fix: validate file
contents server-side (libmagic / file-type sniffing) rather than
trusting filename or Content-Type; serve uploaded files from a
sandboxed origin (different domain, no script execution); set
`Content-Disposition: attachment` on download endpoints; rename
files server-side with a controlled extension.

`verification_status=needs_review` on every finding because the
heuristic relies on response-shape similarity to control + best-effort
fetch-back. The agent should manually trigger the uploaded payload
(visit the URL, check whether the server executes / renders it) to
confirm exploitability before treating any finding as a confirmed
RCE / XSS.
"""

from __future__ import annotations

import logging
import re
import secrets
from typing import Any
from urllib.parse import urlparse, urljoin

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "file_upload_abuse_check"
_DEFAULT_TIMEOUT = 30.0
_MAX_PAYLOAD_BYTES = 4 * 1024
_MAX_RESPONSE_SCAN = 256 * 1024
_BODY_LEN_TOLERANCE_PCT = 25.0  # control ≈ probe within ±25% body length

# Marker prefix for every probe artifact. The nonce is regenerated per
# scan so probes from one run never collide with another.
_PROBE_PREFIX = "strix"

# PNG magic bytes + minimal valid IHDR/IEND chunks — small JPEG-replacement
# image used as the control body. Real servers that sniff via libmagic
# should accept this as image/png.
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_PNG_TINY = (
    _PNG_MAGIC
    + b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    + b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)

# Test-artifact markers — clearly identify probe artifacts as test
# probes, never as real exploit payloads. The agent / target operator
# can find and delete them post-scan.
_PHP_TEST_BODY = (
    b"<?php\n"
    b"/* strix file-upload-abuse-check probe artifact - safe to delete - "
    b"_NONCE_ */\n"
    b"echo 'strix-probe-marker-_NONCE_';\n"
    b"?>\n"
)
_JSP_TEST_BODY = (
    b"<%--\n"
    b"strix file-upload-abuse-check probe artifact - safe to delete - _NONCE_\n"
    b"--%>\n"
    b"<% out.print(\"strix-probe-marker-_NONCE_\"); %>\n"
)
_ASPX_TEST_BODY = (
    b"<%@ Page Language=\"C#\" %>\n"
    b"<%-- strix file-upload-abuse-check probe artifact - safe to delete - _NONCE_ --%>\n"
    b"<% Response.Write(\"strix-probe-marker-_NONCE_\"); %>\n"
)
_SVG_XSS_BODY = (
    b"<?xml version=\"1.0\" standalone=\"no\"?>\n"
    b"<!-- strix file-upload-abuse-check probe artifact - safe to delete - _NONCE_ -->\n"
    b"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1\" height=\"1\">\n"
    b"  <script type=\"text/javascript\">/* strix probe _NONCE_ */</script>\n"
    b"</svg>\n"
)
_HTML_XSS_BODY = (
    b"<!doctype html>\n"
    b"<!-- strix file-upload-abuse-check probe artifact - safe to delete - _NONCE_ -->\n"
    b"<html><body><script>/* strix probe _NONCE_ */</script></body></html>\n"
)
_PLAIN_BENIGN_BODY = (
    b"strix file-upload-abuse-check probe artifact - safe to delete - _NONCE_\n"
)


# Dangerous Content-Types when serving a user-uploaded file from the
# same origin without `Content-Disposition: attachment`. Hits flag the
# response as "uploaded artifact served as code".
_DANGEROUS_SERVED_CTYPES = (
    "application/x-php",
    "application/x-httpd-php",
    "application/x-httpd-php-source",
    "text/x-php",
    "application/x-asp",
    "application/x-jsp",
    "text/html",  # HTML/SVG XSS lives here when no attachment disposition
    "application/xhtml+xml",
)

# Server-executable extensions. Bypass into one of these is treated as
# high regardless of fetch-back outcome (the extension implies the
# served code path).
_EXECUTABLE_EXTENSIONS = ("php", "phtml", "phar", "phps", "jsp", "jspx", "asp", "aspx", "cfm")


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_post_multipart(
    url: str,
    *,
    body: bytes,
    boundary: str,
    extra_headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """POST a pre-built multipart body via cluster-A safety.

    Returns {status, headers, body, error?, skipped?}.
    """
    headers = dict(extra_headers or {})
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"

    # Cluster-A: exclude-path and rate-limit before any send.
    try:
        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            is_path_excluded,
            throttle_for_rate_limit,
        )
    except Exception:  # noqa: BLE001
        inject_auth_headers = None  # type: ignore[assignment]
        is_path_excluded = None  # type: ignore[assignment]
        throttle_for_rate_limit = None  # type: ignore[assignment]

    if is_path_excluded is not None:
        excluded, matched = is_path_excluded(url)
        if excluded:
            return {"status": 0, "headers": {}, "body": "", "skipped": True,
                    "skipped_reason": f"excluded by --exclude-path: {matched or ''}"}
    if throttle_for_rate_limit is not None:
        throttle_for_rate_limit()
    if inject_auth_headers is not None:
        headers = inject_auth_headers(headers)

    # Use httpx directly for byte-exact body control (proxy_manager.send_simple_request
    # accepts `body: str` which would re-encode our bytes).
    try:
        import httpx
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": f"httpx import failed: {e}"}

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.post(url, content=body, headers=headers)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_RESPONSE_SCAN],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _http_get(
    url: str, *, timeout: float = _DEFAULT_TIMEOUT
) -> dict[str, Any]:
    """GET via cluster-A safety. Used for fetch-back verification."""
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, timeout=int(timeout))
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": r.get("body") or "",
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)
    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            is_path_excluded,
            throttle_for_rate_limit,
        )

        excluded, _ = is_path_excluded(url)
        if excluded:
            return {"status": 0, "headers": {}, "body": "", "skipped": True}
        merged = inject_auth_headers({})
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_RESPONSE_SCAN],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Multipart body builder (byte-exact filename control)
# ---------------------------------------------------------------------------


def _build_multipart(
    *,
    boundary: str,
    field_name: str,
    filename: str,
    file_content_type: str,
    file_body: bytes,
    extra_fields: dict[str, str] | None = None,
) -> bytes:
    """Build a multipart/form-data body byte-exact.

    Filename is inserted verbatim — null bytes, trailing spaces,
    encoded slashes all round-trip into the wire bytes.
    """
    parts: list[bytes] = []
    extra_fields = extra_fields or {}

    # File part
    parts.append(f"--{boundary}\r\n".encode("ascii"))
    parts.append(
        f"Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\n".encode("latin-1")
    )
    parts.append(f"Content-Type: {file_content_type}\r\n\r\n".encode("ascii"))
    parts.append(file_body)
    parts.append(b"\r\n")

    # Extra fields
    for k, v in extra_fields.items():
        parts.append(f"--{boundary}\r\n".encode("ascii"))
        parts.append(
            f"Content-Disposition: form-data; name=\"{k}\"\r\n\r\n".encode("latin-1")
        )
        parts.append(v.encode("utf-8", errors="replace"))
        parts.append(b"\r\n")

    parts.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Probe cohort
# ---------------------------------------------------------------------------


def _build_probes(nonce: str) -> list[dict[str, Any]]:
    """Generate the bypass cohort. Each probe specifies filename, body,
    content-type, and a class label."""

    php = _PHP_TEST_BODY.replace(b"_NONCE_", nonce.encode("ascii"))
    jsp = _JSP_TEST_BODY.replace(b"_NONCE_", nonce.encode("ascii"))
    aspx = _ASPX_TEST_BODY.replace(b"_NONCE_", nonce.encode("ascii"))
    svg = _SVG_XSS_BODY.replace(b"_NONCE_", nonce.encode("ascii"))
    html = _HTML_XSS_BODY.replace(b"_NONCE_", nonce.encode("ascii"))
    benign = _PLAIN_BENIGN_BODY.replace(b"_NONCE_", nonce.encode("ascii"))

    n = f"{_PROBE_PREFIX}-{nonce}"

    probes = [
        {
            "label": "php_extension",
            "filename": f"{n}.php",
            "body": php,
            "content_type": "application/x-php",
            "class_": "extension_switch",
            "severity_if_accepted": "high",
        },
        {
            "label": "phtml_extension",
            "filename": f"{n}.phtml",
            "body": php,
            "content_type": "application/x-php",
            "class_": "extension_switch",
            "severity_if_accepted": "high",
        },
        {
            "label": "jsp_extension",
            "filename": f"{n}.jsp",
            "body": jsp,
            "content_type": "application/x-jsp",
            "class_": "extension_switch",
            "severity_if_accepted": "high",
        },
        {
            "label": "aspx_extension",
            "filename": f"{n}.aspx",
            "body": aspx,
            "content_type": "application/x-asp",
            "class_": "extension_switch",
            "severity_if_accepted": "high",
        },
        {
            "label": "php_with_image_magic",
            "filename": f"{n}.php",
            "body": _PNG_MAGIC + php,
            "content_type": "image/png",
            "class_": "magic_byte_spoofing",
            "severity_if_accepted": "high",
        },
        {
            "label": "php_in_jpg_ext",
            "filename": f"{n}.jpg",
            "body": php,
            "content_type": "image/jpeg",
            "class_": "content_mismatch",
            "severity_if_accepted": "medium",
        },
        {
            "label": "double_ext_php_jpg",
            "filename": f"{n}.php.jpg",
            "body": php,
            "content_type": "image/jpeg",
            "class_": "double_extension",
            "severity_if_accepted": "medium",
        },
        {
            "label": "double_ext_jpg_php",
            "filename": f"{n}.jpg.php",
            "body": php,
            "content_type": "application/x-php",
            "class_": "double_extension",
            "severity_if_accepted": "high",
        },
        {
            "label": "null_byte",
            "filename": f"{n}.php\x00.jpg",
            "body": php,
            "content_type": "image/jpeg",
            "class_": "byte_truncation",
            "severity_if_accepted": "medium",
        },
        {
            "label": "alt_case_php",
            "filename": f"{n}.PhP",
            "body": php,
            "content_type": "application/x-php",
            "class_": "case_variant",
            "severity_if_accepted": "medium",
        },
        {
            "label": "trailing_dot",
            "filename": f"{n}.php.",
            "body": php,
            "content_type": "application/x-php",
            "class_": "filename_normalization",
            "severity_if_accepted": "medium",
        },
        {
            "label": "trailing_space",
            "filename": f"{n}.php ",
            "body": php,
            "content_type": "application/x-php",
            "class_": "filename_normalization",
            "severity_if_accepted": "medium",
        },
        {
            "label": "svg_with_script",
            "filename": f"{n}.svg",
            "body": svg,
            "content_type": "image/svg+xml",
            "class_": "svg_xss",
            "severity_if_accepted": "medium",
        },
        {
            "label": "html_xss",
            "filename": f"{n}.html",
            "body": html,
            "content_type": "text/html",
            "class_": "html_xss",
            "severity_if_accepted": "medium",
        },
        {
            "label": "path_traversal",
            "filename": f"../../../{n}.txt",
            "body": benign,
            "content_type": "text/plain",
            "class_": "filename_injection",
            "severity_if_accepted": "low",
        },
    ]
    return probes


# ---------------------------------------------------------------------------
# Response helpers — URL extraction + cacheability
# ---------------------------------------------------------------------------


_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
_PATH_RE = re.compile(r"/[A-Za-z0-9._/\-+%]+")


def _extract_artifact_url(
    response_body: str, response_headers: dict[str, str], nonce: str, base_url: str
) -> str | None:
    """Best-effort: look for `strix-<nonce>` in the response body or
    `Location` header. Returns absolute URL or None."""
    needle = f"{_PROBE_PREFIX}-{nonce}"

    # Location header takes precedence — it's the canonical "where the
    # uploaded artifact landed" answer.
    location = response_headers.get("location")
    if location and needle in location:
        return urljoin(base_url, location)

    body = response_body or ""
    if not body or needle not in body:
        # Some servers strip the nonce from the response and only return
        # an opaque ID. We can't fetch-back without a URL — return None.
        return None

    # Find the closest URL/path containing the nonce in the body.
    for url_match in _URL_RE.finditer(body):
        if needle in url_match.group(0):
            return url_match.group(0)
    for path_match in _PATH_RE.finditer(body):
        if needle in path_match.group(0):
            return urljoin(base_url, path_match.group(0))
    return None


def _status_class(status: int) -> str:
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "unknown"


def _looks_like_acceptance(
    control: dict[str, Any], probe: dict[str, Any]
) -> bool:
    """Did the probe response shape match the control's? Same status-class
    + body-length within ±25% = accepted."""
    if probe.get("error"):
        return False
    c_class = _status_class(control.get("status", 0))
    p_class = _status_class(probe.get("status", 0))
    if c_class not in ("2xx", "3xx"):
        return False
    if p_class != c_class:
        return False
    c_len = len(control.get("body") or "")
    p_len = len(probe.get("body") or "")
    if c_len == 0 and p_len == 0:
        return True
    longer = max(c_len, p_len)
    shorter = min(c_len, p_len)
    return (shorter / longer if longer else 0.0) >= (1 - _BODY_LEN_TOLERANCE_PCT / 100.0)


def _filename_extension(filename: str) -> str:
    """Return last extension (lowercase, no dot). Treats null-byte as
    a terminator the same way most servers do."""
    if "\x00" in filename:
        filename = filename.split("\x00", 1)[0]
    filename = filename.rstrip(". ")
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    target: str,
    endpoint: str,
    description: str,
    description_plain: str,
    recommended_action: str,
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="unrestricted_upload",
        cwe="CWE-434",
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "Unrestricted file uploads enable remote-code-execution "
            "(server-side scripts in `.php` / `.jsp` / `.aspx`), stored "
            "XSS (HTML / SVG with `<script>` served same-origin without "
            "attachment disposition), client-side malware delivery, "
            "phishing-page hosting on a trusted domain, and server-side "
            "request forgery via processed image / archive parsing. "
            "It is one of the highest-conversion finding categories in "
            "real engagements."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
    )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    if t is None:
        return None
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME)


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is None:
        return
    t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


def _normalize_url(url: str) -> str | None:
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    if not url:
        return None
    if "://" not in url:
        url = f"https://{url}"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return url


@register_tool(sandbox_execution=True)
def file_upload_abuse_check(
    upload_url: str,
    field_name: str = "file",
    extra_fields: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe a known multipart upload endpoint for the upload-bypass cohort.

    Args:
        upload_url: The POST endpoint that accepts multipart/form-data
            uploads. Typically the agent has discovered this from the
            BFS crawl + form analysis. Bare hostnames are auto-prefixed
            with `https://`.
        field_name: The form field name for the uploaded file (default
            `file`). Common alternatives: `attachment`, `image`,
            `upload`, `avatar`, `document`.
        extra_fields: Additional form fields the endpoint requires
            (CSRF token, document-type selector, etc.). Pass these
            verbatim — they're round-tripped on every probe.
        timeout: Per-probe timeout in seconds (default 30, accounting
            for slow upload-processing back-ends).

    Returns:
        {
          success, upload_url, target_host, nonce,
          control: {status, body_length, accepted: bool, error?, skipped?},
          probes: [
            {label, class_, severity_if_accepted, filename, status,
             accepted, fetch_back: {url?, status?, content_type?,
             body_match?}, finding_severity, evidence},
            ...
          ],
          findings_emitted: int
        }

    Findings:
        - **High** (CWE-434, unrestricted_upload) — bypass into a
          server-executable extension (`.php`/`.phtml`/`.jsp`/`.aspx`)
          accepted; OR fetch-back-confirmed dangerous Content-Type.
        - **Medium** (CWE-434) — content-mismatch / double-extension /
          null-byte / case-variant / SVG/HTML XSS accepted, no
          fetch-back confirmation.
        - **Low** (CWE-434) — path-traversal filename accepted (weak
          filename validation; not directly exploitable but indicates
          poor hygiene).

    Notes:
        - Every probe artifact has a unique `strix-<nonce>-` filename
          prefix so traffic in target storage is auditable + cleanable.
        - Payload bodies all start with a clear test-artifact marker.
        - Hard-capped at 4 KiB per probe — no DoS / decompression-bomb
          risk.
        - Composes with cluster-A safety: `--exclude-path` /
          `--rate-limit` / `--auth-*` apply to every probe.
        - `verification_status=needs_review` — the agent should
          manually trigger any uploaded payload (visit the URL, check
          server execution / rendering) before treating findings as
          confirmed RCE / XSS.
    """
    target_url = _normalize_url(upload_url)
    if target_url is None:
        return {"success": False, "error": f"invalid upload_url: {upload_url!r}"}

    target_host = urlparse(target_url).hostname or ""
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {upload_url!r}"}

    extra_fields = extra_fields or {}
    nonce = secrets.token_hex(4)
    cev = _start_check("unrestricted_upload", target_host)

    # ---- Control upload ----
    boundary_ctrl = f"--StrixUploadControl{secrets.token_hex(8)}"
    control_body = _build_multipart(
        boundary=boundary_ctrl,
        field_name=field_name,
        filename=f"{_PROBE_PREFIX}-{nonce}-control.jpg",
        file_content_type="image/jpeg",
        file_body=_PNG_TINY,
        extra_fields=extra_fields,
    )
    control_response = _http_post_multipart(
        target_url, body=control_body, boundary=boundary_ctrl, timeout=timeout
    )

    if control_response.get("skipped"):
        _complete_check(cev, "inconclusive", "upload URL excluded by --exclude-path")
        return {
            "success": True,
            "upload_url": target_url,
            "target_host": target_host,
            "nonce": nonce,
            "control": {"skipped": True, "reason": control_response.get("skipped_reason")},
            "probes": [],
            "findings_emitted": 0,
        }

    control_status = control_response.get("status", 0)
    control_body_text = control_response.get("body") or ""
    control_summary = {
        "status": control_status,
        "status_class": _status_class(control_status),
        "body_length": len(control_body_text),
        "error": control_response.get("error"),
    }

    if control_status == 0 or _status_class(control_status) not in ("2xx", "3xx"):
        # Control rejected — endpoint validation requires fields we don't
        # have. Tool can't make per-bypass acceptance decisions.
        control_summary["accepted"] = False
        _complete_check(
            cev,
            "inconclusive",
            f"control upload rejected (status={control_status}); "
            f"endpoint may require extra fields not supplied",
        )
        return {
            "success": True,
            "upload_url": target_url,
            "target_host": target_host,
            "nonce": nonce,
            "control": control_summary,
            "probes": [],
            "findings_emitted": 0,
        }

    control_summary["accepted"] = True

    # ---- Bypass cohort ----
    findings_emitted = 0
    probe_results: list[dict[str, Any]] = []
    seen_finding_keys: set[tuple[str, str]] = set()

    for probe in _build_probes(nonce):
        body_size = len(probe["body"])
        if body_size > _MAX_PAYLOAD_BYTES:
            # Defensive cap — none of the canned bodies should hit this.
            probe["body"] = probe["body"][:_MAX_PAYLOAD_BYTES]

        boundary = f"--StrixUpload{secrets.token_hex(8)}"
        request_body = _build_multipart(
            boundary=boundary,
            field_name=field_name,
            filename=probe["filename"],
            file_content_type=probe["content_type"],
            file_body=probe["body"],
            extra_fields=extra_fields,
        )
        response = _http_post_multipart(
            target_url, body=request_body, boundary=boundary, timeout=timeout
        )

        if response.get("skipped"):
            probe_results.append({
                "label": probe["label"],
                "class_": probe["class_"],
                "severity_if_accepted": probe["severity_if_accepted"],
                "filename": probe["filename"],
                "status": 0,
                "accepted": False,
                "fetch_back": None,
                "finding_severity": None,
                "evidence": "skipped by cluster-A path filter",
            })
            continue

        accepted = _looks_like_acceptance(control_response, response)
        verdict: dict[str, Any] = {
            "label": probe["label"],
            "class_": probe["class_"],
            "severity_if_accepted": probe["severity_if_accepted"],
            "filename": probe["filename"],
            "status": response.get("status", 0),
            "accepted": accepted,
            "fetch_back": None,
            "finding_severity": None,
            "evidence": "",
        }

        if not accepted:
            verdict["evidence"] = (
                f"server rejected (status={response.get('status', 0)}, "
                f"body_len={len(response.get('body') or '')})"
            )
            probe_results.append(verdict)
            continue

        # ---- Fetch-back verification (best-effort) ----
        artifact_url = _extract_artifact_url(
            response.get("body") or "",
            response.get("headers") or {},
            nonce,
            target_url,
        )
        fetch_back: dict[str, Any] = {"url": artifact_url}
        if artifact_url:
            fb = _http_get(artifact_url, timeout=timeout)
            if fb.get("skipped"):
                fetch_back["status"] = 0
                fetch_back["content_type"] = None
                fetch_back["body_match"] = False
                fetch_back["skipped"] = True
            else:
                fetch_back["status"] = fb.get("status", 0)
                fb_headers = fb.get("headers") or {}
                fetch_back["content_type"] = fb_headers.get("content-type")
                fetch_back["disposition"] = fb_headers.get("content-disposition")
                # Match: server returned a body that contains our nonce
                # marker → the artifact is hosted.
                marker = f"{_PROBE_PREFIX}-{nonce}"
                fetch_back["body_match"] = (
                    marker in (fb.get("body") or "")
                    or "strix-probe-marker" in (fb.get("body") or "")
                )

        verdict["fetch_back"] = fetch_back

        # ---- Severity escalation rules ----
        sev = probe["severity_if_accepted"]
        evidence_parts = [
            f"server accepted (status={response.get('status', 0)}, "
            f"body_len={len(response.get('body') or '')})"
        ]

        # Escalate to high if fetch-back returns a dangerous Content-Type.
        if fetch_back.get("body_match"):
            served_ct = (fetch_back.get("content_type") or "").lower().split(";", 1)[0].strip()
            disposition = (fetch_back.get("disposition") or "").lower()
            evidence_parts.append(
                f"fetch-back confirmed (status={fetch_back.get('status')}, "
                f"content-type={served_ct or 'none'})"
            )
            if served_ct in _DANGEROUS_SERVED_CTYPES and "attachment" not in disposition:
                sev = "high"
                evidence_parts.append("served Content-Type is dangerous")

        # Path-traversal filenames are floor-level low even when accepted,
        # since the artifact may not be reachable.
        if probe["class_"] == "filename_injection" and not fetch_back.get("body_match"):
            sev = "low"

        verdict["finding_severity"] = sev
        verdict["evidence"] = "; ".join(evidence_parts)
        probe_results.append(verdict)

        # Per-class dedup so we don't emit 5 near-identical findings for
        # all 5 extension-switch variants.
        key = (sev, probe["class_"])
        if key in seen_finding_keys:
            continue
        seen_finding_keys.add(key)

        # ---- Emit finding ----
        ext = _filename_extension(probe["filename"])
        fb_url_text = fetch_back.get("url") or "<not extractable>"
        # Shared "server-executable extension accepted" copy. Reused by
        # both `extension_switch` and `double_extension`-with-exec-ext
        # branches; the title differs to keep findings distinct under
        # per-class dedup.
        _executable_ext_description_plain = (
            "Your upload endpoint accepts files with server-executable "
            "extensions (PHP / JSP / ASPX). If the upload directory is "
            "served by the application server (and not isolated), an "
            "attacker can upload code that executes on the server — "
            "remote code execution."
        )
        _executable_ext_recommended_action = (
            "Validate uploaded files server-side using a libmagic-style "
            "content sniff, not the client-supplied filename or "
            "Content-Type. Maintain an explicit allow-list of accepted "
            "extensions; reject everything else. Serve uploaded files "
            "from a separate sandboxed origin (e.g. `cdn.example.com` "
            "with no script execution) to defang any bypass that "
            "slips through."
        )

        if probe["class_"] == "extension_switch":
            title = (
                f"Unrestricted file upload — server-executable extension "
                f"`.{ext or 'unknown'}` accepted on {target_host}"
            )
            description_plain = _executable_ext_description_plain
            recommended_action = _executable_ext_recommended_action
        elif probe["class_"] == "double_extension" and ext in _EXECUTABLE_EXTENSIONS:
            title = (
                f"Unrestricted file upload — double-extension bypass "
                f"`.{ext}` accepted on {target_host}"
            )
            description_plain = _executable_ext_description_plain
            recommended_action = _executable_ext_recommended_action
        elif probe["class_"] == "magic_byte_spoofing":
            title = (
                f"Unrestricted file upload — magic-byte-spoofed payload "
                f"accepted on {target_host}"
            )
            description_plain = (
                "Your upload endpoint validates files by magic bytes (image "
                "header) but doesn't check the rest of the file. An attacker "
                "can prepend image headers to a script, bypass validation, "
                "and have the script execute as PHP/JSP/etc."
            )
            recommended_action = (
                "Validate file contents fully — not just the leading bytes. "
                "Maintain an explicit extension allow-list and reject any "
                "filename with a server-executable extension regardless of "
                "magic bytes. Re-encode images server-side (e.g. via "
                "ImageMagick / Pillow) to strip non-image content."
            )
        elif probe["class_"] in ("svg_xss", "html_xss"):
            title = (
                f"Stored XSS via uploaded `{ext}` accepted on {target_host}"
            )
            description_plain = (
                "Your upload endpoint accepts SVG / HTML files that contain "
                "JavaScript. If those files are served same-origin without "
                "`Content-Disposition: attachment`, any user that opens the "
                "URL gets the script run in their session — stored XSS."
            )
            recommended_action = (
                "Either: (a) reject SVG / HTML uploads entirely, OR (b) "
                "serve all uploads with `Content-Disposition: attachment` "
                "(force download), OR (c) serve them from a separate "
                "sandboxed origin (no auth cookies in scope). Re-encode "
                "SVG via a safe SVG library that strips `<script>` tags."
            )
        elif probe["class_"] == "filename_injection":
            title = f"Weak filename validation — path-traversal filename accepted on {target_host}"
            description_plain = (
                "Your upload endpoint stores files using the client-supplied "
                "filename. An attacker can include `../` to control where "
                "the file lands on disk, potentially overwriting application "
                "files or escaping the upload directory."
            )
            recommended_action = (
                "Generate filenames server-side with a controlled prefix + "
                "random ID. Never derive the storage path from "
                "client-supplied filename bytes. Strip / reject any "
                "filename containing path separators (`/`, `\\\\`, `..`) "
                "before validation."
            )
        else:
            title = (
                f"Unrestricted file upload — `{probe['class_']}` bypass "
                f"accepted on {target_host}"
            )
            description_plain = (
                "Your upload endpoint accepts a payload using a known "
                "bypass technique (filename / extension / content-type "
                "manipulation). An attacker who can upload arbitrary "
                "content via this endpoint has a foothold for stored XSS, "
                "phishing-page hosting, or — depending on the upload "
                "directory's execution rules — remote code execution."
            )
            recommended_action = (
                "Validate uploaded files server-side using libmagic-style "
                "content sniffing AND an extension allow-list AND a "
                "Content-Type allow-list. Rename files server-side with a "
                "controlled extension. Serve uploads from a sandboxed "
                "origin without script execution."
            )

        description = (
            f"Probe `{probe['label']}` (filename=`{probe['filename']}`) — "
            f"{verdict['evidence']}. Fetch-back URL: {fb_url_text}."
        )
        _emit_finding(
            title=title,
            severity=sev,
            target=target_host,
            endpoint=target_url,
            description=description,
            description_plain=description_plain,
            recommended_action=recommended_action,
        )
        findings_emitted += 1

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{findings_emitted} upload-bypass(es) on {target_host}",
    )

    return {
        "success": True,
        "upload_url": target_url,
        "target_host": target_host,
        "nonce": nonce,
        "control": control_summary,
        "probes": probe_results,
        "findings_emitted": findings_emitted,
    }
