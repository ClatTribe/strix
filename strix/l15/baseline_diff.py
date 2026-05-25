"""iter-29.2 — Baseline-and-diff verifier.

The standard false-positive failure mode for DAST is: a scanner sends a
payload, gets a 200 response with the word "SQL" in it (because the
page says "SQL Database Tutorial"), and reports a SQL injection.
Real bug hunters compare a CONTROL request to the PAYLOAD request:
the diff is what matters, not the payload response in isolation.

This module is the diff primitive. It takes two responses (or fires
both itself) and produces a `DiffSignal` with structured deltas the
specialists can score on.

**Why this is generic and not overfit:**

  * Diffs are computed on universal HTTP response signals: status,
    body length, body content hash, response time, new error tokens.
  * Error-token list comes from documented database / framework error
    strings (`SQLSTATE`, `mysql_`, `psql:`, `ORA-`, `Traceback`, ...).
  * Threshold defaults come from sqlmap / OWASP DAST best-practice docs
    (≥20% body-size delta, ≥3× time delta, new-error-token => signal).
  * No SUT-specific paths, payloads, or expected responses.

**Composes with iter-29.1 EndpointProfile.** The classifier produces
the baseline (status, size, error_signals, response_shape). The diff
verifier consumes that baseline and contrasts each new probe response
against it.

Pure-python, no docker tools.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import requests


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Error tokens that — if NEW in the payload response (i.e. not in
# baseline) — strongly indicate the payload triggered the vuln class
# the token belongs to. Sourced from each backend's documented error
# format. NOT SUT-specific.
ERROR_TOKEN_TO_VULN_CLASS: dict[str, str] = {
    # SQL injection — DB driver error leakage
    "SQLSTATE":         "sqli",
    "mysql_fetch_":     "sqli",
    "mysql_num_rows":   "sqli",
    "mysql_query":      "sqli",
    "PostgreSQL query failed":  "sqli",
    "psql:":            "sqli",
    "pg_query":         "sqli",
    "ORA-":             "sqli",
    "Oracle ODBC":      "sqli",
    "sqlite_master":    "sqli",
    "SQLite3::SQLException":  "sqli",
    "Microsoft OLE DB Provider": "sqli",
    "ODBC SQL Server Driver":   "sqli",
    "[SQL Server]":     "sqli",
    "Warning: mysqli":  "sqli",
    # Python framework tracebacks (SSTI / deserialization)
    "Traceback (most recent call last)": "code-exec",
    "jinja2.exceptions": "ssti",
    "TemplateSyntaxError": "ssti",
    "TemplateNotFound": "ssti",
    # Java tracebacks (deserialization / RCE)
    "java.lang.NullPointerException": "code-exec",
    "java.lang.ClassCastException":   "code-exec",
    "java.lang.NumberFormatException": "code-exec",
    "javax.servlet.ServletException": "code-exec",
    "<title>Whitelabel Error":        "code-exec",   # Spring default error page
    # Node / Express
    "ReferenceError:":  "code-exec",
    "SyntaxError:":     "code-exec",
    "TypeError:":       "code-exec",
    "at /node_modules/": "code-exec",
    # XXE / XML parsing errors
    "DOCTYPE":          "xxe",   # used in error responses on XML parse
    "ENTITY":           "xxe",
    "xml.etree":        "xxe",
    "SAXParseException": "xxe",
    # SSRF / file-access errors
    "ENOTFOUND":        "ssrf",
    "EHOSTUNREACH":     "ssrf",
    "ECONNREFUSED":     "ssrf",   # could also be code-exec
    # LDAP injection
    "LDAPException":    "ldap",
    "javax.naming.directory.": "ldap",
}


# iter-30.4 — Success-leak tokens: strings that, if present in
# payload response but NOT in baseline, indicate the payload TRIPPED
# the vuln (response leaked data or unlocked a session).
#
# Anti-overfit: each entry is a documented response artifact from
# Linux/UNIX file contents, well-known auth-response schemas, or
# standard application output. No SUT-specific values.
SUCCESS_TOKEN_TO_VULN_CLASS: dict[str, str] = {
    # /etc/passwd leak → path-traversal / LFI
    "root:x:0:0":           "path-traversal",
    "root:!:0:0":           "path-traversal",
    "daemon:x:1:1":         "path-traversal",
    "bin:x:1:1":            "path-traversal",
    "nobody:x:":            "path-traversal",
    # /etc/shadow leak (rarely readable but try anyway)
    "root:$1$":             "path-traversal",
    "root:$6$":             "path-traversal",
    # Windows host file or system info
    "[boot loader]":        "path-traversal",
    "[fonts]":              "path-traversal",
    "for 16-bit app support": "path-traversal",
    # Auth-bypass via SQLi-login — response now contains a token where
    # baseline (no-auth probe) didn't. Common API auth response shapes.
    # ONLY counted as a signal when token isn't in baseline.
    "\"access_token\"":     "sqli",  # OAuth-style auth response
    "\"accessToken\"":      "sqli",  # camelCase variant
    "\"id_token\"":         "sqli",  # OIDC
    "\"jwt\"":              "sqli",  # explicit JWT field
    "\"token\":\"eyJ":      "sqli",  # JWT prefix value (eyJ = base64 `{"`)
    "\"refresh_token\"":    "sqli",
    "\"refreshToken\"":     "sqli",
    # Command-injection success: command output structure
    "uid=0(root)":          "cmd-injection",
    "uid=1000":             "cmd-injection",
    "Linux ":               "cmd-injection",  # output of `uname -a`
    "Darwin Kernel":        "cmd-injection",
    # SSRF success: AWS / GCP / Azure IMDS response markers
    "ami-id":               "ssrf",  # AWS IMDS
    "instance-id":          "ssrf",
    "iam/security-credentials": "ssrf",
    "compute/v1/projects":  "ssrf",  # GCP IMDS
    # XXE / file read via XML entity
    "<!ENTITY":             "xxe",  # echo-back of the payload
}


# Default thresholds. From OWASP DAST playbook + sqlmap manual.
DEFAULT_SIZE_DELTA_PCT = 0.20         # ≥20% body length deviation = signal
DEFAULT_TIME_DELTA_MULT = 3.0         # ≥3× baseline response time = time-based signal
DEFAULT_TIME_DELTA_ABS_MS = 2000      # AND ≥2s absolute (so a 10ms→40ms doesn't trip)
DEFAULT_PROBE_TIMEOUT_S = 8


# ---------------------------------------------------------------------------
# DiffSignal — the verifier's output shape
# ---------------------------------------------------------------------------

@dataclass
class DiffSignal:
    """Structured comparison of payload-response vs baseline.

    Specialists consume this to decide:
      * `score` >= 0.5 → emit a finding
      * `score` >= 0.8 → emit with confidence=verified
      * `score` <  0.5 → discard
    """
    status_delta: int = 0                    # payload_status - baseline_status
    size_delta_pct: float = 0.0              # (payload_size - baseline_size) / max(baseline_size, 1)
    time_delta_ms: int = 0                   # payload_time - baseline_time
    time_ratio: float = 1.0                  # payload_time / max(baseline_time, 1)
    body_hash_changed: bool = False
    new_error_tokens: list[str] = field(default_factory=list)
    new_error_classes: list[str] = field(default_factory=list)  # classified vuln types
    new_success_tokens: list[str] = field(default_factory=list)  # iter-30.4
    new_success_classes: list[str] = field(default_factory=list)  # iter-30.4
    status_class_changed: bool = False       # 2xx -> 4xx etc.
    redirect_target_changed: bool = False

    # Signal score derived from the above. Set by `score_signal()`.
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Diff math
# ---------------------------------------------------------------------------

def _status_class(status: int) -> int:
    """Return status class (200→2, 404→4) — used for "did the response
    semantically change" check."""
    return status // 100


def _body_hash(content: bytes) -> str:
    """Stable hash for body-identity comparison. Truncated for log
    payload sanity."""
    return hashlib.sha256(content or b"").hexdigest()[:16]


def _find_new_error_tokens(
    baseline_body: str, payload_body: str,
) -> tuple[list[str], list[str]]:
    """Return (new_tokens, new_vuln_classes) — tokens that appear in
    payload_body but NOT in baseline_body."""
    new_tokens: list[str] = []
    new_classes: set[str] = set()
    for token, cls in ERROR_TOKEN_TO_VULN_CLASS.items():
        if token in payload_body and token not in baseline_body:
            new_tokens.append(token)
            new_classes.add(cls)
    return new_tokens, sorted(new_classes)


def _find_new_success_tokens(
    baseline_body: str, payload_body: str,
) -> tuple[list[str], list[str]]:
    """iter-30.4 — Return (new_tokens, new_vuln_classes) for SUCCESS-
    leak tokens (auth-bypass JWT, /etc/passwd leak, IMDS markers, etc.)
    that appear in payload but NOT baseline."""
    new_tokens: list[str] = []
    new_classes: set[str] = set()
    for token, cls in SUCCESS_TOKEN_TO_VULN_CLASS.items():
        if token in payload_body and token not in baseline_body:
            new_tokens.append(token)
            new_classes.add(cls)
    return new_tokens, sorted(new_classes)


def diff_responses(
    baseline: dict[str, Any],
    payload: dict[str, Any],
    *,
    size_delta_pct_threshold: float = DEFAULT_SIZE_DELTA_PCT,
    time_delta_mult_threshold: float = DEFAULT_TIME_DELTA_MULT,
    time_delta_abs_ms_threshold: int = DEFAULT_TIME_DELTA_ABS_MS,
) -> DiffSignal:
    """Compare two response captures, return a structured signal.

    Each `baseline` / `payload` dict has shape:
        {
          "status": int,
          "size": int,
          "time_ms": int,
          "body": str,                  # head, ≤16KB
          "body_hash": str | None,       # optional precomputed
          "location": str | None,        # Location header on redirects
        }

    Independent of how the requests were actually fired — callers may
    fire them themselves and just pass the dicts here.
    """
    b_status = int(baseline.get("status") or 0)
    p_status = int(payload.get("status") or 0)
    b_size = int(baseline.get("size") or 0)
    p_size = int(payload.get("size") or 0)
    b_time = int(baseline.get("time_ms") or 0)
    p_time = int(payload.get("time_ms") or 0)
    b_body = str(baseline.get("body") or "")
    p_body = str(payload.get("body") or "")
    b_loc = str(baseline.get("location") or "")
    p_loc = str(payload.get("location") or "")
    b_hash = str(baseline.get("body_hash") or _body_hash(b_body.encode("utf-8", errors="ignore")))
    p_hash = str(payload.get("body_hash") or _body_hash(p_body.encode("utf-8", errors="ignore")))

    sig = DiffSignal(
        status_delta=p_status - b_status,
        size_delta_pct=(
            (p_size - b_size) / max(b_size, 1) if b_size or p_size else 0.0
        ),
        time_delta_ms=p_time - b_time,
        time_ratio=(p_time / max(b_time, 1)) if b_time else (1.0 if not p_time else float("inf")),
        body_hash_changed=(b_hash != p_hash),
        status_class_changed=(_status_class(b_status) != _status_class(p_status)),
        redirect_target_changed=bool(b_loc != p_loc and (b_loc or p_loc)),
    )

    new_tokens, new_classes = _find_new_error_tokens(b_body, p_body)
    sig.new_error_tokens = new_tokens
    sig.new_error_classes = new_classes

    succ_tokens, succ_classes = _find_new_success_tokens(b_body, p_body)
    sig.new_success_tokens = succ_tokens
    sig.new_success_classes = succ_classes

    return score_signal(
        sig,
        size_delta_pct_threshold=size_delta_pct_threshold,
        time_delta_mult_threshold=time_delta_mult_threshold,
        time_delta_abs_ms_threshold=time_delta_abs_ms_threshold,
    )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_signal(
    sig: DiffSignal,
    *,
    size_delta_pct_threshold: float = DEFAULT_SIZE_DELTA_PCT,
    time_delta_mult_threshold: float = DEFAULT_TIME_DELTA_MULT,
    time_delta_abs_ms_threshold: int = DEFAULT_TIME_DELTA_ABS_MS,
) -> DiffSignal:
    """Compute `sig.score` from the populated delta fields. Mutates in
    place + returns.

    Score model (additive, capped at 1.0):
      + 0.5  new error token classified (strongest signal — backend
             literally told us what broke)
      + 0.3  status class changed (2xx → 5xx is suspicious)
      + 0.3  abnormal time delta — time-based blind injection
      + 0.2  body-size deviation past threshold
      + 0.2  redirect-target changed (open redirect / auth bypass)
      + 0.1  body-hash changed but size similar (subtle echo)
    """
    score = 0.0
    reasons: list[str] = []

    # Error-token signal — strongest because backend literally told us
    if sig.new_error_classes:
        score += 0.5
        reasons.append(
            f"new error token(s) {sig.new_error_tokens[:3]} → class(es) {sig.new_error_classes}"
        )

    # iter-30.4 — Success-leak signal — same strength as error (the
    # payload made the SUT leak something / unlock something it
    # shouldn't have). e.g. /etc/passwd contents, JWT in response,
    # IMDS metadata.
    if sig.new_success_classes:
        score += 0.5
        reasons.append(
            f"success-leak token(s) {sig.new_success_tokens[:3]} → "
            f"class(es) {sig.new_success_classes}"
        )

    # Status-class change — 2xx → 5xx is suspicious (we likely broke the parser)
    if sig.status_class_changed:
        score += 0.3
        reasons.append(f"status class changed (delta={sig.status_delta:+d})")

    # Time-based — must clear both abs and mult thresholds (no 10ms→50ms FPs)
    if (
        sig.time_ratio >= time_delta_mult_threshold
        and sig.time_delta_ms >= time_delta_abs_ms_threshold
    ):
        score += 0.3
        reasons.append(
            f"time-based signal: ratio={sig.time_ratio:.1f}x, +{sig.time_delta_ms}ms"
        )

    # Body size deviation
    if abs(sig.size_delta_pct) >= size_delta_pct_threshold:
        score += 0.2
        reasons.append(f"body size delta {sig.size_delta_pct*100:+.1f}%")

    # Redirect change (relevant for open-redirect / auth-bypass)
    if sig.redirect_target_changed:
        score += 0.2
        reasons.append("redirect target changed")

    # Body hash diff with no size diff — subtle change (echo, value substitution)
    if sig.body_hash_changed and abs(sig.size_delta_pct) < 0.05:
        score += 0.1
        reasons.append("body content changed without size change")

    sig.score = round(min(score, 1.0), 2)
    sig.reasons = reasons
    return sig


# ---------------------------------------------------------------------------
# Convenience: fire-and-diff
# ---------------------------------------------------------------------------

def _capture(
    url: str, method: str = "GET", *,
    json: Any | None = None, data: Any | None = None,
    headers: dict[str, str] | None = None, timeout: int = DEFAULT_PROBE_TIMEOUT_S,
) -> dict[str, Any]:
    """Fire a request, return a response-capture dict suitable for
    `diff_responses`."""
    t0 = time.monotonic()
    try:
        r = requests.request(
            method=method, url=url,
            json=json, data=data,
            headers=headers or {}, timeout=timeout,
            allow_redirects=False,
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        body = (r.text or "")[:16384]
        return {
            "status": r.status_code,
            "size": len(r.content or b""),
            "time_ms": elapsed_ms,
            "body": body,
            "body_hash": _body_hash((r.content or b"")[:16384]),
            "location": r.headers.get("Location") or "",
        }
    except requests.RequestException as e:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return {
            "status": 0, "size": 0, "time_ms": elapsed_ms,
            "body": f"__REQUEST_FAILED__:{type(e).__name__}",
            "body_hash": "", "location": "",
        }


# ---------------------------------------------------------------------------
# iter-30.5 — Benign-shape control payload generator.
#
# The original `fire_and_diff` sent a no-body baseline on POST/PUT/PATCH.
# Servers reject a missing body as a 400 "missing required field" /
# "invalid JSON" — and the attack payload (e.g. a SQLi string) ALSO
# gets rejected as malformed. Both responses are 400 with identical
# error envelopes → diff sees zero signal → finding gets dismissed.
#
# Fix: when the caller knows the endpoint's wire shape (from iter-29.1
# EndpointClassifier), generate a SHAPE-MATCHED BENIGN control body
# that the server WILL accept. The diff is then "what the server does
# when given benign-shaped input" vs "what it does when given attack-
# shaped input", which is the actual signal.
#
# This is shape-aware (json / form / multipart / graphql / xml) but
# NEVER endpoint-content-specific. The benign VALUE is always a safe
# placeholder string ("benign") that contains no SQL syntax / shell
# metachars / template tokens / XSS payload tokens.
# ---------------------------------------------------------------------------

# Benign placeholder value. Chosen to be:
#   - non-empty (won't trip "required field" gates)
#   - alphabetic (won't trip integer-only field parsers; we'd rather
#     get a 422 type mismatch than have the server interpret the
#     value as data)
#   - free of any character that's part of an attack alphabet:
#     no quotes / brackets / backticks / dollar / hash / angle / etc.
_BENIGN_VALUE = "benign"
_BENIGN_FALLBACK_PARAM = "q"


def generate_benign_control(
    shape: str | None,
    method: str,
    params: list[str] | None = None,
) -> dict[str, Any] | None:
    """Build a shape-matched benign-control kwargs dict suitable for
    `fire_and_diff(..., control_payload=...)`.

    Returns None when:
      - shape is None / unknown — caller should fall back to no-body
      - method is read-only (GET/HEAD/OPTIONS) — no body needed

    The returned dict mirrors the shape produced by the dispatcher's
    `_build_attack_kwargs_for_shape` so the diff is comparing
    same-shape requests with different values.
    """
    m = (method or "GET").upper()
    if m not in ("POST", "PUT", "PATCH"):
        return None  # no body needed; caller's no-body baseline is fine

    s = (shape or "").strip().lower()
    fields = [p for p in (params or []) if isinstance(p, str) and p] or [_BENIGN_FALLBACK_PARAM]

    if s == "json":
        return {"json": {p: _BENIGN_VALUE for p in fields}}

    if s in ("form", "multipart"):
        return {"data": {p: _BENIGN_VALUE for p in fields}}

    if s == "graphql":
        # Minimal benign query that's syntactically valid GraphQL.
        # No introspection, no field access — server returns either
        # a parse-error (if it doesn't accept this query) or an empty
        # data block. Either way the diff against the attack payload
        # is meaningful.
        return {"json": {
            "query": "query { __typename }",
        }}

    if s == "xml":
        # Minimal well-formed XML envelope. Most XML APIs will reject
        # this as "not the expected schema" with a structured error —
        # which still differs from how they respond to an XXE-shaped
        # attack body.
        return {
            "data": f"<request><value>{_BENIGN_VALUE}</value></request>",
            "headers_override": {"Content-Type": "application/xml"},
        }

    # Unknown shape → no benign control (let caller fall back).
    return None


def fire_and_diff(
    url: str,
    *,
    method: str = "GET",
    control_payload: dict[str, Any] | None = None,
    attack_payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_PROBE_TIMEOUT_S,
    # iter-30.5 — endpoint metadata for auto-generating a benign
    # control body on POST/PUT/PATCH when the caller didn't supply
    # one. shape is from iter-29.1 EndpointClassifier; params are
    # the known body-field names.
    shape: str | None = None,
    params: list[str] | None = None,
) -> DiffSignal:
    """End-to-end helper: fire CONTROL request → fire ATTACK request →
    diff → score.

    `control_payload` and `attack_payload` are kwargs forwarded to the
    second/third positional `_capture()` call:
        {"json": {...}} or {"data": {...}}

    Control-body resolution order:
      1. `control_payload` (caller-supplied) — used as-is
      2. `shape` is supplied + method is POST/PUT/PATCH — auto-generate
         a benign-shape control via `generate_benign_control`. (iter-30.5)
      3. Fall back to a raw no-body baseline (the iter-29.2 default —
         right for GET baselines, fragile on POST where the server
         rejects no-body as malformed).
    """
    if control_payload is None and shape:
        control_payload = generate_benign_control(shape, method, params)

    if control_payload is None:
        baseline = _capture(url, method, headers=headers, timeout=timeout)
    else:
        # `headers_override` (set by XML benign control) merges into headers
        ctrl_kwargs = dict(control_payload)
        ctrl_headers_override = ctrl_kwargs.pop("headers_override", None)
        merged_headers = dict(headers or {})
        if isinstance(ctrl_headers_override, dict):
            merged_headers.update(ctrl_headers_override)
        baseline = _capture(
            url, method, headers=merged_headers or None,
            timeout=timeout, **ctrl_kwargs,
        )
    payload = _capture(url, method, headers=headers, timeout=timeout, **attack_payload)
    return diff_responses(baseline, payload)


__all__ = [
    "DiffSignal",
    "ERROR_TOKEN_TO_VULN_CLASS",
    "SUCCESS_TOKEN_TO_VULN_CLASS",
    "DEFAULT_SIZE_DELTA_PCT",
    "DEFAULT_TIME_DELTA_MULT",
    "DEFAULT_TIME_DELTA_ABS_MS",
    "diff_responses",
    "fire_and_diff",
    "generate_benign_control",
    "score_signal",
]
