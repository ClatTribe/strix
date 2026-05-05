"""`scan_misconfig` — first deterministic specialist-tool (roadmap
§8.5 Phase 1 / single-agent.md B.1).

Pure-Python misconfiguration analysis over an HTTP response. The lead
agent fetches the target URL via the primitive `send_request` tool,
then passes the (status, headers, [body_snippet]) to this specialist
for deterministic header / cookie / TLS-posture checks. No internal
LLM call — `llm=False`.

Why this is the first migration target:

  * Cheapest to implement (~150 lines of pure-Python).
  * No cache-manager dependency (Phase 2 not blocking).
  * Removes ~15-25% of LLM-driven coverage that should be deterministic.
  * Hermetic-testable end-to-end without network access.
  * Validates the §8.5 registry pattern with a minimal blast radius.

Coverage (subset of #110 dns_hygiene + existing
`http_security_headers_audit` — same checks, structured output):

  * **HSTS** — missing / weak max-age / no `includeSubDomains` /
    no `preload`.
  * **CSP** — missing entirely / `unsafe-inline` / `unsafe-eval` /
    missing `frame-ancestors`.
  * **X-Frame-Options** OR **frame-ancestors** — missing.
  * **X-Content-Type-Options** — missing or wrong.
  * **Referrer-Policy** — missing / unsafe-url.
  * **Permissions-Policy** — missing (info-level).
  * **Server / X-Powered-By** version disclosure — info-level.
  * **Set-Cookie** without `Secure` / `HttpOnly` / `SameSite`.

The specialist returns drafts, not finalised findings — the lead
converts via `emit_finding(...)` per draft. This preserves the lead's
control over what actually emits (eager-emit vs review-then-emit
per single-agent.md B.10).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


_HSTS_MIN_MAX_AGE_SECONDS = 6 * 30 * 24 * 60 * 60  # ~180 days; OWASP minimum
_HSTS_PREFERRED_MAX_AGE_SECONDS = 365 * 24 * 60 * 60  # 1 year


def _ci_get(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup. Returns the LAST matching
    value (HTTP allows duplicates; semantics depend on the header)."""
    if not isinstance(headers, dict):
        return None
    target = name.lower()
    last: str | None = None
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == target and isinstance(v, str):
            last = v
    return last


def _ci_get_all(headers: dict[str, str], name: str) -> list[str]:
    """All values for a (case-insensitive) header. Used for Set-Cookie
    which legitimately repeats."""
    if not isinstance(headers, dict):
        return []
    target = name.lower()
    out: list[str] = []
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == target and isinstance(v, str):
            out.append(v)
    return out


def _check_hsts(
    headers: dict[str, str], *, is_https: bool, endpoint: str,
) -> list[FindingDraft]:
    """HSTS missing / weak. Only emits when scheme is HTTPS — HSTS
    on plaintext HTTP is irrelevant (browsers ignore)."""
    if not is_https:
        return []
    raw = _ci_get(headers, "Strict-Transport-Security")
    if raw is None:
        return [FindingDraft(
            title="Missing Strict-Transport-Security header",
            severity="low",
            cwe="CWE-319",
            endpoint=endpoint,
            category="security_headers",
            description=(
                "The HTTPS response did not set a Strict-Transport-Security "
                "header. Without HSTS, attackers on a hostile network can "
                "downgrade the connection to HTTP via SSL-stripping. "
                "Recommended: `Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains; preload`."
            ),
            verification_status="pattern_match",
            confidence=0.95,
            reasoning_trace=[
                "GET response over HTTPS scheme observed",
                "Strict-Transport-Security header absent from response",
                "Without HSTS, downgrade to HTTP is possible on first visit",
            ],
        )]
    findings: list[FindingDraft] = []
    m = re.search(r"max-age\s*=\s*(\d+)", raw, re.IGNORECASE)
    max_age = int(m.group(1)) if m else None
    if max_age is None or max_age < _HSTS_MIN_MAX_AGE_SECONDS:
        findings.append(FindingDraft(
            title=f"HSTS max-age too low ({max_age!r}s)",
            severity="low",
            cwe="CWE-319",
            endpoint=endpoint,
            category="security_headers",
            description=(
                f"HSTS max-age={max_age!r} is below the OWASP-recommended "
                f"minimum of {_HSTS_MIN_MAX_AGE_SECONDS}s (~6 months). "
                f"Recommended: 1 year (31536000)."
            ),
            verification_status="pattern_match",
            confidence=0.9,
        ))
    if "includesubdomains" not in raw.lower():
        findings.append(FindingDraft(
            title="HSTS missing includeSubDomains",
            severity="info",
            cwe="CWE-319",
            endpoint=endpoint,
            category="security_headers",
            description=(
                "HSTS header lacks `includeSubDomains`. Subdomains can "
                "still be downgraded individually."
            ),
            verification_status="pattern_match",
            confidence=0.85,
        ))
    return findings


def _check_csp(headers: dict[str, str], *, endpoint: str) -> list[FindingDraft]:
    raw = _ci_get(headers, "Content-Security-Policy")
    if raw is None:
        return [FindingDraft(
            title="Missing Content-Security-Policy header",
            severity="medium",
            cwe="CWE-1021",
            endpoint=endpoint,
            category="security_headers",
            description=(
                "No CSP defined. The browser will not constrain script "
                "sources, frame ancestors, or other rendering decisions, "
                "amplifying any reflected-XSS class finding."
            ),
            verification_status="pattern_match",
            confidence=0.9,
            reasoning_trace=[
                "Response inspected; Content-Security-Policy absent",
                "CSP is the primary in-browser mitigation for XSS classes",
                "Absence elevates impact of any companion XSS finding",
            ],
        )]
    findings: list[FindingDraft] = []
    lower = raw.lower()
    if "unsafe-inline" in lower:
        findings.append(FindingDraft(
            title="CSP allows unsafe-inline",
            severity="low",
            cwe="CWE-1021",
            endpoint=endpoint,
            category="security_headers",
            description=(
                "CSP includes `unsafe-inline` in script-src or style-src. "
                "Inline JavaScript / CSS bypasses CSP's primary XSS "
                "mitigation. Recommended: nonce- or hash-based allow-list."
            ),
            verification_status="pattern_match",
            confidence=0.95,
        ))
    if "unsafe-eval" in lower:
        findings.append(FindingDraft(
            title="CSP allows unsafe-eval",
            severity="low",
            cwe="CWE-1021",
            endpoint=endpoint,
            category="security_headers",
            description="CSP includes `unsafe-eval`. eval()-class APIs bypass CSP.",
            verification_status="pattern_match",
            confidence=0.95,
        ))
    if "frame-ancestors" not in lower:
        findings.append(FindingDraft(
            title="CSP missing frame-ancestors directive",
            severity="info",
            cwe="CWE-1021",
            endpoint=endpoint,
            category="security_headers",
            description=(
                "CSP is set but lacks frame-ancestors. Pair with X-Frame-"
                "Options or set frame-ancestors='none' to defeat clickjacking."
            ),
            verification_status="pattern_match",
            confidence=0.85,
        ))
    return findings


def _check_clickjacking(headers: dict[str, str], *, endpoint: str) -> list[FindingDraft]:
    """Either X-Frame-Options or CSP frame-ancestors must be set."""
    xfo = _ci_get(headers, "X-Frame-Options")
    csp = _ci_get(headers, "Content-Security-Policy") or ""
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if xfo or has_frame_ancestors:
        return []
    return [FindingDraft(
        title="Missing clickjacking protection",
        severity="low",
        cwe="CWE-1021",
        endpoint=endpoint,
        category="security_headers",
        description=(
            "Neither X-Frame-Options nor CSP frame-ancestors is set. The "
            "page can be embedded in a hostile iframe (clickjacking class)."
        ),
        verification_status="pattern_match",
        confidence=0.9,
    )]


def _check_xcto(headers: dict[str, str], *, endpoint: str) -> list[FindingDraft]:
    raw = _ci_get(headers, "X-Content-Type-Options")
    if raw and raw.strip().lower() == "nosniff":
        return []
    return [FindingDraft(
        title="Missing X-Content-Type-Options: nosniff",
        severity="info",
        cwe="CWE-430",
        endpoint=endpoint,
        category="security_headers",
        description=(
            "Without `X-Content-Type-Options: nosniff`, browsers may MIME-"
            "sniff responses, enabling content-type confusion attacks on "
            "user-uploaded content."
        ),
        verification_status="pattern_match",
        confidence=0.85,
    )]


def _parse_cookie_attributes(raw: str) -> tuple[str, set[str]]:
    """Parse `Set-Cookie` value into (cookie_name, attribute_names).

    Splits on `;`, strips, lowercases attributes. Cookie value (LHS=RHS
    of first segment) is NOT inspected for attribute substrings —
    that was the false-negative bug pre-fix where a cookie with value
    `abc-Secure-fake` matched on substring "secure" without actually
    setting the Secure flag."""
    segments = [s.strip() for s in raw.split(";")]
    name = "<unknown>"
    attributes: set[str] = set()
    for i, seg in enumerate(segments):
        if i == 0:
            # First segment is name=value pair.
            eq = seg.find("=")
            if eq > 0:
                name = seg[:eq].strip()
            continue
        # Subsequent segments are attributes (possibly attr=value).
        eq = seg.find("=")
        attr_name = (seg[:eq] if eq > 0 else seg).strip().lower()
        if attr_name:
            attributes.add(attr_name)
    return name, attributes


def _check_set_cookie(headers: dict[str, str], *, endpoint: str) -> list[FindingDraft]:
    cookies = _ci_get_all(headers, "Set-Cookie")
    findings: list[FindingDraft] = []
    for raw in cookies:
        cookie_name, attrs = _parse_cookie_attributes(raw)
        if "secure" not in attrs:
            findings.append(FindingDraft(
                title=f"Cookie {cookie_name!r} missing Secure flag",
                severity="low",
                cwe="CWE-614",
                endpoint=endpoint,
                category="cookie_attributes",
                description=(
                    f"`Set-Cookie: {cookie_name}=…` lacks the `Secure` "
                    f"attribute. The cookie can be transmitted over HTTP."
                ),
                verification_status="pattern_match",
                confidence=0.95,
            ))
        if "httponly" not in attrs:
            findings.append(FindingDraft(
                title=f"Cookie {cookie_name!r} missing HttpOnly flag",
                severity="low",
                cwe="CWE-1004",
                endpoint=endpoint,
                category="cookie_attributes",
                description=(
                    f"`Set-Cookie: {cookie_name}=…` lacks the `HttpOnly` "
                    f"attribute. JavaScript can read the cookie, amplifying "
                    f"any companion XSS finding."
                ),
                verification_status="pattern_match",
                confidence=0.95,
            ))
        if "samesite" not in attrs:
            findings.append(FindingDraft(
                title=f"Cookie {cookie_name!r} missing SameSite attribute",
                severity="info",
                cwe="CWE-1275",
                endpoint=endpoint,
                category="cookie_attributes",
                description=(
                    f"`Set-Cookie: {cookie_name}=…` lacks the `SameSite` "
                    f"attribute. Default browser behaviour varies; explicit "
                    f"`SameSite=Lax` or stricter is recommended."
                ),
                verification_status="pattern_match",
                confidence=0.7,
            ))
    return findings


def _check_version_disclosure(
    headers: dict[str, str], *, endpoint: str,
) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for header_name in ("Server", "X-Powered-By"):
        raw = _ci_get(headers, header_name)
        if raw and re.search(r"\d", raw):  # version digit suggests disclosure
            findings.append(FindingDraft(
                title=f"{header_name} header discloses version",
                severity="info",
                cwe="CWE-200",
                endpoint=endpoint,
                category="information_disclosure",
                description=(
                    f"`{header_name}: {raw}` reveals the server software "
                    f"version. Attackers correlate this with public CVEs."
                ),
                verification_status="pattern_match",
                confidence=0.7,
            ))
    return findings


@register_specialist_tool(
    category="misconfig-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 30},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1595.002"],
)
def scan_misconfig(
    *,
    url: str,
    status: int | None = None,
    headers: dict[str, str] | None = None,
    is_https: bool | None = None,
) -> SpecialistResult:
    """Deterministic security-misconfiguration analysis (HSTS / CSP /
    clickjacking / cookie attributes / version disclosure).

    Args:
        url: target URL the lead just fetched.
        status: HTTP status code from the response. None when the
            lead didn't capture it (still runs header checks).
        headers: response headers as `{name: value}`. Case-insensitive
            lookups inside. None / empty dict produces a `status="error"`
            result with one-line evidence.
        is_https: explicit override for the scheme; otherwise inferred
            from `url`.

    Returns:
        `SpecialistResult` with `findings` populated. The lead converts
        each `FindingDraft` to a `finding.created` event via
        `emit_finding(...)`.

    Pure-Python; no network access; hermetic-testable. No internal
    LLM call (`llm=False`).
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(
            status="error",
            error="url required",
        )
    url = url.strip()

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return SpecialistResult(
            status="error",
            error=f"invalid url: {url!r}",
        )

    if is_https is None:
        is_https = parsed.scheme == "https"

    if not isinstance(headers, dict) or not headers:
        return SpecialistResult(
            status="partial",
            error="no headers provided — header-based checks skipped",
            evidence=[
                f"scan_misconfig invoked on {url!r} without headers; "
                "fetch the URL via send_request and pass headers back."
            ],
        )

    findings: list[FindingDraft] = []
    findings.extend(_check_hsts(headers, is_https=is_https, endpoint=url))
    findings.extend(_check_csp(headers, endpoint=url))
    findings.extend(_check_clickjacking(headers, endpoint=url))
    findings.extend(_check_xcto(headers, endpoint=url))
    findings.extend(_check_set_cookie(headers, endpoint=url))
    findings.extend(_check_version_disclosure(headers, endpoint=url))

    return SpecialistResult(
        status="ok",
        findings=findings,
        evidence=[
            f"scanned {url!r} (status={status!r}, header_count={len(headers)})",
        ],
        next_probes_suggested=(
            ["follow-up with browser-attacker for clickjacking PoC if /admin endpoint"]
            if any(f.cwe == "CWE-1021" for f in findings)
            else []
        ),
        tool_metadata={
            "scheme": parsed.scheme,
            "host": parsed.netloc,
            "header_names_observed": sorted({k.lower() for k in headers}),
        },
    )
