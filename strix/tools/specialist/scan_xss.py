"""`scan_xss` — deterministic XSS specialist (roadmap §8.5 Phase 3b).

Single-shot reflected-XSS detector that probes a URL+param set with
known canary payloads, examines responses for un-sanitised reflection,
and **auto-emits findings via `add_vulnerability_report`** so the
lead agent doesn't have to negotiate the emit-tool's parameter
schema.

Why deterministic over LLM-driven for Phase 3b
-----------------------------------------------

The post-#169 benchmark proved the architectural shift works
(LeadAgent + tool catalog filtering + watchdog + jinja directive
rendering all green). The remaining failure mode was prompt
compliance — gemini-2.5-pro consistently invented variant tag
names, wrong param shapes, and either over-emitted from training
data OR over-probed without emitting. A deterministic specialist
sidesteps all of that:

  * Probe logic is Python — gemini cannot mis-format it.
  * Auto-emit via `tracer.add_vulnerability_report` — no
    `<function=create_vulnerability_report>` translation step.
  * Single tool call from the lead's perspective:
    `scan_xss(url=..., params=[...])` returns a `SpecialistResult`
    with the count of findings actually emitted.

Detection rules
---------------

For each (param_name, payload) pair:

  1. Send a GET request to `<url>?<param>=<payload>&...` with the
     other params populated by the harmless probe value.
  2. Examine the response body for the payload's canary token
     (a unique random string embedded in each payload).
  3. If the canary appears WITHOUT having been HTML-escaped (no
     `&lt;`, `&#x3C;`, `\\u003c` substitution), emit a finding.

Canary tokens are randomly generated per probe so duplicate
responses (same payload, same response) are detected as the same
finding (cross-tool dedup #98 covers cross-payload dedup via
fingerprint).

Limitations (Phase 3b minimal scope)
------------------------------------

  * GET requests only. POST / multipart / JSON body XSS is Phase 3c.
  * No DOM-XSS — that's #108 / Phase 4 browser-automation specialist.
  * No context-aware payloads (HTML attribute / JS string / URL
    context). Three classic payloads cover most reflected XSS;
    context-aware probes are #108 / browser-automation Phase 4.
  * No auth replay. If a target needs auth, caller passes
    auth-header overrides via the `extra_headers` dict.
"""

from __future__ import annotations

import logging
import secrets
import string
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


_DEFAULT_PAYLOAD_TEMPLATES: tuple[str, ...] = (
    # Classic <script> tag — simplest reflection.
    "<script>alert('{canary}')</script>",
    # Image onerror — bypasses naive `<script>` filters.
    "<img src=x onerror=alert('{canary}')>",
    # SVG onload — bypasses some `<img>` filters.
    "<svg/onload=alert('{canary}')>",
)


# Patterns that indicate the response HTML-escaped the payload (so
# the reflection is harmless). Presence of ANY of these for a given
# canary means the host correctly sanitised that injection.
_ESCAPED_FRAGMENTS_TEMPLATE: tuple[str, ...] = (
    "&lt;script",          # < → &lt;
    "&#60;script",         # < → &#60;
    "&#x3c;script",        # < → &#x3c; (lowercase)
    "&#x3C;script",        # < → &#x3C; (uppercase)
    "%3Cscript",           # < → %3C (URL-encoded)
    "\\u003cscript",       # < → < (JS-encoded)
)


def _make_canary() -> str:
    """Cryptographically random 12-char alphanumeric canary. Embedded
    in the payload so reflections can be uniquely attributed even
    when multiple payloads share a target."""
    alphabet = string.ascii_uppercase + string.digits
    return "STRIX" + "".join(secrets.choice(alphabet) for _ in range(7))


def _build_url_with_param(
    url: str, *, param_name: str, value: str,
    other_params: dict[str, str] | None = None,
) -> str:
    """Replace `param_name` in URL's query string with `value` while
    preserving other params. If the URL has no query string, attaches
    one with the param + any extras."""
    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    # Flatten parse_qs's list-valued dict to single-value strings.
    flat: dict[str, str] = {k: (v[0] if v else "") for k, v in qs.items()}
    if other_params:
        for k, v in other_params.items():
            if k != param_name and k not in flat:
                flat[k] = v
    flat[param_name] = value
    new_query = urlencode(flat, doseq=False)
    return urlunparse(parts._replace(query=new_query))


def _is_payload_escaped(body: str, canary: str) -> bool:
    """True when the response shows the payload was HTML/URL-escaped
    or otherwise sanitised (canary present but only inside an
    escaped form). False when the canary appears in raw payload
    form with a LITERAL `<` opening a tag.

    Strategy: find every occurrence of the canary; for each, look
    backwards up to 80 chars for a literal `<` (raw tag opening). If
    the closest `<` before the canary is a LITERAL one and the
    intervening content is short + tag-shaped (no `&lt;` or `%3C`
    intervening), the canary appears inside a real HTML tag —
    UNESCAPED. Otherwise the canary appears inside an escape
    sequence (`&lt;...{canary}...&gt;` or `%3C...{canary}...%3E`)
    — ESCAPED.

    Conservative — when in doubt, return True (escaped) so we don't
    false-alarm. Real reflected XSS has an obvious `<TAG{canary}>`
    or `<TAG attr=...{canary}...>` pattern in the body.
    """
    if canary not in body:
        return False
    idx = 0
    while True:
        idx = body.find(canary, idx)
        if idx < 0:
            break
        # Look backwards 80 chars for the nearest `<` or `&lt;` /
        # `%3C` / `&#60;` / `<`.
        window_start = max(0, idx - 80)
        prefix = body[window_start:idx].lower()
        # Find the last `<` (raw) and the last escape variant.
        last_raw = prefix.rfind("<")
        last_escapes: list[int] = []
        for esc in ("&lt;", "%3c", "&#60;", "&#x3c;", "\\u003c"):
            p = prefix.rfind(esc)
            if p >= 0:
                last_escapes.append(p)
        nearest_escape = max(last_escapes) if last_escapes else -1
        if last_raw > nearest_escape:
            # Raw `<` is closer to canary than any escape → unescaped.
            return False
        # No raw `<` before canary, OR an escape is closer → treat
        # this occurrence as escaped. Try the next occurrence.
        idx += 1
    # Every occurrence of the canary was preceded by an escape (or no
    # `<` at all — e.g., reflected inside a `<input value="...">` —
    # which is also benign because the value attribute is escaped).
    return True


def _emit_finding(
    *,
    url: str,
    param: str,
    payload: str,
    canary: str,
    response_excerpt: str,
) -> str | None:
    """Emit via `tracer.add_vulnerability_report`. Returns the finding
    id on success, None on failure (best-effort — never raises)."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        return tracer.add_vulnerability_report(
            title=f"Reflected XSS in `{param}` parameter",
            severity="medium",
            cwe="CWE-79",
            endpoint=url,
            target=url,
            category="xss",
            verification_status="verified",
            confidence=0.9,
            description=(
                f"The `{param}` query parameter at `{url}` reflects "
                f"user-supplied input into the response body without "
                f"HTML-escaping. Injecting the payload "
                f"`{payload}` produced an unescaped reflection of the "
                f"canary token `{canary}` in the response."
            ),
            impact=(
                "Reflected XSS. An attacker can craft a malicious "
                "URL targeting authenticated users; clicking the URL "
                "executes attacker-controlled JavaScript in the "
                "victim's browser session, leading to session-token "
                "theft, CSRF token leakage, account takeover, or "
                "delivery of malware via the trusted origin."
            ),
            technical_analysis=(
                f"GET {url}\n"
                f"Probe: {param}={payload}\n"
                f"Response excerpt (canary {canary} present unescaped):\n"
                f"{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send GET request to {url} with `{param}` query "
                f"parameter set to `{payload}`.\n"
                f"2. Render the response in a browser; the JavaScript "
                f"in the payload executes (alert dialog with canary "
                f"`{canary}` confirms execution).\n"
                f"3. Replace the alert payload with a credential-"
                f"exfiltrating script for production attacks."
            ),
            poc_script_code=(
                f"curl -sS '{url}' --data-urlencode '{param}={payload}' -G"
            ),
            remediation_steps=(
                "Apply context-appropriate output encoding when "
                "rendering user input. For HTML body context, use "
                "the framework's HTML-escape helper (e.g. Django "
                "auto-escape, Jinja `|e`, ASP.NET `Html.Encode`, "
                "Java OWASP encoder). For HTML-attribute / JS / URL "
                "contexts, use the corresponding context-specific "
                "encoders. Validate that a strict Content-Security-"
                "Policy is in place as defense-in-depth (no `'unsafe-"
                "inline'` for `script-src`; use nonces or hashes)."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "R",
                "S": "C", "C": "L", "I": "L", "A": "N",
            },
            reasoning_trace=[
                f"Probed {param}= with classic reflection payload.",
                f"Canary {canary} appeared in response body unescaped.",
                "No HTML-escape fragments (&lt;script, &#60;, %3C, \\u003c) "
                "near the canary — server returned raw payload.",
                "Reflection in HTML body context → executable JavaScript.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_xss: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="xss-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1059.007"],  # Command/Scripting: JavaScript
)
def scan_xss(
    *,
    url: str,
    params: list[str] | None = None,
    other_params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
    method: str = "GET",
    body_template: dict[str, Any] | str | None = None,
    body_format: str = "auto",
) -> SpecialistResult:
    """Deterministic reflected-XSS scanner that probes given params,
    emits findings via the tracer, and returns a SpecialistResult.

    Args:
        url: target URL (e.g. `http://example.com/search.aspx`).
            Existing query params are preserved. May contain
            `{param}` placeholders for path-param substitution.
        params: list of param names to probe. When None / empty,
            inferred from (1) URL query-string keys, (2)
            `body_template` dict keys, (3) `{name}` placeholders
            in the URL path.
        other_params: optional baseline values for OTHER query params.
        extra_headers: optional headers to forward (e.g. auth).
        method: HTTP method. Default `GET` (Phase 3b). Use
            `POST`/`PUT` for body-based reflection probes.
        body_template: optional body. dict → JSON or form (per
            body_format); str → raw body with `{param}` placeholder.
            None → query-string substitution (Phase 3b behaviour).
        body_format: `"json"` / `"form"` / `"auto"`.

    Auto-emits one `add_vulnerability_report` per (param × payload)
    pair where reflection is detected unescaped.

    Examples:
        # Phase 3b — GET with query string.
        scan_xss(url="http://x/search?q=test", params=["q"])

        # Phase 3c — POST + JSON body (search API that reflects).
        scan_xss(
            url="http://x/api/search",
            method="POST",
            params=["query"],
            body_template={"query": "test", "limit": 10},
        )

        # Phase 3c — path param.
        scan_xss(
            url="http://x/users/{name}",
            method="GET",
            params=["name"],
        )
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    from strix.tools.specialist._request_builders import build_request

    parsed = urlparse(url)
    if not params:
        if parsed.query:
            params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        elif isinstance(body_template, dict):
            params = list(body_template.keys())
        else:
            import re as _re
            params = _re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", url)
    if not params:
        return SpecialistResult(
            status="partial",
            error="no params supplied and could not infer from URL/body",
            evidence=[
                f"scan_xss invoked on {url!r} with no params; "
                "supply `params=[...]`, include a query string, "
                "supply a `body_template` dict, or use `{name}` "
                "placeholders in the URL path."
            ],
        )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    probe_count = 0
    seen_endpoint_param: set[tuple[str, str]] = set()

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        pm = get_proxy_manager()
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"proxy_manager unavailable: {type(e).__name__}: {e}",
        )

    for param in params:
        if not isinstance(param, str) or not param.strip():
            continue
        param = param.strip()
        for template in _DEFAULT_PAYLOAD_TEMPLATES:
            canary = _make_canary()
            payload = template.format(canary=canary)
            try:
                req_method, req_url, req_headers, req_body = build_request(
                    url=url, method=method,
                    param_name=param, payload=payload,
                    body_template=body_template, body_format=body_format,
                    other_params=other_params, extra_headers=extra_headers,
                )
                resp = pm.send_simple_request(
                    req_method, req_url,
                    headers=req_headers,
                    body=req_body,
                    timeout=15,
                )
            except Exception as e:  # noqa: BLE001
                evidence.append(f"probe failed for {param!r}: {e}")
                continue
            probe_count += 1

            if "error" in resp and not resp.get("status_code"):
                # Network error — record but don't emit.
                evidence.append(
                    f"transport error for {param!r}: "
                    f"{resp.get('error', '<unknown>')}"
                )
                continue

            body = resp.get("body") or ""
            if not isinstance(body, str):
                body = str(body)

            # Detection: canary present + not escaped.
            if canary in body and not _is_payload_escaped(body, canary):
                # De-dup per (endpoint, param) — only first reflection
                # detection per param emits.
                key = (parsed.path or "/", param)
                if key in seen_endpoint_param:
                    continue
                seen_endpoint_param.add(key)

                # Excerpt around the canary for evidence.
                idx = body.find(canary)
                start = max(0, idx - 100)
                end = min(len(body), idx + 200)
                excerpt = body[start:end]

                report_id = _emit_finding(
                    url=url, param=param,
                    payload=payload, canary=canary,
                    response_excerpt=excerpt,
                )
                if report_id:
                    emitted_count += 1
                drafts.append(FindingDraft(
                    title=f"Reflected XSS in `{param}` parameter",
                    severity="medium",
                    cwe="CWE-79",
                    endpoint=url,
                    category="xss",
                    verification_status="verified",
                    confidence=0.9,
                    description=(
                        f"Reflected XSS in {param} at {url}; canary "
                        f"{canary} echoed unescaped via payload "
                        f"{payload[:60]}"
                    ),
                ))
                evidence.append(
                    f"reflection detected: {param}={payload[:40]}... "
                    f"canary {canary} echoed unescaped"
                )

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            ["follow-up with browser-automation specialist for DOM-XSS validation"]
            if drafts else
            ["no reflected-XSS detected; consider authenticated probes "
             "or stored-XSS sinks if app has user-content surfaces"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "params_probed": len(params),
            "findings_emitted_to_tracer": emitted_count,
            "scheme": parsed.scheme,
            "host": parsed.netloc,
        },
    )
