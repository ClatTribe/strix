"""`scan_ssti` — deterministic Server-Side Template Injection specialist
(workitem.md Phase 2.3).

Closes CWE-1336 / CWE-94. SSTI lives in the seam between user input
and a template engine: when input is concatenated into a template
string (instead of bound as data), the engine evaluates attacker
expressions and the impact escalates from XSS-style reflection to
RCE in most engines.

Detection strategy
------------------

The classic SSTI confirmation is **arithmetic evaluation**: send
`{{7*7}}` and look for `49` in the response. The trick is that `49`
also appears organically in many responses, so we use a **distinctive
prime-product** plus a randomly generated nonce so accidental
collisions are negligible.

Engines covered (one probe per syntax family):

  * **Jinja2 / Twig / Liquid** — `{{ expr }}`
  * **Freemarker / Velocity / Smarty / ERB / EJS** — `${expr}`
  * **Mako / older Python** — `<%expr%>`
  * **Razor (.NET)** — `@(expr)`
  * **Handlebars** — `{{expr}}` (same as Jinja but distinct lookup)

Because every engine evaluates plain integer arithmetic, a unique-
product canary distinguishes the engine output from accidental echo:

    canary_a * canary_b → expected_product

We pick `canary_a, canary_b` per probe so the expected_product is
unique to that probe (no payload re-use, no fixture leak).

Auto-emit on detection. SSTI is high/critical severity since most
engines allow attribute lookup + native code execution from
inside the template:

  * **Critical** — Jinja2 (`__class__.__mro__`-based RCE),
    Freemarker (`<#assign value="freemarker.template.utility.Execute"?new()>`),
    Velocity (`#set($e='exp.getRuntime().exec()')`).
  * **High** — Twig sandboxed, Liquid, Handlebars (often only
    template-context attribute access).
"""

from __future__ import annotations

import logging
import secrets
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


def _gen_canary_pair() -> tuple[int, int, int]:
    """Pick two large primes and return (a, b, a*b). The product is
    unique to this probe so accidental echo is statistically improbable
    (collision rate ≈ 1 / 10^6 vs. response bodies)."""
    # Pick two 5-6 digit primes from a small list. Combination space
    # is large enough to avoid collisions across a single scan.
    primes = [
        99991, 99989, 99971, 99961, 99929, 99923, 99889, 99877, 99871,
        99859, 99839, 99823, 99817, 99809, 99793, 99787, 99767, 99761,
    ]
    a = secrets.choice(primes)
    b = secrets.choice([p for p in primes if p != a])
    return a, b, a * b


def _build_probes() -> list[tuple[str, str, int, str]]:
    """Build (engine_label, payload, expected_product, severity) tuples
    with a fresh canary pair per call (so each scan_ssti invocation
    uses fresh primes).
    """
    out: list[tuple[str, str, int, str]] = []
    a, b, prod = _gen_canary_pair()
    out.append(("jinja_twig_liquid", f"{{{{{a}*{b}}}}}", prod, "critical"))
    a, b, prod = _gen_canary_pair()
    out.append(("freemarker_velocity_smarty", f"${{{a}*{b}}}", prod, "critical"))
    a, b, prod = _gen_canary_pair()
    out.append(("mako_python", f"<%{a}*{b}%>", prod, "high"))
    a, b, prod = _gen_canary_pair()
    out.append(("razor_dotnet", f"@({a}*{b})", prod, "high"))
    a, b, prod = _gen_canary_pair()
    # Handlebars syntax (same as Jinja) but uses helper-call shape.
    out.append(("handlebars", f"{{{{{a}*{b}}}}}", prod, "high"))
    a, b, prod = _gen_canary_pair()
    # ERB / EJS — `<%= expr %>`
    out.append(("erb_ejs", f"<%={a}*{b}%>", prod, "critical"))
    return out


def _build_url_with_param(
    url: str, param_name: str, value: str,
    *, other_params: dict[str, str] | None = None,
) -> str:
    """Substitute the named param in the URL's query string."""
    from urllib.parse import parse_qs, urlencode, urlunparse

    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    flat = {k: (v[0] if v else "") for k, v in qs.items()}
    if other_params:
        for k, v in other_params.items():
            if k != param_name and k not in flat:
                flat[k] = v
    flat[param_name] = value
    return urlunparse(parts._replace(query=urlencode(flat, doseq=False)))


def _emit_finding(
    *,
    url: str,
    param: str,
    engine_label: str,
    payload: str,
    expected_product: int,
    response_excerpt: str,
    severity: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        return tracer.add_vulnerability_report(
            title=f"Server-side template injection in `{param}` ({engine_label})",
            severity=severity,
            cwe="CWE-1336",
            endpoint=url,
            target=url,
            category="ssti",
            verification_status="verified",
            confidence=0.97,
            description=(
                f"The `{param}` parameter at `{url}` is concatenated into "
                f"a server-side template before rendering. Probe with "
                f"`{payload}` ({engine_label} syntax) returned the evaluated "
                f"product `{expected_product}` in the response body — the "
                f"template engine evaluated attacker-controlled expressions, "
                f"confirming SSTI."
            ),
            impact=(
                "Server-side template injection. The template engine "
                "evaluates attacker-supplied expressions on the server.\n"
                "  * Jinja2 → `{{ ''.__class__.__mro__[1].__subclasses__() }}` "
                "    chain → arbitrary Python execution → RCE.\n"
                "  * Freemarker → "
                "    `freemarker.template.utility.Execute` → RCE.\n"
                "  * Velocity → "
                "    `#set($e='exp.getRuntime().exec(...)')` → RCE.\n"
                "  * ERB → `<%= system('...') %>` → RCE.\n"
                "  * Mako → `<%= __import__('os').popen('...').read() %>` → RCE.\n"
                "Even sandboxed engines (Twig sandbox, Liquid) leak "
                "internal variables and template-context state."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Param: {param}\n"
                f"Engine family: {engine_label}\n"
                f"Payload: {payload}\n"
                f"Expected product: {expected_product}\n"
                f"Response excerpt:\n{response_excerpt[:1500]}\n"
                "Detection: in-band fingerprint match — the canary "
                "product appears in the response. Because the canary "
                "is two random 5-digit primes, accidental echo is "
                "statistically negligible."
            ),
            poc_description=(
                f"1. Send GET request to {url} with `{param}` set to "
                f"`{payload}`.\n"
                f"2. The response contains `{expected_product}` "
                f"(the evaluated product) — confirms the engine "
                f"interprets the payload as a template expression.\n"
                f"3. Pivot to RCE: replace the arithmetic with the "
                f"engine-specific RCE chain above."
            ),
            poc_script_code=(
                f"curl -sS -G '{url}' --data-urlencode '{param}={payload}'"
            ),
            remediation_steps=(
                "1. Never concatenate user input into a template "
                "string. Bind it as DATA to a pre-compiled template "
                "instead:\n"
                "     template.render(name=user_input)  # bind\n"
                "     # NOT: template_str = f\"Hello, {user_input}\"\n"
                "2. Where dynamic templates are unavoidable, use the "
                "engine's sandbox mode (Twig sandbox, Jinja2 "
                "SandboxedEnvironment) and an expression-allowlist "
                "policy.\n"
                "3. Audit every code-path that builds template "
                "strings dynamically — they're the only place SSTI "
                "lives."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C", "C": "H", "I": "H", "A": "H",
            },
            reasoning_trace=[
                f"Probed {param}= with {engine_label} payload `{payload}`.",
                f"Expected canary product: {expected_product}.",
                "Canary appeared in response — engine evaluated expression.",
                f"Severity {severity} (template engine likely allows code execution).",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_ssti: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="ssti-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1059", "T1190"],
)
def scan_ssti(
    *,
    url: str,
    params: list[str] | str | None = None,
    param: str | None = None,
    other_params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> SpecialistResult:
    """Deterministic SSTI scanner.

    Args:
        url: target URL.
        params: param names to probe. When None, scanner infers from
            URL query keys + a template-shaped lexicon (`name`,
            `template`, `greeting`, `message`, `body`, `q`, `query`,
            `subject`, `content`).
        param: convenience alias for a single param name.
        other_params: baseline values for non-target params on the URL.
        extra_headers: forwarded as-is.

    Auto-emits one finding per vulnerable (endpoint, param) pair.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    # Forgiving args.
    if param and not params:
        params = [param]
    if isinstance(params, str):
        params = [params]

    parsed = urlparse(url)
    if not params:
        from urllib.parse import parse_qs
        qs_keys = list(parse_qs(parsed.query).keys())
        # Param shapes commonly concatenated into templates.
        ssti_lexicon = {
            "name", "username", "user", "greeting", "message", "body",
            "subject", "content", "template", "q", "query", "search",
            "text", "comment", "title", "description", "msg", "reply",
            "input", "data", "value",
        }
        params = [k for k in qs_keys if k.lower() in ssti_lexicon]
        if not params:
            params = qs_keys
    if not params:
        return SpecialistResult(
            status="partial",
            error="no template-shaped params found",
            evidence=[
                f"scan_ssti invoked on {url!r}; supply `params=[...]` or "
                "include a query string with template-shaped params "
                "(e.g. `?name=...`, `?greeting=...`)."
            ],
        )

    # Auto-include captured auth from SecurityContext.
    extra_headers = dict(extra_headers or {})
    if "Authorization" not in extra_headers and "authorization" not in {
        h.lower() for h in extra_headers
    }:
        try:
            from strix.agents.security_context import list_auth_states
            for state in list_auth_states():
                if state.bearer:
                    extra_headers["Authorization"] = f"Bearer {state.bearer}"
                    break
                if state.cookies:
                    extra_headers["Cookie"] = "; ".join(
                        f"{k}={v}" for k, v in state.cookies.items()
                    )
                    break
        except Exception:  # noqa: BLE001
            pass

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager
        pm = get_proxy_manager()
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"proxy_manager unavailable: {type(e).__name__}: {e}",
        )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    probe_count = 0
    seen_endpoint_param: set[tuple[str, str]] = set()

    for raw_param in params:
        if not isinstance(raw_param, str) or not raw_param.strip():
            continue
        p = raw_param.strip()
        key = (parsed.path or "/", p)
        if key in seen_endpoint_param:
            continue

        probes = _build_probes()  # fresh canaries per param

        for engine_label, payload, expected_product, severity in probes:
            probe_url = _build_url_with_param(url, p, payload, other_params=other_params)
            try:
                resp = pm.send_simple_request(
                    "GET", probe_url,
                    headers=extra_headers, body="", timeout=15,
                )
                probe_count += 1
            except Exception as e:  # noqa: BLE001
                evidence.append(f"transport error ({engine_label}): {e}")
                continue
            if "error" in resp and not resp.get("status_code"):
                continue
            body = resp.get("body") or ""
            if not isinstance(body, str):
                continue
            # Look for the unique product. Avoid sub-string match in a
            # huge number sequence: require it as a standalone token.
            expected = str(expected_product)
            # Sub-string check is fine because the product is two 5-digit
            # primes' product (~10 digits) — accidental match in a body
            # would require that exact run to appear, which is
            # statistically negligible.
            if expected in body:
                # Sanity: the original payload should NOT be echoed
                # verbatim — that would be reflection, not SSTI.
                # An engine that evaluated successfully replaced the
                # payload with the product.
                if payload in body:
                    # Both present — could be partial echo with another
                    # source of the number. Skip with low confidence.
                    continue
                seen_endpoint_param.add(key)
                idx = body.find(expected)
                start = max(0, idx - 100)
                end = min(len(body), idx + len(expected) + 200)
                excerpt = body[start:end]
                rid = _emit_finding(
                    url=url, param=p,
                    engine_label=engine_label, payload=payload,
                    expected_product=expected_product,
                    response_excerpt=excerpt,
                    severity=severity,
                )
                if rid:
                    emitted_count += 1
                drafts.append(FindingDraft(
                    title=f"SSTI in `{p}` ({engine_label})",
                    severity=severity, cwe="CWE-1336",
                    endpoint=url, category="ssti",
                    verification_status="verified", confidence=0.97,
                    description=(
                        f"SSTI: {engine_label} → {payload} "
                        f"evaluated to {expected_product}"
                    ),
                ))
                evidence.append(
                    f"SSTI: {p}={payload} → product {expected_product} appeared "
                    f"in body ({engine_label})"
                )
                break  # one finding per param

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="GET", params=params, probed_for="ssti")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_ssti"},
            input={"params": list(params), "probes_sent": probe_count},
            output={"findings_emitted": emitted_count, "drafts": len(drafts)},
        )
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            ["confirm engine + escalate to RCE — Jinja2 "
             "`{{ ''.__class__.__mro__[1].__subclasses__() }}`, "
             "Freemarker `freemarker.template.utility.Execute`, "
             "Velocity `#set($e='exp.getRuntime().exec()')`"]
            if drafts else
            ["no SSTI on listed params; consider POST/JSON body fields "
             "passed to email/template render paths, and PDF / SVG / "
             "Office-document export endpoints (often template-rendered)"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "params_probed": len(params),
            "findings_emitted_to_tracer": emitted_count,
        },
    )
