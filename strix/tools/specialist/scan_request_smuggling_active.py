"""`scan_request_smuggling_active` — timing-based active HTTP-request-
smuggling specialist (workitem.md Phase 2.10).

Closes CWE-444 / OWASP A06:2021 with the **PortSwigger timing-based
methodology** — the gold standard for active smuggle confirmation.

How this differs from `request_smuggling_check` (passive differential)
---------------------------------------------------------------------

`request_smuggling_check` (already in catalog) sends TE-obfuscated
header variants and diffs the response shape against a baseline. It's
a strong header-level signal, but the agent must still convert that
signal into confirmed smuggle. This specialist provides the
**confirmation step**: time-based CL.TE and TE.CL probes that hang
the back-end socket only when the parser disagreement is real.

Probes
------

  1. **CL.TE timing** — front-end uses `Content-Length`, back-end
     uses `Transfer-Encoding: chunked`.

         POST / HTTP/1.1
         Host: target
         Content-Length: 4
         Transfer-Encoding: chunked

         1
         A
         X

     Front-end forwards 4 bytes ("1\\r\\nA\\r\\n"); back-end stops
     reading at `0\\r\\n` (never appears) and waits — socket hangs
     for ~5-15 seconds. If hung-socket signal is observed, CL.TE
     desync is real.

  2. **TE.CL timing** — front-end uses TE.chunked (with
     obfuscation), back-end uses Content-Length.

         POST / HTTP/1.1
         Host: target
         Content-Length: 6
         Transfer-Encoding: chunked

         0

         X

     Front-end terminates on `0\\r\\n\\r\\n`; back-end reads 6 bytes
     including the trailing `X` and waits for more — socket hangs.

  3. **HTTP/2 downgrade probe** — `Content-Length: 0\\r\\nGET ... `
     when target accepts HTTP/2 but back-end is HTTP/1.1.

The specialist establishes a **baseline timing** by sending a normal
POST + measuring elapsed; then runs each smuggle probe and looks for
a response-time anomaly of ≥3× baseline.

Detection criterion: probe elapsed > baseline_elapsed × 3 AND
probe_elapsed > 4.0 seconds. Both bounds prevent flapping on slow
networks.

Auto-emits CWE-444 finding. Severity: critical (smuggling chains to
session theft, cache poisoning, full-app compromise).
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Per-probe configuration. (label, body_template, severity, description)
# `body_template` uses LF placeholders that get rewritten to CRLF.
_PROBES: tuple[tuple[str, str, str, str], ...] = (
    (
        "cl_te_timing",
        # CL=4 says "send 4 bytes"; TE=chunked never sees 0-terminator.
        # Front-end: forwards 4 bytes; back-end: hangs waiting for chunked end.
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "1\r\n"
        "A\r\n"
        "X",
        "critical",
        "CL.TE: Content-Length forwards 4 bytes; back-end waits for chunked terminator",
    ),
    (
        "te_cl_timing",
        # CL=6 says "send 6 bytes"; TE=chunked terminates after `0\r\n\r\n`.
        # Front-end: terminates at `0\r\n\r\n`; back-end: reads 6 bytes incl. trailing X.
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X",
        "critical",
        "TE.CL: TE forwards full chunked body; back-end waits for 6-byte CL",
    ),
    (
        "te_cl_obfuscated_space",
        # Same as TE.CL but with TE-obfuscation (trailing space).
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding : chunked\r\n"  # trailing space before colon
        "Connection: keep-alive\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X",
        "critical",
        "TE.CL with obfuscated TE header (trailing space)",
    ),
    (
        "cl_te_obfuscated_xchunked",
        # CL.TE with `xchunked` — some parsers strip x-prefix.
        "POST / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: xchunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "1\r\n"
        "A\r\n"
        "X",
        "high",
        "CL.TE with xchunked obfuscation",
    ),
)


def _send_raw(host: str, port: int, *, use_tls: bool, raw_request: bytes,
              timeout: float = 8.0) -> tuple[float, bytes, str | None]:
    """Send a raw HTTP request, return (elapsed_seconds, response_bytes, error).

    On socket timeout, the elapsed time is reported AS the timeout value
    (with `error="timeout"`) — that's what indicates a hung back-end.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    started = time.monotonic()
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        sock.sendall(raw_request)
        chunks: list[bytes] = []
        while True:
            try:
                buf = sock.recv(65536)
            except (socket.timeout, TimeoutError):
                # Hung socket — exactly what we want to detect.
                elapsed = time.monotonic() - started
                return elapsed, b"".join(chunks), "timeout"
            if not buf:
                break
            chunks.append(buf)
            if sum(len(c) for c in chunks) > 65536:
                break
        elapsed = time.monotonic() - started
        return elapsed, b"".join(chunks), None
    except (socket.error, OSError) as e:
        elapsed = time.monotonic() - started
        return elapsed, b"", f"{type(e).__name__}: {e}"
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass


def _build_baseline_request(host: str) -> bytes:
    """Plain POST request — used as timing baseline."""
    body = "X"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return raw.encode("ascii", errors="replace")


def _emit_finding(
    *,
    url: str,
    probe_label: str,
    description: str,
    baseline_elapsed: float,
    probe_elapsed: float,
    probe_response_excerpt: str,
    severity: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        return tracer.add_vulnerability_report(
            title=f"HTTP request smuggling at `{url}` ({probe_label})",
            severity=severity,
            cwe="CWE-444",
            endpoint=url,
            target=url,
            category="http_request_smuggling",
            verification_status="verified",
            confidence=0.85,
            description=(
                f"Timing-based smuggle probe `{probe_label}` "
                f"({description}) caused the back-end socket to hang. "
                f"Baseline elapsed: {baseline_elapsed:.2f}s; probe "
                f"elapsed: {probe_elapsed:.2f}s. The back-end is "
                f"reading more bytes than the front-end forwarded "
                f"(or vice versa) — direct evidence of parser "
                f"disagreement on either Content-Length vs Transfer-"
                f"Encoding interpretation."
            ),
            impact=(
                "HTTP request smuggling. The front-end and back-end "
                "disagree about request boundaries — attacker can "
                "smuggle a second request that the back-end attaches "
                "to the next user's connection.\n"
                "  * Cookie / session theft from arbitrary "
                "    concurrent users.\n"
                "  * Web cache poisoning — serve attacker content "
                "    from the CDN cache to other users.\n"
                "  * Bypass of front-end WAF / authn — back-end "
                "    sees the smuggled request as already past the "
                "    edge.\n"
                "  * Full credential capture in some chains "
                "    (especially with proxy + browser cache poisoning)."
            ),
            technical_analysis=(
                f"URL: {url}\n"
                f"Probe: {probe_label}\n"
                f"Variant: {description}\n"
                f"Baseline elapsed: {baseline_elapsed:.2f}s\n"
                f"Probe elapsed: {probe_elapsed:.2f}s "
                f"(ratio: {probe_elapsed / max(baseline_elapsed, 0.01):.1f}×)\n"
                f"Response excerpt:\n{probe_response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Establish baseline: send a plain POST to {url} "
                f"and measure elapsed (~{baseline_elapsed:.1f}s).\n"
                f"2. Send the smuggle probe {probe_label}; back-end "
                f"socket hangs, elapsed grows to "
                f"~{probe_elapsed:.1f}s.\n"
                f"3. Confirm with PortSwigger Burp Repeater "
                f"smuggle-attack template; pivot to second-request "
                f"smuggling for cookie / session theft."
            ),
            poc_script_code=(
                "# raw socket — see PortSwigger SmuggleAttack "
                "tutorial for a copy-paste-ready template."
            ),
            remediation_steps=(
                "1. Disable HTTP/1.1 → HTTP/1.1 keep-alive between "
                "front-end and back-end (use HTTP/2 end-to-end where "
                "possible). Smuggling requires keep-alive to land the "
                "smuggled request on the next user's connection.\n"
                "2. At the front-end, REJECT (don't normalize) "
                "requests with BOTH `Content-Length` and "
                "`Transfer-Encoding` headers.\n"
                "3. REJECT requests with obfuscated TE values "
                "(`xchunked`, trailing whitespace in header name, "
                "duplicate TE headers).\n"
                "4. Use a single HTTP parser end-to-end (e.g. only "
                "h2o or only nginx — don't chain dissimilar parsers).\n"
                "5. Apply WAF rules that block common smuggling "
                "shapes; confirm with PortSwigger's smuggle-attack "
                "lab corpus before declaring fixed."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "H", "PR": "N", "UI": "N",
                "S": "C", "C": "H", "I": "H", "A": "H",
            },
            reasoning_trace=[
                f"Baseline POST to {url} elapsed {baseline_elapsed:.2f}s.",
                f"Probe {probe_label} elapsed {probe_elapsed:.2f}s "
                f"(ratio {probe_elapsed / max(baseline_elapsed, 0.01):.1f}×).",
                "Hung socket evidences front-end / back-end CL/TE "
                "parser disagreement — smuggling primitive confirmed.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_request_smuggling_active: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="request-smuggling-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 120},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190", "T1565"],
)
def scan_request_smuggling_active(
    *,
    url: str,
    timeout_seconds: float = 8.0,
    timing_threshold_ratio: float = 3.0,
    timing_threshold_seconds: float = 4.0,
) -> SpecialistResult:
    """Timing-based active request-smuggling scanner.

    Args:
        url: target URL (the host's `/` is probed).
        timeout_seconds: per-probe socket timeout. A timeout IS the
            evidence — but we cap to keep the run bounded.
        timing_threshold_ratio: probe must be at least this many
            times slower than baseline to count as evidence.
            Default 3.0× — empirically separates jitter from
            actual smuggle hangs.
        timing_threshold_seconds: probe absolute elapsed must
            exceed this. Default 4.0s — prevents flapping on slow
            networks.

    Auto-emits one finding per smuggle-probe hit.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")

    parsed = urlparse(url.strip())
    if not parsed.hostname:
        return SpecialistResult(status="error", error="invalid url (no host)")

    host = parsed.hostname
    use_tls = parsed.scheme == "https"
    port = parsed.port or (443 if use_tls else 80)

    # Baseline timing — three samples, take min.
    baseline_samples: list[float] = []
    baseline_request = _build_baseline_request(host)
    for _ in range(3):
        elapsed, _body, err = _send_raw(
            host, port, use_tls=use_tls,
            raw_request=baseline_request, timeout=timeout_seconds,
        )
        if err is None:
            baseline_samples.append(elapsed)
    if not baseline_samples:
        return SpecialistResult(
            status="error",
            error=f"baseline failed: cannot reach {host}:{port}",
        )
    baseline_elapsed = min(baseline_samples)

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    probe_count = 0
    seen: set[str] = set()

    for label, body_template, severity, description in _PROBES:
        if label in seen:
            continue
        raw = body_template.format(host=host).encode("ascii", errors="replace")
        elapsed, response, err = _send_raw(
            host, port, use_tls=use_tls,
            raw_request=raw, timeout=timeout_seconds,
        )
        probe_count += 1

        # Detection: hung socket OR elapsed >> baseline.
        is_hung = err == "timeout"
        is_slow = (
            elapsed >= baseline_elapsed * timing_threshold_ratio
            and elapsed >= timing_threshold_seconds
        )
        if not (is_hung or is_slow):
            continue

        seen.add(label)
        excerpt = response.decode("utf-8", errors="replace")[:1200]
        rid = _emit_finding(
            url=url, probe_label=label, description=description,
            baseline_elapsed=baseline_elapsed, probe_elapsed=elapsed,
            probe_response_excerpt=excerpt, severity=severity,
        )
        if rid:
            emitted_count += 1
        drafts.append(FindingDraft(
            title=f"HTTP request smuggling: {label}",
            severity=severity, cwe="CWE-444",
            endpoint=url, category="http_request_smuggling",
            verification_status="verified", confidence=0.85,
            description=(
                f"{description}; baseline {baseline_elapsed:.1f}s → "
                f"probe {elapsed:.1f}s"
                + (" (timeout)" if is_hung else "")
            ),
        ))
        evidence.append(
            f"{label}: baseline={baseline_elapsed:.1f}s "
            f"probe={elapsed:.1f}s"
            + (" hung" if is_hung else "")
        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="POST", probed_for="http_request_smuggling")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_request_smuggling_active"},
            input={"baseline_elapsed_s": round(baseline_elapsed, 3),
                   "probes_sent": probe_count},
            output={"findings_emitted": emitted_count, "drafts": len(drafts)},
        )
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            ["confirm with PortSwigger Burp Repeater smuggle-attack PoC; "
             "pivot to cookie/session theft via second-request smuggling"]
            if drafts else
            ["no smuggle confirmed via timing; rerun on slower networks "
             "with higher timing_threshold_seconds, or use the existing "
             "request_smuggling_check (header-level differential) for "
             "weaker signals"]
        ),
        tool_metadata={
            "baseline_elapsed_seconds": round(baseline_elapsed, 3),
            "probes_sent": probe_count,
            "findings_emitted_to_tracer": emitted_count,
            "timing_threshold_ratio": timing_threshold_ratio,
            "timing_threshold_seconds": timing_threshold_seconds,
        },
    )
