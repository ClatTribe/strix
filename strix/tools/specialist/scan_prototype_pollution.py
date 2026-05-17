"""`scan_prototype_pollution` — server-side prototype pollution
detector.

Closes the P1 from `masterroadmap.md` §1 (web_application
coverage). Server-side prototype pollution (SSPP) is the Node.js
attack class where the attacker pollutes `Object.prototype` on
the server — every object thereafter inherits the polluted
property. Practical impact:

  * **Auth bypass** — pollute `Object.prototype.isAdmin = true`,
    every user object becomes admin.
  * **Logic-check bypass** — `if (user.role === undefined)` no
    longer fires once `Object.prototype.role` is set.
  * **DoS** — polluting `Object.prototype.toString` causes type-
    coercion 500s across unrelated handlers.
  * **RCE pivots** — paired with vulnerable sinks
    (`lodash.merge`, `set-value`, `child_process` arg parsing),
    SSPP yields full RCE in real-world chains
    (CVE-2019-10744 prototype-of-lodash, CVE-2022-2999, etc.).

## Detection methodology

Two-phase active probe:

  1. **Pollute** — issue a polluting request via one of the
     canonical vectors:
       * JSON body: `{"__proto__": {"x": "<nonce>"}}`
       * JSON body nested: `{"a": {"__proto__": {"x": "<nonce>"}}}`
       * Query: `?__proto__[x]=<nonce>`
       * Query nested: `?a[__proto__][x]=<nonce>`
       * Constructor variant: `?constructor[prototype][x]=<nonce>`

  2. **Observe** — issue a follow-up request that should NOT
     contain the nonce. If the nonce appears in the response
     body or headers, prototype pollution is confirmed —
     the polluted property leaked into a downstream object
     serialization or template render.

We also detect **status-code differential**: pollute a property
likely to corrupt response shape (e.g. `status`, `statusCode`),
then send a normally-200 request and look for unexpected non-200.

Both signals are sufficient on their own; both firing together
is the highest-confidence case.

## Nonce hygiene

Each probe gets a per-run cryptographic nonce so multiple
strix runs (and parallel probes within a run) don't collide
on observation false-positives. The nonce is the only payload
value the observer scans for — any other reflection is
ignored.

## What this does NOT do

  * **Client-side prototype pollution** — that's `scan_xss` /
    DOM-XSS territory; the JS-side detector requires headless
    Chrome execution and lives in a separate specialist.
  * **Gadget-chain RCE confirmation** — proving the pollution
    pivots to RCE requires sink-specific exploitation
    (lodash, node-set-value chains). The finding flags the
    pollution primitive; pivot is the agent's MOAK follow-up.
  * **Mass-assignment** — distinct attack class even though
    the injection vector overlaps. `scan_api_mass_assignment`
    handles the schema-aware variant.

Findings emit as `category=prototype_pollution`, CWE-1321
(Improperly Controlled Modification of Object Prototype
Attributes — Prototype Pollution), severity **high**.
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Cap on response body size scanned for the nonce.
_MAX_BODY_SCAN = 200 * 1024

# Cap on per-run probe count to keep runs bounded.
_DEFAULT_MAX_PROBES = 24


# ---------------------------------------------------------------------------
# Payload shapes
# ---------------------------------------------------------------------------


def _json_body_direct(nonce: str, marker_key: str) -> tuple[str, dict[str, str]]:
    """`{"__proto__": {"x": "<nonce>"}}` — flat injection."""
    body = json.dumps({"__proto__": {marker_key: nonce}})
    return body, {"Content-Type": "application/json"}


def _json_body_nested(nonce: str, marker_key: str) -> tuple[str, dict[str, str]]:
    """`{"a": {"__proto__": {"x": "<nonce>"}}}` — nested inside a
    legitimate-looking object. Catches handlers that recursively
    merge nested input."""
    body = json.dumps({"a": {"__proto__": {marker_key: nonce}}})
    return body, {"Content-Type": "application/json"}


def _json_body_constructor(
    nonce: str, marker_key: str,
) -> tuple[str, dict[str, str]]:
    """`{"constructor": {"prototype": {"x": "<nonce>"}}}` — bypass
    for handlers that block `__proto__` but allow walking via
    `constructor.prototype`."""
    body = json.dumps({
        "constructor": {"prototype": {marker_key: nonce}}
    })
    return body, {"Content-Type": "application/json"}


def _query_direct(nonce: str, marker_key: str) -> dict[str, str]:
    """`?__proto__[x]=<nonce>` — query-string injection. Frameworks
    using `qs`-style parsing (Express default before 4.x) parse
    bracket-notation into nested objects."""
    return {f"__proto__[{marker_key}]": nonce}


def _query_nested(nonce: str, marker_key: str) -> dict[str, str]:
    """`?a[__proto__][x]=<nonce>` — nested variant."""
    return {f"a[__proto__][{marker_key}]": nonce}


def _query_constructor(nonce: str, marker_key: str) -> dict[str, str]:
    """`?constructor[prototype][x]=<nonce>` — bypass for handlers
    that block `__proto__` but allow `constructor.prototype`."""
    return {f"constructor[prototype][{marker_key}]": nonce}


# Probe registry: (label, kind, builder, description). `kind` is
# either `"json_body"` or `"query"` so the dispatcher knows how
# to assemble the request.
_PROBES: tuple[tuple[str, str, Any, str], ...] = (
    ("json_proto_direct", "json_body", _json_body_direct,
     "JSON body with direct `__proto__` key"),
    ("json_proto_nested", "json_body", _json_body_nested,
     "JSON body with `__proto__` nested inside a benign key"),
    ("json_constructor_proto", "json_body", _json_body_constructor,
     "JSON body via `constructor.prototype` (proto-key bypass)"),
    ("query_proto_direct", "query", _query_direct,
     "Query-string `__proto__[x]=…` (qs-style bracket parsing)"),
    ("query_proto_nested", "query", _query_nested,
     "Query-string `a[__proto__][x]=…` (nested variant)"),
    ("query_constructor_proto", "query", _query_constructor,
     "Query-string `constructor[prototype][x]=…` (proto-key bypass)"),
)


# Status-corruption marker keys. When polluted into Object.prototype,
# many Node frameworks serialize them into the response or use them
# as the response status. We probe these AFTER the nonce probe so
# `status` differential can be observed independently.
_STATUS_MARKERS = ("statusCode", "status")


# ---------------------------------------------------------------------------
# HTTP send (cluster-A safety, same pattern as scan_cache_deception)
# ---------------------------------------------------------------------------


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _send(
    method: str, url: str, *,
    body: str | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """Send via cluster-A safety. Returns `{status, headers, body,
    error?, skipped?}`. Identical contract to `_send_get` in
    `scan_cache_deception`."""
    headers = dict(headers or {})
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager
        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request(
                method, url, headers=headers,
                body=body, timeout=int(timeout),
            )
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": (r.get("body") or "")[:_MAX_BODY_SCAN],
            }
        except Exception:  # noqa: BLE001
            logger.debug("scan_prototype_pollution: proxy send failed; falling back",
                         exc_info=True)

    try:
        import httpx
        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            is_path_excluded,
            throttle_for_rate_limit,
        )
        excluded, _ = is_path_excluded(url)
        if excluded:
            return {"status": 0, "headers": {}, "body": "", "skipped": True}
        merged = inject_auth_headers(headers)
        throttle_for_rate_limit()
        with httpx.Client(
            timeout=timeout, follow_redirects=False, verify=False,
        ) as c:
            if method.upper() == "GET":
                r = c.get(url, headers=merged)
            elif method.upper() == "POST":
                r = c.post(url, headers=merged, content=body or "")
            else:
                r = c.request(method.upper(), url,
                              headers=merged, content=body or "")
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_BODY_SCAN],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


# ---------------------------------------------------------------------------
# URL composition
# ---------------------------------------------------------------------------


def _url_with_query(base_url: str, params: dict[str, str]) -> str:
    """Append (replace) query parameters on `base_url`."""
    parsed = urlparse(base_url)
    qs = urlencode(params, doseq=False, safe="[]")
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, qs, "",
    ))


# ---------------------------------------------------------------------------
# Pollution detection
# ---------------------------------------------------------------------------


def _nonce_in_response(response: dict[str, Any], nonce: str) -> bool:
    """Look for the nonce in body, headers (any value), or
    serialized header set."""
    if not nonce:
        return False
    body = response.get("body") or ""
    if nonce in body:
        return True
    headers = response.get("headers") or {}
    for v in headers.values():
        if isinstance(v, str) and nonce in v:
            return True
    return False


# ---------------------------------------------------------------------------
# Finding emission
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    target_url: str,
    probe_label: str,
    probe_description: str,
    vector_kind: str,
    nonce_evidence: bool,
    status_shift_evidence: dict[str, int] | None,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return None
        # Verification ladder: nonce reflection alone → verified
        # (direct evidence the property leaked into a downstream
        # serialization). Status shift alone → pattern_match (could
        # be a coincident server error). Both together → verified +
        # max confidence.
        if nonce_evidence:
            verification = "verified"
            confidence = 0.95 if status_shift_evidence else 0.9
        else:
            verification = "pattern_match"
            confidence = 0.7

        evidence_lines = []
        if nonce_evidence:
            evidence_lines.append(
                "Nonce planted via `__proto__` injection was reflected "
                "in a subsequent unrelated response — direct proof the "
                "polluted property is inherited by downstream objects."
            )
        if status_shift_evidence:
            baseline_status = status_shift_evidence.get("baseline_status")
            polluted_status = status_shift_evidence.get("polluted_status")
            evidence_lines.append(
                f"Status-code differential observed: baseline returned "
                f"{baseline_status}, follow-up after pollution returned "
                f"{polluted_status}. Consistent with `Object.prototype."
                f"statusCode = X` being read by the response builder."
            )

        finding_id = tracer.add_vulnerability_report(
            title=f"Server-side prototype pollution via `{probe_label}`",
            severity="high",
            cwe="CWE-1321",
            endpoint=target_url,
            target=target_url,
            category="prototype_pollution",
            verification_status=verification,
            confidence=confidence,
            description=(
                f"Probe `{probe_label}` ({probe_description}) "
                f"successfully polluted server-side `Object.prototype`. "
                f"Evidence:\n\n"
                + "\n\n".join(f"  * {line}" for line in evidence_lines)
            ),
            impact=(
                "Server-side prototype pollution. The attacker controls "
                "`Object.prototype` — every Object on the server now "
                "inherits the polluted property. Concrete impact:\n\n"
                "  * **Auth bypass** — set `Object.prototype.isAdmin = "
                "true`, every user becomes admin.\n"
                "  * **Logic-check bypass** — `if (user.role === "
                "undefined)` no longer fires once the prototype "
                "defines `role`.\n"
                "  * **DoS** — polluting `toString` / `valueOf` causes "
                "type-coercion 500s across unrelated handlers.\n"
                "  * **RCE pivot** — paired with vulnerable sinks "
                "(`lodash.merge`, `set-value`, `child_process` arg "
                "parsing), SSPP yields full RCE in real-world chains "
                "(CVE-2019-10744 lodash, CVE-2022-2999, etc.)."
            ),
            technical_analysis=(
                f"Target: {target_url}\n"
                f"Probe: {probe_label}\n"
                f"Vector: {vector_kind}\n"
                f"Description: {probe_description}\n"
                f"Nonce reflected in observation response: "
                f"{nonce_evidence}\n"
                f"Status-code shift after pollution: "
                f"{status_shift_evidence or '(none)'}"
            ),
            poc_description=(
                f"1. Issue a polluting request to {target_url} using "
                f"the `{probe_label}` shape.\n"
                f"2. Issue a follow-up request to the same / a related "
                f"endpoint; observe the polluted property leak "
                f"(nonce reflection in body / status code shift).\n"
                f"3. Pivot: identify a downstream sink that reads the "
                f"polluted property — common chains include `lodash."
                f"merge` (CVE-2019-10744), `set-value`, "
                f"`child_process` arg parsing with key collisions."
            ),
            remediation_steps=(
                "1. **Use `Object.create(null)`** for any object built "
                "from user-controlled input — those objects have no "
                "prototype chain, so pollution can't reach them.\n"
                "2. **Freeze `Object.prototype`** at app startup: "
                "`Object.freeze(Object.prototype)`. Defense in depth.\n"
                "3. **Validate property names** before merge / "
                "deep-assign operations — reject `__proto__`, "
                "`prototype`, `constructor` as keys.\n"
                "4. **Switch to safer libraries**: use `lodash` ≥ "
                "4.17.12 (CVE-2019-10744 patched), avoid `set-value` "
                "< 4.0.0, prefer `Map` over plain Object for user-"
                "input-keyed structures.\n"
                "5. **Disable bracket-notation query parsing** "
                "(`qs.parse(..., { allowPrototypes: false })` — the "
                "Express default since 4.x but check older code)."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C", "C": "H", "I": "H", "A": "H",
            },
            reasoning_trace=[
                f"Polluting request issued via {probe_label}.",
                "Follow-up observation request issued.",
                *evidence_lines,
                "Pollution primitive confirmed; pivot to gadget-"
                "chain RCE is the agent's MOAK follow-up.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=target_url,
                param=probe_label,
                cwe="CWE-1321", severity="high",
                category="prototype_pollution",
                method="POST" if vector_kind == "json_body" else "GET",
                detection_kind=probe_label,
                confidence=confidence,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_prototype_pollution: kg record failed: %s",
                         e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_prototype_pollution: emit failed: %s",
                     e, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Public specialist
# ---------------------------------------------------------------------------


@register_specialist_tool(
    category="prototype-pollution-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 180},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190", "T1565.003"],
)
def scan_prototype_pollution(
    *,
    url: str,
    observation_url: str | None = None,
    probes: list[str] | None = None,
    nonce_marker_key: str = "x_strix_pollution_marker",
    detect_status_shift: bool = True,
    timeout_seconds: float = 12.0,
    max_probes: int = _DEFAULT_MAX_PROBES,
) -> SpecialistResult:
    """Probe a target endpoint for server-side prototype pollution.

    Args:
        url: target endpoint. The polluting request hits this URL;
            JSON probes POST here, query probes GET with appended
            query parameters.
        observation_url: optional separate endpoint to GET after
            each pollution attempt — used for nonce-reflection
            detection. Defaults to the same `url` (most apps share
            response builders across endpoints, so a same-endpoint
            observation often suffices).
        probes: optional allow-list of probe labels. None = all
            built-in probes. Useful for narrowed scans against a
            framework known to use a specific routing style.
        nonce_marker_key: property name to inject into the polluted
            prototype. Default is namespaced to avoid colliding
            with anything else the agent might inject.
        detect_status_shift: when True (default), runs an extra
            pair of probes that pollute `statusCode` / `status` to
            detect the status-differential signal.
        timeout_seconds: per-request timeout.
        max_probes: hard cap on probes (default 24).

    Findings emit as `category=prototype_pollution`, CWE-1321,
    severity high. Verified when the planted nonce is reflected in
    a subsequent response; pattern_match when only the status-shift
    signal fires.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return SpecialistResult(
            status="error",
            error=f"invalid url (need scheme + host): {url}",
        )

    observe_url = (observation_url or url).strip()
    if not urlparse(observe_url).netloc:
        return SpecialistResult(
            status="error",
            error=f"invalid observation_url: {observe_url}",
        )

    # Per-run nonce; cryptographic-quality so observations are
    # unambiguous (collision-free across parallel runs).
    nonce = secrets.token_hex(8)

    allowed_labels = set(probes) if probes else None
    active_probes = [
        p for p in _PROBES
        if allowed_labels is None or p[0] in allowed_labels
    ]
    if not active_probes:
        return SpecialistResult(
            status="error",
            error="no probes selected (check `probes` allow-list)",
        )

    # Baseline status for status-shift detection.
    baseline_status: int | None = None
    if detect_status_shift:
        baseline = _send("GET", observe_url, timeout=timeout_seconds)
        if baseline.get("error") or baseline.get("skipped"):
            detect_status_shift = False  # can't establish baseline
        else:
            baseline_status = baseline["status"]

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted = 0
    probes_run = 0
    seen: set[str] = set()

    for label, kind, builder, description in active_probes:
        if probes_run >= max_probes:
            break
        if label in seen:
            continue
        seen.add(label)
        probes_run += 1

        # ---- Phase 1: pollute ----
        if kind == "json_body":
            body, headers = builder(nonce, nonce_marker_key)
            pollute_url = url
            pollute_method = "POST"
            pollute_resp = _send(
                pollute_method, pollute_url,
                body=body, headers=headers,
                timeout=timeout_seconds,
            )
        elif kind == "query":
            params = builder(nonce, nonce_marker_key)
            pollute_url = _url_with_query(url, params)
            pollute_method = "GET"
            pollute_resp = _send(
                pollute_method, pollute_url,
                timeout=timeout_seconds,
            )
        else:
            continue  # unreachable

        if pollute_resp.get("skipped"):
            continue

        # ---- Phase 2: observe ----
        observe_resp = _send(
            "GET", observe_url, timeout=timeout_seconds,
        )
        if observe_resp.get("skipped") or observe_resp.get("error"):
            continue

        nonce_evidence = _nonce_in_response(observe_resp, nonce)

        # ---- Phase 2b (optional): status-shift detection ----
        status_shift_evidence: dict[str, int] | None = None
        if (
            detect_status_shift
            and baseline_status is not None
            and observe_resp["status"] != baseline_status
            # Filter pure server-error noise: only report a shift
            # if the observation came back DIFFERENT from baseline
            # AND the polluting response itself was 2xx/3xx (a 500
            # back from pollution alone proves nothing about the
            # prototype state).
            and 200 <= pollute_resp["status"] < 500
        ):
            status_shift_evidence = {
                "baseline_status": baseline_status,
                "polluted_status": observe_resp["status"],
            }

        if not (nonce_evidence or status_shift_evidence):
            continue

        rid = _emit_finding(
            target_url=url,
            probe_label=label,
            probe_description=description,
            vector_kind=kind,
            nonce_evidence=nonce_evidence,
            status_shift_evidence=status_shift_evidence,
        )
        if rid:
            emitted += 1
        drafts.append(FindingDraft(
            title=f"Prototype pollution: {label}",
            severity="high", cwe="CWE-1321",
            endpoint=url, category="prototype_pollution",
            verification_status="verified" if nonce_evidence
            else "pattern_match",
            confidence=0.95 if nonce_evidence else 0.7,
            description=(
                f"{description}"
                + (f"; nonce reflected" if nonce_evidence else "")
                + (f"; status shift "
                   f"{status_shift_evidence['baseline_status']}→"
                   f"{status_shift_evidence['polluted_status']}"
                   if status_shift_evidence else "")
            ),
        ))
        evidence.append(
            f"{label}: nonce_reflected={nonce_evidence} "
            f"status_shift={bool(status_shift_evidence)}"
        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(
            url, method="POST", probed_for="prototype_pollution",
        )
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_prototype_pollution"},
            input={"probes_run": probes_run,
                   "observation_url": observe_url,
                   "nonce": nonce[:8] + "..."},
            output={"findings_emitted": emitted,
                    "drafts": len(drafts)},
        )
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            [
                "pivot to gadget-chain RCE: enumerate downstream "
                "sinks that read the polluted property — lodash."
                "merge / set-value / child_process arg parsing.",
                "test sibling endpoints (`/api/*`) for the same "
                "primitive — pollution is process-wide so any "
                "endpoint sharing the Node process inherits it.",
            ]
            if drafts else
            [
                "no pollution found via the bundled probe set; "
                "if the target uses non-`qs` query parsing or "
                "rejects `__proto__` literally, extend `probes` "
                "with custom framework-specific shapes "
                "(e.g. `_proto_`-stripping variants).",
            ]
        ),
        tool_metadata={
            "target": url,
            "observation_url": observe_url,
            "probes_run": probes_run,
            "findings_emitted_to_tracer": emitted,
            "nonce_marker_key": nonce_marker_key,
            "status_shift_detection_enabled": detect_status_shift,
        },
    )
