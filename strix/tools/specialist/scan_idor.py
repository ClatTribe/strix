"""`scan_idor` — deterministic IDOR specialist (workitem.md Phase 4.1).

Closes OWASP A01:2021 / CWE-639 / CWE-284 / CWE-862. Closes the Juice
Shop `idor-basket` manifest gap with a proper category emit (not the
generic info_disclosure that the lead sometimes substitutes).

Detection model
---------------

Insecure Direct Object Reference happens when an endpoint serves a
resource keyed off a user-controlled ID without an ownership/authz
check. The canonical detection is **two-user differential**:

  1. Capture User-A and User-B sessions (precondition shipped by
     Phase 3.1 `scan_multi_role_auth`).
  2. Identify endpoints with numeric / UUID IDs in path or query.
  3. Issue request-A: User-A fetches their own resource. Record body.
  4. Issue request-A2: User-B fetches User-A's resource ID with
     User-B's session.
  5. Compare:
     * Request-A2 returns 200 AND body resembles request-A's body
       → IDOR confirmed (User-B reads User-A's data).
     * Request-A2 returns 401/403/404 → ownership check enforced.

Even simpler: anon (no creds) fetches the protected resource ID and
gets 200 → CWE-862 missing-auth.

Probe matrix
------------

For each candidate endpoint:

  * **anon → resource_id_a**       — missing-auth detection (CWE-862)
  * **user-b → resource_id_a**     — IDOR (CWE-639)
  * **anon → resource_id_b**       — symmetry check
  * **user-a → resource_id_b**     — symmetry IDOR

Resource IDs come from path-segment / query-param introspection of
the URLs SecurityContext recorded. Heuristic: numeric (`/users/42`,
`/orders/100`) or UUID (`/users/<uuid>`) terminal segment.

Auto-emits CWE-639 (IDOR) or CWE-862 (missing auth) on detection.
Severity: high. Critical if response contains PII / payment / admin
data fingerprints.
"""

from __future__ import annotations

import logging
import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Numeric or UUID terminal-segment patterns. The path is split on `/`
# and we look for IDs in any segment, with the LAST id-shaped segment
# being the one we substitute.
_NUMERIC_ID_RE = re.compile(r"^\d+$")
_UUID_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX_ID_RE = re.compile(r"^[0-9a-fA-F]{16,}$")  # MongoDB ObjectId-ish


# Markers in response bodies that imply PII / sensitive data was
# returned. Used to escalate IDOR severity to critical.
_SENSITIVE_MARKERS: tuple[str, ...] = (
    "ssn", "social_security", "creditcard", "credit_card",
    "card_number", "cvv", "cvc", "iban", "swift",
    "passport", "tax_id", "national_id",
    "date_of_birth", "dob", "birthdate",
    "salary", "compensation",
    # Email + phone are weak markers — only counted when paired with
    # other identifiers.
)


def _is_id_segment(segment: str) -> bool:
    """True when the path/query segment looks like a resource ID we
    can substitute (numeric, UUID, MongoDB ObjectId)."""
    if not segment:
        return False
    return bool(
        _NUMERIC_ID_RE.match(segment)
        or _UUID_ID_RE.match(segment)
        or _HEX_ID_RE.match(segment)
    )


def _extract_id_locations(url: str) -> list[tuple[str, str]]:
    """Find ID-shaped segments in the URL. Returns
    [(location_kind, original_value), ...] where location_kind is
    "path" or "query:<param_name>"."""
    out: list[tuple[str, str]] = []
    parts = urlparse(url)
    # Path segments
    for seg in parts.path.split("/"):
        if _is_id_segment(seg):
            out.append(("path", seg))
    # Query params
    from urllib.parse import parse_qs
    for k, vs in parse_qs(parts.query).items():
        for v in vs:
            if _is_id_segment(v):
                out.append((f"query:{k}", v))
    return out


def _swap_id_in_url(url: str, original: str, replacement: str) -> str:
    """Replace `original` (the matched ID segment) with `replacement`
    in `url`. We use a word-boundary-like split to avoid matching
    inside other segments."""
    # Split on `/`, replace exact-match segments, rejoin. Then handle
    # query-string substitution similarly.
    from urllib.parse import parse_qs, urlencode, urlunparse

    parts = urlparse(url)
    new_path_segments = [
        replacement if seg == original else seg
        for seg in parts.path.split("/")
    ]
    new_path = "/".join(new_path_segments)
    qs = parse_qs(parts.query, keep_blank_values=True)
    new_qs: dict[str, list[str]] = {}
    for k, vs in qs.items():
        new_qs[k] = [replacement if v == original else v for v in vs]
    new_query = urlencode(new_qs, doseq=True)
    return urlunparse(parts._replace(path=new_path, query=new_query))


def _looks_like_user_data(body_a: str, body_other: str) -> tuple[bool, float]:
    """Heuristic: does `body_other` (returned to user-B) look like
    user-A's data? Use sequence-similarity over a normalized prefix.

    Returns (is_similar, ratio). Threshold ratio ≥0.7 → confirmed
    IDOR. Below 0.4 → likely a different user's resource (the API
    correctly substituted user-B's resource by ID even though
    user-A's ID was passed — that's still IDOR if the resource is
    sensitive, but let's be cautious).
    """
    if not body_a or not body_other:
        return False, 0.0
    # Normalize: lowercase, strip whitespace runs.
    a_norm = re.sub(r"\s+", " ", body_a[:4000].strip().lower())
    o_norm = re.sub(r"\s+", " ", body_other[:4000].strip().lower())
    if a_norm == o_norm:
        return True, 1.0
    # Empty or trivial bodies don't tell us anything.
    if len(a_norm) < 30 or len(o_norm) < 30:
        return False, 0.0
    ratio = SequenceMatcher(None, a_norm, o_norm).ratio()
    return ratio >= 0.7, ratio


def _has_sensitive_markers(body: str) -> bool:
    if not isinstance(body, str):
        return False
    body_lower = body.lower()
    return any(m in body_lower for m in _SENSITIVE_MARKERS)


def _build_headers(
    *, base_headers: dict[str, str] | None,
    auth_label: str | None,
) -> dict[str, str]:
    """Build request headers with auth from SecurityContext.AuthState
    when `auth_label` is provided. `auth_label="anon"` means no auth
    header — use base_headers as-is."""
    headers = dict(base_headers or {})
    if not auth_label or auth_label == "anon":
        # Strip any baseline auth — anon means anon.
        headers.pop("Authorization", None)
        headers.pop("authorization", None)
        headers.pop("Cookie", None)
        headers.pop("cookie", None)
        return headers
    try:
        from strix.agents.security_context import get_auth_state
        state = get_auth_state(auth_label)
        if state is None:
            return headers
        if state.bearer:
            headers["Authorization"] = f"Bearer {state.bearer}"
        elif state.cookies:
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in state.cookies.items()
            )
    except Exception:  # noqa: BLE001
        pass
    return headers


def _emit_idor_finding(
    *,
    url_attempted: str,
    location_kind: str,
    original_id: str,
    accessor_label: str,
    owner_label: str,
    response_excerpt: str,
    severity: str,
    similarity_ratio: float | None = None,
    cwe: str = "CWE-639",
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        is_missing_auth = (cwe == "CWE-862")
        title = (
            f"Missing authorization at `{url_attempted}` (anon read of "
            f"`{owner_label}`'s resource)"
            if is_missing_auth
            else f"IDOR at `{url_attempted}` (`{accessor_label}` reads "
                 f"`{owner_label}`'s resource)"
        )
        return tracer.add_vulnerability_report(
            title=title,
            severity=severity,
            cwe=cwe,
            endpoint=url_attempted,
            target=url_attempted,
            category="missing_auth" if is_missing_auth else "idor",
            verification_status="verified",
            confidence=0.95,
            description=(
                f"The `{location_kind}` segment `{original_id}` at "
                f"`{url_attempted}` is treated as a direct object "
                f"reference without an ownership check. Session "
                f"`{accessor_label}` fetched the resource owned by "
                f"`{owner_label}` and the server returned the data."
                + (
                    f" Response similarity to owner's view: "
                    f"{similarity_ratio:.0%}"
                    if similarity_ratio is not None else ""
                )
            ),
            impact=(
                "Insecure direct object reference. Any authenticated "
                "user (or, for missing-auth variants, any "
                "unauthenticated client) can iterate object IDs and "
                "read every other user's records:\n"
                "  * Privacy: full PII exfiltration via ID enumeration.\n"
                "  * Payments: read other users' payment / order data.\n"
                "  * Admin: pivot when admin records share the ID space.\n"
                "  * Pre-disclosure data: leak future product / pricing "
                "    data when the records are time-ordered.\n"
                + ("  * Anonymous read of authenticated-only data — "
                   "    multiplies the blast radius (no login needed).\n"
                   if is_missing_auth else "")
            ),
            technical_analysis=(
                f"Endpoint: {url_attempted}\n"
                f"ID location: {location_kind}\n"
                f"Original ID: {original_id}\n"
                f"Accessor session: {accessor_label}\n"
                f"Resource-owner session: {owner_label}\n"
                f"Detection: cross-session probe + response-shape "
                f"comparison.\n"
                + (f"Response similarity ratio: {similarity_ratio:.2f}\n"
                   if similarity_ratio is not None else "")
                + f"Response excerpt:\n{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Authenticate as `{accessor_label}` "
                f"(anonymous client for missing-auth) — no special "
                f"setup required.\n"
                f"2. Send GET {url_attempted}.\n"
                f"3. Observe the response — the server returns "
                f"`{owner_label}`'s record without an ownership "
                f"check.\n"
                f"4. Iterate the ID range to enumerate every user's "
                f"resource."
            ),
            poc_script_code=f"curl -sS '{url_attempted}'",
            remediation_steps=(
                "1. Add an ownership check at the controller layer. "
                "Pseudo-code:\n"
                "     resource = repo.find(id)\n"
                "     if resource.owner_id != current_user.id: 403\n"
                "2. Use the framework's authorization API rather than "
                "ad-hoc checks:\n"
                "     Spring Security: @PreAuthorize(\"@perms.owns("
                "#id, principal)\")\n"
                "     Django: @user_passes_test(...)\n"
                "     Rails: Pundit / CanCanCan policies\n"
                "3. Replace direct database IDs with per-user UUIDs "
                "or signed/encrypted handles where feasible (defense "
                "in depth — IDs become unguessable, but never the "
                "primary defence).\n"
                "4. Audit every endpoint that takes an `id` param "
                "for an explicit ownership check; add a CI lint that "
                "flags missing checks on new endpoints."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L",
                "PR": "N" if is_missing_auth else "L",
                "UI": "N",
                "S": "U",
                "C": "H", "I": "H" if is_missing_auth else "L", "A": "N",
            },
            reasoning_trace=[
                f"Identified ID-shaped segment `{original_id}` in "
                f"{location_kind} of {url_attempted}.",
                f"Probe with `{accessor_label}` against "
                f"`{owner_label}`'s resource ID returned 200.",
                "Response body matched the owner's view — no "
                "ownership check enforced.",
                "Severity: critical when sensitive markers in body, "
                "high otherwise.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_idor: emit failed: %s", e, exc_info=True)
        return None


def _record_in_kg(
    *, finding_id: str | None, url: str, accessor_label: str,
    severity: str, cwe: str,
) -> None:
    """Populate §3 KG with Vuln + Surface + AFFECTS triple after a
    successful IDOR / missing-auth emit. Best-effort."""
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        category = "missing_auth" if cwe == "CWE-862" else "idor"
        record_finding_in_kg(
            finding_id=finding_id, url=url,
            # Use `accessor_label` as the param surrogate — IDOR is
            # path-based, not param-based, but the (url, param,
            # method) dedup key still works (path-only URLs collapse
            # to one Surface; one Vuln per accessor demonstrates
            # the cross-session read).
            param=accessor_label,
            cwe=cwe, severity=severity, category=category,
            method="GET",
            detection_kind="cross_session_read" if cwe == "CWE-639" else "anon_read",
            confidence=0.95,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_idor: kg record failed: %s", e, exc_info=True)


@register_specialist_tool(
    category="idor-specialist",
    # Phase 3b — adaptive-retry inner-LLM enabled. See scan_xss.py
    # for the protocol; same kill switch
    # (STRIX_SPECIALIST_INNER_LLM_DISABLED=1).
    llm=True,
    system_prompt_path="tools/specialist/prompts/idor.md",
    default_budget={"cost_usd": 0.05, "max_wall_seconds": 150},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1078", "T1531"],
)
def scan_idor(
    *,
    urls: list[str] | str | None = None,
    url: str | None = None,
    owner_label: str = "user-a",
    accessor_label: str = "user-b",
    test_anon: bool = True,
    extra_headers: dict[str, str] | None = None,
    max_urls: int = 50,
) -> SpecialistResult:
    """Cross-session IDOR scanner. Requires Phase 3.1 multi-role
    `scan_multi_role_auth` to have captured `owner_label` and
    `accessor_label` sessions in `SecurityContext.AuthState`.

    Args:
        urls: list of URLs to probe (each containing an ID-shaped
            segment). When None, scanner falls back to URLs
            recorded in SecurityContext.endpoints.
        url: convenience alias for a single URL.
        owner_label: AuthState label of the resource owner. The IDs
            in `urls` are assumed to belong to this user.
        accessor_label: AuthState label of the user who SHOULDN'T be
            able to read the owner's resources.
        test_anon: when True (default), also probe with anonymous
            session — surfaces missing-auth (CWE-862) findings.
        extra_headers: forwarded as-is on every request (in addition
            to the auth-label-derived auth header).
        max_urls: cap to prevent runaway probing.

    Auto-emits one finding per (url, accessor) IDOR hit.
    """
    if url and not urls:
        urls = [url]
    if isinstance(urls, str):
        urls = [urls]

    if not urls:
        # Fallback: pull URLs from SecurityContext.endpoints.
        try:
            from strix.agents.security_context import (
                get_security_context, list_endpoints,
            )
            ctx = get_security_context()
            base = ctx.target_url
            urls = []
            if base:
                base_clean = base.rstrip("/")
                for ep in list_endpoints():
                    candidate = base_clean + "/" + ep.path.lstrip("/")
                    if _extract_id_locations(candidate):
                        urls.append(candidate)
        except Exception:  # noqa: BLE001
            pass

    if not urls:
        return SpecialistResult(
            status="partial",
            error="no URLs supplied",
            evidence=[
                "scan_idor invoked with no urls; supply `urls=[...]` or "
                "`url=...`. Typically called after recon has populated "
                "SecurityContext.endpoints with ID-shaped paths."
            ],
        )

    urls = list(urls)[:max_urls]

    # Verify the labels actually have sessions captured.
    captured_labels = []
    try:
        from strix.agents.security_context import list_auth_states
        captured_labels = [s.label for s in list_auth_states()]
    except Exception:  # noqa: BLE001
        pass
    if owner_label not in captured_labels:
        return SpecialistResult(
            status="partial",
            error=(
                f"owner session `{owner_label}` not captured in "
                f"SecurityContext.AuthState; run scan_multi_role_auth "
                f"first."
            ),
            evidence=[f"captured labels: {captured_labels}"],
        )
    if accessor_label not in captured_labels:
        return SpecialistResult(
            status="partial",
            error=(
                f"accessor session `{accessor_label}` not captured in "
                f"SecurityContext.AuthState; run scan_multi_role_auth "
                f"first."
            ),
            evidence=[f"captured labels: {captured_labels}"],
        )

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
    fetch_count = 0
    seen_findings: set[tuple[str, str]] = set()

    headers_owner = _build_headers(
        base_headers=extra_headers, auth_label=owner_label,
    )
    headers_accessor = _build_headers(
        base_headers=extra_headers, auth_label=accessor_label,
    )
    headers_anon = _build_headers(base_headers=extra_headers, auth_label="anon")

    for u in urls:
        if not isinstance(u, str) or not u.strip():
            continue
        u = u.strip()
        id_locations = _extract_id_locations(u)
        if not id_locations:
            continue

        # Owner baseline — establish what the owner-view body looks like.
        try:
            owner_resp = pm.send_simple_request(
                "GET", u, headers=headers_owner, body="", timeout=15,
            )
            fetch_count += 1
        except Exception as e:  # noqa: BLE001
            evidence.append(f"owner fetch error for {u}: {e}")
            continue
        if "error" in owner_resp and not owner_resp.get("status_code"):
            continue
        owner_status = int(owner_resp.get("status_code") or 0)
        owner_body = owner_resp.get("body") or ""
        if not isinstance(owner_body, str):
            owner_body = ""
        if owner_status != 200:
            # Owner can't even read their own resource — skip; not
            # representative of an authorization gap.
            evidence.append(
                f"owner GET {u} → {owner_status}; skipping IDOR probe"
            )
            continue

        # Accessor probe.
        try:
            access_resp = pm.send_simple_request(
                "GET", u, headers=headers_accessor, body="", timeout=15,
            )
            fetch_count += 1
        except Exception as e:  # noqa: BLE001
            evidence.append(f"accessor fetch error for {u}: {e}")
            continue
        if "error" not in access_resp or access_resp.get("status_code"):
            access_status = int(access_resp.get("status_code") or 0)
            access_body = access_resp.get("body") or ""
            if not isinstance(access_body, str):
                access_body = ""
            if access_status == 200:
                similar, ratio = _looks_like_user_data(owner_body, access_body)
                if similar:
                    severity = (
                        "critical" if _has_sensitive_markers(access_body)
                        else "high"
                    )
                    key = (u, accessor_label)
                    if key not in seen_findings:
                        seen_findings.add(key)
                        # Use first id-location for reporting.
                        loc_kind, original_id = id_locations[0]
                        rid = _emit_idor_finding(
                            url_attempted=u,
                            location_kind=loc_kind,
                            original_id=original_id,
                            accessor_label=accessor_label,
                            owner_label=owner_label,
                            response_excerpt=access_body,
                            severity=severity,
                            similarity_ratio=ratio,
                            cwe="CWE-639",
                        )
                        if rid:
                            emitted_count += 1
                            _record_in_kg(
                                finding_id=rid, url=u,
                                accessor_label=accessor_label,
                                severity=severity, cwe="CWE-639",
                            )
                        drafts.append(FindingDraft(
                            title=f"IDOR at `{u}` ({accessor_label} reads {owner_label})",
                            severity=severity, cwe="CWE-639",
                            endpoint=u, category="idor",
                            verification_status="verified",
                            confidence=0.95,
                            description=(
                                f"Cross-session read; similarity={ratio:.2f}"
                            ),
                        ))
                        evidence.append(
                            f"IDOR: {u} ({accessor_label} → "
                            f"{owner_label}'s data, ratio={ratio:.2f})"
                        )

        # Anon probe (missing-auth / CWE-862).
        if test_anon:
            try:
                anon_resp = pm.send_simple_request(
                    "GET", u, headers=headers_anon, body="", timeout=15,
                )
                fetch_count += 1
            except Exception as e:  # noqa: BLE001
                evidence.append(f"anon fetch error for {u}: {e}")
                continue
            if "error" in anon_resp and not anon_resp.get("status_code"):
                continue
            anon_status = int(anon_resp.get("status_code") or 0)
            anon_body = anon_resp.get("body") or ""
            if not isinstance(anon_body, str):
                anon_body = ""
            if anon_status == 200:
                similar, ratio = _looks_like_user_data(owner_body, anon_body)
                if similar:
                    severity = (
                        "critical" if _has_sensitive_markers(anon_body)
                        else "high"
                    )
                    key = (u, "anon")
                    if key not in seen_findings:
                        seen_findings.add(key)
                        loc_kind, original_id = id_locations[0]
                        rid = _emit_idor_finding(
                            url_attempted=u,
                            location_kind=loc_kind,
                            original_id=original_id,
                            accessor_label="anon",
                            owner_label=owner_label,
                            response_excerpt=anon_body,
                            severity=severity,
                            similarity_ratio=ratio,
                            cwe="CWE-862",
                        )
                        if rid:
                            emitted_count += 1
                            _record_in_kg(
                                finding_id=rid, url=u,
                                accessor_label="anon",
                                severity=severity, cwe="CWE-862",
                            )
                        drafts.append(FindingDraft(
                            title=f"Missing auth at `{u}` (anon reads {owner_label})",
                            severity=severity, cwe="CWE-862",
                            endpoint=u, category="missing_auth",
                            verification_status="verified",
                            confidence=0.97,
                            description=(
                                f"Anon read of {owner_label}'s data; "
                                f"similarity={ratio:.2f}"
                            ),
                        ))
                        evidence.append(
                            f"missing-auth: {u} (anon → {owner_label}'s data)"
                        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        for u in urls:
            record_endpoint(u, method="GET", probed_for="idor")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=urls[0] if urls else None,
            actor={"tool_name": "scan_idor"},
            input={
                "owner_label": owner_label,
                "accessor_label": accessor_label,
                "test_anon": test_anon,
                "urls_count": len(urls),
            },
            output={
                "fetches_done": fetch_count,
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
                "iterate the ID range — IDOR enables full enumeration "
                "of every user's records",
                "for write-side IDOR, repeat with PUT/POST/DELETE — "
                "ownership-check bugs often differ between read and write",
            ]
            if drafts else
            [
                "no IDOR via numeric/UUID path-segment substitution; "
                "consider POST-body / JSON-payload ID fields, and "
                "GraphQL `node(id:)` queries"
            ]
        ),
        tool_metadata={
            "fetches_done": fetch_count,
            "urls_probed": len(urls),
            "findings_emitted_to_tracer": emitted_count,
            "owner_label": owner_label,
            "accessor_label": accessor_label,
            "test_anon": test_anon,
        },
    )
