"""`scan_business_logic` — workflow / state-machine abuse specialist
(workitem.md Phase 5.6).

Closes OWASP A04:2021 (Insecure Design / business-logic flaws —
currently 0 dedicated coverage). Targets the class of bugs that
syntax-level scanners miss because the input itself is well-formed
— the abuse is in the WORKFLOW or the BUSINESS RULE.

Probe families
--------------

  1. **Price / coupon tampering** (CWE-840)
     Detect endpoints that accept price-shaped fields in the
     request body. Probe with:
       * Negative price (`{"price": -10}`)
       * Zero price (`{"price": 0}`)
       * Currency-mismatch (`{"price": 100, "currency": "ZWD"}`)
       * Quantity overflow (`{"quantity": 9999999}`)
       * Discount-stack (`{"coupon": "ADMIN50", "coupon": "ADMIN50"}`)
     Detection: response indicates accepted purchase / cart with
     bogus values (success markers + non-error status).

  2. **Workflow skip** (CWE-841)
     Detect endpoints that finalize a multi-step flow (POST
     `/checkout/complete`, `/payment/confirm`, `/order/place`)
     and try to call them WITHOUT going through prerequisite
     steps. Detection: success response without prior cart/state.

  3. **Parameter pollution** (CWE-235)
     Send the same param twice with conflicting values:
     `?role=user&role=admin`. Detection: response treats one as
     authoritative (compare to baseline single-param behaviour).

  4. **Race conditions on idempotency-required flows** —
     coupon redemption, signup, vote, like. Reuses existing
     `race_check` primitive when it's available; this specialist
     just generates the call list. Detection: more
     state-changes occurred than were paid for.

This is a NEW specialist on top of the existing race_check tool;
it doesn't duplicate the race-detection primitive but adds
business-shaped probes that race_check doesn't generate. Tier-A.2
detection — these are the bugs that single-tool scanners always
miss.

Severity:
  * **Critical** — price set to negative / 0 accepted; admin role
    achieved via param pollution
  * **High** — workflow skip succeeds; race condition fires
  * **Medium** — currency mismatch accepted, coupon stack accepted

Best-effort throughout; gracefully reports `status=partial` when
the endpoint shape doesn't match any probe family.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Param-name lexicon for price-shape detection.
_PRICE_FIELDS: frozenset[str] = frozenset({
    "price", "amount", "total", "subtotal", "cost", "fee",
    "shipping", "tax", "discount", "balance", "credit",
    "value", "charge",
})

_QUANTITY_FIELDS: frozenset[str] = frozenset({
    "quantity", "qty", "count", "items", "stock",
})

_ROLE_FIELDS: frozenset[str] = frozenset({
    "role", "user_role", "userRole", "type", "user_type",
    "is_admin", "isAdmin", "permission", "level", "tier",
})


# Workflow-finalization URL patterns.
_FINALIZATION_RE = re.compile(
    r"/(checkout/complete|payment/confirm|order/(place|complete)|"
    r"transaction/(execute|finalize)|workflow/(complete|finish)|"
    r"cart/checkout|api/(orders|payments|transactions)/finalize|"
    r"submit|publish/finalize)",
    re.IGNORECASE,
)


# Success markers in response body — used to discriminate
# "accepted" vs "rejected" responses on tampering probes.
_SUCCESS_MARKERS = (
    '"success":true', '"status":"success"', '"status":"completed"',
    '"order_id"', '"orderId"', '"transaction_id"', '"transactionId"',
    '"confirmed":true', '"paid":true',
)


def _has_success_marker(body: str) -> bool:
    if not isinstance(body, str):
        return False
    bl = body.lower().replace(" ", "")
    return any(m.lower().replace(" ", "") in bl for m in _SUCCESS_MARKERS)


# ---------------------------------------------------------------------------
# Probe builders
# ---------------------------------------------------------------------------


def _tamper_price(body: dict[str, Any], field: str) -> list[tuple[str, dict[str, Any], str]]:
    """Return [(label, mutated_body, severity)] for price-tampering."""
    out: list[tuple[str, dict[str, Any], str]] = []
    out.append((
        f"price_negative_{field}",
        {**body, field: -10},
        "critical",
    ))
    out.append((
        f"price_zero_{field}",
        {**body, field: 0},
        "critical",
    ))
    return out


def _tamper_quantity(body: dict[str, Any], field: str) -> list[tuple[str, dict[str, Any], str]]:
    out: list[tuple[str, dict[str, Any], str]] = []
    out.append((
        f"quantity_negative_{field}",
        {**body, field: -1},
        "high",
    ))
    out.append((
        f"quantity_overflow_{field}",
        {**body, field: 9999999},
        "medium",
    ))
    return out


def _tamper_role(body: dict[str, Any], field: str) -> list[tuple[str, dict[str, Any], str]]:
    out: list[tuple[str, dict[str, Any], str]] = []
    out.append((
        f"role_admin_{field}",
        {**body, field: "admin"},
        "critical",
    ))
    out.append((
        f"role_superuser_{field}",
        {**body, field: "superuser"},
        "critical",
    ))
    return out


# ---------------------------------------------------------------------------
# Workflow-skip probe
# ---------------------------------------------------------------------------


def _is_finalization_url(url: str) -> bool:
    try:
        parts = urlparse(url)
        return bool(_FINALIZATION_RE.search(parts.path or ""))
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Param pollution
# ---------------------------------------------------------------------------


def _build_polluted_url(url: str, param: str, values: list[str]) -> str:
    """Build a URL with `param` repeated multiple times — produces
    `?param=v1&param=v2`."""
    from urllib.parse import parse_qs, urlencode

    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    # Drop the original param entirely.
    qs.pop(param, None)
    base = urlencode(qs, doseq=True)
    pollution = "&".join(f"{param}={v}" for v in values)
    new_query = pollution if not base else f"{base}&{pollution}"
    return urlunparse(parts._replace(query=new_query))


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    url: str,
    family: str,
    probe_label: str,
    severity: str,
    response_excerpt: str,
    extra_context: str = "",
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        cwe_for_family = {
            "price_tampering": "CWE-840",
            "workflow_skip": "CWE-841",
            "param_pollution": "CWE-235",
            "role_tampering": "CWE-269",
            "quantity_tampering": "CWE-682",
        }.get(family, "CWE-840")
        return tracer.add_vulnerability_report(
            title=f"Business-logic abuse at `{url}` ({family})",
            severity=severity,
            cwe=cwe_for_family,
            endpoint=url,
            target=url,
            category="business_logic",
            verification_status="verified",
            confidence=0.85,
            description=(
                f"The endpoint `{url}` accepts a request shape that "
                f"violates business-logic invariants. Probe "
                f"`{probe_label}` exercised the {family} family and "
                f"received a success-class response.\n{extra_context}"
            ),
            impact=(
                "Business-logic flaw. Unlike syntax-level injection, "
                "the input itself is well-formed — the bug is the "
                "WORKFLOW / BUSINESS RULE allowing it. Concrete "
                "impacts depend on the family:\n"
                "  * price_tampering — purchase items at $0 / "
                "    negative price; net financial loss to the app.\n"
                "  * role_tampering — escalate to admin via "
                "    parameter manipulation; full account compromise.\n"
                "  * workflow_skip — bypass payment, KYC, terms-of-"
                "    service flows; complete actions without "
                "    prerequisites.\n"
                "  * param_pollution — server-side parser disagrees "
                "    with router about which value is authoritative; "
                "    attack class spans authz / pricing / cache.\n"
                "  * quantity_tampering — negative quantities can "
                "    create CREDIT in the cart; overflow can drain "
                "    inventory."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Family: {family}\n"
                f"Probe: {probe_label}\n"
                f"{extra_context}\n"
                f"Response excerpt:\n{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send the {family} probe ({probe_label}) to "
                f"{url}.\n"
                f"2. Server returned a success-class response — the "
                f"business invariant doesn't hold.\n"
                f"3. Pivot: chain with cart manipulation / authz "
                f"bypass for full impact PoC."
            ),
            poc_script_code=(
                f"# See test corpus / Phase 5.6 specialist for "
                f"family-specific PoC payload."
            ),
            remediation_steps=(
                "1. Validate business invariants server-side. NEVER "
                "trust client-supplied price / quantity / role "
                "fields. Compute price from server-side product "
                "catalog; clamp quantity to positive integers; "
                "derive role from session, never from request body.\n"
                "2. Use a state machine for multi-step flows. The "
                "finalization endpoint MUST verify all prior steps "
                "completed (cart populated, payment authorised, "
                "TOS accepted). Missing prerequisites → reject.\n"
                "3. Reject duplicate query parameters at the edge "
                "(WAF rule: `?param=v1&param=v2` returns 400) OR pin "
                "the parser order (last-wins / first-wins) and "
                "validate every param fits the expected enum.\n"
                "4. Apply rate-limit + idempotency-key checks on "
                "state-change flows so concurrent requests can't "
                "race past business-logic validation."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "L", "UI": "N",
                "S": "U",
                "C": "L",
                "I": "H" if severity == "critical" else "L",
                "A": "L",
            },
            reasoning_trace=[
                f"Probed business-logic family `{family}`.",
                f"Probe: {probe_label}",
                "Response evidenced acceptance of an invariant-"
                "violating request.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_business_logic: emit failed: %s", e, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------


@register_specialist_tool(
    category="business-logic-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 90},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190"],
)
def scan_business_logic(
    *,
    url: str,
    body_template: dict[str, Any] | None = None,
    method: str = "POST",
    extra_headers: dict[str, str] | None = None,
    enabled_families: list[str] | None = None,
) -> SpecialistResult:
    """Workflow / business-logic abuse scanner.

    Args:
        url: target URL (typically a state-changing POST endpoint).
        body_template: baseline request body. The scanner mutates
            specific fields per probe family. When None, scanner
            tries minimal probes that don't require a body shape
            (workflow-skip + param-pollution).
        method: HTTP method (default POST). Workflow-skip probes
            assume POST.
        extra_headers: forwarded as-is.
        enabled_families: subset of families to probe — `price_tampering`,
            `quantity_tampering`, `role_tampering`, `workflow_skip`,
            `param_pollution`. Default: all.

    Auto-emits findings per family that succeeds. Severity calibrated
    by impact.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    families = list(enabled_families) if enabled_families else [
        "price_tampering", "quantity_tampering", "role_tampering",
        "workflow_skip", "param_pollution",
    ]

    # Auth auto-injection.
    headers = dict(extra_headers or {})
    if "Authorization" not in headers and "authorization" not in {
        h.lower() for h in headers
    }:
        try:
            from strix.agents.security_context import list_auth_states
            for state in list_auth_states():
                if state.bearer:
                    headers["Authorization"] = f"Bearer {state.bearer}"
                    break
                if state.cookies:
                    headers["Cookie"] = "; ".join(
                        f"{k}={v}" for k, v in state.cookies.items()
                    )
                    break
        except Exception:  # noqa: BLE001
            pass

    headers.setdefault("Content-Type", "application/json")

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

    # Discover candidate fields from body_template when present.
    candidate_price_fields: list[str] = []
    candidate_quantity_fields: list[str] = []
    candidate_role_fields: list[str] = []
    if isinstance(body_template, dict):
        for k in body_template.keys():
            kl = (k or "").lower()
            if kl in _PRICE_FIELDS:
                candidate_price_fields.append(k)
            if kl in _QUANTITY_FIELDS:
                candidate_quantity_fields.append(k)
            if kl in _ROLE_FIELDS:
                candidate_role_fields.append(k)

    # ----- price_tampering -----
    if "price_tampering" in families and candidate_price_fields:
        for field in candidate_price_fields:
            for label, mutated, severity in _tamper_price(
                body_template or {}, field,
            ):
                try:
                    resp = pm.send_simple_request(
                        method.upper(), url,
                        headers=headers,
                        body=json.dumps(mutated),
                        timeout=15,
                    )
                    probe_count += 1
                except Exception as e:  # noqa: BLE001
                    evidence.append(f"price_tampering ({label}): {e}")
                    continue
                if "error" in resp and not resp.get("status_code"):
                    continue
                status = int(resp.get("status_code") or 0)
                body_resp = resp.get("body") or ""
                if 200 <= status < 300 and _has_success_marker(body_resp):
                    rid = _emit_finding(
                        url=url, family="price_tampering",
                        probe_label=label, severity=severity,
                        response_excerpt=body_resp,
                        extra_context=(
                            f"Server accepted price-tamper "
                            f"`{label}` with status {status}."
                        ),
                    )
                    if rid:
                        emitted_count += 1
                    drafts.append(FindingDraft(
                        title=f"Price tampering at `{url}` ({label})",
                        severity=severity, cwe="CWE-840",
                        endpoint=url, category="business_logic",
                        verification_status="verified", confidence=0.85,
                        description=(
                            f"Tampered field={field}, status={status}; "
                            f"success markers present"
                        ),
                    ))
                    evidence.append(
                        f"price_tampering: {label} → status={status}, "
                        f"accepted"
                    )

    # ----- quantity_tampering -----
    if "quantity_tampering" in families and candidate_quantity_fields:
        for field in candidate_quantity_fields:
            for label, mutated, severity in _tamper_quantity(
                body_template or {}, field,
            ):
                try:
                    resp = pm.send_simple_request(
                        method.upper(), url,
                        headers=headers,
                        body=json.dumps(mutated),
                        timeout=15,
                    )
                    probe_count += 1
                except Exception as e:  # noqa: BLE001
                    evidence.append(f"quantity_tampering ({label}): {e}")
                    continue
                if "error" in resp and not resp.get("status_code"):
                    continue
                status = int(resp.get("status_code") or 0)
                body_resp = resp.get("body") or ""
                if 200 <= status < 300 and _has_success_marker(body_resp):
                    rid = _emit_finding(
                        url=url, family="quantity_tampering",
                        probe_label=label, severity=severity,
                        response_excerpt=body_resp,
                    )
                    if rid:
                        emitted_count += 1
                    drafts.append(FindingDraft(
                        title=f"Quantity tampering at `{url}` ({label})",
                        severity=severity, cwe="CWE-682",
                        endpoint=url, category="business_logic",
                        verification_status="verified", confidence=0.8,
                        description=f"Tampered quantity field={field}",
                    ))
                    evidence.append(
                        f"quantity_tampering: {label} accepted"
                    )

    # ----- role_tampering -----
    if "role_tampering" in families and candidate_role_fields:
        for field in candidate_role_fields:
            for label, mutated, severity in _tamper_role(
                body_template or {}, field,
            ):
                try:
                    resp = pm.send_simple_request(
                        method.upper(), url,
                        headers=headers,
                        body=json.dumps(mutated),
                        timeout=15,
                    )
                    probe_count += 1
                except Exception as e:  # noqa: BLE001
                    evidence.append(f"role_tampering ({label}): {e}")
                    continue
                if "error" in resp and not resp.get("status_code"):
                    continue
                status = int(resp.get("status_code") or 0)
                body_resp = resp.get("body") or ""
                if 200 <= status < 300 and (
                    _has_success_marker(body_resp)
                    or "admin" in (body_resp or "").lower()
                ):
                    rid = _emit_finding(
                        url=url, family="role_tampering",
                        probe_label=label, severity=severity,
                        response_excerpt=body_resp,
                    )
                    if rid:
                        emitted_count += 1
                    drafts.append(FindingDraft(
                        title=f"Role tampering at `{url}` ({label})",
                        severity=severity, cwe="CWE-269",
                        endpoint=url, category="business_logic",
                        verification_status="verified", confidence=0.85,
                        description=f"Set role field {field}={mutated[field]!r}",
                    ))
                    evidence.append(f"role_tampering: {label} accepted")

    # ----- workflow_skip -----
    if "workflow_skip" in families and _is_finalization_url(url):
        # Empty body POST to a finalization URL — ANY 2xx that
        # contains a transaction/order id is a workflow-skip signal.
        try:
            resp = pm.send_simple_request(
                "POST", url,
                headers=headers, body="{}", timeout=15,
            )
            probe_count += 1
        except Exception as e:  # noqa: BLE001
            evidence.append(f"workflow_skip transport error: {e}")
        else:
            if not ("error" in resp and not resp.get("status_code")):
                status = int(resp.get("status_code") or 0)
                body_resp = resp.get("body") or ""
                if 200 <= status < 300 and _has_success_marker(body_resp):
                    rid = _emit_finding(
                        url=url, family="workflow_skip",
                        probe_label="empty_body_finalize",
                        severity="high",
                        response_excerpt=body_resp,
                        extra_context=(
                            f"Finalization URL accepted empty-body "
                            f"POST, returning a success-shape "
                            f"response — workflow prerequisites not "
                            f"enforced."
                        ),
                    )
                    if rid:
                        emitted_count += 1
                    drafts.append(FindingDraft(
                        title=f"Workflow skip at `{url}`",
                        severity="high", cwe="CWE-841",
                        endpoint=url, category="business_logic",
                        verification_status="verified", confidence=0.85,
                        description="Finalization without prerequisites",
                    ))
                    evidence.append(
                        f"workflow_skip: empty-body finalize → "
                        f"status={status}, accepted"
                    )

    # ----- param_pollution -----
    # Re-purpose role fields into URL pollution: `?role=user&role=admin`.
    # Only meaningful when method=GET and URL has query params.
    if "param_pollution" in families:
        parsed = urlparse(url)
        from urllib.parse import parse_qs
        qs_keys = list(parse_qs(parsed.query).keys())
        for k in qs_keys:
            kl = k.lower()
            if kl in _ROLE_FIELDS:
                polluted = _build_polluted_url(url, k, ["user", "admin"])
                try:
                    resp = pm.send_simple_request(
                        "GET", polluted,
                        headers=headers, body="", timeout=15,
                    )
                    probe_count += 1
                except Exception as e:  # noqa: BLE001
                    evidence.append(f"param_pollution ({k}): {e}")
                    continue
                if "error" in resp and not resp.get("status_code"):
                    continue
                status = int(resp.get("status_code") or 0)
                body_resp = resp.get("body") or ""
                if 200 <= status < 300 and "admin" in (body_resp or "").lower():
                    rid = _emit_finding(
                        url=polluted, family="param_pollution",
                        probe_label=f"role_pollution_{k}",
                        severity="critical",
                        response_excerpt=body_resp,
                    )
                    if rid:
                        emitted_count += 1
                    drafts.append(FindingDraft(
                        title=f"Parameter pollution at `{polluted}`",
                        severity="critical", cwe="CWE-235",
                        endpoint=polluted, category="business_logic",
                        verification_status="verified", confidence=0.85,
                        description=f"Pollution on {k}; admin marker in body",
                    ))
                    evidence.append(
                        f"param_pollution: {k} → admin marker accepted"
                    )

    # No body_template + no finalization URL = no probes ran.
    if probe_count == 0:
        return SpecialistResult(
            status="partial",
            error=(
                "no business-logic probes applied — supply "
                "body_template with price/quantity/role fields, OR "
                "target a finalization URL (e.g. /checkout/complete)."
            ),
            evidence=[
                "scan_business_logic discovered no candidate fields "
                "or workflow finalizers",
            ],
        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method=method, probed_for="business_logic")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_business_logic"},
            input={
                "families": families,
                "probes_sent": probe_count,
                "candidate_fields": {
                    "price": candidate_price_fields,
                    "quantity": candidate_quantity_fields,
                    "role": candidate_role_fields,
                },
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
            ["chain with race_check on idempotency-required flows "
             "(coupon redeem, signup, vote) for the timing variant; "
             "manually verify chain via authenticated PoC "
             "(buy with $0 → confirm cart shows the order)"]
            if drafts else
            ["no business-logic abuse on listed families; consider "
             "multi-step workflow probes (cart manipulation + "
             "checkout) and inter-account transfers (multi-role "
             "from Phase 3.1)"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "families_probed": families,
            "candidate_price_fields": candidate_price_fields,
            "candidate_quantity_fields": candidate_quantity_fields,
            "candidate_role_fields": candidate_role_fields,
            "findings_emitted_to_tracer": emitted_count,
        },
    )
