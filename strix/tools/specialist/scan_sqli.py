"""`scan_sqli` — deterministic SQL-injection specialist (roadmap §8.5
Phase 3b).

Single-shot SQL-injection detector that probes a URL+param set with
classic SQL-error and boolean-difference payloads, classifies
responses, and **auto-emits findings via `add_vulnerability_report`**
so the lead agent doesn't have to handle the emit-tool's parameter
schema.

Detection strategy (deterministic, no LLM)
------------------------------------------

For each param under test, send four request variants:

  1. **Baseline** — the param's original value (or a benign control).
     Captures the "normal" response signature.
  2. **Error-trigger** — append a malformed-SQL fragment (`'`).
     If the server's response now contains a database-error
     fingerprint (`ORA-01756`, `mysql_fetch_array`, `unclosed
     quotation mark`, `Microsoft SQL Server`, etc.), that's a
     direct error-based SQLi confirmation.
  3. **Boolean-true** — append `' OR '1'='1`. If the response
     differs MEANINGFULLY from the baseline (length / status /
     content), the host evaluates the injected condition.
  4. **Boolean-false** — append `' OR '1'='2`. If this response
     resembles the baseline (and DIFFERS from the boolean-true
     response), confirms the host distinguishes true/false → SQLi
     present even without an explicit error.

The boolean-pair test is what catches "blind" SQLi where the host
swallows errors. Two checks must both fire (true≠false AND
true≠baseline) to confirm; weaker signals downgrade to
`pattern_match` instead of `verified`.

Limitations (Phase 3b minimal scope)
------------------------------------

  * GET requests only. POST / JSON / cookie SQLi is Phase 3c.
  * No time-based / out-of-band detection — those need timing-
    accurate measurements which deterministic-with-jitter HTTP
    probes can't reliably do (a sqlmap-style specialist would
    handle this; track as Phase 4).
  * No second-order SQLi (where injection is stored, then
    triggered on a different request).
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Database-error fingerprints. When the response body matches ANY
# pattern, error-based SQLi is confirmed. Patterns are case-
# insensitive substring matches (cheap; no regex needed for these).
_DB_ERROR_FRAGMENTS: tuple[tuple[str, str], ...] = (
    # MySQL
    ("you have an error in your sql syntax", "MySQL"),
    ("supplied argument is not a valid mysql", "MySQL"),
    ("mysql_fetch_array(", "MySQL"),
    ("mysql_num_rows(", "MySQL"),
    ("mysqli::", "MySQL"),
    # PostgreSQL
    ("pg_exec(", "PostgreSQL"),
    ("postgresql query failed", "PostgreSQL"),
    ("npgsql.", "PostgreSQL"),
    # MS SQL Server
    ("microsoft sql server", "MSSQL"),
    ("microsoft ole db provider for sql", "MSSQL"),
    ("unclosed quotation mark", "MSSQL"),
    ("system.data.sqlclient.sqlexception", "MSSQL"),
    # Oracle
    ("ora-01756", "Oracle"),
    ("ora-00933", "Oracle"),
    ("ora-00921", "Oracle"),
    ("ora-00936", "Oracle"),
    ("oracle.dataaccess", "Oracle"),
    # SQLite
    ("sqlite/jdbcdriver", "SQLite"),
    ("sqlite_query(", "SQLite"),
    ("near \"select\": syntax error", "SQLite"),
    ("sqlite3.operationalerror", "SQLite"),
    # Generic
    ("syntax error converting", "MSSQL"),
    ("sql syntax", "Generic"),
)


_PROBE_PAYLOADS: dict[str, str] = {
    "error_trigger": "'",
    "boolean_true": "' OR '1'='1",
    "boolean_false": "' OR '1'='2",
}


def _build_url_with_param(
    url: str, *, param_name: str, value: str,
    other_params: dict[str, str] | None = None,
) -> str:
    parts = urlparse(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    flat: dict[str, str] = {k: (v[0] if v else "") for k, v in qs.items()}
    if other_params:
        for k, v in other_params.items():
            if k != param_name and k not in flat:
                flat[k] = v
    flat[param_name] = value
    return urlunparse(parts._replace(query=urlencode(flat, doseq=False)))


def _detect_db_error(body: str) -> tuple[bool, str | None]:
    """Returns `(detected, db_engine)`. Case-insensitive substring
    match against the fingerprint table."""
    if not isinstance(body, str) or not body:
        return False, None
    lower = body.lower()
    for fragment, engine in _DB_ERROR_FRAGMENTS:
        if fragment in lower:
            return True, engine
    return False, None


def _strip_dynamic_noise(body: str) -> str:
    """Strip timestamps / nonces / random tokens that vary across
    identical requests, so boolean-true vs baseline comparison isn't
    drowned by per-request churn. Conservative — leaves most content
    intact; just removes obvious volatile patterns."""
    if not isinstance(body, str):
        return ""
    # Strip CSRF-token-shaped fragments.
    body = re.sub(r"[a-fA-F0-9]{32,}", "", body)
    # Strip ISO timestamps.
    body = re.sub(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*[Zz]?",
        "", body,
    )
    # Strip request IDs (UUIDs).
    body = re.sub(
        r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-"
        r"[a-fA-F0-9]{4}-[a-fA-F0-9]{12}",
        "", body,
    )
    # Collapse whitespace runs to a single space.
    body = re.sub(r"\s+", " ", body).strip()
    return body


def _bodies_meaningfully_differ(a: str, b: str) -> bool:
    """True when two normalised bodies differ by more than 5% of
    their length (loose threshold — meant to catch true/false
    branching, not minor template variation)."""
    a = _strip_dynamic_noise(a)
    b = _strip_dynamic_noise(b)
    if not a and not b:
        return False
    if not a or not b:
        return True
    longer = max(len(a), len(b))
    if longer == 0:
        return False
    # Crude but cheap: count differing substring chunks.
    # Use length-delta as the signal (response length tracks content).
    diff = abs(len(a) - len(b))
    if diff / longer > 0.05:
        return True
    # Length similar but content might still differ. Hash-fingerprint
    # the first 4KB and compare.
    return a[:4000] != b[:4000]


def _emit_finding(
    *,
    url: str,
    param: str,
    detection_kind: str,           # "error" | "boolean"
    db_engine: str | None,
    payload: str,
    response_excerpt: str,
    verification_status: str,      # "verified" | "pattern_match"
    confidence: float,
) -> str | None:
    """Emit via `tracer.add_vulnerability_report`. Best-effort; never
    raises. Returns finding id on success, None on failure."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        title = (
            f"Error-based SQL injection in `{param}`"
            if detection_kind == "error"
            else f"Boolean-blind SQL injection in `{param}`"
        )
        engine_str = f" (DB engine: {db_engine})" if db_engine else ""
        return tracer.add_vulnerability_report(
            title=title,
            severity="high",
            cwe="CWE-89",
            endpoint=url,
            target=url,
            category="sqli",
            verification_status=verification_status,
            confidence=confidence,
            description=(
                f"The `{param}` query parameter at `{url}` is "
                f"vulnerable to SQL injection.{engine_str} Probe "
                f"payload: `{payload}`. "
                + (
                    f"Response contains database-error fingerprint, "
                    f"confirming the parameter flows directly into a "
                    f"database query without parameterisation."
                    if detection_kind == "error"
                    else "Response differs measurably between the "
                    "boolean-true (`' OR '1'='1`) and boolean-false "
                    "(`' OR '1'='2`) payloads while baseline matches "
                    "boolean-false — the host evaluates the injected "
                    "SQL clause."
                )
            ),
            impact=(
                "SQL injection. An attacker can extract arbitrary "
                "data from the database (credentials, tokens, PII), "
                "modify or delete rows, escalate privileges via "
                "INSERT/UPDATE on auth tables, and depending on the "
                "DB engine and connector permissions, achieve remote "
                "code execution via UDFs, xp_cmdshell, or "
                "out-of-band channels. This is a critical-severity "
                "issue on any production target."
            ),
            technical_analysis=(
                f"Probe URL: {url}\n"
                f"Param: {param}\n"
                f"Payload: {payload}\n"
                f"Detection: {detection_kind}-based\n"
                + (f"DB engine fingerprinted: {db_engine}\n" if db_engine else "")
                + f"Response excerpt:\n{response_excerpt[:1500]}"
            ),
            poc_description=(
                f"1. Send GET request to {url} with `{param}` set to "
                f"`{payload}`.\n"
                + (
                    "2. Observe the database-error message in the "
                    "response body — confirms the parameter is "
                    "concatenated into a SQL query.\n"
                    "3. Pivot to data extraction with UNION-based or "
                    "blind-boolean exploitation (sqlmap can automate)."
                    if detection_kind == "error"
                    else "2. Repeat with `' OR '1'='2` — observe the "
                    "response now resembles the baseline (matches "
                    "false branch), while `' OR '1'='1` returned a "
                    "different response (matches true branch).\n"
                    "3. Pivot to blind-boolean data extraction "
                    "(sqlmap `-p {param} --technique=B`)."
                )
            ),
            poc_script_code=(
                f"# Reproduce the detection\n"
                f"curl -sS -G '{url}' --data-urlencode '{param}={payload}'\n"
                f"\n"
                f"# Pivot to automated exploitation\n"
                f"sqlmap -u '{url}' -p {param} --batch --risk=2 --level=3"
            ),
            remediation_steps=(
                "Replace string-concatenated SQL queries with "
                "parameterised queries (prepared statements) using "
                "the database driver's parameter-binding API. NEVER "
                "interpolate user input directly into SQL strings, "
                "even after escaping — always use bound parameters. "
                "For ORM-based code (Django, SQLAlchemy, Hibernate, "
                "ActiveRecord, Entity Framework), use the ORM's "
                "query builder rather than raw-SQL helpers. Add a "
                "Web Application Firewall (e.g. ModSecurity OWASP "
                "Core Rule Set) as defense-in-depth, but DO NOT "
                "rely on it as the only mitigation."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "U", "C": "H", "I": "H", "A": "H",
            },
            reasoning_trace=[
                f"Probed {param}= with {detection_kind}-based payload "
                f"`{payload}`.",
                f"Detection signal: "
                + (
                    f"DB error fingerprint matched ({db_engine})."
                    if detection_kind == "error"
                    else "boolean-true response differs from "
                    "boolean-false response while baseline matches "
                    "boolean-false."
                ),
                "No timing or behaviour confirmation needed — "
                "deterministic detection based on observed response "
                "shape.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_sqli: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="sqli-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 90},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190"],  # Exploit Public-Facing Application
)
def scan_sqli(
    *,
    url: str,
    params: list[str] | None = None,
    other_params: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
    method: str = "GET",
    body_template: dict[str, Any] | str | None = None,
    body_format: str = "auto",
) -> SpecialistResult:
    """Deterministic SQL-injection scanner.

    Args:
        url: target URL. May contain `{param}` placeholders for
            path-param substitution (e.g.
            `http://x/api/Baskets/{id}`).
        params: list of param names to probe; falls back to URL
            query-string keys when None.
        other_params: baseline values for OTHER params on the URL.
        extra_headers: optional headers to forward (e.g. auth).
        method: HTTP method. Default `GET` (Phase 3b behaviour).
            Modern APIs use `POST`/`PUT`/`PATCH` with a body — supply
            `body_template` along with the method to probe those.
        body_template: optional body for non-GET methods.
            * `dict` → JSON-encoded by default (`body_format="auto"`
              infers JSON), or form-encoded with `body_format="form"`.
              The named param's value is replaced with each probe
              payload.
            * `str` → raw body with `{param}` placeholder for
              substitution.
            * `None` (default) → param is substituted into the URL
              query string (Phase 3b behaviour).
        body_format: `"json"` / `"form"` / `"auto"`. Inferred when
            `"auto"` and `body_template` is a dict (→ JSON).

    Auto-emits one `add_vulnerability_report` per (param × detection)
    via the global tracer. Returns a `SpecialistResult` with mirror
    drafts so the lead agent can see what was detected; canonical
    findings live in `vulnerabilities.json`.

    Examples:
        # Phase 3b — GET with query string.
        scan_sqli(url="http://x/search?q=test", params=["q"])

        # Phase 3c — POST + JSON body (Juice Shop login).
        scan_sqli(
            url="http://x/rest/user/login",
            method="POST",
            params=["email"],
            body_template={"email": "x@example.com", "password": "x"},
        )

        # Phase 3c — path param.
        scan_sqli(
            url="http://x/api/Baskets/{id}",
            method="GET",
            params=["id"],
        )

        # Phase 3c — POST + form body.
        scan_sqli(
            url="http://x/login.php",
            method="POST",
            params=["username"],
            body_template={"username": "admin", "password": "x"},
            body_format="form",
        )
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    from strix.tools.specialist._request_builders import (
        build_request,
        is_path_param_url,
    )

    parsed = urlparse(url)
    if not params:
        # Three fallbacks for inferring params:
        #   1. URL query string keys (existing).
        #   2. body_template dict keys (new — Phase 3c).
        #   3. {placeholder} markers in URL path (new — path params).
        if parsed.query:
            params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
        elif isinstance(body_template, dict):
            params = list(body_template.keys())
        else:
            # Look for {name} placeholders in URL path.
            import re as _re
            params = _re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", url)
    if not params:
        return SpecialistResult(
            status="partial",
            error="no params supplied and could not infer from URL/body",
            evidence=[
                f"scan_sqli invoked on {url!r} with no params; "
                "supply `params=[...]`, include a query string, "
                "supply a `body_template` dict, or use `{name}` "
                "placeholders in the URL path."
            ],
        )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    probe_count = 0
    seen_endpoint_param: set[tuple[str, str]] = set()

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        pm = get_proxy_manager()
    except Exception as e:  # noqa: BLE001
        return SpecialistResult(
            status="error",
            error=f"proxy_manager unavailable: {type(e).__name__}: {e}",
        )

    def _probe(probe_value: str, label: str) -> dict[str, Any] | None:
        nonlocal probe_count
        try:
            req_method, req_url, req_headers, req_body = build_request(
                url=url, method=method,
                param_name=param, payload=probe_value,
                body_template=body_template, body_format=body_format,
                other_params=other_params, extra_headers=extra_headers,
            )
            resp = pm.send_simple_request(
                req_method, req_url,
                headers=req_headers,
                body=req_body,
                timeout=15,
            )
            probe_count += 1
            return resp
        except Exception as e:  # noqa: BLE001
            evidence.append(f"transport error for {param!r} ({label}): {e}")
            return None

    for param in params:
        if not isinstance(param, str) or not param.strip():
            continue
        param = param.strip()
        key = (parsed.path or "/", param)
        if key in seen_endpoint_param:
            continue

        # Establish baseline.
        baseline_resp = _probe("strix_baseline_value", "baseline")
        if not baseline_resp or "error" in baseline_resp and not baseline_resp.get("status_code"):
            evidence.append(f"baseline failed for {param!r}; skipping")
            continue
        baseline_body = baseline_resp.get("body") or ""
        baseline_status = baseline_resp.get("status_code")

        # 1. Error-based detection.
        err_resp = _probe(_PROBE_PAYLOADS["error_trigger"], "error_trigger")
        if err_resp and err_resp.get("status_code"):
            err_body = err_resp.get("body") or ""
            detected, engine = _detect_db_error(err_body)
            if detected:
                seen_endpoint_param.add(key)
                excerpt = err_body[:1500]
                report_id = _emit_finding(
                    url=url, param=param,
                    detection_kind="error",
                    db_engine=engine,
                    payload=_PROBE_PAYLOADS["error_trigger"],
                    response_excerpt=excerpt,
                    verification_status="verified",
                    confidence=0.95,
                )
                if report_id:
                    emitted_count += 1
                drafts.append(FindingDraft(
                    title=f"Error-based SQL injection in `{param}`",
                    severity="high",
                    cwe="CWE-89",
                    endpoint=url,
                    category="sqli",
                    verification_status="verified",
                    confidence=0.95,
                    description=(
                        f"DB error fingerprint ({engine}) detected on "
                        f"{param}={_PROBE_PAYLOADS['error_trigger']}"
                    ),
                ))
                evidence.append(
                    f"error-based SQLi: {param}, engine={engine}"
                )
                continue  # don't double-emit boolean check on same param

        # 2. Boolean-blind detection (only if error path didn't fire).
        true_resp = _probe(_PROBE_PAYLOADS["boolean_true"], "bool_true")
        false_resp = _probe(_PROBE_PAYLOADS["boolean_false"], "bool_false")
        if not true_resp or not false_resp:
            continue
        true_body = true_resp.get("body") or ""
        false_body = false_resp.get("body") or ""
        true_status = true_resp.get("status_code")
        false_status = false_resp.get("status_code")

        # Confirm: true ≠ false AND baseline ≈ false (or status matches).
        true_vs_false_differs = (
            true_status != false_status
            or _bodies_meaningfully_differ(true_body, false_body)
        )
        baseline_vs_false_similar = (
            baseline_status == false_status
            and not _bodies_meaningfully_differ(baseline_body, false_body)
        )
        if true_vs_false_differs and baseline_vs_false_similar:
            seen_endpoint_param.add(key)
            # Use the first 1500 chars of the TRUE response since
            # that's the "anomalous" branch.
            excerpt = (
                f"baseline len={len(baseline_body)} status={baseline_status}\n"
                f"' OR '1'='1 → len={len(true_body)} status={true_status}\n"
                f"' OR '1'='2 → len={len(false_body)} status={false_status}\n\n"
                f"true-branch excerpt:\n{true_body[:1000]}"
            )
            report_id = _emit_finding(
                url=url, param=param,
                detection_kind="boolean",
                db_engine=None,
                payload=_PROBE_PAYLOADS["boolean_true"],
                response_excerpt=excerpt,
                verification_status="pattern_match",
                confidence=0.75,
            )
            if report_id:
                emitted_count += 1
            drafts.append(FindingDraft(
                title=f"Boolean-blind SQL injection in `{param}`",
                severity="high",
                cwe="CWE-89",
                endpoint=url,
                category="sqli",
                verification_status="pattern_match",
                confidence=0.75,
                description=(
                    f"Boolean-blind SQLi on {param}; true ≠ false "
                    f"and baseline ≈ false."
                ),
            ))
            evidence.append(
                f"boolean-blind SQLi: {param} "
                f"(true_len={len(true_body)} vs false_len={len(false_body)})"
            )

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            ["follow-up with sqlmap for automated extraction"]
            if drafts else
            ["no SQLi detected on listed params; consider POST/JSON "
             "body params and authenticated probes"]
        ),
        tool_metadata={
            "probes_sent": probe_count,
            "params_probed": len(params),
            "findings_emitted_to_tracer": emitted_count,
            "scheme": parsed.scheme,
            "host": parsed.netloc,
        },
    )
