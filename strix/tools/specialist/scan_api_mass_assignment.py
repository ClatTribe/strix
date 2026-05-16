"""`scan_api_mass_assignment` — OWASP API3:2023 (Broken Object
Property Level Authorization / CWE-915).

Mass assignment happens when an API endpoint blindly binds an
incoming JSON body to a server-side object. The classic shape:

  POST /users
  { "username": "alice", "email": "a@x", "is_admin": true }

A server that uses unfiltered binding (`User(**request.json)`)
will set `is_admin=True` even though the client wasn't supposed
to control that field.

## Detection

For each write-shaped endpoint (POST / PUT / PATCH) discovered
via `openapi_spec_ingest`:

  1. Build a **baseline body** from the spec's declared schema
     (when present) or an empty body.
  2. Send `request_a = baseline` → record `(status_a, body_a)`.
  3. Send `request_b = baseline + injected privileged fields`
     → record `(status_b, body_b)`.
  4. Mass assignment when ALL of:
     * `status_b` is 2xx (request accepted)
     * `body_b` reflects the injected field (the server echoed
       back `is_admin: true` in the response), OR the response
       differs from `body_a` in a way that suggests acceptance
       (e.g. `200` vs `400` would mean the injection got
       silently accepted)

The injected fields are a curated probe set — the canonical
ones attackers try first:

  is_admin, isAdmin, admin, role, roles, permissions, scopes,
  scope, is_superuser, isSuperuser, superuser, is_staff,
  is_root, user_id, userId, account_id, accountId, tenant_id,
  email_verified, isEmailVerified, verified

## Safety posture

  * The probe MUTATES state on the target. Strix's posture is
    to opt-in via `confirm_mutation=True` on each call.
  * Kill switch: `STRIX_API_MASS_ASSIGNMENT_DISABLED=1`.
  * Skipped for read-only methods (GET/HEAD).
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import FindingDraft, SpecialistResult


logger = logging.getLogger(__name__)


_PATH_PARAM_RE = re.compile(r"\{([A-Za-z_][\w]*)\}")


# Curated probe fields. Each entry is `(field_name, injected_value)`.
# Two batches:
#   * authz_fields — fields that elevate privilege when accepted
#   * id_fields    — fields that re-target the object to another
#                    owner (effectively an IDOR-via-mass-assignment)
_AUTHZ_FIELDS: tuple[tuple[str, Any], ...] = (
    ("is_admin", True),
    ("isAdmin", True),
    ("admin", True),
    ("role", "admin"),
    ("roles", ["admin"]),
    ("permissions", ["*"]),
    ("scopes", ["admin"]),
    ("scope", "admin"),
    ("is_superuser", True),
    ("isSuperuser", True),
    ("superuser", True),
    ("is_staff", True),
    ("is_root", True),
    ("email_verified", True),
    ("isEmailVerified", True),
    ("verified", True),
)


_ID_FIELDS: tuple[tuple[str, Any], ...] = (
    ("user_id", 1),
    ("userId", 1),
    ("account_id", 1),
    ("accountId", 1),
    ("tenant_id", 1),
    ("organization_id", 1),
)


# Name patterns for fields the SERVER typically manages — even
# when the OpenAPI spec doesn't declare them `readOnly`. Used as a
# secondary signal for the schema-aware probe: if the API's
# request body schema declares a field whose name matches one of
# these, we probe it on the assumption it's server-managed.
#
# These deliberately overlap with `_AUTHZ_FIELDS` / `_ID_FIELDS`
# (the canonical set) — the schema-aware path treats overlap as
# "probe once" via dedup.
_SERVER_MANAGED_NAME_PATTERNS: tuple[str, ...] = (
    # Identity / object identity
    "id", "uuid", "guid",
    # Audit / lifecycle timestamps
    "created_at", "createdat", "created_on", "createdon",
    "updated_at", "updatedat", "modified_at", "modifiedat",
    "deleted_at", "deletedat",
    "timestamp",
    # Audit actors
    "created_by", "createdby", "updated_by", "updatedby",
    # Versioning / concurrency
    "version", "etag", "_revision", "revision",
    # Status (server-driven state machines)
    "status", "state",
    # Tenancy (assignment must come from the auth context)
    "owner_id", "ownerid", "owner",
    "tenant_id", "tenantid",
    "organization_id", "organizationid",
    "workspace_id", "workspaceid",
)


def _choose_probe_value_for_type(
    name: str, type_hint: str | None,
) -> Any:
    """Pick a probe value for a server-managed field based on its
    schema-declared type. Conservative defaults — primarily an
    integer for ID-shaped fields, a sentinel string for everything
    else, and `True` for boolean privilege markers.

    The injected value carries a `STRIX-` prefix (where applicable)
    so a successful echo in the response is unambiguously
    attributable to our probe.
    """
    lname = name.lower()

    # Boolean privilege markers — flip them on.
    if any(tok in lname for tok in (
        "admin", "superuser", "staff", "root", "verified",
        "is_active", "isactive",
    )):
        return True

    # Type-led default.
    type_lower = (type_hint or "").lower()
    if type_lower == "boolean":
        return True
    if type_lower in {"integer", "number"}:
        # ID-shaped or numeric — use a probe sentinel.
        return 1
    if type_lower == "array":
        return ["strix-probe"]
    if type_lower == "object":
        return {"strix-probe": True}

    # Default — string sentinel. Includes the field name so the
    # echo check has a strong signal.
    return f"STRIX-{name}-probe"


def _extract_schema_aware_probes(
    request_body_schema: dict[str, Any] | None,
    *,
    canonical_field_names: set[str],
) -> list[tuple[str, Any]]:
    """Derive per-endpoint mass-assignment probe candidates from
    the request body schema.

    A field is a probe candidate when:
      1. Schema declares `readOnly: true` — strongest signal; the
         server explicitly says the client shouldn't supply this.
      2. Field name matches `_SERVER_MANAGED_NAME_PATTERNS` —
         server-managed by convention even when readOnly isn't
         declared.

    Returns `[(field_name, probe_value), ...]`. De-duplicated
    against `canonical_field_names` so the caller doesn't probe
    the same field twice (once from the canonical set, once from
    the schema).
    """
    if not isinstance(request_body_schema, dict):
        return []

    properties = request_body_schema.get("properties") or {}
    if not isinstance(properties, dict):
        return []

    candidates: list[tuple[str, Any]] = []
    seen: set[str] = {n.lower() for n in canonical_field_names}

    for name, prop in properties.items():
        if not isinstance(name, str) or not isinstance(prop, dict):
            continue
        lname = name.lower()
        if lname in seen:
            continue

        is_read_only = bool(prop.get("read_only", False))
        name_matches_pattern = lname in _SERVER_MANAGED_NAME_PATTERNS

        if not (is_read_only or name_matches_pattern):
            continue

        value = _choose_probe_value_for_type(
            name, prop.get("type"),
        )
        candidates.append((name, value))
        seen.add(lname)

    return candidates


def _kill_switched() -> bool:
    return os.environ.get("STRIX_API_MASS_ASSIGNMENT_DISABLED") == "1"


def _is_write_method(method: str) -> bool:
    return method.upper() in ("POST", "PUT", "PATCH")


def _instantiate_path(template: str, ids: dict[str, str]) -> str | None:
    if not _PATH_PARAM_RE.search(template):
        return template
    missing = [
        m.group(1) for m in _PATH_PARAM_RE.finditer(template)
        if not ids.get(m.group(1))
    ]
    if missing:
        return None

    def _sub(m: re.Match[str]) -> str:
        return ids[m.group(1)]

    return _PATH_PARAM_RE.sub(_sub, template)


def _baseline_body_from_spec_params(
    params: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a minimal valid-shaped body from the endpoint's
    declared parameters. We use placeholder values — the goal is
    to get a 2xx baseline so the diff vs the injected probe is
    meaningful. Doesn't synthesize complex schemas; that's the
    LLM's job in a follow-up."""
    body: dict[str, Any] = {}
    for p in params:
        if not isinstance(p, dict):
            continue
        if p.get("in") != "body":
            continue
        name = p.get("name", "")
        if not isinstance(name, str) or not name:
            continue
        # Conservative placeholder shape.
        body[name] = "test-value"
    return body


def _response_accepts_injection(
    *,
    body_a_status: int | None,
    body_a_text: str,
    body_b_status: int | None,
    body_b_text: str,
    injected_field: str,
    injected_value: Any,
) -> tuple[bool, str]:
    """Compare baseline-vs-injection responses. Returns
    `(accepted, reason)`."""
    if body_b_status is None:
        return False, "network error on injection probe"
    if body_b_status >= 400:
        # Server rejected the injection — proper allow-list.
        return False, f"server rejected injection (status={body_b_status})"
    # Status 2xx — server accepted. Two confirmation signals:
    #
    #   1. ECHO — the response body contains the injected field
    #      AND its injected value. Strong signal.
    #   2. BASELINE-DIFF — the injected status is 2xx but the
    #      baseline was 4xx (i.e. server fixed validation by
    #      adding the injected field). Weaker but indicative.
    body_b_lower = body_b_text.lower()
    field_lower = injected_field.lower()
    value_str = (
        str(injected_value).lower() if not isinstance(injected_value, list)
        else ",".join(str(v).lower() for v in injected_value)
    )
    if field_lower in body_b_lower and value_str in body_b_lower:
        return True, "response body echoes injected field + value"
    if body_a_status is not None and body_a_status >= 400 and body_b_status < 300:
        return True, (
            f"baseline rejected (status={body_a_status}) but injection "
            f"accepted (status={body_b_status})"
        )
    return False, "injection accepted but no echo / baseline-diff signal"


def _default_fetcher(
    *, url: str, method: str, headers: dict[str, str] | None,
    json_body: dict[str, Any] | None, timeout: float,
) -> tuple[int | None, str]:
    try:
        import httpx
    except ImportError:
        return None, ""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as c:
            r = c.request(
                method, url,
                headers=headers or None,
                json=json_body,
            )
            return r.status_code, r.text or ""
    except Exception:  # noqa: BLE001
        return None, ""


def _auth_headers_for_label(label: str) -> dict[str, str]:
    try:
        from strix.agents.security_context import get_security_context

        ctx = get_security_context()
        state = ctx.auth_states.get(label)
        if state is None:
            return {}
        headers: dict[str, str] = {}
        if state.bearer:
            headers["Authorization"] = f"Bearer {state.bearer}"
        if state.csrf_token:
            headers["X-CSRF-Token"] = state.csrf_token
        if state.cookies:
            cookie_pairs = "; ".join(
                f"{k}={v}" for k, v in state.cookies.items()
            )
            headers["Cookie"] = cookie_pairs
        return headers
    except Exception:  # noqa: BLE001
        return {}


@register_specialist_tool(
    category="api-mass-assignment-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 180},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1078"],
)
def scan_api_mass_assignment(
    *,
    endpoints: list[dict[str, Any]],
    auth_label: str = "user-a",
    path_ids: dict[str, str] | None = None,
    confirm_mutation: bool = False,
    probe_authz_fields: bool = True,
    probe_id_fields: bool = False,
    probe_schema_aware: bool = True,
    timeout_seconds: float = 8.0,
    max_endpoints: int = 20,
    _fetcher=None,
) -> SpecialistResult:
    """Probe write endpoints for OWASP API3 Mass Assignment / BOPLA.

    Args:
        endpoints: list of endpoint dicts from `openapi_spec_ingest`
            (or any source — `url`, `method`, `auth_required`,
            `params`, and `request_body_schema` are read).
        auth_label: AuthState label whose session to use for the
            probe.
        path_ids: optional path-param substitutions.
        confirm_mutation: MUST be True to actually run the probe.
            Mass-assignment probes mutate state on the target —
            opt-in only. When False, returns a no-op result.
        probe_authz_fields: when True (default), probe the canonical
            privilege-elevation field set (is_admin, role, etc.).
        probe_id_fields: when True, ALSO probe the canonical
            owner-rewrite fields (user_id, account_id). Default
            False — these can break referential integrity.
        probe_schema_aware: when True (default) AND the endpoint
            declares a `request_body_schema` (populated by
            `openapi_spec_ingest`), ALSO derive per-endpoint
            probes from the schema:
              * Fields with `readOnly: true` — server explicitly
                marked them as client-can't-set.
              * Fields whose name matches a server-managed
                pattern (`id`, `created_at`, `etag`, etc.).
            De-duplicated against the canonical probe set. This
            catches per-customer server-managed field names the
            canonical 22-field list can never know about (e.g.
            an Akto-grade application-specific `account_balance`
            or `commission_rate`).
        timeout_seconds: per-request HTTP timeout.
        max_endpoints: cap probe count.
        _fetcher: injection point for tests.

    Kill switch: `STRIX_API_MASS_ASSIGNMENT_DISABLED=1`.
    """
    if _kill_switched():
        return SpecialistResult(
            status="error",
            error="kill_switch (STRIX_API_MASS_ASSIGNMENT_DISABLED)",
        )

    if not confirm_mutation:
        return SpecialistResult(
            status="error",
            error=(
                "confirm_mutation=False — mass-assignment probes "
                "mutate target state and must be explicitly opted "
                "into. Pass confirm_mutation=True after operator "
                "approval."
            ),
        )

    if not endpoints or not isinstance(endpoints, list):
        return SpecialistResult(
            status="error", error="endpoints list required",
        )

    headers = _auth_headers_for_label(auth_label)
    fetcher = _fetcher or _default_fetcher

    canonical_fields: list[tuple[str, Any]] = []
    if probe_authz_fields:
        canonical_fields.extend(_AUTHZ_FIELDS)
    if probe_id_fields:
        canonical_fields.extend(_ID_FIELDS)
    if not canonical_fields and not probe_schema_aware:
        return SpecialistResult(
            status="error",
            error=(
                "no probe fields enabled — set probe_authz_fields, "
                "probe_id_fields, or probe_schema_aware to True"
            ),
        )

    canonical_field_names: set[str] = {n for n, _ in canonical_fields}

    findings: list[FindingDraft] = []
    evidence: list[str] = []
    probed = 0
    skipped: dict[str, int] = {"read_only": 0, "no_url": 0, "missing_ids": 0}
    schema_probes_total = 0

    for ep in endpoints:
        if probed >= max_endpoints:
            break
        method = (ep.get("method") or "GET").upper()
        if not _is_write_method(method):
            skipped["read_only"] += 1
            continue
        url_template = ep.get("url", "")
        if not isinstance(url_template, str) or not url_template:
            skipped["no_url"] += 1
            continue
        target_url = _instantiate_path(url_template, path_ids or {})
        if not target_url:
            skipped["missing_ids"] += 1
            continue

        probed += 1
        baseline_body = _baseline_body_from_spec_params(
            ep.get("params") or [],
        )

        # Phase 4 schema-aware augmentation: when the endpoint
        # declares a request_body_schema (populated by
        # openapi_spec_ingest), derive per-endpoint server-managed
        # field candidates and merge them in.
        per_endpoint_probes: list[tuple[str, Any]] = list(canonical_fields)
        if probe_schema_aware:
            schema_aware = _extract_schema_aware_probes(
                ep.get("request_body_schema"),
                canonical_field_names=canonical_field_names,
            )
            if schema_aware:
                schema_probes_total += len(schema_aware)
                per_endpoint_probes.extend(schema_aware)
                evidence.append(
                    f"schema-aware {method} {url_template}: "
                    f"derived {len(schema_aware)} additional probe "
                    f"fields from request_body_schema "
                    f"({', '.join(n for n, _ in schema_aware)})"
                )

        if not per_endpoint_probes:
            continue

        # Baseline probe.
        a_status, a_text = fetcher(
            url=target_url, method=method, headers=headers,
            json_body=baseline_body or None, timeout=timeout_seconds,
        )
        evidence.append(
            f"baseline {method} {target_url}: status={a_status}"
        )

        for field_name, injected_value in per_endpoint_probes:
            injected = dict(baseline_body)
            injected[field_name] = injected_value
            b_status, b_text = fetcher(
                url=target_url, method=method, headers=headers,
                json_body=injected, timeout=timeout_seconds,
            )

            accepted, reason = _response_accepts_injection(
                body_a_status=a_status, body_a_text=a_text,
                body_b_status=b_status, body_b_text=b_text,
                injected_field=field_name,
                injected_value=injected_value,
            )
            if accepted:
                findings.append(FindingDraft(
                    title=(
                        f"Mass assignment at {method} {url_template} — "
                        f"`{field_name}` accepted via request body"
                    ),
                    severity=(
                        "critical" if field_name in {
                            "is_admin", "isAdmin", "admin",
                            "role", "roles", "is_superuser",
                            "isSuperuser", "is_root",
                        } else "high"
                    ),
                    cwe="CWE-915",
                    endpoint=target_url,
                    category="api_mass_assignment",
                    description=(
                        f"Endpoint `{method} {url_template}` accepted "
                        f"the injected request-body field "
                        f"`{field_name}: {injected_value!r}` "
                        f"(status={b_status}). Detection: {reason}.\n\n"
                        f"OWASP API3:2023 — Broken Object Property "
                        f"Level Authorization. The server is binding "
                        f"client-supplied input directly to a model "
                        f"property the client should not control."
                    ),
                    verification_status="verified",
                    confidence=0.85,
                    reasoning_trace=[
                        f"Baseline body: {json.dumps(baseline_body)[:200]}",
                        f"Injected field: `{field_name}` = "
                        f"{injected_value!r}",
                        f"Baseline status: {a_status}; "
                        f"injection status: {b_status}",
                        f"Acceptance signal: {reason}",
                    ],
                ))
                # Don't keep probing the same endpoint with more
                # fields once we've found a hit — single finding per
                # endpoint is the right shape.
                break

    return SpecialistResult(
        status="ok",
        findings=findings,
        evidence=evidence,
        tool_metadata={
            "probed": probed,
            "skipped": skipped,
            "canonical_probe_fields_count": len(canonical_fields),
            "schema_aware_probes_total": schema_probes_total,
            "findings_count": len(findings),
        },
    )
