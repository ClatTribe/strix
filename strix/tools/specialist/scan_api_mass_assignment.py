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
    timeout_seconds: float = 8.0,
    max_endpoints: int = 20,
    _fetcher=None,
) -> SpecialistResult:
    """Probe write endpoints for OWASP API3 Mass Assignment / BOPLA.

    Args:
        endpoints: list of endpoint dicts from `openapi_spec_ingest`
            (or any source — only `url`, `method`, `auth_required`,
            `params` are read).
        auth_label: AuthState label whose session to use for the
            probe.
        path_ids: optional path-param substitutions.
        confirm_mutation: MUST be True to actually run the probe.
            Mass-assignment probes mutate state on the target —
            opt-in only. When False, returns a no-op result.
        probe_authz_fields: when True (default), probe privilege-
            elevation fields (is_admin, role, etc.).
        probe_id_fields: when True, ALSO probe owner-rewrite fields
            (user_id, account_id). Default False — these can break
            referential integrity.
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

    probe_fields = []
    if probe_authz_fields:
        probe_fields.extend(_AUTHZ_FIELDS)
    if probe_id_fields:
        probe_fields.extend(_ID_FIELDS)
    if not probe_fields:
        return SpecialistResult(
            status="error",
            error=(
                "no probe fields enabled — set probe_authz_fields "
                "or probe_id_fields to True"
            ),
        )

    findings: list[FindingDraft] = []
    evidence: list[str] = []
    probed = 0
    skipped: dict[str, int] = {"read_only": 0, "no_url": 0, "missing_ids": 0}

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

        # Baseline probe.
        a_status, a_text = fetcher(
            url=target_url, method=method, headers=headers,
            json_body=baseline_body or None, timeout=timeout_seconds,
        )
        evidence.append(
            f"baseline {method} {target_url}: status={a_status}"
        )

        for field_name, injected_value in probe_fields:
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
            "probe_fields_count": len(probe_fields),
            "findings_count": len(findings),
        },
    )
