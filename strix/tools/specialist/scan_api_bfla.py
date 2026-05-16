"""`scan_api_bfla` — OWASP API5:2023 (Broken Function Level
Authorization).

BFLA is the FUNCTION-level (not object-level) authz failure: a
low-privilege user (`viewer`) successfully invokes a function
intended for high-privilege users (`admin`). On the API surface
this typically shows up as:

  * `POST /admin/users` returns 200 to a `viewer`-role session.
  * `DELETE /tenants/{id}` works for `member` when it should
    require `owner`.
  * GraphQL mutations executable across roles without distinction.

## Detection

For each endpoint, walk a role matrix:

  1. Pick the **high-privilege role** baseline — does the
     endpoint return 200 to `admin`?
  2. For each **lower-privilege role** in the matrix, send the
     same request. Three outcomes:
     * `2xx` ≡ same body shape as admin → **BFLA positive**
       (function executable across role boundary)
     * `2xx` ≡ DIFFERENT shape from admin → ambiguous
       (might be intentional polymorphic response — info-severity)
     * `401 / 403` → properly authorized, no finding.
  3. Endpoints flagged as admin-only (path contains `/admin/`,
     `/internal/`, `/manage/`, OR tagged `admin` in the spec)
     get higher confidence + severity escalation.

## Inputs

Same plumbing as `scan_api_bola` — endpoint inventory from
`openapi_spec_ingest`, role sessions from
`SecurityContext.auth_states`.

Kill switch: `STRIX_API_BFLA_DISABLED=1`.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import FindingDraft, SpecialistResult


logger = logging.getLogger(__name__)


# Path / tag markers that suggest an admin-only function.
_ADMIN_PATH_MARKERS: tuple[str, ...] = (
    "/admin/", "/internal/", "/manage/", "/sudo/", "/godmode/",
    "/maintenance/", "/_admin/",
)
_ADMIN_TAG_MARKERS: frozenset[str] = frozenset({
    "admin", "internal", "manage", "management",
    "ops", "operations", "godmode",
})


_PATH_PARAM_RE = re.compile(r"\{([A-Za-z_][\w]*)\}")


def _kill_switched() -> bool:
    return os.environ.get("STRIX_API_BFLA_DISABLED") == "1"


def _looks_admin_only(endpoint: dict[str, Any]) -> bool:
    url = (endpoint.get("url") or "").lower()
    if any(marker in url for marker in _ADMIN_PATH_MARKERS):
        return True
    tags = endpoint.get("tags") or []
    if any(
        isinstance(t, str) and t.strip().lower() in _ADMIN_TAG_MARKERS
        for t in tags
    ):
        return True
    op_id = (endpoint.get("operation_id") or "").lower()
    if any(marker in op_id for marker in ("admin", "internal", "manage")):
        return True
    return False


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


def _hash_body(body: str | bytes) -> str:
    data = body.encode("utf-8") if isinstance(body, str) else body or b""
    return hashlib.sha256(data).hexdigest()[:16]


def _default_fetcher(
    *, url: str, method: str, headers: dict[str, str] | None,
    timeout: float,
) -> tuple[int | None, str]:
    try:
        import httpx
    except ImportError:
        return None, ""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as c:
            r = c.request(method, url, headers=headers or None)
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
        logger.debug(
            "scan_api_bfla: SecurityContext read failed", exc_info=True,
        )
        return {}


@register_specialist_tool(
    category="api-bfla-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 180},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1078.003"],   # Local Accounts
)
def scan_api_bfla(
    *,
    endpoints: list[dict[str, Any]],
    admin_label: str = "admin",
    role_labels: list[str] | None = None,
    path_ids: dict[str, str] | None = None,
    timeout_seconds: float = 8.0,
    max_endpoints: int = 50,
    _fetcher=None,
) -> SpecialistResult:
    """Probe OpenAPI-ingested endpoints for OWASP API5 BFLA.

    Args:
        endpoints: list of endpoint dicts from
            `openapi_spec_ingest`.
        admin_label: AuthState label of a high-privilege user
            (baseline — what admin sees).
        role_labels: list of lower-privilege role labels to test
            against the admin baseline. Defaults to
            `["viewer", "member", "user"]` filtered to
            captured sessions.
        path_ids: dict mapping path-param names → safe IDs
            (typically admin's own object IDs, so the probe
            doesn't accidentally mutate someone else's data).
        timeout_seconds: per-request HTTP timeout.
        max_endpoints: cap probe count.
        _fetcher: injection point for tests.

    Returns:
        `SpecialistResult` with one finding per BFLA-positive
        endpoint × role pair.

    Kill switch: `STRIX_API_BFLA_DISABLED=1`.
    """
    if _kill_switched():
        return SpecialistResult(
            status="error",
            error="kill_switch (STRIX_API_BFLA_DISABLED)",
        )

    if not endpoints or not isinstance(endpoints, list):
        return SpecialistResult(
            status="error", error="endpoints list required",
        )

    admin_headers = _auth_headers_for_label(admin_label)
    if not admin_headers:
        return SpecialistResult(
            status="error",
            error=(
                f"admin_label={admin_label!r} session not captured "
                f"in SecurityContext.auth_states. Run "
                f"scan_multi_role_auth first."
            ),
        )

    roles_to_test = role_labels or ["viewer", "member", "user"]
    role_headers: dict[str, dict[str, str]] = {}
    for role in roles_to_test:
        h = _auth_headers_for_label(role)
        if h:
            role_headers[role] = h

    if not role_headers:
        return SpecialistResult(
            status="error",
            error=(
                f"no role sessions captured for labels "
                f"{roles_to_test!r}; run scan_multi_role_auth"
            ),
        )

    fetcher = _fetcher or _default_fetcher
    findings: list[FindingDraft] = []
    evidence: list[str] = []
    probed = 0

    for ep in endpoints:
        if probed >= max_endpoints:
            break
        url_template = ep.get("url", "")
        method = (ep.get("method") or "GET").upper()
        if not isinstance(url_template, str) or not url_template:
            continue
        if not ep.get("auth_required"):
            continue

        admin_only = _looks_admin_only(ep)
        target_url = _instantiate_path(url_template, path_ids or {})
        if not target_url:
            continue

        probed += 1

        # Admin baseline.
        admin_status, admin_body = fetcher(
            url=target_url, method=method,
            headers=admin_headers, timeout=timeout_seconds,
        )
        if admin_status is None:
            evidence.append(
                f"network error: admin probe {method} {target_url}"
            )
            continue
        if admin_status >= 400:
            # Admin can't access either — endpoint may be
            # disabled / wrong path-id. Skip.
            evidence.append(
                f"admin cannot access {method} {target_url} "
                f"(status={admin_status}); skipping"
            )
            continue
        admin_hash = _hash_body(admin_body)

        # Per-role probe.
        for role, headers in role_headers.items():
            role_status, role_body = fetcher(
                url=target_url, method=method,
                headers=headers, timeout=timeout_seconds,
            )
            if role_status is None:
                evidence.append(
                    f"network error: {role} probe {method} {target_url}"
                )
                continue

            role_hash = _hash_body(role_body)

            if role_status in (401, 403):
                continue   # properly authorized; no finding

            if 200 <= role_status < 300 and role_hash == admin_hash:
                # Same response as admin → BFLA positive.
                severity = "critical" if admin_only else "high"
                findings.append(FindingDraft(
                    title=(
                        f"BFLA at {method} {url_template} — "
                        f"role `{role}` invoked admin function"
                    ),
                    severity=severity,
                    cwe="CWE-285",
                    endpoint=target_url,
                    category="api_bfla",
                    description=(
                        f"Endpoint `{method} {url_template}` returned "
                        f"the same response to a low-privilege role "
                        f"`{role}` (status={role_status}) as to the "
                        f"admin baseline `{admin_label}` "
                        f"(status={admin_status}). Body sha256[:16] "
                        f"matched: `{admin_hash}`.\n\n"
                        f"OWASP API5:2023 Broken Function Level "
                        f"Authorization — the endpoint authenticates "
                        f"but doesn't gate by role. "
                        + (
                            "The path / tag signals this is an "
                            "ADMIN-ONLY function (severity escalated "
                            "to critical)."
                            if admin_only else
                            "Function-level authz check is missing."
                        )
                    ),
                    verification_status="verified",
                    confidence=0.95,
                    reasoning_trace=[
                        f"Admin baseline: status={admin_status}, "
                        f"body_hash={admin_hash}.",
                        f"Low-priv `{role}`: status={role_status}, "
                        f"body_hash={role_hash}.",
                        "Hashes match → BFLA positive.",
                        f"admin_only_endpoint={admin_only} → "
                        f"severity={severity}.",
                    ],
                ))
            elif 200 <= role_status < 300:
                # 2xx but different body — ambiguous. Could be
                # intentional polymorphic response or a partial
                # BFLA. Emit info-severity for human review.
                findings.append(FindingDraft(
                    title=(
                        f"Possible partial BFLA at {method} "
                        f"{url_template} — role `{role}` got 2xx "
                        f"with different body shape from admin"
                    ),
                    severity="info",
                    cwe="CWE-285",
                    endpoint=target_url,
                    category="api_bfla",
                    description=(
                        f"Role `{role}` received status={role_status} "
                        f"from `{method} {url_template}` (admin got "
                        f"{admin_status}). Body hashes differ — could "
                        f"be intentional role-scoped polymorphic "
                        f"response, or could be partial BFLA where "
                        f"the function returned filtered data instead "
                        f"of rejecting the call. Human review."
                    ),
                    verification_status="needs_review",
                    confidence=0.45,
                ))

    return SpecialistResult(
        status="ok",
        findings=findings,
        evidence=evidence,
        tool_metadata={
            "probed": probed,
            "roles_tested": list(role_headers.keys()),
            "findings_count": len(findings),
        },
    )
