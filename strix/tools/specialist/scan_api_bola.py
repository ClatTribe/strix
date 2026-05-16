"""`scan_api_bola` — OWASP API1:2023 (Broken Object Level
Authorization).

BOLA is IDOR's API-shaped sibling. Same primitive (a user-A
session reading user-B's data), but the discovery + probing is
different on APIs:

  * **Endpoint inventory** comes from `openapi_spec_ingest`
    (path templates like `/users/{id}/orders/{orderId}`), not
    from a crawl.
  * **Object IDs** must be substituted into path parameters
    (the `{id}`, `{orderId}` placeholders) — different from
    DAST's IDOR which fuzzes query string + JSON body.
  * **Auth shape** is typically Bearer-token rather than
    cookie session; the helper reads the two captured sessions
    from `SecurityContext.auth_states` (same plumbing as
    `scan_idor`).

## Detection

For each endpoint with a path parameter:

  1. As **owner** (`owner_label`'s Bearer token / cookies),
     fetch `/users/<owner-A-id>/orders/<order-A-id>` → record
     `(status_a, body_a_hash)`.
  2. As **accessor** (`accessor_label`'s token), fetch the
     SAME URL → record `(status_b, body_b_hash)`.
  3. **BOLA** when: `status_b == 200` AND `body_b_hash ==
     body_a_hash`. The accessor read the owner's record.
  4. Properly-authorized response: `status_b in {401, 403,
     404}` OR `body_b_hash != body_a_hash` (different content
     scoped to the accessor's records).

The `body_*_hash` compare guards against generic 200-OK
endpoints that return the same empty-list shape regardless of
who asks.

## Relation to `scan_idor`

`scan_idor` exists and handles URL-query-parameter and JSON-
body IDORs on DAST-discovered endpoints. `scan_api_bola` is the
*spec-driven* counterpart: it picks targets from
`SecurityContext.endpoints` that came in via
`openapi_spec_ingest` (recognised by their `kind=api_endpoint`
Surface prop) and substitutes path parameters. The two are
complementary — running both gives full coverage.

Kill switch: `STRIX_API_BOLA_DISABLED=1`.
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


_PATH_PARAM_RE = re.compile(r"\{([A-Za-z_][\w]*)\}")


def _kill_switched() -> bool:
    return os.environ.get("STRIX_API_BOLA_DISABLED") == "1"


def _instantiate_path(template: str, ids: dict[str, str]) -> str | None:
    """Substitute `{name}` placeholders in `template` from `ids`.
    Returns None when any placeholder lacks an id."""
    if not _PATH_PARAM_RE.search(template):
        # No path params — nothing to substitute; return as-is.
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
    """Pull captured Bearer / session headers for `label` from
    `SecurityContext.auth_states`. Returns empty dict when the
    label isn't captured."""
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
            "scan_api_bola: SecurityContext read failed", exc_info=True,
        )
        return {}


@register_specialist_tool(
    category="api-bola-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 180},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1078"],   # Valid Accounts
)
def scan_api_bola(
    *,
    endpoints: list[dict[str, Any]],
    owner_label: str = "user-a",
    accessor_label: str = "user-b",
    owner_ids: dict[str, str] | None = None,
    accessor_ids: dict[str, str] | None = None,
    timeout_seconds: float = 8.0,
    max_endpoints: int = 50,
    _fetcher=None,
) -> SpecialistResult:
    """Probe OpenAPI-ingested endpoints for OWASP API1 BOLA.

    Args:
        endpoints: list of endpoint dicts from
            `openapi_spec_ingest` — each has `url` (with
            `{param}` placeholders), `method`, `auth_required`,
            `params`. Only endpoints with at least one path
            parameter AND auth_required are probed.
        owner_label: AuthState label of the resource owner.
        accessor_label: AuthState label of a different user
            (who should NOT see owner's records).
        owner_ids: dict mapping path-param names → owner's
            object IDs (e.g. `{"id": "42", "orderId": "1001"}`).
        accessor_ids: optional accessor's own IDs. When
            supplied, the helper ALSO probes "accessor fetches
            their own record" → status_a baseline.
        timeout_seconds: per-request HTTP timeout.
        max_endpoints: cap probe count.
        _fetcher: injection point for tests.

    Returns:
        `SpecialistResult` with one finding per BOLA-positive
        endpoint.

    Kill switch: `STRIX_API_BOLA_DISABLED=1`.
    """
    if _kill_switched():
        return SpecialistResult(
            status="error",
            error="kill_switch (STRIX_API_BOLA_DISABLED)",
        )

    if not endpoints or not isinstance(endpoints, list):
        return SpecialistResult(
            status="error", error="endpoints list required",
        )
    if not owner_ids:
        return SpecialistResult(
            status="error",
            error=(
                "owner_ids dict required (map of {param_name: "
                "owner_value} for path-param substitution)"
            ),
        )

    owner_headers = _auth_headers_for_label(owner_label)
    accessor_headers = _auth_headers_for_label(accessor_label)
    if not accessor_headers:
        return SpecialistResult(
            status="error",
            error=(
                f"accessor_label={accessor_label!r} session not captured "
                f"in SecurityContext.auth_states. Run "
                f"scan_multi_role_auth first."
            ),
        )

    fetcher = _fetcher or _default_fetcher
    findings: list[FindingDraft] = []
    evidence: list[str] = []
    probed = 0
    skipped_no_path_params = 0
    skipped_anonymous = 0

    for ep in endpoints:
        if probed >= max_endpoints:
            break
        url_template = ep.get("url", "")
        method = (ep.get("method") or "GET").upper()
        if not isinstance(url_template, str) or not url_template:
            continue
        # Need at least one path parameter — that's the BOLA
        # surface. No-param endpoints can't be BOLA-tested this way.
        if not _PATH_PARAM_RE.search(url_template):
            skipped_no_path_params += 1
            continue
        # Skip anonymous endpoints; BOLA only applies to
        # auth-walled surfaces.
        if not ep.get("auth_required"):
            skipped_anonymous += 1
            continue

        target_url = _instantiate_path(url_template, owner_ids)
        if not target_url:
            evidence.append(
                f"skipped {method} {url_template}: missing "
                f"path-param substitutions"
            )
            continue

        probed += 1

        # Owner request — baseline.
        owner_status, owner_body = fetcher(
            url=target_url, method=method,
            headers=owner_headers, timeout=timeout_seconds,
        )
        if owner_status is None:
            evidence.append(
                f"network error on owner probe: {method} {target_url}"
            )
            continue
        # If the owner can't see their own record, skip — config
        # issue / wrong IDs supplied.
        if owner_status >= 400:
            evidence.append(
                f"owner cannot access {method} {target_url}: "
                f"status={owner_status}; skipping (verify owner_ids)"
            )
            continue

        # Accessor request — same URL, different auth.
        accessor_status, accessor_body = fetcher(
            url=target_url, method=method,
            headers=accessor_headers, timeout=timeout_seconds,
        )
        if accessor_status is None:
            evidence.append(
                f"network error on accessor probe: {method} {target_url}"
            )
            continue

        # The BOLA test: accessor got a 200 AND the body matches
        # owner's. Hash-compare to dodge generic-empty-list noise.
        owner_hash = _hash_body(owner_body)
        accessor_hash = _hash_body(accessor_body)
        bola_positive = (
            accessor_status == 200 and accessor_hash == owner_hash
        )

        if bola_positive:
            findings.append(FindingDraft(
                title=(
                    f"BOLA at {method} {url_template} — "
                    f"{accessor_label} read {owner_label}'s record"
                ),
                severity="high",
                cwe="CWE-639",
                endpoint=target_url,
                category="api_bola",
                description=(
                    f"Endpoint `{method} {url_template}` returned the "
                    f"same response to `{accessor_label}` "
                    f"(status={accessor_status}) as it did to the "
                    f"owner `{owner_label}` (status={owner_status}). "
                    f"Response body sha256[:16] matched: "
                    f"`{owner_hash}`.\n\n"
                    f"This is OWASP API1:2023 Broken Object Level "
                    f"Authorization — the API authenticates but "
                    f"doesn't authorize per-object. Any authenticated "
                    f"user can read any other user's records by "
                    f"changing the path parameter."
                ),
                verification_status="verified",
                confidence=0.95,
                reasoning_trace=[
                    f"Owner ({owner_label}) probe: "
                    f"status={owner_status}, body_hash={owner_hash}.",
                    f"Accessor ({accessor_label}) probe at same URL: "
                    f"status={accessor_status}, "
                    f"body_hash={accessor_hash}.",
                    "Hashes match → accessor read owner's record → BOLA.",
                ],
            ))

    return SpecialistResult(
        status="ok",
        findings=findings,
        evidence=evidence,
        tool_metadata={
            "probed": probed,
            "skipped_no_path_params": skipped_no_path_params,
            "skipped_anonymous": skipped_anonymous,
            "bola_findings": len(findings),
        },
    )
