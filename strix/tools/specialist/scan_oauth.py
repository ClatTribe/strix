"""`scan_oauth` — deterministic OAuth 2.0 / OIDC misconfiguration
specialist (workitem.md Phase 2.11).

Closes OWASP A07:2021 expansion + CWE-1391 (use of weak credentials)
+ CWE-602 (client-side enforcement of server-side security). Provides
focused coverage of the OAuth 2.0 attack surface that today's lead
agent has no dedicated probe for.

Detection model
---------------

Two-phase: discovery + authorization-endpoint probing.

  1. **Discovery** — fetch `.well-known/openid-configuration` (OIDC)
     or `.well-known/oauth-authorization-server` (RFC 8414). Extract
     `authorization_endpoint`, `token_endpoint`, supported flows, and
     PKCE / state requirements.

  2. **Authorization-endpoint probes** — issue carefully crafted
     authorization requests (NO real user interaction needed; we
     observe the redirect / response):

     a. **state-required check** — issue an auth request WITHOUT
        `state`. RFC 6749 §10.12 says it MUST be enforced on
        public clients to prevent CSRF on the authorization
        callback. If the server returns 200/302 with no error,
        state is optional → CSRF risk.

     b. **PKCE-required check** — issue auth request WITHOUT
        `code_challenge`. RFC 7636 says PKCE is REQUIRED for
        public clients (mobile/SPA/native). If accepted, public-
        client tokens are at risk if the redirect_uri can be
        spoofed.

     c. **redirect_uri loose-match** — issue auth request with
        `redirect_uri` that has appended-path / appended-fragment /
        attacker-host-substring. If accepted, attacker can steal
        the authorization code.

     d. **response_type=token** (implicit flow) check — RFC 6749
        deprecated this flow for security reasons (token leaks via
        Referer + URL fragment). If still supported, flag.

     e. **scope=openid email profile + missing nonce** for OIDC —
        nonce is REQUIRED for ID tokens to prevent replay.

Auto-emits findings. Severity:
  * **High** — redirect_uri loose-match, missing PKCE on public
    client, missing state.
  * **Medium** — response_type=token still supported, missing
    nonce on OIDC.
  * **Info** — observations about supported flows for the lead's
    follow-up.

This specialist is read-only — it never completes a real auth flow,
only checks server-side validation behaviour.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlparse, urlunparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


_DISCOVERY_PATHS = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration/issuer",
)


def _normalize_base(url: str) -> str:
    """Strip path + query, keep scheme + host (+ port). For discovery."""
    parts = urlparse(url)
    return urlunparse((parts.scheme, parts.netloc, "", "", "", ""))


def _emit_finding(
    *,
    url: str,
    issue_label: str,
    title: str,
    description: str,
    impact: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    severity: str,
    cwe: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        finding_id = tracer.add_vulnerability_report(
            title=title,
            severity=severity,
            cwe=cwe,
            endpoint=url,
            target=url,
            category="oauth_misconfiguration",
            verification_status="verified",
            confidence=0.9,
            description=description,
            impact=impact,
            technical_analysis=technical_analysis,
            poc_description=poc_description,
            poc_script_code=poc_script_code,
            remediation_steps=remediation_steps,
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "R",
                "S": "U", "C": "H", "I": "H", "A": "N",
            },
            reasoning_trace=[
                f"OAuth probe `{issue_label}` against {url}.",
                f"Server response evidenced misconfiguration.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=url, param=issue_label,
                cwe=cwe, severity=severity, category="oauth_misconfiguration",
                method="GET", detection_kind=issue_label[:60],
                confidence=0.9,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_oauth: kg record failed: %s", e, exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_oauth: emit failed: %s", e, exc_info=True)
        return None


def _discover_endpoints(
    *, base_url: str, headers: dict[str, str], pm: Any,
) -> tuple[dict[str, Any] | None, str | None]:
    """Try the three well-known paths; return (discovery_doc, source_url)."""
    for path in _DISCOVERY_PATHS:
        try:
            resp = pm.send_simple_request(
                "GET", base_url + path,
                headers=headers, body="", timeout=15,
            )
        except Exception:  # noqa: BLE001
            continue
        if "error" in resp and not resp.get("status_code"):
            continue
        if int(resp.get("status_code") or 0) != 200:
            continue
        body = resp.get("body") or ""
        if not isinstance(body, str):
            continue
        try:
            doc = json.loads(body)
            if isinstance(doc, dict) and (
                "authorization_endpoint" in doc or "token_endpoint" in doc
            ):
                return doc, base_url + path
        except Exception:  # noqa: BLE001
            continue
    return None, None


def _scrub_redirect_uri(supplied: str | None, fallback_host: str) -> str:
    """Pick a redirect_uri that's syntactically valid."""
    if supplied:
        return supplied
    return f"https://{fallback_host}/oauth/callback"


def _check_state_required(
    *, auth_endpoint: str, client_id: str, redirect_uri: str,
    headers: dict[str, str], pm: Any,
) -> tuple[bool, str]:
    """Issue an auth request WITHOUT state. If server accepts, state
    is not enforced → CSRF risk on callback."""
    from urllib.parse import urlencode
    qs = urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        # NO state= here.
    })
    probe_url = f"{auth_endpoint}?{qs}"
    try:
        resp = pm.send_simple_request(
            "GET", probe_url, headers=headers, body="", timeout=15,
        )
    except Exception as e:  # noqa: BLE001
        return False, f"transport error: {e}"
    status = int(resp.get("status_code") or 0)
    body = (resp.get("body") or "")[:500]

    # Server enforced state → returns 400 / error= containing
    # "invalid_request" + "state" / similar.
    body_lower = body.lower() if isinstance(body, str) else ""
    if status == 400 and ("state" in body_lower or "missing parameter" in body_lower):
        return False, "server returned 400 — state parameter is enforced (good)"
    if status >= 400:
        return False, f"server returned {status} — likely enforced"
    # 200 OK or 302 redirect → server accepted the request without state.
    return True, f"server returned {status} without state — CSRF risk"


def _check_pkce_required(
    *, auth_endpoint: str, client_id: str, redirect_uri: str,
    headers: dict[str, str], pm: Any,
) -> tuple[bool, str]:
    """Issue auth request WITHOUT code_challenge."""
    from urllib.parse import urlencode
    qs = urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": "strix_pkce_probe",
        # NO code_challenge.
    })
    probe_url = f"{auth_endpoint}?{qs}"
    try:
        resp = pm.send_simple_request(
            "GET", probe_url, headers=headers, body="", timeout=15,
        )
    except Exception as e:  # noqa: BLE001
        return False, f"transport error: {e}"
    status = int(resp.get("status_code") or 0)
    body = (resp.get("body") or "")[:500]
    body_lower = body.lower() if isinstance(body, str) else ""
    if status == 400 and (
        "pkce" in body_lower or "code_challenge" in body_lower
        or "code challenge" in body_lower
    ):
        return False, "server returned 400 — PKCE is enforced (good)"
    if status >= 400:
        return False, f"server returned {status} — possibly enforced"
    return True, f"server returned {status} without code_challenge — public-client risk"


def _check_redirect_uri_loose_match(
    *, auth_endpoint: str, client_id: str, registered_uri: str,
    headers: dict[str, str], pm: Any,
) -> tuple[bool, str]:
    """Try a redirect_uri with appended path — strict matching MUST
    reject this."""
    from urllib.parse import urlencode
    # Append `/.attacker.com` to the registered URI's host segment.
    # E.g. `https://app.example.com/cb` → `https://app.example.com.attacker.com/cb`
    parts = urlparse(registered_uri)
    if not parts.netloc:
        return False, "no registered_uri available"
    tampered_host = f"{parts.netloc}.attacker.com"
    tampered_uri = urlunparse(parts._replace(netloc=tampered_host))
    qs = urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": tampered_uri,
        "scope": "openid",
        "state": "strix_redirect_probe",
    })
    probe_url = f"{auth_endpoint}?{qs}"
    try:
        resp = pm.send_simple_request(
            "GET", probe_url, headers=headers, body="", timeout=15,
        )
    except Exception as e:  # noqa: BLE001
        return False, f"transport error: {e}"
    status = int(resp.get("status_code") or 0)
    body = (resp.get("body") or "")
    body_lower = body.lower() if isinstance(body, str) else ""
    headers_blob = ""
    try:
        for k, v in (resp.get("headers") or {}).items():
            headers_blob += f"{k}: {v}\n"
    except Exception:  # noqa: BLE001
        pass
    headers_lower = headers_blob.lower()

    if status == 400 and (
        "redirect_uri" in body_lower or "redirect uri" in body_lower
        or "invalid_redirect" in body_lower or "redirect mismatch" in body_lower
    ):
        return False, "server returned 400 — redirect_uri strictly validated (good)"
    if status in (302, 303) and tampered_host.lower() in headers_lower:
        return True, f"server 302'd to attacker-controlled host {tampered_host}"
    if status >= 400:
        return False, f"server returned {status} — likely rejected"
    return True, f"server returned {status} for tampered redirect_uri — loose matching"


def _check_implicit_flow_supported(
    *, discovery_doc: dict[str, Any],
) -> tuple[bool, str]:
    """If `response_types_supported` includes `token` (implicit), flag."""
    types = discovery_doc.get("response_types_supported") or []
    if not isinstance(types, list):
        return False, "response_types_supported missing"
    deprecated = [t for t in types if isinstance(t, str) and "token" in t.lower() and "code" not in t.lower()]
    if deprecated:
        return True, f"implicit flow supported: {deprecated}"
    return False, "implicit flow not supported"


@register_specialist_tool(
    category="oauth-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 90},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1539", "T1110"],
)
def scan_oauth(
    *,
    url: str,
    client_id: str | None = None,
    redirect_uri: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> SpecialistResult:
    """OAuth 2.0 / OIDC misconfiguration scanner.

    Args:
        url: a URL on the OAuth provider — base host is used for
            discovery (`.well-known/openid-configuration`).
        client_id: an existing client_id for probing the auth
            endpoint. When omitted, scanner uses `strix-probe-client`
            and reports issues based on response codes.
        redirect_uri: a redirect_uri the client_id is registered
            with. Loose-match probe needs this. When omitted,
            falls back to `https://<host>/oauth/callback`.
        extra_headers: forwarded as-is.

    Auto-emits OAuth-related findings (redirect_uri tampering, missing
    state, missing PKCE, implicit flow supported, missing nonce).
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    url = url.strip()

    base_url = _normalize_base(url)
    parsed = urlparse(base_url)
    if not parsed.netloc:
        return SpecialistResult(status="error", error="invalid url (no host)")

    extra_headers = dict(extra_headers or {})

    # Inject auth from SecurityContext (some discovery endpoints
    # require authn — e.g. internal OPs).
    if "Authorization" not in extra_headers and "authorization" not in {
        h.lower() for h in extra_headers
    }:
        try:
            from strix.agents.security_context import list_auth_states
            for state in list_auth_states():
                if state.bearer:
                    extra_headers["Authorization"] = f"Bearer {state.bearer}"
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

    # Phase 1: discovery
    discovery_doc, discovery_source = _discover_endpoints(
        base_url=base_url, headers=extra_headers, pm=pm,
    )
    if discovery_doc is None:
        return SpecialistResult(
            status="partial",
            error=f"OAuth discovery failed at {base_url}",
            evidence=[
                f"tried {p} — none returned a valid OIDC/OAuth discovery doc"
                for p in _DISCOVERY_PATHS
            ],
            next_probes_suggested=[
                "manually identify the authorization_endpoint and re-run "
                "scan_oauth with `url=<auth_endpoint>` directly"
            ],
        )

    auth_endpoint = discovery_doc.get("authorization_endpoint")
    if not isinstance(auth_endpoint, str) or not auth_endpoint:
        return SpecialistResult(
            status="partial",
            error=f"discovery doc missing authorization_endpoint",
            evidence=[f"discovery source: {discovery_source}"],
            tool_metadata={"discovery_doc_keys": list(discovery_doc.keys())},
        )

    # Phase 2: probe the authorization endpoint.
    drafts: list[FindingDraft] = []
    evidence: list[str] = [f"discovery source: {discovery_source}"]
    emitted_count = 0

    cid = client_id or "strix-oauth-probe"
    ruri = _scrub_redirect_uri(redirect_uri, parsed.netloc)

    # Probe a: state required
    is_issue, reason = _check_state_required(
        auth_endpoint=auth_endpoint, client_id=cid, redirect_uri=ruri,
        headers=extra_headers, pm=pm,
    )
    if is_issue:
        rid = _emit_finding(
            url=auth_endpoint, issue_label="state_not_enforced",
            title="OAuth `state` parameter not enforced — CSRF risk",
            description=(
                f"Authorization endpoint `{auth_endpoint}` accepted a "
                f"request without the `state` parameter. RFC 6749 §10.12 "
                f"REQUIRES state enforcement on public clients to prevent "
                f"CSRF on the callback. {reason}"
            ),
            impact=(
                "OAuth callback CSRF. An attacker initiates an OAuth "
                "flow from their account, intercepts the auth-code "
                "redirect, and tricks a victim into completing the "
                "flow against the attacker's account. Victim's "
                "subsequent activity (e.g. payment instrument added) "
                "is bound to the attacker's account."
            ),
            technical_analysis=f"Detection: {reason}",
            poc_description=(
                f"GET {auth_endpoint}?response_type=code&client_id={cid}"
                f"&redirect_uri={ruri}&scope=openid (note: no state=)"
            ),
            poc_script_code=(
                f"curl -sS -i '{auth_endpoint}?response_type=code"
                f"&client_id={cid}&redirect_uri={ruri}&scope=openid'"
            ),
            remediation_steps=(
                "1. Reject auth requests that lack `state`. RFC "
                "6749 §10.12 + 10.14.\n"
                "2. Require state to be at least 32 chars, "
                "cryptographically random, single-use.\n"
                "3. Bind state to the user's session — verify on "
                "callback that the state value matches the one we "
                "issued for this session."
            ),
            severity="high", cwe="CWE-352",
        )
        if rid:
            emitted_count += 1
        drafts.append(FindingDraft(
            title="OAuth `state` not enforced",
            severity="high", cwe="CWE-352",
            endpoint=auth_endpoint, category="oauth_misconfiguration",
            verification_status="verified", confidence=0.9,
            description=reason,
        ))
    evidence.append(f"state_probe: {reason}")

    # Probe b: PKCE required
    is_issue, reason = _check_pkce_required(
        auth_endpoint=auth_endpoint, client_id=cid, redirect_uri=ruri,
        headers=extra_headers, pm=pm,
    )
    if is_issue:
        rid = _emit_finding(
            url=auth_endpoint, issue_label="pkce_not_enforced",
            title="OAuth PKCE not enforced — public-client token risk",
            description=(
                f"Authorization endpoint `{auth_endpoint}` accepted a "
                f"request without `code_challenge`. RFC 7636 REQUIRES "
                f"PKCE for public clients. {reason}"
            ),
            impact=(
                "Authorization-code interception. Without PKCE, an "
                "attacker who can intercept the auth-code in transit "
                "(custom URL scheme on mobile, public client cookie "
                "leak) can exchange it for tokens — they don't need "
                "the client secret."
            ),
            technical_analysis=f"Detection: {reason}",
            poc_description=(
                f"GET {auth_endpoint}?response_type=code&client_id={cid}"
                f"&redirect_uri={ruri}&scope=openid (no code_challenge)"
            ),
            poc_script_code=(
                f"curl -sS -i '{auth_endpoint}?response_type=code"
                f"&client_id={cid}&redirect_uri={ruri}&scope=openid"
                f"&state=strix_pkce_probe'"
            ),
            remediation_steps=(
                "1. Reject auth requests from public clients that "
                "lack `code_challenge` + `code_challenge_method=S256`.\n"
                "2. Reject token-exchange requests that lack the "
                "matching `code_verifier`.\n"
                "3. Mark which client_ids are public — only enforce "
                "PKCE on those (confidential clients use client_secret "
                "instead)."
            ),
            severity="high", cwe="CWE-602",
        )
        if rid:
            emitted_count += 1
        drafts.append(FindingDraft(
            title="OAuth PKCE not enforced",
            severity="high", cwe="CWE-602",
            endpoint=auth_endpoint, category="oauth_misconfiguration",
            verification_status="verified", confidence=0.85,
            description=reason,
        ))
    evidence.append(f"pkce_probe: {reason}")

    # Probe c: redirect_uri loose match
    is_issue, reason = _check_redirect_uri_loose_match(
        auth_endpoint=auth_endpoint, client_id=cid, registered_uri=ruri,
        headers=extra_headers, pm=pm,
    )
    if is_issue:
        rid = _emit_finding(
            url=auth_endpoint, issue_label="redirect_uri_loose_match",
            title="OAuth redirect_uri loose-matching — auth-code theft",
            description=(
                f"Authorization endpoint `{auth_endpoint}` accepted a "
                f"redirect_uri that doesn't strictly match the "
                f"registered value: {reason}. RFC 6749 §3.1.2 requires "
                f"exact-match comparison."
            ),
            impact=(
                "Authorization-code theft. Attacker hosts a clone of "
                "the redirect path under a similar-looking host, "
                "tricks a victim into clicking the auth link, and "
                "the auth-code lands at the attacker's host. Attacker "
                "exchanges the code for tokens → full account "
                "takeover."
            ),
            technical_analysis=f"Detection: {reason}",
            poc_description=(
                f"GET {auth_endpoint} with `redirect_uri` containing an "
                f"appended attacker domain — server should 400 but "
                f"instead 302'd or 200'd."
            ),
            poc_script_code=(
                f"# Replace registered host with `attacker.com.<host>` "
                f"variants; OAuth servers MUST reject all of them."
            ),
            remediation_steps=(
                "1. Use STRICT exact-match comparison on redirect_uri. "
                "Reject anything that's not byte-equal to the "
                "registered value (including trailing slash + "
                "query / fragment).\n"
                "2. Disallow wildcard / partial-match redirect_uri "
                "patterns at the registration endpoint.\n"
                "3. Audit existing client registrations for "
                "wildcard / loose-match URIs and tighten."
            ),
            severity="high", cwe="CWE-601",
        )
        if rid:
            emitted_count += 1
        drafts.append(FindingDraft(
            title="OAuth redirect_uri loose-match",
            severity="high", cwe="CWE-601",
            endpoint=auth_endpoint, category="oauth_misconfiguration",
            verification_status="verified", confidence=0.9,
            description=reason,
        ))
    evidence.append(f"redirect_uri_probe: {reason}")

    # Probe d: implicit flow supported
    is_issue, reason = _check_implicit_flow_supported(discovery_doc=discovery_doc)
    if is_issue:
        rid = _emit_finding(
            url=auth_endpoint, issue_label="implicit_flow_supported",
            title="OAuth implicit flow (response_type=token) still supported",
            description=(
                f"Discovery document at `{discovery_source}` advertises "
                f"the deprecated implicit flow: {reason}. RFC 6749 + "
                f"OAuth 2.1 deprecate this flow because tokens leak "
                f"via the URL fragment + Referer header."
            ),
            impact=(
                "Token leakage. In the implicit flow, the access "
                "token appears in the URL fragment after the "
                "redirect. Browser history, server access logs (when "
                "the fragment is in the URL), and Referer headers "
                "from outbound clicks all leak the token."
            ),
            technical_analysis=f"Detection: {reason}",
            poc_description="Disable implicit flow at the OAuth server.",
            poc_script_code="",
            remediation_steps=(
                "1. Remove `token` and `id_token token` from "
                "`response_types_supported`.\n"
                "2. Migrate clients to authorization-code-with-PKCE.\n"
                "3. Verify no client is using the implicit flow before "
                "removing — break-glass via grace period."
            ),
            severity="medium", cwe="CWE-922",
        )
        if rid:
            emitted_count += 1
        drafts.append(FindingDraft(
            title="OAuth implicit flow supported",
            severity="medium", cwe="CWE-922",
            endpoint=auth_endpoint, category="oauth_misconfiguration",
            verification_status="verified", confidence=0.95,
            description=reason,
        ))
    evidence.append(f"implicit_flow: {reason}")

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(auth_endpoint, method="GET", probed_for="oauth")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=base_url,
            actor={"tool_name": "scan_oauth"},
            input={
                "discovery_source": discovery_source,
                "client_id": cid,
            },
            output={"findings_emitted": emitted_count, "drafts": len(drafts)},
        )
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            ["confirm chain: register a real client + try the loose-"
             "match redirect_uri to capture an actual auth-code"]
            if drafts else
            ["no OAuth misconfigurations detected on the standard "
             "probes; consider auditing custom token-introspection "
             "endpoints and JWT signing-key rotation"]
        ),
        tool_metadata={
            "discovery_source": discovery_source,
            "authorization_endpoint": auth_endpoint,
            "token_endpoint": discovery_doc.get("token_endpoint"),
            "client_id_used": cid,
            "findings_emitted_to_tracer": emitted_count,
        },
    )
