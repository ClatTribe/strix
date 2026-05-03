"""M365 / Azure AD (Entra ID) tenant enumeration.

Two public Microsoft endpoints reveal everything a recon agent needs to
know about a target's M365 / Entra posture without authentication:

1. **OpenID Connect discovery** at
   `https://login.microsoftonline.com/<domain>/.well-known/openid-configuration`
   When the domain is a registered Entra tenant, the response is the
   standard OIDC discovery JSON with `issuer` =
   `https://login.microsoftonline.com/<tenant-id>/v2.0`. The tenant ID
   is the GUID portion — the pivot key for every Azure-resource probe
   downstream.

2. **GetUserRealm** at
   `https://login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&xml=1`
   Returns XML with `NameSpaceType` (Managed / Federated / Unknown),
   `FederationBrandName` (when federated — names the IdP, e.g. "ADFS"
   / "Okta" / "Ping"), and the canonical `DomainName`. Determines
   whether the org has its own IdP behind M365 (federated) or sits
   directly in the M365 cloud (managed).

Findings:
- **Info** (CWE-200, info_disclosure) when the domain is confirmed as
  an M365 tenant (with tenant ID extracted).
- **Info** when federation is detected — names the IdP (ADFS / Okta /
  Ping). Recon-time signal; the IdP becomes a separate auth surface
  worth investigating.

Composes with cluster-A safety. The probe targets Microsoft endpoints,
not the customer's domain — `--exclude-path` against the customer
shouldn't apply, but `--rate-limit` still throttles outbound calls.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "m365_tenant_recon"
_HTTP_TIMEOUT = 12

# Issuer URL pattern: `https://login.microsoftonline.com/<tenant-guid>/v2.0`.
# Tenant GUID is 32 hex chars + 4 dashes; we accept the standard format
# but tolerate extra suffix characters in case Microsoft adds path components.
_ISSUER_TENANT_RE = re.compile(
    r"https?://login\.microsoftonline\.com/"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"/v2\.0",
    re.IGNORECASE,
)

# GetUserRealm XML field extractors. The response is small; regex is
# adequate and keeps the dependency surface minimal.
_USERREALM_NAMESPACE_RE = re.compile(r"<NameSpaceType>([^<]+)</NameSpaceType>", re.IGNORECASE)
_USERREALM_FEDBRAND_RE = re.compile(r"<FederationBrandName>([^<]+)</FederationBrandName>", re.IGNORECASE)
_USERREALM_DOMAIN_RE = re.compile(r"<DomainName>([^<]+)</DomainName>", re.IGNORECASE)
_USERREALM_AUTH_URL_RE = re.compile(r"<AuthURL>([^<]+)</AuthURL>", re.IGNORECASE)
_USERREALM_FEDERATION_PROTOCOL_RE = re.compile(
    r"<FederationProtocol>([^<]+)</FederationProtocol>", re.IGNORECASE
)


_DOMAIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,63})+$")


def _looks_like_domain(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    return bool(_DOMAIN_RE.match(value))


def _http_get(url: str, *, timeout: int = _HTTP_TIMEOUT) -> dict[str, Any]:
    """GET via cluster-A safety. Returns {status, headers, body, error?}."""
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, timeout=timeout)
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": r.get("headers") or {},
                "body": r.get("body") or "",
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
        merged = inject_auth_headers({})
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body": r.text[:64 * 1024],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _probe_openid_configuration(domain: str) -> dict[str, Any]:
    """Probe the OIDC discovery endpoint. Returns:
    {present: bool, status: int, tenant_id: str | None, issuer: str | None,
     authorization_endpoint, token_endpoint, jwks_uri, error?}
    """
    url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
    response = _http_get(url)
    out: dict[str, Any] = {
        "url": url,
        "present": False,
        "status": response.get("status", 0),
        "tenant_id": None,
        "issuer": None,
    }
    if response.get("error"):
        out["error"] = response["error"]
        return out
    if response.get("status") != 200:
        return out
    body = response.get("body") or ""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        out["error"] = "OIDC response is not valid JSON"
        return out
    if not isinstance(data, dict):
        return out
    issuer = data.get("issuer")
    if isinstance(issuer, str):
        out["issuer"] = issuer
        m = _ISSUER_TENANT_RE.search(issuer)
        if m:
            out["tenant_id"] = m.group(1).lower()
            out["present"] = True
    # Capture the most useful OAuth metadata for downstream reasoning,
    # but keep the captured set tight (no full schema dump).
    for field in (
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "end_session_endpoint",
    ):
        value = data.get(field)
        if isinstance(value, str):
            out[field] = value
    return out


def _probe_user_realm(domain: str) -> dict[str, Any]:
    """Probe the GetUserRealm endpoint. Returns:
    {present, status, namespace_type, federation_brand, federation_protocol,
     auth_url, canonical_domain, error?}
    """
    url = (
        "https://login.microsoftonline.com/getuserrealm.srf?"
        f"login=user@{domain}&xml=1"
    )
    response = _http_get(url)
    out: dict[str, Any] = {
        "url": url,
        "present": False,
        "status": response.get("status", 0),
        "namespace_type": None,
        "federation_brand": None,
        "federation_protocol": None,
        "auth_url": None,
        "canonical_domain": None,
    }
    if response.get("error"):
        out["error"] = response["error"]
        return out
    if response.get("status") != 200:
        return out
    body = response.get("body") or ""

    ns_match = _USERREALM_NAMESPACE_RE.search(body)
    if ns_match:
        out["namespace_type"] = ns_match.group(1).strip()
        # `Unknown` namespace_type means the domain is not registered
        # with Entra. Anything else (Managed / Federated) confirms M365.
        if out["namespace_type"] and out["namespace_type"].lower() != "unknown":
            out["present"] = True

    fb_match = _USERREALM_FEDBRAND_RE.search(body)
    if fb_match:
        out["federation_brand"] = fb_match.group(1).strip()
    fp_match = _USERREALM_FEDERATION_PROTOCOL_RE.search(body)
    if fp_match:
        out["federation_protocol"] = fp_match.group(1).strip()
    auth_match = _USERREALM_AUTH_URL_RE.search(body)
    if auth_match:
        out["auth_url"] = auth_match.group(1).strip()
    domain_match = _USERREALM_DOMAIN_RE.search(body)
    if domain_match:
        out["canonical_domain"] = domain_match.group(1).strip()
    return out


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
        category="info_disclosure",
        cwe="CWE-200",
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "M365 / Entra tenant identification is publicly designed and not "
            "a vulnerability on its own. It accelerates downstream "
            "reconnaissance: with the tenant ID an attacker can probe Azure "
            "blob storage / web apps / cloud services scoped to that tenant, "
            "enumerate users via Graph API in some configurations, and tailor "
            "credential-stuffing or phishing campaigns to the org's specific "
            "auth flow. When federation is in use, the third-party IdP "
            "becomes an additional attack surface (ADFS pre-auth, Okta auth "
            "policy bypass, Ping config, etc.)."
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
    mitre_techniques=["T1591.002"],  # Gather Victim Org Info: Business Relationships
)
def m365_tenant_recon(domain: str) -> dict[str, Any]:
    """Detect M365 / Azure AD (Entra ID) tenant + federation posture.

    Args:
        domain: apex domain (e.g. `example.com` or `contoso.onmicrosoft.com`).
                Bare hostnames only — URLs are rejected.

    Probes two public Microsoft endpoints (no auth required):
    1. OIDC discovery → extracts tenant GUID from issuer URL
    2. GetUserRealm → namespace type (Managed / Federated / Unknown) +
       federation brand (ADFS / Okta / Ping / etc.) when federated

    Findings:
    - **Info** (CWE-200, info_disclosure) when the domain resolves to an
      Entra tenant (with tenant ID in the finding).
    - **Info** with elevated detail when federation reveals a third-party
      IdP — that becomes a separate attack surface.

    Returns:
        {
          success, domain, is_m365_tenant: bool,
          tenant_id: str | None,
          openid_configuration: {...},
          user_realm: {...},
        }
    """
    if not domain or not domain.strip():
        return {"success": False, "error": "domain required"}
    domain = domain.strip().lower().rstrip("/")
    # Strip scheme if the agent accidentally passed a URL.
    if "://" in domain:
        parsed = urlparse(domain)
        domain = (parsed.hostname or "").lower()
    if not _looks_like_domain(domain):
        return {"success": False, "error": f"invalid domain: {domain!r}"}

    cev = _start_check("m365_tenant_recon", domain)

    oidc = _probe_openid_configuration(domain)
    realm = _probe_user_realm(domain)

    is_tenant = bool(oidc.get("present") or realm.get("present"))
    tenant_id = oidc.get("tenant_id")

    if is_tenant:
        # Determine plain-English summary based on what we saw.
        ns_type = realm.get("namespace_type")
        fed_brand = realm.get("federation_brand")
        fed_protocol = realm.get("federation_protocol")
        canonical = realm.get("canonical_domain") or domain

        if (ns_type or "").lower() == "federated" and fed_brand:
            description_plain = (
                f"This domain uses Microsoft 365 with single-sign-on (SSO) via "
                f"{fed_brand}. Sign-in goes through {fed_brand} first, then "
                "back to Microsoft. The third-party identity provider is its "
                "own attack surface worth reviewing."
            )
            severity = "info"
            title_suffix = f"federated via {fed_brand}"
            recommended_action = (
                f"Audit the {fed_brand} configuration: ensure MFA is enforced, "
                "ADFS endpoints aren't pre-auth-bypassable, conditional-access "
                "rules cover all sign-in flows. Confirm the federation trust "
                "relationship is necessary and review the SAML / WS-Fed "
                "claim-transformation rules for over-grants."
            )
        elif (ns_type or "").lower() == "managed":
            description_plain = (
                "This domain is a Microsoft 365 tenant managed directly by "
                "Microsoft (no third-party SSO). Authentication is handled by "
                "Entra ID."
            )
            severity = "info"
            title_suffix = "managed Entra tenant"
            recommended_action = (
                "Ensure all sign-in surfaces require MFA via Conditional "
                "Access. Disable legacy authentication protocols (POP/IMAP "
                "basic auth, SMTP AUTH). Audit Entra app registrations for "
                "over-permissive consent grants."
            )
        else:
            description_plain = (
                "This domain is registered with Microsoft 365 / Entra ID. "
                "Tenant ID is publicly discoverable."
            )
            severity = "info"
            title_suffix = "Entra tenant detected"
            recommended_action = (
                "Tenant-ID disclosure is by design — no remediation. Ensure "
                "downstream Azure resources (storage accounts, web apps, "
                "function apps) scoped to this tenant ID are properly "
                "access-controlled."
            )

        evidence_lines = [f"Domain: {domain}"]
        if canonical and canonical.lower() != domain.lower():
            evidence_lines.append(f"Canonical (Microsoft): {canonical}")
        if tenant_id:
            evidence_lines.append(f"Tenant ID: {tenant_id}")
        if oidc.get("issuer"):
            evidence_lines.append(f"Issuer: {oidc['issuer']}")
        if ns_type:
            evidence_lines.append(f"Namespace type: {ns_type}")
        if fed_brand:
            evidence_lines.append(f"Federation brand: {fed_brand}")
        if fed_protocol:
            evidence_lines.append(f"Federation protocol: {fed_protocol}")
        if realm.get("auth_url"):
            evidence_lines.append(f"AuthURL: {realm['auth_url']}")
        if oidc.get("authorization_endpoint"):
            evidence_lines.append(f"OAuth authz endpoint: {oidc['authorization_endpoint']}")
        if oidc.get("token_endpoint"):
            evidence_lines.append(f"OAuth token endpoint: {oidc['token_endpoint']}")
        if oidc.get("jwks_uri"):
            evidence_lines.append(f"JWKS URI: {oidc['jwks_uri']}")

        _emit_finding(
            title=f"M365 / Entra tenant: {domain} ({title_suffix})",
            severity=severity,
            target=domain,
            endpoint=oidc.get("url") or realm.get("url") or domain,
            description="\n".join(evidence_lines),
            description_plain=description_plain,
            recommended_action=recommended_action,
        )

    _complete_check(
        cev,
        result="vulnerable" if is_tenant else "not_vulnerable",
        evidence=(
            f"M365 tenant detected (tenant_id={tenant_id}, "
            f"namespace={realm.get('namespace_type')})"
            if is_tenant
            else f"not an M365 tenant (oidc_status={oidc.get('status')}, "
            f"realm_status={realm.get('status')})"
        ),
    )

    return {
        "success": True,
        "domain": domain,
        "is_m365_tenant": is_tenant,
        "tenant_id": tenant_id,
        "openid_configuration": oidc,
        "user_realm": realm,
    }
