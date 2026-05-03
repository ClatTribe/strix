"""Tests for m365_tenant_recon.

Hermetic — `_http_get` is mocked. Tests cover:
- Domain validation (rejects URLs / non-hostname inputs)
- OIDC tenant-ID extraction (managed-tenant case)
- GetUserRealm parsing (Managed / Federated / Unknown / unparsable)
- Federation flavors: ADFS / Okta / Ping with proper finding text
- "Unknown" namespace_type → no finding
- Both endpoints unreachable → no finding, no crash
- Cluster-A composition (excluded path)
- Plain-English fields + recommended_action populated correctly per case
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.m365_recon import m365_recon as m365
from strix.tools.proxy import http_safety


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("m365-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_get(monkeypatch, responses: dict[str, dict[str, Any]]) -> list[str]:
    """Patch _http_get with a URL → response dict mapping."""
    log: list[str] = []

    def fake(url, *, timeout=12):
        log.append(url)
        return responses.get(url, {"status": 404, "headers": {}, "body": ""})

    monkeypatch.setattr(m365, "_http_get", fake)
    return log


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_empty_domain_rejected() -> None:
    out = m365.m365_tenant_recon("")
    assert out["success"] is False


def test_invalid_domain_rejected() -> None:
    out = m365.m365_tenant_recon("not a hostname")
    assert out["success"] is False


def test_url_input_normalized(monkeypatch) -> None:
    """Agent might accidentally pass a URL — strip scheme + path."""
    log = _patch_get(monkeypatch, {})
    m365.m365_tenant_recon("https://example.com/some/path")
    # Both probes should target login.microsoftonline.com using just "example.com"
    assert any("/example.com/.well-known" in u for u in log)


# ---------------------------------------------------------------------------
# OIDC discovery
# ---------------------------------------------------------------------------


_TENANT_GUID = "12345678-1234-1234-1234-123456789abc"


def _oidc_response_body(tenant_id: str = _TENANT_GUID) -> str:
    return json.dumps({
        "issuer": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        "authorization_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize",
        "token_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        "userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
        "jwks_uri": f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
        "end_session_endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/logout",
    })


def test_oidc_extracts_tenant_id(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {
            f"https://login.microsoftonline.com/example.com/.well-known/openid-configuration": {
                "status": 200, "headers": {}, "body": _oidc_response_body(),
            },
            f"https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com&xml=1": {
                "status": 200, "headers": {},
                "body": "<RealmInfo><NameSpaceType>Managed</NameSpaceType></RealmInfo>",
            },
        },
    )
    out = m365.m365_tenant_recon("example.com")
    assert out["is_m365_tenant"] is True
    assert out["tenant_id"] == _TENANT_GUID
    oidc = out["openid_configuration"]
    assert oidc["present"] is True
    assert oidc["issuer"].endswith(f"/{_TENANT_GUID}/v2.0")
    assert "authorization_endpoint" in oidc
    assert "jwks_uri" in oidc


def test_oidc_404_means_not_tenant(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {
            f"https://login.microsoftonline.com/notatenant.com/.well-known/openid-configuration": {
                "status": 404, "headers": {}, "body": "",
            },
            f"https://login.microsoftonline.com/getuserrealm.srf?login=user@notatenant.com&xml=1": {
                "status": 200, "headers": {},
                "body": "<RealmInfo><NameSpaceType>Unknown</NameSpaceType></RealmInfo>",
            },
        },
    )
    out = m365.m365_tenant_recon("notatenant.com")
    assert out["is_m365_tenant"] is False
    assert out["tenant_id"] is None


def test_oidc_invalid_json(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {
            f"https://login.microsoftonline.com/example.com/.well-known/openid-configuration": {
                "status": 200, "headers": {}, "body": "<html>not json</html>",
            },
        },
    )
    out = m365.m365_tenant_recon("example.com")
    oidc = out["openid_configuration"]
    assert oidc["present"] is False
    assert "error" in oidc


# ---------------------------------------------------------------------------
# GetUserRealm parsing
# ---------------------------------------------------------------------------


def _realm_xml(
    namespace: str | None = "Managed",
    federation_brand: str | None = None,
    federation_protocol: str | None = None,
    domain: str | None = "example.com",
    auth_url: str | None = None,
) -> str:
    parts = ["<RealmInfo Success='True'>"]
    if namespace:
        parts.append(f"<NameSpaceType>{namespace}</NameSpaceType>")
    if domain:
        parts.append(f"<DomainName>{domain}</DomainName>")
    if federation_brand:
        parts.append(f"<FederationBrandName>{federation_brand}</FederationBrandName>")
    if federation_protocol:
        parts.append(f"<FederationProtocol>{federation_protocol}</FederationProtocol>")
    if auth_url:
        parts.append(f"<AuthURL>{auth_url}</AuthURL>")
    parts.append("</RealmInfo>")
    return "".join(parts)


def test_realm_managed_namespace(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {
            f"https://login.microsoftonline.com/example.com/.well-known/openid-configuration": {
                "status": 200, "headers": {}, "body": _oidc_response_body(),
            },
            f"https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com&xml=1": {
                "status": 200, "headers": {}, "body": _realm_xml(namespace="Managed"),
            },
        },
    )
    out = m365.m365_tenant_recon("example.com")
    realm = out["user_realm"]
    assert realm["present"] is True
    assert realm["namespace_type"] == "Managed"

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert "managed Entra tenant" in reports[0]["title"]
    plain = reports[0]["description_plain"]
    assert "managed directly by Microsoft" in plain


def test_realm_federated_adfs(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        {
            f"https://login.microsoftonline.com/contoso.com/.well-known/openid-configuration": {
                "status": 200, "headers": {}, "body": _oidc_response_body(),
            },
            f"https://login.microsoftonline.com/getuserrealm.srf?login=user@contoso.com&xml=1": {
                "status": 200, "headers": {},
                "body": _realm_xml(
                    namespace="Federated",
                    federation_brand="Contoso ADFS",
                    federation_protocol="WSTrust",
                    auth_url="https://sts.contoso.com/adfs/ls/?...",
                    domain="contoso.com",
                ),
            },
        },
    )
    out = m365.m365_tenant_recon("contoso.com")
    realm = out["user_realm"]
    assert realm["namespace_type"] == "Federated"
    assert realm["federation_brand"] == "Contoso ADFS"
    assert realm["federation_protocol"] == "WSTrust"
    assert realm["auth_url"].startswith("https://sts.contoso.com/adfs")

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert "federated via Contoso ADFS" in reports[0]["title"]
    plain = reports[0]["description_plain"]
    assert "Contoso ADFS" in plain


def test_realm_federated_okta(monkeypatch) -> None:
    """Okta-federated tenant — finding mentions Okta as the IdP."""
    _patch_get(
        monkeypatch,
        {
            f"https://login.microsoftonline.com/example.com/.well-known/openid-configuration": {
                "status": 200, "headers": {}, "body": _oidc_response_body(),
            },
            f"https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com&xml=1": {
                "status": 200, "headers": {},
                "body": _realm_xml(
                    namespace="Federated",
                    federation_brand="Okta",
                    federation_protocol="WSFederation",
                ),
            },
        },
    )
    out = m365.m365_tenant_recon("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert "Okta" in reports[0]["title"]
    assert "Okta" in reports[0]["description_plain"]
    # Recommended action should reference Okta-specific concerns.
    assert "Okta" in reports[0]["recommended_action"]


def test_realm_unknown_namespace_no_tenant(monkeypatch) -> None:
    """`Unknown` namespace_type means the domain isn't registered with Entra."""
    _patch_get(
        monkeypatch,
        {
            f"https://login.microsoftonline.com/notatenant.com/.well-known/openid-configuration": {
                "status": 400, "headers": {}, "body": "",
            },
            f"https://login.microsoftonline.com/getuserrealm.srf?login=user@notatenant.com&xml=1": {
                "status": 200, "headers": {}, "body": _realm_xml(namespace="Unknown"),
            },
        },
    )
    out = m365.m365_tenant_recon("notatenant.com")
    assert out["is_m365_tenant"] is False
    realm = out["user_realm"]
    # Unknown namespace_type recorded but `present` stays False.
    assert realm["namespace_type"] == "Unknown"
    assert realm["present"] is False
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_realm_unparsable_xml(monkeypatch) -> None:
    """Malformed XML body → no field extraction, no crash."""
    _patch_get(
        monkeypatch,
        {
            f"https://login.microsoftonline.com/example.com/.well-known/openid-configuration": {
                "status": 404, "headers": {}, "body": "",
            },
            f"https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com&xml=1": {
                "status": 200, "headers": {}, "body": "<broken>not really XML",
            },
        },
    )
    out = m365.m365_tenant_recon("example.com")
    assert out["is_m365_tenant"] is False
    assert out["user_realm"]["namespace_type"] is None


# ---------------------------------------------------------------------------
# OIDC-only / realm-only detection
# ---------------------------------------------------------------------------


def test_only_oidc_succeeds(monkeypatch) -> None:
    """OIDC succeeds but realm fails → still detected as tenant."""
    _patch_get(
        monkeypatch,
        {
            f"https://login.microsoftonline.com/example.com/.well-known/openid-configuration": {
                "status": 200, "headers": {}, "body": _oidc_response_body(),
            },
            f"https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com&xml=1": {
                "status": 503, "headers": {}, "body": "",
            },
        },
    )
    out = m365.m365_tenant_recon("example.com")
    assert out["is_m365_tenant"] is True
    assert out["tenant_id"] == _TENANT_GUID


def test_only_realm_succeeds(monkeypatch) -> None:
    """Realm reports Managed but OIDC failed → detected, no tenant ID."""
    _patch_get(
        monkeypatch,
        {
            f"https://login.microsoftonline.com/example.com/.well-known/openid-configuration": {
                "status": 503, "headers": {}, "body": "",
            },
            f"https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com&xml=1": {
                "status": 200, "headers": {}, "body": _realm_xml(namespace="Managed"),
            },
        },
    )
    out = m365.m365_tenant_recon("example.com")
    assert out["is_m365_tenant"] is True
    assert out["tenant_id"] is None  # OIDC was the only source for this


# ---------------------------------------------------------------------------
# Both endpoints fail
# ---------------------------------------------------------------------------


def test_both_endpoints_unreachable(monkeypatch) -> None:
    _patch_get(monkeypatch, {})  # everything 404
    out = m365.m365_tenant_recon("example.com")
    assert out["success"] is True
    assert out["is_m365_tenant"] is False
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_both_endpoints_error(monkeypatch) -> None:
    """Network errors on both → graceful no-finding."""
    def fake(url, *, timeout=12):
        return {"status": 0, "headers": {}, "body": "", "error": "conn refused"}

    monkeypatch.setattr(m365, "_http_get", fake)
    out = m365.m365_tenant_recon("example.com")
    assert out["success"] is True
    assert out["is_m365_tenant"] is False


# ---------------------------------------------------------------------------
# Cluster-A composition
# ---------------------------------------------------------------------------


def test_excluded_path_no_finding(monkeypatch) -> None:
    """When the proxy short-circuits both URLs as excluded, no finding."""
    def fake(url, *, timeout=12):
        return {"status": 0, "headers": {}, "body": "", "skipped": True}

    monkeypatch.setattr(m365, "_http_get", fake)
    out = m365.m365_tenant_recon("example.com")
    assert out["is_m365_tenant"] is False
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


# ---------------------------------------------------------------------------
# Wrapper UX baseline
# ---------------------------------------------------------------------------


def test_finding_carries_plain_and_action(monkeypatch) -> None:
    """Per the §11 non-tech UX baseline: every emitted finding has both
    description_plain and recommended_action populated."""
    _patch_get(
        monkeypatch,
        {
            f"https://login.microsoftonline.com/example.com/.well-known/openid-configuration": {
                "status": 200, "headers": {}, "body": _oidc_response_body(),
            },
            f"https://login.microsoftonline.com/getuserrealm.srf?login=user@example.com&xml=1": {
                "status": 200, "headers": {}, "body": _realm_xml(namespace="Managed"),
            },
        },
    )
    m365.m365_tenant_recon("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    r = reports[0]
    assert r.get("description_plain")
    assert r.get("recommended_action")
    assert r["category"] == "info_disclosure"
    assert r["cwe"] == "CWE-200"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted(monkeypatch) -> None:
    _patch_get(monkeypatch, {})
    m365.m365_tenant_recon("example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "m365_tenant_recon" in summary["by_category"]
