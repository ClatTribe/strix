"""iter-37.3 — Deprecation registry for in-house tools superseded by OSS.

Per docs/tool-catalog-rationalization.md the in-house `scan_*` /
`*_check` family is being retired in favor of OSS engines (nuclei,
sqlmap, semgrep, trivy, etc.). This module is the central registry
of every deprecated tool + its OSS replacement.

Deprecated tools still EXECUTE successfully — calling code (sandbox
tool-server / tests / legacy mode) won't break. They emit a warning
to logs + the tracer's events stream so the migration is visible.

Schedule:
  * iter-37.2 (shipped) — hide from L2 Lead's catalog (default)
  * iter-37.3 (this iter) — warn on invocation
  * iter-37.4 — add new OSS wrappers (smuggler.py, SAML Raider, hydra,
    mobsfscan, ffuf, schemathesis)
  * iter-37.5 — DELETE the deprecated tools after grace period
"""

from __future__ import annotations

import logging
from typing import Final


logger = logging.getLogger(__name__)


# Map: deprecated tool name → replacement (either an OSS-wrapper tool
# name OR a string describing the OSS engine + nuclei tag to use).
#
# When the format is "tool_name", the executor logs:
#   "Tool 'X' is deprecated — use 'tool_name' instead"
#
# When the format includes a comma (e.g. "scan_nuclei_templates, tags:sqli"),
# the executor logs the full hint so the LLM can route properly.
_DEPRECATIONS: Final[dict[str, str]] = {
    # === Injection family — route through nuclei templates or sqlmap ===
    "scan_sqli": "scan_sqli_sqlmap (sqlmap — deeper exploit + dump)",
    "sqli_check": "scan_sqli_sqlmap (sqlmap)",
    "scan_xss": "scan_xss_dalfox (dalfox — more accurate XSS detection)",
    "dom_xss_static_probe": "scan_nuclei_templates with tags:xss + scan_xss_dalfox",
    "scan_ssrf": "scan_nuclei_templates with tags:ssrf",
    "scan_blind_ssrf": "scan_nuclei_templates with tags:blind-ssrf",
    "scan_xxe": "scan_nuclei_templates with tags:xxe",
    "scan_oob_xxe": "scan_nuclei_templates with tags:xxe,oob",
    "scan_cmd_injection": "scan_nuclei_templates with tags:cmdi,rce",
    "scan_blind_cmd_injection": "scan_nuclei_templates with tags:blind-cmdi",
    "scan_path_traversal": "scan_nuclei_templates with tags:lfi,traversal",
    "scan_nosql_injection": "scan_nuclei_templates with tags:nosqli",
    "scan_ldap_injection": "scan_nuclei_templates with tags:ldap",
    "scan_xpath_injection": "scan_nuclei_templates with tags:xpath",
    "scan_ssti": "scan_nuclei_templates with tags:ssti",
    "scan_deserialization": "scan_nuclei_templates with tags:deserialization",

    # === Anomaly / misconfig — nuclei templates cover these ===
    "scan_misconfig": "scan_nuclei_templates with tags:misconfig",
    "scan_response_anomaly": "scan_nuclei_templates with tags:default-login,exposure",
    "scan_secrets_in_response": "scan_nuclei_templates with tags:exposure,token-spray,secrets",

    # === Web-specific specialists — nuclei templates ===
    "scan_websocket_auth": "scan_nuclei_templates with tags:websocket",
    "scan_cache_deception": "scan_nuclei_templates with tags:cache-deception,cache-poisoning",
    "scan_prototype_pollution": "scan_nuclei_templates with tags:prototype-pollution",
    "scan_request_smuggling_active": "scan_nuclei_templates with tags:smuggling (also iter-37.4 will add smuggler.py wrapper)",
    "request_smuggling_check": "scan_nuclei_templates with tags:smuggling",
    "scan_race_condition": "scan_nuclei_templates with tags:race-condition",
    "race_condition_check": "scan_nuclei_templates with tags:race-condition",

    # === Headers / CORS / CSRF — nuclei templates ===
    "cors_deep_check": "scan_nuclei_templates with tags:cors",
    "csrf_check": "scan_nuclei_templates with tags:csrf",
    "open_redirect_check": "scan_nuclei_templates with tags:redirect",
    "host_header_check": "scan_nuclei_templates with tags:host-header",
    "method_tamper_check": "scan_nuclei_templates with tags:http-method",
    "debug_endpoint_check": "scan_nuclei_templates with tags:debug,disclosure",
    "file_upload_abuse_check": "scan_nuclei_templates with tags:fileupload",
    "csv_injection_check": "scan_nuclei_templates with tags:csv-injection",
    "cache_deception_check": "scan_nuclei_templates with tags:cache-deception",
    "cookie_jwt_scoping_check": "scan_nuclei_templates with tags:cookie,jwt",
    "session_entropy_check": "scan_nuclei_templates with tags:session-fixation",

    # === Auth / OIDC / SAML / OAuth ===
    "scan_authn_metadata": "scan_nuclei_templates with tags:oidc,oauth,well-known",
    "scan_oauth": "scan_nuclei_templates with tags:oauth",
    "scan_saml_xsw": "scan_nuclei_templates with tags:saml (also iter-37.4 adds SAML Raider wrapper)",

    # === API-shaped specialists ===
    "scan_api_rate_limit": "scan_nuclei_templates with tags:rate-limit",
    "scan_api_grpc_reflection": "scan_nuclei_templates with tags:grpc",
    "scan_api_bola": "scan_idor (session-aware authz — merged)",
    "scan_api_bfla": "scan_idor (session-aware authz — merged)",
    "scan_api_mass_assignment": "scan_idor (session-aware authz — merged)",
    "scan_multi_role_auth": "scan_idor (now handles multi-role internally)",

    # === DNS / domain ===
    "dns_hygiene_check": "scan_dns_hygiene_checkdmarc (checkdmarc — SPF/DKIM/DMARC)",
    "subdomain_takeover_check": "scan_nuclei_templates with tags:takeover",
    "scan_subdomain_takeover_active": "scan_nuclei_templates with tags:takeover",

    # === Cloud / IMDS ===
    "scan_cloud_imds_passthrough": "scan_nuclei_templates with tags:imds,cloud",
    "kev_diff_check": "query_threat_intel (unified threat-intel lookup)",
    "monitoring_posture_check": "scan_nuclei_templates with tags:headers",
    "mfa_attestation_check": "scan_nuclei_templates with tags:mfa + scan_authn_metadata",

    # === Credential / breach ===
    "hibp_breach_check": "scan_credential_leaks_hibp (already HIBP API wrapper)",

    # === GraphQL ===
    "graphql_specialist_check": "map_graphql_inql (InQL — proper introspection)",
}


def is_deprecated(tool_name: str) -> bool:
    """True when calling `tool_name` should emit a deprecation warning."""
    return tool_name in _DEPRECATIONS


def get_replacement(tool_name: str) -> str | None:
    """Return the OSS replacement hint, or None if not deprecated."""
    return _DEPRECATIONS.get(tool_name)


def emit_deprecation_warning(tool_name: str) -> None:
    """Log a deprecation warning for the given tool. Called by the
    executor / tool-server on every invocation of a deprecated tool.

    The warning includes the recommended OSS replacement so the LLM
    can route subsequent calls correctly (when the warning surfaces
    in the agent's reasoning_trace via the tracer).
    """
    replacement = _DEPRECATIONS.get(tool_name)
    if replacement is None:
        return
    logger.warning(
        "iter-37.3 deprecation: tool %r is deprecated and scheduled "
        "for removal. Use %s instead. See docs/tool-catalog-"
        "rationalization.md.",
        tool_name, replacement,
    )


__all__ = [
    "is_deprecated",
    "get_replacement",
    "emit_deprecation_warning",
]
