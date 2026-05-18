"""Canonical-CWE report templates — step 7 of the v2 cost-
optimization plan (docs/proposals/2026-05-19-scan-mode-cost-
optimization.md, workflow phase 7 — report).

## Why this exists

When the agent emits a finding via `create_vulnerability_report`,
it has to fill in a long list of fields: title, description,
impact, technical_analysis, poc_description, poc_script_code,
remediation_steps, plus the optional layer (recommended_action,
fix_time_estimate, business_impact_plain, etc.). For well-known
vulnerability classes (OWASP Top 10, the CWE-89 / CWE-79 / etc.
canonical set), most of that text is boilerplate.

This module ships a per-CWE template of stable boilerplate
fields. When a finding's CWE matches a registered template,
the missing fields are auto-filled at emit time. **The agent's
explicit values always win** — templates only fill what the
agent left blank. That's the recall-safety contract: we never
overwrite a value the agent thought was worth writing.

## What gets templated

Only the boilerplate-shaped fields:
  * `recommended_action` — one-line imperative ("Switch to
    parameterized queries.")
  * `fix_time_estimate` — rough engineering effort
  * `business_impact_plain` — plain-English impact summary

Fields the agent MUST fill (technical_analysis, poc_*, etc.) are
never auto-populated — those are finding-specific by definition.

## What we DON'T template

  * `remediation_steps` — the long-form developer guidance. We
    don't auto-fill this because remediation depends on the
    target's stack (Django ORM vs raw psycopg2 vs Prisma) and a
    template that's right on one stack is wrong on another. The
    agent still writes this.
  * `description` / `impact` / `technical_analysis` — finding-
    specific.

## Kill switch

`STRIX_CWE_TEMPLATES_DISABLED=1` bypasses every template. No
fields are auto-filled. Useful for runs where the agent's prose
needs to be the canonical record (compliance / audit submission
where any auto-fill would muddy the provenance trail).
"""

from __future__ import annotations

import os
import re
from typing import Any


# Per-CWE template dict. Keys are CWE-id strings ("CWE-89");
# values are dicts of stable boilerplate fields to auto-fill
# when the agent's emission left them blank.
#
# Coverage is OWASP Top 10 + the reasoning-bound categories
# (BOLA / mass assignment / business logic) plus the
# auth / crypto / SSRF / XXE classics. Adding a new template:
# pick a CWE that appears in `benchmarks/per_target/fixtures/**/
# expected.yaml`, write the three fields, keep each under 200
# chars so the templates stay legible inside finding JSON.
_TEMPLATES: dict[str, dict[str, str]] = {
    "CWE-89": {
        "recommended_action": (
            "Switch to parameterized queries / prepared statements. "
            "Never concatenate user input into SQL."
        ),
        "fix_time_estimate": "1-4 hours per affected endpoint",
        "business_impact_plain": (
            "An attacker can read or modify any data your database "
            "holds without authentication. Customer records, payment "
            "details, and credentials are at risk."
        ),
    },
    "CWE-79": {
        "recommended_action": (
            "Context-aware output encoding at every sink (HTML body, "
            "attribute, JS string, URL). Set a strict Content Security "
            "Policy as defence in depth."
        ),
        "fix_time_estimate": "2-8 hours per affected sink",
        "business_impact_plain": (
            "An attacker can run arbitrary JavaScript in any victim's "
            "browser when they visit the affected page — steal session "
            "cookies, perform actions as the victim, or pivot to internal "
            "tools the victim can access."
        ),
    },
    "CWE-78": {
        "recommended_action": (
            "Replace shell invocations with library calls. When shell-out "
            "is unavoidable, use argument arrays (not strings) and an "
            "allow-list of expected values."
        ),
        "fix_time_estimate": "4-8 hours per affected handler",
        "business_impact_plain": (
            "An attacker can run any command on the server with the "
            "application's privileges — typically full server compromise, "
            "data exfiltration, and lateral movement into the internal "
            "network."
        ),
    },
    "CWE-94": {
        "recommended_action": (
            "Remove the dynamic-code path entirely; treat user input as "
            "data, never as code. If unavoidable, use a sandbox + strict "
            "allow-list."
        ),
        "fix_time_estimate": "1-3 days",
        "business_impact_plain": (
            "An attacker can execute arbitrary application code on the "
            "server — full server compromise."
        ),
    },
    "CWE-22": {
        "recommended_action": (
            "Resolve user-supplied paths against a fixed base directory + "
            "reject any resolved path that escapes the base. Never "
            "concatenate user input into a file path."
        ),
        "fix_time_estimate": "1-4 hours per affected handler",
        "business_impact_plain": (
            "An attacker can read or write any file the application "
            "process can access — config files, credentials, source code, "
            "or arbitrary data."
        ),
    },
    "CWE-918": {
        "recommended_action": (
            "Allow-list of explicit destination hosts. Reject any URL "
            "that doesn't resolve to an approved IP after DNS resolution. "
            "Block requests to RFC 1918 / link-local / loopback ranges."
        ),
        "fix_time_estimate": "1-2 days",
        "business_impact_plain": (
            "An attacker can make your server probe internal resources — "
            "cloud metadata endpoints, internal admin tools, or arbitrary "
            "third-party hosts under your IP reputation."
        ),
    },
    "CWE-502": {
        "recommended_action": (
            "Replace native deserialization (pickle, ObjectInputStream, "
            "etc.) with a structured format like JSON. If deserialization "
            "is required, integrity-protect the payload with HMAC."
        ),
        "fix_time_estimate": "1-3 days",
        "business_impact_plain": (
            "An attacker can run arbitrary code on the server by crafting "
            "a malicious serialized payload — full server compromise."
        ),
    },
    "CWE-352": {
        "recommended_action": (
            "Require an anti-CSRF token on every state-changing request, "
            "plus enforce `SameSite=Lax` (or stricter) on session cookies."
        ),
        "fix_time_estimate": "4-8 hours",
        "business_impact_plain": (
            "An attacker's website can trigger actions in your application "
            "while a victim is logged in — fund transfers, password "
            "changes, privilege escalations done as the victim."
        ),
    },
    "CWE-639": {
        "recommended_action": (
            "Authorize every object access against the authenticated "
            "principal at the handler level. Never trust a client-supplied "
            "owner id; resolve ownership server-side from the session."
        ),
        "fix_time_estimate": "1-2 days per affected resource type",
        "business_impact_plain": (
            "Any authenticated user can read or modify any other user's "
            "data by changing an id in the URL — cross-tenant data leak."
        ),
    },
    "CWE-862": {
        "recommended_action": (
            "Add an authorization check at the handler level. Default-deny "
            "policy: require an explicit allow rule for every action."
        ),
        "fix_time_estimate": "4-12 hours per affected endpoint",
        "business_impact_plain": (
            "Unauthenticated or low-privilege users can reach actions "
            "intended for admins — privilege escalation, sensitive data "
            "access, destructive operations."
        ),
    },
    "CWE-863": {
        "recommended_action": (
            "Tighten the authorization check to compare the requesting "
            "principal against the resource's owner / tenant, not just "
            "verify presence of a role token."
        ),
        "fix_time_estimate": "1-2 days",
        "business_impact_plain": (
            "Authenticated users can act on resources outside their own "
            "scope — cross-tenant data access or modification."
        ),
    },
    "CWE-915": {
        "recommended_action": (
            "Allow-list the fields the user is permitted to set on each "
            "resource. Reject (don't silently drop) any unknown or "
            "privileged field in the request body."
        ),
        "fix_time_estimate": "1-2 days per affected resource type",
        "business_impact_plain": (
            "A normal user can promote themselves to admin (or alter any "
            "other privileged attribute) by adding fields to a profile "
            "update request."
        ),
    },
    "CWE-200": {
        "recommended_action": (
            "Remove the sensitive data from the response or stamp it as "
            "internal-only. Strip stack traces, version banners, and "
            "debug headers from production responses."
        ),
        "fix_time_estimate": "2-8 hours",
        "business_impact_plain": (
            "Implementation details are exposed to attackers, making it "
            "easier to identify vulnerable components and craft targeted "
            "exploits."
        ),
    },
    "CWE-347": {
        "recommended_action": (
            "Verify the SAML / JWT / etc. signature against the IdP's "
            "current key set on EVERY message. Reject when the signature "
            "is absent, malformed, or doesn't cover the assertion subject."
        ),
        "fix_time_estimate": "1-3 days",
        "business_impact_plain": (
            "An attacker can forge identity assertions and log in as any "
            "user without their password — full authentication bypass."
        ),
    },
    "CWE-601": {
        "recommended_action": (
            "Resolve user-supplied redirect targets against an allow-list "
            "of internal paths. Never redirect to an attacker-controllable "
            "URL."
        ),
        "fix_time_estimate": "1-4 hours per affected handler",
        "business_impact_plain": (
            "Attackers can craft links that appear to point to your "
            "domain but actually send victims to phishing sites — credential "
            "theft via your brand's trust."
        ),
    },
    "CWE-611": {
        "recommended_action": (
            "Disable external entity processing in every XML parser. For "
            "libxml2 / etree, set `resolve_entities=False`; for Java, "
            "set `FEATURE_SECURE_PROCESSING` + disable DOCTYPE."
        ),
        "fix_time_estimate": "1 day",
        "business_impact_plain": (
            "An attacker can read local files, probe internal services, "
            "and in some configurations achieve remote code execution by "
            "submitting a malicious XML document."
        ),
    },
    "CWE-1336": {
        "recommended_action": (
            "Stop rendering user input as a template. If the template "
            "engine MUST process user content, run it in a sandboxed "
            "subset (Jinja2 SandboxedEnvironment, etc.)."
        ),
        "fix_time_estimate": "1-2 days",
        "business_impact_plain": (
            "An attacker can execute server-side code by injecting "
            "template syntax — typically full server compromise."
        ),
    },
    "CWE-798": {
        "recommended_action": (
            "Remove the hardcoded secret. Load it from a secrets manager "
            "(AWS Secrets Manager / Vault / etc.) or a runtime-injected "
            "env var, never from source."
        ),
        "fix_time_estimate": "2-4 hours + secret rotation",
        "business_impact_plain": (
            "Anyone with access to the repository can authenticate as "
            "the application — credential theft scales with the secret's "
            "permissions."
        ),
    },
    "CWE-287": {
        "recommended_action": (
            "Tighten the authentication check on every protected handler. "
            "Default-deny: require a valid session / token, not just "
            "absence of a logout marker."
        ),
        "fix_time_estimate": "1-2 days",
        "business_impact_plain": (
            "Attackers can access protected functionality without valid "
            "credentials — privilege escalation or unauthenticated access "
            "to sensitive data."
        ),
    },
    "CWE-770": {
        "recommended_action": (
            "Add per-principal rate-limiting at the handler or gateway "
            "level. Token-bucket per IP + per account, with sensible "
            "defaults (e.g. 60 req/min)."
        ),
        "fix_time_estimate": "4-8 hours",
        "business_impact_plain": (
            "An attacker can exhaust the service by repeated requests — "
            "denial of service or runaway costs on metered backends."
        ),
    },
    "CWE-307": {
        "recommended_action": (
            "Add exponential-backoff lockout after N failed authentication "
            "attempts (typical N = 5-10) per account AND per source IP."
        ),
        "fix_time_estimate": "1 day",
        "business_impact_plain": (
            "Attackers can brute-force passwords or tokens against the "
            "login endpoint with no friction — account takeover at scale."
        ),
    },
}


_CWE_NORMALIZE_RE = re.compile(r"\bCWE[-_\s]*(\d+)\b", re.IGNORECASE)


def _normalize_cwe(cwe: str | None) -> str:
    """Normalize a CWE string to canonical `CWE-NNN` form.
    Accepts `cwe-89`, `CWE89`, `CWE 89`, `cwe_89`, plain `89` if
    paired with a CWE prefix nearby. Returns empty string when
    no CWE id can be extracted."""
    if not isinstance(cwe, str):
        return ""
    m = _CWE_NORMALIZE_RE.search(cwe)
    if not m:
        # Tolerate plain numeric input (e.g. "89")
        bare = cwe.strip()
        if bare.isdigit():
            return f"CWE-{bare}"
        return ""
    return f"CWE-{m.group(1)}"


def is_disabled() -> bool:
    """Returns True when `STRIX_CWE_TEMPLATES_DISABLED` is truthy.
    Default is enabled."""
    return os.environ.get(
        "STRIX_CWE_TEMPLATES_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def template_for(cwe: str | None) -> dict[str, str] | None:
    """Lookup the canonical template for a CWE. Returns None when
    no template is registered or the kill switch is on."""
    if is_disabled():
        return None
    norm = _normalize_cwe(cwe)
    if not norm:
        return None
    return _TEMPLATES.get(norm)


def list_templated_cwes() -> list[str]:
    """Return the CWEs with a registered template (for telemetry +
    tests)."""
    return sorted(_TEMPLATES.keys())


def auto_fill_missing_fields(
    *,
    cwe: str | None,
    recommended_action: str | None,
    fix_time_estimate: str | None,
    business_impact_plain: str | None,
) -> dict[str, Any]:
    """Apply the per-CWE template to fill any fields the caller
    left as None / empty string. The caller's explicit values
    ALWAYS win — auto-fill only touches missing fields.

    Returns a dict with the (possibly filled) field values plus
    a `template_applied` flag the caller can surface in
    telemetry.
    """
    out: dict[str, Any] = {
        "recommended_action": recommended_action,
        "fix_time_estimate": fix_time_estimate,
        "business_impact_plain": business_impact_plain,
        "template_applied": False,
        "template_cwe": None,
    }
    tpl = template_for(cwe)
    if tpl is None:
        return out
    out["template_cwe"] = _normalize_cwe(cwe)
    filled_any = False
    for key in ("recommended_action", "fix_time_estimate", "business_impact_plain"):
        if out[key] in (None, "") and key in tpl:
            out[key] = tpl[key]
            filled_any = True
    out["template_applied"] = filled_any
    return out
