"""Netlify project-config rules (`netlify.toml`) — Phase 11.3."""

from __future__ import annotations

import re

from strix.iac.parsers.base import PLATFORM_NETLIFY, IacFile
from strix.iac.rules import IacFinding, register_rule


# Same secret regex set used in vercel_rules.
_SECRET_LIKE = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(r"AIza[A-Za-z0-9_-]{35}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY"),
]


def _line_for(raw: str, needle: str) -> int:
    if not raw or not needle:
        return 0
    idx = raw.find(needle)
    return raw[:idx].count("\n") + 1 if idx >= 0 else 0


@register_rule(platform=PLATFORM_NETLIFY)
def netlify_redirect_external_wildcard(iac: IacFile) -> list[IacFinding]:
    """`[[redirects]]` with a splat capture forwarded to an
    external URL — open redirect."""
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    for entry in (iac.data.get("redirects") or []):
        if not isinstance(entry, dict):
            continue
        to = (entry.get("to") or "").strip()
        if (to.startswith("http://") or to.startswith("https://")) \
                and (":splat" in to or ":id" in to or "*" in to):
            out.append(IacFinding(
                rule_id="netlify-redirect-external-wildcard",
                file=iac.path,
                line=_line_for(iac.raw_text, to),
                severity="medium",
                message=(
                    f"Netlify redirect `to = \"{to}\"` includes "
                    f"a captured value in an external URL. Open "
                    f"redirect: anyone hitting the matching path "
                    f"gets bounced to an attacker-controlled "
                    f"host. Use a relative path or validate the "
                    f"captured value against an allowlist."
                ),
                cwe="CWE-601",
                category="open_redirect",
                platform=iac.platform,
            ))
    return out


@register_rule(platform=PLATFORM_NETLIFY)
def netlify_build_env_hardcoded_secret(iac: IacFile) -> list[IacFinding]:
    """`[build.environment]` (or `[context.*.environment]`) with
    a literal secret-shaped value. Netlify build env is logged in
    build output and viewable by anyone with repo read."""
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    sources: list[tuple[str, dict]] = []
    build = iac.data.get("build")
    if isinstance(build, dict) and isinstance(build.get("environment"), dict):
        sources.append(("build.environment", build["environment"]))
    contexts = iac.data.get("context")
    if isinstance(contexts, dict):
        for ctx_name, ctx_cfg in contexts.items():
            if isinstance(ctx_cfg, dict) and \
                    isinstance(ctx_cfg.get("environment"), dict):
                sources.append((f"context.{ctx_name}.environment",
                                ctx_cfg["environment"]))
    for prefix, env_dict in sources:
        for key, value in env_dict.items():
            if not isinstance(value, str):
                continue
            for pat in _SECRET_LIKE:
                if pat.search(value):
                    out.append(IacFinding(
                        rule_id="netlify-build-env-hardcoded-secret",
                        file=iac.path,
                        line=_line_for(iac.raw_text, key),
                        severity="critical",
                        message=(
                            f"Netlify `{prefix}.{key}` has a "
                            f"value matching a known secret "
                            f"pattern. Build env values are "
                            f"viewable by anyone with repo read "
                            f"AND end up in build logs. Move to "
                            f"the Netlify dashboard's Site "
                            f"settings → Build & deploy → "
                            f"Environment. Rotate the value if "
                            f"this file has been pushed."
                        ),
                        cwe="CWE-798",
                        category="info_disclosure",
                        platform=iac.platform,
                        metadata={"env_key": key},
                    ))
                    break
    return out


@register_rule(platform=PLATFORM_NETLIFY)
def netlify_headers_force_basic_auth_disabled(iac: IacFile) -> list[IacFinding]:
    """`[[headers]]` removes default security headers — explicit
    deletion of `X-Frame-Options` or `Content-Security-Policy`
    is suspicious. Netlify defaults are reasonable; overriding
    them is usually a mistake."""
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    for entry in (iac.data.get("headers") or []):
        if not isinstance(entry, dict):
            continue
        values = entry.get("values") or {}
        if not isinstance(values, dict):
            continue
        for header_name, value in values.items():
            if not isinstance(value, str):
                continue
            normalised = (header_name or "").lower()
            if normalised == "content-security-policy" and \
                    ("unsafe-inline" in value or "unsafe-eval" in value):
                out.append(IacFinding(
                    rule_id="netlify-csp-unsafe-inline-or-eval",
                    file=iac.path,
                    line=_line_for(iac.raw_text, value[:40]),
                    severity="medium",
                    message=(
                        f"Netlify CSP includes `unsafe-inline` "
                        f"or `unsafe-eval`. AI-generated CSP "
                        f"often whitelists these to make "
                        f"third-party widgets work — but they "
                        f"defeat CSP's XSS protection entirely. "
                        f"Use nonces or strict-dynamic instead."
                    ),
                    cwe="CWE-1004",
                    category="misconfig",
                    platform=iac.platform,
                    metadata={"header": "Content-Security-Policy",
                              "value": value[:200]},
                ))
            elif normalised == "access-control-allow-origin" and value == "*":
                # Check sibling header for credentials.
                creds = values.get("Access-Control-Allow-Credentials") or \
                        values.get("access-control-allow-credentials") or ""
                if creds.lower() in ("true", "1"):
                    out.append(IacFinding(
                        rule_id="netlify-cors-wildcard-with-credentials",
                        file=iac.path,
                        line=_line_for(iac.raw_text, '"*"'),
                        severity="high",
                        message=(
                            "Netlify headers entry sets "
                            "`Access-Control-Allow-Origin: *` "
                            "AND `Access-Control-Allow-"
                            "Credentials: true`. Browsers reject "
                            "this combo — the usual 'fix' is "
                            "reflecting the Origin header, which "
                            "IS exploitable. Whitelist origins."
                        ),
                        cwe="CWE-1004",
                        category="misconfig",
                        platform=iac.platform,
                    ))
    return out
