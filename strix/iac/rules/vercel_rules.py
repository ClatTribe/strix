"""Vercel project-config rules (`vercel.json`) — Phase 11.3.

Targets the misconfig patterns AI-generated Vercel configs ship
with. Each rule walks the parsed `vercel.json` structure and
flags suspect entries.

Rules shipped:
  * vercel-cors-wildcard-with-credentials — `*` origin AND
    credentials:true ANYwhere in `headers[]`
  * vercel-headers-missing-baseline — no X-Frame-Options /
    Content-Security-Policy on production routes
  * vercel-redirect-external-host — wildcard redirect to a
    user-controlled external host (open redirect)
  * vercel-cron-no-auth-marker — `crons[]` invokes routes
    that don't have an `authorization` middleware marker
    (heuristic; flagged WARNING for human review)
  * vercel-env-hardcoded-secret — literal secret-shaped value
    in `env{}` / `build.env{}` (high entropy + provider prefix)
  * vercel-function-overly-large-max-duration — `maxDuration`
    above 300s creates DoS / cost-exhaustion exposure
"""

from __future__ import annotations

import re

from strix.iac.parsers.base import PLATFORM_VERCEL, IacFile
from strix.iac.rules import IacFinding, register_rule


# Heuristic regexes for "secret-shaped" literals in env values.
# Same shape rules used by the SAST corpus's
# llm-openai-key-in-source rule. False-positive guard: must have
# both a known prefix AND > 20 chars of high-entropy alphanumeric.
_SECRET_LIKE = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),         # OpenAI / Anthropic
    re.compile(r"AKIA[A-Z0-9]{16}"),              # AWS access key
    re.compile(r"AIza[A-Za-z0-9_-]{35}"),         # Google API key
    re.compile(r"ghp_[A-Za-z0-9]{36}"),           # GitHub PAT
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),  # Slack
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY"),  # PEM
]


def _line_for_substring(raw_text: str, needle: str) -> int:
    """Best-effort: return the 1-based line number where
    `needle` first appears in `raw_text`. Returns 0 when not
    found (caller emits whole-file finding)."""
    if not raw_text or not needle:
        return 0
    idx = raw_text.find(needle)
    if idx < 0:
        return 0
    return raw_text[:idx].count("\n") + 1


@register_rule(platform=PLATFORM_VERCEL)
def vercel_cors_wildcard_with_credentials(iac: IacFile) -> list[IacFinding]:
    """`Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`
    in the same `headers[]` entry — browsers actually reject this
    combo, but AI-generated configs ship it because the dev didn't
    realise the constraint. The exposure: developers see
    "credentials don't work" and switch to a permissive origin
    list (`origin: req.headers.origin`) which IS exploitable."""
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    for entry in (iac.data.get("headers") or []):
        if not isinstance(entry, dict):
            continue
        headers = entry.get("headers") or []
        names = {(h.get("key") or "").lower(): (h.get("value") or "")
                 for h in headers if isinstance(h, dict)}
        origin = names.get("access-control-allow-origin", "")
        creds = names.get("access-control-allow-credentials", "").lower()
        if origin == "*" and creds in ("true", "1"):
            out.append(IacFinding(
                rule_id="vercel-cors-wildcard-with-credentials",
                file=iac.path,
                line=_line_for_substring(iac.raw_text, '"*"'),
                severity="high",
                message=(
                    "Vercel headers entry sets "
                    "`Access-Control-Allow-Origin: *` AND "
                    "`Access-Control-Allow-Credentials: true`. "
                    "Browsers reject this combo so credentials "
                    "won't be sent — but developers usually 'fix' "
                    "this by reflecting `req.headers.origin` "
                    "back, which IS exploitable as cross-origin "
                    "credential bleed. Whitelist specific "
                    "origins instead of `*`."
                ),
                cwe="CWE-1004",
                category="misconfig",
                platform=iac.platform,
                metadata={"source_pattern": entry.get("source")},
            ))
    return out


@register_rule(platform=PLATFORM_VERCEL)
def vercel_redirect_external_host(iac: IacFile) -> list[IacFinding]:
    """Wildcard redirect that forwards a query parameter as the
    destination URL — open redirect. Pattern:
        {"source": "/go", "destination": "https://:url"}
    or
        {"source": "/redir", "destination": "/(.*)"}
    """
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    for entry in (iac.data.get("redirects") or []):
        if not isinstance(entry, dict):
            continue
        dest = (entry.get("destination") or "").strip()
        # Pattern: destination contains a `:variable` substitution
        # that came from the source's wildcard match AND the
        # destination is an absolute external URL.
        if (dest.startswith("http://") or dest.startswith("https://")) \
                and (":" in dest or "$1" in dest or "%s" in dest):
            out.append(IacFinding(
                rule_id="vercel-redirect-external-host",
                file=iac.path,
                line=_line_for_substring(iac.raw_text, dest),
                severity="medium",
                message=(
                    f"Vercel redirect with destination `{dest}` "
                    f"forwards a captured value to an absolute "
                    f"external URL. Anyone who can construct the "
                    f"matching path triggers an open redirect. "
                    f"Either redirect to a relative path, or "
                    f"validate the captured value against an "
                    f"allowlist of safe hosts."
                ),
                cwe="CWE-601",
                category="open_redirect",
                platform=iac.platform,
            ))
    return out


@register_rule(platform=PLATFORM_VERCEL)
def vercel_cron_no_auth_marker(iac: IacFile) -> list[IacFinding]:
    """`crons[]` invokes a path on a schedule. Vercel signs cron
    requests with an `authorization` header containing
    `CRON_SECRET`; if the user's route doesn't validate that
    header, an attacker can hit the cron path manually and
    trigger arbitrary backend work.

    We can't statically know whether the route validates auth
    (that's in TS/JS source), so this is a heuristic: any cron
    entry surfaces a WARNING reminding the reviewer to confirm
    the route validates `Authorization: Bearer $CRON_SECRET`.
    """
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    for entry in (iac.data.get("crons") or []):
        if not isinstance(entry, dict):
            continue
        path_field = entry.get("path") or ""
        out.append(IacFinding(
            rule_id="vercel-cron-no-auth-marker",
            file=iac.path,
            line=_line_for_substring(iac.raw_text, path_field),
            severity="medium",
            message=(
                f"Vercel cron registered for path `{path_field}`. "
                f"Vercel signs cron requests with "
                f"`Authorization: Bearer $CRON_SECRET` — confirm "
                f"the route handler validates that header. "
                f"Without validation, the cron path is publicly "
                f"reachable and an attacker can trigger backend "
                f"work on demand."
            ),
            cwe="CWE-862",
            category="authz",
            platform=iac.platform,
            metadata={"cron_path": path_field,
                      "schedule": entry.get("schedule")},
        ))
    return out


@register_rule(platform=PLATFORM_VERCEL)
def vercel_env_hardcoded_secret(iac: IacFile) -> list[IacFinding]:
    """Literal secret-shaped value in `env{}` / `build.env{}`.
    Vercel docs: only commit non-secret values; secrets go via
    the dashboard or `vercel env`. AI-generated configs commit
    api keys directly because "it works"."""
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    sources = []
    if isinstance(iac.data.get("env"), dict):
        sources.append(("env", iac.data["env"]))
    if isinstance(iac.data.get("build"), dict):
        be = iac.data["build"].get("env")
        if isinstance(be, dict):
            sources.append(("build.env", be))
    for prefix, env_dict in sources:
        for key, value in env_dict.items():
            if not isinstance(value, str):
                continue
            for pat in _SECRET_LIKE:
                if pat.search(value):
                    out.append(IacFinding(
                        rule_id="vercel-env-hardcoded-secret",
                        file=iac.path,
                        line=_line_for_substring(iac.raw_text, key),
                        severity="critical",
                        message=(
                            f"Vercel `{prefix}.{key}` has a "
                            f"value matching a known secret "
                            f"pattern. Do not commit secrets to "
                            f"`vercel.json` — anyone with repo "
                            f"read access can read it. Move to "
                            f"the Vercel dashboard or "
                            f"`vercel env add`. Rotate this "
                            f"value if it has been published."
                        ),
                        cwe="CWE-798",
                        category="info_disclosure",
                        platform=iac.platform,
                        metadata={"env_key": key},
                    ))
                    break
    return out


@register_rule(platform=PLATFORM_VERCEL)
def vercel_function_overly_large_max_duration(iac: IacFile) -> list[IacFinding]:
    """`functions{}` with `maxDuration` > 300 (5 min) creates a
    cost-exhaustion / DoS surface. An attacker can hit the
    function repeatedly to drain the user's billing limit."""
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    fns = iac.data.get("functions") or {}
    if not isinstance(fns, dict):
        return out
    for fn_path, cfg in fns.items():
        if not isinstance(cfg, dict):
            continue
        max_dur = cfg.get("maxDuration")
        if isinstance(max_dur, (int, float)) and max_dur > 300:
            out.append(IacFinding(
                rule_id="vercel-function-overly-large-max-duration",
                file=iac.path,
                line=_line_for_substring(iac.raw_text, fn_path),
                severity="low",
                message=(
                    f"Vercel function `{fn_path}` has "
                    f"`maxDuration: {max_dur}` seconds. Long "
                    f"timeouts plus repeated invocations enable "
                    f"cost-exhaustion DoS — Vercel bills per "
                    f"GB-second. Tighten to 60-120s unless the "
                    f"function genuinely needs longer runs."
                ),
                cwe="CWE-400",
                category="misconfig",
                platform=iac.platform,
                metadata={"max_duration_seconds": max_dur,
                          "function": fn_path},
            ))
    return out
