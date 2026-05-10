"""Cloudflare Workers / Pages config rules (`wrangler.toml`)
— Phase 11.3."""

from __future__ import annotations

import re

from strix.iac.parsers.base import PLATFORM_CLOUDFLARE, IacFile
from strix.iac.rules import IacFinding, register_rule


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


@register_rule(platform=PLATFORM_CLOUDFLARE)
def cloudflare_vars_hardcoded_secret(iac: IacFile) -> list[IacFinding]:
    """`[vars]` table has secret-shaped values. Cloudflare's
    docs explicitly say `[vars]` is for non-secrets; secrets go
    via `wrangler secret put` to the encrypted `[secrets]` table.
    AI-generated wrangler configs commit API keys directly
    because the IDE doesn't lint the difference."""
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    vars_section = iac.data.get("vars")
    if not isinstance(vars_section, dict):
        return out
    for key, value in vars_section.items():
        if not isinstance(value, str):
            continue
        for pat in _SECRET_LIKE:
            if pat.search(value):
                out.append(IacFinding(
                    rule_id="cloudflare-vars-hardcoded-secret",
                    file=iac.path,
                    line=_line_for(iac.raw_text, key),
                    severity="critical",
                    message=(
                        f"Cloudflare `[vars].{key}` has a "
                        f"secret-shaped literal. `[vars]` is "
                        f"unencrypted plaintext readable by "
                        f"anyone with repo access. Move to "
                        f"encrypted secrets via "
                        f"`wrangler secret put {key}`."
                    ),
                    cwe="CWE-798",
                    category="info_disclosure",
                    platform=iac.platform,
                    metadata={"var_key": key},
                ))
                break
    return out


@register_rule(platform=PLATFORM_CLOUDFLARE)
def cloudflare_r2_bucket_public(iac: IacFile) -> list[IacFinding]:
    """`[[r2_buckets]]` with a `bucket_name` whose binding
    suggests public-read intent — heuristic: binding name
    contains `public` / `public_assets` / `cdn`. Cloudflare
    R2's public access is configured at the bucket-policy
    level, not in wrangler — but a binding called `PUBLIC_R2`
    is a strong signal the dev intends public read access.
    Surface for review."""
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    for entry in (iac.data.get("r2_buckets") or []):
        if not isinstance(entry, dict):
            continue
        binding = (entry.get("binding") or "").lower()
        bucket = entry.get("bucket_name") or ""
        if any(token in binding for token in
               ("public", "cdn", "open", "anon")):
            out.append(IacFinding(
                rule_id="cloudflare-r2-public-binding",
                file=iac.path,
                line=_line_for(iac.raw_text, bucket),
                severity="medium",
                message=(
                    f"R2 bucket binding `{binding}` suggests "
                    f"intentional public access. Confirm the "
                    f"bucket policy doesn't expose data the "
                    f"app considers private. Public R2 buckets "
                    f"have been the source of multiple "
                    f"production data leaks — the binding name "
                    f"is the only static signal we have to "
                    f"surface this for review."
                ),
                cwe="CWE-732",
                category="misconfig",
                platform=iac.platform,
                metadata={"binding": binding, "bucket": bucket},
            ))
    return out


@register_rule(platform=PLATFORM_CLOUDFLARE)
def cloudflare_route_wildcard_pattern(iac: IacFile) -> list[IacFinding]:
    """Worker `routes` with overly-broad wildcard patterns. A
    pattern like `*/*` or `example.com/*` runs the worker on
    EVERY route — including ones the dev didn't intend (the
    admin panel, the auth callback, etc.). Subtle vibe-coded
    misconfig: dev wanted a worker on `/api/*`, copied an
    example with `/*`."""
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    routes = iac.data.get("routes") or []
    if not isinstance(routes, list):
        return out
    for route in routes:
        # Routes can be strings or objects.
        if isinstance(route, str):
            pattern = route
        elif isinstance(route, dict):
            pattern = route.get("pattern") or ""
        else:
            continue
        if not pattern:
            continue
        # Catch-all patterns: ends with /* AND has only the host
        # before it; OR is literally `*/*`.
        normalised = pattern.strip().rstrip("/")
        if normalised == "*" or normalised == "*/*":
            sev = "high"
            msg = (
                f"Cloudflare worker route `{pattern}` is a global "
                f"catch-all — the worker runs on EVERY request "
                f"to your zone. Almost always unintended; restrict "
                f"to the specific paths the worker should handle."
            )
        elif normalised.endswith("/*") and "/" not in normalised[:-2]:
            sev = "low"
            msg = (
                f"Cloudflare worker route `{pattern}` matches the "
                f"entire host. Confirm the worker is intentionally "
                f"running on every path, not just `/api/*`."
            )
        else:
            continue
        out.append(IacFinding(
            rule_id="cloudflare-route-overly-broad",
            file=iac.path,
            line=_line_for(iac.raw_text, pattern),
            severity=sev,
            message=msg,
            cwe="CWE-732",
            category="misconfig",
            platform=iac.platform,
            metadata={"pattern": pattern},
        ))
    return out


@register_rule(platform=PLATFORM_CLOUDFLARE)
def cloudflare_kv_no_preview_id(iac: IacFile) -> list[IacFinding]:
    """`[[kv_namespaces]]` without `preview_id` means the local
    `wrangler dev` session shares production KV. Devs running
    integration tests against `wrangler dev` will hit production
    data. Sub-critical but real misconfig."""
    out: list[IacFinding] = []
    if not isinstance(iac.data, dict):
        return out
    for entry in (iac.data.get("kv_namespaces") or []):
        if not isinstance(entry, dict):
            continue
        if entry.get("id") and not entry.get("preview_id"):
            binding = entry.get("binding") or ""
            out.append(IacFinding(
                rule_id="cloudflare-kv-no-preview-id",
                file=iac.path,
                line=_line_for(iac.raw_text, binding),
                severity="low",
                message=(
                    f"KV namespace binding `{binding}` has no "
                    f"`preview_id`. `wrangler dev` will share "
                    f"the production KV — running integration "
                    f"tests can mutate live data. Add a "
                    f"`preview_id` for a separate dev namespace."
                ),
                cwe="CWE-732",
                category="misconfig",
                platform=iac.platform,
                metadata={"binding": binding},
            ))
    return out
