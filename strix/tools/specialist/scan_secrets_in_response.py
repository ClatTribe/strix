"""`scan_secrets_in_response` — passive HTTP-response secrets sniffer
(workitem.md Phase 2.5).

Closes CWE-200 / CWE-798. The most common high-impact mistake in
modern web apps is shipping a credential to the browser by accident —
NEXT_PUBLIC env vars, exposed admin tokens in JSON debug responses,
JWT signing keys hot-leaked in stack traces.

Detection strategy
------------------

Iterate a list of URLs (typically populated by recon or
SecurityContext.list_endpoints). For each URL, GET the response and
match the body + headers against a curated regex set:

  * **AWS access keys**          — `AKIA[0-9A-Z]{16}` + secret key
                                   shape `[A-Za-z0-9/+=]{40}`
  * **Google API keys**          — `AIza[0-9A-Za-z_-]{35}`
  * **GitHub tokens**            — `ghp_[A-Za-z0-9]{36}`,
                                   `gho_[A-Za-z0-9]{36}`,
                                   `ghs_[A-Za-z0-9]{36}`
  * **Slack tokens**             — `xox[abprs]-[0-9A-Za-z-]{10,}`
  * **Stripe keys**              — `(sk|rk)_(live|test)_[A-Za-z0-9]{24,}`
  * **Generic JWT**              — `eyJ[A-Za-z0-9_-]+\\.eyJ[...]\\.[...]`
  * **Private key blocks**       — `-----BEGIN (RSA |EC )?PRIVATE KEY-----`
  * **DB connection strings**    — `(mongodb|postgres|mysql|redis)://[^@]+@[^/]+`
  * **Generic api_key/password** — JSON literals with sensitive
                                   keys (`api_key`, `secret`, `token`,
                                   `password`) and high-entropy values

Each hit emits a CWE-798 (or CWE-200 for generic exposure) finding.
Severity:
  * **Critical** — AWS / GCP / Stripe / private-key / connection
    string with credentials.
  * **High** — JWT with `alg!=none`, signed access tokens.
  * **Medium** — generic api_key-named field, low-entropy "secret".

Compared to scan_misconfig (which already detects a few well-known
endpoints), this specialist is **per-URL passive** — caller hands it a
list of URLs and it does pure HTTP+regex with no probing payloads.
That makes it cheap enough to run against every endpoint
SecurityContext recorded.
"""

from __future__ import annotations

import logging
import math
import re
from typing import Any

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# (label, regex, cwe, severity, description)
_PATTERNS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "aws_access_key_id",
        r"\bAKIA[0-9A-Z]{16}\b",
        "CWE-798",
        "critical",
        "AWS access key ID",
    ),
    (
        "aws_secret_access_key",
        # Heuristic — only flag when paired with `aws_secret` context.
        r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"'\s:=]+[\"']?([A-Za-z0-9/+=]{40})[\"']?",
        "CWE-798",
        "critical",
        "AWS secret access key",
    ),
    (
        "google_api_key",
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        "CWE-798",
        "critical",
        "Google API key",
    ),
    (
        "github_pat",
        r"\bgh[posu]_[A-Za-z0-9]{36,255}\b",
        "CWE-798",
        "critical",
        "GitHub personal access / OAuth / server token",
    ),
    (
        "slack_token",
        r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b",
        "CWE-798",
        "critical",
        "Slack token",
    ),
    (
        "stripe_key",
        r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b",
        "CWE-798",
        "critical",
        "Stripe API key",
    ),
    (
        "private_key_block",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        "CWE-798",
        "critical",
        "Private key block",
    ),
    (
        "jwt",
        # Match standard 3-segment JWT shape (header.payload.sig)
        # with the well-known `eyJ` base64-encoded `{` prefix.
        r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "CWE-200",
        "high",
        "JSON Web Token",
    ),
    (
        "mongodb_conn_string",
        r"\bmongodb(?:\+srv)?://[^\s\"'<>]+:[^\s\"'<>@]+@[^\s\"'<>/]+",
        "CWE-798",
        "critical",
        "MongoDB connection string with credentials",
    ),
    (
        "postgres_conn_string",
        r"\bpostgres(?:ql)?://[^\s\"'<>]+:[^\s\"'<>@]+@[^\s\"'<>/]+",
        "CWE-798",
        "critical",
        "Postgres connection string with credentials",
    ),
    (
        "mysql_conn_string",
        r"\bmysql://[^\s\"'<>]+:[^\s\"'<>@]+@[^\s\"'<>/]+",
        "CWE-798",
        "critical",
        "MySQL connection string with credentials",
    ),
    (
        "redis_conn_string",
        r"\bredis://[^:\s\"'<>]+:[^\s\"'<>@]+@[^\s\"'<>/]+",
        "CWE-798",
        "high",
        "Redis connection string with credentials",
    ),
    (
        "generic_secret_field",
        # Generic secret-shaped JSON field name + value.
        r"(?i)\"(?:api[_-]?key|secret(?:_key)?|password|token|access[_-]?token|"
        r"client[_-]?secret|private[_-]?key)\"\s*:\s*\"([^\"\s]{16,})\"",
        "CWE-200",
        "high",
        "Generic secret-named field with high-entropy value",
    ),
)


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per char. Real secrets land
    around 4.0+ bits; words land around 2.5-3.5; placeholder strings
    (`xxxxxxxx`, `your_key_here`) below 2.0."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_likely_placeholder(value: str) -> bool:
    """Filter obvious placeholders to suppress noise."""
    v = value.lower()
    placeholders = (
        "your_", "example_", "placeholder", "redacted", "xxxx",
        "todo", "fixme", "changeme", "<your", "{{", "***", "demo",
        "test", "sample",
    )
    return any(p in v for p in placeholders)


def _emit_finding(
    *,
    url: str,
    label: str,
    description_label: str,
    excerpt: str,
    severity: str,
    cwe: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        return tracer.add_vulnerability_report(
            title=f"{description_label} exposed in HTTP response",
            severity=severity,
            cwe=cwe,
            endpoint=url,
            target=url,
            category="secrets_exposure",
            verification_status="verified",
            confidence=0.95,
            description=(
                f"GET request to `{url}` returned a response body or "
                f"header that contains a {description_label} matching "
                f"the `{label}` pattern. The credential is reachable "
                f"by any client that can request this URL — including "
                f"unauthenticated browsers when the URL is public."
            ),
            impact=(
                "Hard-coded credentials / secrets exposure.\n"
                "  * AWS keys → full account compromise (S3, EC2, IAM "
                "    pivot).\n"
                "  * GitHub tokens → source-code exfil + CI/CD "
                "    poisoning.\n"
                "  * Stripe keys → payment-flow tampering, "
                "    chargebacks.\n"
                "  * Database connection strings → direct DB access "
                "    bypassing the application layer entirely.\n"
                "  * JWT signing secrets → forge tokens for any "
                "    user.\n"
                "  * Private key blocks → impersonate the service in "
                "    TLS, code signing, SSH access."
            ),
            technical_analysis=(
                f"Endpoint: {url}\n"
                f"Pattern matched: {label}\n"
                f"Excerpt:\n{excerpt[:1200]}"
            ),
            poc_description=(
                f"1. GET {url}\n"
                f"2. Inspect the response — credential is in plain "
                f"text inside the body or headers.\n"
                f"3. Validate the credential is live by hitting the "
                f"corresponding API (e.g. `aws sts get-caller-identity` "
                f"with the captured key)."
            ),
            poc_script_code=f"curl -sS '{url}' | head -c 2000",
            remediation_steps=(
                "1. Rotate the exposed credential IMMEDIATELY. Once a "
                "secret has been served from a public URL, assume it's "
                "indexed and compromised.\n"
                "2. Audit how the secret got into the response: "
                "    * `NEXT_PUBLIC_*` env-var prefix (Next.js) — only "
                "      use for non-secret config.\n"
                "    * Debug routes left in production (`/_admin/`, "
                "      `/_debug/env`, `/.env.json`).\n"
                "    * Stack traces leaking from a server-side error "
                "      (turn off debug mode in prod).\n"
                "    * Source maps shipping with secrets baked in.\n"
                "3. Move secret loading to server-side only. Never "
                "embed in client bundles.\n"
                "4. Add a CI check (`gitleaks` / `trufflehog`) that "
                "fails the build when these patterns appear in any "
                "client-shipped artifact."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S": "C", "C": "H", "I": "H", "A": "H",
            },
            reasoning_trace=[
                f"GET {url}",
                f"Response matched secret pattern {label}.",
                f"Credential is reachable via the public URL.",
            ],
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_secrets_in_response: emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="secrets-exposure-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 90},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1552"],
)
def scan_secrets_in_response(
    *,
    urls: list[str] | str | None = None,
    url: str | None = None,
    extra_headers: dict[str, str] | None = None,
    max_urls: int = 50,
    min_entropy_for_generic: float = 3.5,
) -> SpecialistResult:
    """Passive scanner: fetch each URL, regex-match the response for
    well-known credential patterns + emit findings.

    Args:
        urls: list of URLs to fetch. When None / empty, the scanner
            falls back to URLs recorded in `SecurityContext.endpoints`.
        url: convenience alias for a single URL.
        extra_headers: forwarded as-is on every request.
        max_urls: cap to prevent runaway fetches; defaults to 50.
        min_entropy_for_generic: entropy threshold for the
            `generic_secret_field` pattern. Real secrets pass; words
            and placeholders fall below.

    Auto-emits one finding per (url, pattern_label) pair.
    """
    # Forgiving args.
    if url and not urls:
        urls = [url]
    if isinstance(urls, str):
        urls = [urls]

    if not urls:
        # Fall back to SecurityContext-recorded endpoints.
        try:
            from strix.agents.security_context import (
                get_security_context, list_endpoints,
            )
            ctx = get_security_context()
            base = ctx.target_url
            urls = []
            if base:
                for ep in list_endpoints():
                    # Naive composition; sufficient for passive sniffing.
                    urls.append(base.rstrip("/") + "/" + ep.path.lstrip("/"))
        except Exception:  # noqa: BLE001
            pass

    if not urls:
        return SpecialistResult(
            status="partial",
            error="no URLs supplied",
            evidence=[
                "scan_secrets_in_response invoked with no urls; "
                "supply `urls=[...]` or `url=...`. Caller may also "
                "rely on SecurityContext.list_endpoints when the "
                "lead has previously recorded discovery."
            ],
        )

    urls = list(urls)[:max_urls]

    # Auto-include captured auth so authenticated routes are sniffed.
    extra_headers = dict(extra_headers or {})
    if "Authorization" not in extra_headers and "authorization" not in {
        h.lower() for h in extra_headers
    }:
        try:
            from strix.agents.security_context import list_auth_states
            for state in list_auth_states():
                if state.bearer:
                    extra_headers["Authorization"] = f"Bearer {state.bearer}"
                    break
                if state.cookies:
                    extra_headers["Cookie"] = "; ".join(
                        f"{k}={v}" for k, v in state.cookies.items()
                    )
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

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    fetch_count = 0
    seen_findings: set[tuple[str, str]] = set()  # (url, label)

    compiled = [
        (label, re.compile(pattern, re.MULTILINE), cwe, severity, description)
        for label, pattern, cwe, severity, description in _PATTERNS
    ]

    for u in urls:
        if not isinstance(u, str) or not u.strip():
            continue
        u = u.strip()
        try:
            resp = pm.send_simple_request(
                "GET", u,
                headers=extra_headers, body="", timeout=15,
            )
            fetch_count += 1
        except Exception as e:  # noqa: BLE001
            evidence.append(f"transport error for {u}: {e}")
            continue
        if "error" in resp and not resp.get("status_code"):
            continue
        body = resp.get("body") or ""
        if not isinstance(body, str):
            body = ""
        # Combine headers + body for matching — secrets sometimes
        # leak through Set-Cookie or custom debug headers.
        headers_blob = ""
        try:
            for k, v in (resp.get("headers") or {}).items():
                headers_blob += f"{k}: {v}\n"
        except Exception:  # noqa: BLE001
            pass
        haystack = body + "\n" + headers_blob

        for label, regex, cwe, severity, description in compiled:
            for m in regex.finditer(haystack):
                key = (u, label)
                if key in seen_findings:
                    continue
                # Extract matched secret (group 1 if any, else full match).
                matched = m.group(1) if m.groups() else m.group(0)
                if _is_likely_placeholder(matched):
                    continue
                # Generic-secret entropy gate.
                if label == "generic_secret_field":
                    if _shannon_entropy(matched) < min_entropy_for_generic:
                        continue
                seen_findings.add(key)
                start = max(0, m.start() - 80)
                end = min(len(haystack), m.end() + 80)
                # Mask the actual secret in the excerpt to avoid
                # echoing it back in our own logs / decision trail.
                excerpt = haystack[start:end].replace(matched, "***REDACTED***")
                rid = _emit_finding(
                    url=u, label=label, description_label=description,
                    excerpt=excerpt, severity=severity, cwe=cwe,
                )
                if rid:
                    emitted_count += 1
                drafts.append(FindingDraft(
                    title=f"{description} in HTTP response from `{u}`",
                    severity=severity, cwe=cwe,
                    endpoint=u, category="secrets_exposure",
                    verification_status="verified", confidence=0.95,
                    description=f"Pattern: {label}",
                ))
                evidence.append(f"secret leaked at {u}: pattern={label}")

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        for u in urls:
            record_endpoint(u, method="GET", probed_for="secrets_exposure")
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=urls[0] if urls else None,
            actor={"tool_name": "scan_secrets_in_response"},
            input={"urls_count": len(urls), "fetches_done": fetch_count},
            output={"findings_emitted": emitted_count, "drafts": len(drafts)},
        )
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            ["confirm credentials are live: try `aws sts get-caller-identity` / "
             "`gh auth status` / decode and inspect JWT — scope of compromise"]
            if drafts else
            ["no secrets in response bodies of supplied URLs; consider "
             "fetching JS bundles (`/static/js/main.*.js`), source maps, "
             "and `/_next/static/chunks/*` — secrets often hide in "
             "compiled client bundles"]
        ),
        tool_metadata={
            "fetches_done": fetch_count,
            "urls_attempted": len(urls),
            "findings_emitted_to_tracer": emitted_count,
            "patterns_checked": len(_PATTERNS),
        },
    )
