"""Host-header injection / cache-key trust prober.

For a given URL, sends a baseline request and a small cohort of probes
that vary the host-routing headers to attacker-controlled values, then
inspects the response for reflection. Catches the classic primitives
behind:

- **Password-reset link poisoning** — when the app builds the reset URL
  from `Host:` / `X-Forwarded-Host:` and reflects it in the
  password-reset email or the post-submit response (CWE-20 / CWE-640).
- **Cache poisoning** — when an unauthenticated front-end cache keys on
  the URL but the back-end builds responses from `X-Forwarded-Host:`,
  letting an attacker poison the cache for every other user (CWE-444).
- **Open-redirect via host trust** — when 30x `Location` is built from
  a trusted-but-attacker-controlled host header.
- **Cookie-domain leak** — when `Set-Cookie` `Domain=` echoes the
  attacker host, scoping the user's cookie to attacker-controlled
  subdomains (CWE-1275-adjacent).

Probes (each is one HTTP request, all bounded by `timeout`):

| Probe | Mutation | Note |
|---|---|---|
| `host_replace`   | `Host: <attacker>`             | classic vhost trust check |
| `host_suffix`    | `Host: <target>.<attacker>`    | suffix-anchored allowlist bypass |
| `xfh`            | `X-Forwarded-Host: <attacker>` | CDN-reverse-proxy trust |
| `xfs`            | `X-Forwarded-Server: <attacker>` | rare but real; nginx/varnish-style trust |
| `x_host`         | `X-Host: <attacker>`           | non-standard but trusted by some frameworks |
| `forwarded`      | `Forwarded: host=<attacker>`   | RFC 7239 |
| `xforig`         | `X-Forwarded-For: <attacker>`  | weak signal but flagged when reflected |
| `dual_xfh`       | `X-Forwarded-Host: <attacker>` + `Host: <attacker>` | combined-header bypass |

Detection looks for the attacker hostname in:

- the response body (`description="reflected in body"`)
- the `Location` response header (high-severity — direct redirect-to-attacker)
- the `Set-Cookie` `Domain=` attribute (high-severity — cookie scoped to attacker)
- the response `Link` / `Content-Location` / `Refresh` headers

Severity tuning:
- **high** (CWE-20, CWE-444 / cache_poisoning) — reflection in `Location`
  header (clear redirect-to-attacker primitive) or in `Set-Cookie`
  `Domain=` (cookie leak scope).
- **medium** (CWE-20 / improper_input_validation) — reflection in
  response body (information_disclosure / building-the-link gadget; not
  necessarily exploitable on its own without follow-up).
- **low** (CWE-444 / cache_poisoning) — when a cached response (`Cache-
  Control: public` or `Age:` header present) returns a different body
  byte-length when X-Forwarded-Host varies, signaling cache-key
  obliviousness without explicit reflection.

Composes with cluster-A safety (auth-injection / exclude-path / rate-
limit) — every fetch routes through `proxy_manager.send_simple_request`
or the same env-driven http_safety on the direct fallback path. The
tool is read-only (GET only by default; HEAD is a no-op for body
reflection so we don't use it). Probe payloads are random per run so
findings are auditable without poisoning a real user's cache key.

Each finding carries `description_plain` and `recommended_action` (the
§11 non-tech-output fields) so the wrapper's dashboard renders specific
fix instructions per probe rather than just CWE numbers.
"""

from __future__ import annotations

import logging
import secrets
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "host_header_check"
_DEFAULT_TIMEOUT = 12.0
_DEFAULT_ATTACKER_DOMAIN = "attacker.example.com"

# Cap on bytes scanned for reflection. Bodies larger than this are
# truncated for the reflection scan only — full body capture stays
# bounded by the proxy layer.
_MAX_BODY_SCAN = 256 * 1024


# Headers we look at for reflection in the response. Lower-cased.
_REFLECTION_HEADERS_LOCATION = ("location", "content-location", "refresh", "link")
_REFLECTION_HEADERS_COOKIE = ("set-cookie",)
_REFLECTION_HEADERS_OTHER = ("x-original-host", "x-forwarded-host", "via")


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A safety composing)
# ---------------------------------------------------------------------------


def _http_get(
    url: str, *, headers: dict[str, str] | None = None, timeout: float = _DEFAULT_TIMEOUT
) -> dict[str, Any]:
    """GET via cluster-A safety. Returns {status, headers, body, error?, skipped?}.

    Tries the sandbox proxy_manager first so cluster-A middleware
    (auth-injection / exclude-path / rate-limit) is applied. Falls back
    to a direct httpx call (with the same middleware applied manually)
    when the proxy is unreachable — same fallback contract used by
    every other recon tool added since #50.
    """
    headers = dict(headers or {})
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, headers=headers, timeout=int(timeout))
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
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
        merged = inject_auth_headers(headers)
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_BODY_SCAN],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Target / probe shape
# ---------------------------------------------------------------------------


def _normalize_target(target: str) -> str | None:
    """Return canonical URL with explicit scheme. Default to https for
    bare hostnames."""
    if not target or not isinstance(target, str):
        return None
    target = target.strip()
    if not target:
        return None
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return target


def _target_host(url: str) -> str:
    return urlparse(url).hostname or ""


def _build_probes(target_url: str, attacker_host: str) -> list[dict[str, Any]]:
    """Produce the probe cohort.

    Each entry:
        {label, headers, severity_hint?, mutation_note}
    """
    target_host = _target_host(target_url)
    suffix_host = f"{target_host}.{attacker_host}" if target_host else attacker_host
    probes: list[dict[str, Any]] = [
        {
            "label": "host_replace",
            "headers": {"Host": attacker_host},
            "mutation_note": f"Host: {attacker_host}",
        },
        {
            "label": "host_suffix",
            "headers": {"Host": suffix_host},
            "mutation_note": f"Host: {suffix_host}",
        },
        {
            "label": "xfh",
            "headers": {"X-Forwarded-Host": attacker_host},
            "mutation_note": f"X-Forwarded-Host: {attacker_host}",
        },
        {
            "label": "xfs",
            "headers": {"X-Forwarded-Server": attacker_host},
            "mutation_note": f"X-Forwarded-Server: {attacker_host}",
        },
        {
            "label": "x_host",
            "headers": {"X-Host": attacker_host},
            "mutation_note": f"X-Host: {attacker_host}",
        },
        {
            "label": "forwarded",
            "headers": {"Forwarded": f"host={attacker_host}"},
            "mutation_note": f"Forwarded: host={attacker_host}",
        },
        {
            "label": "xforig",
            "headers": {"X-Forwarded-For": attacker_host},
            "mutation_note": f"X-Forwarded-For: {attacker_host}",
        },
        {
            "label": "dual_xfh",
            "headers": {
                "Host": attacker_host,
                "X-Forwarded-Host": attacker_host,
            },
            "mutation_note": f"Host + X-Forwarded-Host: {attacker_host}",
        },
    ]
    return probes


# ---------------------------------------------------------------------------
# Reflection detection
# ---------------------------------------------------------------------------


_COOKIE_DOMAIN_RE = re.compile(r"(?i)\bdomain\s*=\s*([^;\s]+)")


def _scan_reflection(
    response: dict[str, Any], attacker_host: str
) -> dict[str, Any]:
    """Look for the attacker host in body / location-class headers /
    cookie domain. Returns {body, location, cookie_domain, other_header}
    booleans + matched_field strings.
    """
    out: dict[str, Any] = {
        "body": False,
        "location_header": None,
        "cookie_domain_header": None,
        "other_header": None,
    }
    needle = attacker_host.lower()

    body = response.get("body") or ""
    if needle and needle in body.lower():
        out["body"] = True

    headers = response.get("headers") or {}
    for hname in _REFLECTION_HEADERS_LOCATION:
        value = headers.get(hname)
        if value and needle in value.lower():
            out["location_header"] = hname
            break

    for hname in _REFLECTION_HEADERS_COOKIE:
        value = headers.get(hname)
        if not value:
            continue
        # `Set-Cookie: foo=bar; Domain=evil.com; Path=/` — only flag
        # when the attacker host appears as the cookie Domain attribute,
        # not when it merely appears anywhere in the header (e.g. as
        # part of a session value).
        for m in _COOKIE_DOMAIN_RE.finditer(value):
            domain_val = m.group(1).lower().lstrip(".")
            if domain_val == needle or domain_val.endswith("." + needle) or needle.endswith("." + domain_val):
                out["cookie_domain_header"] = hname
                break
        if out["cookie_domain_header"]:
            break

    for hname in _REFLECTION_HEADERS_OTHER:
        value = headers.get(hname)
        if value and needle in value.lower():
            out["other_header"] = hname
            break

    return out


# ---------------------------------------------------------------------------
# Cache-poisoning heuristic
# ---------------------------------------------------------------------------


_CACHE_HEADERS = ("cache-control", "age", "x-cache", "cf-cache-status", "x-served-by")


def _looks_cached(headers: dict[str, str]) -> bool:
    """Heuristic — the response is cacheable / served from a cache."""
    cc = (headers.get("cache-control") or "").lower()
    if cc:
        # `private` / `no-store` / `no-cache` → not poisonable
        if "no-store" in cc or "private" in cc or "no-cache" in cc:
            return False
        if "public" in cc or "max-age" in cc or "s-maxage" in cc:
            return True
    if headers.get("age"):
        return True
    if headers.get("x-cache") or headers.get("cf-cache-status"):
        return True
    return False


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    cwe: str,
    category: str,
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
        category=category,
        cwe=cwe,
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "Attacker-controlled host headers reflected into Location / "
            "Set-Cookie / response body let an attacker poison "
            "password-reset email URLs (account takeover), poison "
            "front-end caches (mass-XSS / mass-redirect via a single "
            "cached response), and scope user cookies to attacker-"
            "controlled domains. Modern web frameworks default to "
            "trusting these headers when behind a reverse proxy; the "
            "fix is an explicit allow-list of known frontends."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
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
# Probe execution
# ---------------------------------------------------------------------------


def _evaluate_probe(
    probe: dict[str, Any],
    response: dict[str, Any],
    baseline: dict[str, Any],
    attacker_host: str,
) -> dict[str, Any]:
    """Inspect one probe response and return a verdict dict.

    Returns:
        {
            label, mutation_note, status, reflection: {...},
            cache_poison_signal: bool, finding_severity: str | None,
            finding_kind: str | None, evidence: str
        }
    """
    refl = _scan_reflection(response, attacker_host)

    # Cache-poison heuristic: response looks cached AND body length differs
    # materially from baseline. Bytes-comparison only — semantic diff
    # would require body parsing per content-type.
    cache_poison_signal = False
    baseline_len = len(baseline.get("body") or "")
    probe_len = len(response.get("body") or "")
    if (
        _looks_cached(response.get("headers") or {})
        and baseline_len > 0
        and abs(probe_len - baseline_len) > max(64, int(baseline_len * 0.05))
    ):
        cache_poison_signal = True

    severity: str | None = None
    kind: str | None = None
    evidence_parts: list[str] = []

    if refl.get("location_header"):
        severity = "high"
        kind = "location_reflection"
        evidence_parts.append(f"reflected in {refl['location_header']} header")
    elif refl.get("cookie_domain_header"):
        severity = "high"
        kind = "cookie_domain_reflection"
        evidence_parts.append(f"reflected in {refl['cookie_domain_header']} Domain= attribute")
    elif refl.get("body"):
        severity = "medium"
        kind = "body_reflection"
        evidence_parts.append("reflected in response body")
    elif cache_poison_signal:
        severity = "low"
        kind = "cache_poison_candidate"
        evidence_parts.append(
            f"cached response body length changed (baseline={baseline_len}, "
            f"probe={probe_len}) without explicit reflection"
        )
    elif refl.get("other_header"):
        # informational but not finding-worthy on its own — header echo
        # is sometimes intentional (Via, etc.). Recorded in the result
        # for the agent but not emitted as a finding.
        evidence_parts.append(f"echoed in {refl['other_header']} header (not finding-worthy)")

    return {
        "label": probe["label"],
        "mutation_note": probe["mutation_note"],
        "status": response.get("status", 0),
        "reflection": refl,
        "cache_poison_signal": cache_poison_signal,
        "finding_severity": severity,
        "finding_kind": kind,
        "evidence": "; ".join(evidence_parts),
    }


def _emit_for_verdict(
    verdict: dict[str, Any], target_url: str, target_host: str, attacker_host: str
) -> bool:
    """Emit the finding implied by a verdict. Returns True if emitted."""
    severity = verdict.get("finding_severity")
    kind = verdict.get("finding_kind")
    if not severity or not kind:
        return False

    label = verdict["label"]
    mutation = verdict["mutation_note"]
    evidence = verdict.get("evidence") or ""

    if kind == "location_reflection":
        title = f"Host-header injection — Location reflects attacker host on {target_host}"
        cwe = "CWE-20"
        category = "host_header_injection"
        description_plain = (
            "Your application trusts the value an attacker can put in the "
            "host headers and uses it to build redirects. An attacker can "
            "send a password-reset email to a victim where the reset link "
            "points at the attacker's server, giving them the victim's "
            "reset token."
        )
        recommended_action = (
            "Allow-list the host headers your application accepts. In nginx, "
            "validate `$host` against an explicit set; in Apache, use "
            "`<VirtualHost>` blocks with `ServerName` + `ServerAlias` and "
            "deny anything else. Application code that builds URLs (password "
            "reset, signup, OAuth callbacks) should use a configured base "
            "URL — never `request.host` / `req.headers.host` / "
            "`X-Forwarded-Host` directly."
        )
    elif kind == "cookie_domain_reflection":
        title = f"Host-header injection — Set-Cookie Domain reflects attacker host on {target_host}"
        cwe = "CWE-20"
        category = "host_header_injection"
        description_plain = (
            "Your application sets cookies whose `Domain=` attribute is "
            "built from a header an attacker can control. This scopes a "
            "victim's session cookie to attacker-controlled subdomains, "
            "letting them steal it."
        )
        recommended_action = (
            "Hard-code the cookie `Domain=` value (or omit it — defaults to "
            "the originating host). Never derive it from `Host:` / "
            "`X-Forwarded-Host:`. Allow-list trusted host headers at the "
            "reverse-proxy edge."
        )
    elif kind == "body_reflection":
        title = f"Host-header injection — attacker host reflected in body on {target_host}"
        cwe = "CWE-20"
        category = "host_header_injection"
        description_plain = (
            "Your application reflects the attacker-controlled host header "
            "into the response body. By itself this is information "
            "disclosure; combined with a follow-up flow that builds a link "
            "from the same field (password reset / signup / unsubscribe) "
            "it becomes account-takeover."
        )
        recommended_action = (
            "Audit every place the application reads `request.host` / "
            "`req.headers.host` / `X-Forwarded-Host` and replace with a "
            "configured base URL. Allow-list trusted host headers at the "
            "reverse-proxy edge so unexpected values never reach the app."
        )
    elif kind == "cache_poison_candidate":
        title = f"Possible cache-key obliviousness on {target_host} ({label})"
        cwe = "CWE-444"
        category = "cache_poisoning"
        description_plain = (
            "Your front-end cache caches responses by URL only, but the "
            "back-end builds different responses depending on a header an "
            "attacker can control. An attacker can poison the cache so "
            "every other user gets the attacker's response."
        )
        recommended_action = (
            "Either: (a) include the host-routing headers in the cache key "
            "(CDN-level — Cloudflare custom cache key, Fastly Vary), or "
            "(b) strip `X-Forwarded-Host` / `X-Forwarded-Server` / `Forwarded` "
            "at the cache edge before they reach the origin. Verify with "
            "`Vary:` headers + an end-to-end test."
        )
    else:
        return False

    description = (
        f"Probe `{label}` ({mutation}) → {evidence}. Attacker host used: "
        f"`{attacker_host}`."
    )
    _emit_finding(
        title=title,
        severity=severity,
        cwe=cwe,
        category=category,
        target=target_host,
        endpoint=target_url,
        description=description,
        description_plain=description_plain,
        recommended_action=recommended_action,
    )
    return True


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1659", "T1190"],  # Content Injection + Public-Facing App exploit
)
def host_header_check(
    target: str,
    timeout: float = _DEFAULT_TIMEOUT,
    attacker_host: str | None = None,
) -> dict[str, Any]:
    """Probe a URL for host-header injection / cache-key trust issues.

    Args:
        target: URL to probe. Bare hostnames are auto-prefixed with
            `https://`. Path component preserved (probes hit the same
            path as the baseline).
        timeout: Per-request timeout in seconds (default 12).
        attacker_host: Override the attacker host used in probes
            (default `attacker.example.com`). A unique random subdomain
            is appended to make every run's probes uniquely
            identifiable in the target's logs.

    Returns:
        {
          success, target_url, target_host, attacker_host,
          baseline: {status, body_length, has_location, looks_cached},
          probes: [
            {label, mutation_note, status, reflection, cache_poison_signal,
             finding_severity, finding_kind, evidence},
            ...
          ],
          findings_emitted: int
        }

    Findings:
        - **High** (CWE-20, host_header_injection) — reflection in
          `Location` header (password-reset link poisoning) or
          `Set-Cookie` `Domain=` (cookie scope leak).
        - **Medium** (CWE-20) — reflection in response body
          (information_disclosure / link-building gadget).
        - **Low** (CWE-444, cache_poisoning) — cached response with
          body-length variance under header mutation, no explicit
          reflection.

    Notes:
        - Read-only (GET only, no follow-redirects so reflected
          `Location` is observable).
        - Composes with cluster-A safety: `--exclude-path` / `--rate-limit`
          / `--auth-*` apply to every probe automatically.
        - Probe payload includes a random unique subdomain so findings
          are auditable and distinguishable from any pre-existing
          attacker-host references in the target's data.
    """
    target_url = _normalize_target(target)
    if not target_url:
        return {"success": False, "error": f"invalid target: {target!r}"}

    target_host = _target_host(target_url)
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {target!r}"}

    # Append a unique random tag so probe traffic in the target's logs
    # is auditable and distinguishable from any pre-existing references
    # to `attacker.example.com` (which is a frequently-used illustrative
    # value in docs / tests / hosts files).
    base_attacker = attacker_host or _DEFAULT_ATTACKER_DOMAIN
    nonce = secrets.token_hex(4)
    attacker = f"strix-{nonce}.{base_attacker}"

    cev = _start_check("host_header_injection", target_host)

    # ---- Baseline ----
    baseline_response = _http_get(target_url, headers={}, timeout=timeout)
    if baseline_response.get("skipped"):
        _complete_check(cev, "inconclusive", "baseline excluded by --exclude-path")
        return {
            "success": True,
            "target_url": target_url,
            "target_host": target_host,
            "attacker_host": attacker,
            "skipped": True,
            "skipped_reason": "baseline excluded by cluster-A path filter",
            "probes": [],
            "findings_emitted": 0,
        }
    if baseline_response.get("error") or baseline_response.get("status", 0) == 0:
        _complete_check(
            cev,
            "inconclusive",
            f"baseline unreachable: {baseline_response.get('error', 'no response')}",
        )
        return {
            "success": True,
            "target_url": target_url,
            "target_host": target_host,
            "attacker_host": attacker,
            "baseline": {
                "status": baseline_response.get("status", 0),
                "error": baseline_response.get("error"),
            },
            "probes": [],
            "findings_emitted": 0,
        }

    baseline_summary = {
        "status": baseline_response.get("status", 0),
        "body_length": len(baseline_response.get("body") or ""),
        "has_location": bool((baseline_response.get("headers") or {}).get("location")),
        "looks_cached": _looks_cached(baseline_response.get("headers") or {}),
    }

    # ---- Probe cohort ----
    findings_emitted = 0
    verdicts: list[dict[str, Any]] = []
    for probe in _build_probes(target_url, attacker):
        probe_response = _http_get(target_url, headers=probe["headers"], timeout=timeout)
        if probe_response.get("skipped"):
            verdicts.append({
                "label": probe["label"],
                "mutation_note": probe["mutation_note"],
                "status": 0,
                "reflection": {},
                "cache_poison_signal": False,
                "finding_severity": None,
                "finding_kind": None,
                "evidence": "skipped by cluster-A path filter",
            })
            continue
        verdict = _evaluate_probe(probe, probe_response, baseline_response, attacker)
        verdicts.append(verdict)
        if _emit_for_verdict(verdict, target_url, target_host, attacker):
            findings_emitted += 1

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{findings_emitted} host-header issue(s) on {target_host}",
    )

    return {
        "success": True,
        "target_url": target_url,
        "target_host": target_host,
        "attacker_host": attacker,
        "baseline": baseline_summary,
        "probes": verdicts,
        "findings_emitted": findings_emitted,
    }
