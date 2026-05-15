"""Web cache deception prober.

Detects whether a target's CDN / front-end cache will cache
authenticated responses when the URL is suffixed with a
static-asset-shaped extension or path-traversal-style delimiter. The
classic web-cache-deception vector (Omer Gil, 2017): origin treats
`/account/x.css` the same as `/account` (returns the authenticated
page) but the CDN sees a `.css` URL and caches it indefinitely → an
attacker who has the victim browse a single attacker-prepared link
later reads the cached response anonymously and harvests the victim's
authenticated content.

Methodology (single pass per scan, no cross-session comparison
required because auth-injection from `--auth-*` flags is applied
automatically by `proxy_manager.send_simple_request`):

1. **Baseline** — fetch the canonical authenticated path. Capture
   status, body, body-length, body-hash, and cacheability verdict.
2. **Variant cohort** — for each of ~15 deception-shaped variants,
   fetch with the same auth and inspect:
   - Is the response status 200?
   - Does the response body match the baseline body (length within
     5% AND a normalized-token Jaccard similarity ≥ 0.85)?
   - Is the response cacheable (Cache-Control: public / max-age set
     without no-store / private / no-cache; OR X-Cache / Age /
     CF-Cache-Status headers present)?

Variants (each is one HTTP request, all bounded by `timeout`):

| Variant | Mutation | Class |
|---|---|---|
| `dot_css`        | `<path>.css`         | static-extension confusion |
| `dot_js`         | `<path>.js`          | static-extension confusion |
| `dot_png`        | `<path>.png`         | static-extension confusion |
| `dot_jpg`        | `<path>.jpg`         | static-extension confusion |
| `dot_ico`        | `<path>.ico`         | static-extension confusion |
| `slash_x_css`    | `<path>/x.css`       | delimiter path-traversal |
| `slash_dot_css`  | `<path>/.css`        | delimiter path-traversal |
| `semicolon_css`  | `<path>;.css`        | matrix-URI / Java/Tomcat |
| `semicolon_x_css`| `<path>;x.css`       | matrix-URI variant |
| `null_css`       | `<path>%00.css`      | null-byte truncation |
| `cr_css`         | `<path>%0d.css`      | CR truncation |
| `hash_css`       | `<path>%23.css`      | URL-fragment trick |
| `query_css`      | `<path>?x=.css`      | query-string trick (some caches strip query) |
| `enc_slash_css`  | `<path>%2fx.css`     | encoded-slash path-traversal |
| `double_slash`   | `<path>//x.css`      | path-normalization confusion |

Severity tuning:

- **High** (CWE-525, web_cache_deception) — body fuzzy-matches
  baseline AND response is cacheable. Both conditions present =
  exploitable; an attacker can poison the cache with a victim's
  authed response.
- **Medium** (CWE-525) — body fuzzy-matches baseline but cacheability
  is ambiguous (no explicit Cache-Control / X-Cache, but also no
  no-store / private). Real-world CDNs default-cache static-extension
  responses absent explicit no-store.
- *(no finding)* — body differs materially from baseline (origin
  correctly distinguishes the static-extension path from the dynamic
  one) OR the variant returns 4xx / redirect / error.

Skip / soft-fail conditions:

- Baseline returns non-200 (the canonical path doesn't actually
  return authed content; nothing to cache-deceive).
- Baseline body is tiny (< 80 bytes) — too short for a meaningful
  fuzzy-match; would false-positive on identical small error bodies.
- Variant URL is filtered by `--exclude-path` (returns gracefully).

Composes with cluster-A safety (auth-injection / exclude-path /
rate-limit) automatically — every fetch routes through
`proxy_manager.send_simple_request` or the direct fallback that uses
the same env-driven `http_safety` middleware.

Each finding carries `description_plain` + `recommended_action` (the
§11 non-tech-output fields) so the wrapper renders specific fix
instructions per cache-deception class (CDN cache-key configuration,
strip-extension-before-routing, Cache-Control: no-store on dynamic
endpoints).
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "cache_deception_check"
_DEFAULT_TIMEOUT = 12.0
_MAX_BODY_SCAN = 256 * 1024
_MIN_BODY_BYTES_FOR_MATCH = 80
_BODY_LEN_TOLERANCE_PCT = 5.0  # ±5% length match
_TOKEN_JACCARD_THRESHOLD = 0.85


# Cache headers we read for the cacheability verdict.
_CACHE_HIT_HEADERS = ("x-cache", "cf-cache-status", "x-served-by", "age")


# Rough word-token regex — used for the body-similarity Jaccard.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]{3,}")


# ---------------------------------------------------------------------------
# HTTP fetch — cluster-A composing
# ---------------------------------------------------------------------------


def _http_get(
    url: str, *, headers: dict[str, str] | None = None, timeout: float = _DEFAULT_TIMEOUT
) -> dict[str, Any]:
    """GET via cluster-A safety. Returns {status, headers, body, error?, skipped?}."""
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
# Target / variant generation
# ---------------------------------------------------------------------------


def _normalize_target(target: str) -> str | None:
    """Return canonical URL with explicit scheme. Default to https for
    bare hostnames. Keep a path component if present."""
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


def _build_variants(target_url: str) -> list[dict[str, str]]:
    """Generate the deception-shaped variants for a URL.

    Each entry: `{label, url, mutation_note, class_}`.
    """
    parsed = urlparse(target_url)
    raw_path = parsed.path or "/"
    # Strip trailing slash for a stable concat anchor (we'll re-introduce
    # for the explicit variants that need it).
    if raw_path.endswith("/") and raw_path != "/":
        anchor = raw_path.rstrip("/")
    else:
        anchor = raw_path

    def _u(new_path: str, *, append_query: str | None = None) -> str:
        # Variants don't carry the original query string by default —
        # the cache-deception primitive is path-shaped, not query-shaped.
        # The `query_css` variant explicitly adds a synthetic query.
        return urlunparse((
            parsed.scheme, parsed.netloc, new_path,
            parsed.params, append_query or "", "",
        ))

    variants: list[dict[str, str]] = [
        {"label": "dot_css", "url": _u(f"{anchor}.css"),
         "mutation_note": f"path → {anchor}.css", "class_": "static_ext"},
        {"label": "dot_js", "url": _u(f"{anchor}.js"),
         "mutation_note": f"path → {anchor}.js", "class_": "static_ext"},
        {"label": "dot_png", "url": _u(f"{anchor}.png"),
         "mutation_note": f"path → {anchor}.png", "class_": "static_ext"},
        {"label": "dot_jpg", "url": _u(f"{anchor}.jpg"),
         "mutation_note": f"path → {anchor}.jpg", "class_": "static_ext"},
        {"label": "dot_ico", "url": _u(f"{anchor}.ico"),
         "mutation_note": f"path → {anchor}.ico", "class_": "static_ext"},
        {"label": "slash_x_css", "url": _u(f"{anchor}/x.css"),
         "mutation_note": f"path → {anchor}/x.css", "class_": "delim_traversal"},
        {"label": "slash_dot_css", "url": _u(f"{anchor}/.css"),
         "mutation_note": f"path → {anchor}/.css", "class_": "delim_traversal"},
        {"label": "semicolon_css", "url": _u(f"{anchor};.css"),
         "mutation_note": f"path → {anchor};.css", "class_": "matrix_uri"},
        {"label": "semicolon_x_css", "url": _u(f"{anchor};x.css"),
         "mutation_note": f"path → {anchor};x.css", "class_": "matrix_uri"},
        {"label": "null_css", "url": _u(f"{anchor}%00.css"),
         "mutation_note": f"path → {anchor}%00.css", "class_": "byte_truncation"},
        {"label": "cr_css", "url": _u(f"{anchor}%0d.css"),
         "mutation_note": f"path → {anchor}%0d.css", "class_": "byte_truncation"},
        {"label": "hash_css", "url": _u(f"{anchor}%23.css"),
         "mutation_note": f"path → {anchor}%23.css (URL-fragment trick)",
         "class_": "byte_truncation"},
        {"label": "query_css", "url": _u(anchor, append_query="x=.css"),
         "mutation_note": f"path → {anchor}?x=.css (query-string trick)",
         "class_": "query_strip"},
        {"label": "enc_slash_css", "url": _u(f"{anchor}%2fx.css"),
         "mutation_note": f"path → {anchor}%2fx.css", "class_": "delim_traversal"},
        {"label": "double_slash", "url": _u(f"{anchor}//x.css"),
         "mutation_note": f"path → {anchor}//x.css", "class_": "delim_traversal"},
    ]
    # Dedup on URL — for a path == "/", `slash_x_css` and `enc_slash_css`
    # would collapse with similar shapes; prefer explicit-label preservation
    # but skip exact URL duplicates.
    seen: set[str] = set()
    deduped: list[dict[str, str]] = []
    for v in variants:
        if v["url"] in seen:
            continue
        seen.add(v["url"])
        deduped.append(v)
    return deduped


# ---------------------------------------------------------------------------
# Body-similarity heuristic
# ---------------------------------------------------------------------------


def _body_hash(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest()


def _tokenize(body: str) -> set[str]:
    if not body:
        return set()
    # Cap the token-set work — extremely long pages would dominate compute.
    capped = body[:64 * 1024]
    return set(_TOKEN_RE.findall(capped))


def _body_match(baseline_body: str, probe_body: str) -> dict[str, Any]:
    """Return {match: bool, length_ratio: float, jaccard: float}.

    Match = length within ±5% AND Jaccard ≥ 0.85.
    """
    bl_len = len(baseline_body)
    pb_len = len(probe_body)
    if bl_len == 0 or pb_len == 0:
        return {"match": False, "length_ratio": 0.0, "jaccard": 0.0}
    longer = max(bl_len, pb_len)
    shorter = min(bl_len, pb_len)
    length_ratio = shorter / longer if longer else 0.0

    # Quick reject on length divergence.
    if length_ratio < (1 - _BODY_LEN_TOLERANCE_PCT / 100.0):
        return {"match": False, "length_ratio": length_ratio, "jaccard": 0.0}

    bl_tokens = _tokenize(baseline_body)
    pb_tokens = _tokenize(probe_body)
    if not bl_tokens or not pb_tokens:
        # Fall back to length-only if no useful tokens (e.g. binary or
        # heavily-numeric content).
        return {
            "match": length_ratio >= (1 - _BODY_LEN_TOLERANCE_PCT / 100.0),
            "length_ratio": length_ratio,
            "jaccard": 0.0,
        }
    inter = len(bl_tokens & pb_tokens)
    union = len(bl_tokens | pb_tokens)
    jaccard = inter / union if union else 0.0
    return {
        "match": jaccard >= _TOKEN_JACCARD_THRESHOLD,
        "length_ratio": length_ratio,
        "jaccard": jaccard,
    }


# ---------------------------------------------------------------------------
# Cacheability verdict
# ---------------------------------------------------------------------------


def _cacheability(headers: dict[str, str]) -> str:
    """Return one of: 'cacheable_explicit', 'cached_already', 'ambiguous',
    'not_cacheable'.

    - cacheable_explicit: Cache-Control says cache (public / max-age) and
      doesn't deny.
    - cached_already: server signals the response came from a cache (Age,
      X-Cache HIT, CF-Cache-Status HIT, etc.).
    - not_cacheable: Cache-Control: no-store / private / no-cache.
    - ambiguous: no Cache-Control, no cache-hit signals; absent explicit
      no-store, real-world CDNs often cache static-extension responses.
    """
    cc = (headers.get("cache-control") or "").lower()
    if "no-store" in cc or "private" in cc or "no-cache" in cc:
        return "not_cacheable"

    # X-Cache / CF-Cache-Status with a HIT-shaped value = served from cache.
    for hname in _CACHE_HIT_HEADERS:
        v = (headers.get(hname) or "").strip().lower()
        if not v:
            continue
        if hname == "age":
            # Numeric > 0 means cached.
            try:
                if int(v) > 0:
                    return "cached_already"
            except ValueError:
                continue
            continue
        if "hit" in v:
            return "cached_already"

    if "public" in cc or "max-age" in cc or "s-maxage" in cc:
        return "cacheable_explicit"

    return "ambiguous"


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


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
    finding_id = tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="web_cache_deception",
        cwe="CWE-525",
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "Web cache deception lets an attacker harvest other users' "
            "authenticated content. The attacker prepares a link that "
            "appears to point at a static asset (`.css`, `.js`, `.png`); "
            "when a victim visits it while logged in, the back-end "
            "returns the victim's authenticated page but the CDN caches "
            "it as a public asset. The attacker then fetches the same "
            "URL anonymously and reads the cached response. Real-world "
            "incidents include user PII / session token leaks at scale."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
    )
    try:
        from strix.agents.kg_emit import record_finding_in_kg
        record_finding_in_kg(
            finding_id=finding_id, url=endpoint, param="cache_key",
            cwe="CWE-525", severity=severity,
            category="web_cache_deception",
            method="GET", detection_kind=title[:60],
            confidence=0.85,
        )
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug(
            "cache_deception: kg record failed: %s", e, exc_info=True,
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
    mitre_techniques=["T1199", "T1190"],  # Trusted Relationship + Public-Facing App
)
def cache_deception_check(
    target: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe a URL for web cache deception.

    Args:
        target: URL to probe — typically an authenticated page (e.g.
            `https://app.example.com/account`). Bare hostnames are
            auto-prefixed with `https://`.
        timeout: Per-request timeout in seconds (default 12).

    Methodology:
        1. Fetch the canonical target as the baseline (with auth if
           `--auth-*` flags are configured).
        2. Generate ~15 deception-shaped URL variants (`.css` suffix,
           `/x.css` traversal, `;.css` matrix-URI, `%00.css` null-byte,
           `?x=.css` query trick, etc.).
        3. Fetch each variant with the same auth.
        4. Flag variants where the response body fuzzy-matches the
           baseline (length ±5% AND token Jaccard ≥ 0.85) AND the
           response is cacheable.

    Returns:
        {
          success, target_url, target_host, baseline: {...},
          variants: [{label, url, mutation_note, class_, status,
                      body_match, cacheability, finding_severity, evidence},
                     ...],
          findings_emitted: int
        }

    Findings:
        - **High** (CWE-525, web_cache_deception) — body matches
          baseline AND cacheability is `cacheable_explicit` /
          `cached_already`.
        - **Medium** (CWE-525) — body matches baseline AND cacheability
          is `ambiguous`. Real-world CDNs default-cache
          static-extension responses absent explicit `no-store`.

    Notes:
        - Read-only: GET only, no follow-redirects.
        - Composes with cluster-A safety: `--exclude-path` /
          `--rate-limit` / `--auth-*` apply to every variant.
        - The agent should follow up high-severity findings by fetching
          the same URL anonymously (no auth) and confirming it returns
          the cached authenticated body.
    """
    target_url = _normalize_target(target)
    if not target_url:
        return {"success": False, "error": f"invalid target: {target!r}"}

    target_host = urlparse(target_url).hostname or ""
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {target!r}"}

    cev = _start_check("web_cache_deception", target_host)

    # ---- Baseline ----
    baseline_response = _http_get(target_url, headers={}, timeout=timeout)
    if baseline_response.get("skipped"):
        _complete_check(cev, "inconclusive", "baseline excluded by --exclude-path")
        return {
            "success": True,
            "target_url": target_url,
            "target_host": target_host,
            "skipped": True,
            "skipped_reason": "baseline excluded by cluster-A path filter",
            "variants": [],
            "findings_emitted": 0,
        }
    baseline_status = baseline_response.get("status", 0)
    baseline_body = baseline_response.get("body") or ""
    baseline_headers = baseline_response.get("headers") or {}

    if baseline_status != 200:
        _complete_check(
            cev,
            "inconclusive",
            f"baseline returned {baseline_status} — nothing to deceive-cache",
        )
        return {
            "success": True,
            "target_url": target_url,
            "target_host": target_host,
            "baseline": {
                "status": baseline_status,
                "body_length": len(baseline_body),
                "error": baseline_response.get("error"),
            },
            "variants": [],
            "findings_emitted": 0,
        }

    if len(baseline_body) < _MIN_BODY_BYTES_FOR_MATCH:
        _complete_check(
            cev,
            "inconclusive",
            f"baseline body {len(baseline_body)} bytes — too short for fuzzy-match",
        )
        return {
            "success": True,
            "target_url": target_url,
            "target_host": target_host,
            "baseline": {
                "status": baseline_status,
                "body_length": len(baseline_body),
                "skipped": "body too short",
            },
            "variants": [],
            "findings_emitted": 0,
        }

    baseline_summary = {
        "status": baseline_status,
        "body_length": len(baseline_body),
        "body_hash": _body_hash(baseline_body)[:16],
        "cacheability": _cacheability(baseline_headers),
    }

    # ---- Variant cohort ----
    findings_emitted = 0
    verdicts: list[dict[str, Any]] = []
    seen_finding_keys: set[tuple[str, str]] = set()

    for variant in _build_variants(target_url):
        v_url = variant["url"]
        v_response = _http_get(v_url, headers={}, timeout=timeout)
        if v_response.get("skipped"):
            verdicts.append({
                **variant,
                "status": 0,
                "body_match": None,
                "cacheability": None,
                "finding_severity": None,
                "evidence": "skipped by cluster-A path filter",
            })
            continue
        v_status = v_response.get("status", 0)
        v_body = v_response.get("body") or ""
        v_headers = v_response.get("headers") or {}

        if v_status != 200:
            verdicts.append({
                **variant,
                "status": v_status,
                "body_match": None,
                "cacheability": None,
                "finding_severity": None,
                "evidence": f"variant returned {v_status} — origin distinguishes",
            })
            continue

        match = _body_match(baseline_body, v_body)
        cache_v = _cacheability(v_headers)

        severity: str | None = None
        evidence_parts: list[str] = []

        if match["match"]:
            evidence_parts.append(
                f"body matches baseline (jaccard={match['jaccard']:.2f}, "
                f"length_ratio={match['length_ratio']:.2f})"
            )
            if cache_v in ("cacheable_explicit", "cached_already"):
                severity = "high"
                evidence_parts.append(f"cacheability={cache_v}")
            elif cache_v == "ambiguous":
                severity = "medium"
                evidence_parts.append("cacheability=ambiguous")
            else:
                evidence_parts.append("cacheability=not_cacheable (no finding)")
        else:
            evidence_parts.append(
                f"body diverges (jaccard={match['jaccard']:.2f}, "
                f"length_ratio={match['length_ratio']:.2f})"
            )

        verdicts.append({
            **variant,
            "status": v_status,
            "body_match": match,
            "cacheability": cache_v,
            "finding_severity": severity,
            "evidence": "; ".join(evidence_parts),
        })

        if severity is None:
            continue

        # Dedup on (severity, class) so one PR-worthy finding per shape
        # class doesn't blow up into 5 near-identical reports for the
        # `dot_css` / `dot_js` / `dot_png` cohort all sharing
        # static_ext.
        key = (severity, variant["class_"])
        if key in seen_finding_keys:
            continue
        seen_finding_keys.add(key)

        if severity == "high":
            title = (
                f"Web cache deception — authenticated body cached at "
                f"{variant['mutation_note']} on {target_host}"
            )
            description_plain = (
                "Your application returns logged-in user content for URLs "
                "that look like static assets (`.css`, `.js`, image extensions). "
                "Your CDN or front-end cache is configured to cache those URLs "
                "publicly. Combined, this means an attacker can craft a link, "
                "trick a logged-in user into visiting it, and then read that "
                "user's authenticated response from the cache — anonymously."
            )
            recommended_action = (
                "Either: (a) configure the back-end to refuse non-canonical "
                "extensions (return 404 for `/account.css`); OR (b) configure "
                "the CDN to cache only paths that exactly match a static-asset "
                "directory (e.g. `/static/*`, `/assets/*`); OR (c) set "
                "`Cache-Control: no-store` on every authenticated dynamic "
                "endpoint regardless of extension."
            )
        else:
            title = (
                f"Web cache deception (cacheability ambiguous) — "
                f"{variant['mutation_note']} on {target_host}"
            )
            description_plain = (
                "Your application returns logged-in user content for URLs "
                "that look like static assets (`.css`, `.js`, image extensions). "
                "We don't see explicit cache headers on the response, but real-"
                "world CDNs default-cache static-extension responses absent "
                "explicit `Cache-Control: no-store`. This is exploitable on "
                "most CDN configurations."
            )
            recommended_action = (
                "Set `Cache-Control: no-store` on every authenticated dynamic "
                "endpoint (regardless of URL extension), OR configure the back-"
                "end to refuse non-canonical extensions (return 404 for "
                "`/account.css`). Verify by hitting the variant URL anonymously "
                "and confirming the cached response is not returned."
            )

        description = (
            f"Variant `{variant['label']}` ({variant['mutation_note']}) — "
            f"{'; '.join(evidence_parts)}. Baseline length="
            f"{len(baseline_body)}; variant length={len(v_body)}; "
            f"baseline body hash={baseline_summary['body_hash']}, "
            f"variant body hash={_body_hash(v_body)[:16]}."
        )
        _emit_finding(
            title=title,
            severity=severity,
            target=target_host,
            endpoint=v_url,
            description=description,
            description_plain=description_plain,
            recommended_action=recommended_action,
        )
        findings_emitted += 1

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{findings_emitted} cache-deception variant(s) on {target_host}",
    )

    return {
        "success": True,
        "target_url": target_url,
        "target_host": target_host,
        "baseline": baseline_summary,
        "variants": verdicts,
        "findings_emitted": findings_emitted,
    }
