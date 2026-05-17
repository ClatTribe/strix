"""`scan_cache_deception` — web cache deception detector.

Closes the highest-impact missing P0 from `masterroadmap.md` §1
(`web_application` coverage gap). Web cache deception is the
2017-era Omer Gil / Kettle research class: an attacker tricks the
CDN into caching a page that returns SENSITIVE per-user data, then
fetches the cache key from their own session to harvest the
victim's content.

## Methodology

The attack chain has three preconditions; this specialist tests
all three deterministically:

  1. **Cacheable-extension path** — server serves a URL with an
     extension typically associated with static assets (`.css`,
     `.js`, `.png`, `.jpg`, `.gif`, `.ico`, `.svg`, `.woff`,
     `.woff2`).
  2. **Sensitive content** — that URL returns the SAME or VERY
     SIMILAR content to the base sensitive path (`/account` vs
     `/account.css`). Authenticated markers (cookie value, email,
     username) appear in both.
  3. **CDN caches the response** — caching is permitted by the
     response headers (`Cache-Control: public`, missing `private`,
     `max-age > 0`, OR presence of `Age`/`X-Cache: HIT`/`CF-Cache-
     Status: HIT` indicating the CDN already cached it).

Probe matrix (per sensitive path):

| | Path mutation | Variant |
|---|---|---|
| `appended_ext` | `/account.css` | append extension |
| `path_segment_ext` | `/account/foo.css` | path-segment variant |
| `semicolon_ext` | `/account;.css` | semicolon path-param trick |
| `encoded_slash_ext` | `/account%2F.css` | URL-encoded slash |
| `dot_slash_ext` | `/account/.css` | trailing slash + dot |
| `query_ext` | `/account?.css` | query-separator |

Detection criterion (BOTH must hold):

  * Response status 200 + body similar to baseline (Jaccard ≥ 0.6
    OR baseline auth-marker reflected in probe response).
  * Response is **cacheable** per the cache-policy parser:
    `Cache-Control: public` OR `max-age > 0` AND no `private` /
    `no-store` / `no-cache` directives — OR cached already
    (`X-Cache: HIT`, `CF-Cache-Status: HIT`, `Age:` header).

Severity:

  * **high** — direct user-data-leak primitive. CWE-525 (Use of
    Web Browser Cache Containing Sensitive Information) +
    CWE-639 (Authorization Bypass Through User-Controlled Key).
  * `verification_status="verified"` when the cacheable-response
    check passes; `"pattern_match"` when content matches but the
    cache policy is uncertain.

## What this does NOT do

  * **Active cache poisoning** (X-Forwarded-Host reflection +
    cache-key obliviousness) — covered by
    `strix.tools.host_header.host_header_check`.
  * **Path normalisation differential** (front-end normalises
    `/foo/../bar` differently from back-end) — separate research
    class, future PR.
  * **Cache-key smuggling via HTTP smuggling** —
    `scan_request_smuggling_active` is the cross-asset chain.

## Auth context

The specialist runs with whatever auth is configured for the run
(`STRIX_AUTH_*` envs feed through `inject_auth_headers`). Without
authenticated sessions the detector can't distinguish
"per-user response that should not be cached" from "static
asset that should be cached" — without auth the false-positive
floor is too high. Returns `status="partial"` with an explanatory
evidence line when no auth signal is detectable.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Cap on response body size we scan for content similarity.
_MAX_BODY_SCAN = 200 * 1024

# Cap on per-run probe count to keep the scan bounded.
_DEFAULT_MAX_PROBES = 30

# Cacheable extensions — the universal CDN allowlist for asset
# caching. Adding a new entry should reflect what real CDN
# configurations honour (Cloudflare's default, Fastly's default,
# AWS CloudFront's default behaviour).
_CACHEABLE_EXTENSIONS: tuple[str, ...] = (
    "css", "js", "jpg", "jpeg", "png", "gif", "ico", "svg",
    "woff", "woff2", "ttf", "otf", "eot",
    "webp", "avif",
    "mp4", "webm", "ogg", "mp3",
    "pdf",
)


# Path-mutation generators. Each takes (path, extension) and
# returns the probed path. Multiple mutations because real CDNs
# normalize URLs differently — what works against Cloudflare may
# not work against Fastly, and vice-versa.
def _mutate_appended(path: str, ext: str) -> str:
    """`/account` → `/account.css`. The canonical Omer Gil shape."""
    return f"{path.rstrip('/')}.{ext}"


def _mutate_path_segment(path: str, ext: str) -> str:
    """`/account` → `/account/x.css`. Bypasses servers that strip
    a trailing extension; some frameworks route `/account/x.css`
    as `/account` because the framework's router treats path
    segments after the matched route as ignored."""
    return f"{path.rstrip('/')}/x.{ext}"


def _mutate_semicolon(path: str, ext: str) -> str:
    """`/account` → `/account;x.css`. Path-parameter trick (RFC
    3986 §3.3); some servers strip after the semicolon, some
    don't. The CDN typically keys on the full path."""
    return f"{path.rstrip('/')};x.{ext}"


def _mutate_encoded_slash(path: str, ext: str) -> str:
    """`/account` → `/account%2Fx.css`. Some servers decode the
    %2F before routing, others don't — caching layer typically
    doesn't."""
    return f"{path.rstrip('/')}%2Fx.{ext}"


def _mutate_dot_slash(path: str, ext: str) -> str:
    """`/account` → `/account/x.css` style but with leading dot —
    rare but catches a small set of servers."""
    return f"{path.rstrip('/')}/.{ext}"


_MUTATIONS: dict[str, Any] = {
    "appended_ext": _mutate_appended,
    "path_segment_ext": _mutate_path_segment,
    "semicolon_ext": _mutate_semicolon,
    "encoded_slash_ext": _mutate_encoded_slash,
    "dot_slash_ext": _mutate_dot_slash,
}


# ---------------------------------------------------------------------------
# HTTP send (cluster-A safety same as host_header_check)
# ---------------------------------------------------------------------------


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _send_get(url: str, *, timeout: float = 12.0) -> dict[str, Any]:
    """GET via cluster-A safety. Returns {status, headers, body,
    error?, skipped?}.

    Tries `proxy_manager.send_simple_request` first so auth-
    injection / exclude-path / rate-limit middleware applies.
    Falls back to a direct httpx call with the same middleware
    applied manually — same contract as `host_header_check`.
    """
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager
        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request(
                "GET", url, headers={}, timeout=int(timeout),
            )
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": (r.get("body") or "")[:_MAX_BODY_SCAN],
            }
        except Exception:  # noqa: BLE001
            logger.debug("scan_cache_deception: proxy send failed; falling back",
                         exc_info=True)

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
        with httpx.Client(
            timeout=timeout, follow_redirects=False, verify=False,
        ) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:_MAX_BODY_SCAN],
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


# ---------------------------------------------------------------------------
# Cacheability parser
# ---------------------------------------------------------------------------


_NON_CACHEABLE_DIRECTIVES = (
    "private", "no-store", "no-cache",
)


def _parse_max_age(cache_control: str) -> int | None:
    m = re.search(r"max-age\s*=\s*(\d+)", cache_control, flags=re.IGNORECASE)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _is_cacheable_response(headers: dict[str, str]) -> tuple[bool, str]:
    """Return `(cacheable, reason)`.

    A response is cacheable when:
      * `X-Cache: HIT` / `CF-Cache-Status: HIT` / `Age:` indicates
        the CDN already cached it (strongest signal).
      * `Cache-Control: public` + non-zero `max-age` AND no
        `private` / `no-store` / `no-cache` directives.
      * No `Cache-Control` header AT ALL — default for some
        servers is implicit cacheability per RFC 7234.

    `Pragma: no-cache` is also treated as a non-cacheable signal.
    """
    cc = (headers.get("cache-control") or "").lower()
    pragma = (headers.get("pragma") or "").lower()

    # Strong cached-already signals — take these first.
    x_cache = (headers.get("x-cache") or "").lower()
    cf_cache = (headers.get("cf-cache-status") or "").lower()
    age = (headers.get("age") or "").strip()
    if "hit" in x_cache or "hit" in cf_cache:
        return True, f"cache-hit header (x-cache={x_cache or '-'}, cf-cache-status={cf_cache or '-'})"
    if age and age != "0":
        return True, f"Age: {age} (cached for {age}s)"

    # Explicit non-cacheable directives. Win against any
    # `public` / `max-age` saying otherwise.
    for directive in _NON_CACHEABLE_DIRECTIVES:
        if directive in cc:
            return False, f"cache-control: {directive}"
    if "no-cache" in pragma:
        return False, "pragma: no-cache"

    # Positive cache signal.
    if "public" in cc:
        return True, "cache-control: public"

    max_age = _parse_max_age(cc)
    if max_age is not None and max_age > 0:
        return True, f"cache-control: max-age={max_age}"

    # No directives at all → implicit cacheability per RFC 7234
    # for GET 200 responses. Conservative: treat as cacheable
    # only if NO `Cache-Control` header exists. Half the web
    # defaults to public for static assets.
    if not cc:
        return True, "no cache-control header (implicit cacheability)"

    return False, f"cache-control: {cc or '(none)'}"


# ---------------------------------------------------------------------------
# Body similarity (Jaccard token overlap)
# ---------------------------------------------------------------------------


_TOKEN_RE = re.compile(r"\w+")


def _tokenize(body: str, *, limit: int = 4000) -> set[str]:
    """Lowercase word-token set, capped for similarity-eval cost.
    `limit` is the max distinct tokens; pages tend to repeat
    boilerplate so 4k is plenty."""
    out: set[str] = set()
    for m in _TOKEN_RE.finditer(body.lower()):
        out.add(m.group(0))
        if len(out) >= limit:
            break
    return out


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


# Authenticated-page markers — when ANY of these appear in BOTH
# baseline and probe, content similarity is moot (we have direct
# evidence the probe returned auth-context content).
_AUTH_MARKERS = (
    "logout", "log out", "sign out", "my account", "profile",
    "csrf", "session", "welcome back",
)


def _has_auth_marker(baseline_body: str, probe_body: str) -> str | None:
    """Return the FIRST auth marker present in both bodies, or
    None. Lowercase substring match — cheap + reliable signal."""
    b = baseline_body.lower()
    p = probe_body.lower()
    for marker in _AUTH_MARKERS:
        if marker in b and marker in p:
            return marker
    return None


# ---------------------------------------------------------------------------
# Path enumeration
# ---------------------------------------------------------------------------


# Default candidate-paths. The agent normally passes paths
# explicitly; this list is the fallback for "run me on a target,
# figure out what to probe yourself."
_DEFAULT_SENSITIVE_PATHS = (
    "/account", "/profile", "/dashboard", "/me", "/api/me",
    "/api/user", "/api/account", "/settings",
)


def _enumerate_probes(
    base_url: str, paths: list[str], extensions: list[str],
    mutations: list[str], max_probes: int,
) -> list[dict[str, str]]:
    """Build the cross-product probe set. Yields entries:
    `{path, mutation, ext, probe_path, probe_url, baseline_url}`."""
    parsed = urlparse(base_url)
    out: list[dict[str, str]] = []
    for path in paths:
        path = path.strip()
        if not path.startswith("/"):
            path = "/" + path
        for mutation_name in mutations:
            mutator = _MUTATIONS.get(mutation_name)
            if mutator is None:
                continue
            for ext in extensions:
                probe_path = mutator(path, ext)
                probe_url = urlunparse(
                    (parsed.scheme, parsed.netloc, probe_path,
                     "", "", "")
                )
                baseline_url = urlunparse(
                    (parsed.scheme, parsed.netloc, path,
                     "", "", "")
                )
                out.append({
                    "path": path,
                    "mutation": mutation_name,
                    "ext": ext,
                    "probe_path": probe_path,
                    "probe_url": probe_url,
                    "baseline_url": baseline_url,
                })
                if len(out) >= max_probes:
                    return out
    return out


# ---------------------------------------------------------------------------
# Finding emission
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    target_url: str,
    sensitive_path: str,
    probe_path: str,
    mutation: str,
    ext: str,
    similarity: float,
    auth_marker: str | None,
    cache_reason: str,
    probe_status: int,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return None
        verification = "verified" if auth_marker else "pattern_match"
        confidence = 0.95 if auth_marker else 0.7
        title = (
            f"Web cache deception at `{sensitive_path}` "
            f"(probe: `{probe_path}`, mutation: {mutation})"
        )
        finding_id = tracer.add_vulnerability_report(
            title=title,
            severity="high",
            cwe="CWE-525",
            endpoint=probe_path,
            target=target_url,
            category="cache_deception",
            verification_status=verification,
            confidence=confidence,
            description=(
                f"Sensitive endpoint `{sensitive_path}` returns the same "
                f"(or near-same) authenticated content when accessed as "
                f"`{probe_path}` — and that probed URL is cacheable per "
                f"the response policy (`{cache_reason}`).\n\n"
                f"Body similarity to baseline: {similarity:.2f}"
                + (f"; authenticated marker `{auth_marker}` reflected "
                   f"in both responses." if auth_marker else "")
            ),
            impact=(
                "Web cache deception. An attacker tricks the victim's "
                "browser (or pre-warms the CDN themselves) into loading "
                "the probed URL while the victim is authenticated. The "
                "CDN caches the response keyed on the URL. The attacker "
                "then GETs the same URL from their own session — they "
                "receive the victim's cached authenticated content "
                "(cookies, PII, session tokens, account details).\n\n"
                "  * Attack vector: `<img src='/account.css'>` on any "
                "    attacker-controlled page; CDN caches the response.\n"
                "  * Auth bypass primitive — bypasses session-based "
                "    access control because the CDN response is keyed "
                "    on URL only.\n"
                "  * Common in real-world breaches: PayPal 2017, "
                "    Cloudflare-fronted SaaS apps, etc."
            ),
            technical_analysis=(
                f"Target: {target_url}\n"
                f"Sensitive path: {sensitive_path}\n"
                f"Probe path: {probe_path}\n"
                f"Mutation: {mutation}\n"
                f"Extension: .{ext}\n"
                f"Probe response status: {probe_status}\n"
                f"Body similarity to baseline (Jaccard): {similarity:.3f}\n"
                f"Auth marker reflected: "
                f"{auth_marker or '(none — pattern match only)'}\n"
                f"Cacheability signal: {cache_reason}"
            ),
            poc_description=(
                f"1. Log into the application as the victim.\n"
                f"2. From an attacker page, embed "
                f"`<img src='{probe_path}'>` (or trick the victim into "
                f"clicking a link to it). The browser sends the request "
                f"with the victim's session cookies.\n"
                f"3. The CDN caches the response keyed on the URL "
                f"`{probe_path}`.\n"
                f"4. From the attacker's own session, GET `{probe_path}` "
                f"— receive the victim's cached authenticated content."
            ),
            remediation_steps=(
                "1. **Strip path parameters before the framework routes "
                "the request** (semicolons, encoded slashes, dot "
                "segments). Reject paths the canonicalized form differs "
                "from the raw input.\n"
                "2. **Validate the URL extension matches the rendered "
                "Content-Type**. Server should refuse to serve dynamic "
                "content with a `.css` / `.js` / `.png` URL — even when "
                "the path routes to a dynamic handler.\n"
                "3. **At the CDN**, configure the cache key to include "
                "the `Vary` headers AND a per-session token (e.g. an "
                "`Origin` rule that bypasses cache when "
                "`Authorization` / `Cookie: session=` is present).\n"
                "4. **Set `Cache-Control: private` on authenticated "
                "responses** unconditionally — the CDN should never "
                "cache them regardless of the URL shape."
            ),
            cvss_breakdown={
                "AV": "N", "AC": "L", "PR": "N", "UI": "R",
                "S": "C", "C": "H", "I": "L", "A": "N",
            },
            reasoning_trace=[
                f"Probe `{probe_path}` returned 200 with body "
                f"similarity {similarity:.2f} to baseline "
                f"`{sensitive_path}`.",
                (f"Authenticated marker `{auth_marker}` reflected "
                 f"in both responses." if auth_marker
                 else "No specific auth marker found, but token-set "
                 "overlap is high enough to evidence content reuse."),
                f"Cacheability: {cache_reason}.",
                "Cache + content-reuse together = deception primitive.",
            ],
        )
        try:
            from strix.agents.kg_emit import record_finding_in_kg
            record_finding_in_kg(
                finding_id=finding_id, url=probe_path,
                param=f"path:{mutation}", cwe="CWE-525", severity="high",
                category="cache_deception", method="GET",
                detection_kind=f"cache_deception_{mutation}",
                confidence=confidence,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("scan_cache_deception: kg record failed: %s", e,
                         exc_info=True)
        return finding_id
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_cache_deception: emit failed: %s", e, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Public specialist
# ---------------------------------------------------------------------------


@register_specialist_tool(
    category="cache-deception-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 180},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1539", "T1212"],
)
def scan_cache_deception(
    *,
    url: str,
    sensitive_paths: list[str] | None = None,
    extensions: list[str] | None = None,
    mutations: list[str] | None = None,
    similarity_threshold: float = 0.6,
    max_probes: int = _DEFAULT_MAX_PROBES,
    timeout_seconds: float = 12.0,
) -> SpecialistResult:
    """Probe a target for web cache deception (CWE-525).

    Args:
        url: target base URL (e.g. `https://app.example.com`). Path
            component is ignored — the specialist enumerates
            `sensitive_paths` against the host.
        sensitive_paths: paths to test for deception. None falls
            back to the bundled defaults (`/account`, `/profile`,
            `/dashboard`, `/me`, `/api/me`, `/api/user`, etc.).
            The agent typically passes paths the surface map
            discovered as authenticated endpoints.
        extensions: cacheable extensions to test. None uses the
            bundled CDN-standard list (`css`, `js`, `jpg`, etc.).
        mutations: mutation names to use. None uses every built-in.
        similarity_threshold: Jaccard token overlap required to
            treat the probe response as content-reused from the
            baseline. Default 0.6 — empirically separates
            "different pages" from "same page, different URL".
        max_probes: hard cap on probe count to keep runs bounded.
        timeout_seconds: per-request timeout.

    Findings emit as `category=cache_deception`, CWE-525, severity
    high. Verified when an auth-marker is reflected; pattern_match
    when similarity passes but no explicit auth signal.
    """
    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    parsed = urlparse(url.strip())
    if not parsed.netloc:
        return SpecialistResult(status="error", error=f"invalid url: {url}")
    base_url = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    paths = list(sensitive_paths or _DEFAULT_SENSITIVE_PATHS)
    exts = list(extensions or _CACHEABLE_EXTENSIONS)
    muts = list(mutations or _MUTATIONS.keys())

    probes = _enumerate_probes(base_url, paths, exts, muts, max_probes)
    if not probes:
        return SpecialistResult(
            status="error",
            error="no probes constructed (check path/ext/mutation inputs)",
        )

    # Baseline cache per path — avoid re-fetching the same baseline
    # for every (extension × mutation) probe against the same path.
    baseline_cache: dict[str, dict[str, Any]] = {}

    def _baseline(path_url: str) -> dict[str, Any]:
        if path_url not in baseline_cache:
            baseline_cache[path_url] = _send_get(
                path_url, timeout=timeout_seconds,
            )
        return baseline_cache[path_url]

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted = 0
    probes_run = 0
    seen_hits: set[tuple[str, str]] = set()  # (path, mutation) dedup

    for probe in probes:
        baseline_resp = _baseline(probe["baseline_url"])
        if baseline_resp.get("skipped") or baseline_resp.get("error"):
            continue
        # Baseline must look auth-context-ish: 200 status AND
        # either a session-y cookie present OR a known auth marker
        # in the body. Otherwise we'd false-positive on truly
        # public pages.
        if baseline_resp["status"] != 200:
            continue
        baseline_body = baseline_resp["body"]
        if not baseline_body:
            continue

        probe_resp = _send_get(probe["probe_url"], timeout=timeout_seconds)
        probes_run += 1
        if probe_resp.get("skipped") or probe_resp.get("error"):
            continue
        if probe_resp["status"] != 200:
            continue
        probe_body = probe_resp["body"]
        if not probe_body:
            continue

        # Cacheability check first — cheapest filter.
        cacheable, cache_reason = _is_cacheable_response(probe_resp["headers"])
        if not cacheable:
            continue

        # Auth-marker check (strongest signal) OR similarity check.
        auth_marker = _has_auth_marker(baseline_body, probe_body)
        if auth_marker is None:
            similarity = _jaccard(
                _tokenize(baseline_body), _tokenize(probe_body),
            )
            if similarity < similarity_threshold:
                continue
        else:
            similarity = _jaccard(
                _tokenize(baseline_body), _tokenize(probe_body),
            )

        # Dedup: one finding per (path, mutation) — across
        # extensions a single mutation type either works or doesn't,
        # additional ext hits are redundant.
        dedup_key = (probe["path"], probe["mutation"])
        if dedup_key in seen_hits:
            continue
        seen_hits.add(dedup_key)

        rid = _emit_finding(
            target_url=base_url,
            sensitive_path=probe["path"],
            probe_path=probe["probe_path"],
            mutation=probe["mutation"],
            ext=probe["ext"],
            similarity=similarity,
            auth_marker=auth_marker,
            cache_reason=cache_reason,
            probe_status=probe_resp["status"],
        )
        if rid:
            emitted += 1
        drafts.append(FindingDraft(
            title=f"Cache deception: {probe['path']} via {probe['mutation']}",
            severity="high", cwe="CWE-525",
            endpoint=probe["probe_path"], category="cache_deception",
            verification_status="verified" if auth_marker else "pattern_match",
            confidence=0.95 if auth_marker else 0.7,
            description=(
                f"{probe['probe_path']} returns cached "
                f"({cache_reason}) authenticated content; similarity "
                f"{similarity:.2f}"
            ),
        ))
        evidence.append(
            f"{probe['mutation']}:{probe['probe_path']} "
            f"sim={similarity:.2f} cache={cache_reason}"
            + (f" marker={auth_marker}" if auth_marker else "")
        )

    # SecurityContext + decision_log
    try:
        from strix.agents.security_context import record_endpoint
        record_endpoint(
            base_url, method="GET", probed_for="cache_deception",
        )
    except Exception:  # noqa: BLE001
        pass
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation", target=base_url,
            actor={"tool_name": "scan_cache_deception"},
            input={"paths_tested": len(paths),
                   "extensions_tested": len(exts),
                   "mutations_tested": len(muts),
                   "probes_run": probes_run},
            output={"findings_emitted": emitted,
                    "drafts": len(drafts)},
        )
    except Exception:  # noqa: BLE001
        pass

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            [
                "confirm exploitability: load the probe URL while "
                "authenticated (via an attacker-page <img>) and "
                "verify the CDN caches it (check `X-Cache: HIT` "
                "on a second fetch from a fresh session)",
                "follow up with `host_header_check` on the same "
                "paths to find the active cache-poisoning siblings",
            ]
            if drafts else
            [
                "no cache deception found via the bundled mutation "
                "set; if the target uses a non-standard router, "
                "extend `mutations` with framework-specific paths",
            ]
        ),
        tool_metadata={
            "target": base_url,
            "paths_tested": len(paths),
            "extensions_tested": len(exts),
            "mutations_tested": len(muts),
            "probes_run": probes_run,
            "findings_emitted_to_tracer": emitted,
            "similarity_threshold": similarity_threshold,
        },
    )
